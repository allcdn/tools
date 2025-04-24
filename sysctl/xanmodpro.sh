#!/bin/bash
set -euo pipefail

# 颜色定义
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
NC='\033[0m'

# 有效的流量管理算法列表
valid_qos=("fq" "fq_codel" "fq_pie" "cake" "pfifo_fast" "sfq" "red" "tbf")
QOS_ALGO="fq_codel"  # 默认算法

# 流量管理算法说明
qos_descriptions=(
    "fq:            公平队列，基本公平性和低延迟，CPU开销低"
    "fq_codel:      公平队列和CoDel结合，适合低延迟场景"
    "fq_pie:        比例积分增强型算法，高负载下比fq_codel更稳定"
    "cake:          综合自适应队列管理，适合CDN和流媒体服务器"
    "pfifo_fast:    Linux默认队列，基于优先级的简单FIFO队列"
    "sfq:           随机公平队列，防止单连接占用所有带宽"
    "red:           随机早期检测，防止网络拥塞，可能增加CPU负载"
    "tbf:           令牌桶过滤器，精确控制带宽使用率"
)

# 服务器类型
SERVER_TYPE=""
server_types=("web" "cdn" "vpn")

# 检查root权限
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误: 此脚本必须以root用户运行${NC}"
   exit 1
fi

# 检查内核参数
check_kernel_param() {
  local param="$1"
  if sysctl -q "$param" &>/dev/null; then
    return 0
  else
    return 1
  fi
}

# 显示算法详细说明
display_qos_details() {
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}流量管理算法详细说明${BLUE}            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    
    for desc in "${qos_descriptions[@]}"; do
        IFS=':' read -r algo explanation <<< "$desc"
        echo -e "${GREEN}$(printf "%-12s" "$algo")${NC} ${YELLOW}$explanation${NC}"
    done
    
    echo -e "${BLUE}────────────────────────────────────────${NC}"
    
    # 根据服务器类型提供推荐
    if [[ "$SERVER_TYPE" == "web" ]]; then
        echo -e "${GREEN}✓ Web服务器推荐: fq_codel, cake${NC}"
    elif [[ "$SERVER_TYPE" == "cdn" ]]; then
        echo -e "${GREEN}✓ CDN节点推荐: cake, fq_codel${NC}"
    elif [[ "$SERVER_TYPE" == "vpn" ]]; then
        echo -e "${GREEN}✓ VPN服务器推荐: fq_pie, fq_codel${NC}"
    elif [[ $is_xanmod -eq 1 ]]; then
        echo -e "${GREEN}✓ XanMod内核推荐: cake, fq_codel${NC}"
    else
        echo -e "${GREEN}✓ 通用服务器推荐: fq_codel, fq${NC}"
    fi
}

# 获取系统信息
mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
cpu_cores=$(nproc)
is_xanmod=$(uname -r | grep -iq xanmod && echo 1 || echo 0)
kernel_version=$(uname -r)

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        --qos|-q)
            QOS_ALGO="$2"
            shift 2
            ;;
        --server-type|-s)
            SERVER_TYPE="$2"
            shift 2
            ;;
        --help|-h)
            echo -e "${GREEN}用法: $0 [选项]${NC}"
            echo -e "${GREEN}选项:${NC}"
            echo -e "  ${YELLOW}--qos, -q${NC} \t指定流量管理算法(fq, fq_codel等), 默认:fq_codel"
            echo -e "  ${YELLOW}--server-type, -s${NC} \t指定服务器类型(web, cdn, vpn)"
            echo -e "  ${YELLOW}--help, -h${NC} \t显示帮助信息"
            echo -e "\n无参数时将以交互方式选择"
            exit 0
            ;;
        *)
            echo -e "${RED}错误: 未知参数 $1${NC}"
            echo -e "${YELLOW}使用 -h 查看帮助${NC}"
            exit 1
            ;;
    esac
done

# 交互式选择服务器类型
if [[ -z "${SERVER_TYPE}" ]]; then
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       ${GREEN}服务器类型选择${BLUE}                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo -e "\n${CYAN}请选择服务器类型:${NC}"
    echo -e "  ${GREEN}1)${NC} Web服务器\t${YELLOW}适用于网站、API和应用服务器${NC}"
    echo -e "  ${GREEN}2)${NC} CDN节点\t${YELLOW}适用于内容分发网络${NC}"
    echo -e "  ${GREEN}3)${NC} VPN服务器\t${YELLOW}适用于VPN和代理服务器${NC}"
    echo -e "  ${GREEN}4)${NC} 通用服务器\t${YELLOW}适合其他类型服务器${NC}"
    
    read -p "$(echo -e ${YELLOW}"请输入选项 [1-4] (默认: 4): "${NC})" server_choice
    
    server_choice=${server_choice:-4}
    
    case $server_choice in
        1) SERVER_TYPE="web"; QOS_ALGO=${QOS_ALGO:-"fq_codel"} ;;
        2) SERVER_TYPE="cdn"; QOS_ALGO=${QOS_ALGO:-"cake"} ;;
        3) SERVER_TYPE="vpn"; QOS_ALGO=${QOS_ALGO:-"fq_pie"} ;;
        4) SERVER_TYPE="general"; QOS_ALGO=${QOS_ALGO:-"fq_codel"} ;;
        *) echo -e "${RED}无效选择，使用默认值${NC}"; SERVER_TYPE="general" ;;
    esac
    
    echo -e "${GREEN}已选择服务器类型: ${CYAN}$SERVER_TYPE${NC}\n"
fi

# 交互式选择流量管理算法
if [[ -z "${QOS_ALGO:-}" ]]; then
    echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║     ${GREEN}流量管理算法选择${BLUE}                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
    echo -e "\n${CYAN}请选择流量管理算法:${NC}"
    echo -e "  ${GREEN}1)${NC} fq_codel\t${YELLOW}[推荐] 控制延迟的公平队列${NC}"
    echo -e "  ${GREEN}2)${NC} cake\t\t${YELLOW}综合自动网络队列管理${NC}"
    echo -e "  ${GREEN}3)${NC} fq_pie\t${YELLOW}适合VPN服务器${NC}"
    echo -e "  ${GREEN}4)${NC} fq\t\t${YELLOW}基本公平队列${NC}"
    echo -e "  ${GREEN}5)${NC} pfifo_fast\t${YELLOW}传统优先级队列${NC}"
    echo -e "  ${GREEN}6)${NC} sfq\t\t${YELLOW}随机公平队列${NC}"
    echo -e "  ${GREEN}7)${NC} red\t\t${YELLOW}随机早期检测队列${NC}"
    echo -e "  ${GREEN}8)${NC} tbf\t\t${YELLOW}令牌桶过滤器${NC}"
    echo -e "  ${GREEN}9)${NC} 查看详细算法说明"
    echo -e "\n  ${GREEN}0)${NC} 退出脚本"
    
    read -p "$(echo -e ${YELLOW}"请输入选项 [0-9] (默认: 1): "${NC})" qos_choice
    
    qos_choice=${qos_choice:-1}
    
    case $qos_choice in
        1) QOS_ALGO="fq_codel" ;;
        2) QOS_ALGO="cake" ;;
        3) QOS_ALGO="fq_pie" ;;
        4) QOS_ALGO="fq" ;;
        5) QOS_ALGO="pfifo_fast" ;;
        6) QOS_ALGO="sfq" ;;
        7) QOS_ALGO="red" ;;
        8) QOS_ALGO="tbf" ;;
        9) 
            display_qos_details
            echo ""
            echo -e "${CYAN}请再次选择流量管理算法:${NC}"
            read -p "$(echo -e ${YELLOW}"请输入选项 [1-8] (默认: 1): "${NC})" qos_choice
            qos_choice=${qos_choice:-1}
            case $qos_choice in
                1) QOS_ALGO="fq_codel" ;;
                2) QOS_ALGO="cake" ;;
                3) QOS_ALGO="fq_pie" ;;
                4) QOS_ALGO="fq" ;;
                5) QOS_ALGO="pfifo_fast" ;;
                6) QOS_ALGO="sfq" ;;
                7) QOS_ALGO="red" ;;
                8) QOS_ALGO="tbf" ;;
                *) echo -e "${RED}无效选择，使用默认值${NC}"; QOS_ALGO="fq_codel" ;;
            esac
            ;;
        0) echo -e "${YELLOW}已取消${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选择，使用默认值${NC}"; QOS_ALGO="fq_codel" ;;
    esac
    
    echo -e "${GREEN}已选择: ${CYAN}$QOS_ALGO${NC}\n"
fi

# 验证QOS算法
qos_valid=0
for qos in "${valid_qos[@]}"; do
    if [[ "$QOS_ALGO" == "$qos" ]]; then
        qos_valid=1
        break
    fi
done

if [[ $qos_valid -eq 0 ]]; then
    echo -e "${RED}错误: 无效的流量管理算法 '$QOS_ALGO'${NC}"
    echo -e "${YELLOW}有效选项: ${valid_qos[*]}${NC}"
    exit 1
fi

echo -e "${BLUE}[•] 正在运行优化... (服务器类型: $SERVER_TYPE, 算法: $QOS_ALGO)${NC}"

# 根据服务器类型计算资源限制
case $SERVER_TYPE in
    "web")
        nofile_soft=$((mem_gb * 65536))
        nofile_hard=$((mem_gb * 131072))
        somaxconn=65535
        backlog=$((cpu_cores * 65536))
        echo -e "${BLUE}[•] 应用Web服务器优化配置...${NC}"
        ;;
    "cdn") 
        nofile_soft=$((mem_gb * 131072))
        nofile_hard=$((mem_gb * 262144))
        somaxconn=131070
        backlog=$((cpu_cores * 131072))
        echo -e "${BLUE}[•] 应用CDN节点优化配置...${NC}"
        ;;
    "vpn")
        nofile_soft=$((mem_gb * 65536))
        nofile_hard=$((mem_gb * 131072))
        somaxconn=32768
        backlog=$((cpu_cores * 32768))
        echo -e "${BLUE}[•] 应用VPN服务器优化配置...${NC}"
        ;;
    *)
        nofile_soft=$((mem_gb * 32768))
        nofile_hard=$((mem_gb * 65536))
        somaxconn=16384
        backlog=$((cpu_cores * 16384))
        echo -e "${BLUE}[•] 应用通用服务器优化配置...${NC}"
        ;;
esac

# 限制值边界检查
[ "$nofile_soft" -lt 262144 ] && nofile_soft=262144
[ "$nofile_soft" -gt 2097152 ] && nofile_soft=2097152
[ "$nofile_hard" -gt 4194304 ] && nofile_hard=4194304

# 调整TCP/UDP缓冲区
case $SERVER_TYPE in
    "web"|"cdn")
        rmem_max=$((mem_gb * 2 * 1024 * 1024))
        wmem_max=$((mem_gb * 1024 * 1024))
        ;;
    "vpn")
        rmem_max=$((mem_gb * 1024 * 1024))
        wmem_max=$((mem_gb * 1024 * 1024))
        ;;
    *)
        rmem_max=$((mem_gb * 1024 * 1024))
        wmem_max=$((mem_gb * 1024 * 1024))
        ;;
esac

# 缓冲区大小边界检查
[ "$rmem_max" -gt 268435456 ] && rmem_max=268435456
[ "$rmem_max" -lt 16777216 ] && rmem_max=16777216
[ "$wmem_max" -gt 268435456 ] && wmem_max=268435456
[ "$wmem_max" -lt 16777216 ] && wmem_max=16777216

# Debian版本检测
debian_version=""
if [ -f /etc/debian_version ]; then
    debian_version=$(cat /etc/debian_version | cut -d. -f1)
    echo -e "${BLUE}[•] 检测到Debian系统，版本: ${debian_version}${NC}"
fi

# 确保内核模块加载
if [[ "$QOS_ALGO" == "cake" ]]; then
    echo -e "${BLUE}[•] 检查CAKE模块...${NC}"
    if ! lsmod | grep -q sch_cake; then
        echo -e "${YELLOW}⚠ 正在加载CAKE模块...${NC}"
        modprobe sch_cake 2>/dev/null || {
            echo -e "${RED}⚠ 无法加载sch_cake模块${NC}"
            echo -e "${YELLOW}尝试安装必要模块...${NC}"
            if command -v apt-get &>/dev/null; then
                if [[ "$debian_version" == "12" ]]; then
                    apt-get update -qq
                    apt-get install -y linux-modules-extra-$(uname -r) 2>/dev/null || 
                    apt-get install -y linux-image-$(uname -r) 2>/dev/null || true
                else
                    apt-get update -qq
                    apt-get install -y linux-modules-extra-$(uname -r) 2>/dev/null || true
                fi
            fi
            modprobe sch_cake 2>/dev/null || {
                echo -e "${RED}⚠ CAKE模块安装失败，切换备选方案${NC}"
                case $SERVER_TYPE in
                    "web"|"cdn") QOS_ALGO="fq_codel" ;;
                    "vpn") QOS_ALGO="fq_pie" ;;
                    *) QOS_ALGO="fq" ;;
                esac
                echo -e "${YELLOW}已切换到 $QOS_ALGO ${NC}"
            }
        }
    else
        echo -e "${GREEN}✓ CAKE模块已加载${NC}"
    fi
fi

# 备份原始配置
if [ -f /etc/sysctl.conf ]; then
    echo -e "${BLUE}[•] 备份原始配置...${NC}"
    cp /etc/sysctl.conf /etc/sysctl.conf.bak_$(date +%F_%T)
    
    # 清除旧设置
    sed -i '/# 内核:/d' /etc/sysctl.conf
    sed -i '/# 流量管理算法:/d' /etc/sysctl.conf
    sed -i '/# 服务器类型:/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.mptcp.enabled/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
    sed -i '/fs.inotify.max_user/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
fi

# 创建临时配置文件
echo -e "${BLUE}[•] 创建系统配置...${NC}"
TMP_SYSCTL="/tmp/sysctl_temp.conf"
cat > "$TMP_SYSCTL" <<EOF
# 内核: $kernel_version | XanMod: $is_xanmod | 内存: ${mem_gb}GB | CPU: ${cpu_cores}核
# 流量管理算法: $QOS_ALGO
# 服务器类型: $SERVER_TYPE

fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536
EOF

# 添加网络参数
if check_kernel_param "net.core.default_qdisc"; then
    echo "net.core.default_qdisc = $QOS_ALGO" >> "$TMP_SYSCTL"
    echo -e "${GREEN}✓ 设置队列算法: $QOS_ALGO${NC}"
else
    echo -e "${YELLOW}⚠ 内核不支持队列算法参数${NC}"
    echo -e "${YELLOW}⚠ 将使用tc命令设置${NC}"
fi

# XanMod内核优化
if [[ $is_xanmod -eq 1 ]]; then
    echo -e "${BLUE}[•] 应用XanMod内核优化...${NC}"
    
    if check_kernel_param "net.ipv4.tcp_congestion_control"; then
        echo "net.ipv4.tcp_congestion_control = bbr" >> "$TMP_SYSCTL"
        echo -e "${GREEN}✓ 设置BBR拥塞控制${NC}"
        
        if check_kernel_param "kernel.sched_autogroup_enabled"; then
            echo "kernel.sched_autogroup_enabled = 1" >> "$TMP_SYSCTL"
        fi
        
        echo "net.ipv4.tcp_notsent_lowat = 16384" >> "$TMP_SYSCTL"
        echo "net.ipv4.tcp_low_latency = 1" >> "$TMP_SYSCTL"
    fi
else
    if check_kernel_param "net.ipv4.tcp_congestion_control"; then
        if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ] && grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control; then
            echo "net.ipv4.tcp_congestion_control = bbr" >> "$TMP_SYSCTL"
            echo -e "${GREEN}✓ 设置BBR拥塞控制${NC}"
        else
            echo -e "${YELLOW}⚠ 内核不支持BBR，跳过${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ 内核不支持设置拥塞控制，跳过${NC}"
    fi
fi

# MPTCP支持检查
if [[ "$SERVER_TYPE" == "vpn" ]] && check_kernel_param "net.mptcp.enabled"; then
    echo "net.mptcp.enabled = 1" >> "$TMP_SYSCTL"
    echo "net.mptcp.pm_type = 0" >> "$TMP_SYSCTL"
    echo -e "${GREEN}✓ 启用MPTCP (VPN优化)${NC}"
elif check_kernel_param "net.mptcp.enabled"; then
    echo "net.mptcp.enabled = 1" >> "$TMP_SYSCTL"
    echo -e "${GREEN}✓ 启用MPTCP${NC}"
else
    echo -e "${YELLOW}⚠ 内核不支持MPTCP，跳过${NC}"
fi

# 添加通用参数
cat >> "$TMP_SYSCTL" <<EOF
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 8
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_slow_start_after_idle = 0
EOF

# 检查tcp_base_mss支持
if check_kernel_param "net.ipv4.tcp_base_mss"; then
    echo "net.ipv4.tcp_base_mss = 1024" >> "$TMP_SYSCTL"
fi

# Web/CDN特定参数
if [[ "$SERVER_TYPE" == "web" || "$SERVER_TYPE" == "cdn" ]]; then
    cat >> "$TMP_SYSCTL" <<EOF
# Web/CDN优化
net.ipv4.tcp_max_syn_backlog = $backlog
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_abort_on_overflow = 0
net.ipv4.ip_local_port_range = 1024 65535
EOF
fi

# VPN特定参数
if [[ "$SERVER_TYPE" == "vpn" ]]; then
    cat >> "$TMP_SYSCTL" <<EOF
# VPN优化
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.tcp_max_tw_buckets = 1000000
net.ipv4.tcp_max_orphans = 400000
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.netfilter.nf_conntrack_max = 1048576
EOF

    # 加载VPN相关模块
    if ! lsmod | grep -q ip_conntrack; then
        modprobe ip_conntrack 2>/dev/null || modprobe nf_conntrack 2>/dev/null
    fi
    
    # 检查conntrack配置
    if [ -d /proc/sys/net/netfilter ]; then
        echo "net.netfilter.nf_conntrack_max = 1048576" >> "$TMP_SYSCTL"
        echo "net.netfilter.nf_conntrack_tcp_timeout_established = 7200" >> "$TMP_SYSCTL"
        echo "net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30" >> "$TMP_SYSCTL"
    fi
fi

# 添加通用网络参数
cat >> "$TMP_SYSCTL" <<EOF
net.core.somaxconn = $somaxconn
net.core.netdev_max_backlog = $backlog

net.ipv4.tcp_rmem = 8192 262144 $rmem_max
net.ipv4.tcp_wmem = 8192 262144 $wmem_max
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.core.optmem_max = 131072

net.ipv4.udp_mem = $((rmem_max/2)) $rmem_max $((rmem_max*2))
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
EOF

# 检查IPv6支持
if [ -d /proc/sys/net/ipv6 ]; then
    echo "net.ipv6.conf.all.forwarding = 1" >> "$TMP_SYSCTL"
    echo "net.ipv6.conf.default.forwarding = 1" >> "$TMP_SYSCTL"
else
    echo -e "${YELLOW}⚠ 未启用IPv6支持，跳过IPv6设置${NC}"
fi

# 安全相关设置
cat >> "$TMP_SYSCTL" <<EOF
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1

net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
EOF

# IPv6邻居设置
if [ -d /proc/sys/net/ipv6 ]; then
    cat >> "$TMP_SYSCTL" <<EOF
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 16384
EOF
fi

# TCP优化
cat >> "$TMP_SYSCTL" <<EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_moderate_rcvbuf = 1

net.ipv4.conf.default.route_localnet = 1
net.ipv4.conf.all.route_localnet = 1
EOF

# 复制到最终配置
cp "$TMP_SYSCTL" /etc/sysctl.conf
rm "$TMP_SYSCTL"

# 应用配置
echo -e "${BLUE}[•] 应用sysctl配置...${NC}"
sysctl --system -e || true

# 使用tc命令设置队列算法
if ! check_kernel_param "net.core.default_qdisc"; then
    # 安装iproute2
    if ! command -v tc &>/dev/null; then
        echo -e "${YELLOW}⚠ 未找到tc命令，安装iproute2...${NC}"
        apt-get update -qq
        apt-get install -y iproute2
    fi
    
    # 获取所有网络接口
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1)
    for iface in $interfaces; do
        if [[ "$iface" != "lo" && "$iface" != "" ]]; then
            echo -e "${BLUE}[•] 在接口 $iface 上设置 $QOS_ALGO 队列算法${NC}"
            tc qdisc replace dev $iface root $QOS_ALGO 2>/dev/null || true
        fi
    done
fi

# 设置系统资源限制
echo -e "${BLUE}[•] 设置系统资源限制...${NC}"
# 备份原始文件
if [ -f /etc/security/limits.conf ]; then
    cp /etc/security/limits.conf /etc/security/limits.conf.bak_$(date +%F_%T)
fi

# 清除旧设置
if [ -f /etc/security/limits.conf ]; then
    sed -i '/^* soft nofile/d' /etc/security/limits.conf
    sed -i '/^* hard nofile/d' /etc/security/limits.conf
    sed -i '/^* soft nproc/d' /etc/security/limits.conf
    sed -i '/^* hard nproc/d' /etc/security/limits.conf
    sed -i '/^* soft core/d' /etc/security/limits.conf
    sed -i '/^* hard core/d' /etc/security/limits.conf
    sed -i '/^* soft memlock/d' /etc/security/limits.conf
    sed -i '/^* hard memlock/d' /etc/security/limits.conf
fi

# 写入新设置
cat > /etc/security/limits.conf <<EOF
* soft nofile $nofile_soft
* hard nofile $nofile_hard
* soft nproc $nofile_soft
* hard nproc $nofile_hard
* soft core unlimited
* hard core unlimited
* soft memlock unlimited
* hard memlock unlimited
EOF

# 确保PAM模块加载limits
for pam_file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    if [ -f "$pam_file" ]; then
        grep -q pam_limits.so "$pam_file" || echo "session required pam_limits.so" >> "$pam_file"
    fi
done

# systemd资源限制
if [ -d /etc/systemd ]; then
    echo -e "${BLUE}[•] 设置systemd默认资源限制...${NC}"
    if [ -f /etc/systemd/system.conf ]; then
        # 备份原始文件
        cp /etc/systemd/system.conf /etc/systemd/system.conf.bak_$(date +%F_%T)
        
        # 清除旧设置
        sed -i '/DefaultLimitCORE\|DefaultLimitNOFILE\|DefaultLimitNPROC/d' /etc/systemd/system.conf
        
        # 写入新设置
        cat >> /etc/systemd/system.conf <<EOF
[Manager]
DefaultLimitCORE=infinity
DefaultLimitNOFILE=$nofile_hard
DefaultLimitNPROC=$nofile_hard
EOF
        systemctl daemon-reexec
    else
        echo -e "${YELLOW}⚠ 未找到systemd配置，跳过${NC}"
    fi
fi

# 设置当前shell的ulimit
echo -e "${BLUE}[•] 设置当前会话限制...${NC}"
current_max=$(ulimit -Hn)
if [ "$nofile_hard" -le "$current_max" ]; then
    ulimit -n "$nofile_hard" 2>/dev/null || echo -e "${YELLOW}⚠ 无法设置会话限制${NC}"
else
    echo -e "${YELLOW}⚠ 当前限制为 $current_max，已跳过设置更高的值${NC}"
    echo -e "${YELLOW}⚠ 请重启系统或重新登录使设置生效${NC}"
fi

ulimit -c unlimited 2>/dev/null || true
if command -v prlimit &>/dev/null; then
    prlimit --pid $ --nofile="$nofile_hard":"$nofile_hard" 2>/dev/null || true
fi

# 创建系统服务确保配置持久化
echo -e "${BLUE}[•] 创建系统服务确保配置持久化...${NC}"
if [[ -d /etc/systemd/system ]]; then
    if [ -f /etc/systemd/system/apply-sysctl.service ]; then
        echo -e "${BLUE}[•] 更新apply-sysctl服务...${NC}"
        systemctl disable apply-sysctl.service 2>/dev/null || true
        rm /etc/systemd/system/apply-sysctl.service
    fi
    
    cat > /etc/systemd/system/apply-sysctl.service <<EOF
[Unit]
Description=应用sysctl设置和网络队列管理
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'sysctl --system; for iface in \$(ip -o link show | grep -v "lo" | awk -F": " \'{print \$2}\' | cut -d@ -f1); do [[ -n "\$iface" ]] && tc qdisc replace dev \$iface root $QOS_ALGO 2>/dev/null || true; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable apply-sysctl.service
    systemctl start apply-sysctl.service || true
    echo -e "${GREEN}✓ 创建服务apply-sysctl.service${NC}"
fi

# 创建rc.local脚本作为备份
if [ ! -f /etc/rc.local ] || ! grep -q "exit 0" /etc/rc.local; then
    echo -e "${BLUE}[•] 创建rc.local备份启动脚本...${NC}"
    
    # 备份原始文件
    if [ -f /etc/rc.local ]; then
        cp /etc/rc.local /etc/rc.local.bak_$(date +%F_%T)
    fi
    
    # 删除旧设置
    if [ -f /etc/rc.local ]; then
        sed -i '/tc qdisc replace/d' /etc/rc.local
        sed -i '/# 设置队列管理/d' /etc/rc.local
        sed -i '/# 应用sysctl设置/d' /etc/rc.local
        sed -i '/\/sbin\/sysctl --system/d' /etc/rc.local
    fi
    
    # 创建新rc.local
    cat > /etc/rc.local <<EOF
#!/bin/bash
# 网络优化配置

# 应用sysctl设置
/sbin/sysctl --system

# 设置队列管理
for iface in \$(ip -o link show | grep -v "lo" | awk -F": " '{print \$2}' | cut -d@ -f1); do
    [[ -n "\$iface" ]] && tc qdisc replace dev \$iface root $QOS_ALGO 2>/dev/null || true
done

exit 0
EOF
    chmod +x /etc/rc.local
    echo -e "${GREEN}✓ 创建rc.local保障${NC}"
    
    # 对于systemd系统，启用rc-local服务
    if [ -d /etc/systemd/system ] && ! systemctl is-enabled rc-local.service &>/dev/null; then
        if [ ! -f /etc/systemd/system/rc-local.service ]; then
            cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local兼容性支持
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable rc-local.service
        fi
    fi
fi

# 服务器类型特定优化
case $SERVER_TYPE in
    "web")
        echo -e "${BLUE}[•] 应用Web服务器额外优化...${NC}"
        
        # 文件系统优化建议
        if grep -q ext4 /etc/mtab; then
            echo -e "${YELLOW}建议: 对Web内容分区添加noatime选项${NC}"
            echo -e "${YELLOW}       可在/etc/fstab中添加noatime,commit=30选项${NC}"
        fi
        
        # Nginx优化建议
        if command -v nginx &>/dev/null; then
            echo -e "${YELLOW}Nginx推荐设置:${NC}"
            echo -e "${YELLOW}  worker_processes: ${cpu_cores}${NC}"
            echo -e "${YELLOW}  worker_connections: $((nofile_soft / cpu_cores / 2))${NC}"
            echo -e "${YELLOW}  worker_rlimit_nofile $nofile_soft;${NC}"
            echo -e "${YELLOW}  use epoll;${NC}"
            echo -e "${YELLOW}  multi_accept on;${NC}"
        fi
        ;;
        
    "cdn")
        echo -e "${BLUE}[•] 应用CDN节点额外优化...${NC}"
        
        # 磁盘I/O调度器优化
        for disk in $(lsblk -d -o NAME | grep -v NAME); do
            if [ -f "/sys/block/$disk/queue/scheduler" ]; then
                echo -e "${BLUE}[•] 设置磁盘 $disk 的I/O调度器...${NC}"
                
                if grep -q "deadline" /sys/block/$disk/queue/scheduler; then
                    echo deadline > /sys/block/$disk/queue/scheduler
                    echo -e "${GREEN}✓ 设置 $disk 为deadline${NC}"
                elif grep -q "none" /sys/block/$disk/queue/scheduler; then
                    echo none > /sys/block/$disk/queue/scheduler
                    echo -e "${GREEN}✓ 设置 $disk 为none${NC}"
                else
                    echo -e "${YELLOW}⚠ 无法设置 $disk 调度器，可用选项:${NC}"
                    cat /sys/block/$disk/queue/scheduler
                fi
                
                # 设置预读缓冲
                if [ -f "/sys/block/$disk/queue/read_ahead_kb" ]; then
                    echo 4096 > /sys/block/$disk/queue/read_ahead_kb
                    echo -e "${GREEN}✓ 设置 $disk 读预读为4096KB${NC}"
                fi
            fi
        done
        
        # IO参数优化
        if [ -f /proc/sys/vm/dirty_ratio ]; then
            echo 15 > /proc/sys/vm/dirty_ratio
            echo 5 > /proc/sys/vm/dirty_background_ratio
            echo 500 > /proc/sys/vm/dirty_writeback_centisecs
            echo -e "${GREEN}✓ 优化VM脏页参数${NC}"
        fi
        ;;
        
    "vpn")
        echo -e "${BLUE}[•] 应用VPN服务器额外优化...${NC}"
        
        # 加载NAT模块
        for module in nf_conntrack nf_conntrack_ipv4 nf_nat iptable_nat ip_tables; do
            if ! lsmod | grep -q $module; then
                echo -e "${BLUE}[•] 加载模块 $module...${NC}"
                modprobe $module 2>/dev/null || echo -e "${YELLOW}⚠ 无法加载 $module${NC}"
            fi
        done
        
        # NAT规则建议
        echo -e "${YELLOW}建议: 为VPN服务器配置NAT规则，例如:${NC}"
        echo -e "${YELLOW}  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE${NC}"
        echo -e "${YELLOW}  iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT${NC}"
        echo -e "${YELLOW}  iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT${NC}"
        
        # TLS硬件加速检查
        if grep -q aes /proc/cpuinfo; then
            echo -e "${GREEN}✓ 检测到AES-NI CPU支持${NC}"
            if command -v openssl &>/dev/null; then
                openssl_engines=$(openssl engine 2>/dev/null)
                if echo "$openssl_engines" | grep -q aesni; then
                    echo -e "${GREEN}✓ OpenSSL已支持AES-NI加速${NC}"
                else
                    echo -e "${YELLOW}⚠ OpenSSL可能未启用硬件加速${NC}"
                fi
            fi
        fi
        ;;
        
    *)
        # 通用服务器优化
        echo -e "${BLUE}[•] 应用通用服务器优化...${NC}"
        ;;
esac

# 验证设置生效
verify_settings() {
    echo -e "${BLUE}[•] 验证配置是否生效...${NC}"
    
    # 检查队列算法
    current_qdisc=$(tc qdisc show | grep -v "pfifo_fast" | head -n1)
    if [[ -z "$current_qdisc" ]]; then
        echo -e "${YELLOW}⚠ 未检测到队列规则，可能需要重启${NC}"
    else
        echo -e "${GREEN}✓ 队列规则已设置: $current_qdisc${NC}"
    fi
    
    # 检查文件描述符限制
    current_fd=$(ulimit -n)
    if [[ $current_fd -lt $nofile_soft ]]; then
        echo -e "${YELLOW}⚠ 当前文件描述符限制($current_fd)小于设定值($nofile_soft)${NC}"
    else
        echo -e "${GREEN}✓ 文件描述符限制: $current_fd${NC}"
    fi
    
    # 验证TCP参数
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
    if [[ "$current_cc" == "bbr" || "$current_cc" == "bbr2" || "$current_cc" == "bbr3" ]]; then
        echo -e "${GREEN}✓ BBR已启用: $current_cc${NC}"
    else
        echo -e "${YELLOW}⚠ 未检测到BBR: 当前使用 $current_cc${NC}"
    fi
    
    # 检查TCP Fast Open
    tcp_fastopen=$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo "0")
    if [[ "$tcp_fastopen" -ge "1" ]]; then
        echo -e "${GREEN}✓ TCP Fast Open已启用${NC}"
    else
        echo -e "${YELLOW}⚠ TCP Fast Open未启用${NC}"
    fi
    
    # 检查服务是否已启用
    if systemctl is-enabled apply-sysctl.service &>/dev/null; then
        echo -e "${GREEN}✓ apply-sysctl.service已启用${NC}"
    else
        echo -e "${YELLOW}⚠ apply-sysctl.service未启用${NC}"
    fi
    
    # 检查服务器类型特定配置
    case $SERVER_TYPE in
        "web")
            somaxconn=$(sysctl -n net.core.somaxconn 2>/dev/null || echo "0")
            if [[ "$somaxconn" -ge "16384" ]]; then
                echo -e "${GREEN}✓ Web服务器连接队列已优化: $somaxconn${NC}"
            else
                echo -e "${YELLOW}⚠ Web服务器连接队列可能未优化: $somaxconn${NC}"
            fi
            ;;
        "cdn")
            dirty_ratio=$(cat /proc/sys/vm/dirty_ratio 2>/dev/null || echo "0")
            if [[ "$dirty_ratio" -eq "15" ]]; then
                echo -e "${GREEN}✓ CDN节点I/O参数已优化${NC}"
            else
                echo -e "${YELLOW}⚠ CDN节点I/O参数可能未优化${NC}"
            fi
            ;;
        "vpn")
            ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
            if [[ "$ip_forward" -eq "1" ]]; then
                echo -e "${GREEN}✓ VPN服务器IP转发已启用${NC}"
            else
                echo -e "${YELLOW}⚠ VPN服务器IP转发未启用${NC}"
            fi
            
            if lsmod | grep -q nf_conntrack; then
                echo -e "${GREEN}✓ VPN服务器连接跟踪模块已加载${NC}"
            else
                echo -e "${YELLOW}⚠ VPN服务器连接跟踪模块未加载${NC}"
            fi
            ;;
    esac
}

# 执行验证
verify_settings

# 输出最终结果
echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         ${GREEN}系统优化完成报告${BLUE}             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo -e "${GREEN}✓ 服务器类型   :${NC} $SERVER_TYPE"
echo -e "${GREEN}✓ 内核版本     :${NC} $kernel_version"
echo -e "${GREEN}✓ 内存         :${NC} ${mem_gb} GB"
echo -e "${GREEN}✓ CPU核心      :${NC} ${cpu_cores} 核"
echo -e "${GREEN}✓ 流量管理算法 :${NC} ${QOS_ALGO}"
echo -e "${GREEN}✓ 文件描述符   :${NC} soft=$nofile_soft, hard=$nofile_hard"
echo -e "${GREEN}✓ TCP缓冲上限  :${NC} $rmem_max 字节 ($((rmem_max/1024/1024))MB)"

if grep -q "tcp_congestion_control = bbr" /etc/sysctl.conf; then
    if [[ $is_xanmod -eq 1 ]]; then
        echo -e "${GREEN}✓ BBR拥塞控制  :${NC} 已启用 (XanMod自动选择最佳版本)"
    else
        echo -e "${GREEN}✓ BBR拥塞控制  :${NC} 已启用"
    fi
else
    echo -e "${YELLOW}⚠ BBR拥塞控制  :${NC} 未启用"
fi

# 服务器类型特定信息
case $SERVER_TYPE in
    "web")
        echo -e "${GREEN}✓ Web服务器优化:${NC} 高并发连接、低延迟"
        ;;
    "cdn")
        echo -e "${GREEN}✓ CDN节点优化  :${NC} 大缓冲区、I/O优化、高吞吐量"
        ;;
    "vpn")
        echo -e "${GREEN}✓ VPN服务器优化:${NC} NAT转发、连接跟踪"
        ;;
    *)
        echo -e "${GREEN}✓ 通用服务器   :${NC} 均衡性能配置"
        ;;
esac

echo -e "\n${YELLOW}验证配置命令:${NC}"
echo -e "  • ${CYAN}文件描述符限制: ${NC}ulimit -n"
echo -e "  • ${CYAN}TCP配置:        ${NC}sysctl -a | grep tcp"
echo -e "  • ${CYAN}队列策略:       ${NC}tc qdisc show"
echo -e "  • ${CYAN}最大连接数:     ${NC}sysctl net.core.somaxconn"

echo -e "\n${YELLOW}提示: 重启系统使所有设置完全生效${NC}"

# XanMod内核特别提示
if [[ $is_xanmod -eq 1 ]]; then
    echo -e "${GREEN}✓ 检测到XanMod内核，已应用特定优化:${NC}"
    echo -e "  • ${CYAN}BBR自动使用最佳版本${NC}"
    echo -e "  • ${CYAN}已启用积极网络参数${NC}"
fi

# Debian 12特别提示
if [[ "$debian_version" == "12" ]]; then
    echo -e "${GREEN}✓ 检测到Debian 12，已应用特定优化${NC}"
fi

# 脚本完成
echo -e "\n${GREEN}脚本执行完成！配置已应用并设置为启动时自动加载${NC}"
echo -e "${YELLOW}建议重启系统以确保所有优化生效${NC}
