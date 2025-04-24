#!/bin/bash
set -euo pipefail

# ====== 颜色定义 ======
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
NC='\033[0m'

# 有效的流量管理算法列表
valid_qos=("fq" "fq_codel" "fq_pie" "fq_cake" "cake" "pfifo_fast" "sfq" "red" "tbf")
QOS_ALGO="fq"  # 默认使用fq

# 流量管理算法详细说明
qos_descriptions=(
    "fq:            公平队列算法，提供基本的公平性和低延迟，适合大多数家庭和小型办公室环境。优点是实现简单，CPU开销低。"
    "fq_codel:      结合了公平队列和CoDel算法，主动管理缓冲区以减少延迟，适合在线游戏、视频会议等需要低延迟的场景。"
    "fq_pie:        使用比例积分增强型算法，在高负载下比fq_codel更稳定，适合带宽波动大的场景。"
    "fq_cake:       CAKE算法的公平队列版本，提供更精细的流量控制和带宽共享，适合复杂网络环境。"
    "cake:          综合自适应队列管理，具有带宽整形、公平排队和主动队列管理功能，最适合家庭路由器和小型服务器。"
    "pfifo_fast:    Linux的默认队列管理，基于数据包优先级的简单FIFO队列，适合低负载环境。"
    "sfq:           随机公平队列，通过哈希算法分配流量，防止单个连接占用所有带宽，适合低端设备。"
    "red:           随机早期检测，主动丢弃数据包以防止网络拥塞，适合高流量路由器但可能增加CPU负载。"
    "tbf:           令牌桶过滤器，精确控制带宽使用率，适合需要严格带宽限制的场景，如流量计费环境。"
)

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误: 此脚本必须以root用户运行${NC}"
   exit 1
fi

# 检查内核是否支持特定参数
check_kernel_param() {
  local param="$1"
  if sysctl -q "$param" &>/dev/null; then
    return 0  # 参数存在
  else
    return 1  # 参数不存在
  fi
}

# 显示QoS算法详细说明
display_qos_details() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║             ${GREEN}流量管理算法详细说明${BLUE}                      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    
    for desc in "${qos_descriptions[@]}"; do
        IFS=':' read -r algo explanation <<< "$desc"
        echo -e "${GREEN}$(printf "%-12s" "$algo")${NC} ${YELLOW}$explanation${NC}"
    done
    
    echo -e "${BLUE}────────────────────────────────────────────────────────${NC}"
    echo -e "${CYAN}选择合适的算法可以显著提升网络性能和体验${NC}"
    
    # 根据系统配置提供推荐
    if [[ $mem_gb -lt 2 ]]; then
        echo -e "${YELLOW}⚠ 低内存系统推荐: fq, sfq, pfifo_fast${NC}"
    elif [[ $is_xanmod -eq 1 ]]; then
        echo -e "${GREEN}✓ XanMod内核推荐: fq_cake, cake, fq_codel${NC}"
    elif [[ $cpu_cores -gt 4 ]]; then
        echo -e "${GREEN}✓ 多核系统推荐: cake, fq_cake, fq_codel${NC}"
    else
        echo -e "${GREEN}✓ 通用系统推荐: fq, fq_codel${NC}"
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
        --help|-h)
            echo -e "${GREEN}用法: $0 [选项]${NC}"
            echo -e "${GREEN}选项:${NC}"
            echo -e "  ${YELLOW}--qos, -q${NC} \t指定流量管理算法(fq, fq_codel, fq_pie, fq_cake等), 默认为fq"
            echo -e "  ${YELLOW}--help, -h${NC} \t显示此帮助信息"
            echo -e "\n如果不指定参数，脚本将以交互方式让您选择流量管理算法"
            exit 0
            ;;
        *)
            echo -e "${RED}错误: 未知参数 $1${NC}"
            echo -e "${YELLOW}使用 -h 或 --help 查看帮助${NC}"
            exit 1
            ;;
    esac
done

# 如果没有通过参数指定算法，提供交互式选择
if [[ -z "${QOS_ALGO:-}" || "$QOS_ALGO" == "fq" ]]; then
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║             ${GREEN}系统网络流量管理算法优化${BLUE}                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo -e "\n${CYAN}请选择流量管理算法:${NC}"
    echo -e "  ${GREEN}1)${NC} fq\t\t${YELLOW}[默认] 基本公平队列，适合大多数场景${NC}"
    echo -e "  ${GREEN}2)${NC} fq_codel\t${YELLOW}控制延迟的公平队列，减少缓冲膨胀${NC}"
    echo -e "  ${GREEN}3)${NC} fq_pie\t${YELLOW}比例积分控制器公平队列${NC}"
    echo -e "  ${GREEN}4)${NC} fq_cake\t${YELLOW}高级功能全面的队列管理算法，推荐服务器使用${NC}"
    echo -e "  ${GREEN}5)${NC} cake\t\t${YELLOW}综合自动网络队列管理${NC}"
    echo -e "  ${GREEN}6)${NC} pfifo_fast\t${YELLOW}传统优先级队列${NC}"
    echo -e "  ${GREEN}7)${NC} sfq\t\t${YELLOW}随机公平队列${NC}"
    echo -e "  ${GREEN}8)${NC} red\t\t${YELLOW}随机早期检测队列${NC}"
    echo -e "  ${GREEN}9)${NC} tbf\t\t${YELLOW}令牌桶过滤器${NC}"
    echo -e "  ${GREEN}10)${NC} 查看详细算法说明"
    echo -e "\n  ${GREEN}0)${NC} 退出脚本"
    
    read -p "$(echo -e ${YELLOW}"请输入选项 [0-10] (默认: 1): "${NC})" qos_choice
    
    # 设置默认选项
    qos_choice=${qos_choice:-1}
    
    case $qos_choice in
        1) QOS_ALGO="fq" ;;
        2) QOS_ALGO="fq_codel" ;;
        3) QOS_ALGO="fq_pie" ;;
        4) QOS_ALGO="fq_cake" ;;
        5) QOS_ALGO="cake" ;;
        6) QOS_ALGO="pfifo_fast" ;;
        7) QOS_ALGO="sfq" ;;
        8) QOS_ALGO="red" ;;
        9) QOS_ALGO="tbf" ;;
        10) 
            display_qos_details
            echo ""
            echo -e "${CYAN}请再次选择流量管理算法:${NC}"
            read -p "$(echo -e ${YELLOW}"请输入选项 [1-9] (默认: 1): "${NC})" qos_choice
            qos_choice=${qos_choice:-1}
            case $qos_choice in
                1) QOS_ALGO="fq" ;;
                2) QOS_ALGO="fq_codel" ;;
                3) QOS_ALGO="fq_pie" ;;
                4) QOS_ALGO="fq_cake" ;;
                5) QOS_ALGO="cake" ;;
                6) QOS_ALGO="pfifo_fast" ;;
                7) QOS_ALGO="sfq" ;;
                8) QOS_ALGO="red" ;;
                9) QOS_ALGO="tbf" ;;
                *) echo -e "${RED}无效选择，使用默认值 'fq'${NC}"; QOS_ALGO="fq" ;;
            esac
            ;;
        0) echo -e "${YELLOW}已取消操作。${NC}"; exit 0 ;;
        *) echo -e "${RED}无效选择，使用默认值 'fq'${NC}"; QOS_ALGO="fq" ;;
    esac
    
    echo -e "${GREEN}已选择: ${CYAN}$QOS_ALGO${NC}"
    echo ""
fi

# 验证QOS算法是否有效
qos_valid=0
for qos in "${valid_qos[@]}"; do
    if [[ "$QOS_ALGO" == "$qos" ]]; then
        qos_valid=1
        break
    fi
done

if [[ $qos_valid -eq 0 ]]; then
    echo -e "${RED}错误: 无效的流量管理算法 '$QOS_ALGO'${NC}"
    echo -e "${YELLOW}有效的选项: ${valid_qos[*]}${NC}"
    exit 1
fi

echo -e "${BLUE}[•] 正在运行智能适配系统优化... (流量管理算法: $QOS_ALGO)${NC}"

# 计算资源限制
nofile_soft=$((mem_gb * 32768))
nofile_hard=$((mem_gb * 65536))
[ "$nofile_soft" -lt 262144 ] && nofile_soft=262144
[ "$nofile_soft" -gt 1048576 ] && nofile_soft=1048576
[ "$nofile_hard" -gt 2097152 ] && nofile_hard=2097152

rmem_max=$((mem_gb * 1024 * 1024))
[ "$rmem_max" -gt 134217728 ] && rmem_max=134217728
[ "$rmem_max" -lt 16777216 ] && rmem_max=16777216

# Debian版本检测
debian_version=""
if [ -f /etc/debian_version ]; then
    debian_version=$(cat /etc/debian_version | cut -d. -f1)
    echo -e "${BLUE}[•] 检测到Debian系统，版本: ${debian_version}${NC}"
fi

# 确保内核模块加载
if [[ "$QOS_ALGO" == "fq_cake" || "$QOS_ALGO" == "cake" ]]; then
    echo -e "${BLUE}[•] 检查 CAKE 队列管理模块...${NC}"
    if ! lsmod | grep -q sch_cake; then
        echo -e "${YELLOW}⚠ 正在加载 CAKE 队列管理模块...${NC}"
        modprobe sch_cake 2>/dev/null || {
            echo -e "${RED}⚠ 无法加载 sch_cake 模块，请检查内核是否支持${NC}"
            echo -e "${YELLOW}尝试安装必要的内核模块...${NC}"
            if command -v apt-get &>/dev/null; then
                # 针对Debian 12添加特殊处理
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
                echo -e "${RED}⚠ CAKE 模块安装失败，切换到 fq 作为备选方案${NC}"
                QOS_ALGO="fq"
            }
        }
    else
        echo -e "${GREEN}✓ CAKE 队列管理模块已加载${NC}"
    fi
fi

# 备份原始配置并清理旧设置
if [ -f /etc/sysctl.conf ]; then
    echo -e "${BLUE}[•] 备份原始配置...${NC}"
    cp /etc/sysctl.conf /etc/sysctl.conf.bak_$(date +%F_%T)
    
    # 清除旧的自定义设置，避免重复
    sed -i '/# 内核:/d' /etc/sysctl.conf
    sed -i '/# 流量管理算法:/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.mptcp.enabled/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
    sed -i '/fs.inotify.max_user/d' /etc/sysctl.conf
fi

# 写入优化配置
echo -e "${BLUE}[•] 创建与检查系统兼容的配置...${NC}"

# 创建临时配置文件
TMP_SYSCTL="/tmp/sysctl_temp.conf"
cat > "$TMP_SYSCTL" <<EOF
# 内核: $kernel_version | XanMod: $is_xanmod | 内存: ${mem_gb}GB | CPU: ${cpu_cores}核
# 流量管理算法: $QOS_ALGO

fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536
EOF

# 检查并添加网络参数
if check_kernel_param "net.core.default_qdisc"; then
    echo "net.core.default_qdisc = $QOS_ALGO" >> "$TMP_SYSCTL"
    echo -e "${GREEN}✓ 设置 net.core.default_qdisc = $QOS_ALGO${NC}"
else
    echo -e "${YELLOW}⚠ 您的内核不支持 net.core.default_qdisc 参数${NC}"
    echo -e "${YELLOW}⚠ 将使用 tc 命令直接设置队列管理算法${NC}"
    # 在后面使用 tc 命令设置
fi

# XanMod内核特定优化
if [[ $is_xanmod -eq 1 ]]; then
    echo -e "${BLUE}[•] 检测到XanMod内核，应用特定优化...${NC}"
    
    # 检查拥塞控制算法支持
    if check_kernel_param "net.ipv4.tcp_congestion_control"; then
        # XanMod内核直接使用bbr, XanMod会自动选择最佳版本
        echo "net.ipv4.tcp_congestion_control = bbr" >> "$TMP_SYSCTL"
        echo -e "${GREEN}✓ 设置 BBR 拥塞控制算法 (XanMod内核)${NC}"
        
        # XanMod特有优化
        if check_kernel_param "kernel.sched_autogroup_enabled"; then
            echo "kernel.sched_autogroup_enabled = 1" >> "$TMP_SYSCTL"
        fi
        
        # 更激进的网络参数
        echo "net.ipv4.tcp_notsent_lowat = 16384" >> "$TMP_SYSCTL"
        echo "net.ipv4.tcp_low_latency = 1" >> "$TMP_SYSCTL"
    fi
else
    # 检查 BBR 支持
    if check_kernel_param "net.ipv4.tcp_congestion_control"; then
        # 检查系统是否支持BBR
        if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ] && grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control; then
            echo "net.ipv4.tcp_congestion_control = bbr" >> "$TMP_SYSCTL"
            echo -e "${GREEN}✓ 设置 BBR 拥塞控制算法${NC}"
        else
            echo -e "${YELLOW}⚠ 您的内核不支持 BBR 拥塞控制算法，跳过${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ 您的内核不支持设置拥塞控制算法，跳过${NC}"
    fi
fi

# 检查 MPTCP 支持
if check_kernel_param "net.mptcp.enabled"; then
    echo "net.mptcp.enabled = 1" >> "$TMP_SYSCTL"
    echo -e "${GREEN}✓ 启用 MPTCP 多路径传输${NC}"
else
    echo -e "${YELLOW}⚠ 您的内核不支持 MPTCP，跳过${NC}"
fi

# 添加其他通用参数
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

# 检查是否支持 tcp_base_mss
if check_kernel_param "net.ipv4.tcp_base_mss"; then
    echo "net.ipv4.tcp_base_mss = 1024" >> "$TMP_SYSCTL"
fi

cat >> "$TMP_SYSCTL" <<EOF
net.ipv4.tcp_max_syn_backlog = $((cpu_cores * 65536 < 524288 ? cpu_cores * 65536 : 524288))
net.core.somaxconn = 65535
net.core.netdev_max_backlog = $((cpu_cores * 65536 < 524288 ? cpu_cores * 65536 : 524288))

net.ipv4.tcp_rmem = 8192 262144 $rmem_max
net.ipv4.tcp_wmem = 8192 262144 $rmem_max
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = $rmem_max
net.core.wmem_max = $rmem_max
net.core.optmem_max = 65536

net.ipv4.udp_mem = $((rmem_max/2)) $rmem_max $((rmem_max*2))
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
EOF

# 检查IPv6支持
if [ -d /proc/sys/net/ipv6 ]; then
    echo "net.ipv6.conf.all.forwarding = 1" >> "$TMP_SYSCTL"
else
    echo -e "${YELLOW}⚠ 系统未启用 IPv6 支持，跳过 IPv6 设置${NC}"
fi

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

# 检查IPv6支持
if [ -d /proc/sys/net/ipv6 ]; then
    cat >> "$TMP_SYSCTL" <<EOF
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 16384
EOF
fi

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

# 应用 sysctl 配置（忽略错误）
echo -e "${BLUE}[•] 应用 sysctl 配置...${NC}"
sysctl --system -e || true

# 使用 tc 命令直接设置队列管理算法（作为备选方案）
if ! check_kernel_param "net.core.default_qdisc"; then
    # Debian可能需要安装iproute2
    if ! command -v tc &>/dev/null; then
        echo -e "${YELLOW}⚠ 未找到 tc 命令，尝试安装 iproute2 包...${NC}"
        apt-get update -qq
        apt-get install -y iproute2
    fi
    
    # 获取所有网络接口
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1)
    for iface in $interfaces; do
        if [[ "$iface" != "lo" && "$iface" != "" ]]; then
            echo -e "${BLUE}[•] 在接口 $iface 上设置 $QOS_ALGO 队列管理算法${NC}"
            tc qdisc replace dev $iface root $QOS_ALGO 2>/dev/null || true
        fi
    done
fi

# 设置 limits.conf
echo -e "${BLUE}[•] 设置系统资源限制...${NC}"
# 备份原始文件
if [ -f /etc/security/limits.conf ]; then
    cp /etc/security/limits.conf /etc/security/limits.conf.bak_$(date +%F_%T)
fi

# 清除旧的设置
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

# systemd 资源限制
if [ -d /etc/systemd ]; then
    echo -e "${BLUE}[•] 设置systemd默认资源限制...${NC}"
    if [ -f /etc/systemd/system.conf ]; then
        # 备份原始文件
        cp /etc/systemd/system.conf /etc/systemd/system.conf.bak_$(date +%F_%T)
        
        # 清除旧的设置
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
        echo -e "${YELLOW}⚠ 未找到 /etc/systemd/system.conf，跳过 systemd 资源限制设置${NC}"
    fi
fi

# 安全设置 ulimit，避免超过当前 shell 上限
echo -e "${BLUE}[•] 设置当前会话文件描述符限制...${NC}"
current_max=$(ulimit -Hn)
if [ "$nofile_hard" -le "$current_max" ]; then
    ulimit -n "$nofile_hard" 2>/dev/null || echo -e "${YELLOW}⚠ 无法设置当前会话文件描述符限制${NC}"
else
    echo -e "${YELLOW}⚠ 当前 shell 会话最大 open files 限制为 $current_max，已跳过设置更高的 ulimit。${NC}"
    echo -e "${YELLOW}⚠ 请重启系统或重新登录以使更高 limits.conf 生效。${NC}"
fi

ulimit -c unlimited 2>/dev/null || true
if command -v prlimit &>/dev/null; then
    prlimit --pid $$ --nofile="$nofile_hard":"$nofile_hard" 2>/dev/null || true
fi

# 创建启动脚本确保 sysctl 设置持久化
echo -e "${BLUE}[•] 创建系统服务确保配置持久化...${NC}"
if [[ -d /etc/systemd/system ]]; then
    # 检查是否已存在，避免重复创建
    if [ -f /etc/systemd/system/apply-sysctl.service ]; then
# 检查是否已存在，避免重复创建
    if [ -f /etc/systemd/system/apply-sysctl.service ]; then
        echo -e "${BLUE}[•] 更新已存在的 apply-sysctl 服务...${NC}"
        systemctl disable apply-sysctl.service 2>/dev/null || true
        rm /etc/systemd/system/apply-sysctl.service
    fi
    
    cat > /etc/systemd/system/apply-sysctl.service <<EOF
[Unit]
Description=Apply sysctl settings and network queue management
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
    echo -e "${GREEN}✓ 创建系统服务 apply-sysctl.service 确保重启后设置生效${NC}"
fi

# 创建rc.local脚本作为备份方案
if [ ! -f /etc/rc.local ] || ! grep -q "exit 0" /etc/rc.local; then
    echo -e "${BLUE}[•] 创建或更新 rc.local 作为备份启动脚本...${NC}"
    
    # 备份原始文件如果存在
    if [ -f /etc/rc.local ]; then
        cp /etc/rc.local /etc/rc.local.bak_$(date +%F_%T)
    fi
    
    # 删除已存在的队列管理设置，避免重复
    if [ -f /etc/rc.local ]; then
        sed -i '/tc qdisc replace/d' /etc/rc.local
        sed -i '/# 设置队列管理/d' /etc/rc.local
        sed -i '/# 应用sysctl设置/d' /etc/rc.local
        sed -i '/\/sbin\/sysctl --system/d' /etc/rc.local
    fi
    
    # 创建新的rc.local文件
    cat > /etc/rc.local <<EOF
#!/bin/bash
# rc.local 网络和系统优化配置脚本

# 应用sysctl设置
/sbin/sysctl --system

# 设置队列管理
for iface in \$(ip -o link show | grep -v "lo" | awk -F": " '{print \$2}' | cut -d@ -f1); do
    [[ -n "\$iface" ]] && tc qdisc replace dev \$iface root $QOS_ALGO 2>/dev/null || true
done

exit 0
EOF
    chmod +x /etc/rc.local
    echo -e "${GREEN}✓ 创建 /etc/rc.local 作为额外保障${NC}"
    
    # 对于使用systemd的系统，确保rc-local服务启用
    if [ -d /etc/systemd/system ] && ! systemctl is-enabled rc-local.service &>/dev/null; then
        if [ ! -f /etc/systemd/system/rc-local.service ]; then
            cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local Compatibility
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

# 验证设置是否生效
verify_settings() {
    echo -e "${BLUE}[•] 验证配置是否已生效...${NC}"
    
    # 检查QoS算法
    current_qdisc=$(tc qdisc show | grep -v "pfifo_fast" | head -n1)
    if [[ -z "$current_qdisc" ]]; then
        echo -e "${YELLOW}⚠ 未检测到设置的队列规则，可能需要重启系统${NC}"
    else
        echo -e "${GREEN}✓ 队列规则已设置: $current_qdisc${NC}"
    fi
    
    # 检查文件描述符限制
    current_fd=$(ulimit -n)
    if [[ $current_fd -lt $nofile_soft ]]; then
        echo -e "${YELLOW}⚠ 当前文件描述符限制($current_fd)低于设定值($nofile_soft)，需要注销后重新登录${NC}"
    else
        echo -e "${GREEN}✓ 文件描述符限制已设置: $current_fd${NC}"
    fi
    
    # 验证TCP参数
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
    if [[ "$current_cc" == "bbr" || "$current_cc" == "bbr2" || "$current_cc" == "bbr3" ]]; then
        echo -e "${GREEN}✓ BBR已启用: $current_cc${NC}"
    else
        echo -e "${YELLOW}⚠ 未检测到BBR: 当前使用 $current_cc${NC}"
    fi
    
    # 检查是否应用了一些关键设置
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
}

# 执行验证
verify_settings

# 输出最终结果
echo -e "\n${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                ${GREEN}系统优化完成报告${BLUE}                        ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e "${GREEN}✓ 内核版本        :${NC} $kernel_version"
echo -e "${GREEN}✓ 内存            :${NC} ${mem_gb} GB"
echo -e "${GREEN}✓ CPU 核心        :${NC} ${cpu_cores} 核"
echo -e "${GREEN}✓ 流量管理算法    :${NC} ${QOS_ALGO}"
echo -e "${GREEN}✓ 文件描述符      :${NC} soft=$nofile_soft, hard=$nofile_hard"
echo -e "${GREEN}✓ TCP 缓冲上限    :${NC} $rmem_max 字节（约 $((rmem_max/1024/1024))MB）"
echo -e "${GREEN}✓ UDP/QUIC 支持   :${NC} 已启用"

if grep -q "tcp_congestion_control = bbr" /etc/sysctl.conf; then
    if [[ $is_xanmod -eq 1 ]]; then
        echo -e "${GREEN}✓ BBR 拥塞控制   :${NC} 已启用 (XanMod内核会自动选择最佳BBR版本)"
    else
        echo -e "${GREEN}✓ BBR 拥塞控制   :${NC} 已启用"
    fi
else
    echo -e "${YELLOW}⚠ BBR 拥塞控制   :${NC} 未启用（内核可能不支持）"
fi

echo -e "${GREEN}✓ 系统限制生效    :${NC} ulimit + systemd + pam"
echo -e "${GREEN}✓ 系统重启持久化  :${NC} apply-sysctl.service + rc.local"
echo -e "${GREEN}✓ 立即生效方式    :${NC} sysctl + tc + ulimit"

echo -e "\n${YELLOW}提示: 验证配置的命令:${NC}"
echo -e "  • ${CYAN}检查文件描述符限制:${NC} ulimit -n"
echo -e "  • ${CYAN}检查TCP配置:${NC} sysctl -a | grep tcp"
echo -e "  • ${CYAN}检查队列策略:${NC} tc qdisc show"
echo -e "\n${YELLOW}提示: 如需完全生效，请重启系统或重新登录会话${NC}"

echo -e "\n${CYAN}流量管理算法说明：${NC}"
for desc in "${qos_descriptions[@]}"; do
    IFS=':' read -r algo explanation <<< "$desc"
    echo -e "  ${YELLOW}$(printf "%-10s" "$algo"):${NC} $explanation"
done
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"

# 如果是XanMod内核，显示特别提示
if [[ $is_xanmod -eq 1 ]]; then
    echo -e "${GREEN}✓ 检测到XanMod内核，已应用特定优化:${NC}"
    echo -e "  • ${CYAN}BBR将自动使用最佳版本 (根据XanMod内核特性)${NC}"
    echo -e "  • ${CYAN}已启用更积极的网络参数优化${NC}"
    echo -e "  • ${CYAN}已优化调度器设置${NC}"
fi

# 如果检测到Debian 12，显示特别提示
if [[ "$debian_version" == "12" ]]; then
    echo -e "${GREEN}✓ 检测到Debian 12，已应用特定优化:${NC}"
    echo -e "  • ${CYAN}已适配Debian 12的软件包和模块管理${NC}"
    echo -e "  • ${CYAN}已兼容systemd服务配置${NC}"
fi

# 如果没有错误，脚本将成功完成
echo -e "${GREEN}脚本执行完成！配置已应用并设置为在系统启动时自动加载。${NC}"
echo -e "${YELLOW}建议: 重启系统以确保所有优化生效。${NC}"   
