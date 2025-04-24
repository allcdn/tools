#!/bin/bash
set -euo pipefail

# ====== 颜色定义 ======
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
NC='\033[0m'

# 有效的流量管理算法列表
valid_qos=("fq" "fq_codel" "fq_pie" "cake" "pfifo_fast" "sfq" "red" "tbf")
QOS_ALGO="fq_codel"  # 默认使用fq_codel

# 流量管理算法简要说明
qos_descriptions=(
    "fq:       公平队列，简单实现，CPU开销低，适合家庭环境"
    "fq_codel: 减少延迟，适合游戏/视频会议/Web服务器"
    "fq_pie:   高负载稳定，适合带宽波动大的VPN场景"
    "cake:     综合队列管理，适合高负载CDN和流媒体"
    "其他:     pfifo_fast(默认), sfq(随机公平), red(拥塞控制), tbf(带宽限制)"
)

# 服务器类型
SERVER_TYPE=""
server_types=("web" "cdn" "vpn" "general")

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误: 此脚本必须以root用户运行${NC}"
   exit 1
fi

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
            echo -e "  ${YELLOW}--qos, -q${NC} \t指定流量管理算法(fq, fq_codel, fq_pie, cake等), 默认为fq_codel"
            echo -e "  ${YELLOW}--server-type, -s${NC} \t指定服务器类型(web, cdn, vpn, general)"
            echo -e "  ${YELLOW}--help, -h${NC} \t显示此帮助信息"
            exit 0
            ;;
        *)
            echo -e "${RED}错误: 未知参数 $1${NC}"
            echo -e "${YELLOW}使用 -h 或 --help 查看帮助${NC}"
            exit 1
            ;;
    esac
done

# 简化的交互式选择
if [[ -z "${SERVER_TYPE}" ]]; then
    echo -e "${BLUE}请选择服务器类型:${NC}"
    echo -e "  ${GREEN}1)${NC} Web服务器 - 网站、API和应用服务器"
    echo -e "  ${GREEN}2)${NC} CDN节点 - 内容分发网络"
    echo -e "  ${GREEN}3)${NC} VPN服务器 - VPN和代理服务器"
    echo -e "  ${GREEN}4)${NC} 通用服务器 - 其他类型服务器"
    
    read -p "$(echo -e ${YELLOW}"请输入选项 [1-4] (默认: 4): "${NC})" server_choice
    
    # 设置默认选项
    server_choice=${server_choice:-4}
    
    case $server_choice in
        1) SERVER_TYPE="web"; QOS_ALGO=${QOS_ALGO:-"fq_codel"} ;;
        2) SERVER_TYPE="cdn"; QOS_ALGO=${QOS_ALGO:-"cake"} ;;
        3) SERVER_TYPE="vpn"; QOS_ALGO=${QOS_ALGO:-"fq_pie"} ;;
        4) SERVER_TYPE="general"; QOS_ALGO=${QOS_ALGO:-"fq_codel"} ;;
        *) SERVER_TYPE="general" ;;
    esac
    
    echo -e "${GREEN}已选择服务器类型: ${SERVER_TYPE}${NC}"
fi

# 简化的算法选择
if [[ -z "${QOS_ALGO:-}" ]]; then
    echo -e "${BLUE}请选择流量管理算法:${NC}"
    for i in "${!qos_descriptions[@]}"; do
        echo -e "  ${GREEN}$(($i+1))${NC} ${qos_descriptions[$i]}"
    done
    
    read -p "$(echo -e ${YELLOW}"请输入选项 [1-7] (默认: 1): "${NC})" qos_choice
    qos_choice=${qos_choice:-1}
    
    case $qos_choice in
        1) QOS_ALGO="fq" ;;
        2) QOS_ALGO="fq_codel" ;;
        3) QOS_ALGO="fq_pie" ;;
        4) QOS_ALGO="cake" ;;
        5) QOS_ALGO="pfifo_fast" ;;
        6) QOS_ALGO="sfq" ;;
        7) QOS_ALGO="red" ;;
        8) QOS_ALGO="tbf" ;;
        *) QOS_ALGO="fq_codel" ;;
    esac
    
    echo -e "${GREEN}已选择: ${QOS_ALGO}${NC}"
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

echo -e "${BLUE}[•] 正在优化系统... (服务器类型: $SERVER_TYPE, 流量管理算法: $QOS_ALGO)${NC}"

# 基于服务器类型计算资源限制
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

# 基于服务器类型调整TCP/UDP缓冲区
case $SERVER_TYPE in
    "web"|"cdn")
        rmem_max=$((mem_gb * 2 * 1024 * 1024))
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

# 备份原始配置
if [ -f /etc/sysctl.conf ]; then
    echo -e "${BLUE}[•] 备份原始配置...${NC}"
    cp /etc/sysctl.conf /etc/sysctl.conf.bak_$(date +%F_%T)
    
    # 清除旧的自定义设置，避免重复
    sed -i '/# 内核:/d' /etc/sysctl.conf
    sed -i '/# 流量管理算法:/d' /etc/sysctl.conf
    sed -i '/# 服务器类型:/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
fi

# 创建临时配置文件
TMP_SYSCTL="/tmp/sysctl_temp.conf"
cat > "$TMP_SYSCTL" <<EOF
# 内核: $kernel_version | 内存: ${mem_gb}GB | CPU: ${cpu_cores}核
# 流量管理算法: $QOS_ALGO | 服务器类型: $SERVER_TYPE

# 文件系统参数
fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536

# 网络队列管理
net.core.default_qdisc = $QOS_ALGO

# TCP/BBR相关
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 8
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_slow_start_after_idle = 0

# 连接和队列相关
net.core.somaxconn = $somaxconn
net.core.netdev_max_backlog = $backlog
net.ipv4.tcp_max_syn_backlog = $backlog

# 缓冲区设置
net.ipv4.tcp_rmem = 8192 262144 $rmem_max
net.ipv4.tcp_wmem = 8192 262144 $wmem_max
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.core.optmem_max = 131072

# UDP设置
net.ipv4.udp_mem = $((rmem_max/2)) $rmem_max $((rmem_max*2))
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# 端口范围和转发
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1

# 安全相关
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

# 邻居表大小
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384

# 其他TCP参数
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
EOF

# VPN特定设置
if [[ "$SERVER_TYPE" == "vpn" ]]; then
    cat >> "$TMP_SYSCTL" <<EOF
# VPN专用设置
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv4.tcp_max_tw_buckets = 1000000
net.ipv4.tcp_max_orphans = 400000
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
EOF
fi

# 检查IPv6支持
if [ -d /proc/sys/net/ipv6 ]; then
    cat >> "$TMP_SYSCTL" <<EOF
# IPv6设置
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 16384
EOF
fi

# 复制到最终配置
cp "$TMP_SYSCTL" /etc/sysctl.conf
rm "$TMP_SYSCTL"

# 应用 sysctl 配置
echo -e "${BLUE}[•] 应用 sysctl 配置...${NC}"
sysctl --system -e || true

# 设置 limits.conf
echo -e "${BLUE}[•] 设置系统资源限制...${NC}"
# 备份原始文件
if [ -f /etc/security/limits.conf ]; then
    cp /etc/security/limits.conf /etc/security/limits.conf.bak_$(date +%F_%T)
    
    # 清除旧的设置
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

# 创建systemd服务
echo -e "${BLUE}[•] 创建系统服务确保配置持久化...${NC}"
if [[ -d /etc/systemd/system ]]; then
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
    echo -e "${GREEN}✓ 创建系统服务 apply-sysctl.service${NC}"
fi

# 输出摘要
echo -e "\n${GREEN}=== 系统优化完成 ===${NC}"
echo -e "${GREEN}• 服务器类型: ${NC}$SERVER_TYPE"
echo -e "${GREEN}• 流量管理算法: ${NC}$QOS_ALGO"
echo -e "${GREEN}• 文件描述符限制: ${NC}$nofile_soft / $nofile_hard"
echo -e "${GREEN}• TCP缓冲区: ${NC}$((rmem_max/1024/1024))MB"
echo -e "${GREEN}• 最大连接队列: ${NC}$somaxconn"
echo -e "\n${YELLOW}提示: 重启系统以确保所有优化生效${NC}"
