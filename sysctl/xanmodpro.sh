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
if [[ "$#" -eq 0 ]]; then
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║             ${GREEN}系统网络流量管理算法优化${BLUE}                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo -e "\n${CYAN}请选择流量管理算法:${NC}"
    echo -e "  ${GREEN}1)${NC} fq\t\t${YELLOW}[默认] 基本公平队列，适合大多数场景${NC}"
    echo -e "  ${GREEN}2)${NC} fq_codel\t${YELLOW}控制延迟的公平队列，减少缓冲膨胀${NC}"
    echo -e "  ${GREEN}3)${NC} fq_pie\t${YELLOW}比例积分控制器公平队列${NC}"
    echo -e "  ${GREEN}4)${NC} fq_cake\t${YELLOW}高级功能全面的队列管理算法，推荐服务器使用${NC}"
    echo -e "  ${GREEN}5)${NC} cake\t${YELLOW}综合自动网络队列管理${NC}"
    echo -e "  ${GREEN}6)${NC} pfifo_fast\t${YELLOW}传统优先级队列${NC}"
    echo -e "  ${GREEN}7)${NC} sfq\t\t${YELLOW}随机公平队列${NC}"
    echo -e "  ${GREEN}8)${NC} red\t\t${YELLOW}随机早期检测队列${NC}"
    echo -e "  ${GREEN}9)${NC} tbf\t\t${YELLOW}令牌桶过滤器${NC}"
    echo -e "\n  ${GREEN}0)${NC} 退出脚本"
    
    read -p "$(echo -e ${YELLOW}"请输入选项 [0-9] (默认: 1): "${NC})" qos_choice
    
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

# 获取系统信息
mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
cpu_cores=$(nproc)
is_xanmod=$(uname -r | grep -iq xanmod && echo 1 || echo 0)
kernel_version=$(uname -r)

# 计算资源限制
nofile_soft=$((mem_gb * 32768))
nofile_hard=$((mem_gb * 65536))
[ "$nofile_soft" -lt 262144 ] && nofile_soft=262144
[ "$nofile_soft" -gt 1048576 ] && nofile_soft=1048576
[ "$nofile_hard" -gt 2097152 ] && nofile_hard=2097152

rmem_max=$((mem_gb * 1024 * 1024))
[ "$rmem_max" -gt 134217728 ] && rmem_max=134217728
[ "$rmem_max" -lt 16777216 ] && rmem_max=16777216

# 备份原始配置
cp /etc/sysctl.conf /etc/sysctl.conf.bak_$(date +%F_%T)

# 写入优化配置
cat > /etc/sysctl.conf <<EOF
# 内核: $kernel_version | XanMod: $is_xanmod | 内存: ${mem_gb}GB | CPU: ${cpu_cores}核
# 流量管理算法: $QOS_ALGO

fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536

net.core.default_qdisc = $QOS_ALGO
net.ipv4.tcp_congestion_control = bbr
net.mptcp.enabled = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1

net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 8
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_base_mss = 1024

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
net.ipv6.conf.all.forwarding = 1

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
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 16384

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

# 应用 sysctl 配置
echo -e "${BLUE}[•] 应用 sysctl 配置...${NC}"
sysctl --system

# 设置 limits.conf
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

grep -q pam_limits.so /etc/pam.d/common-session || echo "session required pam_limits.so" >> /etc/pam.d/common-session
grep -q pam_limits.so /etc/pam.d/common-session-noninteractive || echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive

# systemd 资源限制
sed -i '/DefaultLimitCORE\|DefaultLimitNOFILE\|DefaultLimitNPROC/d' /etc/systemd/system.conf
cat >> /etc/systemd/system.conf <<EOF
[Manager]
DefaultLimitCORE=infinity
DefaultLimitNOFILE=$nofile_hard
DefaultLimitNPROC=$nofile_hard
EOF

systemctl daemon-reexec

# 确保内核模块加载
if [[ "$QOS_ALGO" == "fq_cake" || "$QOS_ALGO" == "cake" ]]; then
    echo -e "${BLUE}[•] 检查 CAKE 队列管理模块...${NC}"
    if ! lsmod | grep -q sch_cake; then
        echo -e "${YELLOW}⚠ 正在加载 CAKE 队列管理模块...${NC}"
        modprobe sch_cake || {
            echo -e "${RED}⚠ 无法加载 sch_cake 模块，请检查内核是否支持${NC}"
            echo -e "${YELLOW}尝试安装必要的内核模块...${NC}"
            apt-get update -qq
            apt-get install -y linux-modules-extra-$(uname -r) 2>/dev/null || true
            modprobe sch_cake || echo -e "${RED}⚠ CAKE 模块安装失败，可能需要升级内核或手动安装模块${NC}"
        }
    else
        echo -e "${GREEN}✓ CAKE 队列管理模块已加载${NC}"
    fi
fi

# 安全设置 ulimit，避免超过当前 shell 上限
current_max=$(ulimit -Hn)
if [ "$nofile_hard" -le "$current_max" ]; then
  ulimit -n "$nofile_hard"
else
  echo -e "${YELLOW}⚠ 当前 shell 会话最大 open files 限制为 $current_max，已跳过设置更高的 ulimit。${NC}"
  echo -e "${YELLOW}⚠ 请重启系统或重新登录以使更高 limits.conf 生效。${NC}"
fi

ulimit -c unlimited
[ -x "$(command -v prlimit)" ] && prlimit --pid $$ --nofile="$nofile_hard":"$nofile_hard"

# 创建启动脚本确保 sysctl 设置持久化
echo -e "${BLUE}[•] 创建系统服务确保配置持久化...${NC}"
if [[ -d /etc/systemd/system ]]; then
    cat > /etc/systemd/system/apply-sysctl.service <<EOF
[Unit]
Description=Apply sysctl settings
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/sysctl --system
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable apply-sysctl.service
    systemctl start apply-sysctl.service
    echo -e "${GREEN}✓ 创建系统服务 apply-sysctl.service 确保重启后设置生效${NC}"
fi

# 创建rc.local脚本作为备份方案
if [ ! -f /etc/rc.local ] || ! grep -q "exit 0" /etc/rc.local; then
    cat > /etc/rc.local <<EOF
#!/bin/bash
# 应用sysctl设置
/sbin/sysctl --system

exit 0
EOF
    chmod +x /etc/rc.local
    echo -e "${GREEN}✓ 创建 /etc/rc.local 作为额外保障${NC}"
fi

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
echo -e "${GREEN}✓ gRPC/HTTP2 增强 :${NC} TCP_FASTOPEN + BBR"
echo -e "${GREEN}✓ 系统限制生效    :${NC} ulimit + systemd + pam"
echo -e "${GREEN}✓ 系统重启持久化  :${NC} apply-sysctl.service + rc.local"
echo -e "${GREEN}✓ 立即生效方式    :${NC} sysctl --system, prlimit, ulimit"
echo -e "${GREEN}✓ 验证命令        :${NC} ulimit -n ; sysctl -a | grep tcp"
echo -e "\n${YELLOW}提示: 如需保障 limits.conf 生效，请重启系统或重新登录会话${NC}"
echo -e "\n${CYAN}流量管理算法说明：${NC}"
echo -e "  ${YELLOW}fq      :${NC} 最常用的公平队列，适合一般场景"
echo -e "  ${YELLOW}fq_codel:${NC} 主要减少延迟，适合游戏、视频会议等需低延迟场景"
echo -e "  ${YELLOW}fq_cake :${NC} 功能最全面的队列算法，适合高负载服务器、复杂网络环境"
echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
