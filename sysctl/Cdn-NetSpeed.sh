#!/bin/bash
set -euo pipefail

# ====== 颜色定义 ======
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
PURPLE='\033[35m'
CYAN='\033[36m'
NC='\033[0m'

# ====== 版本信息 ======
VERSION="2.1.0"

# ====== 辅助函数 ======
function check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✗] 此脚本必须以root身份运行${NC}"
        exit 1
    fi
}

function print_banner() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}       系统性能智能优化工具 v${VERSION}       ${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}▶ 自动检测系统资源并应用最佳配置${NC}"
    echo -e "${GREEN}▶ 优化网络性能、文件系统和资源限制${NC}"
    echo -e "${GREEN}▶ 支持多种内核和网络调度算法${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

function backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp "$file" "${file}.bak_$(date +%F_%T)"
        echo -e "${GREEN}[✓] 已备份 ${file}${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] 文件不存在: ${file}，将创建新文件${NC}"
        touch "$file"
        return 1
    fi
}

function detect_virtualization() {
    if [ -f /proc/self/status ]; then
        if grep -q "VxID" /proc/self/status; then
            echo "openvz"
            return
        fi
    fi
    
    if [ -d /proc/vz ] && [ ! -d /proc/bc ]; then
        echo "openvz"
        return
    fi
    
    if systemd-detect-virt 2>/dev/null | grep -q "lxc\|docker\|container"; then
        echo "container"
        return
    fi
    
    if systemd-detect-virt 2>/dev/null | grep -q "kvm\|qemu\|xen\|vmware\|oracle"; then
        echo "vm"
        return
    fi
    
    if dmesg | grep -iq "kvm\|qemu\|xen\|vmware\|oracle\|hypervisor"; then
        echo "vm"
        return
    fi
    
    echo "physical"
}

# ====== 主程序开始 ======
check_root
print_banner

echo -e "${BLUE}[•] 正在运行智能适配系统优化...${NC}"

# 获取系统信息
mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
cpu_cores=$(nproc)
is_xanmod=$(uname -r | grep -iq xanmod && echo 1 || echo 0)
kernel_version=$(uname -r)
os_name=$(grep -s "^PRETTY_NAME=" /etc/os-release | cut -d'"' -f2 || echo "Unknown")
virt_type=$(detect_virtualization)

echo -e "${BLUE}[•] 系统信息:${NC}"
echo -e "   ${CYAN}操作系统    :${NC} $os_name"
echo -e "   ${CYAN}内核版本    :${NC} $kernel_version"
echo -e "   ${CYAN}内存大小    :${NC} ${mem_gb} GB"
echo -e "   ${CYAN}CPU核心数   :${NC} ${cpu_cores} 核"
echo -e "   ${CYAN}虚拟化类型  :${NC} $virt_type"
echo -e "   ${CYAN}XanMod内核  :${NC} $([ "$is_xanmod" -eq 1 ] && echo "是" || echo "否")\n"

# 计算资源限制 - 根据内存和虚拟化环境调整
if [ "$virt_type" = "container" ]; then
    # 容器环境下保守一些
    nofile_soft=$((mem_gb * 24576))
    nofile_hard=$((mem_gb * 49152))
    rmem_max=$((mem_gb * 1024 * 768))
else
    # 物理机或VM可以更激进
    nofile_soft=$((mem_gb * 32768))
    nofile_hard=$((mem_gb * 65536))
    rmem_max=$((mem_gb * 1024 * 1024))
fi

# 应用最小/最大值限制
[ "$nofile_soft" -lt 262144 ] && nofile_soft=262144
[ "$nofile_soft" -gt 1048576 ] && nofile_soft=1048576
[ "$nofile_hard" -gt 2097152 ] && nofile_hard=2097152

[ "$rmem_max" -gt 134217728 ] && rmem_max=134217728
[ "$rmem_max" -lt 16777216 ] && rmem_max=16777216

# 检测可用的拥塞控制算法
available_cc=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null || echo "cubic")
default_cc="bbr"

# 如果支持bbr，使用bbr，否则使用cubic
if [[ "$available_cc" == *"bbr"* ]]; then
    tcp_cc="bbr"
elif [[ "$available_cc" == *"cubic"* ]]; then
    tcp_cc="cubic"
else
    # 如果以上都不支持，使用默认的第一个算法
    tcp_cc=$(echo "$available_cc" | awk '{print $1}')
fi

# 检测是否支持MPTCP
supports_mptcp=0
if grep -q "MPTCP" /boot/config-$(uname -r) 2>/dev/null || lsmod | grep -q "^mptcp"; then
    supports_mptcp=1
fi

# 让用户选择队列调度算法
echo -e "${BLUE}[•] 请选择队列调度算法:${NC}"
echo -e "   ${CYAN}1)${NC} fq_codel - 低延迟优先，适合游戏和实时应用"
echo -e "   ${CYAN}2)${NC} fq - 平衡选择，适合大多数场景"
echo -e "   ${CYAN}3)${NC} fq_pie - 高吞吐优先，适合大文件传输"
echo -e "   ${CYAN}4)${NC} cake - 更智能但需要内核支持，适合复杂网络"

qdisc_options=("fq_codel" "fq" "fq_pie" "cake")
qdisc_default="fq"
qdisc_index=2  # 默认选择fq

# 检测可用的队列调度算法
available_qdisc=$(tc qdisc show 2>/dev/null | grep -o 'fq\|fq_codel\|fq_pie\|cake' | sort | uniq | tr '\n' ' ')
if [ -z "$available_qdisc" ]; then
    available_qdisc="fq fq_codel"  # 至少这两个一般都支持
fi

while true; do
    read -p "请选择队列调度算法 [1-4，默认 $qdisc_index]: " choice
    if [ -z "$choice" ]; then
        choice=$qdisc_index
    fi
    
    if [[ "$choice" =~ ^[1-4]$ ]]; then
        qdisc=${qdisc_options[$((choice-1))]}
        
        # 验证选择的算法是否可用
        if [[ ! "$available_qdisc" == *"$qdisc"* ]]; then
            echo -e "${YELLOW}[!] 警告: 系统可能不支持 $qdisc，可用的算法: $available_qdisc${NC}"
            read -p "是否仍然使用 $qdisc? (y/n) " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                continue
            fi
        fi
        
        echo -e "${GREEN}[✓] 已选择 $qdisc 作为队列调度算法${NC}"
        break
    else
        echo -e "${RED}[✗] 无效选项，请输入1到4之间的数字${NC}"
    fi
done

# 创建必要的目录
mkdir -p /etc/sysctl.d

# 备份原始配置
backup_file "/etc/sysctl.d/99-sysctl.conf"

# 清空旧配置
> /etc/sysctl.d/99-sysctl.conf

# 根据系统类型调整参数
if [ "$virt_type" = "container" ]; then
    # 容器环境下禁用一些可能不支持的设置
    container_mode=1
    echo -e "${YELLOW}[!] 检测到容器环境，部分内核参数将被跳过${NC}"
else
    container_mode=0
fi

# 写入优化配置
cat > /etc/sysctl.d/99-sysctl.conf <<EOF
# 系统信息: $os_name | 内核: $kernel_version | 环境: $virt_type
# 内存: ${mem_gb}GB | CPU: ${cpu_cores}核 | XanMod: $is_xanmod
# 优化时间: $(date '+%Y-%m-%d %H:%M:%S')

# ====== 文件系统与监控优化 ======
fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536

# ====== TCP 拥塞控制与队列调度 ======
net.core.default_qdisc = $qdisc
net.ipv4.tcp_congestion_control = $tcp_cc
EOF

if [ "$supports_mptcp" -eq 1 ]; then
    echo "net.mptcp.enabled = 1" >> /etc/sysctl.d/99-sysctl.conf
fi

cat >> /etc/sysctl.d/99-sysctl.conf <<EOF
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_base_mss = 1024

# ====== TCP 连接优化 ======
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# ====== 队列与缓冲区优化 ======
net.ipv4.tcp_max_syn_backlog = $((cpu_cores * 65536 < 524288 ? cpu_cores * 65536 : 524288))
net.core.somaxconn = 65535
net.core.netdev_max_backlog = $((cpu_cores * 65536 < 524288 ? cpu_cores * 65536 : 524288))

# ====== TCP 内存参数 ======
net.ipv4.tcp_rmem = 4096 262144 $rmem_max
net.ipv4.tcp_wmem = 4096 262144 $rmem_max
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = $rmem_max
net.core.wmem_max = $rmem_max
net.core.optmem_max = 65536

# ====== UDP 优化 ======
net.ipv4.udp_mem = $((rmem_max/2)) $rmem_max $((rmem_max*2))
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# ====== 端口范围与转发 ======
net.ipv4.ip_local_port_range = 1024 65535
EOF

# 只在非容器环境添加转发设置
if [ "$container_mode" -eq 0 ]; then
    cat >> /etc/sysctl.d/99-sysctl.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ====== IPv6 优化 ======
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.route.max_size = 65536
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 16384

# ====== 安全性设置 ======
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
net.ipv4.conf.all.log_martians = 1

# ====== 邻居表大小 ======
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
EOF
fi

# 继续添加通用设置
cat >> /etc/sysctl.d/99-sysctl.conf <<EOF
# ====== TCP 功能开关 ======
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_moderate_rcvbuf = 1

# ====== 本地网络路由 ======
net.ipv4.conf.default.route_localnet = 1
net.ipv4.conf.all.route_localnet = 1

# ====== 系统内存管理 ======
vm.swappiness = 10
vm.dirty_ratio = 60
vm.dirty_background_ratio = 20
vm.vfs_cache_pressure = 50
EOF

# 如果内存大于8GB，增加一些特定优化
if [ "$mem_gb" -gt 8 ]; then
    cat >> /etc/sysctl.d/99-sysctl.conf <<EOF
# ====== 大内存系统优化 ======
vm.min_free_kbytes = $((mem_gb * 1024 * 3 / 4))
kernel.pid_max = 4194304
kernel.threads-max = 4194304
EOF
fi

echo -e "${GREEN}[✓] 已写入新配置${NC}"

# 应用新配置
echo -e "${BLUE}[•] 正在应用新配置...${NC}"
if ! sysctl --system; then
    echo -e "${YELLOW}[!] 应用某些sysctl参数失败，这在容器环境中是正常的${NC}"
fi

# 备份并设置资源限制
backup_file "/etc/security/limits.conf"

# 清空旧的资源限制配置
> /etc/security/limits.conf

# 设置 limits.conf
cat > /etc/security/limits.conf <<EOF
# 系统资源限制配置 - $(date '+%Y-%m-%d')
# 系统类型: $os_name ($virt_type)
# 内存: ${mem_gb}GB | CPU: ${cpu_cores}核

* soft nofile $nofile_soft
* hard nofile $nofile_hard
* soft nproc $nofile_soft
* hard nproc $nofile_hard
* soft core unlimited
* hard core unlimited
* soft memlock unlimited
* hard memlock unlimited
root soft nofile $nofile_hard
root hard nofile $nofile_hard
root soft nproc $nofile_soft
root hard nproc $nofile_hard
root soft core unlimited
root hard core unlimited
root hard memlock unlimited
root soft memlock unlimited
EOF

# 确保 PAM 加载 limits.so
for file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
    if [ -f "$file" ]; then
        grep -q "pam_limits.so" "$file" || echo "session required pam_limits.so" >> "$file"
    fi
done

# 优化systemd资源限制
if [ -d /etc/systemd ]; then
    backup_file "/etc/systemd/system.conf"
    
    # 清除旧的systemd资源限制设置
    sed -i '/DefaultLimitCORE\|DefaultLimitNOFILE\|DefaultLimitNPROC/d' /etc/systemd/system.conf
    
    # 添加新的systemd资源限制
    cat >> /etc/systemd/system.conf <<EOF
[Manager]
DefaultTimeoutStopSec=30s
DefaultLimitCORE=infinity
DefaultLimitNOFILE=$nofile_hard
DefaultLimitNPROC=$nofile_hard
DefaultTasksMax=infinity
EOF

    # 重新加载 systemd 配置
    if command -v systemctl &>/dev/null; then
        systemctl daemon-reexec
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

# 尝试设置当前会话的资源限制
ulimit -c unlimited 2>/dev/null || true
if command -v prlimit &>/dev/null; then
    prlimit --pid $$ --nofile="$nofile_hard":"$nofile_hard" 2>/dev/null || true
fi

# 根据内存大小优化VM设置
if [ "$mem_gb" -gt 16 ] && [ "$container_mode" -eq 0 ]; then
    echo -e "${BLUE}[•] 检测到大内存系统，应用高级内存优化...${NC}"
    
    # 优化透明大页设置
    if [ -d /sys/kernel/mm/transparent_hugepage ]; then
        echo "madvise" > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
        echo "advise" > /sys/kernel/mm/transparent_hugepage/shmem_enabled 2>/dev/null || true
        echo 1 > /sys/kernel/mm/transparent_hugepage/khugepaged/defrag 2>/dev/null || true
        echo -e "${GREEN}[✓] 已优化透明大页设置${NC}"
    fi
fi

# 优化网络设备队列长度 - 仅物理机和VM
if [ "$container_mode" -eq 0 ] && [ -d /sys/class/net ]; then
    echo -e "${BLUE}[•] 正在优化网络设备队列...${NC}"
    for interface in $(ls /sys/class/net | grep -v "lo\|bond\|docker\|veth\|br"); do
        # 只处理真实的物理网卡或虚拟机网卡
        if [ -f "/sys/class/net/$interface/tx_queue_len" ]; then
            current=$(cat "/sys/class/net/$interface/tx_queue_len")
            if [ "$current" -lt 10000 ]; then
                echo 10000 > "/sys/class/net/$interface/tx_queue_len" 2>/dev/null || true
                echo -e "${GREEN}[✓] 已优化网卡 $interface 的队列长度: $current → 10000${NC}"
            fi
        fi
    done
fi

# 输出最终结果
echo -e "\n${BLUE}══════════════════ 优化完成报告 ══════════════════${NC}"
echo -e "${GREEN}✓ 系统环境        :${NC} $os_name ($virt_type)"
echo -e "${GREEN}✓ 内核版本        :${NC} $kernel_version"
echo -e "${GREEN}✓ 内存            :${NC} ${mem_gb} GB"
echo -e "${GREEN}✓ CPU 核心        :${NC} ${cpu_cores} 核"
echo -e "${GREEN}✓ 拥塞控制算法    :${NC} $tcp_cc"
echo -e "${GREEN}✓ 队列调度算法    :${NC} $qdisc"
echo -e "${GREEN}✓ 文件描述符      :${NC} soft=$nofile_soft, hard=$nofile_hard"
echo -e "${GREEN}✓ TCP 缓冲上限    :${NC} $rmem_max 字节（约 $((rmem_max/1024/1024))MB）"
echo -e "${GREEN}✓ IPv6 优化       :${NC} $([ "$container_mode" -eq 0 ] && echo "已启用" || echo "已跳过 (容器环境)")"
echo -e "${GREEN}✓ UDP/QUIC 支持   :${NC} 已启用"
echo -e "${GREEN}✓ MPTCP 支持      :${NC} $([ "$supports_mptcp" -eq 1 ] && echo "已启用" || echo "未启用")"
echo -e "${GREEN}✓ gRPC/HTTP2 增强 :${NC} TCP_FASTOPEN + $tcp_cc"
echo -e "${GREEN}✓ 系统限制生效    :${NC} ulimit + systemd + pam"

echo -e "\n${CYAN}验证命令:${NC}"
echo -e " • ${YELLOW}sysctl net.ipv4.tcp_congestion_control${NC} - 查看当前拥塞控制算法"
echo -e " • ${YELLOW}sysctl net.core.default_qdisc${NC} - 查看当前队列调度算法"
echo -e " • ${YELLOW}ulimit -n${NC} - 查看当前会话文件描述符限制"
echo -e " • ${YELLOW}cat /proc/sys/net/ipv4/tcp_rmem${NC} - 查看TCP接收缓冲区设置"

echo -e "\n${YELLOW}建议:${NC}"
echo -e " • 对于最佳性能，请重启系统以确保所有更改生效"
echo -e " • 如果是远程服务器，请确保在重启前测试SSH连接正常"
echo -e " • 使用 ${YELLOW}sysctl -a | grep -E 'tcp|udp|rmem|wmem'${NC} 查看详细网络参数"

echo -e "\n${BLUE}════════════════════════════════════════════════════${NC}"

# 提示用户是否需要重启
echo -ne "${CYAN}是否立即重启系统以应用所有更改？ (y/n) ${NC}"
read -r restart_choice
if [[ "$restart_choice" == "y" || "$restart_choice" == "Y" ]]; then
    echo -e "${YELLOW}系统将在5秒后重启...${NC}"
    sleep 5
    reboot
else
    echo -e "${GREEN}您选择了不立即重启。某些更改需要重启后才能生效。${NC}"
fi
