#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

# ====== 颜色定义 ======
readonly RED='\033[31m'
readonly GREEN='\033[32m'
readonly YELLOW='\033[33m'
readonly BLUE='\033[34m'
readonly NC='\033[0m'

# ====== 日志函数 ======
log_info() { echo -e "${BLUE}[•]${NC} $*"; }
log_success() { echo -e "${GREEN}[✓]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*" >&2; }

# ====== 错误处理 ======
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "脚本执行失败 (退出码: $exit_code)"
        log_warning "如有备份文件已创建，请检查并手动恢复"
    fi
}
trap cleanup EXIT

# ====== 权限检查 ======
if [[ $EUID -ne 0 ]]; then
   log_error "此脚本需要 root 权限运行"
   exit 1
fi

log_info "正在运行智能适配系统优化..."

# ====== 获取系统信息 ======
readonly MEM_GB=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
readonly CPU_CORES=$(nproc)
readonly KERNEL_VERSION=$(uname -r)
readonly IS_XANMOD=$(uname -r | grep -iq xanmod && echo 1 || echo 0)

# 验证系统信息
if [[ $MEM_GB -lt 1 || $CPU_CORES -lt 1 ]]; then
    log_error "无法正确获取系统信息 (内存: ${MEM_GB}GB, CPU: ${CPU_CORES}核)"
    exit 1
fi

# ====== 计算资源限制 ======
calc_nofile_limits() {
    local soft=$((MEM_GB * 32768))
    local hard=$((MEM_GB * 65536))
    
    [[ $soft -lt 262144 ]] && soft=262144
    [[ $soft -gt 1048576 ]] && soft=1048576
    [[ $hard -lt $soft ]] && hard=$soft
    [[ $hard -gt 2097152 ]] && hard=2097152
    
    echo "$soft $hard"
}

calc_rmem_max() {
    local rmem=$((MEM_GB * 1024 * 1024))
    [[ $rmem -gt 134217728 ]] && rmem=134217728
    [[ $rmem -lt 16777216 ]] && rmem=16777216
    echo "$rmem"
}

read -r NOFILE_SOFT NOFILE_HARD <<< "$(calc_nofile_limits)"
readonly RMEM_MAX=$(calc_rmem_max)

log_success "系统信息: 内核=${KERNEL_VERSION}, 内存=${MEM_GB}GB, CPU=${CPU_CORES}核"

# ====== 选择拥塞控制算法 ======
select_tcp_cc() {
    local available_cc
    if [[ -f /proc/sys/net/ipv4/tcp_available_congestion_control ]]; then
        available_cc=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)
    else
        log_warning "无法读取可用拥塞控制算法，使用默认值"
        echo "cubic"
        return
    fi
    
    if grep -qw "bbr" <<< "$available_cc"; then
        echo "bbr"
    elif grep -qw "cubic" <<< "$available_cc"; then
        log_warning "系统不支持 BBR，将使用 cubic"
        echo "cubic"
    else
        log_warning "未找到常用算法，使用系统默认"
        echo "cubic"
    fi
}

readonly TCP_CC=$(select_tcp_cc)

# ====== 选择队列调度算法 ======
select_qdisc() {
    log_info "请选择队列调度算法:"
    local PS3="请输入选项编号 (1-4): "
    local options=(
        "fq_codel - 低延迟优先，适合游戏和实时应用"
        "fq - 平衡选择，适合大多数场景"
        "fq_pie - 高吞吐优先，适合大文件传输"
        "cake - 更智能但需要内核支持，适合复杂网络"
    )
    
    local qdisc=""
    select opt in "${options[@]}"; do
        case $REPLY in
            1) qdisc="fq_codel"; break ;;
            2) qdisc="fq"; break ;;
            3) qdisc="fq_pie"; break ;;
            4) qdisc="cake"; break ;;
            *) log_error "无效选项，请输入 1-4" ;;
        esac
    done
    
    echo "$qdisc"
}

readonly QDISC=$(select_qdisc)
log_success "已选择 ${QDISC} 作为队列调度算法"

# ====== 备份和写入配置 ======
backup_and_write_sysctl() {
    local sysctl_file="/etc/sysctl.d/99-optimized.conf"
    local backup_dir="/etc/sysctl.d/backups"
    
    mkdir -p "$backup_dir"
    
    if [[ -f $sysctl_file ]]; then
        local backup_file="${backup_dir}/99-optimized.conf.$(date +%F_%H%M%S)"
        cp "$sysctl_file" "$backup_file"
        log_success "已备份原始配置到: $backup_file"
    fi
    
    cat > "$sysctl_file" <<EOF
# 自动生成的优化配置
# 内核: $KERNEL_VERSION | 内存: ${MEM_GB}GB | CPU: ${CPU_CORES}核
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

# ====== 文件系统与监控 ======
fs.file-max = $((NOFILE_HARD * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536

# ====== TCP 拥塞控制 ======
net.core.default_qdisc = $QDISC
net.ipv4.tcp_congestion_control = $TCP_CC
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0

# ====== TCP 连接优化 ======
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 8
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_syn_backlog = $((CPU_CORES * 65536 < 524288 ? CPU_CORES * 65536 : 524288))

# ====== 队列与缓冲区 ======
net.core.somaxconn = 65535
net.core.netdev_max_backlog = $((CPU_CORES * 65536 < 524288 ? CPU_CORES * 65536 : 524288))
net.core.netdev_budget = 600

# ====== TCP/UDP 内存 ======
net.ipv4.tcp_rmem = 8192 262144 $RMEM_MAX
net.ipv4.tcp_wmem = 8192 262144 $RMEM_MAX
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = $RMEM_MAX
net.core.wmem_max = $RMEM_MAX
net.core.optmem_max = 65536
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# ====== 网络性能 ======
net.core.busy_read = 50
net.core.busy_poll = 50
net.ipv4.tcp_autocorking = 0
net.ipv4.ip_local_port_range = 1024 65535

# ====== IPv4/IPv6 转发 ======
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.default.route_localnet = 1

# ====== 安全设置 ======
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv6.conf.all.accept_redirects = 0

# ====== 邻居表 ======
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384
net.ipv6.neigh.default.gc_thresh1 = 4096
net.ipv6.neigh.default.gc_thresh2 = 8192
net.ipv6.neigh.default.gc_thresh3 = 16384

# ====== TCP 功能 ======
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_moderate_rcvbuf = 1
EOF

    log_success "已写入 sysctl 配置: $sysctl_file"
}

backup_and_write_sysctl

# ====== 应用 sysctl 配置 ======
log_info "正在应用 sysctl 配置..."
if sysctl --system > /dev/null 2>&1; then
    log_success "sysctl 配置应用成功"
else
    log_warning "部分 sysctl 参数可能不被当前内核支持"
fi

# ====== 配置 limits.conf ======
setup_limits() {
    local limits_file="/etc/security/limits.conf"
    local backup_file="${limits_file}.bak.$(date +%F_%H%M%S)"
    
    [[ -f $limits_file ]] && cp "$limits_file" "$backup_file"
    
    cat > "$limits_file" <<EOF
# 系统资源限制配置 - $(date '+%Y-%m-%d %H:%M:%S')
*     soft nofile  $NOFILE_SOFT
*     hard nofile  $NOFILE_HARD
*     soft nproc   $NOFILE_SOFT
*     hard nproc   $NOFILE_HARD
*     soft memlock unlimited
*     hard memlock unlimited
root  soft nofile  $NOFILE_HARD
root  hard nofile  $NOFILE_HARD
root  soft nproc   $NOFILE_HARD
root  hard nproc   $NOFILE_HARD
EOF

    log_success "已更新 limits.conf"
    
    # 确保 PAM 加载 limits 模块
    for pam_file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
        if [[ -f $pam_file ]] && ! grep -q "pam_limits.so" "$pam_file"; then
            echo "session required pam_limits.so" >> "$pam_file"
            log_success "已更新 $pam_file"
        fi
    done
}

setup_limits

# ====== 配置 systemd limits ======
setup_systemd_limits() {
    local drop_in_dir="/etc/systemd/system.conf.d"
    mkdir -p "$drop_in_dir"
    
    cat > "${drop_in_dir}/90-custom-limits.conf" <<EOF
[Manager]
DefaultTimeoutStopSec=30s
DefaultLimitCORE=infinity
DefaultLimitNOFILE=$NOFILE_HARD
DefaultLimitNPROC=$NOFILE_HARD
DefaultTasksMax=infinity
EOF

    log_success "已创建 systemd drop-in 配置"
    
    if systemctl daemon-reexec 2>/dev/null; then
        log_success "systemd 配置已重新加载"
    else
        log_warning "systemd 重新加载失败，需要重启系统"
    fi
}

setup_systemd_limits

# ====== 验证配置 ======
log_info "正在验证配置..."
echo ""
sysctl net.ipv4.tcp_congestion_control 2>/dev/null || true
sysctl net.core.default_qdisc 2>/dev/null || true
ulimit -Sn 2>/dev/null || true
ulimit -Hn 2>/dev/null || true

# ====== 输出报告 ======
cat <<EOF

${BLUE}==================== 优化完成报告 ====================${NC}
${GREEN}✔ 内核版本        :${NC} $KERNEL_VERSION
${GREEN}✔ 内存            :${NC} ${MEM_GB} GB
${GREEN}✔ CPU 核心        :${NC} ${CPU_CORES} 核
${GREEN}✔ 拥塞控制算法    :${NC} $TCP_CC
${GREEN}✔ 队列调度算法    :${NC} $QDISC
${GREEN}✔ 文件描述符      :${NC} soft=$NOFILE_SOFT, hard=$NOFILE_HARD
${GREEN}✔ TCP 缓冲上限    :${NC} $RMEM_MAX 字节 ($((RMEM_MAX/1024/1024))MB)
${GREEN}✔ 配置文件        :${NC} /etc/sysctl.d/99-optimized.conf
${GREEN}✔ 备份目录        :${NC} /etc/sysctl.d/backups/

${YELLOW}⚠ 重要提示:${NC}
  1. 请重新登录或重启系统以完全应用 limits 配置
  2. 验证命令: ulimit -n; sysctl -a | grep tcp_congestion
  3. 如遇问题可从备份目录恢复配置
${BLUE}=====================================================${NC}
EOF
