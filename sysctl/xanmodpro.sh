#!/bin/bash
set -euo pipefail

echo -e "\033[36m[\u2022] 正在运行智能适配系统优化...\033[0m"

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

# 写入优化的 sysctl.conf
cat > /etc/sysctl.conf <<EOF
# 内核: $kernel_version | XanMod: $is_xanmod | 内存: ${mem_gb}GB | CPU: ${cpu_cores}

fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536

net.core.default_qdisc = fq
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

# ulimit 立即生效
ulimit -n "$nofile_hard"
ulimit -c unlimited
[ -x "$(command -v prlimit)" ] && prlimit --pid $$ --nofile="$nofile_hard":"$nofile_hard"

# 显示结果
cat <<EOF

\033[1;34m==================== 优化完成报告 ====================\033[0m
\033[32m✔ 内核版本        :\033[0m $kernel_version
\033[32m✔ 内存                :\033[0m ${mem_gb} GB
\033[32m✔ CPU 核心             :\033[0m ${cpu_cores} 核
\033[32m✔ 文件描述符     :\033[0m soft=$nofile_soft, hard=$nofile_hard
\033[32m✔ TCP 描述符缓冲  :\033[0m $rmem_max (约 $((rmem_max/1024/1024))MB)
\033[32m✔ UDP/QUIC 支持       :\033[0m 已启用
\033[32m✔ gRPC/HTTP2 增强   :\033[0m TCP_FASTOPEN + BBR
\033[32m✔ 系统限制生效   :\033[0m ulimit + systemd + pam
\033[32m✔ 立即生效方式   :\033[0m sysctl --system, prlimit, ulimit
\033[32m✔ 验证命令         :\033[0m ulimit -n ; sysctl -a | grep tcp

\033[1;33m提示: 如需保障 limits.conf 生效, 请重启服务或重新登录会话\033[0m
\033[1;34m====================================================\033[0m
EOF
