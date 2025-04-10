#!/bin/bash

# 备份原来的 sysctl.conf
cp /etc/sysctl.conf /etc/sysctl.conf.bak_$(date +%F_%T)

# 使用 `truncate` 确保彻底清空 `/etc/sysctl.conf`
truncate -s 0 /etc/sysctl.conf

# 确保文件为空
echo "" > /etc/sysctl.conf

# 重新写入优化配置
cat > /etc/sysctl.conf <<EOF
# ======================= 文件描述符和 Inotify =======================
fs.file-max = 1048576
fs.inotify.max_user_instances = 8192

# ======================= TCP 拥塞控制与增强 =======================
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.mptcp.enabled = 1
net.ipv4.tcp_mtu_probing = 1

# ======================= TCP 连接调度优化 =======================
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_max_tw_buckets = 1048576
net.ipv4.tcp_max_syn_backlog = 262144
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 200000

# ======================= TCP 缓冲与窗口优化 =======================
net.ipv4.tcp_rmem = 4096 524288 33554432
net.ipv4.tcp_wmem = 4096 524288 33554432

# ======================= UDP 缓冲优化 =======================
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 134217728
net.core.wmem_default = 134217728
net.core.optmem_max = 65536

# ======================= 端口范围优化 =======================
net.ipv4.ip_local_port_range = 1024 65535

# ======================= IPv4/IPv6 转发配置 =======================
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ======================= ICMP 和安全性优化 =======================
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.rp_filter = 0

# ======================= ARP 和邻居表优化 =======================
net.ipv4.neigh.default.unres_qlen = 10000
net.ipv4.neigh.default.gc_thresh3 = 8192
net.ipv4.neigh.default.gc_thresh2 = 4096
net.ipv4.neigh.default.gc_thresh1 = 2048
net.ipv6.neigh.default.gc_thresh3 = 8192
net.ipv6.neigh.default.gc_thresh2 = 4096
net.ipv6.neigh.default.gc_thresh1 = 2048

# ======================= 防火墙 SYN Flood 防护 =======================
net.ipv4.tcp_syncookies = 1

EOF

# 确保文件已正确写入
sync

# 重新加载 `sysctl` 配置
sysctl --system

echo "sysctl.conf 已彻底清空并写入优化配置，修改已生效！"
