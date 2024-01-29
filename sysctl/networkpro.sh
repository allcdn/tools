cat << 'EOF' > /etc/sysctl.conf
# 使用 FQ-PIE（公平排队带有比例积分控制器的改进版）队列管理算法来控制缓存、排队延迟和提高网络性能
net.core.default_qdisc = fq_pie
# 启用 BBR 拥塞控制算法来优化网络吞吐量和降低延迟
net.ipv4.tcp_congestion_control = bbr
# 调整 TCP 接收缓冲区大小的区间（最小值、默认值、最大值）
net.ipv4.tcp_rmem = 8192 262144 536870912
# 调整 TCP 发送缓冲区大小的区间（最小值、默认值、最大值）
net.ipv4.tcp_wmem = 4096 16384 536870912
# TCP 窗口缩放的系数，负值意味着更小的窗口缩放因子
net.ipv4.tcp_adv_win_scale = -2
# TCP 盲区折叠数据量的最大字节数限制
#net.ipv4.tcp_collapse_max_bytes = 6291456
# TCP 流量控制机制中允许的未发送数据量下限
net.ipv4.tcp_notsent_lowat = 131072
# 本地端口的可用范围（最小值到最大值）
net.ipv4.ip_local_port_range = 1024 65535
# 允许的 TCP 和 UDP 读缓冲区最大值
net.core.rmem_max = 536870912
# 允许的 TCP 和 UDP 写缓冲区最大值
net.core.wmem_max = 536870912
# socket 监听队列的最大长度，适合大量并发连接的场景
net.core.somaxconn = 32768
# 网络设备队列的最大数据包数量
net.core.netdev_max_backlog = 32768
# TIME-WAIT 状态下的 socket 最大数量，防止 TIME-WAIT 锁占用资源
net.ipv4.tcp_max_tw_buckets = 65536
# 当 TCP 接收缓冲溢出时是否立即放弃连接
net.ipv4.tcp_abort_on_overflow = 1
# TCP 空闲时是否禁用慢启动
net.ipv4.tcp_slow_start_after_idle = 0
# 是否启用 TCP 时间戳以改善性能和避免序列号回绕问题
net.ipv4.tcp_timestamps = 1
# 是否启用 SYN 饼干来防御 SYN 洪水攻击（当设置为0时禁用）
net.ipv4.tcp_syncookies = 0
# 收到 SYN 请求时进行重试的次数
net.ipv4.tcp_syn_retries = 3
# SYN+ACK 包在放弃连接尝试前重试的次数
net.ipv4.tcp_synack_retries = 3
# 等待建立连接的 SYN 请求队列的最大长度
net.ipv4.tcp_max_syn_backlog = 32768
# TCP 连接在 FIN-WAIT-2 状态下存活的时间
net.ipv4.tcp_fin_timeout = 15
# TCP 保活探测包的发送间隔
net.ipv4.tcp_keepalive_intvl = 3
# 发送 TCP 保活探测包之前需要等待的时间
net.ipv4.tcp_keepalive_time = 600
# 在第一次和第二次最终数据确认之前可以发送多少个 TCP 保活探测包
net.ipv4.tcp_keepalive_probes = 5
# 放弃连接之前尝试发送的 TCP 尝试次数
net.ipv4.tcp_retries1 = 3
# 放弃回复数据包之前的最大重试次数
net.ipv4.tcp_retries2 = 5
# 是否保存有关网络路径的度量，以便在未来的连接中重用（当设置为1时禁用）
net.ipv4.tcp_no_metrics_save = 1
# 是否允许 IP 数据包转发（将服务器作为路由器使用）
net.ipv4.ip_forward = 1
# 系统范围内允许同时打开的文件描述符的最大数量
fs.file-max = 104857600
# 每个用户可以创建的监听实例的最大数量
fs.inotify.max_user_instances = 8192
# 每个进程可拥有的文件描述符的最大数量
fs.nr_open = 1048576
# 启用 TCP Fast Open，0是禁用，1是开启传入连接，2是开启传出连接，3是同时开启传入和传出
net.ipv4.tcp_fastopen = 3
# 虚拟内存交换操作（0表示避免使用swap，因为已做了大量网络调整）
vm.swappiness=0
EOF

sysctl -p
sysctl --system
echo always >/sys/kernel/mm/transparent_hugepage/enabled

cat >'/etc/systemd/system.conf' <<EOF
[Manager]
#DefaultTimeoutStartSec=90s
DefaultTimeoutStopSec=30s
#DefaultRestartSec=100ms
DefaultLimitCORE=infinity
DefaultLimitNOFILE=infinity
DefaultLimitNPROC=infinity
DefaultTasksMax=infinity
EOF

cat >'/etc/security/limits.conf' <<EOF
root     soft   nofile    1000000
root     hard   nofile    1000000
root     soft   nproc     unlimited
root     hard   nproc     unlimited
root     soft   core      unlimited
root     hard   core      unlimited
root     hard   memlock   unlimited
root     soft   memlock   unlimited
*     soft   nofile    1000000
*     hard   nofile    1000000
*     soft   nproc     unlimited
*     hard   nproc     unlimited
*     soft   core      unlimited
*     hard   core      unlimited
*     hard   memlock   unlimited
*     soft   memlock   unlimited
EOF
sed -i '/ulimit -SHn/d' /etc/profile
sed -i '/ulimit -SHu/d' /etc/profile
echo "ulimit -SHn 1000000" >>/etc/profile
if grep -q "pam_limits.so" /etc/pam.d/common-session; 
then
    :
else
sed -i '/required pam_limits.so/d' /etc/pam.d/common-session
echo "session required pam_limits.so" >>/etc/pam.d/common-session
fi
systemctl daemon-reload
echo -e "网络性能优化方案应用结束，可能需要重启！"
