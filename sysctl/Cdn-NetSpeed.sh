#!/bin/bash
set -euo pipefail

# ====== 颜色定义 ======
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
NC='\033[0m'

echo -e "${BLUE}[•] 正在运行智能适配系统优化...${NC}"

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

# 使用 bbr 而非 bbr2
tcp_cc="bbr"

# 检查是否支持所选算法
if ! grep -q "$tcp_cc" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
  # 如果 bbr 不支持，则使用 cubic
  tcp_cc="cubic"
  echo -e "${YELLOW}[!] 系统不支持BBR，将使用cubic${NC}"
fi

# 让用户选择队列调度算法
echo -e "${BLUE}[•] 请选择队列调度算法:${NC}"
PS3="请输入选项编号: "
options=("fq_codel (低延迟优先)" "fq (平衡选择)" "fq_pie (高吞吐优先)" "cake (更智能但需要支持)")
select opt in "${options[@]}"; do
  case $opt in
    "fq_codel (低延迟优先)")
      qdisc="fq_codel"
      break
      ;;
    "fq (平衡选择)")
      qdisc="fq"
      break
      ;;
    "fq_pie (高吞吐优先)")
      qdisc="fq_pie"
      break
      ;;
    "cake (更智能但需要支持)")
      qdisc="cake"
      break
      ;;
    *) 
      echo -e "${RED}无效选项，请重新选择${NC}"
      ;;
  esac
done

echo -e "${GREEN}[✓] 已选择 $qdisc 作为队列调度算法${NC}"

# 创建必要的目录
mkdir -p /etc/sysctl.d

# 备份原始配置（如果文件存在）
if [ -f /etc/sysctl.d/99-sysctl.conf ]; then
    cp /etc/sysctl.d/99-sysctl.conf /etc/sysctl.d/99-sysctl.conf.bak_$(date +%F_%T)
    echo -e "${GREEN}[✓] 已备份原始sysctl配置${NC}"
else
    echo -e "${YELLOW}[!] 未找到原始sysctl配置，将创建新文件${NC}"
    touch /etc/sysctl.d/99-sysctl.conf
fi

# 清空旧配置
echo -e "${YELLOW}[!] 正在清空旧配置...${NC}"
> /etc/sysctl.d/99-sysctl.conf

# 写入优化配置
cat > /etc/sysctl.d/99-sysctl.conf <<EOF
# 内核: $kernel_version | XanMod: $is_xanmod | 内存: ${mem_gb}GB | CPU: ${cpu_cores}核
# 优化时间: $(date '+%Y-%m-%d %H:%M:%S')

# 文件系统与监控优化
fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536

# TCP 拥塞控制与队列调度
net.core.default_qdisc = $qdisc
net.ipv4.tcp_congestion_control = $tcp_cc
net.mptcp.enabled = 1
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_base_mss = 1024

# TCP 连接优化
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 8
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5

# 队列与缓冲区优化
net.ipv4.tcp_max_syn_backlog = $((cpu_cores * 65536 < 524288 ? cpu_cores * 65536 : 524288))
net.core.somaxconn = 65535
net.core.netdev_max_backlog = $((cpu_cores * 65536 < 524288 ? cpu_cores * 65536 : 524288))

# TCP 内存参数
net.ipv4.tcp_rmem = 4096 262144 $rmem_max
net.ipv4.tcp_wmem = 4096 262144 $rmem_max
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = $rmem_max
net.core.wmem_max = $rmem_max
net.core.optmem_max = 65536

# UDP 优化
net.ipv4.udp_mem = $((rmem_max/2)) $rmem_max $((rmem_max*2))
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# 端口范围与转发
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# IPv6 优化
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

# 安全性设置
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

# 邻居表大小
net.ipv4.neigh.default.gc_thresh1 = 4096
net.ipv4.neigh.default.gc_thresh2 = 8192
net.ipv4.neigh.default.gc_thresh3 = 16384

# TCP 功能开关
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_moderate_rcvbuf = 1

# 本地网络路由
net.ipv4.conf.default.route_localnet = 1
net.ipv4.conf.all.route_localnet = 1
EOF

echo -e "${GREEN}[✓] 已写入新配置${NC}"

# 应用新配置
echo -e "${BLUE}[•] 正在应用新配置...${NC}"
sysctl --system

# 清空旧的资源限制配置
echo -e "${YELLOW}[!] 正在清空旧的资源限制配置...${NC}"
> /etc/security/limits.conf

# 设置 limits.conf
cat > /etc/security/limits.conf <<EOF
# 系统资源限制配置 - $(date '+%Y-%m-%d')
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
EOF

grep -q pam_limits.so /etc/pam.d/common-session || echo "session required pam_limits.so" >> /etc/pam.d/common-session
grep -q pam_limits.so /etc/pam.d/common-session-noninteractive || echo "session required pam_limits.so" >> /etc/pam.d/common-session-noninteractive

# 清空旧的systemd资源限制
echo -e "${YELLOW}[!] 正在清空旧的systemd资源限制...${NC}"
sed -i '/DefaultLimitCORE\|DefaultLimitNOFILE\|DefaultLimitNPROC/d' /etc/systemd/system.conf

# systemd 资源限制
cat >> /etc/systemd/system.conf <<EOF
[Manager]
DefaultLimitCORE=infinity
DefaultLimitNOFILE=$nofile_hard
DefaultLimitNPROC=$nofile_hard
EOF

systemctl daemon-reexec

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

# 输出最终结果
echo -e "\n${BLUE}==================== 优化完成报告 ====================${NC}"
echo -e "${GREEN}✔ 内核版本        :${NC} $kernel_version"
echo -e "${GREEN}✔ 内存            :${NC} ${mem_gb} GB"
echo -e "${GREEN}✔ CPU 核心        :${NC} ${cpu_cores} 核"
echo -e "${GREEN}✔ 拥塞控制算法    :${NC} $tcp_cc"
echo -e "${GREEN}✔ 队列调度算法    :${NC} $qdisc"
echo -e "${GREEN}✔ 文件描述符      :${NC} soft=$nofile_soft, hard=$nofile_hard"
echo -e "${GREEN}✔ TCP 缓冲上限    :${NC} $rmem_max 字节（约 $((rmem_max/1024/1024))MB）"
echo -e "${GREEN}✔ IPv6 优化       :${NC} 已启用"
echo -e "${GREEN}✔ UDP/QUIC 支持   :${NC} 已启用"
echo -e "${GREEN}✔ gRPC/HTTP2 增强 :${NC} TCP_FASTOPEN + $tcp_cc"
echo -e "${GREEN}✔ 系统限制生效    :${NC} ulimit + systemd + pam"
echo -e "${GREEN}✔ 立即生效方式    :${NC} sysctl --system, prlimit, ulimit"
echo -e "${GREEN}✔ 验证命令        :${NC} ulimit -n ; sysctl -a | grep tcp"
echo -e "\n${YELLOW}提示: 如需保障 limits.conf 生效，请重启服务或重新登录会话${NC}"
echo -e "${BLUE}=====================================================${NC}"
