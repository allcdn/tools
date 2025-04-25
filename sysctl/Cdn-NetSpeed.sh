#!/bin/bash

set -euo pipefail

# ====== 颜色定义 ======
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
NC='\033[0m'

# 防止脚本重复运行
SCRIPT_NAME=$(basename "$0")
LOCKFILE="/tmp/${SCRIPT_NAME}.lock"

# 检查锁文件是否存在，如果存在则检查对应进程是否在运行
if [ -f "$LOCKFILE" ]; then
  RUNNING_PID=$(cat "$LOCKFILE")
  if ps -p "$RUNNING_PID" > /dev/null; then
    echo -e "${RED}[!] ${SCRIPT_NAME} 已经在运行中 (PID: $RUNNING_PID)，退出...${NC}"
    exit 0
  else
    # 如果进程不存在，则删除过期的锁文件
    rm -f "$LOCKFILE"
  fi
fi

# 创建锁文件
echo $$ > "$LOCKFILE"

# 脚本退出时自动清理锁文件
trap 'rm -f "$LOCKFILE"; echo -e "${BLUE}[•] 清理锁文件...${NC}"' EXIT

echo -e "${BLUE}[•] 正在运行CDN节点网络和性能优化配置...${NC}"

# 获取系统信息
mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
cpu_cores=$(nproc)
kernel_version=$(uname -r)

# 检查内核版本是否支持BBR
if [[ $(uname -r | cut -d. -f1) -lt 4 || ($(uname -r | cut -d. -f1) -eq 4 && $(uname -r | cut -d. -f2) -lt 9) ]]; then
  echo -e "${RED}[!] 当前内核版本不支持BBR，需要4.9或更高版本${NC}"
  exit 1
fi

# 计算资源限制 - CDN场景下需要更高的文件描述符限制
nofile_soft=$((mem_gb * 65536))
nofile_hard=$((mem_gb * 131072))
[ "$nofile_soft" -lt 524288 ] && nofile_soft=524288
[ "$nofile_soft" -gt 2097152 ] && nofile_soft=2097152
[ "$nofile_hard" -gt 4194304 ] && nofile_hard=4194304

# 网络缓冲区 - CDN需要更大的接收和发送缓冲区
rmem_max=$((mem_gb * 2 * 1024 * 1024))
wmem_max=$((mem_gb * 2 * 1024 * 1024))
[ "$rmem_max" -gt 268435456 ] && rmem_max=268435456
[ "$rmem_max" -lt 33554432 ] && rmem_max=33554432
[ "$wmem_max" -gt 268435456 ] && wmem_max=268435456
[ "$wmem_max" -lt 33554432 ] && wmem_max=33554432

# 创建sysctl.d目录（如果不存在）
mkdir -p /etc/sysctl.d

# 备份原始配置（如果存在且未备份过）
BACKUP_SUFFIX="bak_$(date +%F)"
if [ -f /etc/sysctl.d/99-sysctl.conf ] && ! [ -f "/etc/sysctl.d/99-sysctl.conf.${BACKUP_SUFFIX}" ]; then
  cp /etc/sysctl.d/99-sysctl.conf "/etc/sysctl.d/99-sysctl.conf.${BACKUP_SUFFIX}"
  echo -e "${YELLOW}[•] 已备份原有配置文件到 /etc/sysctl.d/99-sysctl.conf.${BACKUP_SUFFIX}${NC}"
fi

# 如果原来使用的是/etc/sysctl.conf，提示用户
if [ -f /etc/sysctl.conf ] && [ "$(grep -v '^#' /etc/sysctl.conf | grep -v '^$' | wc -l)" -gt 0 ]; then
  echo -e "${YELLOW}[•] 检测到/etc/sysctl.conf中存在配置，将创建新的配置文件/etc/sysctl.d/99-sysctl.conf${NC}"
  echo -e "${YELLOW}[•] 原有配置文件/etc/sysctl.conf将保持不变，但新配置将优先生效${NC}"
fi

# 检查是否已经配置了BBR和fq_pie
NEED_SYSCTL_UPDATE=0
if [ -f /etc/sysctl.d/99-sysctl.conf ]; then
  if ! grep -q "net.ipv4.tcp_congestion_control = bbr" /etc/sysctl.d/99-sysctl.conf || \
     ! grep -q "net.core.default_qdisc = fq_pie" /etc/sysctl.d/99-sysctl.conf; then
    NEED_SYSCTL_UPDATE=1
  fi
else
  NEED_SYSCTL_UPDATE=1
fi

# 只有在需要更新时才写入配置
if [ "$NEED_SYSCTL_UPDATE" -eq 1 ]; then
  echo -e "${BLUE}[•] 更新系统网络配置...${NC}"
  
  # 写入优化配置 - 针对CDN场景的特定优化
  cat > /etc/sysctl.d/99-sysctl.conf << EOF
# CDN节点优化配置 - 由自动脚本生成 $(date +%F_%T)

# 开启BBR+fq_pie拥塞控制算法
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq_pie

# 文件系统和I/O优化 - CDN需要处理大量小文件
fs.file-max = 4194304
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 1024
fs.aio-max-nr = 1048576

# 网络栈优化 - 针对高并发连接
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 524288
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 131072

# TCP参数优化 - 提高吞吐量和降低延迟
net.ipv4.tcp_rmem = 4096 1048576 $rmem_max
net.ipv4.tcp_wmem = 4096 1048576 $wmem_max
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 4000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_low_latency = 1
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_notsent_lowat = 16384

# 安全性设置
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 本地端口范围扩大 - 支持更多并发连接
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1

# 虚拟内存优化 - CDN需要高效的内存管理
vm.swappiness = 5
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10
vm.max_map_count = 524288
vm.min_free_kbytes = $((mem_gb * 1024 * 8))
vm.vfs_cache_pressure = 40
vm.page_cluster = 3
vm.zone_reclaim_mode = 0

# 提高网络接口的接收队列长度
net.core.busy_read = 50
net.core.busy_poll = 50
EOF

  # 检查是否是XanMod内核
  is_xanmod=$(uname -r | grep -iq xanmod && echo 1 || echo 0)
  if [ "$is_xanmod" -eq 1 ]; then
    # 检查是否已经有XanMod特定配置
    if ! grep -q "# XanMod内核特定优化" /etc/sysctl.d/99-sysctl.conf; then
      cat >> /etc/sysctl.d/99-sysctl.conf << EOF
# XanMod内核特定优化
kernel.sched_autogroup_enabled = 0
kernel.sched_cfs_bandwidth_slice_us = 1000
kernel.unprivileged_userns_clone = 1
kernel.sched_migration_cost_ns = 5000
kernel.sched_min_granularity_ns = 1000000
kernel.sched_wakeup_granularity_ns = 500000
EOF
    fi
  fi

  # 应用sysctl配置
  echo -e "${GREEN}[•] 正在应用系统参数配置...${NC}"
  sysctl -p /etc/sysctl.d/99-sysctl.conf
else
  echo -e "${GREEN}[•] 系统网络配置已是最新，无需更新${NC}"
fi

# 备份limits配置（如果未备份过）
if [ -f /etc/security/limits.conf ] && ! [ -f "/etc/security/limits.conf.${BACKUP_SUFFIX}" ]; then
  cp /etc/security/limits.conf "/etc/security/limits.conf.${BACKUP_SUFFIX}"
  echo -e "${YELLOW}[•] 已备份资源限制配置到 /etc/security/limits.conf.${BACKUP_SUFFIX}${NC}"
fi

# 检查是否已经存在limits配置
NEED_LIMITS_UPDATE=0
if grep -q "# 系统资源限制优化" /etc/security/limits.conf; then
  echo -e "${YELLOW}[•] 检测到已存在资源限制配置，检查是否需要更新...${NC}"
  
  # 检查是否需要更新配置
  if ! grep -q "soft nofile $nofile_soft" /etc/security/limits.conf || \
     ! grep -q "hard nofile $nofile_hard" /etc/security/limits.conf; then
    NEED_LIMITS_UPDATE=1
    # 删除旧的配置块
    sed -i '/# 系统资源限制优化/,/# 结束系统资源限制/d' /etc/security/limits.conf
  else
    echo -e "${GREEN}[•] 资源限制配置已是最新，无需更新${NC}"
  fi
else
  NEED_LIMITS_UPDATE=1
fi

# 只有在需要更新时才添加limits配置
if [ "$NEED_LIMITS_UPDATE" -eq 1 ]; then
  echo -e "${BLUE}[•] 更新系统资源限制配置...${NC}"
  
  # 添加limits配置 - CDN场景需要更高的限制
  cat >> /etc/security/limits.conf << EOF
# 系统资源限制优化 - CDN节点配置 - 由自动脚本生成 $(date +%F_%T)
* soft nofile $nofile_soft
* hard nofile $nofile_hard
* soft nproc 1048576
* hard nproc 2097152
* soft memlock unlimited
* hard memlock unlimited
* soft stack 16384
* hard stack 32768
# 结束系统资源限制
EOF
fi

# 确保PAM配置正确
for session_file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
  if [ -f "$session_file" ]; then
    if ! grep -q "pam_limits.so" "$session_file"; then
      echo "session required pam_limits.so" >> "$session_file"
      echo -e "${GREEN}[•] 已添加pam_limits模块到 $session_file${NC}"
    else
      echo -e "${GREEN}[•] $session_file 已包含pam_limits模块${NC}"
    fi
  fi
done

# systemd 资源限制
if [ -f /etc/systemd/system.conf ]; then
  # 备份systemd配置（如果未备份过）
  if ! [ -f "/etc/systemd/system.conf.${BACKUP_SUFFIX}" ]; then
    cp /etc/systemd/system.conf "/etc/systemd/system.conf.${BACKUP_SUFFIX}"
  fi
  
  # 检查是否需要更新systemd配置
  NEED_SYSTEMD_UPDATE=0
  if grep -q "# Systemd资源限制优化" /etc/systemd/system.conf; then
    if ! grep -q "DefaultLimitNOFILE=$nofile_hard" /etc/systemd/system.conf; then
      NEED_SYSTEMD_UPDATE=1
      # 删除旧的配置块
      sed -i '/# Systemd资源限制优化/,/DefaultTasksMax=/d' /etc/systemd/system.conf
    else
      echo -e "${GREEN}[•] systemd资源限制已是最新，无需更新${NC}"
    fi
  else
    NEED_SYSTEMD_UPDATE=1
  fi
  
  if [ "$NEED_SYSTEMD_UPDATE" -eq 1 ]; then
    echo -e "${BLUE}[•] 更新systemd资源限制...${NC}"
    # 删除旧的配置
    sed -i '/DefaultLimitCORE\|DefaultLimitNOFILE\|DefaultLimitNPROC/d' /etc/systemd/system.conf
    # 添加新的配置
    cat >> /etc/systemd/system.conf << EOF
# Systemd资源限制优化 - CDN节点配置 - 由自动脚本生成 $(date +%F_%T)
DefaultLimitCORE=infinity
DefaultLimitNOFILE=$nofile_hard
DefaultLimitNPROC=2097152
DefaultTasksMax=500000
EOF
    echo -e "${GREEN}[•] 已更新systemd资源限制${NC}"
  fi
fi

# 优化网络接口队列长度
for interface in $(ls /sys/class/net/ | grep -v lo); do
  if [ -f "/sys/class/net/$interface/tx_queue_len" ]; then
    current_txqlen=$(cat "/sys/class/net/$interface/tx_queue_len")
    if [ "$current_txqlen" -ne 10000 ]; then
      echo -e "${BLUE}[•] 优化网络接口 $interface 的发送队列长度...${NC}"
      echo 10000 > /sys/class/net/$interface/tx_queue_len
      ip link set dev $interface txqueuelen 10000
    else
      echo -e "${GREEN}[•] 网络接口 $interface 的发送队列长度已优化${NC}"
    fi
  fi
done

# 验证BBR和fq_pie是否已启用
echo -e "${BLUE}[•] 验证BBR和fq_pie是否已启用...${NC}"
current_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
current_qdisc=$(sysctl -n net.core.default_qdisc)

if [ "$current_cc" = "bbr" ]; then
  echo -e "${GREEN}[✓] BBR已成功启用${NC}"
else
  echo -e "${RED}[!] BBR未启用，当前使用的是: $current_cc${NC}"
  echo -e "${YELLOW}[•] 尝试手动加载BBR模块...${NC}"
  modprobe tcp_bbr
  echo "bbr" > /proc/sys/net/ipv4/tcp_congestion_control
fi

if [ "$current_qdisc" = "fq_pie" ]; then
  echo -e "${GREEN}[✓] fq_pie队列算法已成功启用${NC}"
else
  echo -e "${RED}[!] fq_pie未启用，当前使用的是: $current_qdisc${NC}"
  echo -e "${YELLOW}[•] 尝试手动设置fq_pie...${NC}"
  echo "fq_pie" > /proc/sys/net/core/default_qdisc
fi

# 创建定时任务，定期清理网络连接表（检查是否已存在）
if [ ! -f /etc/cron.d/netclean ] || ! grep -q "conntrack -F" /etc/cron.d/netclean; then
  echo -e "${BLUE}[•] 设置定时清理网络连接表任务...${NC}"
  cat > /etc/cron.d/netclean << EOF
# 每小时清理一次过期连接
0 * * * * root /sbin/conntrack -F 2>/dev/null || true
EOF
else
  echo -e "${GREEN}[•] 定时清理网络连接表任务已存在${NC}"
fi

echo -e "${GREEN}[✓] CDN节点系统优化配置完成！${NC}"
echo -e "${YELLOW}[!] 建议重启系统以应用所有更改${NC}"
