#!/bin/bash

set -euo pipefail

# ====== 颜色定义 ======

RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
NC='\033[0m'

# 脚本版本
SCRIPT_VERSION="1.1.0"

# 创建锁文件以防止多实例运行
LOCK_FILE="/var/lock/xanmodpro.lock"

# 有效的流量管理算法列表
valid_qos=("fq" "fq_codel" "fq_pie" "cake" "pfifo_fast" "sfq" "red" "tbf")

# 配置文件路径
CONFIG_FILE="/etc/xanmodpro.conf"

# ======================================================
# 辅助函数
# ======================================================

# 获取脚本执行状态
check_previous_run() {
  if [ -f "$CONFIG_FILE" ]; then
    # 读取先前配置
    source "$CONFIG_FILE"
    echo -e "${BLUE}检测到先前配置:${NC}"
    echo -e " ${GREEN}● 服务器类型:${NC} ${SERVER_TYPE:-未知}"
    echo -e " ${GREEN}● 流量管理算法:${NC} ${QOS_ALGO:-未知}"
    echo -e " ${GREEN}● 上次运行时间:${NC} ${LAST_RUN:-未知}"
    echo
    local reuse_config=""
    read -p "$(echo -e ${YELLOW}"是否使用先前配置? [y/N]: "${NC})" reuse_config
    if [[ "$reuse_config" =~ ^[Yy]$ ]]; then
      REUSE_CONFIG=1
      return 0
    fi
  fi
  REUSE_CONFIG=0
  return 1
}

# 确保脚本只有一个实例在运行
ensure_single_instance() {
  if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$pid" ] && ps -p "$pid" > /dev/null; then
      echo -e "${RED}错误: 脚本已在运行 (PID: $pid)${NC}"
      exit 1
    else
      # 锁文件存在但进程不存在，清理旧锁文件
      rm -f "$LOCK_FILE"
    fi
  fi
  # 创建锁文件
  echo $$ > "$LOCK_FILE"
  # 脚本退出时自动清理锁文件
  trap 'rm -f "$LOCK_FILE"; echo -e "\n${GREEN}已清理锁文件${NC}"; exit' EXIT INT TERM
}

# 检查是否为root用户
check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}错误: 此脚本必须以root用户运行${NC}"
    exit 1
  fi
}

# 获取系统信息
get_system_info() {
  mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
  cpu_cores=$(nproc)
  is_xanmod=$(uname -r | grep -iq xanmod && echo 1 || echo 0)
  kernel_version=$(uname -r)
}

# 检查内核是否支持特定参数
check_kernel_param() {
  local param="$1"
  if sysctl -q "$param" &>/dev/null; then
    return 0 # 参数存在
  else
    return 1 # 参数不存在
  fi
}

# 保存配置到文件
save_config() {
  cat > "$CONFIG_FILE" <<EOF
# XanModPro配置文件
# 创建于: $(date)

# 服务器类型
SERVER_TYPE="$SERVER_TYPE"

# 流量管理算法
QOS_ALGO="$QOS_ALGO"

# 上次运行时间
LAST_RUN="$(date)"

# 性能参数
NOFILE_SOFT="$nofile_soft"
NOFILE_HARD="$nofile_hard"
SOMAXCONN="$somaxconn"
BACKLOG="$backlog"
RMEM_MAX="$rmem_max"
WMEM_MAX="$wmem_max"
EOF
  echo -e "${GREEN}✓ 配置已保存到 $CONFIG_FILE${NC}"
}

# 选择服务器类型
choose_server_type() {
  if [ "${REUSE_CONFIG:-0}" -eq 1 ] && [ -n "${SERVER_TYPE:-}" ]; then
    echo -e "${GREEN}使用先前配置的服务器类型: $SERVER_TYPE${NC}"
    return 0
  fi
  
  echo -e "${BLUE}===== 第1步：选择服务器类型 =====${NC}"
  echo
  echo -e "请选择服务器类型:"
  echo -e " ${GREEN}1) Web服务器${NC} - 适用于运行网站、API和应用服务"
  echo -e " ${GREEN}2) CDN节点${NC} - 适用于内容分发、大文件传输"
  echo -e " ${GREEN}3) VPN服务器${NC} - 适用于VPN、代理服务"
  echo -e " ${GREEN}4) 通用服务器${NC} - 适用于多用途服务器"
  echo
  
  local choice
  read -p "$(echo -e ${YELLOW}"请输入选择 [1-4]: "${NC})" choice
  
  case $choice in
    1) SERVER_TYPE="web" ;;
    2) SERVER_TYPE="cdn" ;;
    3) SERVER_TYPE="vpn" ;;
    4) SERVER_TYPE="general" ;;
    *) 
      echo -e "${RED}无效选择，使用默认值: 通用服务器${NC}"
      SERVER_TYPE="general"
      ;;
  esac
  
  echo -e "${GREEN}已选择: $SERVER_TYPE 服务器${NC}"
  echo
}

# 选择流量管理算法
choose_qos_algorithm() {
  if [ "${REUSE_CONFIG:-0}" -eq 1 ] && [ -n "${QOS_ALGO:-}" ]; then
    echo -e "${GREEN}使用先前配置的流量管理算法: $QOS_ALGO${NC}"
    
    # 检查CAKE模块
    if [ "$QOS_ALGO" = "cake" ]; then
      if ! modprobe sch_cake &>/dev/null; then
        echo -e "${RED}无法加载sch_cake模块，尝试安装必要的内核模块...${NC}"
        # 检测Debian版本
        if [ -f /etc/debian_version ]; then
          debian_version=$(cat /etc/debian_version | cut -d. -f1)
          # Debian安装模块
          if command -v apt-get &>/dev/null; then
            apt-get update -qq
            if [[ "$debian_version" == "12" ]]; then
              apt-get install -y linux-modules-extra-$(uname -r) 2>/dev/null ||
              apt-get install -y linux-image-$(uname -r) 2>/dev/null || true
            else
              apt-get install -y linux-modules-extra-$(uname -r) 2>/dev/null || true
            fi
          fi
        fi
        # 再次尝试加载
        modprobe sch_cake 2>/dev/null || {
          echo -e "${RED}CAKE模块安装失败，切换到备选方案${NC}"
          case $SERVER_TYPE in
            "web"|"cdn") QOS_ALGO="fq_codel" ;;
            "vpn") QOS_ALGO="fq_pie" ;;
            *) QOS_ALGO="fq" ;;
          esac
          echo -e "${YELLOW}已切换到 $QOS_ALGO 作为备选方案${NC}"
        }
      else
        echo -e "${GREEN}CAKE队列管理模块已加载${NC}"
      fi
    fi
    return 0
  fi
  
  echo -e "${BLUE}===== 第2步：选择流量管理算法 =====${NC}"
  echo
  echo -e "请选择流量管理算法:"
  echo -e " ${GREEN}1) FQ (Fair Queuing)${NC} - 公平队列，适合一般用途"
  echo -e " ${GREEN}2) FQ_CODEL${NC} - 减少缓冲膨胀，适合Web服务器"
  echo -e " ${GREEN}3) FQ_PIE${NC} - 改进的延迟控制，适合VPN"
  echo -e " ${GREEN}4) CAKE${NC} - 综合算法，适合高负载服务器"
  echo -e " ${GREEN}5) 其他${NC} - 手动指定算法"
  echo
  
  local choice
  read -p "$(echo -e ${YELLOW}"请输入选择 [1-5]: "${NC})" choice
  
  case $choice in
    1) QOS_ALGO="fq" ;;
    2) QOS_ALGO="fq_codel" ;;
    3) QOS_ALGO="fq_pie" ;;
    4) 
      QOS_ALGO="cake"
      # 检查是否支持CAKE
      if ! modprobe sch_cake &>/dev/null; then
        echo -e "${RED}无法加载sch_cake模块，尝试安装必要的内核模块...${NC}"
        # 检测Debian版本
        if [ -f /etc/debian_version ]; then
          debian_version=$(cat /etc/debian_version | cut -d. -f1)
          # Debian安装模块
          if command -v apt-get &>/dev/null; then
            apt-get update -qq
            if [[ "$debian_version" == "12" ]]; then
              apt-get install -y linux-modules-extra-$(uname -r) 2>/dev/null ||
              apt-get install -y linux-image-$(uname -r) 2>/dev/null || true
            else
              apt-get install -y linux-modules-extra-$(uname -r) 2>/dev/null || true
            fi
          fi
        fi
        # 再次尝试加载
        modprobe sch_cake 2>/dev/null || {
          echo -e "${RED}CAKE模块安装失败，切换到备选方案${NC}"
          case $SERVER_TYPE in
            "web"|"cdn") QOS_ALGO="fq_codel" ;;
            "vpn") QOS_ALGO="fq_pie" ;;
            *) QOS_ALGO="fq" ;;
          esac
          echo -e "${YELLOW}已切换到 $QOS_ALGO 作为备选方案${NC}"
        }
      else
        echo -e "${GREEN}CAKE队列管理模块已加载${NC}"
      fi
      ;;
    5)
      echo -e "可用算法: ${valid_qos[*]}"
      read -p "$(echo -e ${YELLOW}"请输入算法名称: "${NC})" custom_algo
      if [[ " ${valid_qos[*]} " =~ " ${custom_algo} " ]]; then
        QOS_ALGO="$custom_algo"
      else
        echo -e "${RED}无效算法，使用默认值: fq${NC}"
        QOS_ALGO="fq"
      fi
      ;;
    *)
      echo -e "${RED}无效选择，使用默认值: fq${NC}"
      QOS_ALGO="fq"
      ;;
  esac
  
  echo -e "${GREEN}已选择: $QOS_ALGO 流量管理算法${NC}"
  echo
}

# ======================================================
# 第三步：应用优化配置
# ======================================================

apply_optimizations() {
  # 如果重用配置并且参数已经存在，则使用配置文件中的值
  if [ "${REUSE_CONFIG:-0}" -eq 1 ] && [ -n "${NOFILE_SOFT:-}" ] && [ -n "${NOFILE_HARD:-}" ] && [ -n "${SOMAXCONN:-}" ] && [ -n "${BACKLOG:-}" ] && [ -n "${RMEM_MAX:-}" ] && [ -n "${WMEM_MAX:-}" ]; then
    echo -e "${GREEN}使用之前计算的性能参数${NC}"
    nofile_soft=$NOFILE_SOFT
    nofile_hard=$NOFILE_HARD
    somaxconn=$SOMAXCONN
    backlog=$BACKLOG
    rmem_max=$RMEM_MAX
    wmem_max=$WMEM_MAX
  else
    # 计算新的性能参数
    calculate_performance_params
  fi
  
  echo -e "${BLUE}===== 第3步：应用网络优化 =====${NC}"
  echo
  echo -e "${BLUE}正在应用$SERVER_TYPE服务器优化，流量管理算法: $QOS_ALGO${NC}"
  echo
  
  # 备份原始配置
  backup_configs
  
  # 应用sysctl配置
  apply_sysctl_settings
  
  # 应用队列管理
  apply_queue_management
  
  # 设置系统资源限制
  setup_limits
  
  # 创建持久化服务
  create_persistence_service
  
  # 保存当前配置
  save_config
  
  echo -e "${GREEN}✓ 网络优化配置已应用${NC}"
  echo
}

# 计算性能参数
calculate_performance_params() {
  # 基于服务器类型计算资源限制
  case $SERVER_TYPE in
    "web")
      nofile_soft=$((mem_gb * 65536))
      nofile_hard=$((mem_gb * 131072))
      somaxconn=65535
      backlog=$((cpu_cores * 65536))
      ;;
    "cdn")
      nofile_soft=$((mem_gb * 131072))
      nofile_hard=$((mem_gb * 262144))
      somaxconn=131070
      backlog=$((cpu_cores * 131072))
      ;;
    "vpn")
      nofile_soft=$((mem_gb * 65536))
      nofile_hard=$((mem_gb * 131072))
      somaxconn=32768
      backlog=$((cpu_cores * 32768))
      ;;
    *)
      nofile_soft=$((mem_gb * 32768))
      nofile_hard=$((mem_gb * 65536))
      somaxconn=16384
      backlog=$((cpu_cores * 16384))
      ;;
  esac
  
  # 限制值边界检查
  [ "$nofile_soft" -lt 262144 ] && nofile_soft=262144
  [ "$nofile_soft" -gt 2097152 ] && nofile_soft=2097152
  [ "$nofile_hard" -gt 4194304 ] && nofile_hard=4194304
  
  # TCP/UDP缓冲区大小
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
}

# 备份配置文件
backup_configs() {
  echo -e "${BLUE}备份原始配置...${NC}"
  # 生成唯一备份后缀
  BACKUP_SUFFIX=$(date +%F_%H%M%S)
  
  # 备份sysctl配置
  if [ -f /etc/sysctl.conf ] && [ ! -f /etc/sysctl.conf.bak_${BACKUP_SUFFIX} ]; then
    cp /etc/sysctl.conf /etc/sysctl.conf.bak_${BACKUP_SUFFIX}
    echo -e "${GREEN}✓ 已备份 /etc/sysctl.conf${NC}"
  fi
  
  # 备份limits配置
  if [ -f /etc/security/limits.conf ] && [ ! -f /etc/security/limits.conf.bak_${BACKUP_SUFFIX} ]; then
    cp /etc/security/limits.conf /etc/security/limits.conf.bak_${BACKUP_SUFFIX}
    echo -e "${GREEN}✓ 已备份 /etc/security/limits.conf${NC}"
  fi
  
  # 备份systemd配置
  if [ -f /etc/systemd/system.conf ] && [ ! -f /etc/systemd/system.conf.bak_${BACKUP_SUFFIX} ]; then
    cp /etc/systemd/system.conf /etc/systemd/system.conf.bak_${BACKUP_SUFFIX}
    echo -e "${GREEN}✓ 已备份 /etc/systemd/system.conf${NC}"
  fi
}

# 应用sysctl设置
apply_sysctl_settings() {
  # 创建临时配置文件
  TMP_SYSCTL=$(mktemp -p /tmp sysctl_temp.XXXXXX)
  
  # 清除旧设置前先检查文件是否存在
  if [ -f /etc/sysctl.conf ]; then
    # 清除旧的设置
    sed -i '/# 内核:/d' /etc/sysctl.conf
    sed -i '/# 流量管理算法:/d' /etc/sysctl.conf
    sed -i '/# 服务器类型:/d' /etc/sysctl.conf
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.mptcp.enabled/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
    sed -i '/fs.inotify.max_user/d' /etc/sysctl.conf
    sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
    sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
  fi
  
  # 写入配置文件头部
  cat > "$TMP_SYSCTL" <<EOF
# 内核: $(uname -r)
# 流量管理算法: $QOS_ALGO
# 服务器类型: $SERVER_TYPE
# 应用时间: $(date)

EOF
  
  # 设置队列管理算法
  if check_kernel_param "net.core.default_qdisc"; then
    echo "net.core.default_qdisc = $QOS_ALGO" >> "$TMP_SYSCTL"
    echo -e "${GREEN}设置 net.core.default_qdisc = $QOS_ALGO${NC}"
  else
    echo -e "${YELLOW}内核不支持 net.core.default_qdisc，将使用tc命令设置${NC}"
  fi
  
  # 设置BBR拥塞控制
  if check_kernel_param "net.ipv4.tcp_congestion_control"; then
    # 检查系统是否支持BBR
    if [ -f /proc/sys/net/ipv4/tcp_available_congestion_control ] &&
       grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control; then
      echo "net.ipv4.tcp_congestion_control = bbr" >> "$TMP_SYSCTL"
      echo -e "${GREEN}设置BBR拥塞控制算法${NC}"
    else
      echo -e "${YELLOW}内核不支持BBR拥塞控制算法，跳过${NC}"
    fi
  fi
  
  # 添加通用网络参数
  cat >> "$TMP_SYSCTL" <<EOF
# 文件句柄限制
fs.file-max = $nofile_hard
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 8192

# 网络连接参数
net.core.somaxconn = $somaxconn
net.core.netdev_max_backlog = $backlog
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.optmem_max = 65536

# TCP参数
net.ipv4.tcp_rmem = 4096 87380 $rmem_max
net.ipv4.tcp_wmem = 4096 65536 $wmem_max
net.ipv4.tcp_mem = 65536 131072 262144
net.ipv4.udp_mem = 65536 131072 262144
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = $backlog
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.ip_local_port_range = 1024 65535
EOF
  
  # 根据服务器类型添加特定优化
  case $SERVER_TYPE in
    "web")
      cat >> "$TMP_SYSCTL" <<EOF
# Web服务器特定优化
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 16384
EOF
      ;;
    "cdn")
      cat >> "$TMP_SYSCTL" <<EOF
# CDN节点特定优化
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_window_scaling = 1
EOF
      ;;
    "vpn")
      cat >> "$TMP_SYSCTL" <<EOF
# VPN服务器特定优化
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_ecn = 0
net.ipv4.tcp_adv_win_scale = 3
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
EOF
      # 加载必要的内核模块
      for module in nf_conntrack xt_conntrack iptable_nat; do
        if ! lsmod | grep -q "^$module"; then
          modprobe $module 2>/dev/null || echo -e "${YELLOW}模块 $module 加载失败 (可能不影响功能)${NC}"
        else
          echo -e "${GREEN}模块 $module 已加载${NC}"
        fi
      done
      ;;
    *)
      cat >> "$TMP_SYSCTL" <<EOF
# 通用服务器优化
net.ipv4.tcp_slow_start_after_idle = 0
EOF
      ;;
  esac
  
  # 检查IPv6支持
  if [ -d /proc/sys/net/ipv6 ]; then
    cat >> "$TMP_SYSCTL" <<EOF
# IPv6设置
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
EOF
  fi
  
  # 应用sysctl配置
  cat "$TMP_SYSCTL" >> /etc/sysctl.conf
  sysctl -p
  
  # 清理临时文件
  rm -f "$TMP_SYSCTL"
  
  echo -e "${GREEN}✓ 系统内核参数已优化${NC}"
}

# 应用队列管理
apply_queue_management() {
  echo -e "${BLUE}设置队列管理算法...${NC}"
  
  # 检查tc命令是否可用
  if ! command -v tc &>/dev/null; then
    echo -e "${YELLOW}未找到tc命令，尝试安装iproute2包...${NC}"
    if command -v apt-get &>/dev/null; then
      apt-get update -qq
      apt-get install -y iproute2
    elif command -v yum &>/dev/null; then
      yum install -y iproute
    fi
  fi
  
  # 确认tc命令现在可用
  if command -v tc &>/dev/null; then
    # 获取所有网络接口并设置队列
    interfaces=$(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1)
    for iface in $interfaces; do
      if [[ "$iface" != "lo" && "$iface" != "" ]]; then
        # 检查接口是否已经使用相同算法
        current_qdisc=$(tc qdisc show dev $iface | grep -q "$QOS_ALGO" && echo "match" || echo "nomatch")
        if [ "$current_qdisc" = "nomatch" ]; then
          echo -e "${BLUE}在接口 $iface 上设置 $QOS_ALGO 队列管理算法${NC}"
          tc qdisc replace dev $iface root $QOS_ALGO 2>/dev/null || true
        else
          echo -e "${GREEN}接口 $iface 已设置为 $QOS_ALGO${NC}"
        fi
      fi
    done
  else
    echo -e "${RED}无法设置队列管理算法，tc命令不可用${NC}"
  fi
}

# 设置系统资源限制
setup_limits() {
  echo -e "${BLUE}设置系统资源限制...${NC}"
  
  # 确保limits.conf存在
  touch /etc/security/limits.conf
  
  # 清除旧的设置
  sed -i '/^* soft nofile/d' /etc/security/limits.conf
  sed -i '/^* hard nofile/d' /etc/security/limits.conf
  sed -i '/^* soft nproc/d' /etc/security/limits.conf
  sed -i '/^* hard nproc/d' /etc/security/limits.conf
  sed -i '/^* soft core/d' /etc/security/limits.conf
  sed -i '/^* hard core/d' /etc/security/limits.conf
  sed -i '/^* soft memlock/d' /etc/security/limits.conf
  sed -i '/^* hard memlock/d' /etc/security/limits.conf
  
  # 写入新设置
  cat >> /etc/security/limits.conf <<EOF
# XanModPro优化 - $(date)
* soft nofile $nofile_soft
* hard nofile $nofile_hard
* soft nproc $nofile_soft
* hard nproc $nofile_hard
* soft core unlimited
* hard core unlimited
* soft memlock unlimited
* hard memlock unlimited
EOF
  
  # 确保PAM配置包含limits.conf
  for pam_file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive /etc/pam.d/login /etc/pam.d/sshd; do
    if [ -f "$pam_file" ]; then
      if ! grep -q "pam_limits.so" "$pam_file"; then
        echo "session required pam_limits.so" >> "$pam_file"
      fi
    fi
  done
  
  # systemd 资源限制
  if [ -d /etc/systemd ]; then
    if [ -f /etc/systemd/system.conf ]; then
      # 清除旧的设置
      sed -i '/DefaultLimitCORE\|DefaultLimitNOFILE\|DefaultLimitNPROC/d' /etc/systemd/system.conf
      
      # 检查Manager部分是否存在
      if ! grep -q '\[Manager\]' /etc/systemd/system.conf; then
        echo -e "\n[Manager]" >> /etc/systemd/system.conf
      fi
      
      # 写入新设置
      sed -i '/\[Manager\]/a DefaultLimitCORE=infinity\nDefaultLimitNOFILE='$nofile_hard'\nDefaultLimitNPROC='$nofile_hard /etc/systemd/system.conf
      
      # 重载systemd
      systemctl daemon-reexec
    fi
  fi
  
  # 设置当前会话文件描述符限制
  echo -e "${BLUE}设置当前会话文件描述符限制...${NC}"
  current_max=$(ulimit -Hn)
  if [ "$nofile_hard" -le "$current_max" ]; then
    ulimit -n "$nofile_hard" 2>/dev/null || echo -e "${YELLOW}无法设置当前会话文件描述符限制${NC}"
  else
    echo -e "${YELLOW}当前shell会话最大限制为${current_max}，已跳过设置更高的ulimit。请重启系统或重新登录生效。${NC}"
  fi
}

# 创建持久化服务
create_persistence_service() {
  echo -e "${BLUE}创建启动服务确保设置持久化...${NC}"
  
  # 准备服务执行脚本
  SYSCTL_SERVICE_SCRIPT="/usr/local/bin/apply-sysctl.sh"
  
  # 创建服务执行脚本
  cat > "$SYSCTL_SERVICE_SCRIPT" <<EOF
#!/bin/bash
# XanModPro持久化服务
# 创建于: $(date)

# 应用sysctl设置
sysctl -p /etc/sysctl.conf

# 应用队列管理算法
if command -v tc &>/dev/null; then
  interfaces=\$(ip -o link show | awk -F': ' '{print \$2}' | cut -d@ -f1)
  for iface in \$interfaces; do
    if [[ "\$iface" != "lo" && "\$iface" != "" ]]; then
      tc qdisc replace dev \$iface root $QOS_ALGO 2>/dev/null || true
    fi
  done
fi

# 加载必要的内核模块
if [[ "$SERVER_TYPE" == "vpn" ]]; then
  for module in nf_conntrack xt_conntrack iptable_nat; do
    modprobe \$module 2>/dev/null || true
  done
fi

exit 0
EOF
  
  chmod +x "$SYSCTL_SERVICE_SCRIPT"
  
  # 创建systemd服务
  if [[ -d /etc/systemd/system ]]; then
    # 如果已存在则更新
    if [ -f /etc/systemd/system/apply-sysctl.service ]; then
      systemctl disable apply-sysctl.service 2>/dev/null || true
      rm /etc/systemd/system/apply-sysctl.service
    fi
    
    # 创建systemd服务文件
    cat > /etc/systemd/system/apply-sysctl.service <<EOF
[Unit]
Description=XanModPro系统优化
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/apply-sysctl.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    
    # 启用服务
    systemctl daemon-reload
    systemctl enable apply-sysctl.service
    echo -e "${GREEN}✓ 创建并启用systemd服务${NC}"
  else
    # 对于非systemd系统，使用rc.local
    if [ -f /etc/rc.local ]; then
      # 检查rc.local是否包含我们的脚本
      if ! grep -q "$SYSCTL_SERVICE_SCRIPT" /etc/rc.local; then
        # 创建临时文件
        TEMP_RC=$(mktemp)
        
        # 检查是否有exit 0行
        if grep -q "^exit 0" /etc/rc.local; then
          # 在exit 0之前插入我们的脚本
          sed "/^exit 0/i\\$SYSCTL_SERVICE_SCRIPT" /etc/rc.local > "$TEMP_RC"
        else
          # 添加到文件末尾
          cat /etc/rc.local > "$TEMP_RC"
          echo "$SYSCTL_SERVICE_SCRIPT" >> "$TEMP_RC"
          echo "exit 0" >> "$TEMP_RC"
        fi
        
        # 确保有执行权限
        chmod +x "$TEMP_RC"
        
        # 覆盖原文件
        cat "$TEMP_RC" > /etc/rc.local
        rm -f "$TEMP_RC"
      fi
    else
      # 创建新的rc.local
      cat > /etc/rc.local <<EOF
#!/bin/bash
# rc.local
$SYSCTL_SERVICE_SCRIPT
exit 0
EOF
      chmod +x /etc/rc.local
    fi
    
    echo -e "${GREEN}✓ 更新 /etc/rc.local${NC}"
    
    # 对于使用systemd的系统，确保rc-local服务启用
    if [ -d /etc/systemd/system ] && ! systemctl is-enabled rc-local.service &>/dev/null; then
      if [ ! -f /etc/systemd/system/rc-local.service ]; then
        cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local Compatibility
After=network.target

[Service]
Type=oneshot
ExecStart=/etc/rc.local
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
      fi
      systemctl enable rc-local.service
      echo -e "${GREEN}✓ 启用 rc-local.service${NC}"
    fi
  fi
}

# 显示优化总结
show_summary() {
  echo -e "${BLUE}===== 优化总结 =====${NC}"
  echo
  
  # 显示当前系统状态
  echo -e "${GREEN}系统状态:${NC}"
  
  # 检查文件描述符限制
  current_nofile=$(ulimit -n)
  echo -e "${GREEN}● 文件描述符限制:${NC} $current_nofile / $nofile_hard"
  
  # 检查BBR状态
  current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "未知")
  if [[ "$current_cc" == "bbr" ]]; then
    echo -e "${GREEN}● BBR拥塞控制:${NC} 已启用"
  else
    echo -e "${YELLOW}● BBR拥塞控制:${NC} 未启用 (当前: $current_cc)"
  fi
  
  # 检查队列管理算法是否已应用
  current_qdisc=$(tc qdisc show | grep -v "pfifo_fast" | head -n1)
  if [[ -n "$current_qdisc" ]]; then
    echo -e "${GREEN}● 队列规则:${NC} $current_qdisc"
  else
    echo -e "${YELLOW}● 队列规则:${NC} 未检测到，请重启系统"
  fi
  
  # 验证持久化设置
  if systemctl is-enabled apply-sysctl.service &>/dev/null; then
    echo -e "${GREEN}● 持久化配置:${NC} apply-sysctl.service 已启用"
  elif [ -x /etc/rc.local ]; then
    echo -e "${GREEN}● 持久化配置:${NC} /etc/rc.local 已创建"
  else
    echo -e "${YELLOW}● 持久化配置:${NC} 未完全设置，可能需要手动配置"
  fi
  
  # 服务器类型特定信息
  case $SERVER_TYPE in
    "web")
      echo -e "${GREEN}● Web服务器优化:${NC} 高并发连接、低延迟、快速响应"
      ;;
    "cdn")
      echo -e "${GREEN}● CDN节点优化:${NC} 大缓冲区、高吞吐量、最优传输效率"
      ;;
    "vpn")
      echo -e "${GREEN}● VPN服务器优化:${NC} IP转发、连接跟踪、NAT支持"
      ;;
    *)
      echo -e "${GREEN}● 通用服务器优化:${NC} 均衡性能配置"
      ;;
  esac
  
  echo
  echo -e "${YELLOW}验证命令:${NC}"
  echo -e " • 检查文件描述符限制: ${GREEN}ulimit -n${NC}"
  echo -e " • 检查TCP配置: ${GREEN}sysctl -a | grep tcp${NC}"
  echo -e " • 检查队列策略: ${GREEN}tc qdisc show${NC}"
  echo -e " • 检查最大连接数: ${GREEN}sysctl net.core.somaxconn${NC}"
  echo -e " • 检查配置文件: ${GREEN}cat $CONFIG_FILE${NC}"
  
  echo
  echo -e "${BLUE}===== 优化完成 =====${NC}"
  echo -e "${GREEN}系统网络优化配置已应用并设置为在启动时自动加载${NC}"
  
  # 如果是重用配置，显示不同信息
  if [ "${REUSE_CONFIG:-0}" -eq 1 ]; then
    echo -e "${GREEN}使用了之前保存的配置，所有设置已重新应用${NC}"
  else
    echo -e "${YELLOW}建议重启系统以确保所有优化完全生效${NC}"
  fi
}

# ======================================================
# 主程序
# ======================================================

# 确保以root用户运行
check_root

# 确保脚本只有一个实例在运行
ensure_single_instance

# 获取系统信息
get_system_info

# 显示脚本头部
echo -e "${BLUE}=====================================${NC}"
echo -e "${GREEN} XanModPro 系统优化脚本 v$SCRIPT_VERSION ${NC}"
echo -e "${BLUE}=====================================${NC}"
echo

echo -e "${GREEN}系统信息:${NC}"
echo -e " • 内核版本: $kernel_version"
echo -e " • 内存大小: ${mem_gb}GB"
echo -e " • CPU核心数: $cpu_cores"
echo -e " • 是否XanMod内核: $([ $is_xanmod -eq 1 ] && echo "是" || echo "否")"
echo

# 检查之前运行状态
if check_previous_run; then
  read -p "$(echo -e ${YELLOW}"是否跳过配置向导并直接应用优化? [Y/n]: "${NC})" skip_wizard
  if [[ "$skip_wizard" =~ ^[Nn]$ ]]; then
    REUSE_CONFIG=0
  fi
fi

# 1. 选择服务器类型
choose_server_type

# 2. 选择流量管理算法
choose_qos_algorithm

# 3. 应用优化配置
apply_optimizations

# 4. 显示优化总结
show_summary

exit 0
