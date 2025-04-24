#!/bin/bash
set -euo pipefail

# ====== 颜色定义 ======
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
NC='\033[0m'

# 脚本版本信息
SCRIPT_VERSION="2.0"
SCRIPT_HASH=$(md5sum "$0" 2>/dev/null | cut -d ' ' -f 1 || echo "unknown")
SCRIPT_TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")

# 有效的流量管理算法列表
valid_qos=("fq" "fq_codel" "fq_pie" "cake" "pfifo_fast" "sfq" "red" "tbf")

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}错误: 此脚本必须以root用户运行${NC}"
   exit 1
fi

# 检查是否已存在锁文件，防止重复运行
LOCK_FILE="/var/lock/network_optimize.lock"
if [ -f "$LOCK_FILE" ]; then
    # 检查锁文件是否过期(10分钟)
    LOCK_TIME=$(stat -c %Y "$LOCK_FILE" 2>/dev/null || echo 0)
    CURRENT_TIME=$(date +%s)
    if (( CURRENT_TIME - LOCK_TIME < 600 )); then
        echo -e "${YELLOW}警告: 另一个优化脚本实例正在运行。${NC}"
        echo -e "${YELLOW}如果确定没有其他实例在运行，可以删除锁文件: ${LOCK_FILE}${NC}"
        echo -e "${YELLOW}或等待10分钟后再试。${NC}"
        exit 1
    else
        echo -e "${YELLOW}发现过期的锁文件，继续执行...${NC}"
    fi
fi

# 创建锁文件
echo "$SCRIPT_TIMESTAMP" > "$LOCK_FILE"

# 当脚本结束时清理锁文件和临时文件
cleanup() {
    rm -f "$LOCK_FILE" 2>/dev/null || true
    # 清理其他临时文件
    rm -f "/tmp/sysctl_temp.conf" 2>/dev/null || true
    echo -e "\n${BLUE}脚本执行完成，清理临时文件${NC}"
}

# 设置退出时自动调用cleanup函数
trap cleanup EXIT

# 获取系统信息
mem_gb=$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)
cpu_cores=$(nproc)
is_xanmod=$(uname -r | grep -iq xanmod && echo 1 || echo 0)
kernel_version=$(uname -r)

# 记录执行历史
LOG_DIR="/var/log/network_optimize"
mkdir -p "$LOG_DIR" 2>/dev/null || true
LOG_FILE="$LOG_DIR/history.log"
echo "[$SCRIPT_TIMESTAMP] 执行版本:$SCRIPT_VERSION 内核:$kernel_version 内存:${mem_gb}GB CPU:${cpu_cores}核" >> "$LOG_FILE"

# 检查内核是否支持特定参数
check_kernel_param() {
  local param="$1"
  if sysctl -q "$param" &>/dev/null; then
    return 0  # 参数存在
  else
    return 1  # 参数不存在
  fi
}

# ======================================================
# 第一步：选择服务器类型
# ======================================================
choose_server_type() {
    # 检查是否已有配置文件
    CONF_FILE="/etc/network_optimize.conf"
    if [ -f "$CONF_FILE" ] && [ "$PROMPT_REUSE" = "true" ]; then
        source "$CONF_FILE"
        echo -e "${BLUE}===== 加载现有配置 =====${NC}"
        echo -e "${GREEN}● 服务器类型: $SERVER_TYPE${NC}"
        echo -e "${GREEN}● 流量管理算法: $QOS_ALGO${NC}"
        
        read -p "$(echo -e ${YELLOW}"是否使用现有配置? [Y/n]: "${NC})" reuse_config
        if [[ -z "$reuse_config" || "$reuse_config" =~ ^[Yy]$ ]]; then
            echo -e "${GREEN}使用现有配置继续...${NC}"
            return 0
        fi
    fi
    
    echo -e "${BLUE}===== 第1步：选择服务器类型 =====${NC}"
    echo
    echo -e "1) ${GREEN}Web服务器${NC} - 适合网站、API和应用服务器"
    echo -e "2) ${GREEN}CDN节点${NC} - 适合内容分发网络和流媒体"
    echo -e "3) ${GREEN}VPN服务器${NC} - 适合VPN和代理服务"
    echo -e "4) ${GREEN}通用服务器${NC} - 适合其他类型服务器"
    echo
    
    local server_choice=""
    while [[ ! "$server_choice" =~ ^[1-4]$ ]]; do
        read -p "$(echo -e ${YELLOW}"请输入选项 [1-4]: "${NC})" server_choice
        if [[ ! "$server_choice" =~ ^[1-4]$ ]]; then
            echo -e "${RED}请输入1到4之间的数字${NC}"
        fi
    done
    
    case $server_choice in
        1) SERVER_TYPE="web" ;;
        2) SERVER_TYPE="cdn" ;;
        3) SERVER_TYPE="vpn" ;;
        4) SERVER_TYPE="general" ;;
    esac
    
    echo -e "${GREEN}已选择: $SERVER_TYPE${NC}"
    echo
}

# ======================================================
# 第二步：选择流量管理算法
# ======================================================
choose_qos_algorithm() {
    # 如果已经从配置文件加载，并且用户选择了重用，跳过选择
    if [ -f "/etc/network_optimize.conf" ] && [ "$PROMPT_REUSE" = "true" ] && [ -n "${QOS_ALGO:-}" ]; then
        # 验证算法有效性
        qos_valid=0
        for qos in "${valid_qos[@]}"; do
            if [[ "$QOS_ALGO" == "$qos" ]]; then
                qos_valid=1
                break
            fi
        done
        
        if [[ $qos_valid -eq 1 ]]; then
            # 如果为cake算法，检查模块
            if [[ "$QOS_ALGO" == "cake" ]]; then
                check_cake_module
            fi
            return 0
        fi
    fi
    
    echo -e "${BLUE}===== 第2步：选择流量管理算法 =====${NC}"
    echo
    
    # 根据服务器类型推荐算法
    case $SERVER_TYPE in
        "web")
            echo -e "${GREEN}Web服务器推荐算法: fq_codel 或 cake${NC}"
            default_qos="fq_codel"
            ;;
        "cdn")
            echo -e "${GREEN}CDN节点推荐算法: cake 或 fq_codel${NC}"
            default_qos="cake"
            ;;
        "vpn")
            echo -e "${GREEN}VPN服务器推荐算法: fq_pie 或 fq_codel${NC}"
            default_qos="fq_pie"
            ;;
        *)
            echo -e "${GREEN}通用服务器推荐算法: fq_codel${NC}"
            default_qos="fq_codel"
            ;;
    esac
    
    # 显示算法列表
    echo -e "1) ${GREEN}fq_codel${NC} - 控制延迟的公平队列，适合Web服务器和CDN"
    echo -e "2) ${GREEN}cake${NC} - 综合队列管理，适合高负载CDN"
    echo -e "3) ${GREEN}fq_pie${NC} - 比例积分控制队列，适合VPN服务器"
    echo -e "4) ${GREEN}fq${NC} - 基本公平队列，CPU开销低"
    echo -e "5) ${GREEN}pfifo_fast${NC} - 传统优先级队列(Linux默认)"
    echo -e "6) ${GREEN}sfq${NC} - 随机公平队列，适合低端设备"
    echo -e "7) ${GREEN}red${NC} - 随机早期检测队列"
    echo -e "8) ${GREEN}tbf${NC} - 令牌桶过滤器，适合带宽限制"
    echo -e "9) ${GREEN}查看算法详细说明${NC}"
    echo
    
    # 是否显示算法详情
    local show_details=""
    read -p "$(echo -e ${YELLOW}"是否需要查看算法详细说明? [y/N]: "${NC})" show_details
    if [[ "$show_details" =~ ^[Yy]$ ]]; then
        display_qos_details
    fi
    
    # 选择算法
    local qos_choice=""
    while [[ ! "$qos_choice" =~ ^[1-8]$ && ! -z "$qos_choice" ]]; do
        read -p "$(echo -e ${YELLOW}"请选择流量管理算法 [1-8] (回车使用推荐值: ${default_qos}): "${NC})" qos_choice
        
        # 如果用户直接回车，使用默认算法
        if [[ -z "$qos_choice" ]]; then
            QOS_ALGO=$default_qos
            break
        fi
        
        if [[ ! "$qos_choice" =~ ^[1-8]$ ]]; then
            echo -e "${RED}请输入1到8之间的数字${NC}"
        else
            case $qos_choice in
                1) QOS_ALGO="fq_codel" ;;
                2) QOS_ALGO="cake" ;;
                3) QOS_ALGO="fq_pie" ;;
                4) QOS_ALGO="fq" ;;
                5) QOS_ALGO="pfifo_fast" ;;
                6) QOS_ALGO="sfq" ;;
                7) QOS_ALGO="red" ;;
                8) QOS_ALGO="tbf" ;;
            esac
        fi
    done
    
    echo -e "${GREEN}已选择流量管理算法: $QOS_ALGO${NC}"
    echo
    
    # 验证模块并处理cake算法特殊需求
    if [[ "$QOS_ALGO" == "cake" ]]; then
        check_cake_module
    fi
    
    # 保存配置到文件，方便下次重用
    save_config
}

# 保存配置到文件
save_config() {
    cat > "/etc/network_optimize.conf" <<EOF
# 网络优化配置 - 由脚本自动生成
# 最后更新: $SCRIPT_TIMESTAMP

SERVER_TYPE="$SERVER_TYPE"
QOS_ALGO="$QOS_ALGO"
LAST_OPTIMIZE="$SCRIPT_TIMESTAMP"
VERSION="$SCRIPT_VERSION"
EOF
    echo -e "${GREEN}配置已保存至 /etc/network_optimize.conf${NC}"
}

# 显示QoS算法详细说明
display_qos_details() {
    echo -e "${BLUE}===== 流量管理算法详细说明 =====${NC}"
    echo
    echo -e "${GREEN}fq:${NC} 公平队列算法，提供基本的公平性和低延迟，适合大多数家庭和小型办公室环境。"
    echo -e "    优点是实现简单，CPU开销低。"
    echo
    echo -e "${GREEN}fq_codel:${NC} 结合了公平队列和CoDel算法，主动管理缓冲区以减少延迟，适合在线游戏、"
    echo -e "         视频会议、CDN和Web服务器等需要低延迟的场景。"
    echo
    echo -e "${GREEN}fq_pie:${NC} 使用比例积分增强型算法，在高负载下比fq_codel更稳定，适合带宽波动大的场景，"
    echo -e "        非常适合VPN服务器。"
    echo
    echo -e "${GREEN}cake:${NC} 综合自适应队列管理，具有带宽整形、公平排队和主动队列管理功能，"
    echo -e "      最适合高负载CDN和流媒体服务器。"
    echo
    echo -e "${GREEN}pfifo_fast:${NC} Linux的默认队列管理，基于数据包优先级的简单FIFO队列，适合低负载环境。"
    echo
    echo -e "${GREEN}sfq:${NC} 随机公平队列，通过哈希算法分配流量，防止单个连接占用所有带宽，适合低端设备。"
    echo
    echo -e "${GREEN}red:${NC} 随机早期检测，主动丢弃数据包以防止网络拥塞，适合高流量路由器但可能增加CPU负载。"
    echo
    echo -e "${GREEN}tbf:${NC} 令牌桶过滤器，精确控制带宽使用率，适合需要严格带宽限制的场景，如流量计费环境。"
    echo
    
    # 根据服务器类型提供推荐
    case $SERVER_TYPE in
        "web")
            echo -e "${GREEN}Web服务器推荐: fq_codel, cake${NC}"
            ;;
        "cdn")
            echo -e "${GREEN}CDN节点推荐: cake, fq_codel${NC}"
            ;;
        "vpn")
            echo -e "${GREEN}VPN服务器推荐: fq_pie, fq_codel${NC}"
            ;;
        *)
            echo -e "${GREEN}通用服务器推荐: fq_codel, fq${NC}"
            ;;
    esac
    echo
}

# 检查CAKE模块
check_cake_module() {
    if [[ "$QOS_ALGO" == "cake" ]]; then
        echo -e "${BLUE}检查CAKE队列管理模块...${NC}"
        if ! lsmod | grep -q sch_cake; then
            echo -e "${YELLOW}正在加载CAKE队列管理模块...${NC}"
            modprobe sch_cake 2>/dev/null || {
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
                    # 更新配置文件
                    save_config
                }
            }
        else
            echo -e "${GREEN}CAKE队列管理模块已加载${NC}"
        fi
    fi
}

# ======================================================
# 第三步：应用优化配置
# ======================================================
apply_optimizations() {
    echo -e "${BLUE}===== 第3步：应用网络优化 =====${NC}"
    echo
    echo -e "${BLUE}正在应用$SERVER_TYPE服务器优化，流量管理算法: $QOS_ALGO${NC}"
    echo
    
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

    # 备份原始配置 - 限制备份数量，避免堆积
    if [ -f /etc/sysctl.conf ]; then
        backup_dir="/etc/sysctl.conf.backups"
        mkdir -p "$backup_dir" 2>/dev/null || true
        
        # 创建带日期的备份
        backup_file="$backup_dir/sysctl.conf.$(date +%Y%m%d_%H%M%S)"
        cp /etc/sysctl.conf "$backup_file"
        
        # 保留最近10个备份，删除旧的
        ls -t "$backup_dir"/sysctl.conf.* 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null || true
        
        echo -e "${GREEN}原配置已备份至: $backup_file${NC}"
        echo -e "${GREEN}保留最近10个备份在: $backup_dir${NC}"
        
        # 清除旧的设置 - 更全面的清除
        sed -i -E '/^(# 内核:|# 流量管理算法:|# 服务器类型:|net\.core\.default_qdisc|net\.ipv4\.tcp_congestion_control|net\.mptcp\.enabled|fs\.file-max|fs\.inotify\.max_user|net\.core\.somaxconn|net\.core\.netdev_max_backlog|net\.ipv4\.tcp_rmem|net\.ipv4\.tcp_wmem|net\.core\.rmem|net\.core\.wmem|net\.ipv4\.udp_|net\.ipv4\.tcp_|net\.core\.optmem_max)/d' /etc/sysctl.conf
    fi

    # 创建临时配置文件
    TMP_SYSCTL="/tmp/sysctl_temp.conf"
    
    # 清除可能存在的旧临时文件
    rm -f "$TMP_SYSCTL" 2>/dev/null || true
    
    # 写入配置文件头部
    cat > "$TMP_SYSCTL" <<EOF
# 内核: $kernel_version | 内存: ${mem_gb}GB | CPU: ${cpu_cores}核
# 流量管理算法: $QOS_ALGO | 服务器类型: $SERVER_TYPE
# 此配置由网络优化脚本生成于: $SCRIPT_TIMESTAMP
# 脚本版本: $SCRIPT_VERSION

# 文件系统和资源限制
fs.file-max = $((nofile_hard * 2))
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 2097152
fs.inotify.max_queued_events = 65536
EOF

    # 添加网络队列参数
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
# TCP优化
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 8
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_slow_start_after_idle = 0

# 连接队列设置
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
net.ipv4.udp_mem = $((rmem_max/2)) $rmem_max $((rmem_max*2))
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384

# 端口范围和IP转发
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1

# 安全相关参数
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

    # 设置特定服务器类型的参数
    case $SERVER_TYPE in
        "web"|"cdn")
            cat >> "$TMP_SYSCTL" <<EOF
# Web/CDN服务器特定设置
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_abort_on_overflow = 0
EOF
            ;;
        "vpn")
            cat >> "$TMP_SYSCTL" <<EOF
# VPN服务器特定设置
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
            # 加载VPN相关模块 - 但只检查是否已加载，避免重复加载
            echo -e "${BLUE}检查VPN相关连接跟踪模块...${NC}"
            for module in nf_conntrack nf_conntrack_ipv4 nf_nat iptable_nat ip_tables; do
                if ! lsmod | grep -q $module; then
                    echo -e "${YELLOW}加载模块 $module...${NC}"
                    modprobe $module 2>/dev/null || echo -e "${YELLOW}模块 $module 加载失败 (可能不影响功能)${NC}"
                else
                    echo -e "${GREEN}模块 $module 已加载${NC}"
                fi
            done
            ;;
    esac

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
    else
        echo -e "${YELLOW}系统未启用IPv6支持，跳过IPv6设置${NC}"
    fi

    # 将临时配置应用到系统
    echo -e "${BLUE}应用新的sysctl配置...${NC}"
    if grep -q "^include /etc/sysctl.d/" /etc/sysctl.conf; then
        # 如果sysctl.conf已包含include指令，使用sysctl.d目录
        mkdir -p /etc/sysctl.d
        cp "$TMP_SYSCTL" /etc/sysctl.d/99-network-optimize.conf
    else
        # 否则直接替换sysctl.conf
        cp "$TMP_SYSCTL" /etc/sysctl.conf
    fi
    
    # 删除临时文件
    rm -f "$TMP_SYSCTL"

    # 应用配置，忽略可能的错误
    sysctl --system -e || true

    # 使用tc命令设置队列管理算法
    # 首先检查tc命令是否存在，如果不存在则尝试安装
    if ! command -v tc &>/dev/null; then
        echo -e "${YELLOW}未找到tc命令，尝试安装iproute2包...${NC}"
        apt-get update -qq
        apt-get install -y iproute2
    fi
    
    # 获取已应用的队列规则，避免重复应用相同设置
    declare -A applied_qos
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
        if [[ "$iface" != "lo" && -n "$iface" ]]; then
            current_qdisc=$(tc qdisc show dev $iface | head -n1 | grep -o "$QOS_ALGO" || echo "")
            if [[ -n "$current_qdisc" ]]; then
                applied_qos["$iface"]="1"
                echo -e "${GREEN}接口 $iface 已应用 $QOS_ALGO 队列管理算法${NC}"
            else
                applied_qos["$iface"]="0"
            fi
        fi
    done
    
    # 只对未应用的接口设置队列
    for iface in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
        if [[ "$iface" != "lo" && -n "$iface" && "${applied_qos[$iface]}" != "1" ]]; then
            echo -e "${BLUE}在接口 $iface 上设置 $QOS_ALGO 队列管理算法${NC}"
            tc qdisc replace dev $iface root $QOS_ALGO 2>/dev/null || {
                echo -e "${YELLOW}无法在接口 $iface 上设置 $QOS_ALGO，尝试备选方案...${NC}"
                tc qdisc replace dev $iface root fq_codel 2>/dev/null || 
                tc qdisc replace dev $iface root fq 2>/dev/null || true
            }
        fi
    done

    # 设置系统资源限制
    setup_limits
    
    # 创建持久化服务
    create_persistence_service
    
    echo -e "${GREEN}✓ 网络优化配置已应用${NC}"
    echo
}

# 设置系统资源限制
setup_limits() {
    echo -e "${BLUE}设置系统资源限制...${NC}"
    
    # 检查是否已有相同配置
    if [ -f /etc/security/limits.conf ]; then
        current_nofile_soft=$(grep "^\* soft nofile" /etc/security/limits.conf | awk '{print $4}')
        current_nofile_hard=$(grep "^\* hard nofile" /etc/security/limits.conf | awk '{print $4}')
        
        if [[ "$current_nofile_soft" == "$nofile_soft" && "$current_nofile_hard" == "$nofile_hard" ]]; then
            echo -e "${GREEN}文件描述符限制已设置为所需值，跳过修改${NC}"
            return 0
        fi
        
        # 备份原始文件，限制备份数量
        backup_dir="/etc/security/limits.conf.backups"
        mkdir -p "$backup_dir" 2>/dev/null || true
        
        backup_file="$backup_dir/limits.conf.$(date +%Y%m%d_%H%M%S)"
        cp /etc/security/limits.conf "$backup_file"
        
        # 保留最近5个备份
        ls -t "$backup_dir"/limits.conf.* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
        
        echo -e "${GREEN}原limits.conf已备份至: $backup_file${NC}"
        
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
    cat >> /etc/security/limits.conf <<EOF
# 由网络优化脚本设置 - $SCRIPT_TIMESTAMP
* soft nofile $nofile_soft
* hard nofile $nofile_hard
* soft nproc $nofile_soft
* hard nproc $nofile_hard
* soft core unlimited
* hard core unlimited
* soft memlock unlimited
* hard memlock unlimited
EOF

    # 确保PAM模块加载limits
    for pam_file in /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive; do
        if [ -f "$pam_file" ] && ! grep -q "pam_limits.so" "$pam_file"; then
            echo "session required pam_limits.so" >> "$pam_file"
            echo -e "${GREEN}在 $pam_file 中添加了 pam_limits.so 模块${NC}"
        fi
    done

    # systemd 资源限制
    if [ -d /etc/systemd ]; then
        if [ -f /etc/systemd/system.conf ]; then
            # 检查是否已有相同配置
            current_nofile=$(grep "^DefaultLimitNOFILE=" /etc/systemd/system.conf | cut -d= -f2)
            
            if [[ "$current_nofile" == "$nofile_hard" ]]; then
                echo -e "${GREEN}systemd资源限制已设置为所需值，跳过修改${NC}"
            else
                # 备份原始文件
                backup_dir="/etc/systemd/backups"
                mkdir -p "$backup_dir" 2>/dev/null || true
                
                backup_file="$backup_dir/system.conf.$(date +%Y%m%d_%H%M%S)"
                cp /etc/systemd/system.conf "$backup_file"
                
                # 保留最近5个备份
                ls -t "$backup_dir"/system.conf.* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
                
                echo -e "${GREEN}原systemd配置已备份至: $backup_file${NC}"
                
                # 清除旧的设置
                sed -i '/DefaultLimitCORE\|DefaultLimitNOFILE\|DefaultLimitNPROC/d' /etc/systemd/system.conf
                
                # 写入新设置
                cat >> /etc/systemd/system.conf <<EOF
# 由网络优化脚本设置 - $SCRIPT_TIMESTAMP
[Manager]
DefaultLimitCORE=infinity
DefaultLimitNOFILE=$nofile_hard
DefaultLimitNPROC=$nofile_hard
EOF
                echo -e "${GREEN}systemd资源限制已更新${NC}"
                systemctl daemon-reexec
            fi
        fi
    fi

    # 设置当前会话文件描述符限制
    echo -e "${BLUE}设置当前会话文件描述符限制...${NC}"
    current_max=$(ulimit -Hn)
    current_soft=$(ulimit -Sn)
    
    if [[ $current_soft -lt $nofile_soft && $nofile_soft -le $current_max ]]; then
        ulimit -Sn "$nofile_soft" 2>/dev/null && echo -e "${GREEN}当前会话软限制设置为: $nofile_soft${NC}" || 
        echo -e "${YELLOW}无法设置当前会话软限制${NC}"
    fi
    
    if [[ $current_max -lt $nofile_hard ]]; then
        echo -e "${YELLOW}当前shell会话硬限制为${current_max}，无法设置更高值。请重启系统或重新登录生效。${NC}"
    fi
}

# 创建持久化服务
create_persistence_service() {
    echo -e "${BLUE}创建启动服务确保设置持久化...${NC}"
    
    # 创建systemd服务
    if [[ -d /etc/systemd/system ]]; then
        service_file="/etc/systemd/system/apply-sysctl.service"
        
        # 检查是否已存在相同服务
        if [ -f "$service_file" ]; then
            existing_qos=$(grep -o "root $QOS_ALGO" "$service_file" || echo "")
            if [[ -n "$existing_qos" ]]; then
                echo -e "${GREEN}服务已存在且使用相同的队列管理算法，跳过创建${NC}"
            else
                echo -e "${BLUE}更新已存在的服务配置...${NC}"
                systemctl disable apply-sysctl.service 2>/dev/null || true
            fi
        fi
        
        # 如果需要更新或创建新服务
        if [[ ! -f "$service_file" || -z "$existing_qos" ]]; then
            cat > "$service_file" <<EOF
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
            systemctl restart apply-sysctl.service || true
            echo -e "${GREEN}✓ 服务 apply-sysctl.service 已创建并启用${NC}"
        fi
    fi
    
    # 创建rc.local文件作为备份方案
    if [ ! -f /etc/rc.local ] || ! grep -q "$QOS_ALGO" /etc/rc.local; then
        echo -e "${BLUE}创建或更新rc.local作为备份启动脚本...${NC}"
        
        # 如果文件存在，备份它
        if [ -f /etc/rc.local ]; then
            backup_dir="/etc/rc.local.backups"
            mkdir -p "$backup_dir" 2>/dev/null || true
            
            backup_file="$backup_dir/rc.local.$(date +%Y%m%d_%H%M%S)"
            cp /etc/rc.local "$backup_file"
            
            # 保留最近5个备份
            ls -t "$backup_dir"/rc.local.* 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true
            
            echo -e "${GREEN}原rc.local已备份至: $backup_file${NC}"
            
            # 清除旧的设置
            sed -i '/tc qdisc replace/d' /etc/rc.local
            sed -i '/网络优化配置脚本/d' /etc/rc.local
            sed -i '/应用sysctl设置/d' /etc/rc.local
            sed -i '/\/sbin\/sysctl --system/d' /etc/rc.local
        fi
        
        # 创建新的rc.local文件
        # 如果文件不存在或者不包含exit 0
        if [ ! -f /etc/rc.local ] || ! grep -q "exit 0" /etc/rc.local; then
            cat > /etc/rc.local <<EOF
#!/bin/bash
# 网络优化配置脚本 - 由脚本自动生成 $SCRIPT_TIMESTAMP

# 应用sysctl设置
/sbin/sysctl --system

# 设置队列管理
for iface in \$(ip -o link show | grep -v "lo" | awk -F": " '{print \$2}' | cut -d@ -f1); do
    [[ -n "\$iface" ]] && tc qdisc replace dev \$iface root $QOS_ALGO 2>/dev/null || true
done

exit 0
EOF
            chmod +x /etc/rc.local
            echo -e "${GREEN}✓ 创建 /etc/rc.local${NC}"
        else
            # 如果文件存在并且有exit 0，在exit 0前插入命令
            sed -i '/exit 0/i\# 网络优化配置脚本 - 由脚本自动生成 '"$SCRIPT_TIMESTAMP"'\n\n# 应用sysctl设置\n/sbin/sysctl --system\n\n# 设置队列管理\nfor iface in $(ip -o link show | grep -v "lo" | awk -F": " \x27{print $2}\x27 | cut -d@ -f1); do\n    [[ -n "$iface" ]] && tc qdisc replace dev $iface root '"$QOS_ALGO"' 2>/dev/null || true\ndone\n' /etc/rc.local
            echo -e "${GREEN}✓ 更新 /etc/rc.local${NC}"
        fi
        
        # 对于使用systemd的系统，确保rc-local服务启用
        if [ -d /etc/systemd/system ] && ! systemctl is-enabled rc-local.service &>/dev/null; then
            if [ ! -f /etc/systemd/system/rc-local.service ]; then
                cat > /etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local Compatibility
ConditionPathExists=/etc/rc.local

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99

[Install]
WantedBy=multi-user.target
EOF
                systemctl daemon-reload
                systemctl enable rc-local.service
                echo -e "${GREEN}✓ rc-local.service 已启用${NC}"
            fi
        fi
    else
        echo -e "${GREEN}✓ rc.local已包含正确的队列管理算法设置${NC}"
    fi
}

# ======================================================
# 第四步：清理和显示配置总结
# ======================================================
show_summary() {
    echo -e "${BLUE}===== 配置总结 =====${NC}"
    echo
    echo -e "${GREEN}● 服务器类型:${NC} $SERVER_TYPE"
    echo -e "${GREEN}● 流量管理算法:${NC} $QOS_ALGO"
    echo -e "${GREEN}● 系统内核:${NC} $kernel_version"
    echo -e "${GREEN}● 内存:${NC} ${mem_gb}GB"
    echo -e "${GREEN}● CPU核心:${NC} ${cpu_cores}核"
    echo -e "${GREEN}● 文件描述符限制:${NC} $nofile_soft/$nofile_hard"
    echo -e "${GREEN}● TCP缓冲区:${NC} $((rmem_max/1024/1024))MB"
    echo -e "${GREEN}● 最大连接队列:${NC} $somaxconn"
    
    # 检查BBR是否启用
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
    echo -e "  • 检查文件描述符限制: ${GREEN}ulimit -n${NC}"
    echo -e "  • 检查TCP配置: ${GREEN}sysctl -a | grep tcp${NC}"
    echo -e "  • 检查队列策略: ${GREEN}tc qdisc show${NC}"
    echo -e "  • 检查最大连接数: ${GREEN}sysctl net.core.somaxconn${NC}"
    
    echo
    echo -e "${BLUE}===== 优化完成 =====${NC}"
    echo -e "${GREEN}系统网络优化配置已应用并设置为在启动时自动加载${NC}"
    echo -e "${YELLOW}建议重启系统以确保所有优化完全生效${NC}"
    
    # 记录执行结果到日志
    echo "[$SCRIPT_TIMESTAMP] 优化完成: $SERVER_TYPE 服务器, $QOS_ALGO 算法" >> "$LOG_FILE"
}

# ======================================================
# 主程序
# ======================================================

# 检查是否使用已有配置
PROMPT_REUSE="true"
# 如果命令行传入--no-prompt参数，则不提示重用
if [[ "$*" == *"--no-prompt"* ]]; then
    PROMPT_REUSE="false"
fi

# 1. 选择服务器类型
choose_server_type

# 2. 选择流量管理算法
choose_qos_algorithm

# 3. 应用优化配置
apply_optimizations

# 4. 显示优化总结
show_summary

# 脚本结束时会自动执行cleanup
exit 0
