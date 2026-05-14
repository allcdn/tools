#!/usr/bin/env bash
set -Eeuo pipefail

trap 'ret=$?; echo "❌ 脚本失败，行号: ${LINENO}，退出码: ${ret}"; echo "命令: ${BASH_COMMAND}"; exit "${ret}"' ERR

KEYRING="/etc/apt/keyrings/xanmod-archive-keyring.gpg"
LISTFILE="/etc/apt/sources.list.d/xanmod-release.list"
LOGFILE="/var/log/xanmod-lts-install.log"
REPO_URL="http://deb.xanmod.org" 

log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOGFILE"
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "❌ 请使用 root 执行"
    echo "用法: sudo bash $0"
    exit 1
  fi
}

# ✅ 新增：检查日志文件权限
check_logfile() {
  local logdir
  logdir="$(dirname "$LOGFILE")"
  if [ ! -d "$logdir" ]; then
    mkdir -p "$logdir" || { echo "❌ 无法创建日志目录: $logdir"; exit 1; }
  fi
  if [ ! -w "$logdir" ]; then
    echo "❌ 日志目录无写权限: $logdir"
    exit 1
  fi
  touch "$LOGFILE" || { echo "❌ 无法创建日志文件: $LOGFILE"; exit 1; }
}

check_arch() {
  local arch
  arch="$(dpkg --print-architecture)"
  log "系统架构: ${arch}"
  [ "$arch" = "amd64" ] || { echo "❌ 当前仅支持 amd64/x86_64"; exit 1; }
}

install_prereqs() {
  export DEBIAN_FRONTEND=noninteractive
  log "安装基础依赖..."
  apt-get update || { log "❌ apt-get update 失败"; exit 1; }
  apt-get install -y --no-install-recommends ca-certificates wget gnupg lsb-release apt-transport-https || \
    { log "❌ 依赖安装失败"; exit 1; }
}

setup_repo() {
  local codename
  
  # ✅ 改进：检查 lsb_release 是否可用
  if ! command -v lsb_release >/dev/null 2>&1; then
    # 备选方案：从 /etc/os-release 读取
    codename=$(grep -oP 'VERSION_CODENAME=\K[^ ]+' /etc/os-release 2>/dev/null || echo "focal")
  else
    codename="$(lsb_release -sc)" || { log "❌ 无法获取系统版本代号"; exit 1; }
  fi

  log "系统版本代号: ${codename}"
  log "创建 keyrings 目录..."
  install -d -m 0755 /etc/apt/keyrings

  log "导入 XanMod 仓库密钥..."
  # ✅ 改进：网络错误处理
  if ! wget -qO- https://dl.xanmod.org/archive.key | gpg --dearmor --yes -o "$KEYRING"; then
    log "❌ 导入密钥失败，请检查网络连接"
    exit 1
  fi
  chmod 0644 "$KEYRING"

  log "写入 XanMod APT 源..."
  echo "deb [signed-by=${KEYRING}] ${REPO_URL} ${codename} main" > "$LISTFILE"
  chmod 0644 "$LISTFILE"

  log "更新软件源索引..."
  apt-get update || { log "❌ 软件源更新失败"; exit 1; }
}

detect_cpu_level() {
  local ver
  log "检测 CPU x86-64-v 等级..."

  # ✅ 改进：更好的错误处理和日志
  if ! ver="$(wget -qO- https://dl.xanmod.org/check_x86-64_psabi.sh 2>/dev/null | bash 2>/dev/null | grep -oP 'x86-64-v\K[1-4]' | tail -n1)"; then
    log "⚠️ 无法检测 CPU 等级，使用默认值 v3"
    ver=""
  fi

  # ✅ 简化逻辑：统一处理默认值
  ver="${ver:-3}"
  
  # ✅ 确保版本在 1-3 范围内（XanMod LTS 通常不提供 v4）
  if ! [[ "$ver" =~ ^[1-3]$ ]]; then
    log "⚠️ CPU 等级 v${ver} 不支持，降级为 v3"
    ver=3
  fi

  echo "$ver"
}

install_kernel() {
  local ver="$1"
  local pkg="linux-xanmod-lts-x64v${ver}"

  log "检测到 CPU 架构等级: x64v${ver}"
  log "安装 XanMod LTS 内核包: ${pkg}"
  
  # ✅ 改进：检查包是否存在
  if ! apt-cache search "^${pkg}$" | grep -q "$pkg"; then
    log "❌ 内核包不存在: ${pkg}，请检查仓库配置"
    exit 1
  fi

  if ! apt-get install -y "$pkg"; then
    log "❌ 内核安装失败"
    exit 1
  fi

  log "安装外部模块最小依赖..."
  apt-get install -y --no-install-recommends dkms libelf-dev clang lld llvm || \
    { log "⚠️ 部分依赖安装失败，但继续进行"; }
}

refresh_grub() {
  log "更新 GRUB..."
  if command -v update-grub >/dev/null 2>&1; then
    update-grub || { log "⚠️ update-grub 执行失败"; }
  elif command -v grub-mkconfig >/dev/null 2>&1; then
    grub-mkconfig -o /boot/grub/grub.cfg || { log "⚠️ grub-mkconfig 执行失败"; }
  else
    log "⚠️ 未找到 update-grub 或 grub-mkconfig，请手动检查引导配置"
  fi
}

show_result() {
  local current_kernel latest_xanmod
  current_kernel="$(uname -r)"
  latest_xanmod="$(dpkg -l | awk '/^ii/ && /linux-image.*xanmod/ {print $2}' | tail -n1)"

  echo "=================================================="
  echo "✅ 安装完成"
  echo "当前运行内核: ${current_kernel}"
  echo "已安装 XanMod LTS 包: ${latest_xanmod:-未检测到}"
  echo "日志文件: ${LOGFILE}"
  echo "⚠️ 请手动执行 reboot 重启后生效"
  echo "=================================================="
}

main() {
  # ✅ 改进：先检查日志文件，再重定向输出
  check_logfile
  exec > >(tee -a "$LOGFILE") 2>&1

  echo "=================================================="
  echo "XanMod LTS 一键安装启动时间: $(date '+%F %T')"
  echo "日志文件: ${LOGFILE}"
  echo "=================================================="

  require_root
  check_arch
  install_prereqs
  setup_repo

  CPU_VER="$(detect_cpu_level)"
  install_kernel "$CPU_VER"
  refresh_grub
  show_result
}

main "$@"
