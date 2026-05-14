#!/usr/bin/env bash
set -Eeuo pipefail

trap 'ret=$?; echo "❌ 脚本失败，行号: ${LINENO}，退出码: ${ret}"; echo "命令: ${BASH_COMMAND}"; exit "${ret}"' ERR

KEYRING="/etc/apt/keyrings/xanmod-archive-keyring.gpg"
LISTFILE="/etc/apt/sources.list.d/xanmod-release.list"
LOGFILE="/var/log/xanmod-lts-install.log"
REPO_URL="http://deb.xanmod.org"

log() {
  echo "[$(date '+%F %T')] $*"
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "❌ 请使用 root 执行"
    echo "用法: sudo bash $0"
    exit 1
  fi
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
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates wget gnupg lsb-release apt-transport-https
}

setup_repo() {
  local codename
  codename="$(lsb_release -sc)"

  log "系统版本代号: ${codename}"
  log "创建 keyrings 目录..."
  install -d -m 0755 /etc/apt/keyrings

  log "导入 XanMod 仓库密钥..."
  wget -qO- https://dl.xanmod.org/archive.key | gpg --dearmor --yes -o "$KEYRING"
  chmod 0644 "$KEYRING"

  log "写入 XanMod APT 源..."
  echo "deb [signed-by=${KEYRING}] ${REPO_URL} ${codename} main" > "$LISTFILE"
  chmod 0644 "$LISTFILE"

  log "更新软件源索引..."
  apt-get update
}

detect_cpu_level() {
  local ver
  log "检测 CPU x86-64-v 等级..."

  ver="$(
    wget -qO- https://dl.xanmod.org/check_x86-64_psabi.sh |
    bash 2>/dev/null |
    grep -oP 'x86-64-v\K[1-4]' |
    tail -n1
  )"

  ver="${ver:-3}"

  if ! [[ "$ver" =~ ^[1-4]$ ]]; then
    ver=3
  fi

  if [ "$ver" -gt 3 ]; then
    ver=3
  fi

  echo "$ver"
}

install_kernel() {
  local ver="$1"
  local pkg="linux-xanmod-lts-x64v${ver}"

  log "检测到 CPU 架构等级: x64v${ver}"
  log "安装 XanMod LTS 内核包: ${pkg}"
  apt-get install -y "$pkg"

  log "安装外部模块最小依赖..."
  apt-get install -y --no-install-recommends dkms libelf-dev clang lld llvm
}

refresh_grub() {
  log "更新 GRUB..."
  if command -v update-grub >/dev/null 2>&1; then
    update-grub
  elif command -v grub-mkconfig >/dev/null 2>&1; then
    grub-mkconfig -o /boot/grub/grub.cfg
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
