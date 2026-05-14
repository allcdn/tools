#!/usr/bin/env bash
set -Eeuo pipefail

trap 'echo "❌ 执行失败，出错行: $LINENO"; exit 1' ERR

KEYRING="/etc/apt/keyrings/xanmod-archive-keyring.gpg"
LISTFILE="/etc/apt/sources.list.d/xanmod-release.list"
LOGFILE="/var/log/xanmod-lts-install.log"

log() {
  echo "[$(date '+%F %T')] $*"
}

need_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "请使用 root 运行，或先执行 sudo -i 后再运行此脚本。"
    exit 1
  fi
}

check_cmd() {
  command -v "$1" >/dev/null 2>&1
}

install_prereqs() {
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y --no-install-recommends \
    ca-certificates \
    wget \
    gnupg \
    lsb-release \
    apt-transport-https \
    software-properties-common
}

detect_cpu_level() {
  local ver
  ver="$(
    wget -qO- https://dl.xanmod.org/check_x86-64_psabi.sh \
      | bash 2>/dev/null \
      | grep -oP 'x86-64-v\K[1-4]' \
      | tail -n1
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

setup_repo() {
  mkdir -p /etc/apt/keyrings
  chmod 0755 /etc/apt/keyrings

  log "导入 XanMod 仓库密钥..."
  wget -qO- https://dl.xanmod.org/archive.key | gpg --dearmor -o "$KEYRING"
  chmod 0644 "$KEYRING"

  log "写入 XanMod APT 源..."
  echo "deb [signed-by=$KEYRING] http://deb.xanmod.org $(lsb_release -sc) main" > "$LISTFILE"
  chmod 0644 "$LISTFILE"
}

install_kernel() {
  local ver="$1"
  local pkg="linux-xanmod-lts-x64v${ver}"

  log "更新软件源索引..."
  apt update

  log "安装/更新内核包: $pkg"
  apt install -y "$pkg"

  log "安装常用构建依赖与 DKMS 支持..."
  apt install -y --no-install-recommends dkms libelf-dev clang lld llvm
}

refresh_bootloader() {
  if check_cmd update-grub; then
    log "更新 GRUB..."
    update-grub
  elif check_cmd grub-mkconfig; then
    log "生成 grub.cfg..."
    grub-mkconfig -o /boot/grub/grub.cfg
  else
    log "未检测到 update-grub 或 grub-mkconfig，请手动检查引导项。"
  fi
}

show_result() {
  local current latest
  current="$(uname -r)"
  latest="$(dpkg -l | awk '/^ii/ && /linux-image.*xanmod/ {print $2}' | tail -n1)"

  echo
  echo "================ 结果 ================"
  echo "当前运行内核: ${current}"
  echo "已安装 XanMod LTS 包: ${latest:-未检测到}"
  echo "APT 源文件: $LISTFILE"
  echo "Keyring 文件: $KEYRING"
  echo "====================================="
  echo "如需切换到新内核，请手动执行: reboot"
}

main() {
  exec > >(tee -a "$LOGFILE") 2>&1

  need_root

  log "开始执行 XanMod LTS 安装/更新脚本"

  if [ "$(dpkg --print-architecture)" != "amd64" ]; then
    log "当前架构不是 amd64，脚本退出。"
    exit 1
  fi

  install_prereqs
  setup_repo

  CPU_VER="$(detect_cpu_level)"
  log "检测到 CPU 等级: x64v${CPU_VER}（此脚本最高使用 v3）"

  install_kernel "$CPU_VER"
  refresh_bootloader
  show_result

  log "脚本执行完成"
}

main "$@"
