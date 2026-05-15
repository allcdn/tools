#!/bin/bash
# ============================================================
# XanMod 内核 一键安装/更新脚本
# 支持: MAIN / LTS / RT 分支，自动检测 x64v1~v3
# 适用: Debian bookworm/trixie | Ubuntu noble/plucky 等
# 作者: 自动生成 | 版本: 2.0
# ============================================================

set -e

# ── 颜色输出 ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR ]${NC} $*"; exit 1; }

# ── 权限检查 ──────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "请使用 root 或 sudo 运行此脚本"

# ── 自动检测 CPU x86-64 psABI 级别 ───────────────────────
detect_cpu_level() {
    local level=1
    local flags
    flags=$(grep -m1 '^flags' /proc/cpuinfo)

    # v2: SSE4.2 + POPCNT + CX16
    if echo "$flags" | grep -qE 'sse4_2' && \
       echo "$flags" | grep -qE 'popcnt' && \
       echo "$flags" | grep -qE 'cx16'; then
        level=2
    fi

    # v3: AVX + AVX2 + FMA + BMI1 + BMI2
    if [[ $level -ge 2 ]] && \
       echo "$flags" | grep -qE '\bavx\b' && \
       echo "$flags" | grep -qE '\bavx2\b' && \
       echo "$flags" | grep -qE '\bfma\b' && \
       echo "$flags" | grep -qE '\bbmi1\b' && \
       echo "$flags" | grep -qE '\bbmi2\b'; then
        level=3
    fi

    # v4: AVX-512 (XanMod 无 v4 包，降级到 v3)
    if echo "$flags" | grep -qE 'avx512f'; then
        warn "检测到 AVX-512 (x64v4) CPU，XanMod 无 v4 内核包，将使用 v3"
        level=3
    fi

    echo $level
}

# ── 选择分支 ──────────────────────────────────────────────
select_branch() {
    echo ""
    echo -e "${BOLD}┌─────────────────────────────────────────┐${NC}"
    echo -e "${BOLD}│       XanMod 内核分支选择               │${NC}"
    echo -e "${BOLD}├─────────────────────────────────────────┤${NC}"
    echo -e "${BOLD}│${NC}  1) MAIN  - Stable Mainline  (7.0.x)   ${BOLD}│${NC}"
    echo -e "${BOLD}│${NC}  2) LTS   - Long Term Support (6.18.x)  ${BOLD}│${NC}  ${CYAN}← 推荐服务器${NC}"
    echo -e "${BOLD}│${NC}  3) RT    - Real-time         (6.18.x)  ${BOLD}│${NC}"
    echo -e "${BOLD}└─────────────────────────────────────────┘${NC}"
    echo ""
    read -rp "请输入选项 [默认 2/LTS]: " choice </dev/tty
    case "${choice:-2}" in
        1) echo "main" ;;
        3) echo "rt"   ;;
        *) echo "lts"  ;;
    esac
}

# ── 主流程开始 ────────────────────────────────────────────
clear
echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║        XanMod 内核 一键安装/更新         ║"
echo "  ║   MAIN / LTS / RT | 自动检测 x64 等级   ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# 安装前置依赖
info "安装前置依赖 (ca-certificates gpg wget lsb-release)..."
apt-get install -y -q ca-certificates gpg wget lsb-release 2>/dev/null
success "前置依赖就绪"

# 检测 CPU 级别
info "检测 CPU x86-64 psABI 架构级别..."
CPU_LEVEL=$(detect_cpu_level)
success "CPU 支持 x86-64-v${CPU_LEVEL}"

# 选择分支
BRANCH=$(select_branch)
info "已选分支: ${BOLD}${BRANCH^^}${NC}"

# 构造包名
case "$BRANCH" in
    main)
        # MAIN 支持 v2/v3（无 v1）
        [[ $CPU_LEVEL -lt 2 ]] && { warn "MAIN 分支最低需要 x64v2，已自动调整"; CPU_LEVEL=2; }
        PKG="linux-xanmod-x64v${CPU_LEVEL}"
        ;;
    lts)
        # LTS 支持 v1/v2/v3
        PKG="linux-xanmod-lts-x64v${CPU_LEVEL}"
        ;;
    rt)
        # RT 仅支持 v2/v3
        [[ $CPU_LEVEL -lt 2 ]] && { warn "RT 分支最低需要 x64v2，已自动调整"; CPU_LEVEL=2; }
        PKG="linux-xanmod-rt-x64v${CPU_LEVEL}"
        ;;
esac

info "目标安装包: ${BOLD}${PKG}${NC}"
echo ""

# ── 配置仓库 ──────────────────────────────────────────────
KEYRING="/etc/apt/keyrings/xanmod-archive-keyring.gpg"
SOURCES="/etc/apt/sources.list.d/xanmod-release.list"

if [[ ! -f "$KEYRING" ]]; then
    info "注册 XanMod PGP 密钥..."
    mkdir -p /etc/apt/keyrings
    wget -qO - https://dl.xanmod.org/archive.key | \
        gpg --dearmor -o "$KEYRING"
    success "PGP 密钥已写入 → $KEYRING"
else
    success "PGP 密钥已存在，跳过"
fi

if [[ ! -f "$SOURCES" ]]; then
    info "添加 XanMod APT 仓库..."
    DISTRO=$(lsb_release -sc)
    echo "deb [signed-by=${KEYRING}] http://deb.xanmod.org ${DISTRO} main" | \
        tee "$SOURCES" > /dev/null
    success "仓库已添加 (发行版代号: ${BOLD}${DISTRO}${NC})"
else
    success "APT 仓库已存在，跳过"
fi

# ── 更新 APT 缓存 ─────────────────────────────────────────
info "刷新 APT 缓存..."
apt-get update -qq
success "APT 缓存已更新"
echo ""

# ── 判断安装或更新 ────────────────────────────────────────
if dpkg -l "$PKG" 2>/dev/null | grep -q '^ii'; then
    INSTALLED=$(dpkg -l "$PKG" | grep '^ii' | awk '{print $3}')
    CANDIDATE=$(apt-cache policy "$PKG" 2>/dev/null | grep 'Candidate:' | awk '{print $2}')
    if [[ "$INSTALLED" == "$CANDIDATE" ]]; then
        echo -e "${GREEN}══════════════════════════════════════════${NC}"
        success "已是最新版本，无需更新！"
        echo -e "  已安装版本: ${BOLD}${INSTALLED}${NC}"
        echo -e "  当前运行内核: ${BOLD}$(uname -r)${NC}"
        echo -e "${GREEN}══════════════════════════════════════════${NC}"
        exit 0
    else
        info "发现新版本: ${BOLD}${INSTALLED}${NC} → ${BOLD}${CANDIDATE}${NC}，开始升级..."
    fi
else
    info "开始全新安装: ${BOLD}${PKG}${NC}..."
fi

apt-get install -y "$PKG"

# ── 可选: DKMS 外部模块依赖 ───────────────────────────────
echo ""
echo -e "${YELLOW}是否安装 DKMS 外部模块构建依赖？${NC}"
echo "  (dkms / libelf-dev / clang / lld / llvm)"
echo "  适用于: NVIDIA 驱动、OpenZFS、VirtualBox 等外部模块"
read -rp "安装? [y/N]: " dkms_choice </dev/tty
if [[ "${dkms_choice,,}" == "y" ]]; then
    info "安装 DKMS 依赖..."
    apt-get install -y --no-install-recommends dkms libelf-dev clang lld llvm
    success "DKMS 依赖安装完成"
else
    info "跳过 DKMS 依赖安装"
fi

# ── 完成提示 ──────────────────────────────────────────────
INSTALLED_NEW=$(dpkg -l "$PKG" 2>/dev/null | grep '^ii' | awk '{print $3}')
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    ✅  XanMod 内核安装/更新完成！        ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  安装包:     ${BOLD}${PKG}${NC}"
echo -e "  新内核版本: ${BOLD}${INSTALLED_NEW}${NC}"
echo -e "  当前内核:   ${BOLD}$(uname -r)${NC}"
echo ""
echo -e "${YELLOW}  ⚡ 请执行以下命令重启服务器：${NC}"
echo -e "     ${BOLD}reboot${NC}"
echo ""
echo -e "${YELLOW}  ✔  重启后执行以下命令验证：${NC}"
echo -e "     ${BOLD}uname -r${NC}"
echo ""
