#!/bin/bash
# ============================================================
# XanMod 内核 一键安装/更新脚本
# 支持: MAIN / LTS / RT 分支，自动检测 x64v1~v3
# 适用: Debian bookworm/trixie | Ubuntu noble/plucky 等
# ============================================================

set -e

# ── 颜色输出 ──────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR]${NC}  $*"; exit 1; }

# ── 权限检查 ──────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "请使用 root 或 sudo 运行此脚本"

# ── 自动检测 CPU x86-64 psABI 级别 ───────────────────────
detect_cpu_level() {
    local level=1
    local flags
    flags=$(grep -m1 '^flags' /proc/cpuinfo)

    # v2: SSE4.2, POPCNT, CX16, LAHF
    if echo "$flags" | grep -qE 'sse4_2' && \
       echo "$flags" | grep -qE 'popcnt' && \
       echo "$flags" | grep -qE 'cx16'; then
        level=2
    fi

    # v3: AVX, AVX2, BMI1, BMI2, FMA, MOVBE
    if [[ $level -ge 2 ]] && \
       echo "$flags" | grep -qE '\bavx\b' && \
       echo "$flags" | grep -qE '\bavx2\b' && \
       echo "$flags" | grep -qE '\bfma\b' && \
       echo "$flags" | grep -qE '\bbmi1\b' && \
       echo "$flags" | grep -qE '\bbmi2\b'; then
        level=3
    fi

    # v4: AVX-512 (XanMod 无 v4 内核包，降级到 v3)
    if echo "$flags" | grep -qE 'avx512f'; then
        warn "检测到 AVX-512 (x64v4) CPU，XanMod 无 v4 包，将使用 v3"
        level=3
    fi

    echo $level
}

# ── 选择分支 ──────────────────────────────────────────────
select_branch() {
    echo ""
    echo -e "${BOLD}请选择内核分支:${NC}"
    echo "  1) MAIN  - Stable Mainline  (当前: 7.0.x)"
    echo "  2) LTS   - Long Term Support (当前: 6.18.x) [推荐服务器]"
    echo "  3) RT    - Real-time         (当前: 6.18.x-rt)"
    echo ""
    read -rp "请输入选项 [默认 2/LTS]: " choice
    case "${choice:-2}" in
        1) echo "main" ;;
        3) echo "rt"   ;;
        *) echo "lts"  ;;
    esac
}

# ── 主流程 ────────────────────────────────────────────────
info "检测 CPU 架构级别..."
CPU_LEVEL=$(detect_cpu_level)
success "CPU 支持 x86-64-v${CPU_LEVEL}"

BRANCH=$(select_branch)
info "已选分支: ${BRANCH^^}"

# 构造包名
case "$BRANCH" in
    main) PKG="linux-xanmod-x64v${CPU_LEVEL}" ;;
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

# ── 配置仓库 ──────────────────────────────────────────────
KEYRING="/etc/apt/keyrings/xanmod-archive-keyring.gpg"
SOURCES="/etc/apt/sources.list.d/xanmod-release.list"

if [[ ! -f "$KEYRING" ]]; then
    info "注册 XanMod PGP 密钥..."
    mkdir -p /etc/apt/keyrings
    wget -qO - https://dl.xanmod.org/archive.key | \
        gpg --dearmor -o "$KEYRING"
    success "PGP 密钥已写入 $KEYRING"
else
    success "PGP 密钥已存在，跳过"
fi

if [[ ! -f "$SOURCES" ]]; then
    info "添加 XanMod APT 仓库..."
    DISTRO=$(lsb_release -sc)
    echo "deb [signed-by=${KEYRING}] http://deb.xanmod.org ${DISTRO} main" | \
        tee "$SOURCES" > /dev/null
    success "仓库已添加 (发行版: ${DISTRO})"
else
    success "APT 仓库已存在，跳过"
fi

# ── 更新并安装 ────────────────────────────────────────────
info "更新 APT 缓存..."
apt update -qq

# 检查是否已安装该包
if dpkg -l "$PKG" 2>/dev/null | grep -q '^ii'; then
    INSTALLED=$(dpkg -l "$PKG" | grep '^ii' | awk '{print $3}')
    CANDIDATE=$(apt-cache policy "$PKG" | grep Candidate | awk '{print $2}')
    if [[ "$INSTALLED" == "$CANDIDATE" ]]; then
        success "已是最新版本: ${PKG} ${INSTALLED}，无需更新"
        echo ""
        echo -e "当前内核: ${BOLD}$(uname -r)${NC}"
        exit 0
    else
        info "发现新版本: ${INSTALLED} → ${CANDIDATE}，开始升级..."
    fi
else
    info "开始全新安装: ${PKG}..."
fi

apt install -y "$PKG"

# ── 可选: DKMS 外部模块依赖 ───────────────────────────────
echo ""
read -rp "是否安装 DKMS 外部模块依赖 (dkms/clang/lld/llvm)? [y/N]: " dkms_choice
if [[ "${dkms_choice,,}" == "y" ]]; then
    apt install -y --no-install-recommends dkms libelf-dev clang lld llvm
    success "DKMS 依赖安装完成"
fi

# ── 完成提示 ──────────────────────────────────────────────
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  ✅ XanMod 内核安装/更新完成！${NC}"
echo -e "${GREEN}============================================${NC}"
echo -e "  已安装包: ${BOLD}${PKG}${NC}"
echo -e "  当前内核: ${BOLD}$(uname -r)${NC}"
echo -e "  新内核版本: ${BOLD}$(dpkg -l "$PKG" | grep '^ii' | awk '{print $3}')${NC}"
echo ""
echo -e "${YELLOW}  请执行 'reboot' 重启以加载新内核${NC}"
echo -e "${YELLOW}  重启后执行 'uname -r' 验证内核版本${NC}"
echo ""
