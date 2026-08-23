#!/usr/bin/env bash
# setup.sh — Install all tools required by pwnbox
# Usage: sudo ./setup.sh
# Supports: Kali, Ubuntu, Debian

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[-]${NC} $1"; }

# ── Pre-flight checks ───────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    fail "Run as root: sudo ./setup.sh"
    exit 1
fi

if ! command -v apt-get &>/dev/null; then
    fail "apt-get not found — this script targets Debian/Ubuntu/Kali"
    exit 1
fi

REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# Detect distro
DISTRO="unknown"
if [[ -f /etc/os-release ]]; then
    # runtime file; ID/PRETTY_NAME are read below with `${VAR:-default}` fallbacks
    # shellcheck source=/dev/null
    source /etc/os-release
    case "${ID:-}" in
        kali)   DISTRO="kali" ;;
        ubuntu) DISTRO="ubuntu" ;;
        debian) DISTRO="debian" ;;
    esac
fi

info "Installing pwnbox dependencies for user ${CYAN}${REAL_USER}${NC}"
info "Detected distro: ${CYAN}${DISTRO}${NC} (${PRETTY_NAME:-unknown})"
echo ""

INSTALLED=0
FAILED=()
PIP_INSTALLED=0

# Helper: try apt install, return 0/1
try_apt() {
    local pkg="$1"
    # `dpkg -s` also returns 0 for purged-but-configured packages (Status
    # "deinstall ok config-files"), which would wrongly skip a real reinstall.
    # Match the fully-installed status explicitly.
    if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        echo -e "  ${DIM}already installed: ${pkg}${NC}"
        return 0
    fi
    if apt-get install -y "$pkg" &>/dev/null; then
        ok "Installed: ${pkg}"
        INSTALLED=$((INSTALLED + 1))
        return 0
    fi
    return 1
}

# Helper: try pip3 install (as user)
try_pip() {
    local pkg="$1"
    local cmd="${2:-$1}"  # command name to check (defaults to pkg name)
    if command -v "$cmd" &>/dev/null; then
        echo -e "  ${DIM}already installed: ${cmd}${NC}"
        return 0
    fi
    if command -v pipx &>/dev/null; then
        if su - "$REAL_USER" -c "pipx install '$pkg'" &>/dev/null; then
            ok "Installed via pipx: ${pkg}"
            PIP_INSTALLED=$((PIP_INSTALLED + 1))
            return 0
        fi
    fi
    if command -v pip3 &>/dev/null; then
        if pip3 install --break-system-packages "$pkg" &>/dev/null || pip3 install "$pkg" &>/dev/null; then
            ok "Installed via pip3: ${pkg}"
            PIP_INSTALLED=$((PIP_INSTALLED + 1))
            return 0
        fi
    fi
    return 1
}

# Helper: resolve latest GitHub release tag
# Usage: github_latest_tag "owner/repo"  →  prints tag (e.g. "2.4.1")
github_latest_tag() {
    local repo="$1"
    # Follow the /latest redirect chain (-L: repos that moved redirect twice)
    # and extract the tag from the final location header.
    # `|| true`: a no-match (network hiccup, repo without a tagged release) must
    # not abort the whole script under `set -euo pipefail`; callers treat an empty
    # result as "couldn't resolve" and fall back.
    curl -sIL "https://github.com/${repo}/releases/latest" \
        | grep -i '^location:' \
        | grep -oP 'tag/\K[^\s/]+' \
        | tr -d '\r' \
        | tail -n1 || true
}

# Helper: is a command available? This script runs under sudo, whose secure_path
# excludes the real user's per-tool bin dirs (pipx → ~/.local/bin, cargo →
# ~/.cargo/bin, go → ~/go/bin), so add those before looking it up — otherwise
# tools installed for the user look "missing".
have() {
    PATH="${REAL_HOME}/.local/bin:${REAL_HOME}/.cargo/bin:${REAL_HOME}/go/bin:${PATH}" \
        command -v "$1" &>/dev/null
}

# Helper: install a ProjectDiscovery Go tool — prefer `go install` (as the real
# user), else fetch the versioned prebuilt release zip.
# Usage: install_pd_tool <bin> <go-import-path> <owner/repo>
install_pd_tool() {
    local bin="$1" import="$2" repo="$3"
    if have "$bin"; then
        echo -e "  ${DIM}already installed: ${bin}${NC}"
        return 0
    fi
    info "Installing ${bin}..."
    if su - "$REAL_USER" -c "command -v go" &>/dev/null; then
        if su - "$REAL_USER" -c "go install -v ${import}@latest" 2>/dev/null; then
            ok "${bin} installed via go"
            return 0
        fi
        FAILED+=("$bin")
        return 1
    fi
    # No Go toolchain — fetch the prebuilt binary. ProjectDiscovery assets embed
    # the version in the name, e.g. dnsx_1.2.3_linux_amd64.zip, so resolve the
    # tag first.
    local arch pd_arch tag url
    arch=$(uname -m)
    case "$arch" in
        x86_64)  pd_arch="linux_amd64" ;;
        aarch64) pd_arch="linux_arm64" ;;
        *)       pd_arch="" ;;
    esac
    tag=$(github_latest_tag "$repo")
    if [[ -n "$pd_arch" && -n "$tag" ]]; then
        url="https://github.com/${repo}/releases/download/${tag}/${bin}_${tag#v}_${pd_arch}.zip"
        if curl -fsSLo "/tmp/${bin}.zip" "$url" 2>/dev/null \
            && unzip -o "/tmp/${bin}.zip" -d /usr/local/bin/ "$bin" &>/dev/null; then
            chmod +x "/usr/local/bin/${bin}"
            rm -f "/tmp/${bin}.zip"
            ok "${bin} ${tag} installed from GitHub release"
            return 0
        fi
        rm -f "/tmp/${bin}.zip"
    else
        warn "${bin}: Go not installed and could not resolve a prebuilt binary for ${arch}"
    fi
    FAILED+=("$bin")
    return 1
}

# ── Apt cache update ────────────────────────────────────────────

export DEBIAN_FRONTEND=noninteractive

info "Updating apt cache..."
apt-get update -qq

# ── Core / required (all distros) ───────────────────────────────

info "Installing core packages..."
for pkg in nmap curl iputils-ping; do
    try_apt "$pkg" || FAILED+=("$pkg [REQUIRED]")
done

# ── Packages available on all distros ───────────────────────────

info "Installing common packages..."
COMMON_PACKAGES=(
    # DNS
    dnsutils           # dig

    # NFS
    nfs-common         # showmount

    # LDAP
    ldap-utils         # ldapsearch

    # MySQL
    default-mysql-client

    # PostgreSQL
    postgresql-client

    # Kerberos
    krb5-user

    # SMB
    smbclient
    samba-common-bin   # rpcclient

    # SNMP
    snmp               # snmpwalk

    # Misc
    netcat-openbsd
    unzip              # extracting dnsx release archive

    # Python (for pip fallbacks)
    python3-pip
    python3-impacket
)

for pkg in "${COMMON_PACKAGES[@]}"; do
    try_apt "$pkg" || warn "apt: ${pkg} not available"
done

# ── Distro-specific: Kali has many tools as apt packages ────────

if [[ "$DISTRO" == "kali" ]]; then
    info "Installing Kali-specific apt packages..."
    KALI_PACKAGES=(
        whatweb gobuster ffuf
        crackmapexec
        feroxbuster
        smtp-user-enum
        evil-winrm
        enum4linux
        onesixtyone
        nbtscan
        impacket-scripts
        redis-tools
    )
    for pkg in "${KALI_PACKAGES[@]}"; do
        try_apt "$pkg" || warn "apt: ${pkg} not available"
    done
else
    # ── Ubuntu/Debian: try apt first, then pip/binary fallbacks ──

    info "Installing tools (with Ubuntu fallbacks)..."

    # Tools that might be in apt on some Ubuntu versions
    for pkg in whatweb gobuster ffuf redis-tools nbtscan onesixtyone; do
        try_apt "$pkg" || warn "apt: ${pkg} not available (optional)"
    done

    # Impacket scripts (provides impacket-rpcdump, impacket-mssqlclient, etc.)
    if ! command -v impacket-rpcdump &>/dev/null; then
        info "Installing impacket tools via pip..."
        try_pip "impacket" "impacket-rpcdump" || FAILED+=("impacket (pip)")
    fi

    # crackmapexec / netexec
    if ! command -v crackmapexec &>/dev/null && ! command -v netexec &>/dev/null; then
        info "Installing netexec (crackmapexec successor) via pip..."
        try_pip "netexec" "netexec" || warn "netexec: pip install failed (optional)"
    fi

    # smtp-user-enum
    if ! command -v smtp-user-enum &>/dev/null; then
        info "Installing smtp-user-enum via pip..."
        try_pip "smtp-user-enum" "smtp-user-enum" || warn "smtp-user-enum: pip install failed (optional)"
    fi

    # evil-winrm (Ruby gem)
    if ! command -v evil-winrm &>/dev/null; then
        info "Installing evil-winrm..."
        if command -v gem &>/dev/null; then
            if gem install evil-winrm &>/dev/null; then
                ok "evil-winrm installed via gem"
            else
                warn "evil-winrm: gem install failed (optional)"
            fi
        else
            warn "evil-winrm: Ruby gem not available — install ruby first or skip"
        fi
    fi

    # enum4linux-ng (Python replacement for enum4linux)
    if ! command -v enum4linux-ng &>/dev/null && ! command -v enum4linux &>/dev/null; then
        info "Installing enum4linux-ng via pip..."
        try_pip "enum4linux-ng" "enum4linux-ng" || warn "enum4linux-ng: pip install failed (optional)"
    fi
fi

# ── Pip packages (cross-distro) ─────────────────────────────────

# enum4linux-ng (if not already handled above)
if ! command -v enum4linux-ng &>/dev/null; then
    try_pip "enum4linux-ng" "enum4linux-ng" || true
fi

echo ""

# ── Rust toolchain ───────────────────────────────────────────────

CARGO_BIN="${REAL_HOME}/.cargo/bin"

if ! su - "$REAL_USER" -c "command -v cargo" &>/dev/null; then
    info "Installing Rust toolchain..."
    # Bare command under `set -e`: a failed rustup (offline, TLS error, …) would
    # abort the whole script right here — taking rustscan, feroxbuster and the
    # pwnbox build down with it. Guard it so we degrade to a warning instead.
    if su - "$REAL_USER" -c 'curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y' 2>/dev/null; then
        ok "Rust toolchain installed"
    else
        warn "Rust toolchain install failed — install manually from https://rustup.rs"
        FAILED+=("rust toolchain")
    fi
else
    echo -e "  ${DIM}already installed: cargo${NC}"
fi

# ── Cargo packages ───────────────────────────────────────────────

# rustscan — install via cargo. (Upstream ships its .deb as a zipped, unversioned
# asset under a moved repo; the cargo path is the reliable one and we have the
# Rust toolchain anyway.)
if ! command -v rustscan &>/dev/null && ! test -f "${CARGO_BIN}/rustscan"; then
    info "Installing rustscan via cargo (may take a few minutes)..."
    if su - "$REAL_USER" -c "cargo install rustscan" 2>/dev/null; then
        ok "rustscan installed via cargo"
    else
        FAILED+=("rustscan")
    fi
else
    echo -e "  ${DIM}already installed: rustscan${NC}"
fi

# feroxbuster
if ! command -v feroxbuster &>/dev/null && ! test -f "${CARGO_BIN}/feroxbuster"; then
    info "Installing feroxbuster..."
    if try_apt feroxbuster; then
        true  # installed via apt
    elif su - "$REAL_USER" -c "cargo install feroxbuster" 2>/dev/null; then
        ok "feroxbuster installed via cargo"
    else
        FAILED+=("feroxbuster")
    fi
else
    echo -e "  ${DIM}already installed: feroxbuster${NC}"
fi

# ── Go binaries ─────────────────────────────────────────────────

# kerbrute
if ! command -v kerbrute &>/dev/null; then
    info "Installing kerbrute..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)  KB_ARCH="linux_amd64" ;;
        aarch64) KB_ARCH="linux_arm64" ;;
        *)       KB_ARCH="" ;;
    esac

    if [[ -n "$KB_ARCH" ]]; then
        KB_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_${KB_ARCH}"
        if curl -fsSLo /usr/local/bin/kerbrute "$KB_URL" 2>/dev/null; then
            chmod +x /usr/local/bin/kerbrute
            ok "kerbrute installed to /usr/local/bin/"
        else
            rm -f /usr/local/bin/kerbrute
            FAILED+=("kerbrute")
        fi
    else
        warn "kerbrute: unsupported architecture $ARCH"
        FAILED+=("kerbrute")
    fi
else
    echo -e "  ${DIM}already installed: kerbrute${NC}"
fi

# dnsx + subfinder (ProjectDiscovery) — go install, else prebuilt release.
# `|| true` keeps a failed install (tracked in FAILED inside the helper) from
# aborting the script under `set -e`.
install_pd_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx" "projectdiscovery/dnsx" || true
install_pd_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "projectdiscovery/subfinder" || true

# ── SecLists ─────────────────────────────────────────────────────

if [[ ! -d /opt/SecLists ]] && [[ ! -d /usr/share/seclists ]]; then
    info "Installing SecLists to /opt/SecLists..."
    if apt-get install -y -qq seclists &>/dev/null; then
        # Kali installs to /usr/share/seclists, symlink to /opt
        [[ -d /usr/share/seclists ]] && ln -sf /usr/share/seclists /opt/SecLists
        ok "SecLists installed via apt"
    elif command -v git &>/dev/null; then
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/SecLists 2>/dev/null \
            && ok "SecLists cloned to /opt/SecLists" \
            || FAILED+=("SecLists")
    else
        FAILED+=("SecLists (git not found)")
    fi
else
    echo -e "  ${DIM}already installed: SecLists${NC}"
fi

# ── Build pwnbox itself ──────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${SCRIPT_DIR}/Cargo.toml" ]]; then
    info "Building pwnbox (release)..."
    su - "$REAL_USER" -c "cd '${SCRIPT_DIR}' && cargo build --release" 2>&1 \
        || warn "pwnbox build failed — build manually: cargo build --release"
    BINARY="${SCRIPT_DIR}/target/release/pwnbox"
    if [[ -f "$BINARY" ]]; then
        cp "$BINARY" /usr/local/bin/pwnbox
        chmod +x /usr/local/bin/pwnbox
        ok "pwnbox installed to /usr/local/bin/pwnbox"
    else
        warn "pwnbox binary not found at ${BINARY}"
    fi
fi

# ── Summary ──────────────────────────────────────════════════════

echo ""
echo -e "${CYAN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup complete${NC} (${DISTRO})"
[[ $INSTALLED -gt 0 ]] && echo -e "  ${GREEN}Installed ${INSTALLED} apt package(s)${NC}"
[[ $PIP_INSTALLED -gt 0 ]] && echo -e "  ${GREEN}Installed ${PIP_INSTALLED} pip package(s)${NC}"

if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo ""
    warn "Failed to install (install manually):"
    for f in "${FAILED[@]}"; do
        echo -e "    ${RED}- ${f}${NC}"
    done
fi

# Post-install verification
echo ""
info "Verifying tool availability..."
TOOLS_OK=0
TOOLS_MISS=0
for tool in nmap curl ping rustscan feroxbuster whatweb gobuster ffuf \
            smbclient rpcclient crackmapexec ldapsearch dig mysql psql \
            redis-cli showmount snmpwalk kerbrute smtp-user-enum dnsx subfinder \
            enum4linux-ng impacket-rpcdump evil-winrm onesixtyone nc; do
    # Some tools ship under an alternative name — accept either.
    case "$tool" in
        crackmapexec)  alt="netexec" ;;
        enum4linux-ng) alt="enum4linux" ;;
        *)             alt="" ;;
    esac
    if have "$tool" || { [[ -n "$alt" ]] && have "$alt"; }; then
        TOOLS_OK=$((TOOLS_OK + 1))
    else
        echo -e "  ${YELLOW}missing: ${tool}${NC}"
        TOOLS_MISS=$((TOOLS_MISS + 1))
    fi
done
echo -e "  ${GREEN}${TOOLS_OK} tools available${NC}, ${YELLOW}${TOOLS_MISS} missing${NC}"

echo -e "${CYAN}══════════════════════════════════════════${NC}"

# Signal failure to callers/automation if a REQUIRED package failed to install
# (optional tools only warn). Without this the script always exits 0, so a
# missing nmap/curl is indistinguishable from success in a pipeline.
if [[ ${#FAILED[@]} -gt 0 ]]; then
    for f in "${FAILED[@]}"; do
        if [[ "$f" == *"[REQUIRED]"* ]]; then
            exit 1
        fi
    done
fi
exit 0
