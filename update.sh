#!/bin/bash
# Whispera Update Script v2.1

set -e

WORK_DIR="/opt/whispera"
BIN_PATH="/usr/local/bin"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"
BRANCH="main"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERR]${PLAIN} $1"; }

get_public_ip() {
    local IP=$(curl -s https://api.ipify.org -m 5 2>/dev/null)
    if [[ -z "$IP" ]]; then
        IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    echo "${IP:-localhost}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        RELEASE=$ID
    fi
}

# --- Extra Functions ---

setup_bbr() {
    log_info "Enabling BBR TCP congestion control..."
    
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_info "BBR already enabled"
        return
    fi
    
    local KERNEL_MAJOR=$(uname -r | cut -d. -f1)
    local KERNEL_MINOR=$(uname -r | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 4 ]] || [[ $KERNEL_MAJOR -eq 4 && $KERNEL_MINOR -lt 9 ]]; then
        log_warn "Kernel too old for BBR (requires 4.9+)"
        return
    fi
    
    cat >> /etc/sysctl.conf <<EOF

# BBR TCP Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    sysctl -p >/dev/null 2>&1
    
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_success "BBR enabled"
    else
        log_warn "BBR enable failed"
    fi
}

setup_warp() {
    log_info "Setting up Cloudflare WARP..."
    
    if command -v warp-cli &>/dev/null; then
        if warp-cli status 2>/dev/null | grep -q "Connected"; then
            log_success "WARP already connected"
            return
        fi
    else
        case $RELEASE in
            ubuntu|debian)
                curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
                echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list
                apt-get update >/dev/null 2>&1
                apt-get install -y cloudflare-warp >/dev/null 2>&1
                ;;
            centos|fedora|almalinux|rocky)
                curl -fsSL https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo > /etc/yum.repos.d/cloudflare-warp.repo
                yum install -y cloudflare-warp >/dev/null 2>&1
                ;;
            *)
                log_warn "WARP not supported on $RELEASE"
                return
                ;;
        esac
    fi
    
    if ! command -v warp-cli &>/dev/null; then
        log_warn "WARP installation failed"
        return
    fi
    
    warp-cli --accept-tos register 2>/dev/null || true
    warp-cli set-mode proxy 2>/dev/null || true
    warp-cli connect 2>/dev/null || true
    sleep 2
    
    if warp-cli status 2>/dev/null | grep -q "Connected"; then
        log_success "WARP connected (SOCKS5 on 127.0.0.1:40000)"
    else
        log_warn "WARP connection failed"
    fi
}

setup_fail2ban() {
    log_info "Setting up Fail2ban..."
    
    case $RELEASE in
        ubuntu|debian) apt-get install -y fail2ban >/dev/null 2>&1 ;;
        centos|fedora|almalinux|rocky) yum install -y fail2ban >/dev/null 2>&1 ;;
        *) log_warn "Fail2ban not supported"; return ;;
    esac
    
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
EOF
    
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    log_success "Fail2ban installed"
}

setup_swap() {
    log_info "Setting up Swap..."
    
    if swapon --show | grep -q "/"; then
        log_info "Swap already exists"
        return
    fi
    
    fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    
    sysctl vm.swappiness=10 >/dev/null 2>&1
    log_success "Swap 2GB created"
}

setup_sysctl() {
    log_info "Optimizing system..."
    
    cat >> /etc/sysctl.conf <<EOF

# Whispera Optimizations
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_fastopen = 3
fs.file-max = 1000000
EOF
    
    sysctl -p >/dev/null 2>&1
    log_success "System optimized"
}

setup_autoupdate() {
    log_info "Setting up auto-update..."
    
    cat > /etc/cron.daily/whispera-update <<EOF
#!/bin/bash
cd $WORK_DIR
git pull origin $BRANCH --quiet
export PATH=\$PATH:/usr/local/go/bin
go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server 2>/dev/null
if [[ -f whispera-server ]]; then
    cp whispera-server $BIN_PATH/whispera
    systemctl restart whispera
fi
EOF
    chmod +x /etc/cron.daily/whispera-update
    log_success "Auto-update enabled (daily)"
}

setup_ssh_hardening() {
    log_info "Hardening SSH..."
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    log_success "SSH hardened (password auth disabled)"
    log_warn "Make sure you have SSH key access!"
}

show_extras_menu() {
    while true; do
        echo ""
        echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${PLAIN}"
        echo -e "${BLUE}║              OPTIONAL EXTRAS - Select by number              ║${PLAIN}"
        echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  1. BBR           - Faster TCP (recommended)                ${BLUE}║${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  2. WARP          - Hide server IP via Cloudflare           ${BLUE}║${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  3. Fail2ban      - Protect SSH from brute-force            ${BLUE}║${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  4. Swap          - Add 2GB swap (for low-RAM servers)      ${BLUE}║${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  5. Optimize      - Tune sysctl for high performance        ${BLUE}║${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  6. Auto-update   - Daily auto-update from GitHub           ${BLUE}║${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  7. SSH Hardening - Disable password auth (keys only)       ${BLUE}║${PLAIN}"
        echo -e "${BLUE}╠══════════════════════════════════════════════════════════════╣${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  9. Show menu     - Refresh this menu                       ${BLUE}║${PLAIN}"
        echo -e "${BLUE}║${PLAIN}  0. Exit                                                    ${BLUE}║${PLAIN}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${PLAIN}"
        echo ""
        
        read -p "Select [0-7, 9]: " choice
        case $choice in
            1) setup_bbr ;;
            2) setup_warp ;;
            3) setup_fail2ban ;;
            4) setup_swap ;;
            5) setup_sysctl ;;
            6) setup_autoupdate ;;
            7) setup_ssh_hardening ;;
            9) continue ;;
            0|"") log_info "Done!"; break ;;
            *) log_warn "Invalid option" ;;
        esac
    done
}

# --- Main Update ---

do_update() {
    log_info "Updating Whispera..."
    
    # Sync source
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ "$SCRIPT_DIR" != "$WORK_DIR" ]] && [[ -f "$SCRIPT_DIR/cmd/server/main.go" ]]; then
        log_info "Syncing from local source..."
        rsync -a --delete --exclude='.git' "$SCRIPT_DIR/" "$WORK_DIR/" 2>/dev/null || cp -r "$SCRIPT_DIR"/* "$WORK_DIR/"
    elif [[ -d "$WORK_DIR/.git" ]]; then
        log_info "Pulling from GitHub..."
        cd "$WORK_DIR"
        git fetch origin $BRANCH --quiet
        git reset --hard origin/$BRANCH --quiet
    fi
    
    cd "$WORK_DIR" || exit 1
    
    # Build
    log_info "Building server..."
    export PATH=$PATH:/usr/local/go/bin
    rm -f whispera-server
    go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server
    
    if [[ ! -f "whispera-server" ]]; then
        log_err "Build failed!"
        exit 1
    fi
    
    # Stop service
    log_info "Stopping service..."
    systemctl stop whispera 2>/dev/null || true
    sleep 1
    
    # Update binary
    log_info "Installing binary..."
    cp whispera-server "$BIN_PATH/whispera"
    chmod +x "$BIN_PATH/whispera"
    
    # Update Web UI
    if [[ -d "web" ]]; then
        log_info "Updating Web UI..."
        mkdir -p "$DAT_PATH/web"
        cp -r web/* "$DAT_PATH/web/"
    fi
    
    # Preserve config - just restart
    log_info "Starting service..."
    systemctl start whispera
    
    # Get keys for display
    PRIVATE_KEY=$(grep "private_key:" "$CONF_PATH/config.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' | head -n1)
    PUBLIC_KEY=$($BIN_PATH/whispera pubkey "$PRIVATE_KEY" 2>/dev/null)
    SERVER_IP=$(get_public_ip)
    
    echo ""
    log_success "Whispera updated successfully!"
    echo -e "  Config:         ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:8080${PLAIN}"
    
    if [[ -n "$PUBLIC_KEY" ]]; then
        echo ""
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "${GREEN} CLIENT CONNECTION KEY                                          ${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "${BLUE}whispera://${SERVER_IP}:8443?pub=${PUBLIC_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
    fi
    echo ""
    
    # Show extras menu
    show_extras_menu
}

# --- Entry Point ---

check_root
check_os

case "${1:-}" in
    bbr) setup_bbr ;;
    warp) setup_warp ;;
    fail2ban) setup_fail2ban ;;
    swap) setup_swap ;;
    optimize) setup_sysctl ;;
    autoupdate) setup_autoupdate ;;
    harden) setup_ssh_hardening ;;
    extras) show_extras_menu ;;
    help|--help|-h)
        echo "Whispera Update Script v2.1"
        echo ""
        echo "Usage: ./update.sh [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)   Update Whispera"
        echo "  extras      Show extras menu"
        echo ""
        echo "Individual extras:"
        echo "  bbr         Enable BBR (faster TCP)"
        echo "  warp        Cloudflare WARP (hide IP)"
        echo "  fail2ban    Protect SSH"
        echo "  swap        Create 2GB swap"
        echo "  optimize    Tune sysctl"
        echo "  autoupdate  Enable daily updates"
        echo "  harden      SSH hardening"
        ;;
    *)
        do_update
        ;;
esac
