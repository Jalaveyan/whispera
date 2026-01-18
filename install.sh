#!/bin/bash

# Whispera Installer v2.1
# One-liner: bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh)

set -e

# --- Global Variables ---
REPO_URL="https://github.com/Jalaveyan/Whispera.git"
BRANCH="main"
WORK_DIR="/opt/whispera"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"
BIN_PATH="/usr/local/bin"
LOG_PATH="/var/log/whispera"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# --- Helpers ---

log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERR]${PLAIN} $1"; }

get_public_ip() {
    local IP=$(curl -s https://api.ipify.org -m 5 2>/dev/null)
    if [[ -z "$IP" ]]; then
        IP=$(curl -s https://ifconfig.me -m 5 2>/dev/null)
    fi
    if [[ -z "$IP" ]]; then
        IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    echo "${IP:-localhost}"
}

print_logo() {
    echo -e "${BLUE}"
    echo "█   █ █ █ █ ▀▀█ █▀▀ █▀▀ █▀▀ █▀█"
    echo "█ █ █ █▀█ █   ▀▀█ █▀▀ █▀▀ █▀▀ █▀█"
    echo "▀▄▀▄▀ ▀ ▀ ▀   ▀▀▀ ▀   ▀▀▀ ▀   ▀ ▀"
    echo ":: Whispera Installer :: (v2.1.0)"
    echo -e "${PLAIN}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root!"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        RELEASE=$ID
    else
        log_err "Failed to check OS"
        exit 1
    fi
}

# --- Installation Steps ---

install_dependencies() {
    log_info "Installing dependencies..."
    
    case $RELEASE in
        centos|fedora|almalinux|rocky)
            yum install -y curl git wget tar unzip openssl >/dev/null 2>&1
            ;;
        ubuntu|debian)
            apt-get update >/dev/null 2>&1
            apt-get install -y curl git wget tar unzip openssl >/dev/null 2>&1
            ;;
        alpine)
            apk add curl git wget tar unzip openssl >/dev/null 2>&1
            ;;
        *)
            log_warn "Unknown OS: $RELEASE - trying apt-get"
            apt-get update >/dev/null 2>&1 || true
            apt-get install -y curl git wget tar unzip openssl >/dev/null 2>&1 || true
            ;;
    esac
    
    log_success "Dependencies installed"
}

install_go() {
    if command -v go &>/dev/null; then
        local GO_VER=$(go version | awk '{print $3}')
        log_info "Go already installed: $GO_VER"
        return
    fi
    
    log_info "Installing Go..."
    local GO_V=$(curl -s https://go.dev/dl/?mode=json 2>/dev/null | grep -o 'go[0-9.]*' | head -n1)
    
    if [[ -z "$GO_V" ]]; then
        GO_V="go1.23.4"
    fi
    
    wget -q "https://go.dev/dl/${GO_V}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
    rm -f /tmp/go.tar.gz
    
    export PATH=$PATH:/usr/local/go/bin
    
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi
    
    log_success "Go installed: $GO_V"
}

setup_bbr() {
    log_info "Enabling BBR TCP congestion control..."
    
    # Check if BBR is already enabled
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_info "BBR already enabled"
        return
    fi
    
    # Check kernel version (BBR requires 4.9+)
    local KERNEL_VER=$(uname -r | cut -d. -f1-2)
    local KERNEL_MAJOR=$(echo $KERNEL_VER | cut -d. -f1)
    local KERNEL_MINOR=$(echo $KERNEL_VER | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 4 ]] || [[ $KERNEL_MAJOR -eq 4 && $KERNEL_MINOR -lt 9 ]]; then
        log_warn "Kernel $KERNEL_VER too old for BBR (requires 4.9+), skipping"
        return
    fi
    
    # Enable BBR
    cat >> /etc/sysctl.conf <<EOF

# BBR TCP Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    
    sysctl -p >/dev/null 2>&1
    
    # Verify
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_success "BBR enabled"
    else
        log_warn "BBR enable failed, kernel may not support it"
    fi
}

setup_warp() {
    log_info "Setting up Cloudflare WARP..."
    
    # Check if already installed
    if command -v warp-cli &>/dev/null; then
        log_info "WARP already installed"
        
        # Check status
        if warp-cli status 2>/dev/null | grep -q "Connected"; then
            log_success "WARP is connected"
            return
        fi
    else
        # Install WARP based on OS
        case $RELEASE in
            ubuntu|debian)
                # Add Cloudflare GPG key and repo
                curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor -o /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg 2>/dev/null
                echo "deb [arch=amd64 signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/cloudflare-client.list
                apt-get update >/dev/null 2>&1
                apt-get install -y cloudflare-warp >/dev/null 2>&1
                ;;
            centos|fedora|almalinux|rocky)
                # Add Cloudflare repo for RHEL-based
                curl -fsSL https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo > /etc/yum.repos.d/cloudflare-warp.repo
                yum install -y cloudflare-warp >/dev/null 2>&1
                ;;
            *)
                log_warn "WARP installation not supported on $RELEASE, skipping"
                return
                ;;
        esac
    fi
    
    # Check if installed successfully
    if ! command -v warp-cli &>/dev/null; then
        log_warn "WARP installation failed, skipping"
        return
    fi
    
    # Register and connect (non-interactive)
    log_info "Registering WARP..."
    
    # Accept TOS and register
    warp-cli --accept-tos register 2>/dev/null || true
    
    # Set mode to proxy (SOCKS5 on 127.0.0.1:40000)
    warp-cli set-mode proxy 2>/dev/null || true
    
    # Connect
    warp-cli connect 2>/dev/null || true
    
    sleep 2
    
    # Verify connection
    if warp-cli status 2>/dev/null | grep -q "Connected"; then
        log_success "WARP connected (SOCKS5 proxy on 127.0.0.1:40000)"
        
        # Add WARP proxy to config hint
        echo ""
        log_info "To route traffic through WARP, add to config.yaml:"
        echo "  relay:"
        echo "    upstream_proxy: \"socks5://127.0.0.1:40000\""
    else
        log_warn "WARP connection failed. Run 'warp-cli connect' manually."
    fi
}

setup_fail2ban() {
    log_info "Setting up Fail2ban..."
    
    case $RELEASE in
        ubuntu|debian)
            apt-get install -y fail2ban >/dev/null 2>&1
            ;;
        centos|fedora|almalinux|rocky)
            yum install -y fail2ban >/dev/null 2>&1
            ;;
        *)
            log_warn "Fail2ban not supported on $RELEASE"
            return
            ;;
    esac
    
    # Configure jail for SSH
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
    
    log_success "Fail2ban installed (SSH protection enabled)"
}

setup_swap() {
    log_info "Setting up Swap..."
    
    # Check if swap exists
    if swapon --show | grep -q "/"; then
        log_info "Swap already exists"
        swapon --show
        return
    fi
    
    # Create 2GB swap
    local SWAP_SIZE="2G"
    
    fallocate -l $SWAP_SIZE /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    
    # Make permanent
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    
    # Optimize swappiness
    sysctl vm.swappiness=10 >/dev/null 2>&1
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    
    log_success "Swap $SWAP_SIZE created"
}

setup_sysctl() {
    log_info "Optimizing system settings..."
    
    cat >> /etc/sysctl.conf <<EOF

# Whispera Optimizations
# Network buffers
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

# File descriptors
fs.file-max = 1000000

# TCP optimizations
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
EOF
    
    sysctl -p >/dev/null 2>&1
    
    # Increase ulimits
    cat >> /etc/security/limits.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
EOF
    
    log_success "System optimized"
}

setup_autoupdate() {
    log_info "Setting up auto-update..."
    
    # Create update script
    cat > /etc/cron.daily/whispera-update <<EOF
#!/bin/bash
cd $WORK_DIR
git pull origin main --quiet
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
    
    # Backup original config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
    
    # Apply hardening
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    
    log_success "SSH hardened (password auth disabled)"
    log_warn "Make sure you have SSH key access before logging out!"
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

clone_or_update_repo() {
    log_info "Setting up Whispera source code..."
    
    mkdir -p "$WORK_DIR"
    
    if [[ -d "$WORK_DIR/.git" ]]; then
        log_info "Repository exists, updating..."
        cd "$WORK_DIR"
        git fetch origin "$BRANCH" --quiet
        git reset --hard "origin/$BRANCH" --quiet
    else
        # Check if we're running from source tree
        SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        
        if [[ -f "$SCRIPT_DIR/cmd/server/main.go" ]]; then
            log_info "Installing from local source..."
            if [[ "$SCRIPT_DIR" != "$WORK_DIR" ]]; then
                rm -rf "$WORK_DIR"/*
                cp -r "$SCRIPT_DIR"/* "$WORK_DIR/"
            fi
        else
            log_info "Cloning repository..."
            rm -rf "$WORK_DIR"
            git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$WORK_DIR" --quiet
        fi
    fi
    
    cd "$WORK_DIR"
    log_success "Source code ready in $WORK_DIR"
}

build_whispera() {
    log_info "Building Whispera server..."
    
    cd "$WORK_DIR"
    export PATH=$PATH:/usr/local/go/bin
    export CGO_ENABLED=0
    
    rm -f whispera-server
    go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server
    
    if [[ ! -f "whispera-server" ]]; then
        log_err "Build failed!"
        exit 1
    fi
    
    cp whispera-server "$BIN_PATH/whispera"
    chmod +x "$BIN_PATH/whispera"
    
    log_success "Binary installed to $BIN_PATH/whispera"
}

install_web_ui() {
    log_info "Installing Web UI..."
    
    mkdir -p "$DAT_PATH/web"
    
    if [[ -d "$WORK_DIR/web" ]]; then
        cp -r "$WORK_DIR/web"/* "$DAT_PATH/web/"
        log_success "Web UI installed"
    else
        log_warn "Web directory not found, skipping"
    fi
}

generate_keys() {
    log_info "Generating X25519 keypair..."
    
    mkdir -p "$CONF_PATH"
    
    local OUTPUT=$("$BIN_PATH/whispera" x25519 2>/dev/null)
    local PRIVATE_KEY=$(echo "$OUTPUT" | grep "Private Key:" | awk '{print $3}')
    local PUBLIC_KEY=$(echo "$OUTPUT" | grep "Public Key:" | awk '{print $3}')
    
    if [[ -z "$PRIVATE_KEY" ]]; then
        log_err "Failed to generate keys"
        exit 1
    fi
    
    echo "$PRIVATE_KEY" > "$CONF_PATH/server.key"
    echo "$PUBLIC_KEY" > "$CONF_PATH/server.pub"
    
    log_success "Keys generated"
}

generate_config() {
    log_info "Generating configuration..."
    
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key" 2>/dev/null)
    
    if [[ -z "$PRIVATE_KEY" ]]; then
        generate_keys
        PRIVATE_KEY=$(cat "$CONF_PATH/server.key")
    fi
    
    cat > "$CONF_PATH/config.yaml" <<EOF
server:
  name: whispera-server
  listen_addr: "0.0.0.0:8443"
  mtu: 1420
  workers: 8

transport:
  udp:
    enabled: true
    listen_addr: ":8443"
  tcp:
    enabled: false
    listen_addr: ":8443"
  websocket:
    enabled: false
    listen_addr: ":8080"

phantom:
  enabled: true
  dest: "yandex.ru:443"
  server_names:
    - "sberbank.ru"
    - "tinkoff.ru"
    - "yandex.ru"
    - "mail.ru"
    - "rambler.ru"
    - "ya.ru"
    - "vk.com"
    - "ok.ru"
    - "dzen.ru"
    - "rutube.ru"
    - "ozon.ru"
    - "wildberries.ru"
    - "avito.ru"
    - "mos.ru"
    - "gosuslugi.ru"
  private_key: "$PRIVATE_KEY"
  max_time_diff: 60
  fingerprint: "chrome"

relay:
  max_streams: 10000
  enable_tcp: true
  enable_udp: true

metrics:
  enabled: true
  listen_addr: ":9090"
  path: "/metrics"

api:
  enabled: true
  listen_addr: ":8080"
  web_root: "$DAT_PATH/web"
EOF
    
    log_success "Config saved to $CONF_PATH/config.yaml"
}

setup_systemd() {
    log_info "Setting up SystemD service..."
    
    cat > /etc/systemd/system/whispera.service <<EOF
[Unit]
Description=Whispera Server
Documentation=https://github.com/Jalaveyan/Whispera
After=network.target network-online.target
Requires=network-online.target

[Service]
User=root
WorkingDirectory=$WORK_DIR
ExecStart=$BIN_PATH/whispera -config $CONF_PATH/config.yaml -api :8080
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable whispera >/dev/null 2>&1
    systemctl restart whispera
    
    log_success "Service installed and started"
}

setup_network() {
    log_info "Configuring network..."
    
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    
    if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
    
    # Detect WAN interface and setup NAT
    local WAN_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -n "$WAN_IF" ]] && command -v iptables &>/dev/null; then
        iptables -t nat -C POSTROUTING -s 10.0.85.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.0.85.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
    fi
    
    log_success "Network configured"
}

setup_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &>/dev/null; then
        ufw allow ssh >/dev/null 2>&1 || true
        ufw allow 8443/tcp >/dev/null 2>&1 || true
        ufw allow 8443/udp >/dev/null 2>&1 || true
        ufw allow 8080/tcp >/dev/null 2>&1 || true
        ufw --force enable >/dev/null 2>&1 || true
        log_success "UFW configured"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=8443/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=8443/udp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_success "Firewalld configured"
    else
        log_warn "No firewall found, skipping"
    fi
}

show_connection_key() {
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key" 2>/dev/null)
    local PUBLIC_KEY=$("$BIN_PATH/whispera" pubkey "$PRIVATE_KEY" 2>/dev/null)
    local SERVER_IP=$(get_public_ip)
    
    echo ""
    echo -e "${GREEN}================================================================${PLAIN}"
    echo -e "${GREEN} CLIENT CONNECTION KEY                                          ${PLAIN}"
    echo -e "${GREEN}================================================================${PLAIN}"
    echo -e "${BLUE}whispera://${SERVER_IP}:8443?pub=${PUBLIC_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome${PLAIN}"
    echo -e "${GREEN}================================================================${PLAIN}"
    echo ""
}

install_cli_wrapper() {
    cat > "$BIN_PATH/whispera-mgmt" <<'EOF'
#!/bin/bash
case $1 in
    start) systemctl start whispera ;;
    stop) systemctl stop whispera ;;
    restart) systemctl restart whispera ;;
    status) systemctl status whispera ;;
    log|logs) journalctl -u whispera -f ;;
    config) ${EDITOR:-nano} /etc/whispera/config.yaml ;;
    key) 
        PRIVATE_KEY=$(cat /etc/whispera/server.key 2>/dev/null)
        PUBLIC_KEY=$(/usr/local/bin/whispera pubkey "$PRIVATE_KEY" 2>/dev/null)
        SERVER_IP=$(curl -s https://api.ipify.org -m 5 2>/dev/null || echo "YOUR_IP")
        echo "whispera://${SERVER_IP}:8443?pub=${PUBLIC_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome"
        ;;
    update)
        cd /opt/whispera && git pull origin main
        go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server
        cp whispera-server /usr/local/bin/whispera
        systemctl restart whispera
        echo "Updated!"
        ;;
    *) echo "Usage: whispera-mgmt {start|stop|restart|status|log|config|key|update}" ;;
esac
EOF
    chmod +x "$BIN_PATH/whispera-mgmt"
    log_success "CLI wrapper installed (whispera-mgmt)"
}

# --- Main Installation ---

main() {
    check_root
    check_os
    print_logo
    
    install_dependencies
    install_go
    clone_or_update_repo
    build_whispera
    install_web_ui
    
    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        generate_keys
        generate_config
    else
        log_info "Config exists, keeping current configuration"
    fi
    
    install_cli_wrapper
    setup_network
    setup_firewall
    setup_systemd
    
    echo ""
    log_success "Whispera installed successfully!"
    echo ""
    echo -e "  Manage:         ${GREEN}whispera-mgmt${PLAIN}"
    echo -e "  Config:         ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    echo -e "  Web Interface:  ${GREEN}http://$(get_public_ip):8080${PLAIN}"
    
    show_connection_key
    
    # Show interactive extras menu
    show_extras_menu
}

# --- Entry Point ---

case "${1:-}" in
    keygen)
        generate_keys
        generate_config
        systemctl restart whispera 2>/dev/null || true
        show_connection_key
        ;;
    key|showkey)
        show_connection_key
        ;;
    update)
        log_info "Updating Whispera..."
        clone_or_update_repo
        build_whispera
        systemctl restart whispera
        log_success "Update complete"
        ;;
    bbr)
        check_root
        setup_bbr
        ;;
    warp)
        check_root
        check_os
        setup_warp
        ;;
    fail2ban)
        check_root
        check_os
        setup_fail2ban
        ;;
    swap)
        check_root
        setup_swap
        ;;
    optimize)
        check_root
        setup_sysctl
        ;;
    autoupdate)
        check_root
        setup_autoupdate
        ;;
    harden)
        check_root
        setup_ssh_hardening
        ;;
    extras)
        check_root
        check_os
        show_extras_menu
        ;;
    restart)
        systemctl restart whispera
        log_success "Whispera restarted"
        ;;
    status)
        systemctl status whispera
        ;;
    help|--help|-h)
        echo "Whispera Installer v2.1"
        echo ""
        echo "Usage: ./install.sh [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)   Full installation + extras menu"
        echo "  keygen      Regenerate keys"
        echo "  key         Show connection key"
        echo "  update      Pull latest and rebuild"
        echo "  extras      Show extras menu"
        echo ""
        echo "Individual extras:"
        echo "  bbr         Enable BBR (faster TCP)"
        echo "  warp        Cloudflare WARP (hide IP)"
        echo "  fail2ban    Protect SSH from brute-force"
        echo "  swap        Create 2GB swap"
        echo "  optimize    Tune sysctl settings"
        echo "  autoupdate  Enable daily auto-updates"
        echo "  harden      SSH hardening (keys only)"
        echo ""
        echo "Service:"
        echo "  restart     Restart Whispera"
        echo "  status      Show status"
        echo ""
        echo "One-liner install:"
        echo "  bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh)"
        ;;
    *)
        main "$@"
        ;;
esac
