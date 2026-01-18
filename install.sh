#!/bin/bash

# Whispera Installer
# Inspired by Xray-core installation script
# https://github.com/XTLS/Xray-core

# --- Global Variables ---
DAT_PATH=${DAT_PATH:-/usr/local/share/whispera}
CONF_PATH=${CONF_PATH:-/etc/whispera}
BIN_PATH=${BIN_PATH:-/usr/local/bin}
LOG_PATH=${LOG_PATH:-/var/log/whispera}
WORK_DIR="/opt/whispera"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

# --- Helpers ---

get_public_ip() {
    local IP=$(curl -s https://api.ipify.org -m 5)
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
    echo ":: Whispera Installer :: (v2.0.0)"
    echo -e "${PLAIN}"
}

log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERR]${PLAIN} $1"; }

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
    
    local CMD_INSTALL=""
    case $RELEASE in
        centos|fedora|almalinux|rocky)
            CMD_INSTALL="yum install -y"
            ;;
        ubuntu|debian)
            log_info "Installing security tools..."
            apt-get update >/dev/null
            apt-get install -y fail2ban whois
            systemctl enable fail2ban
            systemctl start fail2ban
            
            CMD_INSTALL="apt-get install -y"
            ;;
        alpine)
            CMD_INSTALL="apk add"
            ;;
        *)
            log_err "Unsupported OS: $RELEASE"
            exit 1
            ;;
    esac

    $CMD_INSTALL curl git wget tar unzip openssl python3 python3-pip >/dev/null 2>&1
    log_success "Dependencies installed"
}

install_go() {
    if command -v go &>/dev/null; then
        local GO_VER=$(go version | awk '{print $3}')
        log_info "Go is already installed: $GO_VER"
        return
    fi
    
    log_info "Installing Go (latest)..."
    local GO_V=$(curl -s https://go.dev/dl/?mode=json | grep -o 'go[0-9.]*' | head -n1)
    
    if [[ -z "$GO_V" ]]; then
        GO_V="go1.23.4"
    fi
    
    wget -q "https://go.dev/dl/${GO_V}.linux-amd64.tar.gz" -O go.tar.gz
    rm -rf /usr/local/go && tar -C /usr/local -xzf go.tar.gz
    rm -f go.tar.gz
    
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    
    log_success "Go installed: $GO_V"
}

setup_ml_engine() {
    log_info "Setting up ML Engine..."
    
    # Check Python version
    if ! command -v python3 &>/dev/null; then
         log_warn "Python3 not found, skipping ML setup"
         return
    fi
    
    # Install pip deps
    log_info "Installing Python dependencies (this may take a while)..."
    pip3 install --upgrade pip >/dev/null 2>&1
    pip3 install numpy pandas scikit-learn fastapi uvicorn pydantic psutil >/dev/null 2>&1
    # TensorFLow optional/heavy, install separately if needed
    
    log_success "ML Engine dependencies ready"
}

build_whispera() {
    log_info "Building Whispera..."
    
    mkdir -p "$WORK_DIR"
    cp -r ./* "$WORK_DIR/"
    cd "$WORK_DIR"
    
    export CGO_ENABLED=0
    /usr/local/go/bin/go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server
    
    if [[ ! -f "whispera-server" ]]; then
        log_err "Build failed!"
        exit 1
    fi
    
    cp whispera-server "$BIN_PATH/whispera"
    chmod +x "$BIN_PATH/whispera"

    # Install Web UI
    log_info "Installing Web UI..."
    mkdir -p "$DAT_PATH/web"
    if [[ -d "web" ]]; then
        cp -r web/* "$DAT_PATH/web/"
    else
        log_warn "Web directory not found, skipping UI installation"
    fi
    
    log_success "Whispera binary installed to $BIN_PATH/whispera"
}

	# Generate new keys
generate_keys() {
    log_info "Generating X25519 keypair..."
    
    local PRIVATE_KEY=""
    local PUBLIC_KEY=""
    local UUID=$(cat /proc/sys/kernel/random/uuid)
    
    mkdir -p "$CONF_PATH"
    
    # Generate X25519 keypair using binary (if available) or temp build
    if [[ -f "$BIN_PATH/whispera" ]]; then
        OUTPUT=$($BIN_PATH/whispera x25519)
        PRIVATE_KEY=$(echo "$OUTPUT" | grep "Private Key:" | awk '{print $3}')
        PUBLIC_KEY=$(echo "$OUTPUT" | grep "Public Key:" | awk '{print $3}')
    fi

    # Fallback if binary not ready yet (first install)
    if [[ -z "$PRIVATE_KEY" ]]; then
        # Use our just-built binary in work dir
         if [[ -f "./whispera-server" ]]; then
            OUTPUT=$(./whispera-server x25519)
            PRIVATE_KEY=$(echo "$OUTPUT" | grep "Private Key:" | awk '{print $3}')
            PUBLIC_KEY=$(echo "$OUTPUT" | grep "Public Key:" | awk '{print $3}')
         else
            # Worst case fallback to openssl (not recommended due to format diffs)
             log_warn "Binary not found for keygen, using openssl (might be incompatible)"
             PRIVATE_KEY=$(openssl rand -hex 32)
         fi
    fi
    
    # Save keys
    echo "$PRIVATE_KEY" > "$CONF_PATH/server.key"
    if [[ -n "$PUBLIC_KEY" ]]; then
        echo "$PUBLIC_KEY" > "$CONF_PATH/server.pub"
    fi
    echo "$UUID" > "$CONF_PATH/uuid"
    
    log_success "Server private key: $CONF_PATH/server.key"
    log_success "Server public key:  $CONF_PATH/server.pub (for clients)"
    log_success "Server UUID:        $CONF_PATH/uuid"
}

generate_connection_key() {
    log_info "Generating connection key for clients..."
    
    local SERVER_IP=$(get_public_ip)
    local PUBLIC_KEY=$(cat "$CONF_PATH/server.pub" 2>/dev/null)
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key" 2>/dev/null)
    
    # Try to derive public key if missing
    if [[ -z "$PUBLIC_KEY" ]] || [[ "$PUBLIC_KEY" == "COMPUTED_AT_RUNTIME" ]]; then
        if [[ -n "$PRIVATE_KEY" ]] && [[ -f "$BIN_PATH/whispera" ]]; then
             PUBLIC_KEY=$($BIN_PATH/whispera pubkey "$PRIVATE_KEY")
             echo "$PUBLIC_KEY" > "$CONF_PATH/server.pub"
        fi
    fi
    
    if [[ -z "$PUBLIC_KEY" ]]; then
        log_err "Could not generate public key"
        return 1
    fi
    
    # Build connection key URL
    # Format: whispera://SERVER:PORT?pub=PUBLIC_KEY&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome
    local CONNECTION_KEY="whispera://${SERVER_IP}:8443?pub=${PUBLIC_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome"
    
    echo "$CONNECTION_KEY" > "$CONF_PATH/connection.key"
    
    log_success "Connection key saved to $CONF_PATH/connection.key"
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${PLAIN}"
    echo -e "${GREEN}║                     CONNECTION KEY FOR CLIENTS                    ║${PLAIN}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════════╣${PLAIN}"
    echo -e "${GREEN}║${PLAIN} Copy this key and paste it in the Whispera client:              ${GREEN}║${PLAIN}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${PLAIN}"
    echo ""
    echo -e "${BLUE}$CONNECTION_KEY${PLAIN}"
    echo ""
}

generate_config() {
    log_info "Generating configuration..."
    
    local UUID=$(cat "$CONF_PATH/uuid")
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key")
    
    cat > "$CONF_PATH/config.yaml" <<EOF
server:
  name: whispera-server
  listen_addr: "0.0.0.0:8443"
  uuid: "$UUID"
  private_key: "$PRIVATE_KEY"
  mtu: 1420
  workers: 8

transport:
  udp:
    enabled: true
    listen_addr: ":8443"
  tcp:
    enabled: false   # Disabled - Phantom handles TCP/TLS on same port
    listen_addr: ":8443"
  websocket:
    enabled: true
    listen_addr: ":8080"

# Phantom Protocol - REALITY-like TLS masquerading
# Handles all TCP connections on server.listen_addr with SNI spoofing
phantom:
  enabled: true
  dest: "yandex.ru:443"              # Real TLS server for mimicry
  private_key: "$PRIVATE_KEY"        # X25519 private key for REALITY auth
  server_names:
    # Banking
    - "sberbank.ru"
    - "tinkoff.ru"
    # Search
    - "yandex.ru"
    - "mail.ru"
    - "rambler.ru"
    - "ya.ru"
    # Video
    - "rutube.ru"
    - "kinopoisk.ru"
    - "kion.ru"
    - "ivi.ru"
    - "pladform.ru"
    - "ntv.ru"
    - "1tv.ru"
    # Social/Other
    - "vk.com"
    - "ok.ru"
    - "gosuslugi.ru"
    - "avito.ru"
    - "wildberries.ru"
    - "ozon.ru"
    - "dzen.ru"
    - "hh.ru"
    - "rbc.ru"
  private_key: "$PRIVATE_KEY"       # Same key as server for simplicity
  short_ids:
    - ""                            # Allow any shortId from client
  max_time_diff: 60000              # 60 seconds tolerance
  fingerprint: "chrome"             # Browser fingerprint to mimic

obfuscation:
  enabled: true
  profile: "http2"
  threat_level: 5

session:
  max_sessions: 10000
  session_timeout: 30m
  cleanup_interval: 1m
  keepalive_interval: 30s

relay:
  max_streams: 10000
  enable_tcp: true
  enable_udp: true
  debug: false

metrics:
  enabled: true
  listen_addr: ":9090"
  path: "/metrics"

logging:
  level: "info"
  format: "text"
  output: "stdout"

api:
  enabled: true
  listen_addr: ":8080"
  auth_token: "$UUID"
  web_root: "$DAT_PATH/web"
  enable_cors: true
EOF
    
    log_success "Config saved to $CONF_PATH/config.yaml"
}

setup_systemd() {
    log_info "Setting up SystemD service..."
    
    cat > /etc/systemd/system/whispera.service <<EOF
[Unit]
Description=Whispera Server
Documentation=https://github.com/Whispera
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
    systemctl enable whispera
    systemctl restart whispera
    
    log_success "SystemD service installed and started"
}

show_cli_help() {
    echo "Usage: whispera [command]"
    echo "Commands:"
    echo "  start       Start Whispera"
    echo "  stop        Stop Whispera"
    echo "  restart     Restart Whispera"
    echo "  status      Check status"
    echo "  log         Tail logs"
    echo "  config      Edit config"
}

install_cli_wrapper() {
    cat > "$BIN_PATH/whispera-cli" <<'EOF'
#!/bin/bash
GREEN='\033[0;32m'
PLAIN='\033[0m'

get_public_ip() {
    local IP=$(curl -s https://api.ipify.org -m 5)
    if [[ -z "$IP" ]]; then
        IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    echo "${IP:-localhost}"
}

show_summary() {
    echo ""
    echo -e "${GREEN}[OK]${PLAIN} Command executed successfully."
    echo -e "  Manage command: ${GREEN}whispera-mgmt${PLAIN}"
    echo -e "  Config file:    ${GREEN}/etc/whispera/config.yaml${PLAIN}"
    local SERVER_IP=$(get_public_ip)
    echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:8080${PLAIN}"
    echo -e "Update dependencies: apt-get update"
}

case $1 in
    start) systemctl start whispera && show_summary ;;
    stop) systemctl stop whispera && echo "Stopped." ;;
    restart) systemctl restart whispera && show_summary ;;
    status) systemctl status whispera ;;
    log) journalctl -u whispera -f ;;
    config) nano /etc/whispera/config.yaml ;;
    info) show_summary ;;
    *) echo "Usage: whispera-mgmt {start|stop|restart|status|log|config|info}" ;;
esac
EOF
    chmod +x "$BIN_PATH/whispera-cli"
    # Create alias if doesn't conflict
    if [[ ! -f "$BIN_PATH/whispera-mgmt" ]]; then
        ln -sf "$BIN_PATH/whispera-cli" "$BIN_PATH/whispera-mgmt"
    fi
    log_success "CLI wrapper installed (whispera-mgmt)"
}

setup_network() {
    log_info "Setting up VPN networking (IP forwarding, NAT, etc.)..."
    
    # Detect WAN interface
    local WAN_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
    if [[ -z "$WAN_IF" ]]; then
        log_warn "Could not auto-detect WAN interface. Please configure manually with:"
        log_warn "  sudo sysctl -w net.ipv4.ip_forward=1"
        log_warn "  sudo iptables -t nat -A POSTROUTING -s 10.0.85.0/24 -o <WAN_IF> -j MASQUERADE"
        return
    fi
    
    log_info "Detected WAN interface: $WAN_IF"
    
    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    
    # Make permanent
    if grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
        sed -i 's/^net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/' /etc/sysctl.conf
    else
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null 2>&1
    
    # Setup NAT
    if command -v iptables &> /dev/null; then
        # MASQUERADE for client subnet
        iptables -t nat -A POSTROUTING -s 10.0.85.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
        
        # FORWARD rules
        iptables -A FORWARD -i tun0 -o "$WAN_IF" -j ACCEPT 2>/dev/null || true
        iptables -A FORWARD -i "$WAN_IF" -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        
        # Save rules (if iptables-persistent available)
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        
        log_success "NAT and FORWARD rules configured for $WAN_IF"
    fi
}

setup_firewall() {
    log_info "Setting up Firewall (UFW)..."
    
    if [[ "$RELEASE" == "ubuntu" ]] || [[ "$RELEASE" == "debian" ]]; then
        # Install UFW if missing
        if ! command -v ufw &>/dev/null; then
            apt-get update >/dev/null
            apt-get install -y ufw >/dev/null 2>&1
        fi
        
        # Allow SSH to prevent lockout
        ufw allow ssh
        ufw allow 22/tcp
        
        # Whispera Ports
        ufw allow 8443/tcp   # Whispera TCP Transport
        ufw allow 8443/udp   # Whispera UDP Transport
        ufw allow 8080/tcp   # Whispera API / Web UI / WebSocket

        # Enable UFW non-interactively
        ufw --force enable
        
        log_success "Firewall configured: 8443 (tcp/udp), 8080 open"
    else
        log_warn "Firewall setup currently supports Ubuntu/Debian only. Please configure your firewall manually."
    fi
}

# --- Main ---

main() {
    check_root
    check_os
    print_logo
    
    install_dependencies
    install_go
    setup_ml_engine
    
    build_whispera
    
    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        generate_keys
        generate_config
    else
        log_info "Config already exists, skipping generation"
    fi
    
    install_cli_wrapper
    setup_network
    setup_firewall
    setup_systemd
    
    # Always generate/show connection key
    generate_connection_key
    
    echo ""
    log_success "Whispera installed successfully!"
    echo -e "  Manage command: ${GREEN}whispera-mgmt${PLAIN}"
    echo -e "  Config file:    ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    local SERVER_IP=$(get_public_ip)
    echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:8080${PLAIN}"
    echo -e "  Connection Key: ${GREEN}$CONF_PATH/connection.key${PLAIN}"
    echo ""
    echo -e "${YELLOW}To view connection key anytime: cat $CONF_PATH/connection.key${PLAIN}"
}

show_connection_key() {
    if [[ -f "$CONF_PATH/connection.key" ]]; then
        echo ""
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${PLAIN}"
        echo -e "${GREEN}║                     CONNECTION KEY FOR CLIENTS                    ║${PLAIN}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${PLAIN}"
        echo ""
        cat "$CONF_PATH/connection.key"
        echo ""
    else
        log_err "Connection key not found. Run ./install.sh keygen first."
    fi
}

regenerate_keys() {
    log_info "Regenerating keys..."
    
    # Backup old keys
    if [[ -f "$CONF_PATH/server.key" ]]; then
        cp "$CONF_PATH/server.key" "$CONF_PATH/server.key.bak"
        cp "$CONF_PATH/server.pub" "$CONF_PATH/server.pub.bak"
    fi
    
    # Generate new keys
    generate_keys
    
    # Update config with new private key
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key")
    sed -i "s/private_key: \".*\"/private_key: \"$PRIVATE_KEY\"/g" "$CONF_PATH/config.yaml"
    
    # Generate new connection key
    generate_connection_key
    
    # Restart service
    if systemctl is-active --quiet whispera; then
        systemctl restart whispera
        log_success "Server restarted with new keys"
    fi
}

# --- Entry Point ---

case "${1:-}" in
    keygen)
        regenerate_keys
        ;;
    showkey|key)
        show_connection_key
        ;;
    update)
        log_info "Updating Whispera..."
        cd "$WORK_DIR" && git pull
        build_whispera
        systemctl restart whispera
        log_success "Update complete"
        ;;
    restart)
        systemctl restart whispera
        log_success "Whispera restarted"
        ;;
    status)
        systemctl status whispera
        ;;
    help|--help|-h)
        echo "Whispera Installer"
        echo ""
        echo "Usage: ./install.sh [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)   Full installation"
        echo "  keygen      Regenerate keys and show new connection key"
        echo "  showkey     Show current connection key"
        echo "  update      Pull latest code and rebuild"
        echo "  restart     Restart Whispera service"
        echo "  status      Show service status"
        echo ""
        ;;
    *)
        main "$@"
        ;;
esac
