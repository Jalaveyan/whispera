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
            apt-get update >/dev/null
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

generate_keys() {
    log_info "Generating keys..."
    
    # Ensure keygen tool exists or run from source
    local PRIVATE_KEY=""
    local PUBLIC_KEY=""
    local UUID=$(cat /proc/sys/kernel/random/uuid)
    
    # Simple X25519 generation using Go one-liner if keygen not built
    if [[ -f "./cmd/keygen/main.go" ]]; then
        OUTPUT=$(/usr/local/go/bin/go run ./cmd/keygen/main.go -mode x25519 2>/dev/null)
        PRIVATE_KEY=$(echo "$OUTPUT" | grep "priv=" | cut -d= -f2 | xargs)
        PUBLIC_KEY=$(echo "$OUTPUT" | grep "pub=" | cut -d= -f2 | xargs)
    fi
    
    mkdir -p "$CONF_PATH"
    
    # Save keys
    echo "$PRIVATE_KEY" > "$CONF_PATH/server.key"
    echo "$PUBLIC_KEY" > "$CONF_PATH/server.pub"
    echo "$UUID" > "$CONF_PATH/uuid"
    
    log_success "Keys generated in $CONF_PATH"
}

generate_config() {
    log_info "Generating configuration..."
    
    local UUID=$(cat "$CONF_PATH/uuid")
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key")
    
    cat > "$CONF_PATH/config.yaml" <<EOF
server:
  listen_addr: "0.0.0.0:443"
  uuid: "$UUID"
  private_key: "$PRIVATE_KEY"

transport:
  udp:
    enabled: true
    listen_addr: ":51820"
  tcp:
    enabled: true
    listen_addr: ":4443"
  websocket:
    enabled: true
    listen_addr: ":8443"

obfuscation:
  enabled: true
  ml_engine:
    enabled: true
    model_path: "$WORK_DIR/ml_engine/models"

logging:
  level: "info"
  path: "$LOG_PATH/access.log"

api:
  enabled: true
  listen_addr: ":8080"
  auth_token: "$UUID"
  web_root: "$DAT_PATH/web"
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
case $1 in
    start) systemctl start whispera ;;
    stop) systemctl stop whispera ;;
    restart) systemctl restart whispera ;;
    status) systemctl status whispera ;;
    log) journalctl -u whispera -f ;;
    config) nano /etc/whispera/config.yaml ;;
    info)
        echo "=== Whispera Server Info ==="
        echo "UUID:       $(cat /etc/whispera/uuid)"
        echo "Public Key: $(cat /etc/whispera/server.pub)"
        echo "Config:     /etc/whispera/config.yaml"
        ;;
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
    setup_systemd
    
    echo ""
    log_success "Whispera installed successfully!"
    echo -e "  Manage command: ${GREEN}whispera-mgmt${PLAIN}"
    echo -e "  Config file:    ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    local SERVER_IP=$(get_public_ip)
    echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:8080${PLAIN}"
    echo ""
}

main "$@"
