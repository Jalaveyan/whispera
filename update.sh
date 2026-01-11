#!/bin/bash
# Whispera Update Script

WORK_DIR="/opt/whispera"
BIN_PATH="/usr/local/bin"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"

# Colors
GREEN='\033[0;32m'
PLAIN='\033[0m'
BLUE='\033[0;34m'

log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }

get_public_ip() {
    local IP=$(curl -s https://api.ipify.org -m 5)
    if [[ -z "$IP" ]]; then
        IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    echo "${IP:-localhost}"
}

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Updating Whispera..."

cd "$WORK_DIR" || exit 1

echo "Building server..."
export PATH=$PATH:/usr/local/go/bin
go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server

if [[ ! -f "whispera-server" ]]; then
    echo "Build failed!"
    exit 1
fi

echo "Stopping service..."
systemctl stop whispera
sleep 2

echo "Updating binary..."
# Backup old binary to avoid "Text file busy"
if [[ -f "$BIN_PATH/whispera" ]]; then
    mv "$BIN_PATH/whispera" "$BIN_PATH/whispera.old"
fi
cp whispera-server "$BIN_PATH/whispera"
chmod +x "$BIN_PATH/whispera"

echo "Updating Web UI..."
if [[ -d "web" ]]; then
    # Clean old web files
    rm -rf "$DAT_PATH/web/*"
    mkdir -p "$DAT_PATH/web"
    cp -r web/* "$DAT_PATH/web/"
fi

echo "Restarting service..."
systemctl start whispera

echo ""
log_success "Whispera updated successfully!"
echo -e "  Manage command: ${GREEN}whispera-mgmt${PLAIN}"
echo -e "  Config file:    ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
SERVER_IP=$(get_public_ip)
echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:8080${PLAIN}"
echo -e "Update dependencies: apt-get update"
