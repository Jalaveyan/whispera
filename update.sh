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

# Copy latest source to work directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$SCRIPT_DIR" != "$WORK_DIR" ]]; then
    log_info "Syncing source code..."
    rsync -a --delete --exclude='.git' "$SCRIPT_DIR/" "$WORK_DIR/" 2>/dev/null || cp -r "$SCRIPT_DIR"/* "$WORK_DIR/"
fi

cd "$WORK_DIR" || exit 1

echo "Building server..."
export PATH=$PATH:/usr/local/go/bin
rm -f whispera-server
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

# Helper to get key
get_key_from_config() {
    grep "$1:" "$CONF_PATH/config.yaml" 2>/dev/null | head -n1 | awk -F': ' '{print $2}' | tr -d '"' | tr -d " " | tr -d '\r'
}

echo "Updating configuration..."

# Generate keys (always fresh pair to ensure match)
log_info "Generating keys..."
OUTPUT=$(./whispera-server x25519 2>/dev/null)
PRIVATE_KEY=$(echo "$OUTPUT" | grep "Private Key:" | awk '{print $3}')
PUBLIC_KEY=$(echo "$OUTPUT" | grep "Public Key:" | awk '{print $3}')

# Regenerate config (Updating to latest structure)
cat > "$CONF_PATH/config.yaml" << EOF
server:
  name: whispera-server
  listen_addr: "0.0.0.0:8443"
  mtu: 1420
  workers: 8

transport:
  udp:
    enabled: true
    listen_addr: ":8443"
    max_packet_size: 65535
  tcp:
    enabled: true
    listen_addr: ":8443"
  websocket:
    enabled: true
    listen_addr: ":8080"
    path: "/ws"

relay:
  max_streams: 10000
  enable_tcp: true
  enable_udp: true
  # upstream_proxy: "socks5://127.0.0.1:40000" # Cloudflare WARP

phantom:
  enabled: true
  dest: "cloudflare.com:443"
  server_names: []
  private_key: "$PRIVATE_KEY"
  max_time_diff: 60000
  short_ids:
    - ""
  fingerprint: "chrome"

metrics:
  enabled: true
  listen_addr: ":9090"
  path: "/metrics"

api:
  enabled: true
  listen_addr: ":8080"
EOF

echo "Restarting service..."
systemctl restart whispera

SERVER_IP=$(get_public_ip)

echo ""
log_success "Whispera updated successfully!"
echo -e "  Config file:    ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:8080${PLAIN}"

if [[ -n "$PUBLIC_KEY" ]]; then
    CONN_URL="whispera://${SERVER_IP}:8443?pub=${PUBLIC_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome"
    echo ""
    echo -e "${GREEN}================================================================${PLAIN}"
    echo -e "${GREEN} CLIENT CONNECTION KEY                                          ${PLAIN}"
    echo -e "${GREEN}================================================================${PLAIN}"
    echo -e "${BLUE}${CONN_URL}${PLAIN}"
    echo -e "${GREEN}================================================================${PLAIN}"
else
    echo ""
    echo -e "${YELLOW}Public key not found. Run: whispera x25519${PLAIN}"
fi
echo ""

