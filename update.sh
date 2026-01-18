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

# Sync source code if running from different directory
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
    echo "Build failed! No binary created."
    exit 1
fi

echo "Stopping service..."
systemctl stop whispera
sleep 2

echo "Updating binary..."
if [[ -f "$BIN_PATH/whispera" ]]; then
    mv "$BIN_PATH/whispera" "$BIN_PATH/whispera.old"
fi
cp whispera-server "$BIN_PATH/whispera"
chmod +x "$BIN_PATH/whispera"

echo "Updating Web UI..."
if [[ -d "web" ]]; then
    rm -rf "$DAT_PATH/web/*"
    mkdir -p "$DAT_PATH/web"
    cp -r web/* "$DAT_PATH/web/"
fi

echo "Updating configuration..."

# Read existing private key
PRIVATE_KEY=$(grep "private_key:" "$CONF_PATH/config.yaml" 2>/dev/null | awk '{print $2}' | tr -d '"' | head -n1)

# If no key, generate new one
if [[ -z "$PRIVATE_KEY" ]] || [[ "$PRIVATE_KEY" == '""' ]]; then
    log_info "Generating new keys..."
    OUTPUT=$(./whispera-server x25519 2>/dev/null)
    PRIVATE_KEY=$(echo "$OUTPUT" | grep "Private Key:" | awk '{print $3}')
fi

# Regenerate config
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
EOF

echo "Restarting service..."
systemctl start whispera

# Get public key
PUBLIC_KEY=$($BIN_PATH/whispera pubkey "$PRIVATE_KEY" 2>/dev/null)
SERVER_IP=$(get_public_ip)

echo ""
log_success "Whispera updated successfully!"
echo -e "  Config file:    ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
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
