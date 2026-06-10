#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

MAIN_SERVER=""
REG_TOKEN=""
BRIDGE_TYPE="operator"
PROVIDER="unknown"
REGION="auto"
LISTEN_PORT="443"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/whispera"

while [[ $# -gt 0 ]]; do
    case $1 in
        --type)
            BRIDGE_TYPE="$2"
            shift 2
            ;;
        --provider)
            PROVIDER="$2"
            shift 2
            ;;
        --port)
            LISTEN_PORT="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        -*)
            log_error "Unknown option: $1"
            ;;
        *)
            if [ -z "$MAIN_SERVER" ]; then
                MAIN_SERVER="$1"
            elif [ -z "$REG_TOKEN" ]; then
                REG_TOKEN="$1"
            fi
            shift
            ;;
    esac
done

if [ -z "$MAIN_SERVER" ]; then
    log_info "No server specified, trying DNS discovery..."
    
    if command -v dig &> /dev/null; then
        for domain in "whispera.local" "vpn.local" "bridge.local"; do
            SRV_RESULT=$(dig +short _whispera._tcp.$domain SRV 2>/dev/null | head -1)
            if [ -n "$SRV_RESULT" ]; then
                PORT=$(echo $SRV_RESULT | awk '{print $3}')
                HOST=$(echo $SRV_RESULT | awk '{print $4}' | sed 's/\.$//')
                MAIN_SERVER="$HOST:$PORT"
                log_info "Discovered via DNS: $MAIN_SERVER"
                break
            fi
        done
    fi
    
    if [ -z "$MAIN_SERVER" ] && command -v dig &> /dev/null; then
        TXT_RESULT=$(dig +short whispera-server.local TXT 2>/dev/null | tr -d '"')
        if [ -n "$TXT_RESULT" ]; then
            MAIN_SERVER="$TXT_RESULT"
            log_info "Discovered via TXT: $MAIN_SERVER"
        fi
    fi
    
    if [ -z "$MAIN_SERVER" ]; then
        log_error "Usage: $0 <MAIN_SERVER_ADDRESS:PORT> <REGISTRATION_TOKEN> [OPTIONS]
        
Or configure DNS SRV record:
  _whispera._tcp.yourdomain.com SRV 0 0 443 vpn.yourdomain.com"
    fi
fi

if [ -z "$REG_TOKEN" ]; then
    log_error "Registration token is required. Get it from Web Panel → Bridges → Get Token"
fi

log_info "Installing Whispera Bridge..."
log_info "Main Server: $MAIN_SERVER"
log_info "Bridge Type: $BRIDGE_TYPE"
log_info "Provider: $PROVIDER"
log_info "Listen Port: $LISTEN_PORT"

if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo)"
fi

ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *)       log_error "Unsupported architecture: $ARCH" ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')

mkdir -p "$CONFIG_DIR"
mkdir -p "$INSTALL_DIR"

log_info "Downloading Whispera Bridge binary..."
DIRECT_URL="https://github.com/Jalaveyan/Whispera/releases/latest/download/whispera-server-linux-${ARCH}.tar.gz"
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

BIN_OK=false
if curl -fsSL --retry 3 --retry-delay 2 -o "$TMP_DIR/whispera.tar.gz" "$DIRECT_URL" 2>/dev/null; then
    if tar -xzf "$TMP_DIR/whispera.tar.gz" -C "$TMP_DIR" 2>/dev/null && [ -f "$TMP_DIR/whispera-server" ]; then
        cp "$TMP_DIR/whispera-server" "$INSTALL_DIR/whispera-bridge"
        BIN_OK=true
    fi
fi

if [ "$BIN_OK" = false ]; then
    log_warn "GitHub release download failed, trying API..."
    API_JSON=$(curl -s https://api.github.com/repos/Jalaveyan/Whispera/releases/latest 2>/dev/null)
    API_URL=$(echo "$API_JSON" | grep "browser_download_url" | grep "whispera-server-linux-${ARCH}.tar.gz" | head -1 | cut -d'"' -f4)
    if [ -n "$API_URL" ]; then
        if curl -fsSL -o "$TMP_DIR/whispera.tar.gz" "$API_URL" 2>/dev/null; then
            if tar -xzf "$TMP_DIR/whispera.tar.gz" -C "$TMP_DIR" 2>/dev/null && [ -f "$TMP_DIR/whispera-server" ]; then
                cp "$TMP_DIR/whispera-server" "$INSTALL_DIR/whispera-bridge"
                BIN_OK=true
            fi
        fi
    fi
fi

if [ "$BIN_OK" = false ]; then
    if [ -f "./whispera-server" ]; then
        cp ./whispera-server "$INSTALL_DIR/whispera-bridge"
        BIN_OK=true
        log_warn "Using local binary"
    else
        log_error "Could not download binary and no local binary found"
    fi
fi

chmod +x "$INSTALL_DIR/whispera-bridge"

log_info "Generating keys..."
log_info "Creating configuration..."
cat > "$CONFIG_DIR/bridge.yaml" <<EOF

relay_mode: bridge
upstream_server: "${MAIN_SERVER}"

server:
  listen_addr: ":${LISTEN_PORT}"

bridge:
  auto_register: true
  type: ${BRIDGE_TYPE}
  provider: ${PROVIDER}
  registration_token: "${REG_TOKEN}"

logging:
  level: info
EOF

log_info "Creating systemd service..."
cat > /etc/systemd/system/whispera-bridge.service <<EOF
[Unit]
Description=Whispera Bridge
Documentation=https://github.com/Jalaveyan/Whispera
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/whispera-bridge -c ${CONFIG_DIR}/bridge.yaml
Restart=always
RestartSec=5
LimitNOFILE=infinity

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${CONFIG_DIR} /var/log/whispera
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

log_info "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow ${LISTEN_PORT}/tcp
    ufw limit 22/tcp
    ufw default deny incoming
    ufw default allow outgoing
    ufw --force enable
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=${LISTEN_PORT}/tcp
    firewall-cmd --permanent --add-rich-rule='rule family="ipv4" service name="ssh" limit value="4/m" accept'
    firewall-cmd --reload
fi

log_info "Setting up fail2ban..."
if ! command -v fail2ban-server &> /dev/null; then
    apt-get install -y fail2ban 2>/dev/null || yum install -y fail2ban 2>/dev/null || true
fi
if command -v fail2ban-server &> /dev/null; then
    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/whispera-bridge.conf <<'FILTER'
[Definition]
failregex = ^.*authentication failed from <HOST>.*$
            ^.*invalid token from <HOST>.*$
            ^.*rejected connection from <HOST>.*$
ignoreregex =
FILTER

    cat > /etc/fail2ban/jail.d/whispera-bridge.conf <<JAIL
[DEFAULT]
bantime  = 24h
findtime = 2m
maxretry = 3
backend  = systemd

[sshd]
enabled = true
maxretry = 3

[whispera-bridge]
enabled  = true
port     = ${LISTEN_PORT}
filter   = whispera-bridge
logpath  = /var/log/whispera/bridge.log
maxretry = 5
bantime  = 12h
findtime = 5m
JAIL

    systemctl enable fail2ban
    systemctl restart fail2ban
fi

log_info "Starting Whispera Bridge..."
systemctl daemon-reload
systemctl enable whispera-bridge
systemctl start whispera-bridge

sleep 3

PUBLIC_IP=$(curl -s --connect-timeout 5 https://2ip.ru/api/self 2>/dev/null | grep -oE '"ip":"[^"]*"' | cut -d'"' -f4)
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(curl -s --connect-timeout 5 https://2ip.io 2>/dev/null | tr -d '[:space:]')
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(curl -s --connect-timeout 5 https://api.ipify.org 2>/dev/null)
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=""

if [ "$REGION" = "auto" ] || [ -z "$REGION" ]; then
    REGION=$(curl -s --connect-timeout 5 "https://ipinfo.io/${PUBLIC_IP}/country" 2>/dev/null | tr -d '"' | head -1)
    [ -z "$REGION" ] && REGION="unknown"
fi

if systemctl is-active --quiet whispera-bridge; then
    log_info "✓ Whispera Bridge is running!"

    BRIDGE_ADDR="${PUBLIC_IP}:${LISTEN_PORT}"

    if [ -n "$PUBLIC_IP" ] && [ -n "$MAIN_SERVER" ] && [ -n "$REG_TOKEN" ]; then
        log_info "Registering bridge with main server..."
        REG_RESPONSE=$(curl -s -k --connect-timeout 10 \
            -X POST "https://${MAIN_SERVER}/api/bridge-register" \
            -H "Content-Type: application/json" \
            -d "{\"address\":\"${BRIDGE_ADDR}\",\"token\":\"${REG_TOKEN}\",\"provider\":\"${PROVIDER}\",\"region\":\"${REGION}\",\"type\":\"${BRIDGE_TYPE}\"}" \
            2>/dev/null)

        BRIDGE_ID=$(echo "$REG_RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)

        if echo "$REG_RESPONSE" | grep -q '"success":true' && [ -n "$BRIDGE_ID" ]; then
            log_info "✓ Bridge registered (ID: ${BRIDGE_ID})"
            mkdir -p "$CONFIG_DIR"
            echo "$BRIDGE_ID"  > "$CONFIG_DIR/bridge-id"
            echo "$REG_TOKEN"  > "$CONFIG_DIR/bridge-token"
            echo "$MAIN_SERVER" > "$CONFIG_DIR/bridge-server"
            chmod 600 "$CONFIG_DIR/bridge-id" "$CONFIG_DIR/bridge-token" "$CONFIG_DIR/bridge-server"

            cat > /usr/local/bin/whispera-bridge-heartbeat <<'HBEOF'
#!/bin/bash
BRIDGE_ID=$(cat /etc/whispera/bridge-id 2>/dev/null)
TOKEN=$(cat /etc/whispera/bridge-token 2>/dev/null)
SERVER=$(cat /etc/whispera/bridge-server 2>/dev/null)
[ -z "$BRIDGE_ID" ] || [ -z "$TOKEN" ] || [ -z "$SERVER" ] && exit 0

LOAD=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo "0")
USERS=$(who 2>/dev/null | wc -l)
VERSION=$(/usr/local/bin/whispera-bridge --version 2>/dev/null | head -1 || echo "unknown")

RESPONSE=$(curl -s -k --connect-timeout 10 \
    -X POST "https://${SERVER}/api/bridge-heartbeat" \
    -H "Content-Type: application/json" \
    -d "{\"id\":\"${BRIDGE_ID}\",\"token\":\"${TOKEN}\",\"load\":${LOAD},\"cur_users\":${USERS},\"version\":\"${VERSION}\"}" \
    2>/dev/null)

UPDATE_URL=$(echo "$RESPONSE" | grep -o '"update_url":"[^"]*"' | cut -d'"' -f4)
if [ -n "$UPDATE_URL" ]; then
    ARCH=$(uname -m); [ "$ARCH" = "aarch64" ] && ARCH="arm64" || ARCH="amd64"
    TMP=$(mktemp -d)
    if curl -fsSL --retry 3 -o "$TMP/whispera.tar.gz" "$UPDATE_URL" 2>/dev/null; then
        if tar -xzf "$TMP/whispera.tar.gz" -C "$TMP" 2>/dev/null && [ -f "$TMP/whispera-server" ]; then
            systemctl stop whispera-bridge 2>/dev/null || true
            cp "$TMP/whispera-server" /usr/local/bin/whispera-bridge
            chmod +x /usr/local/bin/whispera-bridge
            systemctl start whispera-bridge
            echo "[$(date)] Updated to new version" >> /var/log/whispera/bridge-update.log
        fi
    fi
    rm -rf "$TMP"
fi

KEYS=$(echo "$RESPONSE" | grep -o '"authorized_keys":\[[^]]*\]' | grep -oP '"[^"]{20,}"' | tr -d '"')
if [ -n "$KEYS" ]; then
    mkdir -p /root/.ssh
    echo "$KEYS" > /root/.ssh/authorized_keys
    chmod 600 /root/.ssh/authorized_keys
fi
HBEOF
            chmod +x /usr/local/bin/whispera-bridge-heartbeat

            mkdir -p /var/log/whispera
            if ! crontab -l 2>/dev/null | grep -q "whispera-bridge-heartbeat"; then
                (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/whispera-bridge-heartbeat >> /var/log/whispera/heartbeat.log 2>&1") | crontab -
            fi
            log_info "Heartbeat cron installed (every 5 min)"
        else
            log_warn "Registration response: ${REG_RESPONSE:-no response}"
            log_warn "Bridge will retry registration on next heartbeat"
        fi
    fi

    echo ""
    echo "========================================"
    echo "  Bridge Installation Complete!"
    echo "========================================"
    echo ""
    echo "  Bridge Address: ${BRIDGE_ADDR}"
    echo "  Main Server:    ${MAIN_SERVER}"
    echo "  Region:         ${REGION}"
    echo "  Provider:       ${PROVIDER}"
    echo "  Bridge Type:    ${BRIDGE_TYPE}"
    echo ""
    echo "  Config:    ${CONFIG_DIR}/bridge.yaml"
    echo "  Bridge ID: ${BRIDGE_ID:-not registered}"
    echo "  Logs:      journalctl -u whispera-bridge -f"
    echo "========================================"
else
    log_error "Bridge failed to start. Check logs: journalctl -u whispera-bridge"
fi
