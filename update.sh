#!/bin/bash

set -e

WORK_DIR="/opt/whispera"
BIN_PATH="/usr/local/bin"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"
BRANCH="main"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'

log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${PLAIN} $1"; }
log_err() { echo -e "${RED}[ERR]${PLAIN} $1"; }

refresh_config() {
    local cfg="${1:-$CONF_PATH/config.yaml}"
    if [[ ! -f "$cfg" ]]; then return; fi
    if command -v whispera &>/dev/null; then
        whispera update-checksum "$cfg" 2>/dev/null && log_info "Config checksum updated" || true
    fi
}

_enable_tcp8443_in_config() {
    local cfg="${CONF_PATH}/config.yaml"
    [[ -f "$cfg" ]] || return
    # Already on :8443 and tcp block is enabled — nothing to do
    if awk '/^  tcp:/{f=1} f && /listen_addr:.*:8443/{a=1} f && /enabled: true/{b=1} /^  [a-z]/ && !/^  tcp:/{f=0} END{exit !(a&&b)}' "$cfg" 2>/dev/null; then
        return
    fi
    local changed=0
    # Enable TCP transport and point it to :8443
    if grep -q 'listen_addr: ":8443"' "$cfg"; then
        # Replace tcp block: enabled: false + :8443 → enabled: true + :443
        # We use awk to only change the tcp sub-block
        awk '
            /^  tcp:/ { in_tcp=1 }
            in_tcp && /listen_addr:/ { sub(/":[0-9]+"/, "\":8443\""); changed=1 }
            in_tcp && /enabled: false/ { sub(/false/, "true"); changed=1 }
            /^  [a-z]/ && !/^  tcp:/ { in_tcp=0 }
            { print }
        ' "$cfg" > "${cfg}.tmp" && mv "${cfg}.tmp" "$cfg"
        changed=1
    fi
    if [[ $changed -eq 1 ]]; then
        refresh_config "$cfg"
        log_success "TCP transport enabled on :8443 in config.yaml"
    fi
}

_enable_chameleon_in_config() {
    local cfg="${CONF_PATH}/config.yaml"
    [[ -f "$cfg" ]] || return

    # Detect existing TLS cert from nginx config (used in both branches).
    # Skip commented-out lines (otherwise awk picks the directive name as $2
    # and we end up writing tls_cert: "ssl_certificate" into config.yaml).
    local cert="" key=""
    cert=$(grep -hE '^[[:space:]]*ssl_certificate[[:space:]]' /etc/nginx/sites-available/* 2>/dev/null | grep -v "ssl_certificate_key" | awk '{print $2}' | tr -d ';' | head -1)
    key=$(grep -hE '^[[:space:]]*ssl_certificate_key[[:space:]]' /etc/nginx/sites-available/* 2>/dev/null | awk '{print $2}' | tr -d ';' | head -1)

    if grep -q "^chameleon:" "$cfg"; then
        # Already present — ensure enabled: true
        sed -i '/^chameleon:/,/^[^ ]/{s/enabled: false/enabled: true/}' "$cfg"
        # Skip cert injection entirely if the chameleon block already has a
        # non-empty `domain:` — that means autocert (Let's Encrypt) is in use
        # and we must NOT overwrite tls_cert with an nginx path.
        local cur_domain
        cur_domain=$(awk '/^chameleon:/{f=1} f && /^[[:space:]]+domain:/{print $2; exit}' "$cfg" | tr -d '"')
        if [[ -n "$cur_domain" ]]; then
            refresh_config "$cfg"
            log_success "Chameleon enabled in config.yaml (autocert domain=$cur_domain, tls_cert untouched)"
            return
        fi
        # If tls_cert is empty ("" or absent) and we have an nginx cert, fill it in
        local cur_cert
        cur_cert=$(awk '/^chameleon:/{f=1} f && /tls_cert:/{print $2; exit}' "$cfg" | tr -d '"')
        if [[ -z "$cur_cert" && -n "$cert" ]]; then
            # Replace tls_cert: "" and tls_key: "" inside the chameleon section
            python3 - "$cfg" "$cert" "$key" <<'PYEOF'
import sys, re
path, cert, key = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path) as f:
    text = f.read()
# Only patch inside the chameleon: block (lines until next top-level key)
def patch_block(m):
    blk = m.group(0)
    blk = re.sub(r'tls_cert:\s*""', f'tls_cert: "{cert}"', blk)
    blk = re.sub(r'tls_key:\s*""',  f'tls_key: "{key}"',   blk)
    return blk
text = re.sub(r'^chameleon:.*?(?=\n\S|\Z)', patch_block, text, flags=re.S|re.M)
with open(path, 'w') as f:
    f.write(text)
PYEOF
            log_info "Chameleon: injected TLS cert from nginx into existing config"
        fi
    else
        printf '\nchameleon:\n  enabled: true\n  listen_addr: ":8443"\n  tls_cert: "%s"\n  tls_key: "%s"\n  domain: ""\n  acme_dir: "/var/lib/whispera/acme"\n' \
            "${cert}" "${key}" >> "$cfg"
    fi
    if command -v ufw &>/dev/null; then
        ufw allow 8443/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=8443/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    refresh_config "$cfg"
    log_success "Chameleon enabled in config.yaml"
}

_disable_phantom_in_config() {
    local cfg="${CONF_PATH}/config.yaml"
    [[ -f "$cfg" ]] || return
    grep -q "^phantom:" "$cfg" || return
    sed -i '/^phantom:/,/^[^ ]/{s/enabled: true/enabled: false/}' "$cfg"
    refresh_config "$cfg"
    log_success "Phantom disabled in config.yaml"
}

_enable_ml_in_config() {
    local cfg="${CONF_PATH}/config.yaml"
    [[ -f "$cfg" ]] || return
    if grep -q "^ml:" "$cfg"; then
        sed -i '/^ml:/,/^[^ ]/{s/enabled: false/enabled: true/}' "$cfg"
    else
        printf '\nml:\n  enabled: true\n  server_url: "https://127.0.0.1:8000"\n  token_file: ""\n' >> "$cfg"
    fi
    refresh_config "$cfg"
    log_success "ML enabled in config.yaml"
}

get_public_ip() {
    local IP
    IP=$(curl -s https://2ip.ru/api/self -m 5 2>/dev/null | grep -oE '"ip":"[^"]*"' | cut -d'"' -f4)
    if [[ -z "$IP" ]]; then
        IP=$(curl -s https://2ip.io -m 5 2>/dev/null | tr -d '[:space:]')
    fi
    if [[ -z "$IP" ]]; then
        IP=$(curl -s https://api.ipify.org -m 5 2>/dev/null)
    fi
    if [[ -z "$IP" ]]; then
        IP=$(ip addr show | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}' | cut -d/ -f1 | head -n1)
    fi
    echo "${IP:-localhost}"
}

gen_password() {
    local len=${1:-30}
    if command -v openssl &>/dev/null; then
        openssl rand -base64 40 | tr -dc 'A-Za-z0-9' | head -c "$len"
    else
        head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c "$len"
    fi
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


restore() {
    log_warn "Update failed or service unstable. Rolling back..."

    if [[ -f "$BIN_PATH/whispera.bak" ]]; then
        log_info "Restoring server binary..."
        cp -f "$BIN_PATH/whispera.bak" "$BIN_PATH/whispera"
        chmod +x "$BIN_PATH/whispera"
    fi

    if [[ -d "$DAT_PATH/panel.bak" ]]; then
        log_info "Restoring panel..."
        rm -rf "$DAT_PATH/panel"
        cp -r "$DAT_PATH/panel.bak" "$DAT_PATH/panel"
    fi

    systemctl daemon-reload
    if systemctl restart whispera 2>/dev/null; then
        log_success "Rollback complete. System restored to previous state."
    else
        log_warn "Rollback restart also failed. Trying start..."
        systemctl start whispera 2>/dev/null || log_warn "Service could not be started. Run: systemctl start whispera"
    fi
    systemctl restart whispera-panel 2>/dev/null || true

    exit 1
}

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
    
    if ! grep -q "tcp_congestion_control" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null; then
        cat >> /etc/sysctl.conf <<EOF

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
    fi

    sysctl -p >/dev/null 2>&1

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_success "BBR enabled"
    else
        log_warn "BBR enable failed"
    fi
}

setup_warp() {
    log_info "Setting up Cloudflare WARP..."
    
    if ! command -v warp-cli &>/dev/null; then
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
        if ! command -v warp-cli &>/dev/null; then
            log_warn "WARP installation failed"
            return
        fi
    fi

    systemctl enable warp-svc --now 2>/dev/null || true
    sleep 2

    if ! warp-cli status 2>/dev/null | grep -q "Connected"; then
        if warp-cli registration new &>/dev/null; then
            warp-cli mode proxy 2>/dev/null || true
        else
            warp-cli --accept-tos register 2>/dev/null || true
            warp-cli set-mode proxy 2>/dev/null || true
        fi
        warp-cli connect 2>/dev/null || true
        for i in $(seq 1 5); do
            sleep 3
            warp-cli status 2>/dev/null | grep -q "Connected" && break
            log_info "Waiting for WARP... ($((i*3))s)"
        done
    fi

    if warp-cli status 2>/dev/null | grep -q "Connected"; then
        log_success "WARP connected (SOCKS5 proxy on 127.0.0.1:40000)"

        if [[ -f "$CONF_PATH/config.yaml" ]]; then
            log_info "Auto-configuring Whispera to use WARP..."

            if grep -q "^relay:" "$CONF_PATH/config.yaml"; then
                if grep -q "upstream_proxy:" "$CONF_PATH/config.yaml"; then
                    sed -i 's|upstream_proxy:.*|upstream_proxy: "socks5://127.0.0.1:40000"|' "$CONF_PATH/config.yaml"
                else
                    sed -i '/^relay:/a \ \ upstream_proxy: "socks5://127.0.0.1:40000"' "$CONF_PATH/config.yaml"
                fi
            else
                printf '\nrelay:\n  upstream_proxy: "socks5://127.0.0.1:40000"\n' >> "$CONF_PATH/config.yaml"
            fi

            log_success "Configuration updated."
            refresh_config
            systemctl restart whispera 2>/dev/null || true
        else
            log_warn "Config file not found at $CONF_PATH/config.yaml - please configure manually"
        fi
    else
        log_warn "WARP connection failed. Run 'warp-cli connect' manually."
    fi
}

setup_fail2ban() {
    log_info "Setting up Fail2ban..."

    if [[ -f /etc/fail2ban/jail.local ]] && systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_success "Fail2ban already installed and configured"
        log_info "Config: /etc/fail2ban/jail.local"
        return
    fi

    case $RELEASE in
        ubuntu|debian) apt-get install -y fail2ban >/dev/null 2>&1 ;;
        centos|fedora|almalinux|rocky) yum install -y fail2ban >/dev/null 2>&1 ;;
        *) log_warn "Fail2ban not supported"; return ;;
    esac

    if ! command -v fail2ban-server &>/dev/null; then
        log_warn "Fail2ban installation failed"
        return
    fi

    mkdir -p /etc/fail2ban

    cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 24h
findtime = 2m
maxretry = 3
backend  = systemd

[sshd]
enabled = true

[whispera]
enabled   = true
backend   = systemd
journalmatch = _SYSTEMD_UNIT=whispera.service
maxretry  = 5
findtime  = 1m
bantime   = 6h
filter    = whispera

[whispera-panel]
enabled   = true
backend   = systemd
journalmatch = _SYSTEMD_UNIT=whispera-panel.service
maxretry  = 10
findtime  = 1m
bantime   = 1h
filter    = whispera-panel

[nginx-auth]
enabled  = true
backend  = auto
filter   = nginx-auth
logpath  = /var/log/nginx/access.log
maxretry = 5
findtime = 1m
bantime  = 1h
EOF

    mkdir -p /etc/fail2ban/filter.d
    cat > /etc/fail2ban/filter.d/whispera.conf <<'EOF'
[Definition]
failregex = .*handshake failed.*<HOST>
            .*auth failed.*<HOST>
            .*invalid key.*<HOST>
            .*connection rejected.*<HOST>
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/whispera-panel.conf <<'EOF'
[Definition]
failregex = .*401.*<HOST>
            .*403.*<HOST>
            .*login failed.*<HOST>
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/nginx-auth.conf <<'EOF'
[Definition]
failregex = ^<HOST> - \S+ \[.*\] ".*" 401 .*$
ignoreregex =
EOF

    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    sleep 2

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_success "Fail2ban installed and running (sshd + whispera + panel jails)"
        log_info "Config: /etc/fail2ban/jail.local"
    else
        log_warn "Fail2ban installed but not running. Check: journalctl -u fail2ban"
    fi
}

setup_redis() {
    log_info "Setting up Redis..."
    
    if command -v redis-server &>/dev/null; then
        if systemctl is-active --quiet redis-server 2>/dev/null || systemctl is-active --quiet redis 2>/dev/null; then
            log_success "Redis already installed and running"
            return
        fi
    fi
    
    case $RELEASE in
        ubuntu|debian)
            apt-get update >/dev/null 2>&1
            apt-get install -y redis-server >/dev/null 2>&1
            ;;
        centos|fedora|almalinux|rocky)
            yum install -y redis >/dev/null 2>&1
            ;;
        *) log_warn "Redis not supported on $RELEASE"; return ;;
    esac
    
    if ! command -v redis-server &>/dev/null; then
        log_warn "Redis installation failed"
        return
    fi
    
    local REDIS_CONF="/etc/redis/redis.conf"
    [[ -f "/etc/redis.conf" ]] && REDIS_CONF="/etc/redis.conf"
    
    if [[ -f "$REDIS_CONF" ]]; then
        sed -i 's/^bind .*/bind 127.0.0.1/' "$REDIS_CONF" 2>/dev/null || true
        grep -q "^maxmemory " "$REDIS_CONF" || echo "maxmemory 256mb" >> "$REDIS_CONF"
        grep -q "^maxmemory-policy " "$REDIS_CONF" || echo "maxmemory-policy allkeys-lru" >> "$REDIS_CONF"
    fi
    
    systemctl enable redis-server 2>/dev/null || systemctl enable redis 2>/dev/null
    systemctl restart redis-server 2>/dev/null || systemctl restart redis 2>/dev/null
    
    if redis-cli ping 2>/dev/null | grep -q "PONG"; then
        log_success "Redis installed on 127.0.0.1:6379"
        echo ""
        log_info "Add to config.yaml: cache.redis_url: \"redis://127.0.0.1:6379\""
    else
        log_warn "Redis installed but not responding"
    fi
}

setup_postgres() {
    log_info "Setting up PostgreSQL..."
    
    if command -v psql &>/dev/null && systemctl is-active --quiet postgresql 2>/dev/null; then
        if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
            log_success "PostgreSQL already installed with whispera database"
            return
        fi
    fi
    
    case $RELEASE in
        ubuntu|debian)
            apt-get update >/dev/null 2>&1
            apt-get install -y postgresql postgresql-contrib >/dev/null 2>&1
            ;;
        centos|fedora|almalinux|rocky)
            yum install -y postgresql-server postgresql >/dev/null 2>&1
            postgresql-setup --initdb 2>/dev/null || true
            ;;
        *) log_warn "PostgreSQL not supported on $RELEASE"; return ;;
    esac
    
    if ! command -v psql &>/dev/null; then
        log_warn "PostgreSQL installation failed"
        return
    fi
    
    systemctl enable postgresql >/dev/null 2>&1
    systemctl start postgresql >/dev/null 2>&1
    sleep 2
    
    local PG_PASS=$(gen_password 30)
    
    sudo -u postgres psql <<EOF >/dev/null 2>&1
CREATE USER whispera WITH PASSWORD '$PG_PASS';
CREATE DATABASE whispera OWNER whispera;
GRANT ALL PRIVILEGES ON DATABASE whispera TO whispera;
EOF
    
    mkdir -p "$CONF_PATH"
    cat > "$CONF_PATH/postgres.env" <<EOF
POSTGRES_USER=whispera
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=whispera
POSTGRES_URL=postgresql://whispera:$PG_PASS@localhost/whispera
EOF
    chmod 600 "$CONF_PATH/postgres.env"
    
    if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
        log_success "PostgreSQL installed"
        log_info "Credentials: /etc/whispera/postgres.env"
    else
        log_warn "PostgreSQL database creation failed"
    fi
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
    grep -q "vm.swappiness" /etc/sysctl.conf || echo "vm.swappiness=10" >> /etc/sysctl.conf
    log_success "Swap 2GB created"
}

setup_sysctl() {
    log_info "Optimizing system..."

    cat > /etc/sysctl.d/99-whispera.conf <<'EOF'
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_fastopen = 3
fs.file-max = 1000000
EOF

    sysctl --system >/dev/null 2>&1
    log_success "System optimized"
}

setup_autoupdate() {
    log_info "Setting up auto-update..."
    
    cat > /etc/cron.daily/whispera-update <<'CRONEOF'
WORK_DIR="__WORK_DIR__"
BIN_PATH="__BIN_PATH__"
BRANCH="__BRANCH__"
LOG="/var/log/whispera-update.log"
exec >> "$LOG" 2>&1
echo "=== $(date) ==="

cd "$WORK_DIR" || exit 1
git config --global --add safe.directory "$WORK_DIR" 2>/dev/null || true

BEFORE=$(git rev-parse HEAD)
git pull origin "$BRANCH" --quiet
AFTER=$(git rev-parse HEAD)

if [[ "$BEFORE" == "$AFTER" ]]; then
    echo "No changes."
    exit 0
fi

CHANGED=$(git diff --name-only "$BEFORE" "$AFTER")
echo "Changed files:"
echo "$CHANGED"

GO_CHANGED=$(echo "$CHANGED" | grep -E '\.(go)$|^go\.(mod|sum)$' || true)
ML_PY_CHANGED=$(echo "$CHANGED" | grep -E '^(internal/obfuscation/ml|ml_engine)/.*\.py$' || true)
PANEL_CHANGED=$(echo "$CHANGED" | grep -E '^panel/' || true)

if [[ -n "$ML_PY_CHANGED" ]]; then
    echo "ML files updated — restarting whispera (ML is built-in)"
    systemctl restart whispera 2>/dev/null && echo "whispera restarted" || echo "whispera not running"
fi

if [[ -n "$PANEL_CHANGED" ]]; then
    echo "Panel files updated — restarting whispera-panel"
    systemctl restart whispera-panel 2>/dev/null && echo "whispera-panel restarted" || true
fi

if [[ -n "$GO_CHANGED" ]]; then
    echo "Go files updated — rebuilding whispera-server"
    export PATH=$PATH:/usr/local/go/bin
    go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server 2>/dev/null
    if [[ -f whispera-server ]]; then
        cp whispera-server "$BIN_PATH/whispera"
        systemctl restart whispera
        echo "whispera-server rebuilt and restarted"
    else
        echo "Build failed — keeping old binary"
    fi
fi
CRONEOF

    sed -i \
        -e "s|__WORK_DIR__|$WORK_DIR|g" \
        -e "s|__BIN_PATH__|$BIN_PATH|g" \
        -e "s|__BRANCH__|$BRANCH|g" \
        /etc/cron.daily/whispera-update
    chmod +x /etc/cron.daily/whispera-update
    log_success "Auto-update enabled (daily, smart: Go→rebuild, ML-py→restart only)"
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

generate_panel_cert() {
    local CERT="$CONF_PATH/panel.crt"
    local KEY="$CONF_PATH/panel.key"
    local SERVER_IP
    SERVER_IP=$(get_public_ip)

    if [[ -f "$CERT" && -f "$KEY" ]]; then
        if openssl x509 -in "$CERT" -noout -text 2>/dev/null | grep -q "whispera-ui"; then
            log_info "Panel TLS cert already exists, skipping generation"
            return
        fi
        log_info "Regenerating panel TLS cert (adding DNS:whispera-ui SAN)..."
        rm -f "$CERT" "$KEY"
    fi

    log_info "Generating self-signed TLS certificate for panel (CN=whispera-ui)..."
    if command -v openssl &>/dev/null; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY" -out "$CERT" \
            -days 3650 -subj "/CN=whispera-ui" \
            -addext "subjectAltName=DNS:whispera-ui,IP:127.0.0.1,IP:${SERVER_IP}" \
            2>/dev/null
        chmod 600 "$KEY"
        log_success "Panel TLS cert generated: $CERT"
    else
        log_warn "openssl not found — panel will run without HTTPS"
    fi
}

_build_htpasswd() {
    local htfile="$CONF_PATH/panel.htpasswd"
    local pass
    pass=$(cat "$CONF_PATH/admin.pass" 2>/dev/null)
    [[ -z "$pass" ]] && return
    if command -v openssl &>/dev/null; then
        local hash
        hash=$(openssl passwd -apr1 "$pass" 2>/dev/null)
        printf 'admin:%s\n' "$hash" > "$htfile"
        chmod 640 "$htfile"
    fi
}

setup_nginx_proxy() {
    local SERVER_IP
    SERVER_IP=$(get_public_ip)
    local CERT="$CONF_PATH/panel.crt"
    local KEY="$CONF_PATH/panel.key"
    local HTPASSWD="$CONF_PATH/panel.htpasswd"

    if ! command -v nginx &>/dev/null; then
        log_info "Installing nginx..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y nginx >/dev/null 2>&1
        elif command -v yum &>/dev/null; then
            yum install -y nginx >/dev/null 2>&1
        else
            log_warn "Cannot install nginx — package manager not found"
            return
        fi
    fi

    _build_htpasswd

    # Rate-limit zone: max 10 req/min per IP on protected endpoints
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/whispera-ratelimit.conf <<'RLCONF'
limit_req_zone $binary_remote_addr zone=panel_auth:10m rate=10r/m;
limit_req_status 429;
RLCONF

    if ! grep -q "whispera-ui" /etc/hosts; then
        echo "127.0.0.1 whispera-ui" >> /etc/hosts
        log_info "Added whispera-ui to /etc/hosts"
    fi

    local AUTH_BLOCK=""
    if [[ -f "$HTPASSWD" ]]; then
        AUTH_BLOCK="
        auth_basic           \"Whispera\";
        auth_basic_user_file ${HTPASSWD};"
    fi

    cat > /etc/nginx/sites-available/whispera-ui <<NGINX
server {
    listen 443 ssl default_server;
    server_name _;

    ssl_certificate     ${CERT};
    ssl_certificate_key ${KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Prevent downgrade attacks — browser will enforce HTTPS for 1 year
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # /sub/ is public — VPN clients need subscription URLs without auth
    location /sub/ {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$remote_addr;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
    }

    location /api/ {
        limit_req  zone=panel_auth burst=20 nodelay;
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$remote_addr;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;${AUTH_BLOCK}
    }

    location / {
        limit_req  zone=panel_auth burst=20 nodelay;
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$remote_addr;
        proxy_set_header   X-Forwarded-Host \$host;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection "upgrade";${AUTH_BLOCK}
    }
}
NGINX

    mkdir -p /etc/nginx/sites-enabled
    ln -sf /etc/nginx/sites-available/whispera-ui /etc/nginx/sites-enabled/whispera-ui

    rm -f /etc/nginx/sites-enabled/default

    if command -v ufw &>/dev/null; then
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi

    if nginx -t 2>/dev/null; then
        systemctl enable nginx >/dev/null 2>&1
        if systemctl restart nginx 2>/dev/null; then
            log_success "Nginx reverse proxy configured: https://whispera-ui/"
        else
            log_warn "Nginx failed to restart — port 443 may be in use. Check: journalctl -u nginx"
        fi
    else
        log_warn "Nginx config test failed — check /etc/nginx/sites-available/whispera-ui"
    fi
}

setup_telegram() {
    echo ""
    echo -e "${YELLOW}--- Setup Telegram Notifications ---${PLAIN}"
    echo "1. Create a bot via @BotFather in Telegram and copy the token."
    echo "2. Send /start to your bot, then get your user ID via @userinfobot."
    echo ""
    read -p "Enter Telegram Bot Token (from @BotFather, leave empty to cancel): " TG_TOKEN

    if [[ -z "$TG_TOKEN" ]]; then
        log_warn "Cancelled."
        return
    fi

    read -p "Enter your Telegram User ID (numbers only): " TG_ID

    if [[ -z "$TG_ID" ]]; then
        log_warn "Cancelled."
        return
    fi

    if ! [[ "$TG_ID" =~ ^-?[0-9]+$ ]]; then
        log_err "Invalid Telegram ID: must be a number (e.g. 123456789). Got: $TG_ID"
        return
    fi

    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        log_err "Config file not found!"
        return
    fi

    log_info "Updating config..."
    sed -i "s|admin_id: .*|admin_id: $TG_ID|" "$CONF_PATH/config.yaml"
    sed -i "s|chat_id: .*|chat_id: \"$TG_ID\"|" "$CONF_PATH/config.yaml"
    sed -i "s|token: \"YOUR_TELEGRAM_BOT_TOKEN\"|token: \"$TG_TOKEN\"|g" "$CONF_PATH/config.yaml"
    sed -i "/^bot:/,/^[^ ]/ s|enabled: false|enabled: true|" "$CONF_PATH/config.yaml"
    sed -i "/^notifications:/,/^[^ ]/ s|enabled: false|enabled: true|" "$CONF_PATH/config.yaml"

    log_info "Testing bot connection..."
    local TEST_RESULT=$(curl -s "https://api.telegram.org/bot${TG_TOKEN}/getMe" 2>/dev/null)
    if echo "$TEST_RESULT" | grep -q '"ok":true'; then
        local BOT_NAME=$(echo "$TEST_RESULT" | grep -o '"first_name":"[^"]*"' | cut -d'"' -f4)
        log_success "Bot connected: $BOT_NAME"
    else
        log_warn "Could not verify bot token. Check the token and try again."
    fi

    log_info "Restarting Whispera..."
    refresh_config
    systemctl restart whispera
    log_success "Telegram notifications enabled for ID $TG_ID"
}

gen_bridge_ssh_otp() {
    log_info "Generating one-time SSH access code for bridge..."

    local TTL=${1:-3600}
    local KEY_DIR=$(mktemp -d)
    local KEY_FILE="$KEY_DIR/bridge_otp"

    ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "whispera-bridge-otp-$(date +%s)" -q

    local PUB_KEY=$(cat "$KEY_FILE.pub")
    local PRIV_KEY=$(cat "$KEY_FILE")
    local EXPIRE_AT=$(date -d "+${TTL} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -v "+${TTL}S" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "in ${TTL}s")
    local MARKER="whispera-bridge-otp-$(date +%s)"

    mkdir -p ~/.ssh
    chmod 700 ~/.ssh
    echo "${PUB_KEY} ${MARKER}" >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys

    local CLEANUP_SCRIPT="/tmp/whispera-otp-${MARKER}.sh"
    cat > "$CLEANUP_SCRIPT" <<CLEANSCRIPT
sed -i "/${MARKER}/d" ~/.ssh/authorized_keys
rm -f "$CLEANUP_SCRIPT"
CLEANSCRIPT
    chmod +x "$CLEANUP_SCRIPT"
    local SCHEDULED=0

    if command -v at &>/dev/null; then
        if systemctl is-active --quiet atd 2>/dev/null || service atd status &>/dev/null 2>&1 || pgrep -x atd &>/dev/null; then
            echo "bash $CLEANUP_SCRIPT" | at "now + $(( TTL / 60 + 1 )) minutes" 2>/dev/null && SCHEDULED=1
        fi
    fi

    if [[ "$SCHEDULED" -eq 0 ]] && command -v crontab &>/dev/null; then
        local CRON_TIME
        CRON_TIME=$(date -d "+$(( TTL / 60 + 1 )) minutes" '+%M %H %d %m *' 2>/dev/null \
                 || date -v "+$(( TTL / 60 + 1 ))M" '+%M %H %d %m *' 2>/dev/null)
        if [[ -n "$CRON_TIME" ]]; then
            (crontab -l 2>/dev/null | grep -v "$CLEANUP_SCRIPT"; \
             echo "$CRON_TIME bash $CLEANUP_SCRIPT") | crontab - 2>/dev/null && SCHEDULED=1
        fi
    fi

    if [[ "$SCHEDULED" -eq 0 ]]; then
        nohup bash -c "sleep ${TTL}; bash $CLEANUP_SCRIPT" </dev/null >/dev/null 2>&1 &
        log_warn "at/cron unavailable — using background process (key removed in ${TTL}s if server stays up)"
    fi

    rm -rf "$KEY_DIR"

    echo ""
    echo -e "${YELLOW}┌─── One-time SSH key (valid until: ${EXPIRE_AT}) ───────────────────────────────┐${PLAIN}"
    echo -e "${YELLOW}│ Expires automatically. Use ONCE to set up the bridge, then key is removed.   │${PLAIN}"
    echo -e "${YELLOW}└───────────────────────────────────────────────────────────────────────────────┘${PLAIN}"
    echo ""
    echo -e "${GREEN}Paste this private key into a file on the bridge server:${PLAIN}"
    echo ""
    echo "$PRIV_KEY"
    echo ""
    local SRV_IP=$(get_public_ip)
    echo -e "${GREEN}SSH command to use on the bridge server:${PLAIN}"
    echo -e "  ssh -i /tmp/bridge_key -o StrictHostKeyChecking=no root@${SRV_IP}"
    echo ""
    log_success "Key added to authorized_keys. It will self-remove after ${TTL}s."
}

setup_backups() {
    log_info "Setting up daily database backups..."
    
    if [[ ! -f "$CONF_PATH/postgres.env" ]]; then
        log_warn "PostgreSQL credentials not found. Installing PostgreSQL first..."
        setup_postgres
    fi
    
    cat > /usr/local/bin/whispera-backup <<'BACKUPEOF'
BACKUP_DIR="/var/backups/whispera"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/whispera/backup.log"
CONF_PATH="/etc/whispera"

mkdir -p "$BACKUP_DIR"
mkdir -p "$(dirname "$LOG_FILE")"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"; }

DB_URL=""
if [[ -f "$CONF_PATH/config.yaml" ]]; then
    DB_URL=$(grep -E '^\s*postgres_url:' "$CONF_PATH/config.yaml" | head -1 | sed 's/.*postgres_url:\s*["\x27]\?\([^"'\''[:space:]]*\)["\x27]\?.*/\1/')
fi
if [[ -z "$DB_URL" && -f "$CONF_PATH/postgres.env" ]]; then
    source "$CONF_PATH/postgres.env"
    DB_URL="${POSTGRES_URL:-postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost/${POSTGRES_DB}}"
fi
if [[ -z "$DB_URL" ]]; then
    log "ERROR: No database URL found in config.yaml or postgres.env"
    exit 1
fi

export PGPASSWORD=$(echo "$DB_URL" | grep -oP '://[^:]+:\K[^@]+')
PG_USER=$(echo "$DB_URL" | grep -oP '://\K[^:]+')
PG_HOST=$(echo "$DB_URL" | grep -oP '@\K[^:/]+')
PG_PORT=$(echo "$DB_URL" | grep -oP '@[^/]+:\K[0-9]+' || echo "5432")
PG_DB=$(echo "$DB_URL" | grep -oP '/\K[^?]+$')

FILENAME="$BACKUP_DIR/whispera_${DATE}.sql.gz"
log "Backup → $FILENAME (db=$PG_DB host=$PG_HOST)"

if ! command -v pg_dump &>/dev/null; then
    log "ERROR: pg_dump not found"
    exit 1
fi

if pg_dump -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d "$PG_DB" | gzip > "$FILENAME"; then
    SIZE=$(du -h "$FILENAME" | cut -f1)
    log "OK: $SIZE"
else
    log "FAILED"
    rm -f "$FILENAME"
    exit 1
fi

find "$BACKUP_DIR" -name "whispera_*.sql.gz" -mtime +"$RETENTION_DAYS" -delete
KEPT=$(ls -1 "$BACKUP_DIR"/whispera_*.sql.gz 2>/dev/null | wc -l)
log "Retention: kept $KEPT backups (${RETENTION_DAYS}d)"
BACKUPEOF

    chmod +x /usr/local/bin/whispera-backup
    
    if ! crontab -l 2>/dev/null | grep -q "whispera-backup"; then
        (crontab -l 2>/dev/null; echo "0 3 * * * /usr/local/bin/whispera-backup >> /var/log/whispera/backup.log 2>&1") | crontab -
    fi
    
    log_success "Backups scheduled daily at 03:00"
    log_info "Backup location: /var/backups/whispera"
}

show_extras_menu() {
    local SEP
    SEP=$(printf '═%.0s' {1..62})
    _row() { echo -e "${BLUE}║${PLAIN} $(printf '%-60s' "$1") ${BLUE}║${PLAIN}"; }

    while true; do
        clear

        local SRV_IP=$(get_public_ip)
        local ADMIN_PASS=$(cat "$CONF_PATH/admin.pass" 2>/dev/null)
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"
        echo -e "${GREEN} WEB PANEL${PLAIN}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"
        echo -e "  URL:      ${BLUE}https://${SRV_IP}/${PLAIN}"
        echo -e "  User:     ${BLUE}admin${PLAIN}"
        echo -e "  Password: ${BLUE}${ADMIN_PASS}${PLAIN}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"

        local BRIDGE_TOKEN=$(cat "$CONF_PATH/bridge.token" 2>/dev/null)

        echo ""
        echo -e "${BLUE}╔${SEP}╗${PLAIN}"
        _row "          WHISPERA MANAGEMENT MENU"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  Web Panel:  https://${SRV_IP}/"
        _row "  Config:     /etc/whispera/config.yaml"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  BRIDGE MANAGEMENT"
        _row " 19.  Show bridge token & install command"
        _row " 20.  Add bridge manually (enter IP + token)"
        _row " 21.  List registered bridges"
        _row " 22.  SSH OTP       - One-time SSH key for bridge admin (1h)"
        _row " 23.  Panel Password  - Change panel Basic Auth password"
        _row " 24.  Panel Integrity - Verify panel bundle has not been tampered"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  OPTIONAL EXTRAS"
        _row "  1.  BBR           - Faster TCP (recommended)"
        _row "  2.  WARP          - Hide server IP via Cloudflare"
        _row "  3.  Fail2ban      - Protect SSH from brute-force"
        _row "  4.  Swap          - Add 2GB swap (for low-RAM servers)"
        _row "  5.  Optimize      - Tune sysctl for high performance"
        _row "  6.  Auto-update   - Daily auto-update from GitHub"
        _row "  7.  SSH Hardening - Disable password auth (keys only)"
        _row "  8.  Redis         - Session cache for persistence"
        _row "  9.  PostgreSQL    - User accounts, traffic, billing"
        _row " 10.  Telegram      - Configure notifications"
        _row " 11.  Backups       - Daily database backups"
        _row "  a.  ALL (1,5,8,9,11) - Install recommended stack"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  SERVICE MANAGEMENT"
        _row " 12.  Start         - Start Whispera service"
        _row " 13.  Stop          - Stop Whispera service"
        _row " 14.  Restart       - Restart Whispera service"
        _row " 15.  Status        - Check service status"
        _row " 16.  View Logs     - Watch live logs"
        _row " 17.  Edit Config   - Modify config.yaml"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row " 18.  Update        - Update Whispera from GitHub"
        _row "  0.  Exit"
        echo -e "${BLUE}╚${SEP}╝${PLAIN}"
        echo ""

        read -rp "  Select option: " choice
        case $choice in
            1) setup_bbr ;;
            2) setup_warp ;;
            3) setup_fail2ban ;;
            4) setup_swap ;;
            5) setup_sysctl ;;
            6) setup_autoupdate ;;
            7) setup_ssh_hardening ;;
            8) setup_redis ;;
            9) setup_postgres ;;
            10) setup_telegram ;;
            11) setup_backups ;;
            a|A) setup_bbr; setup_sysctl; setup_redis; setup_postgres; setup_backups ;;
            12) systemctl start whispera && log_success "Service started" || log_err "Failed to start service" ;;
            13) systemctl stop whispera && log_success "Service stopped" || log_err "Failed to stop service" ;;
            14) systemctl restart whispera && log_success "Service restarted" || log_err "Failed to restart service" ;;
            15) systemctl status whispera ;;
            16) journalctl -u whispera -f ;;
            17) ${EDITOR:-nano} /etc/whispera/config.yaml; refresh_config ;;
            18) bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/update.sh) ;;
            19)
                local tok=$(cat "$CONF_PATH/bridge.token" 2>/dev/null)
                if [[ -z "$tok" ]]; then
                    log_warn "Bridge token not found at $CONF_PATH/bridge.token"
                else
                    echo ""
                    echo -e "${GREEN}Bridge token:${PLAIN} $tok"
                    echo ""
                    echo -e "${GREEN}Install bridge on another server:${PLAIN}"
                    echo -e "  curl -sL https://${SRV_IP}:8080/install-bridge.sh | bash -s -- ${SRV_IP}:8443 $tok"
                fi
                ;;
            20)
                read -rp "  Bridge IP:port (e.g. 1.2.3.4:8443): " BR_ADDR
                read -rp "  Bridge token: " BR_TOK
                if [[ -n "$BR_ADDR" && -n "$BR_TOK" ]]; then
                    curl -sk -X POST "https://127.0.0.1:8080/api/bridges" \
                        -H "Content-Type: application/json" \
                        -H "Authorization: Bearer $(cat $CONF_PATH/admin.token 2>/dev/null)" \
                        -d "{\"address\":\"$BR_ADDR\",\"token\":\"$BR_TOK\"}" && \
                        log_success "Bridge $BR_ADDR registered" || log_err "Failed to register bridge"
                else
                    log_warn "Address and token are required"
                fi
                ;;
            21)
                curl -sk "https://127.0.0.1:8080/api/bridges" \
                    -H "Authorization: Bearer $(cat $CONF_PATH/admin.token 2>/dev/null)" | \
                    jq . 2>/dev/null || cat || \
                    log_err "Failed to fetch bridges (is Whispera running?)"
                ;;
            22)
                gen_bridge_ssh_otp 3600
                ;;
            23)
                read -rp "  New password (leave empty to generate): " NEW_PASS
                if [[ -z "$NEW_PASS" ]]; then
                    NEW_PASS=$(gen_password 20)
                    echo -e "  Generated password: ${BLUE}${NEW_PASS}${PLAIN}"
                fi
                echo "$NEW_PASS" > "$CONF_PATH/admin.pass"
                chmod 600 "$CONF_PATH/admin.pass"
                _build_htpasswd
                nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
                log_success "Panel password updated. User: admin / Password: ${NEW_PASS}"
                ;;
            24)
                _check_panel_integrity
                echo ""
                _verify_panel_bundle "$DAT_PATH/panel"
                ;;
            0|"") log_info "Exiting menu."; break ;;
            *) log_warn "Invalid option: $choice" ;;
        esac

        if [[ "$choice" != "0" ]] && [[ -n "$choice" ]]; then
            echo ""
            read -rp "  Press Enter to return to menu..."
        fi
    done
}


# Minimum acceptable size for bundle/index.js in bytes (1 MB)
PANEL_BUNDLE_MIN_BYTES=1048576

_verify_panel_archive() {
    local archive="$1"       # path to panel-release.tar.gz
    local sums_url="$2"      # URL to SHA256SUMS

    # Size check — reject anything under 500 KB
    local bytes
    bytes=$(stat -c%s "$archive" 2>/dev/null || stat -f%z "$archive" 2>/dev/null || echo 0)
    if [[ "$bytes" -lt 524288 ]]; then
        log_err "Panel archive is suspiciously small (${bytes} bytes < 512 KB) — refusing to install"
        return 1
    fi

    # SHA256 verification against release checksums
    if [[ -n "$sums_url" ]]; then
        local sums_file
        sums_file=$(mktemp)
        if curl -sL -o "$sums_file" "$sums_url" && [[ -s "$sums_file" ]]; then
            local expected_hash
            expected_hash=$(grep "whispera-panel.tar.gz" "$sums_file" | awk '{print $1}')
            if [[ -n "$expected_hash" ]]; then
                local actual_hash
                actual_hash=$(sha256sum "$archive" | awk '{print $1}')
                if [[ "$actual_hash" != "$expected_hash" ]]; then
                    log_err "Panel archive SHA256 mismatch!"
                    log_err "  Expected: $expected_hash"
                    log_err "  Actual:   $actual_hash"
                    rm -f "$sums_file"
                    return 1
                fi
                log_info "Panel archive SHA256 verified ✓"
            else
                log_warn "No entry for whispera-panel.tar.gz in SHA256SUMS — skipping hash check"
            fi
        else
            log_warn "Could not download SHA256SUMS — skipping hash verification"
        fi
        rm -f "$sums_file"
    fi
    return 0
}

_verify_panel_bundle() {
    local panel_dir="${1:-$DAT_PATH/panel}"
    local bundle="$panel_dir/bundle/index.js"
    [[ -f "$bundle" ]] || { log_err "Panel bundle missing: $bundle"; return 1; }

    local bytes
    bytes=$(stat -c%s "$bundle" 2>/dev/null || stat -f%z "$bundle" 2>/dev/null || echo 0)
    if [[ "$bytes" -lt "$PANEL_BUNDLE_MIN_BYTES" ]]; then
        log_err "Panel bundle is suspiciously small (${bytes} bytes < 1 MB) — possible tampering!"
        return 1
    fi

    # Record hash for future integrity checks
    sha256sum "$bundle" > "$CONF_PATH/panel-bundle.sha256" 2>/dev/null
    log_info "Panel bundle OK ($(( bytes / 1024 )) KB), hash recorded"
    return 0
}

_check_panel_integrity() {
    local panel_dir="${1:-$DAT_PATH/panel}"
    local bundle="$panel_dir/bundle/index.js"
    local stored="$CONF_PATH/panel-bundle.sha256"

    if [[ ! -f "$stored" ]]; then
        log_warn "No stored panel hash — run update to establish baseline"
        return 0
    fi
    if ! sha256sum --check "$stored" --status 2>/dev/null; then
        log_err "Panel bundle hash MISMATCH — file may have been tampered with!"
        sha256sum "$bundle" 2>/dev/null
        echo "Expected:"
        cat "$stored"
        return 1
    fi
    log_success "Panel integrity OK"
    return 0
}

_repair_panel_bundle() {
    local panel_dir="${1:-$DAT_PATH/panel}"
    if [[ -f "$panel_dir/bundle/index.js" ]]; then
        return
    fi
    log_warn "bundle/index.js missing — attempting repair"
    if [[ -f "$panel_dir/dist/main.js" ]]; then
        local node_bin
        node_bin=$(command -v node || echo /usr/bin/node)
        if "$node_bin" -e "require('@vercel/ncc')" 2>/dev/null; then
            cd "$panel_dir"
            npx @vercel/ncc build dist/main.js -o bundle/ --minify --no-source-map-register \
                && log_success "Panel bundle rebuilt" \
                || { mkdir -p bundle; cp dist/main.js bundle/index.js; log_warn "ncc failed — copied dist/main.js"; }
            cd - >/dev/null
        else
            mkdir -p "$panel_dir/bundle"
            cp "$panel_dir/dist/main.js" "$panel_dir/bundle/index.js"
            log_warn "ncc not available — copied dist/main.js as bundle/index.js"
        fi
    else
        log_warn "Neither bundle/index.js nor dist/main.js found — panel needs reinstall"
    fi
}

do_update() {
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || exit 1

    _repair_panel_bundle

    if command -v whispera-backup &>/dev/null; then
        log_info "Creating pre-update backup..."
        whispera-backup || log_warn "Backup failed, continuing anyway..."
    fi

    if [[ -d ".git" ]]; then
        log_info "Updating source code..."
        git config --global --add safe.directory "$(pwd)" 2>/dev/null || true
        git fetch origin $BRANCH --quiet
        git reset --hard origin/$BRANCH --quiet
    fi

    log_info "Creating backup of current version..."
    cp "$BIN_PATH/whispera" "$BIN_PATH/whispera.bak" 2>/dev/null || true
    if [[ -d "$DAT_PATH/panel" ]]; then
        rm -rf "$DAT_PATH/panel.bak"
        cp -r "$DAT_PATH/panel" "$DAT_PATH/panel.bak"
    fi

    log_info "Updating Whispera server..."
    export PATH=$PATH:/usr/local/go/bin
    rm -f whispera-server

    local ARCH="amd64"
    [[ $(uname -m) == "aarch64" ]] && ARCH="arm64"

    log_info "Fetching latest release info..."
    local RELEASE_JSON
    RELEASE_JSON=$(curl -s https://api.github.com/repos/Jalaveyan/Whispera/releases/latest)

    log_info "Downloading latest release from GitHub..."
    local DIRECT_URL="https://github.com/Jalaveyan/Whispera/releases/latest/download/whispera-server-linux-${ARCH}.tar.gz"

    local BIN_FOUND=false

    if curl -fL --retry 3 --retry-delay 2 -o whispera-server.tar.gz "$DIRECT_URL" 2>/dev/null; then
        if tar -xzf whispera-server.tar.gz 2>/dev/null; then
            rm -f whispera-server.tar.gz
            if [[ -f "whispera-server" ]]; then
                BIN_FOUND=true
                log_success "Update downloaded successfully"
            fi
        fi
    fi

    if [[ "$BIN_FOUND" != "true" ]]; then
        log_warn "Direct download failed, trying GitHub API..."
        local DOWNLOAD_URL
        DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "whispera-server-linux-$ARCH.tar.gz" | head -n 1 | cut -d '"' -f 4)
        if [[ -n "$DOWNLOAD_URL" ]]; then
            if curl -fL --retry 3 -o whispera-server.tar.gz "$DOWNLOAD_URL" 2>/dev/null; then
                if tar -xzf whispera-server.tar.gz 2>/dev/null; then
                    rm -f whispera-server.tar.gz
                    [[ -f "whispera-server" ]] && BIN_FOUND=true && log_success "Update downloaded via API"
                fi
            fi
        fi
    fi

    if [[ "$BIN_FOUND" != "true" ]]; then
        log_info "Release download failed, building from source..."

        if [[ -d "$WORK_DIR/.git" ]]; then
            log_info "Pulling from GitHub..."
            cd "$WORK_DIR"
            git config --global --add safe.directory "$WORK_DIR" 2>/dev/null || true
            git fetch origin $BRANCH --quiet
            git reset --hard origin/$BRANCH --quiet
        fi

        go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server || true
    fi
    
    if [[ ! -f "whispera-server" ]]; then
        log_err "Build failed!"
        exit 1
    fi
    
    log_info "Stopping service..."
    systemctl stop whispera 2>/dev/null || true
    sleep 1
    
    log_info "Installing binary..."
    cp whispera-server "$BIN_PATH/whispera"
    chmod +x "$BIN_PATH/whispera"
    
    if [[ -d "web" ]]; then
        log_info "Updating Web UI..."
        mkdir -p "$DAT_PATH/web"
        cp -r web/* "$DAT_PATH/web/"
    fi

    if [[ -f "scripts/install-bridge.sh" ]]; then
        mkdir -p "/opt/whispera/scripts"
        cp "scripts/install-bridge.sh" "/opt/whispera/scripts/install-bridge.sh" 2>/dev/null || true
        chmod +x "/opt/whispera/scripts/install-bridge.sh"
        log_info "Bridge install script deployed to /opt/whispera/scripts/"
    fi

    local PANEL_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "whispera-panel.tar.gz" | head -n 1 | cut -d '"' -f 4)
    local SUMS_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "SHA256SUMS" | head -n 1 | cut -d '"' -f 4)

    if [[ -n "$PANEL_URL" ]]; then
        log_info "Updating panel from release..."
        if curl -L -o panel-release.tar.gz "$PANEL_URL"; then
            if ! _verify_panel_archive "panel-release.tar.gz" "$SUMS_URL"; then
                rm -f panel-release.tar.gz
                log_err "Panel update aborted due to integrity check failure"
            else
            mkdir -p /tmp/panel-update
            tar -xzf panel-release.tar.gz -C /tmp/panel-update
            rm -f panel-release.tar.gz
            
            local PANEL_DEST="$DAT_PATH/panel"
            mkdir -p "$PANEL_DEST"
            
            local ENV_BAK=""
            if [[ -f "$PANEL_DEST/.env" ]]; then
                ENV_BAK=$(cat "$PANEL_DEST/.env")
            fi
            
            rm -rf "$PANEL_DEST/dist" "$PANEL_DEST/bundle" "$PANEL_DEST/public" "$PANEL_DEST/node_modules"
            cp -r /tmp/panel-update/* "$PANEL_DEST/"
            rm -rf /tmp/panel-update


            if [[ -n "$ENV_BAK" ]]; then
                echo "$ENV_BAK" > "$PANEL_DEST/.env"
            elif [[ ! -f "$PANEL_DEST/.env" ]]; then
                cat > "$PANEL_DEST/.env" <<ENVEOF
BACKEND_URL=http://127.0.0.1:8080
PORT=3000
CORS_ORIGIN=*
ENVEOF
            fi



            if grep -q "dist/main.js" /etc/systemd/system/whispera-panel.service 2>/dev/null; then
                local NODE_BIN=$(command -v node || echo "/usr/bin/node")
                sed -i "s|ExecStart=.* dist/main.js|ExecStart=$NODE_BIN bundle/index.js|" /etc/systemd/system/whispera-panel.service
                systemctl daemon-reload
                log_info "Migrated panel service to bundle/index.js"
            fi

            generate_panel_cert

            sed -i '/^Environment=TLS_CERT\|^Environment=TLS_KEY\|^Environment=HTTP_PORT/d' \
                /etc/systemd/system/whispera-panel.service 2>/dev/null || true

            if ! grep -q "AmbientCapabilities" /etc/systemd/system/whispera-panel.service 2>/dev/null; then
                sed -i "/^NoNewPrivileges/i AmbientCapabilities=CAP_NET_BIND_SERVICE" \
                    /etc/systemd/system/whispera-panel.service
                log_info "Added CAP_NET_BIND_SERVICE to panel service"
            fi
            if ! grep -q "CAP_NET_ADMIN" /etc/systemd/system/whispera.service 2>/dev/null; then
                sed -i 's/AmbientCapabilities=CAP_NET_BIND_SERVICE$/AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN/' \
                    /etc/systemd/system/whispera.service
                log_info "Added CAP_NET_ADMIN to whispera service"
            fi
            if ! grep -q " /run" /etc/systemd/system/whispera.service 2>/dev/null; then
                if grep -q "^ReadWritePaths=" /etc/systemd/system/whispera.service 2>/dev/null; then
                    sed -i 's|^ReadWritePaths=\(.*\)|ReadWritePaths=\1 /run /var/crash|' /etc/systemd/system/whispera.service
                else
                    sed -i '/^ProtectSystem=strict/a ReadWritePaths=/run /var/crash /etc/ufw /lib/ufw /var/lib/ufw /var/log/whispera' \
                        /etc/systemd/system/whispera.service
                fi
                log_info "Added /run to ReadWritePaths in whispera service"
            fi
            if grep -q "/run/ufw.lock" /etc/systemd/system/whispera.service 2>/dev/null; then
                sed -i 's| /run/ufw\.lock||g' /etc/systemd/system/whispera.service
            fi
            systemctl daemon-reload

            _repair_panel_bundle "$PANEL_DEST"
            _verify_panel_bundle "$PANEL_DEST" || log_warn "Post-install bundle check failed — review manually"
            systemctl daemon-reload
            systemctl restart whispera-panel 2>/dev/null || log_warn "Panel service not configured"

            setup_nginx_proxy
            log_success "Panel updated from release"
            fi  # end integrity check
        else
            log_warn "Panel download failed"
        fi
    else
        log_info "No panel release found, skipping panel update"
    fi
    
    mkdir -p /var/log/whispera
    chown whispera:whispera /var/log/whispera 2>/dev/null || true

    if [[ ! -f /etc/sudoers.d/whispera-ufw ]]; then
        local UFW_BIN
        UFW_BIN=$(command -v ufw 2>/dev/null || echo /usr/sbin/ufw)
        echo "whispera ALL=(ALL) NOPASSWD: $UFW_BIN" > /etc/sudoers.d/whispera-ufw
        chmod 440 /etc/sudoers.d/whispera-ufw
        log_info "Configured sudo access for UFW"
    fi

    if ! grep -q "WHISPERA_MASK_LOGS" /etc/systemd/system/whispera.service; then
        sed -i '/\[Service\]/a Environment=WHISPERA_MASK_LOGS=false' /etc/systemd/system/whispera.service
        systemctl daemon-reload
    fi

    if ! grep -q "StandardOutput=append" /etc/systemd/system/whispera.service 2>/dev/null; then
        sed -i '/ReadWritePaths=.*/a StandardOutput=append:\/var\/log\/whispera\/whispera.log\nStandardError=append:\/var\/log\/whispera\/whispera.log' \
            /etc/systemd/system/whispera.service
        systemctl daemon-reload
        log_info "Enabled file logging for whispera service"
    fi

    if [[ -d "$DAT_PATH/panel" ]]; then
        mkdir -p "$DAT_PATH/panel/public/uploads"
        chown -R whispera:whispera "$DAT_PATH/panel/public" 2>/dev/null || true
    fi

    local SVC=/etc/systemd/system/whispera.service
    if [[ -f "$SVC" ]]; then
        local RELOAD=false
        if grep -q "^NoNewPrivileges=true" "$SVC"; then
            sed -i '/^NoNewPrivileges=true/d' "$SVC"
            RELOAD=true
            log_info "Removed NoNewPrivileges from whispera.service (required for UFW sudo)"
        fi
        if ! grep -q "CAP_NET_RAW" "$SVC"; then
            sed -i 's/AmbientCapabilities=\(.*\)/AmbientCapabilities=\1 CAP_NET_RAW/' "$SVC"
            RELOAD=true
        fi
        if ! grep -q "/etc/ufw" "$SVC"; then
            sed -i 's|ReadWritePaths=\(.*\)|ReadWritePaths=\1 /etc/ufw /lib/ufw /var/lib/ufw|' "$SVC"
            RELOAD=true
        fi
        if ! grep -q "$CONF_PATH" "$SVC"; then
            sed -i "s|ReadWritePaths=\(.*\)|ReadWritePaths=\1 $CONF_PATH|" "$SVC"
            RELOAD=true
            log_info "Added $CONF_PATH to ReadWritePaths in whispera.service"
        fi
        if ! grep -qE " /run( |$)" "$SVC"; then
            sed -i 's|ReadWritePaths=\(.*\)|ReadWritePaths=\1 /run /var/crash|' "$SVC"
            RELOAD=true
            log_info "Added /run to ReadWritePaths in whispera.service"
        fi
        if grep -q "/run/ufw.lock" "$SVC"; then
            sed -i 's| /run/ufw\.lock||g' "$SVC"
            RELOAD=true
        fi
        # Remove all timeout/watchdog settings that cause spurious failures
        for directive in Type=notify WatchdogSec TimeoutStopSec TimeoutStartSec; do
            if grep -q "^${directive}" "$SVC"; then
                sed -i "/^${directive}/d" "$SVC"
                RELOAD=true
                log_info "Removed $directive from whispera.service"
            fi
        done
        # Ensure LimitNOFILE=infinity (like xray/sing-box)
        if grep -q "^LimitNOFILE=" "$SVC"; then
            sed -i 's/^LimitNOFILE=.*/LimitNOFILE=infinity/' "$SVC"
            RELOAD=true
        fi
        if [[ "$RELOAD" == true ]]; then
            systemctl daemon-reload
            log_info "Updated whispera.service for UFW access"
        fi
    fi

    if [[ -d "/opt/whispera-ml" ]]; then
        log_info "Removing legacy ML repo at /opt/whispera-ml..."
        rm -rf "/opt/whispera-ml"
    fi
    log_info "ML engine is built into the main Whispera binary (no Python required)"
    if [[ -f /etc/systemd/system/whispera-ml.service ]]; then
        log_info "Removing legacy Python ML service..."
        systemctl stop whispera-ml 2>/dev/null || true
        systemctl disable whispera-ml 2>/dev/null || true
        rm -f /etc/systemd/system/whispera-ml.service
        systemctl daemon-reload
    fi
    _enable_ml_in_config
    _enable_tcp8443_in_config
    _enable_chameleon_in_config
    _disable_phantom_in_config

    if [[ -f "$CONF_PATH/config.yaml" ]]; then
        local MTD
        MTD=$(grep 'max_time_diff:' "$CONF_PATH/config.yaml" | awk '{print $2}' | tr -d '[:space:]')
        if [[ -n "$MTD" && "$MTD" -lt 1000 ]] 2>/dev/null; then
            log_warn "Config: max_time_diff=$MTD is too small (ms units). Updating to 300000 (5 min)..."
            sed -i "s/max_time_diff: $MTD/max_time_diff: 300000/" "$CONF_PATH/config.yaml"
            log_success "max_time_diff updated: $MTD -> 300000"
        fi

        local RELAY_COUNT
        RELAY_COUNT=$(grep -c "^relay:" "$CONF_PATH/config.yaml" 2>/dev/null || echo 0)
        if [[ "$RELAY_COUNT" -gt 1 ]]; then
            log_warn "Config: duplicate relay: blocks detected ($RELAY_COUNT). Merging..."
            awk '
            /^relay:/ { if (seen_relay) { skip=1; next } seen_relay=1 }
            skip && /^[^ ]/ && !/^relay:/ { skip=0 }
            !skip { print }
            ' "$CONF_PATH/config.yaml" > "$CONF_PATH/config.yaml.tmp" && \
                mv "$CONF_PATH/config.yaml.tmp" "$CONF_PATH/config.yaml"
            log_success "relay: blocks merged"
        fi

        "$BIN_PATH/whispera" update-checksum "$CONF_PATH/config.yaml" && log_info "Config checksum updated" || log_warn "Config checksum update failed (non-fatal)"
    fi

    setup_nginx_proxy
    log_info "Starting service..."
    systemctl daemon-reload
    if ! systemctl start whispera; then
        log_err "Whispera service failed to start after update!"
        journalctl -u whispera -n 20 --no-pager 2>/dev/null || true
        restore
    fi

    sleep 3
    if ! systemctl is-active --quiet whispera; then
        log_err "Whispera service started but is not active after 3s!"
        journalctl -u whispera -n 20 --no-pager 2>/dev/null || true
        restore
    fi

    PUBLIC_KEY=$(cat "$CONF_PATH/server.pub" 2>/dev/null)
    SERVER_IP=$(get_public_ip)
    
    echo ""
    log_success "Whispera updated successfully!"
    echo -e "  Config:         ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    echo -e "  Web Panel:      ${GREEN}https://whispera-ui/${PLAIN}"
    echo -e "  ${GREEN}${SERVER_IP} whispera-ui${PLAIN}  → в файл /etc/hosts (Linux/Mac) или C:\\Windows\\System32\\drivers\\etc\\hosts (Windows)"
    
    local ADMIN_PASS_UPD=$(cat "$CONF_PATH/admin.pass" 2>/dev/null)
    if [[ -n "$ADMIN_PASS_UPD" ]]; then
        echo ""
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "${GREEN} WEB PANEL                                                      ${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "  URL:      ${BLUE}https://${SERVER_IP}/${PLAIN}"
        echo -e "  User:     ${BLUE}admin${PLAIN}"
        echo -e "  Password: ${BLUE}${ADMIN_PASS_UPD}${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
    fi
    echo ""
    
    show_extras_menu
}


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
    redis) setup_redis ;;
    postgres) setup_postgres ;;
    telegram) setup_telegram ;;
    backups) setup_backups ;;
    all) setup_bbr; setup_sysctl; setup_redis; setup_postgres; setup_backups ;;
    extras) show_extras_menu ;;
    help|--help|-h)
        echo "Whispera Update Script v2.1"
        echo ""
        echo "Usage: ./update.sh [command]"
        echo ""
        echo "Commands:"
        echo "  (no args)   Update Whispera"
        echo "  extras      Show extras menu"
        echo "  all         Install BBR + sysctl + Redis + PostgreSQL"
        echo ""
        echo "Individual extras:"
        echo "  bbr         Enable BBR (faster TCP)"
        echo "  warp        Cloudflare WARP (hide IP)"
        echo "  fail2ban    Protect SSH"
        echo "  swap        Create 2GB swap"
        echo "  optimize    Tune sysctl"
        echo "  autoupdate  Enable daily updates"
        echo "  harden      SSH hardening"
        echo "  redis       Install Redis cache"
        echo "  postgres    Install PostgreSQL database"
        ;;
    *)
        do_update
        ;;
esac
