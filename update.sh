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

# Call after any edit to config.yaml so the integrity check passes on restart
refresh_config() {
    local cfg="${1:-$CONF_PATH/config.yaml}"
    if [[ ! -f "$cfg" ]]; then return; fi
    if command -v whispera &>/dev/null; then
        whispera update-checksum "$cfg" 2>/dev/null && log_info "Config checksum updated"
    fi
}

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
    
    systemctl restart whispera
    systemctl restart whispera-panel 2>/dev/null || true

    log_success "Rollback complete. System restored to previous state."
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
    
    cat >> /etc/sysctl.conf <<EOF

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
                echo "" >> "$CONF_PATH/config.yaml"
                echo "relay:" >> "$CONF_PATH/config.yaml"
                echo "  upstream_proxy: \"socks5://127.0.0.1:40000\"" >> "$CONF_PATH/config.yaml"
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
    
    local AUTH_LOG="/var/log/auth.log"
    [[ -f /var/log/secure ]] && AUTH_LOG="/var/log/secure"
    
    cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = auto

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = $AUTH_LOG
maxretry = 3
EOF
    
    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_success "Fail2ban installed and running"
        log_info "Config: /etc/fail2ban/jail.local (logpath: $AUTH_LOG)"
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
    
    local PG_PASS=$(openssl rand -hex 16)
    
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
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    log_success "Swap 2GB created"
}

setup_sysctl() {
    log_info "Optimizing system..."
    
    cat >> /etc/sysctl.conf <<EOF

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

setup_telegram() {
    echo ""
    echo -e "${YELLOW}--- Setup Telegram Notifications ---${PLAIN}"
    echo "This will configure the server to send status updates to your Telegram."
    echo "1. Start bot @WhisperaStatusBot (or your configured bot)."
    echo "2. Use /start to get your ID."
    echo ""
    read -p "Enter your Telegram User ID (leave empty to cancel): " TG_ID
    
    if [[ -z "$TG_ID" ]]; then
        log_warn "Cancelled."
        return
    fi
    
    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        log_err "Config file not found!"
        return
    fi
    
    log_info "Updating config..."
    sed -i "s/admin_id: .*/admin_id: $TG_ID/" "$CONF_PATH/config.yaml"
    sed -i "s/chat_id: .*/chat_id: \"$TG_ID\"/" "$CONF_PATH/config.yaml"
    
    log_info "Restarting Whispera..."
    refresh_config
    systemctl restart whispera
    log_success "Telegram notifications enabled for ID $TG_ID"
}

setup_backups() {
    log_info "Setting up daily database backups..."
    
    if [[ ! -f "$CONF_PATH/postgres.env" ]]; then
        log_warn "PostgreSQL credentials not found. Installing PostgreSQL first..."
        setup_postgres
    fi
    
    cat > /usr/local/bin/whispera-backup <<EOF
BACKUP_DIR="/var/backups/whispera"
RETENTION_DAYS=7
DATE=\$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/whispera/backup.log"

mkdir -p "\$BACKUP_DIR"
mkdir -p "\$(dirname "\$LOG_FILE")"

log() {
    echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" | tee -a "\$LOG_FILE"
}

if [ -f "$CONF_PATH/postgres.env" ]; then
    source $CONF_PATH/postgres.env
else
    log "Error: $CONF_PATH/postgres.env not found!"
    exit 1
fi

export PGPASSWORD=\$POSTGRES_PASSWORD

FILENAME="\$BACKUP_DIR/whispera_backup_\$DATE.sql.gz"
log "Starting backup: \$FILENAME"

if command -v pg_dump &>/dev/null; then
    if pg_dump -h localhost -U \$POSTGRES_USER -d \$POSTGRES_DB | gzip > "\$FILENAME"; then
        log "Backup created successfully: \$(du -h "\$FILENAME" | cut -f1)"
    else
        log "Backup failed!"
        rm -f "\$FILENAME"
        exit 1
    fi
else
    log "pg_dump not found!"
    exit 1
fi

ls -1t "\$BACKUP_DIR"/whispera_backup_*.sql.gz 2>/dev/null | tail -n +6 | xargs -r rm -f
EOF

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

        local PUB_KEY=$(cat "$CONF_PATH/server.pub" 2>/dev/null)
        local SRV_IP=$(get_public_ip)
        if [[ -n "$PUB_KEY" ]]; then
            echo ""
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"
            echo -e "${GREEN} CONNECTION KEY${PLAIN}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"
            echo -e "${BLUE}whispera://${SRV_IP}:8443?pub=${PUB_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome${PLAIN}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${PLAIN}"
        fi

        echo ""
        echo -e "${BLUE}╔${SEP}╗${PLAIN}"
        _row "          WHISPERA MANAGEMENT MENU"
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
            0|"") log_info "Exiting menu."; break ;;
            *) log_warn "Invalid option: $choice" ;;
        esac

        if [[ "$choice" != "0" ]] && [[ -n "$choice" ]]; then
            echo ""
            read -rp "  Press Enter to return to menu..."
        fi
    done
}


do_update() {
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || exit 1

    if command -v whispera-backup &>/dev/null; then
        log_info "Creating pre-update backup..."
        whispera-backup || log_warn "Backup failed, continuing anyway..."
    fi

    if [[ -d ".git" ]]; then
        log_info "Updating source code..."
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
    
    log_info "Checking for latest release on GitHub..."
    local RELEASE_JSON=$(curl -s https://api.github.com/repos/Jalaveyan/Whispera/releases/latest)
    local DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "whispera-server-linux-$ARCH.tar.gz" | head -n 1 | cut -d '"' -f 4)

    local BIN_FOUND=false
    
    if [[ -n "$DOWNLOAD_URL" ]]; then
        log_info "Downloading update from $DOWNLOAD_URL..."
        if curl -L -o whispera-server.tar.gz "$DOWNLOAD_URL"; then
            if tar -xzf whispera-server.tar.gz; then
                rm -f whispera-server.tar.gz
                if [[ -f "whispera-server" ]]; then
                   BIN_FOUND=true
                   log_success "Update downloaded successfully"
                fi
            fi
        fi
    fi
    
    if [[ "$BIN_FOUND" != "true" ]]; then
        log_info "Release download failed, building from source..."
        
        if [[ -d "$WORK_DIR/.git" ]]; then
            log_info "Pulling from GitHub..."
            cd "$WORK_DIR"
            git fetch origin $BRANCH --quiet
            git reset --hard origin/$BRANCH --quiet
        fi
        
        go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server
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

    local PANEL_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "whispera-panel.tar.gz" | head -n 1 | cut -d '"' -f 4)
    
    if [[ -n "$PANEL_URL" ]]; then
        log_info "Updating panel from release..."
        if curl -L -o panel-release.tar.gz "$PANEL_URL"; then
            mkdir -p /tmp/panel-update
            tar -xzf panel-release.tar.gz -C /tmp/panel-update
            rm -f panel-release.tar.gz
            
            local PANEL_DEST="$DAT_PATH/panel"
            mkdir -p "$PANEL_DEST"
            
            local ENV_BAK=""
            if [[ -f "$PANEL_DEST/.env" ]]; then
                ENV_BAK=$(cat "$PANEL_DEST/.env")
            fi
            
            rm -rf "$PANEL_DEST/dist" "$PANEL_DEST/public" "$PANEL_DEST/node_modules"
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


            if grep -q "bundle/index.js" /etc/systemd/system/whispera-panel.service 2>/dev/null; then
                local NODE_BIN=$(command -v node || echo "/usr/bin/node")
                sed -i "s|ExecStart=.* bundle/index.js|ExecStart=$NODE_BIN dist/main.js|" /etc/systemd/system/whispera-panel.service
                systemctl daemon-reload
                log_info "Updated panel service to use dist/main.js"
            fi

            systemctl restart whispera-panel 2>/dev/null || log_warn "Panel service not configured"
            log_success "Panel updated from release"
        else
            log_warn "Panel download failed"
        fi
    else
        log_info "No panel release found, skipping panel update"
    fi
    
    if ! grep -q "WHISPERA_MASK_LOGS" /etc/systemd/system/whispera.service; then
        sed -i '/\[Service\]/a Environment=WHISPERA_MASK_LOGS=false' /etc/systemd/system/whispera.service
        systemctl daemon-reload
    fi

    # Migrate config: fix max_time_diff if it was set too small (< 1000ms)
    if [[ -f "$CONF_PATH/config.yaml" ]]; then
        local MTD
        MTD=$(grep 'max_time_diff:' "$CONF_PATH/config.yaml" | awk '{print $2}' | tr -d '[:space:]')
        if [[ -n "$MTD" && "$MTD" -lt 1000 ]] 2>/dev/null; then
            log_warn "Config: max_time_diff=$MTD is too small (ms units). Updating to 300000 (5 min)..."
            sed -i "s/max_time_diff: $MTD/max_time_diff: 300000/" "$CONF_PATH/config.yaml"
            log_success "max_time_diff updated: $MTD -> 300000"
        fi
        # Always recompute checksum so server accepts the (possibly migrated) config
        "$BIN_PATH/whispera" update-checksum "$CONF_PATH/config.yaml" && log_info "Config checksum updated"
    fi

    log_info "Starting service..."
    systemctl start whispera

    sleep 3
    if ! systemctl is-active --quiet whispera; then
        log_err "Whispera service failed to start!"
        restore
    fi

    PUBLIC_KEY=$(cat "$CONF_PATH/server.pub" 2>/dev/null)
    SERVER_IP=$(get_public_ip)
    
    echo ""
    log_success "Whispera updated successfully!"
    echo -e "  Config:         ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    echo -e "  Web Interface:  ${GREEN}http://${SERVER_IP}:3000${PLAIN}"
    
    if [[ -n "$PUBLIC_KEY" ]]; then
        echo ""
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "${GREEN} CLIENT CONNECTION KEY                                          ${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
        echo -e "${BLUE}whispera://${SERVER_IP}:8443?pub=${PUBLIC_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome${PLAIN}"
        echo -e "${GREEN}================================================================${PLAIN}"
    fi
    echo ""
    
    if command -v ufw &>/dev/null; then
        ufw allow 3000/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=3000/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi

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
