#!/bin/bash


REPO_URL="https://github.com/Jalaveyan/Whispera.git"
BRANCH="main"
WORK_DIR="/opt/whispera"
DAT_PATH="/usr/local/share/whispera"
CONF_PATH="/etc/whispera"
BIN_PATH="/usr/local/bin"
LOG_PATH="/var/log/whispera"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PLAIN='\033[0m'


log_info() { echo -e "${BLUE}[INFO]${PLAIN} $1"; }
log_success() { echo -e "${GREEN}[OK]${PLAIN} $1"; }
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


install_dependencies() {
    log_info "Installing dependencies..."
    
    case $RELEASE in
        centos|fedora|almalinux|rocky)
            yum install -y curl git wget tar unzip openssl >/dev/null 2>&1
            ;;
        ubuntu|debian)
            apt-get update
            apt-get remove -y libnode-dev libnode72 nodejs npm || true
            dpkg --remove --force-all libnode-dev libnode72 || true
            apt-get autoremove -y || true
            apt-get install -y curl git wget tar unzip openssl nano jq bc net-tools
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
            apt-get install -y nodejs
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
    
    if command -v timedatectl &>/dev/null; then
        log_info "Synchronizing system time..."
        timedatectl set-ntp on || true
    fi
    
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
    export PATH=$PATH:$HOME/go/bin
    
    if ! grep -q '/usr/local/go/bin' /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
        echo 'export PATH=$PATH:$HOME/go/bin' >> /etc/profile
    fi
    
    log_success "Go installed: $GO_V"
}

setup_bbr() {
    log_info "Enabling BBR TCP congestion control..."
    
    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        log_info "BBR already enabled"
        return
    fi
    
    local KERNEL_VER=$(uname -r | cut -d. -f1-2)
    local KERNEL_MAJOR=$(echo $KERNEL_VER | cut -d. -f1)
    local KERNEL_MINOR=$(echo $KERNEL_VER | cut -d. -f2)
    
    if [[ $KERNEL_MAJOR -lt 4 ]] || [[ $KERNEL_MAJOR -eq 4 && $KERNEL_MINOR -lt 9 ]]; then
        log_warn "Kernel $KERNEL_VER too old for BBR (requires 4.9+), skipping"
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
        log_warn "BBR enable failed, kernel may not support it"
    fi
}

setup_warp() {
    log_info "Setting up Cloudflare WARP..."

    # Install warp-cli if not present
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

    # Connect if not already connected
    if ! warp-cli status 2>/dev/null | grep -q "Connected"; then
        # Support both old and new warp-cli syntax
        if warp-cli registration new &>/dev/null; then
            warp-cli mode proxy 2>/dev/null || true
        else
            warp-cli --accept-tos register 2>/dev/null || true
            warp-cli set-mode proxy 2>/dev/null || true
        fi
        warp-cli connect 2>/dev/null || true
        # Wait up to 15s for connection
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
EOF

    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    sleep 2

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        log_success "Fail2ban installed and running"
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
        alpine)
            apk add redis >/dev/null 2>&1
            ;;
        *)
            log_warn "Redis installation not supported on $RELEASE"
            return
            ;;
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
    
    sleep 1
    
    if redis-cli ping 2>/dev/null | grep -q "PONG"; then
        log_success "Redis installed and running on 127.0.0.1:6379"
        
        echo ""
        log_info "To enable Redis in Whispera, add to config.yaml:"
        echo "  cache:"
        echo "    redis_url: \"redis://127.0.0.1:6379\""
    else
        log_warn "Redis installed but not responding"
    fi
}

setup_postgres() {
    log_info "Setting up PostgreSQL..."
    
    if command -v psql &>/dev/null && systemctl is-active --quiet postgresql 2>/dev/null; then
        if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
            log_success "PostgreSQL already installed with whispera database"
            log_info "Connection: postgresql://whispera@localhost/whispera"
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
        alpine)
            apk add postgresql >/dev/null 2>&1
            ;;
        *)
            log_warn "PostgreSQL installation not supported on $RELEASE"
            return
            ;;
    esac
    
    if ! command -v psql &>/dev/null; then
        log_warn "PostgreSQL installation failed"
        return
    fi
    
    systemctl enable postgresql >/dev/null 2>&1
    systemctl start postgresql >/dev/null 2>&1
    
    sleep 2
    
    local PG_CONF_DIR=""
    for dir in /etc/postgresql/*/main /var/lib/pgsql/data /var/lib/postgresql/*/data; do
        if [[ -f "$dir/pg_hba.conf" ]]; then
            PG_CONF_DIR="$dir"
            break
        fi
    done
    
    if [[ -z "$PG_CONF_DIR" ]]; then
        PG_CONF_DIR=$(sudo -u postgres psql -t -c "SHOW config_file" 2>/dev/null | xargs dirname 2>/dev/null)
    fi
    
    if [[ -n "$PG_CONF_DIR" ]] && [[ -f "$PG_CONF_DIR/pg_hba.conf" ]]; then
        log_info "Configuring pg_hba.conf for local TCP auth..."
        cp "$PG_CONF_DIR/pg_hba.conf" "$PG_CONF_DIR/pg_hba.conf.bak"
        
        if ! grep -q "whispera" "$PG_CONF_DIR/pg_hba.conf"; then
            sed -i '/^# IPv4 local connections/a host    whispera        whispera        127.0.0.1/32            scram-sha-256' "$PG_CONF_DIR/pg_hba.conf" 2>/dev/null || true
        fi
        
        if grep -q "^local.*all.*all.*peer" "$PG_CONF_DIR/pg_hba.conf"; then
            sed -i 's/^local\s\+all\s\+all\s\+peer/local   all             all                                     md5/' "$PG_CONF_DIR/pg_hba.conf"
        fi
        
        sed -i 's/^\(host\s\+all\s\+all\s\+127\.0\.0\.1\/32\s\+\)ident/\1scram-sha-256/' "$PG_CONF_DIR/pg_hba.conf" 2>/dev/null || true
        sed -i 's/^\(host\s\+all\s\+all\s\+::1\/128\s\+\)ident/\1scram-sha-256/' "$PG_CONF_DIR/pg_hba.conf" 2>/dev/null || true
        
        if grep -q "0\.0\.0\.0/0" "$PG_CONF_DIR/pg_hba.conf"; then
            sed -i '/0\.0\.0\.0\/0/d' "$PG_CONF_DIR/pg_hba.conf"
        fi
        
        log_success "pg_hba.conf: local-only password auth (no remote access)"
    fi
    
    if [[ -n "$PG_CONF_DIR" ]] && [[ -f "$PG_CONF_DIR/postgresql.conf" ]]; then
        if grep -q "^#listen_addresses" "$PG_CONF_DIR/postgresql.conf"; then
            sed -i "s/^#listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF_DIR/postgresql.conf"
        elif grep -q "^listen_addresses" "$PG_CONF_DIR/postgresql.conf"; then
            sed -i "s/^listen_addresses.*/listen_addresses = 'localhost'/" "$PG_CONF_DIR/postgresql.conf"
        fi
        
        log_success "postgresql.conf: listen_addresses = 'localhost' (secure)"
    fi
 
    systemctl restart postgresql >/dev/null 2>&1
    sleep 2
    
    local PG_PASS=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -p | head -c 32)
    
    sudo -u postgres psql <<EOF >/dev/null 2>&1
CREATE USER whispera WITH PASSWORD '$PG_PASS';
CREATE DATABASE whispera OWNER whispera;
GRANT ALL PRIVILEGES ON DATABASE whispera TO whispera;
\q
EOF
    
    mkdir -p "$CONF_PATH"
    cat > "$CONF_PATH/postgres.env" <<EOF
POSTGRES_USER=whispera
POSTGRES_PASSWORD=$PG_PASS
POSTGRES_DB=whispera
POSTGRES_URL=postgresql://whispera:$PG_PASS@localhost/whispera
EOF
    chmod 600 "$CONF_PATH/postgres.env"
    
    if command -v ufw &>/dev/null; then
        ufw deny 5432/tcp >/dev/null 2>&1 || true
    fi
    
    if sudo -u postgres psql -lqt 2>/dev/null | grep -q whispera; then
        log_success "PostgreSQL installed and configured (local-only)"
        log_info "Credentials saved to: $CONF_PATH/postgres.env"
        echo ""
        log_info "DBeaver: use SSH tunnel to connect securely"
        echo "  SSH Host:     $(get_public_ip)"
        echo "  SSH Port:     22"
        echo "  SSH User:     root"
        echo "  DB Host:      127.0.0.1"
        echo "  DB Port:      5432"
        echo "  DB Name:      whispera"
        echo "  DB User:      whispera"
        echo "  DB Password:  (see $CONF_PATH/postgres.env)"
    else
        log_warn "PostgreSQL installed but database creation failed"
    fi
}

setup_swap() {
    log_info "Setting up Swap..."
    
    if swapon --show | grep -q "/"; then
        log_info "Swap already exists"
        swapon --show
        return
    fi
    
    local SWAP_SIZE="2G"
    
    fallocate -l $SWAP_SIZE /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    
    sysctl vm.swappiness=10 >/dev/null 2>&1
    echo "vm.swappiness=10" >> /etc/sysctl.conf
    
    log_success "Swap $SWAP_SIZE created"
}

setup_sysctl() {
    log_info "Optimizing system settings..."
    
    cat >> /etc/sysctl.conf <<EOF

net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

fs.file-max = 1000000

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
EOF
    
    sysctl -p >/dev/null 2>&1
    
    cat >> /etc/security/limits.conf <<EOF
* soft nofile 1000000
* hard nofile 1000000
EOF
    
    log_success "System optimized"
}

setup_autoupdate() {
    log_info "Setting up auto-update..."
    
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

setup_ssh_hardening() {
    log_info "Hardening SSH..."
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak 2>/dev/null
    
    sed -i 's/#PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/#MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
    
    
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    
    log_success "SSH hardened (password auth disabled)"
    log_warn "Make sure you have SSH key access before logging out!"
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

if pg_dump -h localhost -U \$POSTGRES_USER -d \$POSTGRES_DB | gzip > "\$FILENAME"; then
    log "Backup created successfully: \$(du -h "\$FILENAME" | cut -f1)"
else
    log "Backup failed!"
    rm -f "\$FILENAME"
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

        local BRIDGE_TOKEN=$(cat "$CONF_PATH/bridge.token" 2>/dev/null)

        echo ""
        echo -e "${BLUE}╔${SEP}╗${PLAIN}"
        _row "          WHISPERA MANAGEMENT MENU"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  Web Panel:  https://${SRV_IP}:3000/"
        _row "  Config:     /etc/whispera/config.yaml"
        echo -e "${BLUE}╠${SEP}╣${PLAIN}"
        _row "  BRIDGE MANAGEMENT"
        _row " 19.  Show bridge token & install command"
        _row " 20.  Add bridge manually (enter IP + token)"
        _row " 21.  List registered bridges"
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
        _row " 18.  Reinstall     - Fresh install from GitHub"
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
            18) bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh) ;;
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
                    python3 -m json.tool 2>/dev/null || \
                    log_err "Failed to fetch bridges (is Whispera running?)"
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

clone_or_update_repo() {
    log_info "Setting up Whispera source code..."
    
    mkdir -p "$WORK_DIR"
    
    if [[ -d "$WORK_DIR/.git" ]]; then
        log_info "Repository exists, updating..."
        cd "$WORK_DIR"
        git fetch origin "$BRANCH" --quiet
        git reset --hard "origin/$BRANCH" --quiet
    else
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

install_obfuscation_tools() {
    log_info "Installing obfuscation tools..."
    
    export PATH=$PATH:/usr/local/go/bin
    
    if ! command -v garble &>/dev/null; then
        log_info "Installing garble..."
        go install mvdan.cc/garble@latest
    fi

    if ! command -v javascript-obfuscator &>/dev/null; then
        log_info "Installing javascript-obfuscator..."
        if ! command -v npm &>/dev/null; then
             case $RELEASE in
                ubuntu|debian) apt-get install -y npm ;;
                centos|fedora|almalinux|rocky) yum install -y npm ;;
                alpine) apk add npm ;;
            esac
        fi
        npm install -g javascript-obfuscator
    fi
    
    log_success "Obfuscation tools ready"
}

build_whispera() {
    log_info "Installing Whispera server..."
    
    cd "$WORK_DIR"
    export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin:/root/go/bin
    
    local ARCH="amd64"
    [[ $(uname -m) == "aarch64" ]] && ARCH="arm64"

    log_info "Checking for latest release on GitHub..."
    local RELEASE_JSON=$(curl -s https://api.github.com/repos/Jalaveyan/Whispera/releases/latest)
    local DOWNLOAD_URL=$(echo "$RELEASE_JSON" | grep "browser_download_url" | grep "whispera-server-linux-$ARCH.tar.gz" | head -n 1 | cut -d '"' -f 4)

    if [[ -n "$DOWNLOAD_URL" ]]; then
        log_info "Downloading binary from $DOWNLOAD_URL..."
        if curl -L -o whispera-server.tar.gz "$DOWNLOAD_URL"; then
            if tar -xzf whispera-server.tar.gz; then
                rm -f whispera-server.tar.gz
                
                if [[ -f "whispera-server" ]]; then
                    chmod +x whispera-server
                    cp whispera-server "$BIN_PATH/whispera"
                    chmod +x "$BIN_PATH/whispera"
                    log_success "Binary installed from GitHub Release"
                    return
                fi
            fi
        fi
        log_warn "Download failed or invalid archive, falling back to build from source..."
    else
        log_warn "No release found or API rate limit exceeded, building from source..."
    fi

    log_info "Building from source..."
    
    install_obfuscation_tools
    export CGO_ENABLED=0
    
    rm -f whispera-server
    
    if garble -literals -tiny -seed=random build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server 2>/dev/null; then
        log_success "Obfuscated build successful"
    else
        log_info "Garble build failed or not found, using standard Go build..."
        go build -trimpath -ldflags "-w -s" -o whispera-server ./cmd/server
    fi
    
    if [[ ! -f "whispera-server" ]]; then
        log_err "Build failed!"
        exit 1
    fi
    
    cp whispera-server "$BIN_PATH/whispera"
    chmod +x "$BIN_PATH/whispera"
    
    log_success "Binary installed to $BIN_PATH/whispera"
}

install_nodejs() {
    log_info "Installing Node.js..."
    
    if command -v node &>/dev/null; then
        local NODE_VER=$(node -v)
        if [[ "${NODE_VER}" > "v18" ]]; then
            log_info "Node.js already installed: $NODE_VER"
            return
        fi
    fi

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case $ID in
            ubuntu|debian)
                curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
                apt-get install -y nodejs >/dev/null 2>&1
                ;;
            centos|fedora|almalinux|rocky)
                curl -fsSL https://rpm.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
                yum install -y nodejs >/dev/null 2>&1
                ;;
            alpine)
                apk add nodejs npm >/dev/null 2>&1
                ;;
        esac
    fi
    
    log_success "Node.js installed"
}

setup_monitoring() {
    log_info "Setting up Monitoring (Prometheus + Grafana)..."

    if ! command -v docker &>/dev/null; then
        log_warn "Docker not found. Installing Docker..."
        curl -fsSL https://get.docker.com | sh
    fi

    if ! command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null; then
         log_warn "Docker Compose not found. Installing..."
         apt-get install -y docker-compose-plugin
    fi

    if [[ ! -d "$WORK_DIR/monitoring" ]]; then
        log_err "Monitoring configuration not found in $WORK_DIR/monitoring"
        return
    fi
    
    cd "$WORK_DIR/monitoring"
    
    log_info "Starting monitoring stack..."
    docker compose up -d || docker-compose up -d

    if [[ $? -eq 0 ]]; then
        log_success "Monitoring started!"
        echo ""
        log_info "Grafana: http://$(get_public_ip):3001 (admin/admin)"
        log_info "Prometheus: http://$(get_public_ip):9091"
    else
        log_err "Failed to start monitoring stack"
    fi
}

install_panel() {
    log_info "Installing Whispera Panel..."

    # Ensure Node.js runtime is available to run bundle/index.js
    install_nodejs
    
    local PANEL_SRC="$WORK_DIR/panel"
    local PANEL_DEST="$DAT_PATH/panel"

    log_info "Checking for pre-built Panel release..."
    local LATEST_TAG=$(curl -s "https://api.github.com/repos/Jalaveyan/Whispera/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    
    if [[ -n "$LATEST_TAG" ]]; then
        local PANEL_URL="https://github.com/Jalaveyan/Whispera/releases/download/${LATEST_TAG}/whispera-panel.tar.gz"
        
        if curl -L -f -o "/tmp/whispera-panel.tar.gz" "$PANEL_URL"; then
            log_info "Downloaded Panel release ${LATEST_TAG}"
            
            rm -rf "$PANEL_DEST"
            mkdir -p "$PANEL_DEST"
            
            tar -xzf "/tmp/whispera-panel.tar.gz" -C "$PANEL_DEST"
            rm -f "/tmp/whispera-panel.tar.gz"
            
            if [[ ! -f "$PANEL_DEST/.env" ]]; then
                cat > "$PANEL_DEST/.env" <<ENVEOF
BACKEND_URL=http://127.0.0.1:8080
PORT=3000
CORS_ORIGIN=*
ENVEOF
                log_info "Generated .env"
            fi

            if [[ ! -f "$PANEL_DEST/bundle/index.js" ]]; then
                log_warn "bundle/index.js not found in release — panel may not start"
            fi

            log_success "Panel installed from release"
            return
        else
            log_warn "Pre-built panel not found in release (will build from source)..."
            rm -f "/tmp/whispera-panel.tar.gz"
        fi
    fi
    
    if [[ ! -d "$PANEL_SRC" ]]; then
        log_warn "Panel source directory not found! Cloning..."
        cd /tmp
        rm -rf "$WORK_DIR"
        git clone -b test https://github.com/Jalaveyan/Whispera.git "$WORK_DIR"
    fi
    
    if [[ ! -d "$PANEL_SRC" ]]; then
        log_err "Failed to clone panel source!"
        return
    fi
    
    log_info "Building Panel..."
    cd "$PANEL_SRC"
    npm install --legacy-peer-deps
    
    export NODE_OPTIONS="--max-old-space-size=2048"
    npm run build
    
    if command -v javascript-obfuscator &>/dev/null; then
        log_info "Obfuscating Panel..."
        npm run obfuscate
    fi
    
    if [[ ! -d "dist" ]]; then
        log_err "Panel build failed!"
        exit 1
    fi
    
    mkdir -p "$PANEL_DEST"
    rm -rf "$PANEL_DEST"/*
    cp -r dist "$PANEL_DEST/"
    cp -r public "$PANEL_DEST/" 2>/dev/null || true
    cp package.json "$PANEL_DEST/"
    cp package-lock.json "$PANEL_DEST/" 2>/dev/null || true
    cp nest-cli.json "$PANEL_DEST/" 2>/dev/null || true
    
    cat > "$PANEL_DEST/.env" <<ENVEOF
BACKEND_URL=http://127.0.0.1:8080
PORT=3000
CORS_ORIGIN=*
ENVEOF
    
    cd "$PANEL_DEST"
    npm install --omit=dev --force
    

    log_success "Panel installed to $PANEL_DEST"
}

cleanup_source() {
    log_info "Cleaning up source code..."
    cd /
    rm -rf "$WORK_DIR"
    if [[ -d "$WORK_DIR" ]]; then
        log_warn "Failed to remove source directory"
    else
        log_success "Source code removed (Security)"
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

generate_bridge_token() {
    local TOKEN=$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | xxd -p | head -c 32)
    echo "$TOKEN"
}

setup_dns_discovery() {
    log_info "Setting up DNS discovery for bridges..."
    
    local SERVER_IP=$(get_public_ip)
    
    echo ""
    log_info "To enable automatic bridge discovery, add this DNS record:"
    echo ""
    echo -e "  ${GREEN}_whispera._tcp.yourdomain.com  SRV  0 0 8443 $SERVER_IP${PLAIN}"
    echo ""
    echo "  Or TXT record:"
    echo -e "  ${GREEN}whispera-server.yourdomain.com  TXT  \"$SERVER_IP:8443\"${PLAIN}"
    echo ""
    
    cat > "$CONF_PATH/dns-discovery.txt" <<EOF

_whispera._tcp.yourdomain.com  SRV  0 0 8443 $SERVER_IP

whispera-server.yourdomain.com  TXT  "$SERVER_IP:8443"

EOF
    
    log_success "DNS instructions saved to $CONF_PATH/dns-discovery.txt"
}

generate_config() {
    log_info "Generating configuration..."
    
    local PRIVATE_KEY=$(cat "$CONF_PATH/server.key" 2>/dev/null)
    
    if [[ -z "$PRIVATE_KEY" ]]; then
        generate_keys
        PRIVATE_KEY=$(cat "$CONF_PATH/server.key")
    fi
    
    local BRIDGE_TOKEN=$(generate_bridge_token)
    echo "$BRIDGE_TOKEN" > "$CONF_PATH/bridge.token"
    log_info "Bridge token generated: $BRIDGE_TOKEN"
    
    local PG_PASS=""
    if [[ -f "$CONF_PATH/postgres.env" ]]; then
        PG_PASS=$(grep POSTGRES_PASSWORD "$CONF_PATH/postgres.env" | cut -d= -f2)
    fi
    if [[ -z "$PG_PASS" ]]; then
         PG_PASS="whispera" 
    fi
    
    local ADMIN_PASS=$(openssl rand -hex 12 2>/dev/null || head -c 24 /dev/urandom | xxd -p | head -c 24)
    echo "$ADMIN_PASS" > "$CONF_PATH/admin.pass"
    chmod 600 "$CONF_PATH/admin.pass"

    if [[ -n "$PG_PASS" ]]; then
        log_info "Creating admin user in database..."
        if "$BIN_PATH/whispera" create-admin -email "admin" -password "$ADMIN_PASS" -db "postgresql://whispera:$PG_PASS@localhost/whispera" 2>/dev/null; then
            echo "$ADMIN_PASS" > "$CONF_PATH/admin.pass"
            chmod 600 "$CONF_PATH/admin.pass"
        else
            log_warn "Failed to create admin user in database (config.yaml fallback will be used)"
        fi
    else
        log_warn "Skipping admin creation (Postgres not configured)"
    fi
    
    cat > "$CONF_PATH/config.yaml" <<EOF
server:
  name: whispera-server
  listen_addr: "0.0.0.0:8443"
  private_key: "$PRIVATE_KEY"
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
    - "tamtam.chat"
    - "sberbank.ru"
    - "tinkoff.ru"
    - "yandex.ru"
    - "mail.ru"
    - "rambler.ru"
    - "ya.ru"
    - "vk.com"
    - "ok.ru"
    - "dzen.ru"
    - "max.ru"
    - "rutube.ru"
    - "ozon.ru"
    - "wildberries.ru"
    - "avito.ru"
    - "mos.ru"
    - "gosuslugi.ru"
  max_time_diff: 300000
  fingerprint: "chrome"
  enable_sni_rotation: true
  sni_rotation_interval: 900
  enable_cover_traffic: true

network:
  tun_name: "Whispera"
  tun_ip: "198.18.0.1"
  tun_mtu: 1420
  dns: "1.1.1.1"

relay:
  max_streams: 10000
  enable_tcp: true
  enable_udp: true

session:
  max_sessions: 10000
  idle_timeout: 300
  cleanup_interval: 60

metrics:
  enabled: true
  listen_addr: ":9090"
  path: "/metrics"

api:
  enabled: true
  listen_addr: ":8080"
  web_root: ""
  admin_username: "admin"
  admin_password: "$ADMIN_PASS"
  enable_cors: true
  login_rate_limit: 5

bridge:
  enabled: true
  registration_token: "$BRIDGE_TOKEN"
  auto_cleanup: true
  health_check_interval: 60

bot:
  enabled: false
  token: "YOUR_TELEGRAM_BOT_TOKEN"
  debug: false
  admin_id: 0
  monitor_admin_ids: []

notifications:
  enabled: false
  token: "YOUR_TELEGRAM_BOT_TOKEN"
  chat_id: ""

database:
  postgres_url: "postgresql://whispera:$PG_PASS@localhost/whispera"
  max_conns: 25
  min_conns: 5

cache:
  redis_url: "redis://127.0.0.1:6379"

EOF
    
    log_success "Config saved to $CONF_PATH/config.yaml"
}

generate_panel_cert() {
    local CERT="$CONF_PATH/panel.crt"
    local KEY="$CONF_PATH/panel.key"
    local SERVER_IP
    SERVER_IP=$(get_public_ip)

    if [[ -f "$CERT" && -f "$KEY" ]]; then
        log_info "Panel TLS cert already exists, skipping generation"
        return
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

setup_nginx_proxy() {
    local SERVER_IP
    SERVER_IP=$(get_public_ip)
    local CERT="$CONF_PATH/panel.crt"
    local KEY="$CONF_PATH/panel.key"

    # Install nginx if missing
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

    # Add whispera-ui to /etc/hosts
    if ! grep -q "whispera-ui" /etc/hosts; then
        echo "127.0.0.1 whispera-ui" >> /etc/hosts
        log_info "Added whispera-ui to /etc/hosts"
    fi

    # Write nginx config
    cat > /etc/nginx/sites-available/whispera-ui <<NGINX
server {
    listen 80;
    server_name whispera-ui ${SERVER_IP};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name whispera-ui ${SERVER_IP};

    ssl_certificate     ${CERT};
    ssl_certificate_key ${KEY};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass         http://127.0.0.1:3000;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$remote_addr;
        proxy_set_header   X-Forwarded-Host \$host;
        proxy_set_header   X-Forwarded-Proto https;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade \$http_upgrade;
        proxy_set_header   Connection "upgrade";
    }
}
NGINX

    # Enable site
    mkdir -p /etc/nginx/sites-enabled
    ln -sf /etc/nginx/sites-available/whispera-ui /etc/nginx/sites-enabled/whispera-ui

    # Disable default site if present
    rm -f /etc/nginx/sites-enabled/default

    # Open ports
    if command -v ufw &>/dev/null; then
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
    fi

    if nginx -t 2>/dev/null; then
        systemctl enable nginx >/dev/null 2>&1
        systemctl restart nginx
        log_success "Nginx reverse proxy configured: https://whispera-ui/"
    else
        log_warn "Nginx config test failed — check /etc/nginx/sites-available/whispera-ui"
    fi
}

setup_systemd() {
    log_info "Setting up SystemD services..."

    if ! id -u whispera &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin whispera
        log_info "Created system user 'whispera'"
    fi

    # Allow whispera user to manage UFW without password (for firewall panel)
    local UFW_BIN
    UFW_BIN=$(command -v ufw 2>/dev/null || echo /usr/sbin/ufw)
    echo "whispera ALL=(ALL) NOPASSWD: $UFW_BIN" > /etc/sudoers.d/whispera-ufw
    chmod 440 /etc/sudoers.d/whispera-ufw
    log_info "Configured sudo access for UFW"

    mkdir -p "$LOG_PATH"
    mkdir -p "$DAT_PATH/panel/public/uploads"
    chown -R whispera:whispera "$WORK_DIR" "$CONF_PATH" "$DAT_PATH" "$LOG_PATH" 2>/dev/null || true
    chmod 750 "$CONF_PATH"
    chmod 640 "$CONF_PATH/config.yaml" 2>/dev/null || true

    cat > /etc/systemd/system/whispera.service <<EOF
[Unit]
Description=Whispera Server (Backend)
Documentation=https://github.com/Jalaveyan/Whispera
After=network.target network-online.target
Requires=network-online.target

[Service]
User=whispera
Group=whispera
WorkingDirectory=$WORK_DIR
Environment=WHISPERA_MASK_LOGS=true
ExecStart=$BIN_PATH/whispera -config $CONF_PATH/config.yaml -api :8080
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$WORK_DIR $CONF_PATH $DAT_PATH /var/log/whispera /etc/ufw /lib/ufw /var/lib/ufw /run/ufw
StandardOutput=append:/var/log/whispera/whispera.log
StandardError=append:/var/log/whispera/whispera.log

[Install]
WantedBy=multi-user.target
EOF

    local NODE_BIN=$(command -v node || echo "/usr/bin/node")

    local PANEL_HTTPS_VARS=""

    cat > /etc/systemd/system/whispera-panel.service <<EOF
[Unit]
Description=Whispera Panel (Frontend)
After=network.target whispera.service

[Service]
User=whispera
Group=whispera
WorkingDirectory=$DAT_PATH/panel
ExecStart=$NODE_BIN bundle/index.js
Restart=always
RestartSec=3
Environment=PORT=3000
Environment=BACKEND_URL=http://127.0.0.1:8080
Environment=CORS_ORIGIN=*
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DAT_PATH
$PANEL_HTTPS_VARS

[Install]
WantedBy=multi-user.target
EOF

    # ── ML service — адаптивная установка под ресурсы сервера ───────────────
    local ML_SCRIPT="$WORK_DIR/internal/obfuscation/ml/ml_api_server.py"
    local PYTHON_BIN
    PYTHON_BIN=$(command -v python3 || command -v python || echo "")
    if [[ -n "$PYTHON_BIN" && -f "$ML_SCRIPT" ]]; then

        # Определяем ресурсы сервера
        local SRV_CORES SRV_RAMMB ML_PROFILE MEM_LIMIT RETRAIN_THRESH
        SRV_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
        SRV_RAMMB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print int($2/1024)}' || echo 1024)

        if   [[ $SRV_CORES -le 1 || $SRV_RAMMB -lt 2048 ]]; then
            ML_PROFILE="minimal";  MEM_LIMIT="256M"; RETRAIN_THRESH="200"
        elif [[ $SRV_CORES -ge 8 && $SRV_RAMMB -ge 8192 ]]; then
            ML_PROFILE="full";     MEM_LIMIT="1G";   RETRAIN_THRESH="1000"
        else
            ML_PROFILE="standard"; MEM_LIMIT="512M"; RETRAIN_THRESH="500"
        fi

        log_info "Server: ${SRV_CORES} core(s), ${SRV_RAMMB} MB RAM → ML profile: $ML_PROFILE"

        # Базовые зависимости (нужны всегда)
        $PYTHON_BIN -m pip install --quiet \
            fastapi uvicorn pydantic python-multipart \
            numpy "scikit-learn>=1.6.1,<1.7.0" scipy joblib 2>/dev/null || \
            log_warn "Some base ML deps failed to install"

        # ML inference backend
        if [[ "$ML_PROFILE" == "full" ]]; then
            # Мощный сервер: пробуем tensorflow-cpu (~600 MB)
            log_info "Installing tensorflow-cpu (full profile, may take a few minutes)..."
            $PYTHON_BIN -m pip install --quiet tensorflow-cpu 2>/dev/null || {
                log_warn "tensorflow-cpu failed — falling back to onnxruntime"
                $PYTHON_BIN -m pip install --quiet onnxruntime skl2onnx 2>/dev/null || true
            }
        else
            # Minimal/Standard: onnxruntime CPU (~60 MB, Python 3.9+)
            $PYTHON_BIN -m pip install --quiet onnxruntime skl2onnx 2>/dev/null || \
                log_warn "onnxruntime install failed — ML will use heuristics"
        fi

        # Обучаем ONNX-модели (нужны skl2onnx + sklearn)
        local TRAIN_SCRIPT="$WORK_DIR/ml_engine/train_onnx_models.py"
        if [[ -f "$TRAIN_SCRIPT" ]]; then
            log_info "Training ML models (profile: $ML_PROFILE)..."
            WHISPERA_ML_PROFILE="$ML_PROFILE" \
                $PYTHON_BIN "$TRAIN_SCRIPT" 2>/dev/null && \
                log_success "ML models trained" || \
                log_warn "ML model training failed — heuristics will be used"
        fi

        cat > /etc/systemd/system/whispera-ml.service <<EOF
[Unit]
Description=Whispera ML Server
After=network.target whispera.service
PartOf=whispera.service

[Service]
User=whispera
Group=whispera
WorkingDirectory=$WORK_DIR/internal/obfuscation/ml
ExecStart=$PYTHON_BIN $ML_SCRIPT
Restart=on-failure
RestartSec=10
Environment=WHISPERA_ML_PORT=8000
Environment=PYTHONPATH=$WORK_DIR/ml_engine
Environment=WHISPERA_ML_PROFILE=$ML_PROFILE
Environment=WHISPERA_ML_RETRAIN_THRESHOLD=$RETRAIN_THRESH
MemoryMax=$MEM_LIMIT
MemorySwapMax=0

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    systemctl enable whispera >/dev/null 2>&1
    systemctl enable whispera-panel >/dev/null 2>&1
    [[ -f /etc/systemd/system/whispera-ml.service ]] && systemctl enable whispera-ml >/dev/null 2>&1

    systemctl restart whispera
    log_success "Whispera service started"

    if systemctl restart whispera-panel 2>/dev/null; then
        log_success "Panel service started"
    else
        log_warn "Panel service not started (panel may not be installed yet — run option 18 later)"
    fi

    if [[ -f /etc/systemd/system/whispera-ml.service ]]; then
        if systemctl restart whispera-ml 2>/dev/null; then
            log_success "ML service started"
        else
            log_warn "ML service not started (install fastapi+uvicorn manually: pip3 install fastapi uvicorn)"
        fi
    fi
}

setup_network() {
    log_info "Configuring network..."
    
    if ! command -v iptables &>/dev/null; then
        log_info "Installing iptables..."
        apt-get update >/dev/null 2>&1
        apt-get install -y iptables >/dev/null 2>&1 || yum install -y iptables >/dev/null 2>&1
    fi
    
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    
    if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi
    
    local WAN_IF=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -n "$WAN_IF" ]] && command -v iptables &>/dev/null; then
        iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
        iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
        iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true
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
        ufw allow 80/tcp >/dev/null 2>&1 || true
        ufw allow 443/tcp >/dev/null 2>&1 || true
        ufw allow 3000/tcp >/dev/null 2>&1 || true
        ufw --force enable >/dev/null 2>&1 || true
        log_success "UFW configured"
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=8443/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=8443/udp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=80/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --permanent --add-port=3000/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_success "Firewalld configured"
    else
        log_warn "No firewall found, skipping"
    fi
}

show_connection_key() {
    local PUBLIC_KEY
    PUBLIC_KEY=$(cat "$CONF_PATH/server.pub" 2>/dev/null)
    if [[ -z "$PUBLIC_KEY" ]]; then
        log_warn "Public key not found at $CONF_PATH/server.pub — run 'keygen' first"
        return
    fi
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
case $1 in
    start) systemctl start whispera && systemctl start whispera-panel ;;
    stop) systemctl stop whispera && systemctl stop whispera-panel ;;
    restart) systemctl restart whispera && systemctl restart whispera-panel ;;
    status) systemctl status whispera whispera-panel ;;
    log|logs) journalctl -u whispera -u whispera-panel -f ;;
    config) ${EDITOR:-nano} /etc/whispera/config.yaml ;;
    key)
        PUBLIC_KEY=$(cat /etc/whispera/server.pub 2>/dev/null)
        SERVER_IP=$(curl -s https://api.ipify.org -m 5 2>/dev/null || echo "YOUR_IP")
        echo "whispera://${SERVER_IP}:8443?pub=${PUBLIC_KEY}&transport=tcp&phantom=1&sni=random_ru&asn=1&tls=chrome"
        ;;
    update)
        bash /opt/whispera/update.sh
        ;;
    menu|extras)
        bash /opt/whispera/update.sh extras
        ;;
    *) echo "Usage: whispera-mgmt {start|stop|restart|status|log|config|key|update|menu}" ;;
esac
EOF
    chmod +x "$BIN_PATH/whispera-mgmt"
    
    cat > "$BIN_PATH/menu" <<EOF
#!/bin/bash
bash /opt/whispera/update.sh extras
EOF
    chmod +x "$BIN_PATH/menu"
    
    cat > "$WORK_DIR/menu" <<EOF
#!/bin/bash
bash /opt/whispera/update.sh extras
EOF
    chmod +x "$WORK_DIR/menu"
    
    log_success "CLI wrapper installed (whispera-mgmt, menu)"
}

main() {
    check_root
    check_os
    print_logo
    
    install_dependencies
    install_go
    clone_or_update_repo
    build_whispera
    install_panel
    
    if [[ ! -f "$CONF_PATH/config.yaml" ]]; then
        generate_keys
        generate_config
    else
        log_info "Config exists, keeping current configuration"
    fi
    
    install_cli_wrapper
    setup_network
    setup_firewall
    generate_panel_cert
    setup_systemd
    setup_nginx_proxy
    
    local PG_PASS=""
    local ADMIN_PASS=""
    
    if [[ -f "$CONF_PATH/postgres.env" ]]; then
        PG_PASS=$(grep POSTGRES_PASSWORD "$CONF_PATH/postgres.env" | cut -d= -f2)
    fi
    if [[ -f "$CONF_PATH/admin.pass" ]]; then
        ADMIN_PASS=$(cat "$CONF_PATH/admin.pass")
    fi

    echo ""
    log_success "Whispera installed successfully!"
    echo ""
    echo -e "  Manage:         ${GREEN}whispera-mgmt${PLAIN}"
    echo -e "  Config:         ${GREEN}$CONF_PATH/config.yaml${PLAIN}"
    local SERVER_IP
    SERVER_IP=$(get_public_ip)
    echo -e "  Web Panel:      ${GREEN}https://whispera-ui/${PLAIN}"
    echo -e "  (или напрямую: ${GREEN}https://${SERVER_IP}:3000/${PLAIN})"
    echo -e "  ${YELLOW}Чтобы открыть панель по имени, добавьте на своём компьютере:${PLAIN}"
    echo -e "  ${GREEN}${SERVER_IP} whispera-ui${PLAIN}  → в файл /etc/hosts (Linux/Mac) или C:\\Windows\\System32\\drivers\\etc\\hosts (Windows)"
    echo -e "  ${YELLOW}(самоподписанный сертификат — в браузере нажмите «Продолжить»)${PLAIN}"
    echo ""
    echo -e "  ${YELLOW}Admin User:${PLAIN}     admin"
    echo -e "  ${YELLOW}Admin Password:${PLAIN} ${GREEN}$ADMIN_PASS${PLAIN}"
    echo ""
    echo -e "  ${YELLOW}DB Password:${PLAIN}    $PG_PASS"
    
    local BRIDGE_TOKEN=$(cat "$CONF_PATH/bridge.token" 2>/dev/null)
    if [[ -n "$BRIDGE_TOKEN" ]]; then
        echo ""
        echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${PLAIN}"
        echo -e "${BLUE}║              BRIDGE REGISTRATION TOKEN                        ║${PLAIN}"
        echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${PLAIN}"
        echo -e "  Token: ${GREEN}$BRIDGE_TOKEN${PLAIN}"
        echo ""
        echo -e "  Install bridge on other servers:"
        echo -e "  ${GREEN}curl -sL https://$(get_public_ip):8080/install-bridge.sh | bash -s -- $(get_public_ip):8443 $BRIDGE_TOKEN${PLAIN}"
    fi
    
    show_connection_key
    
    setup_dns_discovery
    
    show_extras_menu
}


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
        
        if ! grep -q "^  private_key:" "$CONF_PATH/config.yaml"; then
             log_info "Migrating config: ensuring private_key is in server section..."
             EXISTING_KEY=$(grep "private_key:" "$CONF_PATH/config.yaml" | head -n 1 | awk '{print $2}' | tr -d '"')
             [[ -z "$EXISTING_KEY" ]] && EXISTING_KEY=$(cat "$CONF_PATH/server.key" 2>/dev/null)
             
             if [[ -n "$EXISTING_KEY" ]]; then
                 sed -i "/listen_addr: \"0.0.0.0:8443\"/a \  private_key: \"$EXISTING_KEY\"" "$CONF_PATH/config.yaml"
                 log_success "Config successfully migrated"
             fi
        fi

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
    telegram)
        check_root
        setup_telegram
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
