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

check_os() {
    if [[ ! -f /etc/os-release ]]; then
        log_err "Failed to check OS (missing /etc/os-release)"
        exit 1
    fi
    source /etc/os-release
    RELEASE="${ID:-}"

    case "$RELEASE" in
        ubuntu|debian|centos|fedora|almalinux|rocky|alpine|arch|manjaro|opensuse*|sles|mageia) ;;
        *)
            for like in ${ID_LIKE:-}; do
                case "$like" in
                    debian|ubuntu)          RELEASE="debian";   break ;;
                    rhel|fedora|centos)     RELEASE="rocky";    break ;;
                    suse|opensuse)          RELEASE="opensuse"; break ;;
                    arch)                   RELEASE="arch";     break ;;
                esac
            done
            ;;
    esac

    case "$RELEASE" in
        ubuntu|debian|centos|fedora|almalinux|rocky|alpine|arch|manjaro|opensuse*|sles|mageia)
            log_info "Detected OS: $RELEASE" ;;
        *)
            log_warn "Unrecognised OS '${ID:-unknown}' (ID_LIKE='${ID_LIKE:-}') — falling back to apt-get" ;;
    esac
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

setup_decoy_refresh() {
    if ! command -v wget &>/dev/null; then
        if command -v apt-get &>/dev/null; then apt-get install -y wget >/dev/null 2>&1
        elif command -v dnf &>/dev/null; then dnf install -y wget >/dev/null 2>&1
        elif command -v yum &>/dev/null; then yum install -y wget >/dev/null 2>&1
        elif command -v pacman &>/dev/null; then pacman -Sy --noconfirm wget >/dev/null 2>&1
        elif command -v zypper &>/dev/null; then zypper install -y wget >/dev/null 2>&1
        elif command -v apk &>/dev/null; then apk add wget >/dev/null 2>&1
        fi
    fi

    local default_sites="https://ria.ru/,https://lenta.ru/,https://www.rbc.ru/,https://www.kp.ru/,https://tass.ru/,\
https://www.gazeta.ru/,https://www.kommersant.ru/,https://www.vedomosti.ru/,https://www.fontanka.ru/,https://www.ng.ru/,\
https://www.rg.ru/,https://iz.ru/,https://life.ru/,https://www.vesti.ru/,https://www.interfax.ru/,\
https://yandex.ru/,https://mail.ru/,https://www.rambler.ru/,https://ok.ru/,https://go.mail.ru/,\
https://www.ozon.ru/,https://www.wildberries.ru/,https://www.avito.ru/,https://www.citilink.ru/,https://www.dns-shop.ru/,\
https://www.mvideo.ru/,https://www.eldorado.ru/,https://www.lamoda.ru/,https://www.sportmaster.ru/,https://leroymerlin.ru/,\
https://www.sberbank.ru/,https://www.vtb.ru/,https://alfabank.ru/,https://www.gazprombank.ru/,https://www.raiffeisen.ru/,\
https://sovcombank.ru/,https://www.gosuslugi.ru/,https://www.nalog.gov.ru/,https://www.mos.ru/,https://www.gibdd.ru/,\
https://hh.ru/,https://auto.ru/,https://www.cian.ru/,https://www.drom.ru/,https://www.kinopoisk.ru/,\
https://2gis.ru/,https://www.eapteka.ru/,https://www.dixy.ru/,https://www.perekrestok.ru/,https://www.pochta.ru/"
    local sites="${WHISPERA_DECOY_SITES:-$default_sites}"
    local interval="${WHISPERA_DECOY_REFRESH_INTERVAL:-1d}"

    cat > /usr/local/bin/whispera-refresh-decoy.sh <<REFRESHEOF
#!/bin/bash
DECOY_DIR="/var/www/whispera-decoy"
SITES="\${WHISPERA_DECOY_SITES:-$sites}"
IFS=',' read -ra SITE_ARR <<< "\$SITES"
N=\${#SITE_ARR[@]}
[[ \$N -eq 0 ]] && exit 0

command -v wget &>/dev/null || exit 0

MAX_ATTEMPTS=8
[[ \$MAX_ATTEMPTS -gt \$N ]] && MAX_ATTEMPTS=\$N

for ((attempt=0; attempt<MAX_ATTEMPTS; attempt++)); do
    PICK="\${SITE_ARR[\$((RANDOM % N))]}"
    TMP_DIR=\$(mktemp -d)
    wget --quiet --page-requisites --convert-links --adjust-extension \\
        --span-hosts --no-parent --no-host-directories \\
        --timeout=15 --tries=1 -e robots=off \\
        -P "\$TMP_DIR" "\$PICK" 2>/dev/null
    if [[ ! -f "\$TMP_DIR/index.html" ]]; then
        first_html=\$(find "\$TMP_DIR" -maxdepth 1 -name '*.html' | head -n1)
        [[ -n "\$first_html" ]] && cp "\$first_html" "\$TMP_DIR/index.html"
    fi
    if [[ -f "\$TMP_DIR/index.html" ]]; then
        rm -rf "\$DECOY_DIR"
        mkdir -p "\$(dirname "\$DECOY_DIR")"
        mv "\$TMP_DIR" "\$DECOY_DIR"
        logger -t whispera-decoy "refreshed from \$PICK" 2>/dev/null || true
        exit 0
    fi
    rm -rf "\$TMP_DIR"
done

mkdir -p "\$DECOY_DIR"
if [[ ! -f "\$DECOY_DIR/index.html" ]]; then
    cat > "\$DECOY_DIR/index.html" <<'DECOYHTML'
<!doctype html><html><head><title>Welcome</title></head><body><h1>It works.</h1></body></html>
DECOYHTML
fi
REFRESHEOF
    chmod +x /usr/local/bin/whispera-refresh-decoy.sh

    if command -v systemctl &>/dev/null; then
        cat > /etc/systemd/system/whispera-decoy-refresh.service <<'EOF'
[Unit]
Description=Refresh Whispera nginx decoy backend content

[Service]
Type=oneshot
ExecStart=/usr/local/bin/whispera-refresh-decoy.sh
EOF
        cat > /etc/systemd/system/whispera-decoy-refresh.timer <<EOF
[Unit]
Description=Periodically refresh Whispera decoy backend content

[Timer]
OnBootSec=10min
OnUnitActiveSec=${interval}
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload >/dev/null 2>&1
        systemctl enable --now whispera-decoy-refresh.timer >/dev/null 2>&1
        log_success "Decoy refresh timer installed (every ${interval}, randomized up to 6h)"
    fi
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

_enable_whispera_in_config() {
    local cfg="${CONF_PATH}/config.yaml"
    [[ -f "$cfg" ]] || return

    if grep -q "^chameleon:" "$cfg"; then
        awk '
            /^chameleon:[[:space:]]*$/ { skip=1; next }
            skip && /^[^[:space:]]/ { skip=0 }
            skip { next }
            { print }
        ' "$cfg" > "$cfg.tmp" && mv "$cfg.tmp" "$cfg"
        log_info "Removed stale chameleon: config block (superseded by whispera:)"
    fi

    local decoy_first="${WHISPERA_DECOY_SITES%%,*}"
    decoy_first="${decoy_first:-https://ria.ru/}"
    local decoy_origin="${decoy_first%%/}"

    if grep -q "^whispera:" "$cfg"; then
        sed -i '/^whispera:/,/^[^ ]/{s/enabled: false/enabled: true/}' "$cfg"
        local cur_domain
        cur_domain=$(awk '/^whispera:/{f=1} f && /^[[:space:]]+domain:/{print $2; exit}' "$cfg" | tr -d '"')
        if [[ -n "$cur_domain" ]]; then
            refresh_config "$cfg"
            log_success "Whispera enabled in config.yaml (autocert domain=$cur_domain, tls_cert untouched)"
            return
        fi
        local cur_decoy
        cur_decoy=$(awk '/^whispera:/{f=1} f && /decoy_origin:/{print $2; exit}' "$cfg" | tr -d '"')
        if [[ -z "$cur_decoy" ]]; then
            python3 - "$cfg" "$decoy_origin" <<'PYEOF'
import sys, re
path, origin = sys.argv[1], sys.argv[2]
with open(path) as f:
    text = f.read()
def patch_block(m):
    blk = m.group(0)
    if 'decoy_origin:' not in blk:
        blk = blk.rstrip('\n') + f'\n  decoy_origin: "{origin}"\n'
    return blk
text = re.sub(r'^whispera:.*?(?=\n\S|\Z)', patch_block, text, flags=re.S|re.M)
with open(path, 'w') as f:
    f.write(text)
PYEOF
            log_info "Whispera: decoy_origin set to $decoy_origin (TLS cert will be auto-cloned from it on first start)"
        fi
    else
        printf '\nwhispera:\n  enabled: true\n  listen_addr: ":443"\n  tls_cert: ""\n  tls_key: ""\n  domain: ""\n  acme_dir: "/var/lib/whispera/acme"\n  decoy_origin: "%s"\n' \
            "${decoy_origin}" >> "$cfg"
    fi
    if command -v ufw &>/dev/null; then
        ufw allow 443/tcp >/dev/null 2>&1 || true
    elif command -v firewall-cmd &>/dev/null; then
        firewall-cmd --permanent --add-port=443/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
    fi
    refresh_config "$cfg"
    log_success "Whispera enabled in config.yaml"
}
