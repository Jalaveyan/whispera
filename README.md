# Whispera

It is a fast, easy-to-use and easy-to-install censorship-bypassing proxy server disguised as a regular HTTPS connection and powered by built-in neural networks written in Go.

## Install and Update

### How to install? (Ubuntu/Debian/Arch)

```bash
sudo bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh)
```

### How to update?

```bash
bash menu
Select item 18
```

## Build from source

Requires Go 1.25+. Pure-Go cross-compile:

```bash
# Server (linux only)
CGO_ENABLED=0 go build -o whispera-server ./cmd/server

# Go client (windows/linux/macos/android)
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -o whispera-go-client ./cmd/client

# ML server (windows/linux/macos)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o whispera-ml-server ./cmd/mlserver
```
## Configuration example

```yaml
server:
    name: whispera-server
    listen_addr: 0.0.0.0:8443
    tun_name: tun0
    mtu: 1420
    workers: 8
    graceful_stop: 30000000000
    private_key: YOUR_PRIVATE_KEY
    uuid: ""
    public_url: ""
transport:
    udp:
        enabled: true
        listen_addr: :8443
        max_packet_size: 65535
        buffer_size: 4096
        workers: 8
    tcp:
        enabled: true
        listen_addr: :8443
    websocket:
        enabled: false
        listen_addr: :8080
        path: ""
    xhttp:
        enabled: false
        listen_addr: ""
        mode: ""
        max_concurrency: 0
session:
    max_sessions: 10000
    session_timeout: 86400000000000
    cleanup_interval: 60000000000
    keepalive_interval: 30000000000
    rekey_interval: 43200000000000
routing:
    rules_file: ""
    default_route: direct
    geo:
        enabled: false
        geoip_file: ""
        geosite_file: ""
        update_interval: 0
    dns:
        enabled: false
        upstream: ""
        fakeip_range: ""
obfuscation:
    enabled: true
    profile: default
    threat_level: 5
    padding:
        enabled: false
        min_size: 0
        max_size: 0
    chaff:
        enabled: false
        interval: 0
        min_size: 0
        max_size: 0
api:
    enabled: true
    listen_addr: :8080
    auth_token: YOUR_AUTH_TOKEN
    web_root: ""
    enable_cors: true
    allowed_origins: []
    tls_cert: ""
    tls_key: ""
    login_rate_limit: 5
metrics:
    enabled: true
    listen_addr: :9090
    path: /metrics
logging:
    level: info
    format: text
    output: stdout
    file: ""
relay:
    max_streams: 10000
    enable_tcp: true
    enable_udp: true
    debug: false
    upstream_proxy: ""
phantom:
    enabled: false
    dest: yandex.ru:443
    server_names:
        - tamtam.chat
        - sberbank.ru
        - tinkoff.ru
        - yandex.ru
        - mail.ru
        - rambler.ru
        - ya.ru
        - vk.com
        - ok.ru
        - dzen.ru
        - max.ru
        - rutube.ru
        - ozon.ru
        - wildberries.ru
        - avito.ru
        - mos.ru
        - gosuslugi.ru
    private_key: ""
    short_ids:
        - ""
    max_time_diff: 300000
    fingerprint: <your fingerprint>
    use_russian_service: false
    russian_service: ""
    enable_chat_fsm: false
    chat_fsm_cover_interval_sec: 0
chameleon:
    ### chameleon need a tls cert!!!
    enabled: true
    listen_addr: :9443
    tls_cert: /etc/whispera/panel.crt
    tls_key: /etc/whispera/panel.key
    domain: ""
    acme_dir: /var/lib/whispera/acme
    decoy_origin: ""
    gan_iface: ""
    gan_port: 0
    gan_max_padding: 0
    brutal_mbps: 0
inbounds:
    - tag: default-inbound
      protocol: whispera
      listen: 0.0.0.0
      port: 8443
      settings: {}
      stream_settings:
        network: tcp
        security: none
        tls:
            cert_file: ""
            key_file: ""
        phantom:
            dest: ""
            server_names: []
            private_key: ""
            short_ids: []
            max_time_diff: 0
            enable_obfuscation: false
            obfuscation_profile: ""
        ws:
            path: ""
        h2c:
            path: ""
      sniffing:
        enabled: false
        dest_override: []
outbounds: []
relay_mode: ""
upstream_server: ""
bridge:
    auto_register: false
    type: ""
    provider: ""
    region: ""
    registration_token: YOUR_REG_TOKEN
vk_relay:
    enabled: false
    mode: ""
    token: ""
    group_id: 0
    peer_id: 0
    server_mode: false
    stream_key: ""
stealth_mode: ""
cache:
    redis_url: redis://127.0.0.1:6379
database:
    postgres_url: "your link postgtes db"
    max_conns: 25
    min_conns: 5
notifications:
    enabled: false
    token: YOUR_TELEGRAM_BOT_TOKEN
    chat_id: ""
bot:
    enabled: false
    token: YOUR_TELEGRAM_BOT_TOKEN
    debug: false
    admin_id: 0
    monitor_admin_ids: []
nats:
    enabled: false
    url: ""
    prefix: ""
update:
    enabled: false
    manifest_url: ""
    public_key: ""
    channel: ""
    check_interval: 0
correlation:
    enabled: false
    padding: false
    jitter: false
    cover_traffic: false
    max_jitter_ms: 0
    cover_rate_ms: 0
    rate_bytes_per_sec: 0
sni_bypass:
    enabled: false
    mode: ""
    fragment_size: 0
    fingerprint: ""
ml:
    enabled: true
    server_url: https://127.0.0.1:8000
    listen_addr: ""
    token_file: ""
```

## If you need a cascade, I recommend using this instruction

Install a whisper on each relay

```bash
curl -sSL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh | bash -s -- relay
```

Generate a secret on each relay

```bash
whispera keygen # save key
```

Open the config

```bash
nano /etc/whispera/config.yaml
```

Add secret to the config of each relay

```bash
chameleon:
enabled: true
secret: "OUTPUT_KEYGEN_RELAY1" # base64 from step 2
# other fields (listen_addr, tls_cert, etc.) are already set

// update checksum and restart
whispera update-checksum /etc/whispera/config.yaml
systemctl restart whispera
```

Add outbounds on the master - /etc/whispera/config.yaml

```bash
outbounds:
  - tag: relay1
    protocol: whispera
    address: IP_RELAY1:443
    settings:
      chameleon_secret: "SECRET_RELAY1"

  - tag: relay2
    protocol: whispera
    address: IP_RELAY2:443
    settings:
      chameleon_secret: "SECRET_RELAY2"

  - tag: exit
    protocol: whispera
    address: IP_EXIT:443
    settings:
      chameleon_secret: "SECRET_EXIT"
    chain: ["relay1", "relay2"]

# update checksum and restart
# whispera update-checksum /etc/whispera/config.yaml
# systemctl restart whispera
```

Check

```bash
journalctl -u whispera -n 50 --no-pager
```

There should be something in the logs

```bash
Started outbound tunnel: relay1 (1.2.3.4:443)
Started outbound tunnel: relay2 (5.6.7.8:443)
Started outbound tunnel: exit (9.10.11.12:443)
```

## Supported platforms - windows, android, linux
Self-Hosting и
почему это база?
Self-Hosting или же самохостинг - ещё одно направление кибер безопасности: самохостинг даёт понимание того, как развернуть проект локально, внутри своего девайса.

Что это даёт? Безопасность!
• 127.0.0.1|::1 (loopback
interface) — это виртуальный сетевой интерфейс, полностью изолированный от физической сети. Пакеты, отправленные на localhost, никогда не покидают операционную систему. Они не доходят даже до сетевой карты.
Поэтому провайдер, сосед по
Wi-Fi и любой внешний злоумышленник не могут увидеть такой сервис.
Что происходит в Лас-Вегасе — остаётся в Лас-Вегасе.

﻿﻿Даже если ты запустишь сервис на 0.0.0.0 или на IP-адресе локальной сети (LAN:
192.168.0.0/16, 10.0.0.0/8 и т.д.), трафик всё равно не выходит за пределы твоего роутера.
Провайдер его не видит.

Важно понимать - self-hosting - не понацея и не делает вас полностью анонимным, ведь это невозможно.
Но, самохостинг даёт сильную поддержку для борьбы за свой суверенитет и так таковые права.
Ведь, даже если отключат интернет, localhost продолжит работать.

https://github.com/user-attachments/assets/232f6c88-75c4-4adf-938e-cf5cae795a89

https://t.me/ghostprovideroff
---

## License

Licensed under GNU AGPL v3.0.
