# Whispera

**Stealth-transport** protocol & VPN server designed to bypass DPI censorship.
Masquerades as legitimate HTTPS traffic with ML-driven obfuscation, multi-transport architecture, and bridge network.

---

## Features

- **15+ transport protocols** — TCP, UDP, QUIC, WebSocket, HTTP Upgrade, Split HTTP, Snowflake, TUIC, WireGuard-like, VK WebRTC, Telegram Bot, Yandex Cloud/Disk/Telemost, TOR SOCKS, ASN Bypass, SNI Bypass
- **Marionette obfuscation** — behavioral mimicry of real messengers (Telegram, VK, WhatsApp, WeChat, Facebook, Instagram) with full chat protocol state machine (typing, sending, read receipts, feed scrolling, media viewing)
- **ML-driven DPI evasion** — neural network that analyzes traffic patterns, detects DPI probes, and auto-switches obfuscation profiles
- **Bridge network** — distributed bridge pool with health monitoring, per-user bridge discovery, automatic rotation, white/community bridge types
- **16KB SNI bypass** — TLS ClientHello fragmentation to bypass SNI-based filtering
- **TLS fingerprint protection** — uTLS with Chrome/Firefox/Safari/iOS/Android fingerprints, JA3/JA4 spoofing
- **Correlation attack protection** — constant-rate padding, delay jitter, cover traffic generation
- **JWT auth with roles** — admin/operator/user/bridge roles, refresh tokens, MFA/TOTP
- **mTLS bridge authentication** — mutual TLS with auto-generated CA, certificate pinning
- **Bridge agent** — heartbeat, system metrics (CPU/RAM/bandwidth), config polling, update delivery
- **Signed updates** — ed25519 binary signing, checksum verification, atomic replace with rollback
- **NATS message bus** — distributed event architecture (drop-in replacement for in-process EventBus)
- **Disaster recovery** — automatic snapshots, restore, health checks
- **Chaos testing** — fault injection engine for bridge resilience testing
- **Admin panel** — web UI for user management, bridge registry, traffic stats, routing rules, firewall, backups
- **Whisp desktop client** — Tauri 2.0 app with interactive bridge map, click-to-connect

---

## Installation

### Quick install (Ubuntu/Debian)

```bash
bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh)
```

The installer will:
1. Install Go, build the server binary
2. Generate config at `/etc/whispera/config.yaml`
3. Generate encryption keys
4. Create systemd service `whispera`
5. Set up the admin panel on port 3000
6. Optionally configure WARP, Telegram proxy, fail2ban

### Update

```bash
bash menu
Select item 18
```

### Docker

```bash
docker-compose up -d
```

### Kubernetes (Helm)

```bash
helm install whispera deploy/helm/whispera \
  --set config.adminPassword=YOUR_PASSWORD \
  --set postgresql.auth.postgresPassword=DB_PASSWORD
```

### Build from source

Requires Go 1.25+. Pure-Go cross-compile (no CGO needed):

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

CI builds all five desktop targets (`x86_64-pc-windows-msvc`,
`{x86_64,aarch64}-unknown-linux-gnu`, `{x86_64,aarch64}-apple-darwin`)
plus Android arm64 — see [`.github/workflows/release.yml`](.github/workflows/release.yml).

---

## Configuration

Config file: `/etc/whispera/config.yaml` (default path on installed systems).
Schema: [`internal/modules/config/config.go`](internal/modules/config/config.go).
Live reload — the server watches the file and re-applies changes without
restart (see [Live reconfiguration](#live-reconfiguration) below).

> Run `whispera update-checksum /etc/whispera/config.yaml` after manual edits;
> `install.sh` and the panel do this automatically.

### Example 1 — minimal TCP server with phantom masquerade

The default profile produced by `install.sh`. Single inbound, server hides
behind the chosen `dest` (a real popular HTTPS site); active probes get
forwarded to it transparently.

```yaml
server:
  name: whispera-server
  listen_addr: "0.0.0.0:8443"
  private_key: "<32-byte X25519 base64 — generate with: whispera x25519>"
  mtu: 1420
  workers: 8

inbounds:
  - tag: "tcp-phantom"
    protocol: "whispera"
    listen: "0.0.0.0"
    port: 8443
    stream_settings:
      network: "tcp"
      security: "none"
      phantom:
        dest: "yandex.ru:443"
        server_names: ["yandex.ru", "mail.ru", "vk.com", "ok.ru", "sberbank.ru"]
        private_key: "<same as server.private_key>"
        short_ids: ["", "0123456789abcdef"]

phantom:
  enabled: true
  dest: "yandex.ru:443"
  fingerprint: "chrome"

api:
  enabled: true
  listen_addr: ":8080"
  admin_username: "admin"
  admin_password: "<set me>"

metrics:
  enabled: true
  listen_addr: ":9090"
  path: "/metrics"
```

### Example 2 — multi-port TCP + WebSocket on the same server

Two inbounds on different ports; clients pick whichever transport survives
their network. Same private key reused — phantom auth is keyed at the server,
not per-inbound.

```yaml
server:
  name: whispera-edge
  private_key: "<X25519 base64>"

inbounds:
  - tag: "tcp-phantom"
    protocol: "whispera"
    listen: "0.0.0.0"
    port: 8443
    stream_settings:
      network: "tcp"
      phantom:
        dest: "yandex.ru:443"
        server_names: ["yandex.ru", "vk.com", "mail.ru"]
        private_key: "<same>"
        short_ids: ["", "deadbeef"]

  - tag: "ws-phantom"
    protocol: "whispera"
    listen: "0.0.0.0"
    port: 8444
    stream_settings:
      network: "websocket"
      ws:
        path: "/ws"
      phantom:
        dest: "yandex.ru:443"
        server_names: ["yandex.ru", "vk.com", "mail.ru"]
        private_key: "<same>"
        short_ids: ["", "deadbeef"]

transport:
  udp:
    enabled: true
    listen_addr: ":8443"
    workers: 16
```

### Example 3 — ChatFSM live obfuscation (messenger imitation on the wire)

After phantom auth completes, the data stream is wrapped in a chat-protocol
framing layer that emits typing/presence/keep-alive cover frames between real
payload, with periodic profile swaps (VK ↔ Telegram ↔ Spotify) driven by the
ML profiler. Static-profile DPI signatures stop working.

```yaml
phantom:
  enabled: true
  dest: "yandex.ru:443"
  enable_chat_fsm: true
  chat_fsm_cover_interval_sec: 30

obfuscation:
  enabled: true
  profile: "default"
  threat_level: 5
  padding:
    enabled: true
    min_size: 16
    max_size: 64
  chaff:
    enabled: true
    interval: 30s
    min_size: 32
    max_size: 128

ml:
  enabled: true
  server_url: "http://127.0.0.1:8000"
  listen_addr: ":8000"
```

The client side must set `phantom.enable_chat_fsm: true` to match.

### Example 4 — bridge node (hides the main server)

Bridge accepts users, forwards encrypted traffic to the upstream control
plane, and registers itself in the bridge pool for ML-driven selection.

```yaml
server:
  name: "bridge-eu-1"
  private_key: "<X25519 base64>"

inbounds:
  - tag: "tcp-phantom"
    protocol: "whispera"
    listen: "0.0.0.0"
    port: 8443
    stream_settings:
      network: "tcp"
      phantom:
        dest: "yandex.ru:443"
        server_names: ["yandex.ru", "vk.com"]
        private_key: "<same>"
        short_ids: [""]

bridge:
  auto_register: true
  type: "white"            # or "community"
  provider: "hetzner"
  region: "eu-central"
  registration_token: "<token from main server panel>"

upstream_server: "control.example.com:8443"
relay_mode: "bridge"
```

Generate a registration token in the panel under **Bridges → Add bridge**
or via `POST /api/bridges/token` on the main server's API.

### Example 5 — Discord/voice low-latency tunnel

Optimised for real-time UDP traffic — small fragments, low jitter buffer,
ChaCha20 cipher (cheaper on mobile CPUs than AES-GCM without hardware AES).

```yaml
server:
  name: "voice-edge"
  private_key: "<X25519 base64>"

transport:
  udp:
    enabled: true
    listen_addr: ":51820"
    max_packet_size: 1400
    buffer_size: 2097152
    workers: 16

inbounds:
  - tag: "udp-direct"
    protocol: "whispera"
    listen: "0.0.0.0"
    port: 51820
    stream_settings:
      network: "udp"

session:
  max_sessions: 10000
  session_timeout: 30m
  cleanup_interval: 1m
  keepalive_interval: 15s
```

Phantom is intentionally disabled for the voice path — added handshake RTT
hurts call setup. Use Example 1 in parallel for non-voice traffic.

### Example 6 — server→server chain (multi-hop egress)

Daisy-chain two or more Whispera servers so client traffic exits at the
last hop. Each `outbound` references the previous hop in its `chain` field;
the dataplane composes them transparently. Cycles are rejected at load time.

On the **entry** server (the one clients connect to), declare both the
intermediate hop and the exit, where exit routes through the intermediate:

```yaml
server:
  name: "entry-ru"
  private_key: "<X25519 base64>"

inbounds:
  - tag: "in"
    protocol: "whispera"
    listen: "0.0.0.0"
    port: 8443
    stream_settings:
      network: "tcp"
      phantom:
        enabled: true
        server_names: ["www.gosuslugi.ru"]

outbounds:
  - tag: "mid"
    protocol: "whispera"
    address: "mid.example.com:8443"
    settings:
      server_pub_key: "<mid X25519 pubkey>"
      sni: "www.cloudflare.com"

  - tag: "exit"
    protocol: "whispera"
    address: "exit.example.com:8443"
    chain: ["mid"]
    settings:
      server_pub_key: "<exit X25519 pubkey>"
      sni: "www.cloudflare.com"
```

Both `mid` and `exit` run vanilla Whispera servers (any of Examples 1-3 will
do); only the entry node needs the chain wiring. To extend to three hops add
`outbound: { tag: "exit", chain: ["mid2"] }` and a separate
`outbound: { tag: "mid2", chain: ["mid"] }` — each link references the one
before it. The cycle detector in [internal/modules/dataplane/outbound.go](internal/modules/dataplane/outbound.go)
will refuse a configuration that would loop back on itself.

### Client transport whitelist / blacklist

Operators can constrain which dial candidates the client races, useful when
the local network blocks specific protocols (UDP egress closed, no DNS over
HTTPS, etc.) or when forbidding privacy-sensitive paths (Tor/Snowflake) in a
managed deployment. Both lists are by transport name (the prefix before `:`
for compound names like `russian:gosuslugi`):

```yaml
server: "vpn.example.com:8443"
transport: "auto"

transport_whitelist:
  - "tcp"
  - "websocket"
  - "quic"

transport_blacklist:
  - "snowflake"
  - "tor"
```

Whitelist (when non-empty) keeps only listed transports; blacklist removes
matches afterward. Empty lists disable filtering. Filter is applied in
`Manager.applyTransportPolicy` after the regular candidate build, so the
existing `transport: "tcp,quic"` shorthand still works on top of it.

### Configuration reference

Top-level sections (all optional unless noted):

| Section          | Purpose                                                       |
| ---------------- | ------------------------------------------------------------- |
| `server`         | Identity, private key, TUN, workers (required)                |
| `inbounds[]`     | Listeners (network/security/phantom/ws stream settings)       |
| `transport`      | Per-protocol tuning (udp/tcp/websocket/xhttp)                 |
| `phantom`        | Top-level Reality-style auth + chat-FSM toggle                |
| `obfuscation`    | Padding, chaff, threat_level                                  |
| `bridge`         | Auto-register as a bridge under a control plane               |
| `relay`          | Relay-mode tuning (`max_streams`, enable_tcp/udp)             |
| `session`        | Limits, timeouts, keepalive                                   |
| `api`            | Panel/REST listener, admin creds                              |
| `metrics`        | Prometheus exporter                                           |
| `ml`             | ML profiler URL/listen addr, token file                       |
| `bot`            | Telegram bot token + admin IDs                                |
| `notifications`  | Telegram notifier (separate from `bot`)                       |
| `database`       | PostgreSQL DSN + pool sizes                                   |
| `cache`          | Redis URL                                                     |
| `nats`           | NATS URL for distributed event bus                            |
| `update`         | Signed-update poll URL + ed25519 pubkey                       |
| `correlation`    | Constant-rate padding for correlation-attack defence          |
| `sni_bypass`     | TLS ClientHello fragmentation                                 |
| `vk_relay`       | VK WebRTC video transport (TURN over `calls.okcdn.ru`)        |
| `outbounds[]`    | Egress routes (default = direct)                              |

For the full list of fields per section, see
[`config.go`](internal/modules/config/config.go) — every YAML tag corresponds
1:1 to a struct field.

---

## CLI

The `whispera` binary doubles as a service and a toolbox.

### Server management (systemd wrapper, installed by `install.sh`)

| Command                  | Action                  |
| ------------------------ | ----------------------- |
| `whispera-mgmt status`   | Service status          |
| `whispera-mgmt start`    | Start the service       |
| `whispera-mgmt stop`     | Stop the service        |
| `whispera-mgmt restart`  | Restart                 |
| `whispera-mgmt log`      | Tail journald logs      |
| `whispera-mgmt config`   | `$EDITOR` on config.yaml |
| `whispera-mgmt menu`     | Interactive TUI menu    |

### `whispera` subcommands (run as a CLI)

```bash
whispera x25519
# → Prints a fresh X25519 keypair (use Private as `server.private_key`)

whispera pubkey <private_key_base64>
# → Derives the public key from a private key

whispera create-admin -email a@b -password '...' -db postgres://...
# → Inserts (or updates) an admin user in the panel DB

whispera update-checksum [/path/to/config.yaml]
# → Refreshes the integrity checksum after manual edits

whispera wiraid <subcommand>
# → Pluggable-module CLI (install/list/enable/start/validate)
#   See: pkg/wiraid/README.md
```

### Common operational recipes

Generate a new server identity and put it into config:

```bash
KEYS=$(whispera x25519)
PRIV=$(echo "$KEYS" | awk '/^Private/ {print $3}')
sed -i "s|^  private_key:.*|  private_key: \"$PRIV\"|" /etc/whispera/config.yaml
whispera update-checksum /etc/whispera/config.yaml
systemctl restart whispera
```

Install and enable a third-party transport (e.g. xray-client) via wiraid:

```bash
whispera wiraid install ./examples/wiraid/xray-client
whispera wiraid enable xray-client
whispera wiraid list
```

Promote a connected user to admin:

```bash
whispera create-admin \
  -email user@example.com -password 'newpass' \
  -db "$(awk '/postgres_url/ {gsub(/"/,"",$2); print $2}' /etc/whispera/config.yaml)"
```

---

## Admin Panel

Default URL after install: `https://<server-ip>:3000` (self-signed cert,
generated automatically by `install.sh`). Login with the `admin_username`/
`admin_password` from `api:` section.

Features:
- User management (add/edit/delete, traffic limits, plans, ChatFSM toggle)
- Bridge registry (register, health, white/community types, SSH key mgmt)
- Traffic statistics and active-session monitoring
- Routing rules and outbound management
- Inbound editor with one-click key generation
- Firewall (UFW + fail2ban) management
- Configuration editor with **live reload** (no service restart)
- Backup and restore (snapshots to `/var/lib/whispera/backups/`)
- System info, journald log viewer
- wiraid module browser (install / enable / start third-party transports)

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Whisp App  │────▶│  Bridge Pool │────▶│  Internet   │
│  (Client)   │     │  (Bridges)   │     │             │
└─────────────┘     └──────────────┘     └─────────────┘
                           │
                    ┌──────┴──────┐
                    │ Control     │
                    │ Plane       │
                    ├─────────────┤
                    │ API Server  │
                    │ Bridge Reg  │
                    │ JWT Auth    │
                    │ NATS Events │
                    │ Updater     │
                    └─────────────┘
```

### Live reconfiguration

Anything user-visible in the obfuscation layer (messenger profile, cover
cadence, FSM state, foreground/background) is changeable on an open
connection without re-handshaking. Profile updates from the panel or YAML
watcher are broadcast to every live `ChatFSMConn` via
[`marionette.BroadcastSetProfile`](internal/obfuscation/marionette/registry.go).
This makes static-profile DPI signatures impossible — the tunnel can migrate
from VK→Spotify→Telegram mid-session in response to ML-detected classifier
pressure.

---

## Pluggable transports — wiraid

Whispera can install and run arbitrary third-party transport binaries
(xray, sing-box, hysteria2, brook, cloak, trojan-go, naive, gost, mieru,
v2ray, …) through the **wiraid** module system. A module is a
`module.json` manifest plus a binary; the engine handles install,
config rendering, port allocation, and pairing of client↔server sides.

```bash
whispera wiraid install ./examples/wiraid/xray-client
whispera wiraid enable xray-client
whispera wiraid list
```

Full docs and manifest schema: [`pkg/wiraid/README.md`](pkg/wiraid/README.md).
Ready-to-install examples: [`examples/wiraid/`](examples/wiraid/).

---

## Project layout

```
cmd/
  server/        # whispera-server (VPN + control plane)
  client/        # whispera-go-client (used by Whisp desktop)
  mlserver/      # whispera-ml-server (Gorgonia DPI classifier)
internal/
  modules/       # transports, phantom, tunnel, bridge, bot, panel
  obfuscation/   # marionette (chat FSM), behavioral profiles, evasion
  core/          # interfaces, base module, registry, container
  bridgepool/    # bridge ranking + ML selection
  proxyagent/    # transport selection (UCB)
  relay/         # P2P client↔client whitelist bypass
pkg/
  wiraid/        # pluggable module runtime (see pkg/wiraid/README.md)
panel/           # admin web UI (Node/Vue)
deploy/          # Helm charts, systemd units
examples/wiraid/ # ready-to-install module manifests
```

Companion repo [Jalaveyan/Whisp](https://github.com/Jalaveyan/Whisp) — Tauri
2.0 desktop client with cross-platform CI (Windows / Linux / macOS Intel +
Apple Silicon / Android).

---

## Development

```bash
go test ./...                  # full test suite
go vet ./...
go build ./...                 # cross-cutting build check
```

Cross-compile sanity check for all release targets:

```bash
# Server (linux-only — uses Netfilter / TUN)
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
    go build -o /dev/null ./cmd/server
done

# Client + ML server (windows/linux/macos)
for combo in "windows amd64" "linux amd64" "linux arm64" \
             "darwin amd64" "darwin arm64"; do
  read -r os arch <<<"$combo"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch \
    go build -o /dev/null ./cmd/client ./cmd/mlserver
done
```

---

## License

Licensed under GNU AGPL v3.0.
