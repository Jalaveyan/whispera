# Whispera

**Stealth-transport** protocol & VPN server designed to bypass DPI censorship.
Masquerades as legitimate HTTPS traffic with ML-driven obfuscation, multi-transport architecture, and bridge network.

---

## Features

- **30+ transport protocols** — TCP, UDP, QUIC, WebSocket, HTTP Upgrade, Split HTTP, Snowflake, TUIC, WireGuard-like, VK WebRTC, Telegram Bot, Yandex Cloud/Disk/Telemost, TOR SOCKS, ASN Bypass, SNI Bypass
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
- **Kubernetes ready** — Helm chart with HPA, PVC, ConfigMap, Secrets
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

---

## Configuration

Config file: `/etc/whispera/config.yaml`

### Example 1: Basic server with HTTPS masquerade

```yaml
listen: ":8080"
protocol: tcp
encryption:
  method: aes-256-gcm
tls:
  enabled: true
  sni: "cdn.example.com"
  fingerprint: chrome
obfuscation:
  enabled: true
  profile: websocket
  marionette:
    enabled: true
    active_profile: telegram
api:
  enabled: true
  listen_addr: ":8081"
  admin_username: admin
  admin_password: "your-secure-password"
modules:
  handshake:
    enabled: true
  tunnel:
    enabled: true
  metrics:
    enabled: true
    listen_addr: ":9090"
```

### Example 2: Bridge mode with VK WebRTC transport and ML evasion

```yaml
listen: ":8080"
protocol: vkwebrtc
bridge:
  auto_register: true
  upstream_server: "main-server.example.com:8081"
  registration_token: "your-bridge-token"
  type: white
  provider: hetzner
  region: eu-central
encryption:
  method: chacha20-poly1305
obfuscation:
  enabled: true
  profile: vk
  marionette:
    enabled: true
    active_profile: vk
    ml_enabled: true
    correlation_defense:
      enabled: true
      constant_rate_pps: 100
      padding_enabled: true
      delay_jitter: 50ms
tls:
  enabled: true
  fingerprint: chrome
  sni_bypass:
    enabled: true
    fragment_size: 41
transport:
  vkwebrtc:
    vk_token: "your-vk-token"
    vk_group_id: "your-group-id"
    signaling_mode: vk
    ice_policy: relay
    num_tracks: 3
modules:
  handshake:
    enabled: true
  tunnel:
    enabled: true
  bridge_agent:
    heartbeat_interval: 30s
    metrics_interval: 60s
```

---

## Admin Panel

Access: `http://YOUR_SERVER_IP:3000`

Features:
- User management (add/edit/delete, traffic limits, plans)
- Bridge registry (register, health status, white/community types, SSH key management)
- Traffic statistics and session monitoring
- Routing rules and outbound management
- Inbound configuration with key generation
- Firewall management
- Configuration editor with live reload
- Backup and restore
- System info and logs

---

---

## CLI Management

**Service commands (`whispera-mgmt`):**
- `whispera-mgmt status`   — Check server status
- `whispera-mgmt start`    — Start the service
- `whispera-mgmt stop`     — Stop the service
- `whispera-mgmt restart`  — Restart the service
- `whispera-mgmt log`      — View live logs
- `whispera-mgmt config`   — Edit configuration

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

---

## License

Licensed under GNU AGPL v3.0.
