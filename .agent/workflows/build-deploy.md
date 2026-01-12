---
description: Build and deploy Whispera (server, client, Tauri)
---

# Whispera Build & Deploy Workflow

## Prerequisites
- Go 1.21+
- Node.js 18+ (for Tauri)
- Rust/Cargo (for Tauri)

## Quick Build (All Components)

// turbo-all
1. Build everything with one command:
```bash
# Linux/macOS
./build.sh

# Windows
build.bat
```

## Manual Build Steps

### Server
// turbo
2. Build server:
```bash
go build -o build/server/whispera-server ./cmd/server
```

### Client
// turbo
3. Build client:
```bash
go build -o build/client/whispera-client ./cmd/client
```

### Windows Client
// turbo
4. Cross-compile for Windows:
```bash
GOOS=windows GOARCH=amd64 go build -o build/client/whispera-go-client.exe ./cmd/client
```

### Tauri Client
// turbo
5. Build Tauri:
```bash
cd client-package-tauri
npm install
npm run tauri build
```

## Deploy Server

// turbo
6. Copy server files:
```bash
scp -r build/server/* user@server:/opt/whispera/
```

// turbo
7. Start server:
```bash
ssh user@server 'cd /opt/whispera && ./whispera-server -config config.yaml'
```

## Quick Connect

8. Save connection key:
```bash
echo 'whispera://YOUR_SERVER:51820?key=PSK&pub=PUB&profile=vk' > ~/.whispera/key.txt
```

9. Connect:
```bash
whispera-connect
```

## Connection Key Format

Full format with all options:
```
whispera://server:port?key=PSK&pub=SERVER_PUB&profile=vk&phantom=1&sni=cloudflare.com&asn=1&tls=chrome
```

Parameters:
- `key` - Pre-shared key (required)
- `pub` - Server public key (required)
- `profile` - Behavioral profile: vk, telegram, instagram, max, wechat, facebook (default: vk)
- `phantom` - Enable Phantom protocol: 0|1 (default: 0)
- `sni` - SNI for Phantom (default: cloudflare.com)
- `asn` - Enable ASN bypass: 0|1 (default: 0)
- `tls` - TLS fingerprint: chrome, firefox, safari (default: chrome)
- `transport` - Transport mode: auto, tcp, udp (default: auto)
