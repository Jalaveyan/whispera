#!/bin/bash
# =============================================================================
# Whispera Full Build Script
# Builds server, client, and Tauri client in one command
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    WHISPERA BUILD SYSTEM                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
VERSION=$(git describe --tags --always 2>/dev/null || echo "dev")

# Create build directory
mkdir -p "${BUILD_DIR}"/{server,client,tauri}

echo -e "${YELLOW}[1/5] Building Go Server...${NC}"
cd "${PROJECT_DIR}"
CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o "${BUILD_DIR}/server/whispera-server" ./cmd/server
echo -e "${GREEN}✓ Server built${NC}"

echo -e "${YELLOW}[2/5] Building Go Client...${NC}"
CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o "${BUILD_DIR}/client/whispera-client" ./cmd/client
echo -e "${GREEN}✓ Client built${NC}"

echo -e "${YELLOW}[3/5] Building Go Client for Windows...${NC}"
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=${VERSION}" -o "${BUILD_DIR}/client/whispera-go-client.exe" ./cmd/client
echo -e "${GREEN}✓ Windows client built${NC}"

echo -e "${YELLOW}[4/5] Copying Web Panel...${NC}"
cp -r "${PROJECT_DIR}/web" "${BUILD_DIR}/server/"
echo -e "${GREEN}✓ Web panel copied${NC}"

echo -e "${YELLOW}[5/5] Building Tauri Client...${NC}"
if command -v cargo &> /dev/null && [ -d "${PROJECT_DIR}/client-package-tauri" ]; then
    cd "${PROJECT_DIR}/client-package-tauri"
    
    # Copy Go client to Tauri bin
    mkdir -p src-tauri/bin
    cp "${BUILD_DIR}/client/whispera-go-client.exe" src-tauri/bin/ 2>/dev/null || true
    
    # Build Tauri (if npm installed)
    if command -v npm &> /dev/null; then
        npm install 2>/dev/null || true
        npm run tauri build 2>/dev/null || echo "Tauri build skipped (run manually)"
    fi
    echo -e "${GREEN}✓ Tauri prepared${NC}"
else
    echo -e "${YELLOW}⚠ Tauri skipped (cargo not found)${NC}"
fi

cd "${PROJECT_DIR}"

# Create default configs
echo -e "${YELLOW}Creating default configs...${NC}"

cat > "${BUILD_DIR}/server/config.yaml" << 'EOF'
# Whispera Server Configuration
server:
  listen: ":51820"
  listen_tcp: ":51821"

# Security
security:
  psk: "CHANGE_ME_RANDOM_32_BYTES_BASE64"
  
# API Server
api:
  enabled: true
  listen: ":8080"
  web_root: "./web"

# Obfuscation (VK Messenger default)
obfuscation:
  enabled: true
  profile: "vk"
  
# Phantom Protocol
phantom:
  enabled: true
  dest: "cloudflare.com:443"
  server_names: ["cloudflare.com"]
EOF

cat > "${BUILD_DIR}/client/client_config.yaml" << 'EOF'
# Whispera Client Configuration
server: "YOUR_SERVER:51820"
psk: "YOUR_PSK"
server_pub: "YOUR_SERVER_PUB"

# SOCKS5 Proxy
socks:
  enabled: true
  address: "127.0.0.1"
  port: 1080

# Obfuscation (VK Messenger by default)
obfuscation:
  enabled: true
  profile: "vk"

# Phantom Protocol
phantom:
  enabled: true
  sni: "cloudflare.com"

# ASN Bypass
asn_bypass:
  enabled: true
  tls_fingerprint: "chrome"
EOF

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    BUILD COMPLETE!                            ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Server:  ${BUILD_DIR}/server/whispera-server"
echo -e "Client:  ${BUILD_DIR}/client/whispera-client"
echo -e "Windows: ${BUILD_DIR}/client/whispera-go-client.exe"
echo ""
echo -e "${BLUE}Version: ${VERSION}${NC}"
