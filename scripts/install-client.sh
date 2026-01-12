#!/bin/bash
# =============================================================================
# Whispera One-Line Installer
# Usage: curl -sSL https://yourserver.com/install.sh | bash
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
echo "║                   WHISPERA INSTALLER                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    armv7l) ARCH="arm" ;;
esac

echo "Detected: $OS/$ARCH"

# Installation directory
INSTALL_DIR="${INSTALL_DIR:-$HOME/.whispera}"
BIN_DIR="$INSTALL_DIR/bin"
CONFIG_DIR="$INSTALL_DIR"

mkdir -p "$BIN_DIR"

# Download URL (change to your server)
BASE_URL="${WHISPERA_DOWNLOAD_URL:-https://github.com/yourrepo/whispera/releases/latest/download}"

echo ""
echo -e "${YELLOW}[1/4] Downloading Whispera client...${NC}"

# Download client
CLIENT_URL="$BASE_URL/whispera-client-$OS-$ARCH"
if [ "$OS" = "darwin" ]; then
    CLIENT_URL="$BASE_URL/whispera-client-darwin-$ARCH"
fi

# Try curl, then wget
if command -v curl &> /dev/null; then
    curl -sSL "$CLIENT_URL" -o "$BIN_DIR/whispera-client" 2>/dev/null || {
        echo -e "${YELLOW}Download from URL failed, building from source...${NC}"
    }
elif command -v wget &> /dev/null; then
    wget -q "$CLIENT_URL" -O "$BIN_DIR/whispera-client" 2>/dev/null || true
fi

# If download failed and go is available, build from source
if [ ! -f "$BIN_DIR/whispera-client" ] || [ ! -s "$BIN_DIR/whispera-client" ]; then
    if command -v go &> /dev/null; then
        echo -e "${YELLOW}Building from source...${NC}"
        
        TMP_DIR=$(mktemp -d)
        cd "$TMP_DIR"
        
        # Clone and build
        git clone --depth 1 https://github.com/yourrepo/whispera.git 2>/dev/null || {
            echo -e "${YELLOW}Using local source if available...${NC}"
        }
        
        if [ -d whispera ]; then
            cd whispera
            CGO_ENABLED=0 go build -o "$BIN_DIR/whispera-client" ./cmd/client
        fi
        
        cd - > /dev/null
        rm -rf "$TMP_DIR"
    fi
fi

chmod +x "$BIN_DIR/whispera-client" 2>/dev/null || true

echo -e "${GREEN}✓ Client installed${NC}"

echo -e "${YELLOW}[2/4] Creating configuration...${NC}"

# Create default config
cat > "$CONFIG_DIR/client_config.yaml" << 'EOF'
# Whispera Client Configuration
# Edit server and psk values, or use quick-connect with a key

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

echo -e "${GREEN}✓ Config created${NC}"

echo -e "${YELLOW}[3/4] Creating quick-connect script...${NC}"

cat > "$BIN_DIR/whispera-connect" << 'SCRIPT'
#!/bin/bash
# Whispera Quick Connect

KEY=""
if [ -n "$1" ]; then
    KEY="$1"
elif [ -n "$WHISPERA_KEY" ]; then
    KEY="$WHISPERA_KEY"
elif [ -f "$HOME/.whispera/key.txt" ]; then
    KEY=$(cat "$HOME/.whispera/key.txt")
fi

if [ -z "$KEY" ]; then
    echo "Usage: whispera-connect 'whispera://...'"
    echo "Or set WHISPERA_KEY or create ~/.whispera/key.txt"
    exit 1
fi

exec "$HOME/.whispera/bin/whispera-client" -key "$KEY" "$@"
SCRIPT

chmod +x "$BIN_DIR/whispera-connect"

echo -e "${GREEN}✓ Quick-connect script created${NC}"

echo -e "${YELLOW}[4/4] Setting up PATH...${NC}"

# Add to PATH
SHELL_RC=""
if [ -n "$ZSH_VERSION" ] || [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.profile" ]; then
    SHELL_RC="$HOME/.profile"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "WHISPERA" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# Whispera VPN" >> "$SHELL_RC"
        echo "export PATH=\"\$HOME/.whispera/bin:\$PATH\"" >> "$SHELL_RC"
        echo -e "${GREEN}✓ Added to PATH in $SHELL_RC${NC}"
    else
        echo -e "${GREEN}✓ Already in PATH${NC}"
    fi
fi

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                   INSTALLATION COMPLETE!                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Installed to: $INSTALL_DIR"
echo ""
echo "Quick Start:"
echo "  1. Save your connection key:"
echo "     echo 'whispera://...' > ~/.whispera/key.txt"
echo ""
echo "  2. Connect:"
echo "     whispera-connect"
echo ""
echo "  3. Or connect with key directly:"
echo "     whispera-connect 'whispera://server:port?key=...&pub=...'"
echo ""
echo "Reload your shell or run: source $SHELL_RC"
