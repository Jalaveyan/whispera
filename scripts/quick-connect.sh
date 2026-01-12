#!/bin/bash
# =============================================================================
# Whispera Quick Connect for Linux/macOS
# Place your connection key in key.txt or set WHISPERA_KEY env var
# =============================================================================

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                   WHISPERA QUICK CONNECT                       ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Find connection key
KEY=""

# 1. Command line argument
if [ -n "$1" ]; then
    KEY="$1"
# 2. Environment variable
elif [ -n "$WHISPERA_KEY" ]; then
    KEY="$WHISPERA_KEY"
# 3. Local key.txt
elif [ -f "./key.txt" ]; then
    KEY=$(cat ./key.txt)
# 4. Home directory
elif [ -f "$HOME/.whispera/key.txt" ]; then
    KEY=$(cat "$HOME/.whispera/key.txt")
fi

if [ -z "$KEY" ]; then
    echo "Usage: $0 'whispera://server:port?key=...&pub=...'"
    echo ""
    echo "Or create ~/.whispera/key.txt with your connection key"
    echo "Or set WHISPERA_KEY environment variable"
    exit 1
fi

# Find client binary
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT=""

for path in \
    "${SCRIPT_DIR}/whispera-client" \
    "${SCRIPT_DIR}/../whispera-client" \
    "/usr/local/bin/whispera-client" \
    "/opt/whispera/bin/whispera-client" \
    "$HOME/.whispera/bin/whispera-client"; do
    if [ -x "$path" ]; then
        CLIENT="$path"
        break
    fi
done

if [ -z "$CLIENT" ]; then
    echo "ERROR: Whispera client not found!"
    echo "Install it to /usr/local/bin/ or $HOME/.whispera/bin/"
    exit 1
fi

echo "Client: $CLIENT"
echo ""
echo -e "${GREEN}Connecting...${NC}"
echo ""

# Start client
exec "$CLIENT" -key "$KEY"
