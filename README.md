Важно что данный проект только для технически подготовленных пользователей и с обычным использованием лезть во внутрь не рекомендуется

# Whispera
VPN-туннель

## Quick Start (Linux)
The easiest way to install Whispera on Linux is via the automated installer:
```bash
bash install.sh
```

## Menu (Linux)
call menu:
```bash
bash menu
```

### Management
After installation, you can manage the server using the `whispera-mgmt` command:
- `whispera-mgmt status`   - Check server status
- `whispera-mgmt start`    - Start the service
- `whispera-mgmt stop`     - Stop the service
- `whispera-mgmt restart`  - Restart the service
- `whispera-mgmt log`      - View live logs
- `whispera-mgmt config`   - Edit configuration

Configuration is stored in `/etc/whispera/config.yaml`.

## Manual Build
If you prefer to build from source manually:
```bash
# Build
go build -o whispera-server ./cmd/server
go build -o whispera-client ./cmd/client

# Run Server
./whispera-server -listen :51820

# Run Client
./whispera-client -server your-server.com:51820
```
