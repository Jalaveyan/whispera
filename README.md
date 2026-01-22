## License

This project is licensed under the GNU AGPL v3.0.
Commercial use without compliance with AGPL is prohibited.

It is important to note that this project is intended for technically advanced users only and is not recommended for general use.

# Whispera
Stealth-transport

## Quick Start (Linux)
The easiest way to install Whispera on Linux is via the automated installer:
```bash
git clone https://github.com/Jalaveyan/Whispera.git
cd Whispera
bash install.sh
```

## Menu (Linux)
Сall menu:
```bash
bash menu
```

## Use Warp (Linux)
If you want to use warp, you need to follow these steps:
```bash
Install warp through the menu
Add to /etc/whispera/config.yaml :
relay:
  upstream_proxy: "socks5://127.0.0.1:40000"
systemctl restart whispera
warp-cli status
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
