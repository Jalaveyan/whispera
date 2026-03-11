# Whispera
**Stealth-transport** protocol & VPN server designed to bypass DPI censorship.
Masquerades as legitimate HTTPS traffic. Includes a Web Admin Panel for management.

---

### 🚀 **Installation**
```bash
bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh)
```

### 🔄 **Update**
Update the server and panel to the latest version.
```bash
bash menu
Select item 18
```

### 🌐 **Admin Panel**
Monitor traffic and manage users via web interface.
- **URL:** `http://YOUR_SERVER_IP:3000`

*(Configuration file: `/etc/whispera/config.yaml`)*

---

## 🛠️ **CLI Management**

**Installation Menu:**
```bash
bash menu
```

**Service Commands (`whispera-mgmt`):**
- `whispera-mgmt status`   - Check server status
- `whispera-mgmt start`    - Start the service
- `whispera-mgmt stop`     - Stop the service
- `whispera-mgmt restart`  - Restart the service
- `whispera-mgmt log`      - View live logs
- `whispera-mgmt config`   - Edit configuration

## ⚖️ License
Licensed under GNU AGPL v3.0. Intended for advanced users.
