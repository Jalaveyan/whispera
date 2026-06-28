<img width="5189" height="640" alt="logo2" src="https://github.com/user-attachments/assets/dbace4f7-b2f7-42d7-aec0-edacdf6688e2" />

### It is a fast, easy-to-use and easy-to-install censorship-bypassing proxy server disguised as a regular HTTPS connection and powered by built-in neural networks written in Go.

## Install and Update

### How to install? (Ubuntu/Debian/Arch) ( only root )

```bash
bash <(curl -sL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh)
```

### How to update?

```bash
bash menu
```

Select item 18

### Create keys, subscriptions, and view all keys

This is for creating a key

```bash
whispera create-key -user <your_username> -port <your_port> -sni <realdomain>
```

Available options

```
-user <name> required — username (login via Whispera Auth)

-port <port> required — dedicated listening port for this user

-transport whispera|grpc|yadisk (default: whispera)

-quic enable/disable tunneling over QUIC instead of TCP

-quic-port <port> dedicated QUIC port (0 = reuse shared port)

-yadisk-token <token> Yandex.Disk OAuth token (YADISK transport only)

-yadisk-session <id> Yandex.Disk session/folder ID (automatically generated if empty)

-neural enable/disable RL agents + GAN seeding for this user
```

This is for creating a sub

```bash
whispera generate-sub -name "" -users <john, ...> 
```

This allows you to view all keys

```bash
whispera view-keys
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

## If you need a cascade, I recommend using this instruction

Install a whispera on each relay

```bash
curl -sSL https://raw.githubusercontent.com/Jalaveyan/Whispera/main/install.sh | bash -s -- relay
```

Whispera secret (copy to master):
```bash
a1b2c3...== # this is an example
```

Open the config

```bash
nano /etc/whispera/config.yaml
```

Add outbounds on the master - /etc/whispera/config.yaml

```bash
outbounds:
  - tag: relay1
    protocol: whispera
    address: IP_RELAY1:443
    settings:
      whispera_secret: "SECRET_RELAY1"

  - tag: relay2
    protocol: whispera
    address: IP_RELAY2:443
    settings:
      whispera_secret: "SECRET_RELAY2"

  - tag: exit
    protocol: whispera
    address: IP_EXIT:443
    settings:
      whispera_secret: "SECRET_EXIT"
    chain: ["relay1", "relay2"]
```

Next command data

```bash
update checksum and restart
whispera update-checksum /etc/whispera/config.yaml
systemctl restart whispera
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

## License

Licensed under GNU AGPL v3.0.
