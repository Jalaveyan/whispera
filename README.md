# Whispera

VPN-туннель

## Сборка и запуск

```bash
# Сборка
go build -o whispera-server.exe ./cmd/server
go build -o whispera-client.exe ./cmd/client

# Сервер
./whispera-server.exe -listen :51820

# Клиент
./whispera-client.exe -server your-server.com:51820
```
