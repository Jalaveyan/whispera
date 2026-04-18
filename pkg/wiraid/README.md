# wiraid

Pluggable module runtime for Whispera. Lets the server install, configure, and
launch arbitrary transport binaries (xray, sing-box, hysteria2, brook, …) from a
single declarative manifest, without code changes.

A module = a directory with `module.json` + a binary (or build instructions).
The Engine handles install, config rendering, port allocation, lifecycle, and
exposes the result over both an HTTP API (panel/bot) and a `wiraid_id`-based
pairing endpoint (clients fetch ready-to-use config).

## Quickstart

Author a new module interactively:

```bash
whispera wiraid new xray-client --dir ./examples/wiraid/xray-client
```

Install from a Git URL or local directory:

```bash
whispera wiraid install ./examples/wiraid/xray-client
whispera wiraid enable xray-client
whispera wiraid list
```

Validate a manifest without installing:

```bash
whispera wiraid validate --manifest ./module.json
whispera wiraid validate --live xray-client   # dry start/stop with mock binary
```

## Manifest (`module.json`)

Minimum fields:

```json
{
  "schema": 2,
  "module": {
    "name": "xray-client",
    "version": "0.1.0",
    "lang": "binary",
    "platforms": ["linux-x86_64"]
  },
  "capabilities": { "transport": true },
  "runtime": {
    "cmd": ["{binary}", "run", "-c", "{config_path}"],
    "config_template": "{...JSON template with {params.x} placeholders...}",
    "config_path": "config.json",
    "protocol": "socks5",
    "port_discovery": { "mode": "fixed" },
    "ready_signal": { "mode": "tcp_connect", "timeout_ms": 5000 }
  },
  "params_schema": {
    "server_host": { "type": "string", "required": true },
    "uuid":        { "type": "string", "required": true }
  }
}
```

Template placeholders the Engine substitutes at start time:

| Token              | Meaning                                                     |
| ------------------ | ----------------------------------------------------------- |
| `{binary}`         | Absolute path to the module binary                          |
| `{config_path}`    | Rendered config file path                                   |
| `{listen_host}`    | Always `127.0.0.1`                                          |
| `{listen_port}`    | Auto-allocated free port                                    |
| `{server_host}`    | `WHISPERA_PUBLIC_HOST` env                                  |
| `{params.<name>}`  | Value from `params_schema` (CLI/wizard/install fills these) |

`port_discovery` modes: `fixed` (use `{listen_port}`), `regex` (parse stdout),
`file` (read written port file).

`ready_signal` modes: `delay`, `tcp_connect`, `stdout_match`, `health_http`.

### Pairing API (`uri` + `peer`)

Two-sided modules (e.g. xray-client ↔ xray-server) declare:

```json
"module": {
  "wiraid_id": "xray-client",
  "peer": { "id": "xray-server", "min_version": "0.1.0" },
  "uri": {
    "schemes": ["vless"],
    "userinfo_to": "uuid",
    "host_to": "server_host",
    "port_to": "server_port",
    "query_map": { "sni": "sni", "pbk": "public_key" }
  }
}
```

The server-side module exposes its URI via `pair_exports`; the client fetches
it from `GET /api/wiraid/public/uri/<wiraid_id>` and parses it through the `uri`
spec into local `params`. No manual config copy.

## HTTP API

Mounted by `Engine.RegisterRoutes(handle)`:

| Route                                | Use                                  |
| ------------------------------------ | ------------------------------------ |
| `GET  /api/wiraid/list`              | All installed modules + status       |
| `POST /api/wiraid/install`           | `{"url": "..."}`                     |
| `POST /api/wiraid/uninstall`         | `{"name": "..."}`                    |
| `POST /api/wiraid/enable`            | `{"name": "...", "enabled": true}`  |
| `POST /api/wiraid/start`             | `{"name": "...", "upstream_port":N}` |
| `POST /api/wiraid/stop`              | `{"name": "..."}`                    |
| `POST /api/wiraid/rebuild`           | `{"name": "..."}`                    |
| `GET  /api/wiraid/status`            | Lightweight running list             |
| `GET  /api/wiraid/public/list`       | Public pairing-eligible modules      |
| `GET  /api/wiraid/public/uri/<id>`   | Server-issued URI for client pairing |
| `GET  /api/wiraid/public/pair/<id>`  | Full pair config blob                |

## Environment

| Var                          | Default                         | Notes                                |
| ---------------------------- | ------------------------------- | ------------------------------------ |
| `WHISPERA_WIRAID_DIR`        | `/var/lib/whispera/wiraid`      | Module install root                  |
| `WHISPERA_WIRAID_SYSTEMD`    | `0`                             | Set `1` to launch via systemd-run    |
| `WHISPERA_PUBLIC_HOST`       | (unset)                         | Used in `{server_host}` and pairing  |

## Examples

See [`../../examples/wiraid/`](../../examples/wiraid/) for ready-to-install
manifests covering xray (vless/vmess), sing-box, hysteria2, brook, cloak,
trojan-go, naive, gost, mieru, v2ray (client + server pairs).

The JSON Schema for `module.json` lives at
[`../../examples/wiraid/module.schema.json`](../../examples/wiraid/module.schema.json).
