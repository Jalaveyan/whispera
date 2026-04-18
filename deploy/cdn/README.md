# Whispera behind a CDN

Whispera can be fronted by **any** WebSocket-capable CDN or reverse proxy.
The CDN terminates TLS and hides the origin IP; Whispera speaks WebSocket
(`stream_settings.network: "websocket"`) to the edge.

This folder contains ready-made configs for several providers. Pick one:

| Provider                  | Path                  | Free tier?            | Notes                                  |
|---------------------------|-----------------------|-----------------------|----------------------------------------|
| Cloudflare Workers        | `cloudflare/`         | 100k req/day          | Rewrites ClientHello — incompatible with phantom |
| Fastly Compute            | `fastly/`             | Trial only            | Full TCP passthrough via Spectrum      |
| Nginx / self-hosted       | `nginx/`              | Free (your VPS)       | Works as reverse proxy on any IP        |
| AWS CloudFront            | —                     | Pay-per-use           | WebSocket supported since 2018         |
| Deno Deploy / Vercel Edge | —                     | Free tier             | Same pattern as CF Worker (see below)  |

## Minimum CDN requirements

- **WebSocket passthrough** (Upgrade: websocket) over TLS (wss://).
- **No caching** of `/ws` path.
- Ability to inject an upstream URL (origin).
- (Optional) ability to set headers — for bearer-token gating.

If the CDN supports only HTTP/1.1 or only HTTP/2 without WebSocket, it won't
work. QUIC/HTTP3 is **not** required and must not be used for censorship-bypass
paths — stick to TCP/TLS WebSocket.

## Server side (applies to every CDN)

Origin must accept WebSocket. Example 2 from the main README works as-is:

```yaml
inbounds:
  - listen: "0.0.0.0:8443"
    stream_settings:
      security: "tls"
      network: "websocket"
      tls:
        cert: "/etc/whispera/fullchain.pem"
        key:  "/etc/whispera/privkey.pem"
```

Lock the origin firewall to **only** accept inbound TCP from the CDN's IP
ranges (Cloudflare publishes them; Fastly/AWS likewise). Otherwise the
origin IP is discoverable via direct probe and the CDN stops being a shield.

## Client side (applies to every CDN)

```yaml
server: "cdn.yourname.example:443"
transport: "cdnworker"
cdn_worker_url: "wss://cdn.yourname.example/ws?t=YOUR_TOKEN"
```

`cdn_worker_url` is the **CDN-facing** URL. The token (if used) either rides
as `?t=...` or as `Authorization: Bearer ...`.

## Per-provider quickstart

### Cloudflare Workers (`cloudflare/`)

```bash
cd cloudflare
npm i -g wrangler
wrangler login
wrangler secret put WHISPERA_UPSTREAM     # wss://origin.example.com:8443
wrangler secret put WHISPERA_ACCESS_TOKEN # optional
wrangler deploy
```

Get `https://whispera-cdn.yourname.workers.dev`; clients use `wss://.../ws`.

Note: CF rewrites the TLS ClientHello, so **phantom (Reality-style) masquerade
is incompatible with this path**. Use CDN-worker OR phantom, not both.

### Fastly Compute (`fastly/`)

`fastly/fastly.toml` + `fastly/src/main.js` mirror the CF worker. Deploy with:

```bash
cd fastly
fastly compute init
fastly compute publish
```

Fastly doesn't rewrite ClientHello — phantom masquerade stays usable.

### Nginx reverse proxy (`nginx/`)

Run on any VPS with a public IP and a TLS cert (Let's Encrypt, etc.):

```bash
sudo apt install nginx
sudo cp nginx/whispera-cdn.conf /etc/nginx/sites-enabled/
sudo systemctl reload nginx
```

This is the "poor-man's CDN" — one extra hop that hides your real origin.
Combine with multiple nginx front-ends for blast-radius reduction.

### AWS CloudFront / Deno Deploy / Vercel Edge

Same pattern as CF Worker: a function that accepts `Upgrade: websocket`,
forwards to `WHISPERA_UPSTREAM`, optionally checks a bearer token.
`cloudflare/worker.js` is ~30 lines of vanilla JS — port it to any edge
runtime that exposes `fetch(request, env)`.

## Security notes

- **Always** set `WHISPERA_ACCESS_TOKEN`. Without it the worker is an open
  WebSocket relay and will get scraped.
- The token is a shared secret — put it in the CDN's secret store, never in
  the repo. Rotate on key compromise.
- Origin firewall must accept **only** CDN IP ranges. An open origin defeats
  the whole point.
- Do not enable CDN caching on `/ws` — WebSocket bodies are not cacheable
  and caching may leak bytes to other clients.
- Free-tier CDNs usually proxy TCP only (no UDP/QUIC). That's fine:
  bypass-mode Whispera does not use QUIC.
