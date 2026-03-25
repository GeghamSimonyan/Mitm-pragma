# MITM Proxy — Game Launcher Interceptor
**Domain:** `prag.digitain.tools`

Intercepts game-launcher traffic over HTTPS/WSS to:
- Route all traffic through `prag.digitain.tools` via the `?host=` convention
- Block analytics silently (return 204)
- Apply static URL-rewrite rules to redirect CDN / API / auth endpoints
- Scrub tracking headers from requests and responses
- Capture game-launch tokens for debugging

---

## Quick Start

```bash
pip install -r requirements.txt

# Interactive TUI
./launch.sh

# Non-interactive (CI / server)
./launch.sh --dump

# Start proxy and game together
./launch.sh --game /path/to/launcher

# mitmweb UI at http://127.0.0.1:8081
./launch.sh --web
```

Configure the game launcher to use the proxy:

```
HTTP_PROXY=http://prag.digitain.tools:8080
HTTPS_PROXY=http://prag.digitain.tools:8080
```

---

## Upstream routing — `?host=` parameter

Every request (HTTP or WebSocket upgrade) must carry a `host` query parameter
that names the real upstream.  The proxy strips it and forwards the request
preserving the original path and all remaining query params.

```
# HTTP
GET /api/login?host=https%3A%2F%2Fgame.example.com&token=abc
→ https://game.example.com/api/login?token=abc

# WebSocket
GET /ws/live?host=wss%3A%2F%2Fgame.example.com&room=42
Upgrade: websocket
→ wss://game.example.com/ws/live?room=42
```

---

## SSL / TLS

SSL interception is **on by default**.  mitmproxy generates its own CA on first
run (`~/.mitmproxy/mitmproxy-ca-cert.pem`).

### Use mitmproxy's auto-generated CA (default)

```bash
./launch.sh
# Then trust: ~/.mitmproxy/mitmproxy-ca-cert.pem
```

Install system-wide on Linux:

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem \
    /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

### Use a real certificate (Let's Encrypt / custom)

Drop the certificate files into `certs/` — `launch.sh` picks them up automatically:

```
certs/
  prag.digitain.tools-fullchain.pem   # full chain (cert + intermediates)
  prag.digitain.tools.key             # private key
```

Or pass them explicitly:

```bash
./launch.sh --cert /path/to/fullchain.pem --key /path/to/key.pem
```

`launch.sh` automatically sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
`NODE_EXTRA_CA_CERTS`, and `JAVA_TOOL_OPTIONS` when launching the game, so
most runtimes pick up the CA without manual configuration.

---

## Configuration — `config.yaml`

| Section | Purpose |
|---|---|
| `proxy` | Listen address, port, domain, SSL cert/key paths |
| `analytics_block.domains` | Domains blocked entirely (204 response) |
| `analytics_block.path_patterns` | URL regex patterns to block |
| `url_rewrites.rules` | Regex → replacement URL rules (first match wins) |
| `header_modifications` | Headers to strip from requests / responses |
| `game_launch` | Token capture + header injection on launch endpoints |
| `websocket` | WS message logging settings |
| `logging` | Log level, file, verbosity |

### Add a URL rewrite

```yaml
url_rewrites:
  rules:
    - match: "https://cdn\\.mygame\\.com/(.*)"
      replace: "https://prag.digitain.tools/cdn/\\1"
      target_host: "prag.digitain.tools"
```

### Block an analytics endpoint

```yaml
analytics_block:
  domains:
    - "my-vendor.com"
  path_patterns:
    - ".*/track\\?.*"
```

---

## Project structure

```
.
├── addon.py            # mitmproxy entry point — hook dispatch only
├── config.yaml         # all configuration
├── launch.sh           # SSL-aware launcher script
├── requirements.txt    # mitmproxy + PyYAML
├── certs/              # drop real TLS certs here (gitignored)
└── modules/
    ├── __init__.py     # re-exports all public classes
    ├── config.py       # Config dataclass, loader, logger factory
    ├── router.py       # UpstreamRouter — ?host= param extraction
    ├── analytics.py    # AnalyticsBlocker — domain/path blocking
    ├── rewriter.py     # UrlRewriter — static regex rewrite rules
    ├── headers.py      # HeaderScrubber — tracking header removal
    ├── launch.py       # GameLaunchInterceptor — token capture
    └── ws.py           # WebSocketHandler — lifecycle logging
```

---

## Architecture

```
Game Launcher
     │
     ▼  HTTPS / WSS  (with ?host=<upstream> query param)
     │
  prag.digitain.tools:8080  (mitmproxy + addon.py)
     │
     ├─ modules/router.py    extract ?host=, rewrite target, strip param
     │
     ├─ modules/analytics.py  blocked domain/path? → 204, stop
     │
     ├─ modules/headers.py   strip tracking headers from request
     │
     ├─ modules/rewriter.py  apply static URL-rewrite rules
     │
     ├─ modules/launch.py    game-launch endpoint? inject headers, log token
     │
     └─────────────────────► upstream (TLS, verify_upstream=false by default)
                                │
                             modules/headers.py  strip tracking headers from response
                             modules/launch.py   capture launch token from response body
```
