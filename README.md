# MITM Proxy — Game Launcher Interceptor

Intercepts game launcher traffic to:
- **Block analytics** (Google Analytics, Firebase, Amplitude, Sentry, etc.)
- **Rewrite URLs** to route game CDN / API / auth traffic through our own proxy server
- **Scrub tracking headers** from requests and responses
- **Capture game launch tokens** for debugging / re-use

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start proxy (interactive TUI)
./launch.sh

# 3. Or start and launch a game at the same time
./launch.sh --game /path/to/game-launcher

# 4. Web UI variant
./launch.sh --web
```

## Configuration

Edit `config.yaml` to customize behavior:

| Section | Purpose |
|---|---|
| `proxy` | Listen address/port, upstream chain |
| `analytics_block.domains` | Domains to silence (return 204) |
| `analytics_block.path_patterns` | URL path regex patterns to block |
| `url_rewrites.rules` | Regex-based URL rewriting to our server |
| `header_modifications` | Headers to strip from requests/responses |
| `game_launch` | Launch token capture + header injection |

### Adding a URL Rewrite

```yaml
url_rewrites:
  rules:
    - match: "https://cdn\\.mygame\\.com/(.*)"
      replace: "http://our-proxy.local:8090/cdn/\\1"
      target_host: "our-proxy.local"
```

### Blocking an Analytics Endpoint

```yaml
analytics_block:
  domains:
    - "my-analytics-vendor.com"
  path_patterns:
    - ".*/track\\?.*"
```

## Certificate Setup

On first run mitmproxy generates a CA certificate at `~/.mitmproxy/mitmproxy-ca-cert.pem`.
Install it as a trusted CA in the OS / game process to decrypt HTTPS traffic.

### Linux (system-wide)

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

### Per-process (environment variables)

`launch.sh` automatically sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and
`NODE_EXTRA_CA_CERTS` when launching the game, so most runtimes pick it up automatically.

## Architecture

```
Game Launcher
     │
     ▼  HTTP(S)
MITM Proxy (mitmproxy + addon.py)
     │
     ├── analytics request  ──►  204 No Content  (dropped)
     │
     ├── game CDN request   ──►  rewritten URL  ──►  our-proxy.local
     │
     └── everything else    ──►  upstream as-is
```

## Files

| File | Description |
|---|---|
| `addon.py` | mitmproxy Python addon (core logic) |
| `config.yaml` | All configuration |
| `launch.sh` | Shell launcher script |
| `requirements.txt` | Python dependencies |
