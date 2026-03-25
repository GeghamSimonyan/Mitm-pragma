"""
MITM Proxy Addon — Game Launcher Interceptor

Traffic routing:
  Clients send requests to this proxy with a `host` query parameter that
  names the real upstream, e.g.:

    GET /api/login?host=https%3A%2F%2Fgame.example.com&token=abc HTTP/1.1

  The addon strips the `host` param, rewrites the connection target to the
  upstream, and forwards the request preserving the original path + remaining
  query string.  WebSocket upgrades follow the same convention:

    GET /ws/chat?host=wss%3A%2F%2Fgame.example.com&room=1 HTTP/1.1
    Upgrade: websocket

Modifications applied before forwarding:
  - Analytics requests blocked (return 204)
  - Static URL-rewrite rules from config.yaml (applied after host-routing)
  - Tracking headers stripped from requests/responses
  - Game-launch tokens captured and optionally injected with custom headers
"""

import re
import logging
import json
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import yaml
from mitmproxy import http, websocket, ctx


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def _setup_logger(level: str, log_file: Optional[str]) -> logging.Logger:
    logger = logging.getLogger("mitm-game")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def _load_config(path: str = "config.yaml") -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    with cfg_path.open() as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Upstream router  (reads ?host= query param)
# ---------------------------------------------------------------------------

class UpstreamRouter:
    """
    Reads the `host` query parameter to determine where to forward the request.

    Input:  GET /some/path?host=https%3A%2F%2Fgame.example.com&foo=bar
    Result: request is sent to https://game.example.com/some/path?foo=bar
            (host param removed, path + scheme + authority rewritten)

    Works for both plain HTTP requests and WebSocket upgrade requests.
    """

    PARAM = "host"  # query param name that carries the upstream URL

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def route(self, flow: http.HTTPFlow) -> bool:
        """
        Inspect the request, extract the upstream from the `host` param,
        rewrite the flow target, and strip the param from the query string.

        Returns True if routing was applied, False if no `host` param found.
        """
        upstream_raw = self._extract_and_strip_host_param(flow)
        if not upstream_raw:
            return False

        try:
            upstream = urlparse(upstream_raw)
        except Exception as exc:
            self.logger.warning(f"[ROUTER] Bad upstream URL {upstream_raw!r}: {exc}")
            return False

        if not upstream.scheme or not upstream.netloc:
            self.logger.warning(f"[ROUTER] Incomplete upstream URL: {upstream_raw!r}")
            return False

        original = f"{flow.request.scheme}://{flow.request.pretty_host}{flow.request.path}"
        self._apply_upstream(flow, upstream)
        self.logger.info(
            f"[ROUTER] {original}"
            f"\n       → {flow.request.scheme}://{flow.request.pretty_host}{flow.request.path}"
        )
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_and_strip_host_param(flow: http.HTTPFlow) -> Optional[str]:
        """Remove `host` from query string, return its value (or None)."""
        params = parse_qsl(flow.request.query_string, keep_blank_values=True)
        remaining = []
        found = None
        for key, value in params:
            if key == UpstreamRouter.PARAM and found is None:
                found = value  # take only the first occurrence
            else:
                remaining.append((key, value))

        if found is None:
            return None

        # Rebuild query string without `host`
        flow.request.query_string = urlencode(remaining)
        return found

    @staticmethod
    def _apply_upstream(flow: http.HTTPFlow, upstream: urlparse) -> None:
        """Point the flow at the upstream server."""
        # Scheme
        flow.request.scheme = upstream.scheme.rstrip("+")  # handle ws+tls etc.

        # Normalise WebSocket schemes to HTTP for mitmproxy's connection layer
        # mitmproxy handles the actual WS framing; the transport scheme is what matters.
        scheme = upstream.scheme.lower()
        if scheme in ("wss",):
            flow.request.scheme = "https"
        elif scheme in ("ws",):
            flow.request.scheme = "http"

        # Host / port
        if upstream.port:
            flow.request.host = upstream.hostname
            flow.request.port = upstream.port
        else:
            flow.request.host = upstream.hostname
            flow.request.port = 443 if flow.request.scheme == "https" else 80

        # Host header — must match the upstream, not our proxy
        flow.request.headers["Host"] = upstream.netloc


# ---------------------------------------------------------------------------
# Analytics blocker
# ---------------------------------------------------------------------------

class AnalyticsBlocker:
    def __init__(self, cfg: dict, logger: logging.Logger):
        self.logger = logger
        self.log_blocked = cfg.get("logging", {}).get("log_blocked", True)

        analytics_cfg = cfg.get("analytics_block", {})
        self.blocked_domains: set[str] = set(analytics_cfg.get("domains", []))
        self.path_patterns: list[re.Pattern] = [
            re.compile(p) for p in analytics_cfg.get("path_patterns", [])
        ]

    def should_block(self, flow: http.HTTPFlow) -> bool:
        host = flow.request.pretty_host.lower()
        host = re.sub(r"^www\.", "", host)

        for blocked in self.blocked_domains:
            if host == blocked or host.endswith("." + blocked):
                return True

        full_url = flow.request.pretty_url
        return any(p.match(full_url) for p in self.path_patterns)

    def block(self, flow: http.HTTPFlow) -> None:
        if self.log_blocked:
            self.logger.info(f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}")
        flow.response = http.Response.make(
            204,
            b"",
            {"Content-Type": "text/plain", "X-Mitm-Action": "blocked-analytics"},
        )


# ---------------------------------------------------------------------------
# Static URL rewriter (config.yaml rules, applied after host-routing)
# ---------------------------------------------------------------------------

class UrlRewriter:
    def __init__(self, cfg: dict, logger: logging.Logger):
        self.logger = logger
        self.log_rewrites = cfg.get("logging", {}).get("log_rewrites", True)

        rules_cfg = cfg.get("url_rewrites", {}).get("rules", [])
        self.rules: list[dict] = []
        for rule in rules_cfg:
            self.rules.append({
                "pattern": re.compile(rule["match"]),
                "replace": rule["replace"],
                "target_host": rule.get("target_host"),
            })

    def rewrite(self, flow: http.HTTPFlow) -> None:
        original_url = flow.request.pretty_url
        for rule in self.rules:
            new_url, n = rule["pattern"].subn(rule["replace"], original_url)
            if n > 0:
                if self.log_rewrites:
                    self.logger.info(f"[REWRITE] {original_url}\n        → {new_url}")
                flow.request.url = new_url
                if rule["target_host"]:
                    flow.request.headers["Host"] = rule["target_host"]
                break


# ---------------------------------------------------------------------------
# Header scrubber
# ---------------------------------------------------------------------------

class HeaderScrubber:
    def __init__(self, cfg: dict):
        mods = cfg.get("header_modifications", {})
        self.remove_request: list[str] = [
            h.lower() for h in mods.get("remove_request", [])
        ]
        self.remove_response: list[str] = [
            h.lower() for h in mods.get("remove_response", [])
        ]

    def scrub_request(self, flow: http.HTTPFlow) -> None:
        for header in self.remove_request:
            if header in flow.request.headers:
                del flow.request.headers[header]

    def scrub_response(self, flow: http.HTTPFlow) -> None:
        for header in self.remove_response:
            if header in flow.response.headers:
                del flow.response.headers[header]


# ---------------------------------------------------------------------------
# Game launch interceptor
# ---------------------------------------------------------------------------

class GameLaunchInterceptor:
    def __init__(self, cfg: dict, logger: logging.Logger):
        self.logger = logger
        launch_cfg = cfg.get("game_launch", {})
        self.capture_token = launch_cfg.get("capture_launch_token", True)
        self.token_patterns: list[re.Pattern] = [
            re.compile(p) for p in launch_cfg.get("token_url_patterns", [])
        ]
        self.inject_headers: dict[str, str] = launch_cfg.get("inject_headers") or {}

    def _is_launch(self, flow: http.HTTPFlow) -> bool:
        return any(p.match(flow.request.pretty_url) for p in self.token_patterns)

    def handle_request(self, flow: http.HTTPFlow) -> None:
        if not self._is_launch(flow):
            return
        for name, value in self.inject_headers.items():
            flow.request.headers[name] = value
        self.logger.info(f"[LAUNCH] {flow.request.pretty_url}")

    def handle_response(self, flow: http.HTTPFlow) -> None:
        if not self._is_launch(flow) or not self.capture_token:
            return
        if "application/json" in flow.response.headers.get("Content-Type", ""):
            try:
                body = json.loads(flow.response.content)
                token = (
                    body.get("token")
                    or body.get("launch_token")
                    or body.get("session_token")
                    or body.get("access_token")
                )
                if token:
                    self.logger.info(f"[LAUNCH] token captured: {token[:8]}…")
            except (json.JSONDecodeError, AttributeError):
                pass


# ---------------------------------------------------------------------------
# WebSocket handler
# ---------------------------------------------------------------------------

class WebSocketHandler:
    """
    Logs WebSocket lifecycle events and optionally inspects messages.
    Routing is already done in the HTTP `request` hook during the upgrade.
    """

    def __init__(self, cfg: dict, logger: logging.Logger):
        self.logger = logger
        ws_cfg = cfg.get("websocket", {})
        self.log_messages = ws_cfg.get("log_messages", False)
        self.max_message_log_bytes = ws_cfg.get("max_message_log_bytes", 256)

    def started(self, flow: websocket.WebSocketFlow) -> None:
        self.logger.info(
            f"[WS] connected  {flow.request.pretty_url}"
        )

    def message(self, flow: websocket.WebSocketFlow) -> None:
        if not self.log_messages:
            return
        msg = flow.websocket.messages[-1]
        direction = "↑ client→server" if msg.from_client else "↓ server→client"
        content = msg.content
        if isinstance(content, (bytes, bytearray)):
            preview = content[: self.max_message_log_bytes]
            suffix = "…" if len(content) > self.max_message_log_bytes else ""
            self.logger.debug(f"[WS] {direction}  {preview!r}{suffix}")
        else:
            preview = str(content)[: self.max_message_log_bytes]
            self.logger.debug(f"[WS] {direction}  {preview}")

    def ended(self, flow: websocket.WebSocketFlow) -> None:
        msgs = len(flow.websocket.messages) if flow.websocket else 0
        self.logger.info(
            f"[WS] closed     {flow.request.pretty_url}  ({msgs} messages)"
        )

    def error(self, flow: websocket.WebSocketFlow) -> None:
        self.logger.warning(
            f"[WS] error      {flow.request.pretty_url}  {flow.error}"
        )


# ---------------------------------------------------------------------------
# Main addon
# ---------------------------------------------------------------------------

class GameLauncherAddon:
    def __init__(self, config_path: str = "config.yaml"):
        cfg = _load_config(config_path)
        log_cfg = cfg.get("logging", {})
        self.logger = _setup_logger(
            log_cfg.get("level", "INFO"),
            log_cfg.get("log_file"),
        )
        self.log_headers = log_cfg.get("log_headers", False)

        self.router  = UpstreamRouter(self.logger)
        self.blocker = AnalyticsBlocker(cfg, self.logger)
        self.rewriter = UrlRewriter(cfg, self.logger)
        self.scrubber = HeaderScrubber(cfg)
        self.launch  = GameLaunchInterceptor(cfg, self.logger)
        self.ws      = WebSocketHandler(cfg, self.logger)

        self.logger.info("GameLauncherAddon initialized")

    # ------------------------------------------------------------------
    # HTTP hooks
    # ------------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        # 1. Route to upstream extracted from ?host= param (HTTP + WS upgrades)
        self.router.route(flow)

        # 2. Block analytics — no further processing
        if self.blocker.should_block(flow):
            self.blocker.block(flow)
            return

        # 3. Scrub tracking headers
        self.scrubber.scrub_request(flow)

        # 4. Apply static rewrite rules (config.yaml)
        self.rewriter.rewrite(flow)

        # 5. Game-launch interception
        self.launch.handle_request(flow)

        if self.log_headers:
            self.logger.debug(f"[REQ HEADERS] {dict(flow.request.headers)}")

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response and flow.response.headers.get("X-Mitm-Action") == "blocked-analytics":
            return

        self.scrubber.scrub_response(flow)
        self.launch.handle_response(flow)

        if self.log_headers:
            self.logger.debug(f"[RESP HEADERS] {dict(flow.response.headers)}")

    # ------------------------------------------------------------------
    # WebSocket hooks
    # ------------------------------------------------------------------

    def websocket_start(self, flow: websocket.WebSocketFlow) -> None:
        self.ws.started(flow)

    def websocket_message(self, flow: websocket.WebSocketFlow) -> None:
        self.ws.message(flow)

    def websocket_end(self, flow: websocket.WebSocketFlow) -> None:
        self.ws.ended(flow)

    def websocket_error(self, flow: websocket.WebSocketFlow) -> None:
        self.ws.error(flow)


# ---------------------------------------------------------------------------
# mitmproxy entry point
# ---------------------------------------------------------------------------

addons = [GameLauncherAddon()]
