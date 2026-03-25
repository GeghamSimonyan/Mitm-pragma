"""
MITM Proxy Addon — Game Launcher Interceptor

Handles:
  - Analytics blocking (domain + path pattern matching)
  - URL rewrites (redirect game endpoints to our proxy)
  - Request/response header scrubbing
  - Game launch token capture
"""

import re
import logging
import json
from pathlib import Path
from typing import Optional

import yaml
from mitmproxy import http, ctx
from mitmproxy.net.http import http1


# ---------------------------------------------------------------------------
# Logging setup
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
        # Strip leading www.
        host = re.sub(r"^www\.", "", host)

        # Exact domain match or subdomain match
        for blocked in self.blocked_domains:
            if host == blocked or host.endswith("." + blocked):
                return True

        # Path pattern match
        full_url = flow.request.pretty_url
        for pattern in self.path_patterns:
            if pattern.match(full_url):
                return True

        return False

    def block(self, flow: http.HTTPFlow) -> None:
        if self.log_blocked:
            self.logger.info(f"[BLOCKED] {flow.request.method} {flow.request.pretty_url}")
        flow.response = http.Response.make(
            204,
            b"",
            {"Content-Type": "text/plain", "X-Mitm-Action": "blocked-analytics"},
        )


# ---------------------------------------------------------------------------
# URL rewriter
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

                # Parse and apply new URL
                flow.request.url = new_url

                # Override Host header if specified
                if rule["target_host"]:
                    flow.request.headers["Host"] = rule["target_host"]

                # Only apply first matching rule
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

    def is_launch_request(self, flow: http.HTTPFlow) -> bool:
        url = flow.request.pretty_url
        return any(p.match(url) for p in self.token_patterns)

    def handle_request(self, flow: http.HTTPFlow) -> None:
        if not self.is_launch_request(flow):
            return

        # Inject custom headers
        for name, value in self.inject_headers.items():
            flow.request.headers[name] = value
            self.logger.debug(f"[LAUNCH] Injected header {name}: {value}")

        self.logger.info(f"[LAUNCH] Intercepted launch request: {flow.request.pretty_url}")

    def handle_response(self, flow: http.HTTPFlow) -> None:
        if not self.is_launch_request(flow):
            return

        if not self.capture_token:
            return

        # Try to extract token from JSON response
        content_type = flow.response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            try:
                body = json.loads(flow.response.content)
                token = (
                    body.get("token")
                    or body.get("launch_token")
                    or body.get("session_token")
                    or body.get("access_token")
                )
                if token:
                    self.logger.info(f"[LAUNCH] Captured token: {token[:8]}... (truncated)")
            except (json.JSONDecodeError, AttributeError):
                pass


# ---------------------------------------------------------------------------
# Main addon class
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

        self.blocker = AnalyticsBlocker(cfg, self.logger)
        self.rewriter = UrlRewriter(cfg, self.logger)
        self.scrubber = HeaderScrubber(cfg)
        self.launch = GameLaunchInterceptor(cfg, self.logger)

        self.logger.info("GameLauncherAddon initialized")

    # ------------------------------------------------------------------
    # mitmproxy hooks
    # ------------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        # 1. Block analytics first — no further processing needed
        if self.blocker.should_block(flow):
            self.blocker.block(flow)
            return

        # 2. Scrub tracking headers from outgoing request
        self.scrubber.scrub_request(flow)

        # 3. Rewrite URLs to route through our proxy
        self.rewriter.rewrite(flow)

        # 4. Handle game launch interception
        self.launch.handle_request(flow)

        if self.log_headers:
            self.logger.debug(f"[REQ HEADERS] {dict(flow.request.headers)}")

    def response(self, flow: http.HTTPFlow) -> None:
        # Skip analytics responses (already blocked)
        if flow.response and flow.response.headers.get("X-Mitm-Action") == "blocked-analytics":
            return

        # Scrub response headers
        self.scrubber.scrub_response(flow)

        # Capture launch tokens from responses
        self.launch.handle_response(flow)

        if self.log_headers:
            self.logger.debug(f"[RESP HEADERS] {dict(flow.response.headers)}")


# ---------------------------------------------------------------------------
# Entry point for mitmproxy
# ---------------------------------------------------------------------------

def load(l):  # noqa: E741
    """Called by mitmproxy to register the addon."""
    return GameLauncherAddon()


addons = [GameLauncherAddon()]
