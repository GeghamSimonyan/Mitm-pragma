"""
Game-launch interceptor.

Detects game launch / session / token requests, injects configured headers,
and optionally captures bearer tokens from JSON responses for debugging.

Config section:
  game_launch:
    capture_launch_token: true
    token_url_patterns:
      - ".*/launch.*"
      - ".*/session.*"
      - ".*/token.*"
    inject_headers:
      X-Game-Region: "EU"
      X-Debug-Mode: "0"
"""

import json
import logging
import re

from mitmproxy import http

from .config import Config


class GameLaunchInterceptor:
    def __init__(self, cfg: Config, logger: logging.Logger) -> None:
        self.log = logger
        section = cfg.raw.get("game_launch", {})

        self._capture: bool = section.get("capture_launch_token", True)
        self._patterns: list[re.Pattern] = [
            re.compile(p) for p in section.get("token_url_patterns", [])
        ]
        self._inject: dict[str, str] = section.get("inject_headers") or {}

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def handle_request(self, flow: http.HTTPFlow) -> None:
        if not self._is_launch(flow):
            return
        for name, value in self._inject.items():
            flow.request.headers[name] = value
            self.log.debug(f"[LAUNCH] injected {name}: {value}")
        self.log.info(f"[LAUNCH] {flow.request.pretty_url}")

    def handle_response(self, flow: http.HTTPFlow) -> None:
        if not self._capture or not flow.response or not self._is_launch(flow):
            return
        if "application/json" not in flow.response.headers.get("Content-Type", ""):
            return
        try:
            body = json.loads(flow.response.content)
            token = (
                body.get("token")
                or body.get("launch_token")
                or body.get("session_token")
                or body.get("access_token")
            )
            if token:
                self.log.info(f"[LAUNCH] token captured: {str(token)[:8]}…")
        except (json.JSONDecodeError, AttributeError):
            pass

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _is_launch(self, flow: http.HTTPFlow) -> bool:
        url = flow.request.pretty_url
        return any(p.match(url) for p in self._patterns)
