"""
Analytics blocker.

Matches requests against a configured list of domains and path-pattern regexes.
Matched requests receive a 204 No Content response immediately; the upstream
never sees them.

Config section:
  analytics_block:
    domains:
      - "google-analytics.com"
      - ...
    path_patterns:
      - ".*/telemetry.*"
      - ...
"""

import re
import logging

from mitmproxy import http

from .config import Config

_BLOCK_MARKER = "blocked-analytics"


class AnalyticsBlocker:
    def __init__(self, cfg: Config, logger: logging.Logger) -> None:
        self.log = logger
        self.log_blocked: bool = cfg.logging.log_blocked

        section = cfg.raw.get("analytics_block", {})

        self._domains: set[str] = set(section.get("domains", []))
        self._path_patterns: list[re.Pattern] = [
            re.compile(p) for p in section.get("path_patterns", [])
        ]

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def should_block(self, flow: http.HTTPFlow) -> bool:
        return self._domain_match(flow) or self._path_match(flow)

    def block(self, flow: http.HTTPFlow) -> None:
        if self.log_blocked:
            self.log.info(f"[BLOCK] {flow.request.method} {flow.request.pretty_url}")
        flow.response = http.Response.make(
            204,
            b"",
            {"Content-Type": "text/plain", "X-Mitm-Action": _BLOCK_MARKER},
        )

    @staticmethod
    def is_blocked_response(flow: http.HTTPFlow) -> bool:
        """True if this flow was already short-circuited by the blocker."""
        return (
            flow.response is not None
            and flow.response.headers.get("X-Mitm-Action") == _BLOCK_MARKER
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _domain_match(self, flow: http.HTTPFlow) -> bool:
        host = re.sub(r"^www\.", "", flow.request.pretty_host.lower())
        return any(
            host == blocked or host.endswith("." + blocked)
            for blocked in self._domains
        )

    def _path_match(self, flow: http.HTTPFlow) -> bool:
        url = flow.request.pretty_url
        return any(p.match(url) for p in self._path_patterns)
