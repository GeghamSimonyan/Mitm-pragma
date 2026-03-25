"""
Upstream router — extracts the `host` query parameter and rewrites the
mitmproxy flow target to that upstream, preserving the original path and
all remaining query params.

Protocol:
  Client sends any request (HTTP or WebSocket upgrade) with:
    ?host=<url-encoded upstream URL>

  Example:
    GET /api/v2/login?host=https%3A%2F%2Fprag.digitain.tools&token=xyz
    → forwarded to https://prag.digitain.tools/api/v2/login?token=xyz

    GET /ws/live?host=wss%3A%2F%2Fprag.digitain.tools&room=42
    Upgrade: websocket
    → WebSocket tunnel to wss://prag.digitain.tools/ws/live?room=42
"""

import logging
from typing import Optional
from urllib.parse import urlparse, urlencode, parse_qsl

from mitmproxy import http

from .config import Config

_PARAM = "host"


class UpstreamRouter:
    """
    Reads ?host= from the query string on every request, rewrites the flow
    destination, and strips the param so the upstream never sees it.

    Works identically for HTTP requests and WebSocket upgrade requests —
    both are intercepted in mitmproxy's `request` hook.
    """

    def __init__(self, cfg: Config, logger: logging.Logger) -> None:
        self.log = logger

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def route(self, flow: http.HTTPFlow) -> bool:
        """
        Apply routing.  Returns True if the flow was re-targeted, False if
        no `host` param was present (request passes through unchanged).
        """
        upstream_url = self._pop_host_param(flow)
        if not upstream_url:
            return False

        parsed = self._parse_upstream(upstream_url)
        if parsed is None:
            return False

        original = f"{flow.request.scheme}://{flow.request.pretty_host}{flow.request.path}"
        self._apply(flow, parsed)
        self.log.info(
            f"[ROUTER] {original}"
            f"\n       → {flow.request.scheme}://{flow.request.pretty_host}{flow.request.path}"
        )
        return True

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _pop_host_param(self, flow: http.HTTPFlow) -> Optional[str]:
        """Remove the first `host` param from the query string; return its value."""
        params = parse_qsl(flow.request.query_string, keep_blank_values=True)
        remaining, found = [], None
        for key, value in params:
            if key == _PARAM and found is None:
                found = value
            else:
                remaining.append((key, value))

        if found is not None:
            flow.request.query_string = urlencode(remaining)
        return found

    def _parse_upstream(self, raw: str) -> Optional["_Upstream"]:
        try:
            p = urlparse(raw)
        except Exception as exc:
            self.log.warning(f"[ROUTER] Bad upstream URL {raw!r}: {exc}")
            return None

        if not p.scheme or not p.netloc:
            self.log.warning(f"[ROUTER] Incomplete upstream URL: {raw!r}")
            return None

        return _Upstream(p)

    def _apply(self, flow: http.HTTPFlow, upstream: "_Upstream") -> None:
        flow.request.scheme = upstream.transport_scheme
        flow.request.host   = upstream.hostname
        flow.request.port   = upstream.port
        flow.request.headers["Host"] = upstream.host_header


class _Upstream:
    """Thin wrapper that normalises the upstream URL into connection params."""

    _SCHEME_MAP = {
        "ws":  ("http",  80),
        "wss": ("https", 443),
        "http":  ("http",  80),
        "https": ("https", 443),
    }

    def __init__(self, parsed: "ParseResult") -> None:  # type: ignore[name-defined]
        scheme = parsed.scheme.lower()
        transport, default_port = self._SCHEME_MAP.get(scheme, ("https", 443))

        self.transport_scheme: str = transport
        self.hostname: str = parsed.hostname or ""
        self.port: int = parsed.port or default_port
        # Host header includes port only when non-standard
        standard = (transport == "http" and self.port == 80) or \
                   (transport == "https" and self.port == 443)
        self.host_header: str = (
            self.hostname if standard else f"{self.hostname}:{self.port}"
        )
