"""
WebSocket lifecycle handler.

Routing of WS connections is performed in the HTTP `request` hook
(during the Upgrade handshake) by UpstreamRouter — this module only
handles post-handshake lifecycle events.

Config section:
  websocket:
    log_messages: false
    max_message_log_bytes: 256
"""

import logging

from mitmproxy import websocket

from .config import Config


class WebSocketHandler:
    def __init__(self, cfg: Config, logger: logging.Logger) -> None:
        self.log = logger
        section = cfg.raw.get("websocket", {})
        self._log_messages: bool = section.get("log_messages", False)
        self._max_bytes: int = section.get("max_message_log_bytes", 256)

    # ------------------------------------------------------------------
    # mitmproxy WebSocket hooks (called from the main addon)
    # ------------------------------------------------------------------

    def started(self, flow: websocket.WebSocketFlow) -> None:
        self.log.info(f"[WS] opened  {flow.request.pretty_url}")

    def message(self, flow: websocket.WebSocketFlow) -> None:
        if not self._log_messages:
            return
        msg = flow.websocket.messages[-1]
        direction = "C→S" if msg.from_client else "S→C"
        raw = msg.content
        if isinstance(raw, (bytes, bytearray)):
            preview = raw[: self._max_bytes]
            tail = "…" if len(raw) > self._max_bytes else ""
            self.log.debug(f"[WS] {direction} {preview!r}{tail}")
        else:
            preview = str(raw)[: self._max_bytes]
            tail = "…" if len(str(raw)) > self._max_bytes else ""
            self.log.debug(f"[WS] {direction} {preview}{tail}")

    def ended(self, flow: websocket.WebSocketFlow) -> None:
        count = len(flow.websocket.messages) if flow.websocket else 0
        self.log.info(f"[WS] closed  {flow.request.pretty_url}  ({count} msgs)")

    def error(self, flow: websocket.WebSocketFlow) -> None:
        self.log.warning(f"[WS] error   {flow.request.pretty_url}  — {flow.error}")
