"""
Header scrubber.

Strips configured tracking / fingerprinting headers from outgoing requests
and incoming responses before they reach the client or the upstream server.

Config section:
  header_modifications:
    remove_request:
      - "X-Analytics-Id"
      - "X-Device-Id"
      - ...
    remove_response:
      - "X-Analytics-Token"
      - "Set-Cookie"
      - ...
"""

import logging

from mitmproxy import http

from .config import Config


class HeaderScrubber:
    def __init__(self, cfg: Config, logger: logging.Logger) -> None:
        self.log = logger
        mods = cfg.raw.get("header_modifications", {})

        self._drop_req: list[str] = [
            h.lower() for h in mods.get("remove_request", [])
        ]
        self._drop_resp: list[str] = [
            h.lower() for h in mods.get("remove_response", [])
        ]

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def scrub_request(self, flow: http.HTTPFlow) -> None:
        self._drop(flow.request.headers, self._drop_req)

    def scrub_response(self, flow: http.HTTPFlow) -> None:
        if flow.response:
            self._drop(flow.response.headers, self._drop_resp)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _drop(headers, names: list[str]) -> None:
        for name in names:
            if name in headers:
                del headers[name]
