"""
addon.py — mitmproxy entry point

Wires together the modules in modules/ and registers mitmproxy hooks.
All business logic lives in the individual modules; this file is only
responsible for the hook dispatch.
"""

from mitmproxy import http, websocket

from modules import (
    Config,
    setup_logger,
    UpstreamRouter,
    AnalyticsBlocker,
    UrlRewriter,
    HeaderScrubber,
    GameLaunchInterceptor,
    WebSocketHandler,
)


class GameLauncherAddon:
    def __init__(self, config_path: str = "config.yaml") -> None:
        cfg = Config.load(config_path)
        log = setup_logger(cfg.logging.level, cfg.logging.log_file)
        self._log_headers = cfg.logging.log_headers

        self.router    = UpstreamRouter(cfg, log)
        self.analytics = AnalyticsBlocker(cfg, log)
        self.rewriter  = UrlRewriter(cfg, log)
        self.headers   = HeaderScrubber(cfg, log)
        self.launch    = GameLaunchInterceptor(cfg, log)
        self.ws        = WebSocketHandler(cfg, log)

        log.info(
            f"GameLauncherAddon ready — "
            f"domain={cfg.proxy.domain} "
            f"ssl={'on' if cfg.proxy.ssl.enabled else 'off'}"
        )

    # ------------------------------------------------------------------
    # HTTP hooks
    # ------------------------------------------------------------------

    def request(self, flow: http.HTTPFlow) -> None:
        # 1. Route to upstream from ?host= param (also covers WS upgrades)
        self.router.route(flow)

        # 2. Block analytics — short-circuit, no further processing
        if self.analytics.should_block(flow):
            self.analytics.block(flow)
            return

        # 3. Strip tracking headers from the outgoing request
        self.headers.scrub_request(flow)

        # 4. Apply static URL-rewrite rules
        self.rewriter.rewrite(flow)

        # 5. Game-launch interception (inject headers, log)
        self.launch.handle_request(flow)

        if self._log_headers:
            import logging
            logging.getLogger("mitm-game").debug(
                f"[REQ] {dict(flow.request.headers)}"
            )

    def response(self, flow: http.HTTPFlow) -> None:
        # Skip flows already short-circuited by the analytics blocker
        if AnalyticsBlocker.is_blocked_response(flow):
            return

        # Strip tracking headers from the response
        self.headers.scrub_response(flow)

        # Capture launch tokens
        self.launch.handle_response(flow)

        if self._log_headers:
            import logging
            logging.getLogger("mitm-game").debug(
                f"[RESP] {dict(flow.response.headers)}"
            )

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


addons = [GameLauncherAddon()]
