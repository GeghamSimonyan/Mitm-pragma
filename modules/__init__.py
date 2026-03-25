"""
modules — Game Launcher MITM Proxy

Each module owns one concern:
  config    — Config dataclass, loader, logger factory
  router    — ?host= upstream routing (HTTP + WebSocket)
  analytics — analytics domain/path blocking
  rewriter  — static URL rewrite rules
  headers   — tracking header scrubbing
  launch    — game-launch token capture + header injection
  ws        — WebSocket lifecycle logging
"""

from .config import Config, setup_logger
from .router import UpstreamRouter
from .analytics import AnalyticsBlocker
from .rewriter import UrlRewriter
from .headers import HeaderScrubber
from .launch import GameLaunchInterceptor
from .ws import WebSocketHandler

__all__ = [
    "Config",
    "setup_logger",
    "UpstreamRouter",
    "AnalyticsBlocker",
    "UrlRewriter",
    "HeaderScrubber",
    "GameLaunchInterceptor",
    "WebSocketHandler",
]
