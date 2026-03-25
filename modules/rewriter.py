"""
Static URL rewriter.

Applies regex-based rewrite rules from config in order; the first match wins.
Runs after UpstreamRouter so the URL being matched is already pointing at the
real upstream host.

Config section:
  url_rewrites:
    rules:
      - match:       "https://cdn\\.game\\.example\\.com/(.*)"
        replace:     "https://prag.digitain.tools/cdn/\\1"
        target_host: "prag.digitain.tools"   # optional Host header override
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional

from mitmproxy import http

from .config import Config


@dataclass
class RewriteRule:
    pattern: re.Pattern
    replace: str
    target_host: Optional[str]


class UrlRewriter:
    def __init__(self, cfg: Config, logger: logging.Logger) -> None:
        self.log = logger
        self.log_rewrites: bool = cfg.logging.log_rewrites

        rules_raw = cfg.raw.get("url_rewrites", {}).get("rules", [])
        self._rules: list[RewriteRule] = [
            RewriteRule(
                pattern=re.compile(r["match"]),
                replace=r["replace"],
                target_host=r.get("target_host"),
            )
            for r in rules_raw
        ]

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def rewrite(self, flow: http.HTTPFlow) -> None:
        original = flow.request.pretty_url
        for rule in self._rules:
            new_url, count = rule.pattern.subn(rule.replace, original)
            if count:
                if self.log_rewrites:
                    self.log.info(f"[REWRITE] {original}\n        → {new_url}")
                flow.request.url = new_url
                if rule.target_host:
                    flow.request.headers["Host"] = rule.target_host
                return  # first match only
