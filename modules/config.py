"""
Shared configuration loader and logger factory.

All other modules import from here — nothing else imports cross-module,
so this is the only shared dependency inside the modules/ package.
"""

import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

def setup_logger(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    logger = logging.getLogger("mitm-game")
    if logger.handlers:
        return logger  # already configured (mitmproxy may call addon twice)

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return logger


# ---------------------------------------------------------------------------
# Typed sub-configs
# ---------------------------------------------------------------------------

@dataclass
class SslConfig:
    enabled: bool = True
    cert: Optional[str] = None           # path to fullchain PEM (or mitmproxy-ca-cert)
    key: Optional[str] = None            # path to private key PEM
    verify_upstream: bool = False        # False = accept any upstream cert (MITM-friendly)

    @classmethod
    def from_dict(cls, d: dict) -> "SslConfig":
        return cls(
            enabled=d.get("enabled", True),
            cert=d.get("cert"),
            key=d.get("key"),
            verify_upstream=d.get("verify_upstream", False),
        )


@dataclass
class ProxyConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    domain: str = "prag.digitain.tools"
    ssl: SslConfig = field(default_factory=SslConfig)

    @classmethod
    def from_dict(cls, d: dict) -> "ProxyConfig":
        return cls(
            host=d.get("host", "0.0.0.0"),
            port=d.get("port", 8080),
            domain=d.get("domain", "prag.digitain.tools"),
            ssl=SslConfig.from_dict(d.get("ssl", {})),
        )


@dataclass
class LoggingConfig:
    level: str = "INFO"
    log_file: Optional[str] = None
    log_blocked: bool = True
    log_rewrites: bool = True
    log_headers: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "LoggingConfig":
        return cls(
            level=d.get("level", "INFO"),
            log_file=d.get("log_file"),
            log_blocked=d.get("log_blocked", True),
            log_rewrites=d.get("log_rewrites", True),
            log_headers=d.get("log_headers", False),
        )


# ---------------------------------------------------------------------------
# Root config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    """
    Full parsed configuration.  Each module receives this object and reads
    only the section it cares about.
    """
    proxy: ProxyConfig
    logging: LoggingConfig
    raw: dict  # full raw dict for modules that read their own sections

    @classmethod
    def load(cls, path: str = "config.yaml") -> "Config":
        cfg_path = Path(path)
        if not cfg_path.exists():
            raise FileNotFoundError(f"Config not found: {path}")
        with cfg_path.open() as f:
            raw = yaml.safe_load(f) or {}
        return cls(
            proxy=ProxyConfig.from_dict(raw.get("proxy", {})),
            logging=LoggingConfig.from_dict(raw.get("logging", {})),
            raw=raw,
        )
