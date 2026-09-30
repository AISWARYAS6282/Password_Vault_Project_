"""Event logging.

Security rule: logs record *what happened*, never secrets. Any field whose name looks
sensitive is redacted, and callers should not pass passwords in the first place.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOGGER_NAME = "password_vault"
_SENSITIVE = ("password", "passwd", "secret", "key", "token", "notes", "master")
_configured = False


def configure(log_dir: str | os.PathLike | None = None) -> logging.Logger:
    """(Re)configure file logging. Log directory defaults to $VAULT_LOG_DIR or ./logs."""
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)

    directory = Path(log_dir or os.environ.get("VAULT_LOG_DIR", "logs"))
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass

    handler = RotatingFileHandler(
        directory / "vault.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    _configured = True
    return logger


def _redact(details: dict) -> str:
    parts = []
    for name, value in details.items():
        if any(word in name.lower() for word in _SENSITIVE):
            value = "[REDACTED]"
        parts.append(f"{name}={value}")
    return " ".join(parts)


def log_event(event: str, level: int = logging.INFO, **details) -> None:
    """Write one structured line, e.g. log_event("entry_added", entry_id=3)."""
    if not _configured:
        configure()
    message = event if not details else f"{event} {_redact(details)}"
    logging.getLogger(_LOGGER_NAME).log(level, message)
