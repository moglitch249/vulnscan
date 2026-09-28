"""Structured logging setup using structlog.

Configures JSON or console logging, ensures secrets are never logged,
and provides a consistent logger interface across the framework.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from pathlib import Path
from typing import Any

import structlog

# Patterns that look like API keys / tokens — redacted from log output
_SECRET_PATTERNS = re.compile(
    r"(api[_-]?key|token|password|secret|authorization|bearer)"
    r"\s*[:=]\s*\S+",
    re.IGNORECASE,
)

_SECRET_FIELD_NAMES = frozenset({
    "api_key",
    "apikey",
    "token",
    "password",
    "secret",
    "authorization",
    "nvd_api_key",
    "vulncheck_api_key",
    "github_token",
})


def _redact_secrets(
    logger: Any, method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Structlog processor that redacts secret values from log events."""
    for key in list(event_dict.keys()):
        if key.lower() in _SECRET_FIELD_NAMES:
            event_dict[key] = "***REDACTED***"
        elif isinstance(event_dict[key], str):
            event_dict[key] = _SECRET_PATTERNS.sub(
                r"\1=***REDACTED***", event_dict[key]
            )
    return event_dict


def setup_logging(
    level: str = "INFO",
    log_format: str = "json",
    log_file: str | None = None,
) -> None:
    """Configure structlog with the specified level, format, and file.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR).
        log_format: "json" for structured JSON, "console" for human-readable.
        log_file: Optional path to a log file.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Ensure log directory exists
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    # Standard library root logger
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        format="%(message)s",
        level=numeric_level,
        handlers=handlers,
        force=True,
    )

    # Choose renderer
    if log_format == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.UnicodeDecoder(),
            _redact_secrets,
            renderer,
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a named structured logger.

    Args:
        name: Logger name, typically __name__ of the calling module.

    Returns:
        Configured structlog BoundLogger.
    """
    return structlog.get_logger(name)
