"""
Secure logging module for SinXTan.

Provides structured logging that automatically sanitizes sensitive data
such as passwords, encryption keys, tokens, and salts before writing
to any log destination.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Final


SENSITIVE_KEYS: Final[frozenset[str]] = frozenset({
    "password",
    "key",
    "secret",
    "token",
    "salt",
    "nonce",
    "master_key",
    "encryption_key",
    "embedding_key",
})

_LOG_FORMAT: Final[str] = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"

_REDACTED: Final[str] = "***REDACTED***"

# Module-level cache so repeated get_logger calls for the same name reuse the
# same SecureLogger (and therefore the same underlying logging.Logger).
_logger_cache: dict[str, SecureLogger] = {}


class SecureLogger:
    """A logger wrapper that never emits sensitive data."""

    __slots__ = ("_logger",)

    def __init__(
        self,
        name: str,
        log_file: str | Path | None = None,
        level: int = logging.INFO,
    ) -> None:
        self._logger: logging.Logger = logging.getLogger(name)
        self._logger.setLevel(level)

        # Prevent duplicate handlers when the same name is instantiated twice.
        if not self._logger.handlers:
            formatter = logging.Formatter(_LOG_FORMAT)

            console_handler = logging.StreamHandler()
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            self._logger.addHandler(console_handler)

            if log_file is not None:
                file_path = Path(log_file)
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(
                    str(file_path), encoding="utf-8"
                )
                file_handler.setLevel(level)
                file_handler.setFormatter(formatter)
                self._logger.addHandler(file_handler)

    # ------------------------------------------------------------------
    # Public logging helpers
    # ------------------------------------------------------------------

    def info(self, message: str) -> None:
        """Log an informational message."""
        self._logger.info(message)

    def warning(self, message: str) -> None:
        """Log a warning message."""
        self._logger.warning(message)

    def error(self, message: str, exc_info: bool = False) -> None:
        """Log an error message, optionally including exception info."""
        self._logger.error(message, exc_info=exc_info)

    def debug(self, message: str) -> None:
        """Log a debug message."""
        self._logger.debug(message)

    # ------------------------------------------------------------------
    # Structured operation tracking
    # ------------------------------------------------------------------

    def operation_start(
        self,
        operation: str,
        details: dict[str, object] | None = None,
    ) -> str:
        """Log the start of a named operation.

        Parameters
        ----------
        operation:
            Human-readable name for the operation (e.g. ``"embed_message"``).
        details:
            Optional context dict.  Sensitive keys are redacted automatically.

        Returns
        -------
        str
            A unique ``operation_id`` that can be passed to
            :meth:`operation_complete` to correlate the log entries.
        """
        operation_id: str = uuid.uuid4().hex[:12]
        sanitized: str = ""
        if details is not None:
            sanitized = f" | details={self._sanitize(details)}"
        self._logger.info(
            "OP_START [%s] op=%s%s",
            operation_id,
            operation,
            sanitized,
        )
        return operation_id

    def operation_complete(
        self,
        operation_id: str,
        success: bool,
        details: dict[str, object] | None = None,
    ) -> None:
        """Log the completion of a previously-started operation.

        Parameters
        ----------
        operation_id:
            The id returned by :meth:`operation_start`.
        success:
            Whether the operation succeeded.
        details:
            Optional context dict.  Sensitive keys are redacted automatically.
        """
        status: str = "SUCCESS" if success else "FAILURE"
        sanitized: str = ""
        if details is not None:
            sanitized = f" | details={self._sanitize(details)}"
        log_fn = self._logger.info if success else self._logger.error
        log_fn(
            "OP_%s [%s]%s",
            status,
            operation_id,
            sanitized,
        )

    # ------------------------------------------------------------------
    # Sanitisation
    # ------------------------------------------------------------------

    def _sanitize(self, data: dict[str, object]) -> dict[str, object]:
        """Return a shallow copy of *data* with sensitive values redacted.

        Keys are compared case-insensitively against :data:`SENSITIVE_KEYS`.
        Nested dicts are sanitized recursively.
        """
        sanitized: dict[str, object] = {}
        for k, v in data.items():
            if k.lower() in SENSITIVE_KEYS:
                sanitized[k] = _REDACTED
            elif isinstance(v, dict):
                sanitized[k] = self._sanitize(v)
            else:
                sanitized[k] = v
        return sanitized


def get_logger(name: str) -> SecureLogger:
    """Module-level convenience to obtain a :class:`SecureLogger`.

    Repeated calls with the same *name* return the same instance.
    """
    if name not in _logger_cache:
        _logger_cache[name] = SecureLogger(name)
    return _logger_cache[name]
