from __future__ import annotations

from typing import Optional


class InIDError(Exception):
    """Something InID (or the SDK) refused: code is InID's error code, status its HTTP status."""

    def __init__(self, code: str, status: Optional[int] = None) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


class InIDConfigError(InIDError):
    """Missing or malformed settings: raised at startup, never per request."""


class InIDNetworkError(InIDError):
    """InID couldn't be reached (DNS, connection, timeout)."""

    def __init__(self, detail: str = "") -> None:
        super().__init__("network_error", None)
        self.detail = detail


class InIDWebhookError(InIDError):
    """A webhook whose signature doesn't hold: answer 400 and ignore it."""
