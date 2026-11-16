"""InID's webhooks: InID-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any, Optional, Union

from .errors import InIDConfigError, InIDWebhookError

SIGNATURE_TOLERANCE_SECONDS = 300


def verify_webhook(
    raw_body: Union[str, bytes],
    header: Optional[str],
    secret: Optional[str] = None,
    *,
    now: Optional[float] = None,
) -> dict[str, Any]:
    """The event in a webhook, from its raw body (bytes as received, before any JSON parsing)
    and its InID-Signature header. Raises InIDWebhookError when it isn't InID's."""
    secret = secret or os.environ.get("INID_WEBHOOK_SECRET")
    if not secret:
        raise InIDConfigError("INID_WEBHOOK_SECRET is missing: set it to your webhook secret (whsec_...)")
    body = raw_body if isinstance(raw_body, bytes) else raw_body.encode("utf-8")
    parts: dict[str, str] = {}
    for piece in (header or "").split(","):
        key, _, value = piece.strip().partition("=")
        parts.setdefault(key, value)
    try:
        at = int(parts.get("t", ""))
    except ValueError:
        raise InIDWebhookError("invalid_signature") from None
    current = time.time() if now is None else now
    if not at or not parts.get("v1") or abs(current - at) > SIGNATURE_TOLERANCE_SECONDS:
        raise InIDWebhookError("invalid_signature")
    expected = hmac.new(secret.encode("utf-8"), f"{at}.".encode("ascii") + body, hashlib.sha256).digest()
    try:
        given = bytes.fromhex(parts["v1"])
    except ValueError:
        raise InIDWebhookError("invalid_signature") from None
    if not hmac.compare_digest(given, expected):
        raise InIDWebhookError("invalid_signature")
    event = json.loads(body.decode("utf-8"))
    if not isinstance(event, dict):
        raise InIDWebhookError("invalid_event")
    return event
