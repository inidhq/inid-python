from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from conftest import FakeInID, make_inid

from inid import InIDConfigError, InIDWebhookError, verify_webhook

SECRET = "whsec_test"
BODY = json.dumps({"type": "user.created", "sub": "user_123", "created_at": "2026-11-16T00:00:00Z"})


def signed(body: str = BODY, secret: str = SECRET, at: int | None = None) -> str:
    at = int(time.time()) if at is None else at
    mac = hmac.new(secret.encode(), f"{at}.{body}".encode(), hashlib.sha256).hexdigest()
    return f"t={at},v1={mac}"


def test_valid_signature_returns_the_event():
    event = verify_webhook(BODY, signed(), SECRET)
    assert event["type"] == "user.created" and event["sub"] == "user_123"
    assert verify_webhook(BODY.encode(), signed(), SECRET) == event


def test_client_method_uses_configured_secret(fake: FakeInID):
    inid = make_inid(fake, webhook_secret=SECRET)
    assert inid.verify_webhook(BODY, signed())["type"] == "user.created"


def test_wrong_secret():
    with pytest.raises(InIDWebhookError):
        verify_webhook(BODY, signed(secret="whsec_other"), SECRET)


def test_tampered_body():
    with pytest.raises(InIDWebhookError):
        verify_webhook(BODY.replace("user_123", "user_999"), signed(), SECRET)


def test_too_old_or_in_the_future():
    now = int(time.time())
    with pytest.raises(InIDWebhookError):
        verify_webhook(BODY, signed(at=now - 301), SECRET)
    with pytest.raises(InIDWebhookError):
        verify_webhook(BODY, signed(at=now + 301), SECRET)
    assert verify_webhook(BODY, signed(at=now - 299), SECRET)


@pytest.mark.parametrize("header", [None, "", "garbage", "t=abc,v1=00", f"t={int(time.time())}", "v1=abcd", f"t={int(time.time())},v1=zz-not-hex", "t=0,v1=00"])
def test_malformed_header(header):
    with pytest.raises(InIDWebhookError):
        verify_webhook(BODY, header, SECRET)


def test_missing_secret(monkeypatch):
    monkeypatch.delenv("INID_WEBHOOK_SECRET", raising=False)
    with pytest.raises(InIDConfigError):
        verify_webhook(BODY, signed(), None)
    monkeypatch.setenv("INID_WEBHOOK_SECRET", SECRET)
    assert verify_webhook(BODY, signed())["type"] == "user.created"
