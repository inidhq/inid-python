"""A fake InID: serves a JWKS, signs ID tokens with a test RSA key, and answers the token,
revoke and app API endpoints through an injected transport (no network)."""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any, Mapping, Optional
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from inid import Config, HTTPResponse, InID, InIDNetworkError, Request

ISSUER = "https://id.test"
PK = "pk_test_abc"
SK = "sk_test_xyz"
APP = "https://app.test"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _num(n: int) -> str:
    return b64(n.to_bytes((n.bit_length() + 7) // 8, "big"))


class FakeInID:
    def __init__(self) -> None:
        self.key = _KEY
        self.kid = "key-1"
        self.now = float(int(time.time()))
        self.calls: list[dict[str, Any]] = []
        self.codes: dict[str, str] = {}
        # Make the next refresh fail: a status (4xx/5xx) or "down" for a network error
        self.refresh_fails: Any = None
        self.down = False
        self.sub = "user_123"
        self.sid = "sess_1"
        self.claims: dict[str, Any] = {
            "given_name": "Laura",
            "family_name": "Gómez",
            "email": "laura@example.com",
            "email_verified": True,
            "phone_number": "+573001234567",
            "roles": ["member"],
            "permissions": ["invoices:read"],
            "public_metadata": {"plan": "pro"},
        }
        self.sessions = [
            {"id": "sess_1", "createdAt": "2026-11-01T00:00:00Z", "lastActiveAt": "2026-11-02T00:00:00Z", "device": "Mac"},
            {"id": "sess_2", "createdAt": "2026-11-01T00:00:00Z", "lastActiveAt": "2026-11-02T00:00:00Z", "device": None},
        ]

    def clock(self) -> float:
        return self.now

    # ---------- tokens ----------

    def jwk(self) -> dict[str, Any]:
        numbers = self.key.public_key().public_numbers()
        return {"kty": "RSA", "kid": self.kid, "alg": "RS256", "use": "sig", "n": _num(numbers.n), "e": _num(numbers.e)}

    def sign(self, claims: Mapping[str, Any], *, kid: Optional[str] = None, key: Any = None, alg: str = "RS256") -> str:
        header = b64(json.dumps({"alg": alg, "kid": kid or self.kid, "typ": "JWT"}).encode())
        payload = b64(json.dumps(dict(claims)).encode())
        signature = (key or self.key).sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{b64(signature)}"

    def id_token(self, *, ttl: int = 600, **overrides: Any) -> str:
        claims = {"iss": ISSUER, "aud": PK, "sub": self.sub, "sid": self.sid, "iat": int(self.now), "exp": int(self.now) + ttl, **self.claims}
        claims.update(overrides)
        return self.sign({k: v for k, v in claims.items() if v is not None})

    def other_key_token(self) -> str:
        claims = {"iss": ISSUER, "aud": PK, "sub": self.sub, "exp": int(self.now) + 600}
        return self.sign(claims, key=_OTHER_KEY)

    def issue_code(self, nonce: str) -> str:
        code = secrets.token_urlsafe(8)
        self.codes[code] = nonce
        return code

    # ---------- the transport ----------

    def calls_to(self, path: str) -> list[dict[str, Any]]:
        return [c for c in self.calls if urlsplit(c["url"]).path == path]

    def transport(self, method: str, url: str, headers: Mapping[str, str], body: Optional[bytes], timeout: float) -> HTTPResponse:
        form = {k: v[0] for k, v in parse_qs((body or b"").decode()).items()}
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body, "form": form, "timeout": timeout})
        if self.down:
            raise InIDNetworkError("down")
        path = urlsplit(url).path

        def answer(data: Any, status: int = 200) -> HTTPResponse:
            return HTTPResponse(status, json.dumps(data).encode(), {"content-type": "application/json"})

        if path == "/.well-known/jwks.json":
            return answer({"keys": [self.jwk(), {"kty": "EC", "kid": "ec", "crv": "P-256"}]})
        if path == "/oauth/token" and method == "POST":
            if form.get("grant_type") == "authorization_code":
                nonce = self.codes.pop(form.get("code", ""), None)
                if nonce is None:
                    return answer({"error": "invalid_grant"}, 400)
                return answer({"id_token": self.id_token(nonce=nonce), "refresh_token": "rt_new", "access_token": "at", "expires_in": 600})
            if form.get("grant_type") == "refresh_token":
                if self.refresh_fails == "down":
                    raise InIDNetworkError("down")
                if self.refresh_fails:
                    return answer({"error": "invalid_grant"}, self.refresh_fails)
                return answer({"id_token": self.id_token(), "refresh_token": "rt_renewed", "access_token": "at", "expires_in": 600})
        if path == "/oauth/revoke":
            return HTTPResponse(200, b"")
        if path == f"/v1/users/{self.sub}/sessions" and method == "GET":
            return answer({"sessions": self.sessions})
        if path.startswith(f"/v1/users/{self.sub}/sessions/") and method == "DELETE":
            return answer({"ended": 1})
        if path == f"/v1/users/{self.sub}" and method == "GET":
            return answer({"id": self.sub, "firstName": "Laura", "role": "member"})
        if path == f"/v1/users/{self.sub}/role" and method == "PUT":
            role = json.loads(body or b"{}").get("role")
            if role == "nope":
                return answer({"error": "unknown_role"}, 400)
            return answer({"id": self.sub, "role": role})
        if path == f"/v1/users/{self.sub}/metadata" and method == "PATCH":
            return answer({"ok": True})
        if path == "/v1/roles":
            return answer({"roles": [{"key": "admin", "name": "Admin", "permissions": []}], "defaultRole": "member", "entrances": []})
        if path == "/v1/invitations" and method == "POST":
            return answer({"invited": 1, "failed": []})
        return answer({"error": "not_found"}, 404)


def make_inid(fake: FakeInID, **settings: Any) -> InID:
    config = Config.from_env(publishable_key=PK, secret_key=SK, issuer=ISSUER, env={}, **settings)
    return InID(config, transport=fake.transport, clock=fake.clock)


def req(method: str, path: str, cookies: Optional[Mapping[str, str]] = None, origin: str = APP) -> Request:
    cookie = "; ".join(f"{k}={v}" for k, v in (cookies or {}).items())
    return Request(method, origin + path, {"cookie": cookie})


def cookie_named(set_cookies: list[str], name: str) -> Optional[str]:
    for c in set_cookies:
        if c.startswith(name + "="):
            return c
    return None


@pytest.fixture
def fake() -> FakeInID:
    return FakeInID()


@pytest.fixture
def inid(fake: FakeInID) -> InID:
    return make_inid(fake)
