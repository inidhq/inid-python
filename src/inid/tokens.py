"""InID's public keys (JWKS) and RS256 ID token verification."""

from __future__ import annotations

import base64
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers

from .errors import InIDError, InIDNetworkError
from .http import Transport, urllib_transport

JWKS_TTL_SECONDS = 3600
# Unknown kids are looked up at most this often, so made-up kids can't make us hammer InID
UNKNOWN_KID_INTERVAL_SECONDS = 1.0
MISSED_KIDS_CAP = 100


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _int(text: str) -> int:
    return int.from_bytes(from_b64url(text), "big")


@dataclass
class _Entry:
    at: float
    keys: dict[str, RSAPublicKey]
    missed: set[str] = field(default_factory=set)
    asked_at: float = 0.0


class JWKSCache:
    """InID's signing keys, kept an hour. A kid it doesn't know (InID just rotated) is looked
    for at once, but once per kid and at most once a second."""

    def __init__(self, issuer: str, transport: Optional[Transport] = None, clock: Callable[[], float] = time.time) -> None:
        self.issuer = issuer
        self.transport = transport or urllib_transport
        self.clock = clock
        self._entry: Optional[_Entry] = None
        self._lock = threading.Lock()

    def key_for(self, kid: str) -> Optional[RSAPublicKey]:
        with self._lock:
            known = self._entry
            now = self.clock()
            if known and now - known.at < JWKS_TTL_SECONDS:
                if kid in known.keys:
                    return known.keys[kid]
                if kid in known.missed or now - known.asked_at < UNKNOWN_KID_INTERVAL_SECONDS:
                    return None
                known.missed.add(kid)
                if len(known.missed) > MISSED_KIDS_CAP:
                    known.missed.clear()
            # Only lookups for unknown kids count toward "once a second"
            asked_at = now if known else 0.0
            if known:
                known.asked_at = now
            keys = self._fetch()
            self._entry = _Entry(at=now, keys=keys, missed=known.missed if known else set(), asked_at=asked_at)
            return keys.get(kid)

    def _fetch(self) -> dict[str, RSAPublicKey]:
        res = self.transport("GET", f"{self.issuer}/.well-known/jwks.json", {"accept": "application/json"}, None, 10.0)
        # Always 5xx-like: a JWKS that can't be read never ends anyone's session
        if not res.ok:
            raise InIDError("jwks_unavailable", 502)
        try:
            body = res.json()
        except ValueError as err:
            raise InIDError("jwks_unavailable", 502) from err
        keys: dict[str, RSAPublicKey] = {}
        for jwk in body.get("keys", []) if isinstance(body, dict) else []:
            if not isinstance(jwk, dict) or jwk.get("kty") != "RSA" or not isinstance(jwk.get("kid"), str):
                continue
            try:
                keys[jwk["kid"]] = RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
            except (KeyError, ValueError, TypeError):
                continue
        return keys


@dataclass
class VerifiedToken:
    claims: dict[str, Any]
    exp: int
    # Ended: still returned so the session can be renewed from it, never counts as signed in
    expired: bool


def verify_id_token(
    token: str,
    *,
    issuer: str,
    audience: str,
    jwks: JWKSCache,
    nonce: Optional[str] = None,
    now: Optional[float] = None,
) -> Optional[VerifiedToken]:
    """An ID token InID signed for this app, or None. Raises only when InID's keys can't be read."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3:
        return None
    try:
        header = json.loads(from_b64url(parts[0]))
        if not isinstance(header, dict) or header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            return None
        key = jwks.key_for(header["kid"])
        if key is None:
            return None
        key.verify(from_b64url(parts[2]), f"{parts[0]}.{parts[1]}".encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        claims = json.loads(from_b64url(parts[1]))
    except (InIDError, InIDNetworkError):
        raise
    except (InvalidSignature, ValueError, TypeError, UnicodeError):
        return None
    if not isinstance(claims, dict):
        return None
    exp = claims.get("exp")
    if claims.get("iss") != issuer or claims.get("aud") != audience or not isinstance(claims.get("sub"), str):
        return None
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        return None
    if nonce is not None and claims.get("nonce") != nonce:
        return None
    current = time.time() if now is None else now
    return VerifiedToken(claims=claims, exp=int(exp), expired=exp <= current)
