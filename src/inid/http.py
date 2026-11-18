"""A framework-neutral request/response model, and the HTTP transport InID is reached with."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional
from urllib.parse import quote, unquote, urlsplit

from .errors import InIDNetworkError

# ---------- talking to InID ----------


@dataclass
class HTTPResponse:
    status: int
    body: bytes = b""
    headers: Mapping[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8") or "null")


# (method, url, headers, body, timeout) -> HTTPResponse. It raises InIDNetworkError when
# InID can't be reached; an HTTP error status is an answer, not an exception.
Transport = Callable[[str, str, Mapping[str, str], Optional[bytes], float], HTTPResponse]


def urllib_transport(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes], timeout: float) -> HTTPResponse:
    req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:  # noqa: S310 (the issuer is configured)
            return HTTPResponse(res.status, res.read(), dict(res.headers.items()))
    except urllib.error.HTTPError as err:
        return HTTPResponse(err.code, err.read() or b"", dict(err.headers.items()) if err.headers else {})
    except (urllib.error.URLError, OSError, ValueError) as err:
        raise InIDNetworkError(str(err)) from err


# ---------- the app's requests and responses ----------


def parse_cookies(header: Optional[str]) -> dict[str, str]:
    jar: dict[str, str] = {}
    for part in (header or "").split(";"):
        part = part.strip()
        at = part.find("=")
        if at > 0:
            jar[part[:at]] = unquote(part[at + 1 :])
    return jar


# Like JavaScript's encodeURIComponent, so every InID SDK writes the same cookies
def encode_component(value: str) -> str:
    return quote(value, safe="-_.!~*'()")


def serialize_cookies(jar: Mapping[str, str]) -> str:
    return "; ".join(f"{k}={encode_component(v)}" for k, v in jar.items())


@dataclass
class Request:
    """What InID needs of a request: its method, absolute URL and headers (the cookies come
    from the Cookie header unless given). body: only InID's own POST/PATCH routes read it."""

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Optional[Mapping[str, str]] = None
    body: bytes = b""

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        if self.cookies is None:
            self.cookies = parse_cookies(self.headers.get("cookie"))

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

    @property
    def origin(self) -> str:
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def path(self) -> str:
        return urlsplit(self.url).path or "/"

    @property
    def query(self) -> str:
        return urlsplit(self.url).query


@dataclass
class Response:
    """What to answer: a status, headers (a list, so several Set-Cookie fit) and a body."""

    status: int
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    @property
    def set_cookies(self) -> list[str]:
        return [v for k, v in self.headers if k.lower() == "set-cookie"]

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))
