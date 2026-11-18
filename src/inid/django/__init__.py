"""InID for Django.

    # settings.py
    INSTALLED_APPS = [..., "inid.django"]          # for {% load inid %}
    MIDDLEWARE = [..., "inid.django.InIDMiddleware"]
    INID = {"PROTECT": ["/dashboard", {"path": "/admin", "role": "admin"}]}   # keys from INID_* env
"""

from __future__ import annotations

import asyncio
import threading
from functools import wraps
from http.cookies import Morsel
from typing import Any, Callable, Optional, TypeVar, cast

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.utils.module_loading import import_string

from ..core import Auth, Config, InID, Protect
from ..http import Request, Response, parse_cookies

__all__ = ["InIDMiddleware", "get_inid", "get_protect", "inid_required", "to_django_response", "apply_cookies"]

_SETTINGS = {
    "PUBLISHABLE_KEY": "publishable_key",
    "SECRET_KEY": "secret_key",
    "ISSUER": "issuer",
    "API_PATH": "api_path",
    "SCOPE": "scope",
    "APP_URL": "app_url",
    "WEBHOOK_SECRET": "webhook_secret",
}
_cache: dict[str, Any] = {}
_lock = threading.Lock()


def _settings() -> dict[str, Any]:
    return dict(getattr(settings, "INID", None) or {})


def get_inid() -> InID:
    """The InID client for this project, from settings.INID (then INID_* env vars)."""
    conf = _settings()
    given = {arg: conf[name] for name, arg in _SETTINGS.items() if conf.get(name)}
    transport = conf.get("TRANSPORT")
    if isinstance(transport, str):
        transport = import_string(transport)
    # Rebuilt only when the settings change (tests), so the JWKS cache is kept
    key = repr((sorted(given.items()), id(transport)))
    with _lock:
        if _cache.get("key") != key:
            _cache["inid"] = InID(Config.from_env(**given), transport=transport)
            _cache["key"] = key
        return cast(InID, _cache["inid"])


def get_protect() -> Protect:
    return _settings().get("PROTECT")


def _core_request(request: HttpRequest, inid: InID) -> Request:
    method = request.method or "GET"
    # Only InID's own routes read the body (POST team)
    body = request.body if inid.is_api_path(request.path) and method in ("POST", "PATCH") else b""
    return Request(method, request.build_absolute_uri(), {"cookie": request.META.get("HTTP_COOKIE", "")}, body=body)


def apply_cookies(response: HttpResponse, set_cookies: list[str]) -> HttpResponse:
    """Adds InID's Set-Cookie headers as they are (Django's set_cookie would re-encode them)."""
    for raw in set_cookies:
        name_value, *attributes = [p.strip() for p in raw.split(";")]
        name, _, value = name_value.partition("=")
        morsel: Morsel[str] = Morsel()
        morsel.set(name, value, value)
        for attribute in attributes:
            key, _, val = attribute.partition("=")
            k = key.lower()
            if k in ("httponly", "secure"):
                morsel[k] = True
            elif k in ("path", "max-age", "samesite"):
                morsel[k] = val
        response.cookies[name] = morsel
    return response


def to_django_response(res: Response) -> HttpResponse:
    response = HttpResponse(res.body, status=res.status)
    for key, value in res.headers:
        if key.lower() != "set-cookie":
            response[key] = value
    return apply_cookies(response, res.set_cookies)


class InIDMiddleware:
    """Answers InID's routes under the api path, renews the session, applies settings.INID
    PROTECT and sets request.inid (an inid.Auth)."""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        # Fail at startup when the keys are missing, not on the first request
        get_inid()

    def __call__(self, request: HttpRequest) -> HttpResponse:
        inid = get_inid()
        result = inid.gate(_core_request(request, inid), get_protect())
        request.inid = result.auth  # type: ignore[attr-defined]
        if result.response is not None:
            return to_django_response(result.response)
        if result.cookies is not None:
            # The rest of this request sees the renewed session
            request.META["HTTP_COOKIE"] = result.cookie_header or ""
            request.COOKIES = parse_cookies(request.META["HTTP_COOKIE"])
        response = self.get_response(request)
        return apply_cookies(response, result.set_cookies)


F = TypeVar("F", bound=Callable[..., Any])


def _check(
    request: HttpRequest, role: Optional[str], permission: Optional[str], entrance: Optional[str], team_role: Optional[str] = None
) -> Optional[HttpResponse]:
    auth: Optional[Auth] = getattr(request, "inid", None)
    if auth is None:
        raise ImproperlyConfigured("inid_required needs inid.django.InIDMiddleware in MIDDLEWARE")
    if not auth.is_signed_in:
        return HttpResponseRedirect(get_inid().sign_in_url(request.get_full_path(), entrance))
    if (role or permission or team_role) and not auth.has(role=role, permission=permission, team_role=team_role):
        return HttpResponseForbidden("Forbidden")
    return None


def inid_required(
    view: Optional[F] = None,
    *,
    role: Optional[str] = None,
    permission: Optional[str] = None,
    entrance: Optional[str] = None,
    team_role: Optional[str] = None,
) -> Any:
    """@inid_required, or @inid_required(role="admin", permission=..., team_role=..., entrance=...):
    signs in whoever isn't, and answers 403 to whoever lacks the role, team role or permission."""

    def decorate(fn: F) -> F:
        if asyncio.iscoroutinefunction(fn):

            @wraps(fn)
            async def async_wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
                return _check(request, role, permission, entrance, team_role) or await fn(request, *args, **kwargs)

            return cast(F, async_wrapper)

        @wraps(fn)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            return _check(request, role, permission, entrance, team_role) or fn(request, *args, **kwargs)

        return cast(F, wrapper)

    return decorate(view) if view is not None else decorate
