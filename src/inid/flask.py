"""InID for Flask.

    app = Flask(__name__)
    InID(app, protect=["/dashboard", {"path": "/admin", "role": "admin"}])   # keys from INID_* env

    @app.get("/admin/reports")
    @inid_required(role="admin")
    def reports(): return g.inid.user.name
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, Optional, TypeVar, cast

from flask import Flask, current_app, g, redirect, request
from flask import Response as FlaskResponse

from .core import Config
from .core import InID as InIDClient
from .core import Protect
from .http import Request, Response

__all__ = ["InID", "inid_required"]

_SETTINGS = {
    "PUBLISHABLE_KEY": "publishable_key",
    "SECRET_KEY": "secret_key",
    "ISSUER": "issuer",
    "API_PATH": "api_path",
    "SCOPE": "scope",
    "APP_URL": "app_url",
    "WEBHOOK_SECRET": "webhook_secret",
}


def _to_flask(res: Response) -> FlaskResponse:
    response = FlaskResponse(res.body, status=res.status)
    response.headers.clear()
    for key, value in res.headers:
        response.headers.add(key, value)
    return response


class InID:
    """The Flask extension: answers InID's routes under the api path, renews the session,
    applies `protect` and sets g.inid (an inid.Auth). Settings come from the arguments, then
    app.config["INID"] ({"PUBLISHABLE_KEY": ..., "PROTECT": [...]}), then INID_* env vars."""

    def __init__(self, app: Optional[Flask] = None, *, protect: Protect = None, client: Optional[InIDClient] = None, **settings: Any) -> None:
        self.protect = protect
        self.client = client
        self.settings = settings
        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        conf = dict(app.config.get("INID") or {})
        if self.client is None:
            given = {arg: conf[name] for name, arg in _SETTINGS.items() if conf.get(name)}
            transport = self.settings.pop("transport", None) or conf.get("TRANSPORT")
            given.update(self.settings)
            self.client = InIDClient(Config.from_env(**given), transport=transport)
        if self.protect is None:
            self.protect = conf.get("PROTECT")
        app.extensions["inid"] = self
        app.before_request(self._before)
        app.after_request(self._after)

    def _before(self) -> Optional[FlaskResponse]:
        assert self.client is not None
        # Only InID's own routes read the body (POST team)
        body = request.get_data() if self.client.is_api_path(request.path) and request.method in ("POST", "PATCH") else b""
        core = Request(request.method, request.url, {"cookie": request.headers.get("Cookie", "")}, body=body)
        result = self.client.gate(core, self.protect)
        g.inid = result.auth
        g._inid_set_cookies = result.set_cookies
        if result.response is not None:
            return _to_flask(result.response)
        if result.cookies is not None:
            # The rest of this request sees the renewed session (request.cookies is cached)
            request.environ["HTTP_COOKIE"] = result.cookie_header or ""
            request.__dict__.pop("cookies", None)
        return None

    def _after(self, response: FlaskResponse) -> FlaskResponse:
        for cookie in g.pop("_inid_set_cookies", []):
            response.headers.add("Set-Cookie", cookie)
        return response


F = TypeVar("F", bound=Callable[..., Any])


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
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            auth = g.get("inid")
            if auth is None:
                raise RuntimeError("inid_required needs the InID(app) extension")
            if not auth.is_signed_in:
                ext: InID = current_app.extensions["inid"]
                assert ext.client is not None
                return_to = request.full_path if request.query_string else request.path
                return redirect(ext.client.sign_in_url(return_to, entrance))
            if (role or permission or team_role) and not auth.has(role=role, permission=permission, team_role=team_role):
                return FlaskResponse("Forbidden", status=403, mimetype="text/plain")
            return fn(*args, **kwargs)

        return cast(F, wrapper)

    return decorate(view) if view is not None else decorate
