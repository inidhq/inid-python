"""InID for FastAPI and Starlette (ASGI).

    app = FastAPI()
    app.add_middleware(InIDMiddleware, protect=["/dashboard", {"path": "/admin", "role": "admin"}])

    @app.get("/me")
    def me(user: User = Depends(require_user())): ...
"""

# No `from __future__ import annotations`: FastAPI reads the dependencies' annotations at runtime
from typing import Any, Awaitable, Callable, MutableMapping, Optional

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import URL
from starlette.exceptions import HTTPException
from starlette.requests import Request as StarletteRequest

from .core import Auth, InID, Protect, User
from .http import Request, Response

__all__ = ["InIDMiddleware", "get_auth", "require", "require_bearer", "require_user"]

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]


class InIDMiddleware:
    """Answers InID's routes under the api path, renews the session, applies `protect` and
    sets request.state.inid (an inid.Auth). Settings not given come from INID_* env vars."""

    def __init__(self, app: ASGIApp, *, protect: Protect = None, inid: Optional[InID] = None, **settings: Any) -> None:
        self.app = app
        self.inid = inid or InID(**settings)
        self.protect = protect

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}
        request = Request(scope["method"], str(URL(scope=scope)), {"cookie": headers.get("cookie", "")})
        # The core is synchronous (urllib): keep it off the event loop
        result = await run_in_threadpool(self.inid.gate, request, self.protect)
        scope.setdefault("state", {})["inid"] = result.auth
        if result.response is not None:
            await _send(result.response, send)
            return
        if result.cookies is not None:
            # The rest of this request sees the renewed session
            kept = [(k, v) for k, v in scope.get("headers", []) if k.lower() != b"cookie"]
            scope = {**scope, "headers": kept + [(b"cookie", (result.cookie_header or "").encode("latin-1"))]}
        set_cookies = [(b"set-cookie", c.encode("latin-1")) for c in result.set_cookies]

        async def send_with_cookies(message: Message) -> None:
            if message["type"] == "http.response.start" and set_cookies:
                message = {**message, "headers": list(message.get("headers", [])) + set_cookies}
            await send(message)

        await self.app(scope, receive, send_with_cookies)


async def _send(response: Response, send: Send) -> None:
    headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in response.headers]
    headers.append((b"content-length", str(len(response.body)).encode("ascii")))
    await send({"type": "http.response.start", "status": response.status, "headers": headers})
    await send({"type": "http.response.body", "body": response.body})


def get_auth(request: StarletteRequest) -> Auth:
    """Dependency: who is signed in (anonymous Auth when nobody)."""
    auth = getattr(request.state, "inid", None)
    if auth is None:
        raise RuntimeError("inid.fastapi.InIDMiddleware is missing: app.add_middleware(InIDMiddleware)")
    return auth


def require_user() -> Callable[[StarletteRequest], User]:
    """Dependency: the signed-in user, or 401."""

    def dependency(request: StarletteRequest) -> User:
        user = get_auth(request).user
        if user is None:
            raise HTTPException(status_code=401, detail="not_signed_in")
        return user

    return dependency


def require(role: Optional[str] = None, permission: Optional[str] = None) -> Callable[[StarletteRequest], User]:
    """Dependency: the signed-in user with this role and/or permission; 401 or 403 otherwise."""
    signed_in = require_user()

    def dependency(request: StarletteRequest) -> User:
        user = signed_in(request)
        if (role or permission) and not user.has(role=role, permission=permission):
            raise HTTPException(status_code=403, detail="forbidden")
        return user

    return dependency


def require_bearer(inid: InID) -> Callable[[StarletteRequest], Awaitable[User]]:
    """Dependency for a native app's backend: the user in `Authorization: Bearer <id_token>`, or 401."""

    async def dependency(request: StarletteRequest) -> User:
        session = await run_in_threadpool(inid.verify_bearer, request.headers.get("authorization"))
        if session is None:
            raise HTTPException(status_code=401, detail="invalid_token", headers={"WWW-Authenticate": "Bearer"})
        return session.user

    return dependency
