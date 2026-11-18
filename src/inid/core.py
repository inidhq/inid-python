"""Sign-in with InID for an app's server.

The app is an OpenID Connect client of InID (its publishable key is the client id, its secret
key the client secret). Signing in is the authorization code flow with PKCE; the session is
InID's signed ID token in a cookie, checked with InID's public keys and never with a call to
InID. It lasts ten minutes; the refresh token (another cookie) renews it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence, Union
from urllib.parse import parse_qs, parse_qsl, quote, unquote, urlencode, urlsplit

from .errors import InIDConfigError, InIDError, InIDNetworkError
from .http import HTTPResponse, Request, Response, Transport, encode_component, serialize_cookies, urllib_transport
from .tokens import JWKSCache, VerifiedToken, b64url, from_b64url, verify_id_token
from .webhooks import verify_webhook as _verify_webhook

SESSION_COOKIE = "__inid_session"
REFRESH_COOKIE = "__inid_refresh"
FLOW_COOKIE = "__inid_flow"
# This browser signed out of the app: its next sign-in asks, instead of going in by itself
OUT_COOKIE = "__inid_out"

COOKIE_MAX_AGE = 30 * 86_400
FLOW_MAX_AGE = 600
# A session with less than this left is renewed now, not in the middle of the next request
RENEW_BEFORE_SECONDS = 60

DEFAULT_ISSUER = "https://id.inid.co"
DEFAULT_API_PATH = "/api/inid"
DEFAULT_SCOPE = "openid profile email phone"

_SAFE_PATH = re.compile(r"^/(?![/\\])")
_STATE = re.compile(r"^[\w-]{1,64}$", re.ASCII)
_TEAMS_REST = re.compile(r"^(/[\w-]{1,80}){0,4}$", re.ASCII)


def safe_return(to: Any) -> str:
    """Only somewhere in the app itself: a path, never another site."""
    return to if isinstance(to, str) and _SAFE_PATH.match(to) else "/"


def _random(size: int) -> str:
    return b64url(secrets.token_bytes(size))


def _cookie(name: str, value: str, *, max_age: int, secure: bool, path: str = "/") -> str:
    return f"{name}={encode_component(value)}; Path={path}; Max-Age={max_age}; HttpOnly; SameSite=Lax{'; Secure' if secure else ''}"


# ---------- configuration ----------


@dataclass(frozen=True)
class Config:
    publishable_key: str
    secret_key: str
    # InID itself; a local one while developing InID
    issuer: str = DEFAULT_ISSUER
    # Where the app's sign-in routes live
    api_path: str = DEFAULT_API_PATH
    scope: str = DEFAULT_SCOPE
    # The app's own origin, when the requests it sees don't say it (behind some proxies)
    app_url: Optional[str] = None
    webhook_secret: Optional[str] = None

    @classmethod
    def from_env(
        cls,
        *,
        publishable_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        issuer: Optional[str] = None,
        api_path: Optional[str] = None,
        scope: Optional[str] = None,
        app_url: Optional[str] = None,
        webhook_secret: Optional[str] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> "Config":
        """Settings given here win; the rest come from INID_* environment variables."""
        env = os.environ if env is None else env
        config = cls(
            publishable_key=publishable_key or env.get("INID_PUBLISHABLE_KEY", ""),
            secret_key=secret_key or env.get("INID_SECRET_KEY", ""),
            issuer=(issuer or env.get("INID_ISSUER") or DEFAULT_ISSUER).rstrip("/"),
            api_path=(api_path or DEFAULT_API_PATH).rstrip("/"),
            scope=scope or DEFAULT_SCOPE,
            app_url=(app_url or env.get("INID_APP_URL") or "").rstrip("/") or None,
            webhook_secret=webhook_secret or env.get("INID_WEBHOOK_SECRET") or None,
        )
        if not config.publishable_key.startswith("pk_"):
            raise InIDConfigError("INID_PUBLISHABLE_KEY is missing: set it to your publishable key (pk_...)")
        if not config.secret_key.startswith("sk_"):
            raise InIDConfigError("INID_SECRET_KEY is missing: set it to your secret key (sk_...)")
        return config


# ---------- the user, the session, who is signed in ----------


def _allows(user: Optional["User"], role: Optional[str], permission: Optional[str], team_role: Optional[str] = None) -> bool:
    # None of them: someone signed in is enough. A permission counts from their app role or
    # their active team's role.
    if user is None:
        return False
    if role and role not in user.roles:
        return False
    if team_role and (user.team is None or user.team.role != team_role):
        return False
    if permission and permission not in user.permissions and (user.team is None or permission not in user.team.permissions):
        return False
    return True


def _strings(v: Any) -> tuple[str, ...]:
    return tuple(x for x in v if isinstance(x, str)) if isinstance(v, list) else ()


@dataclass(frozen=True)
class Team:
    """The person's active team (apps with teams), chosen per session: their role there and
    what it allows."""

    id: str
    slug: str = ""
    name: str = ""
    role: str = ""
    permissions: tuple[str, ...] = ()

    @classmethod
    def from_claim(cls, claim: Any) -> Optional["Team"]:
        """The ID token's team claim; None when it's missing or malformed."""
        if not isinstance(claim, dict) or not isinstance(claim.get("id"), str) or not isinstance(claim.get("role"), str):
            return None
        slug, name = claim.get("slug"), claim.get("name")
        return cls(
            id=claim["id"],
            slug=slug if isinstance(slug, str) else "",
            name=name if isinstance(name, str) else "",
            role=claim["role"],
            permissions=_strings(claim.get("permissions")),
        )

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "slug": self.slug, "name": self.name, "role": self.role, "permissions": list(self.permissions)}


@dataclass(frozen=True)
class User:
    # The person's id at this app (InID gives each app its own)
    id: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = None
    email_verified: bool = False
    # E.164
    phone: Optional[str] = None
    # The app's roles for this person and what they allow; empty when the app has no roles
    roles: tuple[str, ...] = ()
    permissions: tuple[str, ...] = ()
    public_metadata: dict[str, Any] = field(default_factory=dict)
    # The team they're working in now (apps with teams), with their role there; None: none
    team: Optional[Team] = None

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> "User":
        def text(v: Any) -> Optional[str]:
            return v if isinstance(v, str) and v else None

        first, last = text(claims.get("given_name")), text(claims.get("family_name"))
        metadata = claims.get("public_metadata")
        return cls(
            id=str(claims.get("sub")),
            first_name=first,
            last_name=last,
            name=" ".join(p for p in (first, last) if p) or text(claims.get("name")),
            email=text(claims.get("email")),
            email_verified=claims.get("email_verified") is True,
            phone=text(claims.get("phone_number")),
            roles=_strings(claims.get("roles")),
            permissions=_strings(claims.get("permissions")),
            public_metadata=dict(metadata) if isinstance(metadata, dict) else {},
            team=Team.from_claim(claims.get("team")),
        )

    def has(self, role: Optional[str] = None, permission: Optional[str] = None, team_role: Optional[str] = None) -> bool:
        """has(role="admin"), has(permission="invoices:read"), has(team_role="admin"); every one
        given must hold; none is True (a signed-in user is enough, as for a path-only protect
        rule). A permission counts from their app role or their active team's role."""
        return _allows(self, role, permission, team_role)

    def to_json(self) -> dict[str, Any]:
        """The same JSON as every InID SDK (camelCase)."""
        return {
            "id": self.id,
            "firstName": self.first_name,
            "lastName": self.last_name,
            "name": self.name,
            "email": self.email,
            "emailVerified": self.email_verified,
            "phone": self.phone,
            "roles": list(self.roles),
            "permissions": list(self.permissions),
            "publicMetadata": self.public_metadata,
            "team": self.team.to_json() if self.team else None,
        }


@dataclass(frozen=True)
class Session:
    user: User
    # When this session's token ends (seconds since 1970); renewed before then
    expires_at: int
    claims: dict[str, Any]

    @classmethod
    def of(cls, checked: VerifiedToken) -> "Session":
        return cls(user=User.from_claims(checked.claims), expires_at=checked.exp, claims=checked.claims)


@dataclass(frozen=True)
class Auth:
    """Who is signed in, for a page or an API route."""

    session: Optional[Session] = None

    @property
    def is_signed_in(self) -> bool:
        return self.session is not None

    @property
    def user(self) -> Optional[User]:
        return self.session.user if self.session else None

    @property
    def user_id(self) -> Optional[str]:
        return self.session.user.id if self.session else None

    def has(self, role: Optional[str] = None, permission: Optional[str] = None, team_role: Optional[str] = None) -> bool:
        return bool(self.user and self.user.has(role=role, permission=permission, team_role=team_role))

    def __bool__(self) -> bool:
        return self.is_signed_in


# ---------- the gate's rules ----------


@dataclass(frozen=True)
class Rule:
    """A path (or pattern) that needs someone signed in, and maybe a role, a role in their
    active team or a permission. entrance: the door its sign-in goes through, with that door's
    rules."""

    path: Union[str, "re.Pattern[str]"]
    role: Optional[str] = None
    permission: Optional[str] = None
    entrance: Optional[str] = None
    team_role: Optional[str] = None


RuleLike = Union[str, "re.Pattern[str]", Rule, Mapping[str, Any]]
Protect = Union[Sequence[RuleLike], Callable[[Request], bool], None]


def as_rule(rule: RuleLike) -> Rule:
    if isinstance(rule, Rule):
        return rule
    if isinstance(rule, Mapping):
        return Rule(
            path=rule["path"],
            role=rule.get("role"),
            permission=rule.get("permission"),
            entrance=rule.get("entrance"),
            team_role=rule.get("team_role") or rule.get("teamRole"),
        )
    return Rule(path=rule)


def _under(path: str, rule: Union[str, "re.Pattern[str]"]) -> bool:
    if isinstance(rule, str):
        return path == rule or path.startswith(rule if rule.endswith("/") else rule + "/")
    return rule.search(path) is not None


def rules_for(request: Request, protect: Protect) -> list[Rule]:
    if not protect:
        return []
    if callable(protect):
        return [Rule("/")] if protect(request) else []
    path = request.path
    return [r for r in map(as_rule, protect) if _under(path, r.path)]


# ---------- results ----------


@dataclass
class SessionResult:
    session: Optional[Session]
    # Cookies to send back to the browser (a renewed or ended session)
    set_cookies: list[str] = field(default_factory=list)
    # The request's cookies as they are now, for the rest of this same request; None: unchanged
    cookies: Optional[dict[str, str]] = None

    @property
    def cookie_header(self) -> Optional[str]:
        return None if self.cookies is None else serialize_cookies(self.cookies)


@dataclass
class GateResult:
    auth: Auth
    # When set, answer with it: InID's routes, a sign-in, back from Google, a 403
    response: Optional[Response] = None
    # Cookies the page's own response must carry (a renewed session)
    set_cookies: list[str] = field(default_factory=list)
    cookies: Optional[dict[str, str]] = None

    @property
    def cookie_header(self) -> Optional[str]:
        return None if self.cookies is None else serialize_cookies(self.cookies)


def _json_response(body: Any, status: int = 200, cookies: Sequence[str] = (), no_store: bool = True) -> Response:
    headers = [("content-type", "application/json")]
    if no_store:
        headers.append(("cache-control", "no-store"))
    headers += [("set-cookie", c) for c in cookies]
    return Response(status, headers, json.dumps(body, separators=(",", ":")).encode("utf-8"))


def _redirect(to: str, cookies: Sequence[str] = (), status: int = 302) -> Response:
    return Response(status, [("location", to), ("cache-control", "no-store")] + [("set-cookie", c) for c in cookies])


def _leave_frame(to: str, cookies: Sequence[str] = ()) -> Response:
    # A tiny page that sends the whole window on (InID's form was in a frame of the app's page)
    target = json.dumps(to).replace("<", "\\u003c")
    html = f'<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace({target})</script>'
    headers = [("content-type", "text/html; charset=utf-8"), ("cache-control", "no-store")] + [("set-cookie", c) for c in cookies]
    return Response(200, headers, html.encode("utf-8"))


def _bearer_token(value: str) -> str:
    value = value.strip()
    return value[7:].strip() if value[:7].lower() == "bearer " else value


# ---------- the client ----------


class InID:
    """One InID for this server: its routes, sessions, gate and app API.

        inid = InID()   # INID_PUBLISHABLE_KEY, INID_SECRET_KEY (and INID_ISSUER, INID_APP_URL...)
        result = inid.gate(request, protect=["/dashboard", Rule("/admin", role="admin")])
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        *,
        transport: Optional[Transport] = None,
        clock: Callable[[], float] = time.time,
        **settings: Any,
    ) -> None:
        self.config = config or Config.from_env(**settings)
        self.transport: Transport = transport or urllib_transport
        self.clock = clock
        self.jwks = JWKSCache(self.config.issuer, self.transport, clock)
        basic = f"{quote(self.config.publishable_key, safe='')}:{quote(self.config.secret_key, safe='')}"
        self._basic = "Basic " + base64.b64encode(basic.encode("utf-8")).decode("ascii")

    # ---------- tokens ----------

    def verify(self, token: str, nonce: Optional[str] = None) -> Optional[VerifiedToken]:
        c = self.config
        return verify_id_token(token, issuer=c.issuer, audience=c.publishable_key, jwks=self.jwks, nonce=nonce, now=self.clock())

    def verify_bearer(self, authorization: Optional[str]) -> Optional[Session]:
        """A native app's ID token sent as `Authorization: Bearer <id_token>` (the header or the
        bare token): its session, or None when it isn't valid or has ended."""
        if not authorization:
            return None
        checked = self.verify(_bearer_token(authorization))
        return Session.of(checked) if checked and not checked.expired else None

    def _form(self, path: str, params: Mapping[str, str], timeout: float = 10.0) -> HTTPResponse:
        headers = {"content-type": "application/x-www-form-urlencoded", "authorization": self._basic, "accept": "application/json"}
        return self.transport("POST", f"{self.config.issuer}{path}", headers, urlencode(params).encode("ascii"), timeout)

    def _token(self, params: Mapping[str, str]) -> dict[str, Any]:
        res = self._form("/oauth/token", params)
        try:
            body = res.json()
        except ValueError:
            body = {}
        body = body if isinstance(body, dict) else {}
        if not res.ok:
            raise InIDError(str(body.get("error") or "token_failed"), res.status)
        if not isinstance(body.get("id_token"), str):
            raise InIDError("invalid_token_response", 502)
        return body

    # ---------- the session ----------

    def _session_cookies(self, tokens: Mapping[str, Any], secure: bool) -> list[str]:
        return [
            _cookie(SESSION_COOKIE, tokens["id_token"], max_age=COOKIE_MAX_AGE, secure=secure),
            _cookie(REFRESH_COOKIE, str(tokens.get("refresh_token") or ""), max_age=COOKIE_MAX_AGE, secure=secure),
        ]

    @staticmethod
    def _clear_cookies(secure: bool) -> list[str]:
        return [_cookie(SESSION_COOKIE, "", max_age=0, secure=secure), _cookie(REFRESH_COOKIE, "", max_age=0, secure=secure)]

    def session(self, cookies: Mapping[str, str], *, refresh: bool = False, secure: bool = True) -> SessionResult:
        """The session in these cookies. With refresh, one that ends within a minute is renewed."""
        jar = dict(cookies)
        try:
            current = self.verify(jar[SESSION_COOKIE]) if jar.get(SESSION_COOKIE) else None
        except InIDError:
            # InID's keys can't be read (and aren't cached): nobody can be told signed in, but
            # public pages still work
            current = None
        now = self.clock()
        if current and current.exp - now > RENEW_BEFORE_SECONDS:
            return SessionResult(Session.of(current))
        still_good = Session.of(current) if current and not current.expired else None
        if not refresh or not jar.get(REFRESH_COOKIE):
            return SessionResult(still_good)
        try:
            tokens = self._token({"grant_type": "refresh_token", "refresh_token": jar[REFRESH_COOKIE]})
            renewed = self.verify(tokens["id_token"])
            if not renewed:
                raise InIDError("invalid_id_token", 400)
        except InIDNetworkError:
            # InID couldn't be reached: what's still valid stays
            return SessionResult(still_good)
        except InIDError as err:
            # InID said no (signed out elsewhere, authorization taken back): the session is over
            if err.status and err.status < 500:
                rest = {k: v for k, v in jar.items() if k not in (SESSION_COOKIE, REFRESH_COOKIE)}
                return SessionResult(None, self._clear_cookies(secure), rest)
            return SessionResult(still_good)
        jar[SESSION_COOKIE] = tokens["id_token"]
        jar[REFRESH_COOKIE] = str(tokens.get("refresh_token") or "")
        return SessionResult(Session.of(renewed), self._session_cookies(tokens, secure), jar)

    def auth(self, request: Request) -> Auth:
        """Who is signed in, from a request (it reads the session; the gate is what renews it)."""
        return Auth(self.session(request.cookies or {}).session)

    def _secure(self, request: Request) -> bool:
        return (self.config.app_url or request.origin).startswith("https://")

    # ---------- the routes under api_path ----------

    def handle(self, request: Request) -> Response:
        """The app's routes under api_path: signin, callback, signout, session, sessions, team, teams."""
        try:
            return self._handle(request)
        except InIDError as err:
            status = err.status if err.status and 400 <= err.status < 600 else 502
            return _json_response({"error": err.code}, status)

    def _handle(self, request: Request) -> Response:
        c = self.config
        origin = c.app_url or request.origin
        secure = origin.startswith("https://")
        path = request.path
        action = path[len(c.api_path) + 1 :] if path.startswith(c.api_path + "/") else ""
        query = parse_qs(request.query, keep_blank_values=True)
        q = lambda name: query[name][0] if name in query else None  # noqa: E731
        redirect_uri = f"{origin}{c.api_path}/callback"
        cookies = request.cookies or {}
        method = request.method

        if method == "GET" and action == "signin":
            # display=embed: InID's form inside the app's own page (<inid-sign-in>)
            embed = q("display") == "embed"
            # Back from Google, the frame goes on with the same sign-in (its flow cookie stays)
            resume = q("continue")
            if embed and resume is not None:
                given = parse_qs(resume, keep_blank_values=True)
                kept = [(k, given[k][0]) for k in ("request", "session", "from", "lang") if given.get(k, [""])[0]]
                kept.append(("display", "embed"))
                return _redirect(f"{c.issuer}/oauth/authorize/continue?{urlencode(kept)}")
            flow: dict[str, Any] = {"state": _random(16), "nonce": _random(16), "verifier": _random(32), "returnTo": safe_return(q("return_to"))}
            if embed:
                # page: where the form is, to go on there after Google
                flow.update(embed=True, page=safe_return(q("page") or q("return_to")))
            params: dict[str, str] = {
                "client_id": c.publishable_key,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": c.scope,
                "state": flow["state"],
                "nonce": flow["nonce"],
                "code_challenge": b64url(hashlib.sha256(flow["verifier"].encode("ascii")).digest()),
                "code_challenge_method": "S256",
            }
            for passed in ("ui_locales", "login_hint", "prompt", "entrance"):
                if q(passed):
                    params[passed] = q(passed)  # type: ignore[assignment]
            # In the page, someone InID knows still clicks to go in: never signed in by just loading it
            if embed:
                params["display"] = "embed"
                params["prompt"] = "login"
            # Right after signing out, InID asks too: they chose to leave
            if cookies.get(OUT_COOKIE):
                params["prompt"] = "login"
            # One cookie per sign-in (named by its state): two at once don't overwrite each other
            value = b64url(json.dumps(flow, separators=(",", ":")).encode("utf-8"))
            flow_cookie = _cookie(f"{FLOW_COOKIE}_{flow['state']}", value, max_age=FLOW_MAX_AGE, path=c.api_path, secure=secure)
            return _redirect(f"{c.issuer}/oauth/authorize?{urlencode(params)}", [flow_cookie])

        if method == "GET" and action == "callback":
            state = q("state") or ""
            flow_name = f"{FLOW_COOKIE}_{state}" if _STATE.match(state) else FLOW_COOKIE
            clear_flow = _cookie(flow_name, "", max_age=0, path=c.api_path, secure=secure)
            flow_data: Optional[dict[str, Any]] = None
            try:
                parsed = json.loads(from_b64url(cookies.get(flow_name, "")))
                flow_data = parsed if isinstance(parsed, dict) else None
            except (ValueError, TypeError):
                pass
            # Back from Google, a sign-in that started in the app's page goes on in that page
            resume = q("inid_continue")
            if resume is not None and flow_data and flow_data.get("embed") and q("state") == flow_data.get("state"):
                page = urlsplit(safe_return(flow_data.get("page")))
                pairs = [(k, v) for k, v in parse_qsl(page.query, keep_blank_values=True) if k != "inid_continue"]
                pairs.append(("inid_continue", resume))
                return _redirect(f"{page.path}?{urlencode(pairs)}")
            code = q("code")
            # From InID's form inside the page, the whole page goes on (not just its frame)
            go = _leave_frame if flow_data and flow_data.get("embed") else _redirect
            return_to = safe_return(flow_data.get("returnTo") if flow_data else None)
            if not flow_data or not code or q("state") != flow_data.get("state"):
                return go(return_to, [clear_flow])
            tokens = self._token({"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri, "code_verifier": str(flow_data.get("verifier", ""))})
            if not self.verify(tokens["id_token"], nonce=str(flow_data.get("nonce", ""))):
                raise InIDError("invalid_id_token", 400)
            return go(return_to, [clear_flow, *self._session_cookies(tokens, secure), _cookie(OUT_COOKIE, "", max_age=0, secure=secure)])

        if method == "POST" and action == "signout":
            refresh_token = cookies.get(REFRESH_COOKIE)
            # The sign-in ends at InID too (best effort); the person's InID stays signed in
            if refresh_token:
                try:
                    self._form("/oauth/revoke", {"token": refresh_token, "token_type_hint": "refresh_token"}, timeout=3.0)
                except Exception:  # noqa: BLE001
                    pass
            out = _cookie(OUT_COOKIE, "1", max_age=COOKIE_MAX_AGE, secure=secure)
            return _json_response({"ok": True}, cookies=[*self._clear_cookies(secure), out])

        # The person's own sessions at this app, and ending them: one or all but this one
        if action == "sessions" or action.startswith("sessions/"):
            current = self.session(cookies).session
            if not current:
                return _json_response({"error": "not_signed_in"}, 401)
            base = f"{c.issuer}/v1/users/{quote(current.user.id, safe='')}/sessions"
            as_app = {"authorization": f"Bearer {c.secret_key}", "accept": "application/json"}
            sid = current.claims.get("sid") if isinstance(current.claims.get("sid"), str) else None

            def listed() -> list[dict[str, Any]]:
                res = self.transport("GET", base, as_app, None, 10.0)
                try:
                    sessions = res.json().get("sessions") if res.ok else None
                except (ValueError, AttributeError):
                    sessions = None
                if not isinstance(sessions, list):
                    raise InIDError("sessions_unavailable", 502)
                return [x for x in sessions if isinstance(x, dict)]

            if method == "GET":
                return _json_response({"sessions": [{**x, "current": x.get("id") == sid} for x in listed()]})
            if method == "DELETE":
                one = unquote(action[len("sessions/") :]) if action.startswith("sessions/") else ""
                ending = [one] if one else [x["id"] for x in listed() if x.get("id") != sid] if q("others") else []
                for ended in ending:
                    self.transport("DELETE", f"{base}/{quote(ended, safe='')}", as_app, None, 10.0)
                return _json_response({"ended": len(ending)})

        # The person's active team: POST team {"teamId"} (None: their own account). InID renews
        # the session with it, so the new cookies (and this answer) say the team.
        if method == "POST" and action == "team":
            current = self.session(cookies).session
            if not current or not cookies.get(REFRESH_COOKIE):
                return _json_response({"error": "not_signed_in"}, 401)
            try:
                given = json.loads(request.body or b"{}")
            except ValueError:
                given = {}
            asked = given.get("teamId") if isinstance(given, dict) else None
            if asked is not None and not isinstance(asked, str):
                return _json_response({"error": "invalid_request"}, 400)
            try:
                tokens = self._token({"grant_type": "refresh_token", "refresh_token": cookies[REFRESH_COOKIE], "team": asked or ""})
                renewed = self.verify(tokens["id_token"])
                if not renewed:
                    raise InIDError("invalid_id_token", 400)
            except InIDNetworkError:
                return _json_response({"error": "inid_unreachable"}, 502)
            except InIDError as err:
                # The session itself is over; anything else (a team they aren't in) leaves it as it was
                if err.code == "invalid_grant":
                    return _json_response({"error": "not_signed_in"}, 401, cookies=self._clear_cookies(secure))
                return _json_response({"error": err.code}, 400 if err.status and err.status < 500 else 502)
            return _json_response({"user": User.from_claims(renewed.claims).to_json()}, cookies=self._session_cookies(tokens, secure))

        # The person's own teams, through the app's server (InID checks what their team role lets
        # them do): teams, teams/:id, teams/:id/members... -> {issuer}/v1/users/{sub}/teams...
        if action == "teams" or action.startswith("teams/"):
            current = self.session(cookies).session
            if not current:
                return _json_response({"error": "not_signed_in"}, 401)
            rest = action[len("teams") :]
            if not _TEAMS_REST.match(rest) or method not in ("GET", "POST", "PATCH", "DELETE"):
                return _json_response({"error": "not_found"}, 404)
            headers = {"authorization": f"Bearer {c.secret_key}", "accept": "application/json"}
            data = None if method in ("GET", "DELETE") else (request.body or None)
            if data:
                headers["content-type"] = "application/json"
            res = self.transport(method, f"{c.issuer}/v1/users/{quote(current.user.id, safe='')}/teams{rest}", headers, data, 10.0)
            try:
                answer = res.json()
            except ValueError:
                answer = {"error": "teams_unavailable"}
            return _json_response(answer, 502 if res.status >= 500 else res.status)

        if method == "GET" and action == "session":
            result = self.session(cookies, refresh=True, secure=secure)
            body = {
                "user": result.session.user.to_json() if result.session else None,
                "accountUrl": f"{c.issuer}/account?{urlencode({'client_id': c.publishable_key})}",
            }
            return _json_response(body, cookies=result.set_cookies)

        return _json_response({"error": "not_found"}, 404, no_store=False)

    # ---------- the gate ----------

    def is_api_path(self, path: str) -> bool:
        return path == self.config.api_path or path.startswith(self.config.api_path + "/")

    def sign_in_url(self, return_to: str, entrance: Optional[str] = None) -> str:
        """The app's own sign-in route, coming back to return_to (a path)."""
        params = {"return_to": return_to, **({"entrance": entrance} if entrance else {})}
        return f"{self.config.api_path}/signin?{urlencode(params)}"

    def gate(self, request: Request, protect: Protect = None, *, routes: bool = True) -> GateResult:
        """What every framework's middleware does with each request."""
        c = self.config
        anonymous = Auth()
        if self.is_api_path(request.path):
            return GateResult(anonymous, self.handle(request) if routes else None)
        # Back from Google on the app's own domain: Google's answer is for InID, so go straight there
        query = parse_qs(request.query, keep_blank_values=True)
        if query.get("state", [""])[0].startswith("inidg_") and ("code" in query or "error" in query):
            return GateResult(anonymous, Response(307, [("location", f"{c.issuer}/oauth/google/callback?{request.query}")]))
        result = self.session(request.cookies or {}, refresh=True, secure=self._secure(request))
        session, set_cookies = result.session, result.set_cookies
        rules = rules_for(request, protect)
        if not session and rules:
            entrance = next((r.entrance for r in rules if r.entrance), None)
            return_to = request.path + (f"?{request.query}" if request.query else "")
            to = (c.app_url or request.origin) + self.sign_in_url(return_to, entrance)
            response = Response(307, [("location", to), ("cache-control", "no-store")] + [("set-cookie", x) for x in set_cookies])
            return GateResult(anonymous, response)
        if session and any(not _allows(session.user, r.role, r.permission, r.team_role) for r in rules):
            # Signed in, without the role or permission the path needs
            response = Response(403, [("content-type", "text/plain; charset=utf-8")] + [("set-cookie", x) for x in set_cookies], b"Forbidden")
            return GateResult(Auth(session), response)
        return GateResult(Auth(session), None, set_cookies, result.cookies)

    # ---------- webhooks ----------

    def verify_webhook(self, raw_body: Union[str, bytes], header: Optional[str], *, now: Optional[float] = None) -> dict[str, Any]:
        """The event in an InID webhook; raises InIDWebhookError when it isn't InID's."""
        return _verify_webhook(raw_body, header, self.config.webhook_secret, now=now)

    # ---------- the app API (secret key) ----------

    def api(self, method: str, path: str, body: Any = None) -> Any:
        """Any call to InID's app API with the secret key; raises InIDError on an error answer."""
        headers = {"authorization": f"Bearer {self.config.secret_key}", "accept": "application/json"}
        data = None
        if body is not None:
            headers["content-type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        res = self.transport(method, f"{self.config.issuer}{path}", headers, data, 10.0)
        try:
            answer = res.json() if res.body else None
        except ValueError:
            answer = None
        if not res.ok:
            code = answer.get("error") if isinstance(answer, dict) else None
            raise InIDError(str(code or "request_failed"), res.status)
        return answer

    def get_user(self, sub: str) -> dict[str, Any]:
        return self.api("GET", f"/v1/users/{quote(sub, safe='')}")

    def set_role(self, sub: str, role: Optional[str]) -> dict[str, Any]:
        """None: back to the role of new users."""
        return self.api("PUT", f"/v1/users/{quote(sub, safe='')}/role", {"role": role})

    def update_metadata(self, sub: str, *, public: Optional[Mapping[str, Any]] = None, private: Optional[Mapping[str, Any]] = None) -> Any:
        """Each one given replaces the previous (8 KB at most); public travels in the ID token."""
        body: dict[str, Any] = {}
        if public is not None:
            body["publicMetadata"] = dict(public)
        if private is not None:
            body["privateMetadata"] = dict(private)
        return self.api("PATCH", f"/v1/users/{quote(sub, safe='')}/metadata", body)

    def list_roles(self) -> dict[str, Any]:
        return self.api("GET", "/v1/roles")

    def invite(self, email: str, role: Optional[str] = None) -> Any:
        return self.api("POST", "/v1/invitations", {"email": email, **({"role": role} if role else {})})

    def invite_many(self, invitations: Sequence[Mapping[str, Any]]) -> Any:
        """Up to 200 at once: [{"email": ..., "role": ...}]; answers {"invited", "failed"}."""
        return self.api("POST", "/v1/invitations", {"invitations": [dict(i) for i in invitations]})
