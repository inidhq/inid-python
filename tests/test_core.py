from __future__ import annotations

import base64
import hashlib
import json
import re
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import pytest
from conftest import APP, ISSUER, PK, SK, FakeInID, cookie_named, make_inid, req

from inid import (
    Auth,
    Config,
    InID,
    InIDConfigError,
    InIDError,
    Request,
    Rule,
    User,
    safe_return,
)
from inid.tokens import JWKSCache, b64url, from_b64url


def query_of(location: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query, keep_blank_values=True).items()}


def flow_of(set_cookies: list[str]) -> tuple[str, dict]:
    raw = next(c for c in set_cookies if c.startswith("__inid_flow_"))
    name, value = raw.split(";")[0].split("=", 1)
    return name, json.loads(from_b64url(unquote(value)))


def sign_in(inid: InID, path: str = "/api/inid/signin?return_to=/panel", cookies: dict | None = None):
    res = inid.handle(req("GET", path, cookies))
    name, flow = flow_of(res.set_cookies)
    return res, name, flow


# ---------- configuration ----------


def test_config_from_env_and_errors():
    env = {"INID_PUBLISHABLE_KEY": PK, "INID_SECRET_KEY": SK, "INID_ISSUER": "https://id.example/", "INID_APP_URL": "https://app.example/"}
    config = Config.from_env(env=env)
    assert config.issuer == "https://id.example"
    assert config.app_url == "https://app.example"
    assert config.api_path == "/api/inid"
    assert config.scope == "openid profile email phone"
    assert Config.from_env(env={"INID_PUBLISHABLE_KEY": PK, "INID_SECRET_KEY": SK}).issuer == "https://id.inid.co"
    with pytest.raises(InIDConfigError, match="INID_PUBLISHABLE_KEY"):
        Config.from_env(env={"INID_SECRET_KEY": SK})
    with pytest.raises(InIDConfigError, match="INID_SECRET_KEY"):
        Config.from_env(env={"INID_PUBLISHABLE_KEY": PK, "INID_SECRET_KEY": "pk_wrong"})


def test_safe_return():
    assert safe_return("/panel?x=1") == "/panel?x=1"
    for bad in ("//evil.com", "/\\evil.com", "https://evil.com", "panel", None, ""):
        assert safe_return(bad) == "/"


# ---------- 1. signin ----------


def test_signin_redirect_has_every_parameter_and_pkce(inid: InID):
    res, name, flow = sign_in(inid, "/api/inid/signin?return_to=/panel&ui_locales=es&login_hint=%2B57300&entrance=team")
    assert res.status in (302, 303, 307)
    assert res.header("cache-control") == "no-store"
    location = res.header("location")
    assert location.startswith(f"{ISSUER}/oauth/authorize?")
    q = query_of(location)
    assert q["client_id"] == PK
    assert q["redirect_uri"] == f"{APP}/api/inid/callback"
    assert q["response_type"] == "code"
    assert q["scope"] == "openid profile email phone"
    assert q["state"] == flow["state"] and name == f"__inid_flow_{flow['state']}"
    assert q["nonce"] == flow["nonce"]
    assert q["code_challenge_method"] == "S256"
    assert q["code_challenge"] == b64url(hashlib.sha256(flow["verifier"].encode()).digest())
    assert q["ui_locales"] == "es" and q["login_hint"] == "+57300" and q["entrance"] == "team"
    assert "prompt" not in q and "display" not in q
    assert flow["returnTo"] == "/panel" and "embed" not in flow
    assert len(from_b64url(flow["state"])) == 16 and len(from_b64url(flow["verifier"])) == 32
    cookie = res.set_cookies[0]
    assert "Path=/api/inid" in cookie and "Max-Age=600" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Secure" in cookie


def test_signin_return_to_is_sanitized(inid: InID):
    for bad in ("//evil.com", "https://evil.com", "/%5Cevil.com"):
        _, _, flow = sign_in(inid, f"/api/inid/signin?return_to={bad}")
        assert flow["returnTo"] == "/"


def test_signin_after_signout_asks_again(inid: InID):
    res, _, _ = sign_in(inid, "/api/inid/signin", {"__inid_out": "1"})
    assert query_of(res.header("location"))["prompt"] == "login"


def test_signin_embed(inid: InID):
    res, _, flow = sign_in(inid, "/api/inid/signin?display=embed&return_to=/panel&page=/entrar")
    q = query_of(res.header("location"))
    assert q["display"] == "embed" and q["prompt"] == "login"
    assert flow["embed"] is True and flow["page"] == "/entrar"
    _, _, flow = sign_in(inid, "/api/inid/signin?display=embed&return_to=/panel")
    assert flow["page"] == "/panel"


def test_signin_embed_resume_after_google(inid: InID):
    resume = "request=abc&session=s1&from=google&lang=es&evil=1"
    res = inid.handle(req("GET", "/api/inid/signin?" + urlencode({"display": "embed", "continue": resume})))
    location = res.header("location")
    assert location.startswith(f"{ISSUER}/oauth/authorize/continue?")
    assert query_of(location) == {"request": "abc", "session": "s1", "from": "google", "lang": "es", "display": "embed"}
    assert res.set_cookies == []


def test_cookies_not_secure_on_http(fake: FakeInID):
    inid = make_inid(fake)
    res = inid.handle(req("GET", "/api/inid/signin", origin="http://localhost:8000"))
    assert "Secure" not in res.set_cookies[0]
    assert query_of(res.header("location"))["redirect_uri"] == "http://localhost:8000/api/inid/callback"
    # app_url wins over the request's origin (behind a proxy)
    behind = make_inid(fake, app_url="https://app.example")
    res = behind.handle(req("GET", "/api/inid/signin", origin="http://internal:8000"))
    assert query_of(res.header("location"))["redirect_uri"] == "https://app.example/api/inid/callback"
    assert "Secure" in res.set_cookies[0]


# ---------- 2. callback ----------


def test_callback_exchanges_the_code_and_signs_in(fake: FakeInID, inid: InID):
    _, name, flow = sign_in(inid)
    code = fake.issue_code(flow["nonce"])
    flow_value = b64url(json.dumps(flow).encode())
    res = inid.handle(req("GET", f"/api/inid/callback?code={code}&state={flow['state']}", {name: flow_value, "__inid_out": "1"}))
    assert res.status in (302, 303, 307) and res.header("location") == "/panel"
    (call,) = fake.calls_to("/oauth/token")
    expected = "Basic " + base64.b64encode(f"{PK}:{SK}".encode()).decode()
    assert call["headers"]["authorization"] == expected
    assert call["form"] == {"grant_type": "authorization_code", "code": code, "redirect_uri": f"{APP}/api/inid/callback", "code_verifier": flow["verifier"]}
    session_cookie = cookie_named(res.set_cookies, "__inid_session")
    assert session_cookie and "Max-Age=2592000" in session_cookie and "Path=/;" in session_cookie
    assert "__inid_refresh=rt_new;" in cookie_named(res.set_cookies, "__inid_refresh")
    assert "Max-Age=0" in cookie_named(res.set_cookies, "__inid_out")
    assert "Max-Age=0" in cookie_named(res.set_cookies, name) and "Path=/api/inid" in cookie_named(res.set_cookies, name)


def test_callback_rejects_a_wrong_nonce(fake: FakeInID, inid: InID):
    _, name, flow = sign_in(inid)
    code = fake.issue_code("another-nonce")
    res = inid.handle(req("GET", f"/api/inid/callback?code={code}&state={flow['state']}", {name: b64url(json.dumps(flow).encode())}))
    assert res.status == 400 and res.json() == {"error": "invalid_id_token"}
    assert cookie_named(res.set_cookies, "__inid_session") is None


def test_callback_state_mismatch_goes_home(fake: FakeInID, inid: InID):
    _, name, flow = sign_in(inid)
    res = inid.handle(req("GET", "/api/inid/callback?code=x&state=unknown", {name: b64url(json.dumps(flow).encode())}))
    assert res.header("location") == "/"
    assert fake.calls_to("/oauth/token") == []
    # The same cookie, but the state in it differs
    tampered = {**flow, "state": "other"}
    res = inid.handle(req("GET", f"/api/inid/callback?code=x&state={flow['state']}", {name: b64url(json.dumps(tampered).encode())}))
    assert res.header("location") == "/panel"
    assert fake.calls_to("/oauth/token") == []


def test_callback_without_code_returns(inid: InID):
    _, name, flow = sign_in(inid)
    res = inid.handle(req("GET", f"/api/inid/callback?error=access_denied&state={flow['state']}", {name: b64url(json.dumps(flow).encode())}))
    assert res.header("location") == "/panel"
    assert "Max-Age=0" in cookie_named(res.set_cookies, name)


def test_callback_embedded_leaves_the_frame(fake: FakeInID, inid: InID):
    _, name, flow = sign_in(inid, "/api/inid/signin?display=embed&return_to=/panel%3Cx")
    code = fake.issue_code(flow["nonce"])
    res = inid.handle(req("GET", f"/api/inid/callback?code={code}&state={flow['state']}", {name: b64url(json.dumps(flow).encode())}))
    assert res.status == 200
    assert res.header("content-type").startswith("text/html")
    body = res.body.decode()
    assert body == '<!doctype html><meta charset="utf-8"><script>(window.top || window).location.replace("/panel\\u003cx")</script>'
    assert cookie_named(res.set_cookies, "__inid_session")


def test_callback_resumes_embedded_flow_after_google(inid: InID):
    _, name, flow = sign_in(inid, "/api/inid/signin?display=embed&return_to=/panel&page=/entrar%3Fa%3D1")
    res = inid.handle(req("GET", f"/api/inid/callback?inid_continue=xyz&state={flow['state']}", {name: b64url(json.dumps(flow).encode())}))
    assert res.header("location") == "/entrar?a=1&inid_continue=xyz"


# ---------- 3. reading and renewing the session ----------


def test_valid_session_needs_no_call(fake: FakeInID, inid: InID):
    result = inid.session({"__inid_session": fake.id_token()}, refresh=True)
    assert result.session and result.session.user.id == "user_123"
    assert result.set_cookies == [] and result.cookies is None
    assert fake.calls_to("/oauth/token") == []


def test_session_renewed_near_expiry(fake: FakeInID, inid: InID):
    old = fake.id_token(ttl=30)
    result = inid.session({"__inid_session": old, "__inid_refresh": "rt_old", "theme": "dark"}, refresh=True)
    (call,) = fake.calls_to("/oauth/token")
    assert call["form"] == {"grant_type": "refresh_token", "refresh_token": "rt_old"}
    assert result.session and result.session.expires_at == int(fake.now) + 600
    assert cookie_named(result.set_cookies, "__inid_refresh").startswith("__inid_refresh=rt_renewed;")
    # The same request sees the renewed session
    assert result.cookies["__inid_refresh"] == "rt_renewed" and result.cookies["__inid_session"] != old
    assert result.cookies["theme"] == "dark"
    assert "__inid_refresh=rt_renewed" in result.cookie_header


def test_session_not_renewed_without_refresh_flag(fake: FakeInID, inid: InID):
    result = inid.session({"__inid_session": fake.id_token(ttl=30), "__inid_refresh": "rt"})
    assert result.session is not None and fake.calls_to("/oauth/token") == []
    result = inid.session({"__inid_session": fake.id_token(ttl=-5), "__inid_refresh": "rt"})
    assert result.session is None


def test_expired_session_renewed(fake: FakeInID, inid: InID):
    result = inid.session({"__inid_session": fake.id_token(ttl=-100), "__inid_refresh": "rt"}, refresh=True)
    assert result.session is not None


def test_refresh_4xx_ends_the_session(fake: FakeInID, inid: InID):
    fake.refresh_fails = 400
    result = inid.session({"__inid_session": fake.id_token(ttl=30), "__inid_refresh": "rt", "theme": "dark"}, refresh=True)
    assert result.session is None
    assert "Max-Age=0" in cookie_named(result.set_cookies, "__inid_session")
    assert "Max-Age=0" in cookie_named(result.set_cookies, "__inid_refresh")
    assert result.cookies == {"theme": "dark"}


@pytest.mark.parametrize("failure", ["down", 503])
def test_unreachable_inid_keeps_a_valid_session(fake: FakeInID, inid: InID, failure):
    token = fake.id_token(ttl=30)
    inid.verify(token)  # the keys are cached, as they would be in a running app
    fake.refresh_fails = failure
    result = inid.session({"__inid_session": token, "__inid_refresh": "rt"}, refresh=True)
    assert result.session and result.session.user.id == "user_123"
    assert result.set_cookies == []
    # An ended one isn't kept
    result = inid.session({"__inid_session": fake.id_token(ttl=-1), "__inid_refresh": "rt"}, refresh=True)
    assert result.session is None and result.set_cookies == []


def test_unreadable_keys_mean_signed_out_not_an_error(fake: FakeInID, inid: InID):
    fake.down = True
    assert inid.session({"__inid_session": fake.id_token()}).session is None


# ---------- 4. signout ----------


def test_signout_revokes_and_clears(fake: FakeInID, inid: InID):
    res = inid.handle(req("POST", "/api/inid/signout", {"__inid_session": fake.id_token(), "__inid_refresh": "rt_1"}))
    assert res.status == 200 and res.json() == {"ok": True}
    assert res.header("cache-control") == "no-store"
    (call,) = fake.calls_to("/oauth/revoke")
    assert call["form"] == {"token": "rt_1", "token_type_hint": "refresh_token"}
    assert call["headers"]["authorization"].startswith("Basic ")
    assert call["timeout"] <= 3
    assert "Max-Age=0" in cookie_named(res.set_cookies, "__inid_session")
    assert "Max-Age=0" in cookie_named(res.set_cookies, "__inid_refresh")
    out = cookie_named(res.set_cookies, "__inid_out")
    assert out.startswith("__inid_out=1;") and "Max-Age=2592000" in out


def test_signout_works_when_inid_is_down(fake: FakeInID, inid: InID):
    fake.down = True
    res = inid.handle(req("POST", "/api/inid/signout", {"__inid_refresh": "rt_1"}))
    assert res.status == 200 and cookie_named(res.set_cookies, "__inid_out")


def test_signout_needs_post(inid: InID):
    assert inid.handle(req("GET", "/api/inid/signout")).status == 404


# ---------- 5. /session ----------


def test_session_route_json_shape(fake: FakeInID, inid: InID):
    res = inid.handle(req("GET", "/api/inid/session", {"__inid_session": fake.id_token()}))
    assert res.status == 200 and res.header("cache-control") == "no-store"
    assert res.json() == {
        "user": {
            "id": "user_123",
            "firstName": "Laura",
            "lastName": "Gómez",
            "name": "Laura Gómez",
            "email": "laura@example.com",
            "emailVerified": True,
            "phone": "+573001234567",
            "roles": ["member"],
            "permissions": ["invoices:read"],
            "publicMetadata": {"plan": "pro"},
        },
        "accountUrl": f"{ISSUER}/account?client_id={PK}",
    }


def test_session_route_signed_out_and_renewing(fake: FakeInID, inid: InID):
    assert inid.handle(req("GET", "/api/inid/session")).json()["user"] is None
    res = inid.handle(req("GET", "/api/inid/session", {"__inid_session": fake.id_token(ttl=10), "__inid_refresh": "rt"}))
    assert res.json()["user"]["id"] == "user_123"
    assert cookie_named(res.set_cookies, "__inid_session")


def test_unknown_route_is_404(inid: InID):
    res = inid.handle(req("GET", "/api/inid/nope"))
    assert res.status == 404 and res.json() == {"error": "not_found"}


# ---------- sessions ----------


def test_sessions_route(fake: FakeInID, inid: InID):
    assert inid.handle(req("GET", "/api/inid/sessions")).status == 401
    assert inid.handle(req("GET", "/api/inid/sessions")).json() == {"error": "not_signed_in"}
    cookies = {"__inid_session": fake.id_token()}
    res = inid.handle(req("GET", "/api/inid/sessions", cookies))
    assert [(s["id"], s["current"]) for s in res.json()["sessions"]] == [("sess_1", True), ("sess_2", False)]
    call = fake.calls_to(f"/v1/users/{fake.sub}/sessions")[0]
    assert call["headers"]["authorization"] == f"Bearer {SK}"
    assert inid.handle(req("DELETE", "/api/inid/sessions/sess_2", cookies)).json() == {"ended": 1}
    assert fake.calls[-1]["method"] == "DELETE" and fake.calls[-1]["url"].endswith("/sessions/sess_2")
    fake.calls.clear()
    assert inid.handle(req("DELETE", "/api/inid/sessions?others=1", cookies)).json() == {"ended": 1}
    assert [c["url"].rsplit("/", 1)[1] for c in fake.calls if c["method"] == "DELETE"] == ["sess_2"]
    assert inid.handle(req("DELETE", "/api/inid/sessions", cookies)).json() == {"ended": 0}


# ---------- 6. the gate ----------


def test_gate_redirects_to_signin_with_return_to_and_entrance(inid: InID):
    protect = ["/public-nothing", Rule("/dashboard", entrance="team")]
    result = inid.gate(req("GET", "/dashboard/reports?x=1"), protect)
    assert result.response.status == 307
    location = result.response.header("location")
    assert location.startswith(f"{APP}/api/inid/signin?")
    assert query_of(location) == {"return_to": "/dashboard/reports?x=1", "entrance": "team"}
    assert not result.auth.is_signed_in


def test_gate_subpaths_regex_and_dicts(inid: InID):
    protect = ["/admin", re.compile(r"^/private-\d+$"), {"path": "/team/", "role": "staff"}]
    assert inid.gate(req("GET", "/admin"), protect).response is not None
    assert inid.gate(req("GET", "/admin/x"), protect).response is not None
    assert inid.gate(req("GET", "/adminx"), protect).response is None
    assert inid.gate(req("GET", "/private-12"), protect).response is not None
    assert inid.gate(req("GET", "/private-x"), protect).response is None
    assert inid.gate(req("GET", "/team/a"), protect).response is not None
    assert inid.gate(req("GET", "/"), protect).response is None
    assert inid.gate(req("GET", "/x"), lambda r: r.path == "/x").response is not None


def test_gate_403_on_missing_role_or_permission(fake: FakeInID, inid: InID):
    cookies = {"__inid_session": fake.id_token()}
    protect = [{"path": "/admin", "role": "admin"}, Rule("/invoices", permission="invoices:read"), Rule("/billing", permission="billing:write")]
    result = inid.gate(req("GET", "/admin/users", cookies), protect)
    assert result.response.status == 403 and result.response.body == b"Forbidden"
    assert result.auth.user_id == "user_123"
    assert inid.gate(req("GET", "/billing", cookies), protect).response.status == 403
    # A rule with only a path lets anyone signed in through
    assert inid.gate(req("GET", "/panel", cookies), [{"path": "/panel"}, Rule("/panel")]).response is None
    ok = inid.gate(req("GET", "/invoices", cookies), protect)
    assert ok.response is None and ok.auth.is_signed_in and ok.auth.has(permission="invoices:read")


def test_gate_answers_api_routes(inid: InID):
    result = inid.gate(req("GET", "/api/inid/session"))
    assert result.response.json()["user"] is None
    assert inid.gate(req("GET", "/api/inid/session"), routes=False).response is None


def test_gate_google_return(inid: InID):
    result = inid.gate(req("GET", "/?state=inidg_abc&code=xyz&scope=email"), ["/"])
    assert result.response.status == 307
    assert result.response.header("location") == f"{ISSUER}/oauth/google/callback?state=inidg_abc&code=xyz&scope=email"
    assert inid.gate(req("GET", "/?state=inidg_abc&error=access_denied")).response.status == 307
    assert inid.gate(req("GET", "/?state=other&code=xyz")).response is None
    assert inid.gate(req("GET", "/?state=inidg_abc")).response is None


def test_gate_renews_and_passes_cookies_on(fake: FakeInID, inid: InID):
    result = inid.gate(req("GET", "/dashboard", {"__inid_session": fake.id_token(ttl=20), "__inid_refresh": "rt"}), ["/dashboard"])
    assert result.response is None and result.auth.is_signed_in
    assert cookie_named(result.set_cookies, "__inid_session") and result.cookies["__inid_refresh"] == "rt_renewed"


def test_gate_ended_session_redirect_clears_cookies(fake: FakeInID, inid: InID):
    fake.refresh_fails = 401
    result = inid.gate(req("GET", "/dashboard", {"__inid_session": fake.id_token(ttl=-5), "__inid_refresh": "rt"}), ["/dashboard"])
    assert result.response.status == 307
    assert "Max-Age=0" in cookie_named(result.response.set_cookies, "__inid_session")


# ---------- the user and auth ----------


def test_user_has_and_json():
    user = User.from_claims({"sub": "u1", "name": "Solo Name", "roles": ["admin", 3], "permissions": ["a:b"], "public_metadata": [1]})
    assert user.name == "Solo Name" and user.roles == ("admin",) and user.public_metadata == {}
    assert user.email_verified is False and user.first_name is None
    assert user.has(role="admin") and user.has(permission="a:b") and user.has(role="admin", permission="a:b")
    assert not user.has(role="admin", permission="x") and not user.has(role="x")
    assert user.has()  # neither: a signed-in user is enough
    assert set(user.to_json()) == {"id", "firstName", "lastName", "name", "email", "emailVerified", "phone", "roles", "permissions", "publicMetadata"}
    assert User.from_claims({"sub": "u", "given_name": "Ana", "name": "ignored"}).name == "Ana"
    assert User.from_claims({"sub": "u"}).name is None
    anonymous = Auth()
    assert not anonymous.is_signed_in and anonymous.user is None and anonymous.user_id is None
    assert not anonymous.has(role="admin") and not anonymous.has()


# ---------- 8. ID token verification ----------


def test_verification_accepts_a_good_token(fake: FakeInID, inid: InID):
    checked = inid.verify(fake.id_token(nonce="n1"), nonce="n1")
    assert checked and checked.claims["sub"] == "user_123" and not checked.expired


@pytest.mark.parametrize(
    "overrides",
    [{"aud": "pk_test_other"}, {"iss": "https://evil.test"}, {"sub": 42}, {"exp": "soon"}, {"exp": None}],
)
def test_verification_rejects_bad_claims(fake: FakeInID, inid: InID, overrides):
    assert inid.verify(fake.id_token(**overrides)) is None


def test_verification_rejects_bad_signature_and_tampering(fake: FakeInID, inid: InID):
    assert inid.verify(fake.other_key_token()) is None
    header, payload, signature = fake.id_token().split(".")
    forged = b64url(json.dumps({"iss": ISSUER, "aud": PK, "sub": "admin", "exp": int(fake.now) + 600}).encode())
    assert inid.verify(f"{header}.{forged}.{signature}") is None
    assert inid.verify("not-a-token") is None and inid.verify("a.b.c") is None


def test_verification_rejects_other_algorithms(fake: FakeInID, inid: InID):
    claims = {"iss": ISSUER, "aud": PK, "sub": "u", "exp": int(fake.now) + 600}
    assert inid.verify(fake.sign(claims, alg="HS256")) is None
    header = b64url(json.dumps({"alg": "RS256", "kid": 7}).encode())
    assert inid.verify(f"{header}.{fake.id_token().split('.', 1)[1]}") is None


def test_verification_wrong_nonce(fake: FakeInID, inid: InID):
    assert inid.verify(fake.id_token(nonce="a"), nonce="b") is None


def test_verification_unknown_kid(fake: FakeInID, inid: InID):
    claims = {"iss": ISSUER, "aud": PK, "sub": "u", "exp": int(fake.now) + 600}
    assert inid.verify(fake.sign(claims, kid="unknown")) is None


def test_expired_token_verifies_as_expired(fake: FakeInID, inid: InID):
    checked = inid.verify(fake.id_token(ttl=-10))
    assert checked and checked.expired
    assert inid.session({"__inid_session": fake.id_token(ttl=-10)}).session is None


def test_jwks_cache_and_unknown_kid_rate_limit(fake: FakeInID):
    cache = JWKSCache(ISSUER, fake.transport, fake.clock)
    assert cache.key_for("key-1") is not None
    assert cache.key_for("key-1") is not None
    assert len(fake.calls_to("/.well-known/jwks.json")) == 1
    # An unknown kid within a second of the last lookup isn't looked for
    assert cache.key_for("new") is None
    assert len(fake.calls_to("/.well-known/jwks.json")) == 2  # first unknown kid: asked at once
    fake.now += 0.5
    assert cache.key_for("other") is None
    assert len(fake.calls_to("/.well-known/jwks.json")) == 2
    fake.now += 1
    assert cache.key_for("new") is None  # remembered as missed
    assert len(fake.calls_to("/.well-known/jwks.json")) == 2
    # InID rotates its key: a new kid is found at once
    fake.kid = "key-2"
    assert cache.key_for("key-2") is not None
    assert len(fake.calls_to("/.well-known/jwks.json")) == 3
    # After an hour everything is fetched again
    fake.now += 3600
    cache.key_for("key-2")
    assert len(fake.calls_to("/.well-known/jwks.json")) == 4


def test_bearer_verification(fake: FakeInID, inid: InID):
    token = fake.id_token()
    assert inid.verify_bearer(f"Bearer {token}").user.id == "user_123"
    assert inid.verify_bearer(token).user.id == "user_123"
    assert inid.verify_bearer(f"Bearer {fake.id_token(ttl=-1)}") is None
    assert inid.verify_bearer(f"Bearer {fake.id_token(aud='pk_test_other')}") is None
    assert inid.verify_bearer(None) is None and inid.verify_bearer("") is None


# ---------- the app API ----------


def test_app_api_helpers(fake: FakeInID, inid: InID):
    assert inid.get_user("user_123")["firstName"] == "Laura"
    assert fake.calls[-1]["headers"]["authorization"] == f"Bearer {SK}"
    assert inid.set_role("user_123", "admin") == {"id": "user_123", "role": "admin"}
    assert json.loads(fake.calls[-1]["body"]) == {"role": "admin"}
    with pytest.raises(InIDError) as raised:
        inid.set_role("user_123", "nope")
    assert raised.value.code == "unknown_role" and raised.value.status == 400
    inid.update_metadata("user_123", public={"plan": "pro"}, private={"stripe": "cus_1"})
    assert json.loads(fake.calls[-1]["body"]) == {"publicMetadata": {"plan": "pro"}, "privateMetadata": {"stripe": "cus_1"}}
    assert fake.calls[-1]["method"] == "PATCH"
    assert inid.list_roles()["defaultRole"] == "member"
    assert inid.invite("a@b.co", role="admin") == {"invited": 1, "failed": []}
    assert json.loads(fake.calls[-1]["body"]) == {"email": "a@b.co", "role": "admin"}
    inid.invite_many([{"email": "a@b.co"}, {"email": "c@d.co", "role": "member"}])
    assert json.loads(fake.calls[-1]["body"]) == {"invitations": [{"email": "a@b.co"}, {"email": "c@d.co", "role": "member"}]}


def test_request_model_parses_cookies():
    request = Request("get", "https://app.test/x?y=1", {"Cookie": "a=1; b=hello%20world"})
    assert request.method == "GET" and request.cookies == {"a": "1", "b": "hello world"}
    assert request.path == "/x" and request.query == "y=1" and request.origin == "https://app.test"
