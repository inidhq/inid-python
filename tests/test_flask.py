from __future__ import annotations

import pytest

pytest.importorskip("flask")

from conftest import ISSUER, PK, SK, FakeInID, cookie_named  # noqa: E402
from flask import Flask, g, jsonify, request  # noqa: E402

from inid.flask import InID, inid_required  # noqa: E402


def make_app(fake: FakeInID) -> Flask:
    app = Flask(__name__)
    app.config["INID"] = {"PUBLISHABLE_KEY": PK, "SECRET_KEY": SK, "ISSUER": ISSUER, "PROTECT": ["/dashboard", {"path": "/admin", "role": "admin"}]}
    InID(app, transport=fake.transport)

    @app.get("/")
    def home():
        return jsonify(user=g.inid.user_id, cookie=request.cookies.get("__inid_refresh"))

    @app.get("/dashboard")
    def dashboard():
        return jsonify(user=g.inid.user_id)

    @app.get("/admin/users")
    def admin():
        return "admin"

    @app.get("/me")
    @inid_required
    def me():
        return g.inid.user.name

    @app.get("/reports")
    @inid_required(role="admin")
    def reports():
        return "reports"

    return app


@pytest.fixture
def client(fake: FakeInID):
    return make_app(fake).test_client()


def jar(client, **cookies: str):
    # Werkzeug's test client writes the Cookie header from its own jar: a fresh client per request
    client = client.application.test_client()
    for k, v in cookies.items():
        client.set_cookie(k, v)
    return client


def test_api_routes_are_answered(client, fake: FakeInID):
    res = jar(client, __inid_session=fake.id_token()).get("/api/inid/session")
    assert res.status_code == 200 and res.get_json()["user"]["id"] == "user_123"
    assert res.headers["cache-control"] == "no-store"
    res = jar(client).get("/api/inid/signin")
    assert res.status_code == 302 and res.headers["location"].startswith(f"{ISSUER}/oauth/authorize?")
    res = jar(client, __inid_refresh="rt").post("/api/inid/signout")
    assert res.get_json() == {"ok": True} and len(res.headers.getlist("Set-Cookie")) == 3


def test_protected_path_redirects(client):
    res = client.get("/dashboard?x=1")
    assert res.status_code == 307
    assert res.headers["location"] == "http://localhost/api/inid/signin?return_to=%2Fdashboard%3Fx%3D1"


def test_g_inid(client, fake: FakeInID):
    assert jar(client, __inid_session=fake.id_token()).get("/dashboard").get_json() == {"user": "user_123"}
    assert jar(client).get("/").get_json() == {"user": None, "cookie": None}


def test_missing_role_is_403(client, fake: FakeInID):
    assert jar(client, __inid_session=fake.id_token()).get("/admin/users").status_code == 403


def test_renewal(client, fake: FakeInID):
    res = jar(client, __inid_session=fake.id_token(ttl=5), __inid_refresh="rt").get("/")
    assert res.get_json() == {"user": "user_123", "cookie": "rt_renewed"}
    assert cookie_named(res.headers.getlist("Set-Cookie"), "__inid_refresh").startswith("__inid_refresh=rt_renewed;")


def test_decorator(client, fake: FakeInID):
    res = jar(client).get("/me?a=1")
    assert res.status_code == 302 and res.headers["location"] == "/api/inid/signin?return_to=%2Fme%3Fa%3D1"
    assert jar(client, __inid_session=fake.id_token()).get("/me").get_data(as_text=True) == "Laura Gómez"
    assert jar(client, __inid_session=fake.id_token()).get("/reports").status_code == 403
    assert jar(client, __inid_session=fake.id_token(roles=["admin"])).get("/reports").status_code == 200


def test_team_route_reads_the_body(client, fake: FakeInID):
    res = jar(client, __inid_session=fake.id_token(), __inid_refresh="rt").post("/api/inid/team", json={"teamId": "team_1"})
    assert res.status_code == 200 and res.get_json()["user"]["team"]["role"] == "admin"
    assert fake.calls_to("/oauth/token")[-1]["form"]["team"] == "team_1"
