from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from conftest import ISSUER, FakeInID, cookie_named, make_inid  # noqa: E402
from fastapi import Depends, FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from inid import User  # noqa: E402
from inid.fastapi import InIDMiddleware, get_auth, require, require_bearer, require_user  # noqa: E402


def make_app(fake: FakeInID) -> FastAPI:
    inid = make_inid(fake)
    app = FastAPI()
    app.add_middleware(InIDMiddleware, inid=inid, protect=["/dashboard", {"path": "/admin", "role": "admin"}])

    @app.get("/")
    def home(request: Request):
        auth = request.state.inid
        return {"user": auth.user_id, "cookie": request.cookies.get("__inid_refresh")}

    @app.get("/dashboard")
    def dashboard(auth=Depends(get_auth)):
        return {"user": auth.user_id}

    @app.get("/admin/users")
    def admin():
        return {"ok": True}

    @app.get("/me")
    def me(user: User = Depends(require_user())):
        return user.to_json()

    @app.get("/reports")
    def reports(user: User = Depends(require(role="admin"))):
        return {"ok": True}

    @app.get("/native")
    def native(user: User = Depends(require_bearer(inid))):
        return {"user": user.id}

    return app


@pytest.fixture
def client(fake: FakeInID) -> TestClient:
    return TestClient(make_app(fake), follow_redirects=False)


def cookies(**jar: str) -> dict[str, str]:
    return {"cookie": "; ".join(f"{k}={v}" for k, v in jar.items())}


def test_api_routes_are_answered(client: TestClient, fake: FakeInID):
    res = client.get("/api/inid/session", headers=cookies(__inid_session=fake.id_token()))
    assert res.status_code == 200 and res.json()["user"]["firstName"] == "Laura"
    res = client.get("/api/inid/signin?return_to=/dashboard")
    assert res.status_code == 302 and res.headers["location"].startswith(f"{ISSUER}/oauth/authorize?")
    res = client.post("/api/inid/signout", headers=cookies(__inid_refresh="rt"))
    set_cookies = res.headers.get_list("set-cookie")
    assert res.json() == {"ok": True} and len(set_cookies) == 3 and cookie_named(set_cookies, "__inid_out")
    assert client.get("/api/inid/nope").status_code == 404


def test_protected_path_redirects(client: TestClient):
    res = client.get("/dashboard?x=1")
    assert res.status_code == 307
    assert res.headers["location"] == "http://testserver/api/inid/signin?return_to=%2Fdashboard%3Fx%3D1"


def test_request_state_inid(client: TestClient, fake: FakeInID):
    assert client.get("/dashboard", headers=cookies(__inid_session=fake.id_token())).json() == {"user": "user_123"}
    assert client.get("/").json() == {"user": None, "cookie": None}


def test_missing_role_is_403(client: TestClient, fake: FakeInID):
    assert client.get("/admin/users", headers=cookies(__inid_session=fake.id_token())).status_code == 403
    assert client.get("/admin/users", headers=cookies(__inid_session=fake.id_token(roles=["admin"]))).status_code == 200


def test_renewal(client: TestClient, fake: FakeInID):
    res = client.get("/", headers=cookies(__inid_session=fake.id_token(ttl=5), __inid_refresh="rt"))
    assert res.json() == {"user": "user_123", "cookie": "rt_renewed"}
    set_cookies = res.headers.get_list("set-cookie")
    assert cookie_named(set_cookies, "__inid_session") and cookie_named(set_cookies, "__inid_refresh")


def test_dependencies(client: TestClient, fake: FakeInID):
    assert client.get("/me").status_code == 401
    assert client.get("/me", headers=cookies(__inid_session=fake.id_token())).json()["emailVerified"] is True
    assert client.get("/reports", headers=cookies(__inid_session=fake.id_token())).status_code == 403
    assert client.get("/reports", headers=cookies(__inid_session=fake.id_token(roles=["admin"]))).status_code == 200


def test_bearer_dependency(client: TestClient, fake: FakeInID):
    assert client.get("/native", headers={"authorization": f"Bearer {fake.id_token()}"}).json() == {"user": "user_123"}
    assert client.get("/native", headers={"authorization": f"Bearer {fake.id_token(ttl=-1)}"}).status_code == 401
    assert client.get("/native").status_code == 401
