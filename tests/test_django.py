from __future__ import annotations

import pytest

pytest.importorskip("django")

import django  # noqa: E402
from conftest import ISSUER, PK, SK, FakeInID, cookie_named  # noqa: E402
from django.conf import settings  # noqa: E402

FAKE = FakeInID()

if not settings.configured:
    settings.configure(
        DEBUG=False,
        SECRET_KEY="test",
        ALLOWED_HOSTS=["testserver"],
        ROOT_URLCONF=__name__,
        INSTALLED_APPS=["inid.django"],
        MIDDLEWARE=["inid.django.InIDMiddleware"],
        TEMPLATES=[{"BACKEND": "django.template.backends.django.DjangoTemplates", "APP_DIRS": True}],
        INID={
            "PUBLISHABLE_KEY": PK,
            "SECRET_KEY": SK,
            "ISSUER": ISSUER,
            "TRANSPORT": FAKE.transport,
            "PROTECT": ["/dashboard", {"path": "/admin", "role": "admin"}, {"path": "/team", "entrance": "team"}],
        },
    )
    django.setup()

from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.template import Context, Template  # noqa: E402
from django.test import Client  # noqa: E402
from django.urls import path  # noqa: E402

from inid.django import inid_required  # noqa: E402


def whoami(request):
    return JsonResponse({"user": request.inid.user_id, "cookie": request.COOKIES.get("__inid_refresh")})


@inid_required
def me(request):
    return HttpResponse(request.inid.user.name)


@inid_required(role="admin")
def reports(request):
    return HttpResponse("reports")


@inid_required(permission="invoices:read")
async def invoices(request):
    return HttpResponse("invoices")


urlpatterns = [
    path("", whoami),
    path("dashboard", whoami),
    path("admin/users", whoami),
    path("me", me),
    path("reports", reports),
    path("invoices", invoices),
]


def client(**cookies: str) -> Client:
    c = Client()
    for k, v in cookies.items():
        c.cookies[k] = v
    return c


def test_api_routes_are_answered():
    res = client().get("/api/inid/session")
    assert res.status_code == 200 and res.json()["user"] is None
    res = client().get("/api/inid/signin?return_to=/dashboard")
    assert res.status_code == 302 and res["Location"].startswith(f"{ISSUER}/oauth/authorize?")
    assert any(name.startswith("__inid_flow_") for name in res.cookies)
    res = client(__inid_refresh="rt").post("/api/inid/signout")
    assert res.json() == {"ok": True} and res.cookies["__inid_out"].value == "1"
    assert res.cookies["__inid_session"]["max-age"] == "0"


def test_protected_path_redirects_to_signin():
    res = client().get("/dashboard?x=1")
    assert res.status_code == 307
    assert res["Location"] == "http://testserver/api/inid/signin?return_to=%2Fdashboard%3Fx%3D1"


def test_signed_in_sets_request_inid():
    res = client(__inid_session=FAKE.id_token()).get("/dashboard")
    assert res.status_code == 200 and res.json()["user"] == "user_123"
    assert client().get("/").json()["user"] is None


def test_missing_role_is_403():
    res = client(__inid_session=FAKE.id_token()).get("/admin/users")
    assert res.status_code == 403


def test_renewal_reaches_the_view_and_the_browser():
    res = client(__inid_session=FAKE.id_token(ttl=10), __inid_refresh="rt").get("/")
    assert res.json() == {"user": "user_123", "cookie": "rt_renewed"}
    assert res.cookies["__inid_refresh"].value == "rt_renewed"
    raw = res.cookies["__inid_refresh"].OutputString()
    assert "HttpOnly" in raw and "SameSite=Lax" in raw and "Max-Age=2592000" in raw and "Path=/" in raw


def test_decorators():
    res = client().get("/me?a=1")
    assert res.status_code == 302 and res["Location"] == "/api/inid/signin?return_to=%2Fme%3Fa%3D1"
    assert client(__inid_session=FAKE.id_token()).get("/me").content.decode() == "Laura Gómez"
    assert client(__inid_session=FAKE.id_token()).get("/reports").status_code == 403
    assert client(__inid_session=FAKE.id_token(roles=["admin"])).get("/reports").status_code == 200
    assert client(__inid_session=FAKE.id_token()).get("/invoices").status_code == 200
    assert client(__inid_session=FAKE.id_token(permissions=[])).get("/invoices").status_code == 403


def test_entrance_rule():
    res = client().get("/team")
    assert res["Location"].endswith("&entrance=team")


def test_template_tag():
    html = Template('{% load inid %}{% inid_sign_in app_name="Mi <App>" return_to="/panel" %}').render(Context())
    assert '<script src="https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js" defer></script>' in html
    assert '<inid-sign-in app-name="Mi &lt;App&gt;" return-to="/panel"></inid-sign-in>' in html
    bare = Template('{% load inid %}{% inid_sign_in app_name="X" script=False redirect=True %}').render(Context())
    assert bare == '<inid-sign-in app-name="X" redirect=""></inid-sign-in>'


def test_flow_cookie_set_through_django_unchanged():
    res = client().get("/api/inid/signin")
    name = next(n for n in res.cookies if n.startswith("__inid_flow_"))
    raw = res.cookies[name].OutputString()
    assert f"Path=/api/inid" in raw and "Max-Age=600" in raw
    assert cookie_named([raw], name)


def test_team_route_reads_the_body():
    res = client(__inid_session=FAKE.id_token(), __inid_refresh="rt").post("/api/inid/team", data={"teamId": "team_1"}, content_type="application/json")
    assert res.status_code == 200 and res.json()["user"]["team"]["id"] == "team_1"
    assert FAKE.calls_to("/oauth/token")[-1]["form"]["team"] == "team_1"
