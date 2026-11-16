# inid

Sign-in with [InID](https://inid.co) for Python servers: the routes that sign people in and out, the session in its cookies (renewed before it ends), who may see each path, webhooks, and the bearer tokens of native apps. For Django, FastAPI/Starlette and Flask, or any framework through the framework-neutral core.

```bash
pip install inid              # the core
pip install "inid[django]"    # or [fastapi], [flask]
```

Python 3.10+. The only dependency is `cryptography` (to check InID's RS256 signatures); HTTP uses the standard library.

## Settings

| Setting | Environment variable | Default |
|---|---|---|
| Publishable key (`pk_test_…` / `pk_live_…`) | `INID_PUBLISHABLE_KEY` | required |
| Secret key (`sk_…`) | `INID_SECRET_KEY` | required |
| Issuer | `INID_ISSUER` | `https://id.inid.co` |
| The app's own URL (behind proxies) | `INID_APP_URL` | the request's origin |
| Webhook secret (`whsec_…`) | `INID_WEBHOOK_SECRET` | only for webhooks |
| API path | — | `/api/inid` |
| Scope | — | `openid profile email phone` |

Missing or malformed keys fail at startup. In the InID panel, add `https://your-app/api/inid/callback` as a redirect URI (or your app's origin as an allowed origin).

The browser components ([`@inid/js`](https://www.npmjs.com/package/@inid/js): `<inid-sign-in>`, `<inid-user-button>`…) talk to the routes under `/api/inid`, so they work unchanged with this package.

## Django

```python
# settings.py
INSTALLED_APPS = [..., "inid.django"]               # for {% load inid %}
MIDDLEWARE = [..., "inid.django.InIDMiddleware"]    # after SessionMiddleware, if any
INID = {
    # Keys from INID_PUBLISHABLE_KEY / INID_SECRET_KEY unless given here ("PUBLISHABLE_KEY", "SECRET_KEY",
    # "ISSUER", "APP_URL", "API_PATH", "WEBHOOK_SECRET")
    "PROTECT": [
        "/dashboard",                                       # signed in (and every path under it)
        {"path": "/admin", "role": "admin"},                # with a role
        {"path": "/invoices", "permission": "invoices:read"},
        {"path": "/team", "entrance": "team"},              # signs in through that entrance
    ],
}
```

The middleware answers the routes under `/api/inid`, renews the session and sets `request.inid`:

```python
from inid.django import inid_required

def home(request):
    if request.inid.is_signed_in:
        return HttpResponse(f"Hello, {request.inid.user.name}")
    return HttpResponse("Hello")

@inid_required(role="admin")           # or @inid_required, permission=..., entrance=...
def reports(request):
    ...
```

Not signed in: a redirect to sign in, back to the same page. Signed in without the role or permission: `403`.

```django
{% load inid %}
{% inid_sign_in app_name="My App" return_to="/dashboard" %}
```

renders `<inid-sign-in app-name="My App" return-to="/dashboard">` with the `@inid/js` script (`script=False` to leave the script out; `{% inid_script %}` adds it alone, for `<inid-user-button>` and the others).

## FastAPI and Starlette

```python
from fastapi import Depends, FastAPI, Request
from inid import User
from inid.fastapi import InIDMiddleware, get_auth, require, require_user

app = FastAPI()
app.add_middleware(InIDMiddleware, protect=["/dashboard", {"path": "/admin", "role": "admin"}])
# keys from the environment, or InIDMiddleware(..., publishable_key=..., secret_key=...)

@app.get("/")
def home(request: Request):
    return {"user": request.state.inid.user_id}

@app.get("/me")
def me(user: User = Depends(require_user())):        # 401 when nobody is signed in
    return user.to_json()

@app.get("/reports")
def reports(user: User = Depends(require(role="admin"))):   # 401, or 403 without the role
    ...
```

`Depends(get_auth)` gives the `Auth` object (signed in or not).

## Flask

```python
from flask import Flask, g
from inid.flask import InID, inid_required

app = Flask(__name__)
InID(app, protect=["/dashboard", {"path": "/admin", "role": "admin"}])
# or app.config["INID"] = {"PROTECT": [...], "PUBLISHABLE_KEY": ...}; keys from the environment

@app.get("/")
def home():
    return f"Hello, {g.inid.user.name}" if g.inid.is_signed_in else "Hello"

@app.get("/reports")
@inid_required(role="admin")
def reports():
    ...
```

## Who is signed in

Every integration gives the same `Auth` object:

```python
auth.is_signed_in
auth.user_id
auth.user             # inid.User or None
auth.session          # .claims, .expires_at
auth.has(role="admin")
auth.has(permission="invoices:read")
```

`User` has `id`, `first_name`, `last_name`, `name`, `email`, `email_verified`, `phone` (E.164), `roles`, `permissions`, `public_metadata`, `has(role=, permission=)` (both must hold; with neither, `True`: being signed in is enough) and `to_json()` with the camelCase keys every InID SDK uses (`firstName`, `emailVerified`, `publicMetadata`…).

## Webhooks

Pass the body exactly as received, before any JSON parsing:

```python
from inid import InIDWebhookError, verify_webhook

# Django
def inid_webhook(request):
    try:
        event = verify_webhook(request.body, request.headers.get("InID-Signature"))  # INID_WEBHOOK_SECRET
    except InIDWebhookError:
        return HttpResponse(status=400)
    if event["type"] == "user.deleted":
        ...
    return HttpResponse(status=204)

# FastAPI: event = verify_webhook(await request.body(), request.headers.get("inid-signature"))
# Flask:   event = verify_webhook(request.get_data(), request.headers.get("InID-Signature"))
```

It rejects a signature older (or newer) than five minutes. Events: `user.created`, `user.updated`, `user.deleted`, `session.created`, `session.ended`, `subscription.cancel_requested`, `customer.logged_out`, `customer.registered`, `checkout.abandoned`; each has `type`, `created_at`, and `sub` or `token`.

## Native apps (bearer ID tokens)

An iOS, Android, React Native or Flutter app signs in with InID itself and calls its backend with `Authorization: Bearer <id_token>`. Verify it with the same keys and checks (`aud` is your publishable key):

```python
from inid import InID

inid = InID()   # one per process: it keeps InID's public keys

session = inid.verify_bearer(request.headers.get("Authorization"))
if session is None:
    ...  # 401
session.user.id, session.user.has(role="admin")
```

With FastAPI: `user: User = Depends(require_bearer(inid))` (from `inid.fastapi`).

## Your users, from your server

With the secret key (errors raise `InIDError` with `code` and `status`):

```python
inid.get_user(sub)
inid.set_role(sub, "admin")                                  # None: back to the default role
inid.update_metadata(sub, public={"plan": "pro"}, private={"stripe": "cus_123"})
inid.list_roles()
inid.invite("ana@example.com", role="admin")
inid.invite_many([{"email": "ana@example.com"}, {"email": "luis@example.com", "role": "member"}])
inid.api("GET", "/v1/users?q=ana")                          # any other endpoint
```

## Any other framework

The core works on a small request/response model:

```python
from inid import InID, Request

inid = InID()
result = inid.gate(Request(method, absolute_url, {"cookie": cookie_header}), protect=["/dashboard"])
if result.response:                       # InID's routes, a sign-in redirect, a 403
    status, headers, body = result.response.status, result.response.headers, result.response.body
    # headers is a list of (name, value): several Set-Cookie
else:
    ...  # the page, with result.auth; add result.set_cookies (Set-Cookie values) to its response
         # result.cookie_header: the request's cookies after a renewal, for the rest of the request
```

`inid.handle(request)` answers just the routes under the api path; `inid.session(cookies, refresh=True)` reads (and renews) a session.

## Tests

```bash
docker run --rm -v "$PWD":/app -w /app python:3.12-slim \
  sh -c "pip install -q -e '.[django,fastapi,flask]' pytest httpx && pytest -q"
```

## License

MIT
