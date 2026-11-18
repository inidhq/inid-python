"""Sign-in with InID for Python servers: the sign-in routes, a fresh session, and paths
protected by role or permission. Framework integrations: inid.django, inid.fastapi, inid.flask."""

from .core import (
    COOKIE_MAX_AGE,
    FLOW_COOKIE,
    OUT_COOKIE,
    REFRESH_COOKIE,
    SESSION_COOKIE,
    Auth,
    Config,
    GateResult,
    InID,
    Protect,
    Rule,
    Session,
    SessionResult,
    Team,
    User,
    rules_for,
    safe_return,
)
from .errors import InIDConfigError, InIDError, InIDNetworkError, InIDWebhookError
from .http import HTTPResponse, Request, Response, Transport, parse_cookies, urllib_transport
from .tokens import JWKSCache, VerifiedToken, verify_id_token
from .webhooks import verify_webhook

__version__ = "0.1.0"

# The @inid/js browser components, for pages rendered by the server
INID_JS_URL = "https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js"

__all__ = [
    "COOKIE_MAX_AGE",
    "FLOW_COOKIE",
    "INID_JS_URL",
    "OUT_COOKIE",
    "REFRESH_COOKIE",
    "SESSION_COOKIE",
    "Auth",
    "Config",
    "GateResult",
    "HTTPResponse",
    "InID",
    "InIDConfigError",
    "InIDError",
    "InIDNetworkError",
    "InIDWebhookError",
    "JWKSCache",
    "Protect",
    "Request",
    "Response",
    "Rule",
    "Session",
    "SessionResult",
    "Team",
    "Transport",
    "User",
    "VerifiedToken",
    "parse_cookies",
    "rules_for",
    "safe_return",
    "urllib_transport",
    "verify_id_token",
    "verify_webhook",
]
