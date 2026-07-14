"""
api/auth.py — the login gate (SHARING.md Rounds 1–3).

Three modes, decided purely by environment variables:

  - Nothing set                    -> gate OFF. Local development unchanged;
    nothing prompts, nothing is required.
  - APP_PASSWORD set               -> the Rounds-1/2 shared password (the
    friends server). Kept as the dev/fallback mode until Round-3 cutover.
  - GOOGLE_CLIENT_ID + _SECRET set -> "Continue with Google" (Round 3, R3.1):
    server-side authorization-code flow, identities in the central auth store
    (api/authdb.py). INVITE_REQUIRED=1 additionally gates NEW sign-ups behind
    single-use invite codes (`python -m api.invites_cli new`).

Both may be armed at once during cutover: a session from either is valid.
Sessions now live in auth.db (hashed tokens), NOT process memory — a deploy
or restart no longer logs anyone out. The cookie mechanics are unchanged:
HttpOnly, SameSite=Lax, 30 days.

The destructive flag rides with the gate: purge/archive are disabled whenever
ANY gate is armed (shared workspace until R3.2 isolates users) unless
ALLOW_DESTRUCTIVE=1 is also set.

Google flow (no new heavyweight deps — httpx ships with the anthropic SDK):
  GET /api/auth/google/start?invite=..  -> 307 to Google's consent screen
     (a CSRF state row carries the invite code across the round-trip)
  GET /api/auth/google/callback         -> validates state, exchanges the
     code, reads the userinfo endpoint (sub/email/name), enforces the invite
     rule for new users, issues the session cookie, redirects to "/".
     Failures redirect to "/?auth_error=google|invite" — the login screen
     shows the message; no error page ever strands anyone.
"""

import os
import secrets
from urllib.parse import urlencode

from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from api import authdb

load_dotenv()                       # APP_PASSWORD / GOOGLE_* may live in .env

COOKIE_NAME = "thesis_session"
COOKIE_MAX_AGE = authdb.SESSION_DAYS * 24 * 3600

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


# ---------------------------------------------------------------------------
# Mode flags — read per-call so tests can flip env vars without re-imports
# ---------------------------------------------------------------------------

def app_password():
    """The shared password, or None when password mode is off."""
    pw = os.environ.get("APP_PASSWORD", "").strip()
    return pw or None


def google_enabled() -> bool:
    return bool(os.environ.get("GOOGLE_CLIENT_ID", "").strip()
                and os.environ.get("GOOGLE_CLIENT_SECRET", "").strip())


def gate_armed() -> bool:
    return app_password() is not None or google_enabled()


def invite_required() -> bool:
    return os.environ.get("INVITE_REQUIRED", "").strip() == "1"


def admin_emails() -> set:
    """ADMIN_EMAILS env: comma-separated Google emails that may open the
    admin view (R3.5)."""
    raw = os.environ.get("ADMIN_EMAILS", "")
    return {e.strip().lower() for e in raw.split(",") if e.strip()}


def is_admin_request(request: Request) -> bool:
    """Gate off = your own machine, you are the admin. Gated = only a
    Google session whose email is listed in ADMIN_EMAILS."""
    if not gate_armed():
        return True
    user = current_user(request)
    return bool(user and (user.get("email") or "").lower() in admin_emails())


def destructive_allowed():
    """Purge/archive. Always allowed locally (gate off). A Google session is
    isolated in its OWN database (R3.2), so archive/purge are that user's
    right again — GDPR deletion depends on it. Only the SHARED workspace
    (password sessions) keeps the friends-era block, overridable with
    ALLOW_DESTRUCTIVE=1 for a maintenance session."""
    if not gate_armed():
        return True
    from api import tenancy
    if tenancy.current_user_id() is not None:
        return True
    return os.environ.get("ALLOW_DESTRUCTIVE", "").strip() == "1"


def require_destructive():
    """Guard for the destructive routes. 403 with an honest message — the
    buttons are also hidden in the UI via /api/auth/status."""
    if not destructive_allowed():
        raise HTTPException(
            status_code=403,
            detail=("Archive and purge are disabled on this shared server — "
                    "the record belongs to everyone testing. Ask the host to "
                    "run maintenance."))


# ---------------------------------------------------------------------------
# Session checks (used by the middleware in api/main.py)
# ---------------------------------------------------------------------------

def request_session(request: Request) -> dict | None:
    """The live session row for this request's cookie, or None. The
    middleware calls this ONCE per request and derives both the 401
    decision and the tenant binding from it."""
    return authdb.session_user(request.cookies.get(COOKIE_NAME, ""))


def is_authenticated(request: Request):
    """True when the gate is off, or the request carries a live session."""
    if not gate_armed():
        return True
    return request_session(request) is not None


def current_user(request: Request) -> dict | None:
    """{email, name} for a Google session; None for password sessions,
    anonymous requests, and gate-off local dev."""
    if not gate_armed():
        return None
    sess = authdb.session_user(request.cookies.get(COOKIE_NAME, ""))
    if sess is None or sess["user_id"] is None:
        return None
    return {"email": sess["email"], "name": sess["name"]}


def _secure_cookie(request: Request) -> bool:
    """Secure flag when the user-facing origin is https. Caddy terminates
    TLS and forwards X-Forwarded-Proto; plain local http stays workable."""
    return (request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "") == "https")


def _set_session_cookie(response, request: Request, token: str) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=COOKIE_MAX_AGE,
        httponly=True, samesite="lax", path="/",
        secure=_secure_cookie(request),
    )


def _status_payload(request: Request):
    return {
        "auth_required": gate_armed(),
        "authenticated": is_authenticated(request),
        "destructive_allowed": destructive_allowed(),
        "password_enabled": app_password() is not None,
        "google_enabled": google_enabled(),
        "invite_required": invite_required(),
        "user": current_user(request),
        "is_admin": is_admin_request(request),
    }


# ---------------------------------------------------------------------------
# Routes — the only /api paths reachable without a session
# ---------------------------------------------------------------------------

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    password: str


@router.get("/status")
def get_status(request: Request):
    """Public: tells the frontend which login controls to show and whether
    the archive/purge controls render at all."""
    return _status_payload(request)


@router.post("/login")
def post_login(body: LoginRequest, request: Request, response: Response):
    """Exchange the shared password for a session cookie. Wrong password is
    a 401 (the frontend shows the message); when password mode is off this
    is a no-op so a stale login screen can never strand anyone."""
    pw = app_password()
    if pw is None:
        return _status_payload(request)
    if not secrets.compare_digest(body.password.strip(), pw):
        raise HTTPException(status_code=401, detail="That password is not right.")
    token = authdb.create_session(user_id=None)
    _set_session_cookie(response, request, token)
    payload = _status_payload(request)
    payload["authenticated"] = True
    return payload


@router.post("/logout")
def post_logout(request: Request, response: Response):
    """Forget this browser's session (the DB row is revoked too, and any
    session-only API key goes with it)."""
    token = request.cookies.get(COOKIE_NAME, "")
    authdb.delete_session(token)
    from api import keys
    keys.forget_session_key(token)
    response.delete_cookie(COOKIE_NAME, path="/")
    payload = _status_payload(request)
    payload["authenticated"] = False
    payload["user"] = None
    return payload


# ---------------------------------------------------------------------------
# Google OAuth (authorization-code flow, server-side)
# ---------------------------------------------------------------------------

def _redirect_uri(request: Request) -> str:
    """Google requires the redirect URI to exactly match one registered on
    the OAuth client. OAUTH_REDIRECT_BASE (e.g. https://example.com) is the
    explicit production setting; local dev falls back to the request's own
    origin (register http://localhost:8000/... on the dev client)."""
    base = os.environ.get("OAUTH_REDIRECT_BASE", "").strip().rstrip("/")
    if not base:
        base = str(request.base_url).rstrip("/")
    return f"{base}/api/auth/google/callback"


def _fetch_google_identity(code: str, redirect_uri: str) -> dict:
    """Exchange the authorization code, then read the OpenID userinfo
    endpoint. Returns {sub, email, name}. Module-level so tests stub it —
    everything around it (state, invites, sessions) runs for real.

    Userinfo over HTTPS is used instead of decoding the id_token: same
    claims, no JWT/JWKS machinery."""
    import httpx  # ships with the anthropic SDK; imported lazily like it
    token_resp = httpx.post(GOOGLE_TOKEN_URL, data={
        "code": code,
        "client_id": os.environ["GOOGLE_CLIENT_ID"].strip(),
        "client_secret": os.environ["GOOGLE_CLIENT_SECRET"].strip(),
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }, timeout=15.0)
    token_resp.raise_for_status()
    access_token = token_resp.json()["access_token"]
    info_resp = httpx.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"}, timeout=15.0)
    info_resp.raise_for_status()
    info = info_resp.json()
    return {"sub": info["sub"], "email": info.get("email", ""),
            "name": info.get("name")}


@router.get("/google/start")
def google_start(request: Request, invite: str = ""):
    """Kick off the Google flow. The invite code (if the login screen sent
    one) rides in the server-side state row, not the URL Google sees."""
    if not google_enabled():
        raise HTTPException(status_code=404, detail="Google sign-in is not "
                            "configured on this server.")
    state = authdb.new_state(invite.strip() or None)
    params = urlencode({
        "client_id": os.environ["GOOGLE_CLIENT_ID"].strip(),
        "redirect_uri": _redirect_uri(request),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "prompt": "select_account",
    })
    return RedirectResponse(f"{GOOGLE_AUTH_URL}?{params}")


@router.get("/google/callback")
def google_callback(request: Request, code: str = "", state: str = "",
                    error: str = ""):
    """Google redirects here. Every failure lands back on the login screen
    with a readable reason — never a bare error page."""
    if not google_enabled():
        raise HTTPException(status_code=404, detail="Google sign-in is not "
                            "configured on this server.")
    st = authdb.pop_state(state)          # single-use CSRF check
    if error or not code or st is None:
        return RedirectResponse("/?auth_error=google")
    try:
        identity = _fetch_google_identity(code, _redirect_uri(request))
    except Exception:
        return RedirectResponse("/?auth_error=google")

    existing = authdb.find_user(identity["sub"])
    needs_invite = existing is None and invite_required()
    if needs_invite and not authdb.invite_valid(st.get("invite_code") or ""):
        # New face, no (valid) code: no user row, no session. The code is
        # only CONSUMED after the user row exists, below.
        return RedirectResponse("/?auth_error=invite")

    user_id = authdb.upsert_user(identity["sub"], identity["email"],
                                 identity["name"])
    if needs_invite and not authdb.redeem_invite(st["invite_code"], user_id):
        # Lost a race for the last use of this code between the check and
        # the redeem: honest rejection, the user row is harmless without
        # a session and the next valid code will claim it.
        return RedirectResponse("/?auth_error=invite")

    token = authdb.create_session(user_id)
    resp = RedirectResponse("/", status_code=303)
    _set_session_cookie(resp, request, token)
    return resp
