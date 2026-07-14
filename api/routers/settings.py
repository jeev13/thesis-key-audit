"""
api/routers/settings.py — the BYO-key settings surface (SHARING.md R3.3
+ the session-only option, R3.4).

Thin, like every router: each route is one api/keys.py call. The key
itself never appears in any response — only its hint. All routes sit
behind the login gate like the rest of /api; the write routes additionally
require a Google session (a key belongs to an account, not a shared
workspace).
"""

from fastapi import APIRouter, HTTPException, Request

from api import authdb, keys, tenancy
from api.auth import COOKIE_NAME
from api.schemas import ApiKeyRequest, ScheduledChecksRequest

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _token(request: Request) -> str:
    return request.cookies.get(COOKIE_NAME, "")


@router.get("")
def get_settings(request: Request):
    """Whose money a paid action would spend right now, the stored (or
    session-held) key's hint, and the scheduled-checks toggle. Free."""
    return keys.settings_info(tenancy.current_user_id(), _token(request))


@router.put("/key")
def put_key(body: ApiKeyRequest, request: Request):
    """Accept the caller's Anthropic API key: validated with one FREE call
    (count_tokens needs auth, bills nothing). `remember` true (default)
    stores it encrypted — which is CONSENT for the scheduled monitoring
    checks to run on it while you're away (the UI says so first; the
    toggle below withdraws it). `remember` false keeps the key in server
    memory for THIS login session only: never written anywhere, gone on
    sign-out or restart, and scheduled monitoring honestly can't use it."""
    user_id = keys.current_user_id_or_400()
    api_key = body.api_key.strip()
    if len(api_key) < 20:
        raise HTTPException(status_code=400,
                            detail="That does not look like an API key — "
                                   "Anthropic keys start with sk-ant-.")
    try:
        keys.validate_api_key(api_key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if body.remember:
        keys.forget_session_key(_token(request))
        authdb.set_user_key(user_id, keys.encrypt_key(api_key),
                            keys.key_hint(api_key))
    else:
        keys.set_session_key(_token(request), api_key)
    return keys.settings_info(user_id, _token(request))


@router.delete("/key")
def delete_key(request: Request):
    """Forget the key — both the encrypted stored blob and any
    session-held key for this login."""
    user_id = keys.current_user_id_or_400()
    authdb.clear_user_key(user_id)
    keys.forget_session_key(_token(request))
    return keys.settings_info(user_id, _token(request))


@router.put("/checks")
def put_checks(body: ScheduledChecksRequest, request: Request):
    """The scheduled-monitoring toggle: off = the nightly heartbeat skips
    this user's record entirely (their key is never spent while away)."""
    user_id = keys.current_user_id_or_400()
    authdb.set_scheduled_checks(user_id, body.enabled)
    return keys.settings_info(user_id, _token(request))
