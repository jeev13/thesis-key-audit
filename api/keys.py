"""
api/keys.py — bring-your-own Anthropic key (SHARING.md Round 3, R3.3).

Each Google user may store their OWN Anthropic API key; every paid call in
their session then runs on it. This is what makes a public beta affordable
(the host pays hosting, users pay their own inference) and honest (people
judge the tool at its true price).

Storage: encrypted at rest with Fernet in the CENTRAL auth store
(api/authdb.py `user_settings`) — a deliberate deviation from the plan's
"in the user's own DB file": the record databases stay pure record (the
R3.2 principle), and the cron can resolve keys without opening record
files. The Fernet secret comes from APP_SECRET_KEY in .env, else an
auto-generated `secret.key` beside auth.db (zero-config dev). A key is
NEVER logged, NEVER returned by the API — only its hint ("sk-ant-…wxyz").

Validation: one FREE call — `count_tokens` needs valid auth but bills
nothing, so a typo'd key is caught at paste time without spending a cent
of the user's money.

Policy (binding_for): who spends on what —
  gate off / password session   -> server env key, shared meter (unchanged)
  Google user with a stored key -> THEIR key, THEIR meter
  Google user without a key     -> REQUIRE_USER_KEYS=1: paid actions refuse
                                   with "add your key in Settings" (reads
                                   stay free); unset: server-key fallback
                                   (friends-grade default), own meter.
"""

import base64
import hashlib
import os
import re
import threading
from pathlib import Path

from api import authdb, tenancy

_KEY_FILE = "secret.key"

# "This session only" keys (R3.4): held in PROCESS MEMORY, keyed by the
# hash of the login-session token — never written anywhere. Gone on
# logout and on every restart/deploy; that impermanence is the promise
# this option makes to sceptics. Scheduled monitoring honestly cannot
# run on one (the cron reads only stored keys).
_session_keys: dict[str, tuple[str, str]] = {}   # token_hash -> (key, hint)
_session_keys_lock = threading.Lock()


def set_session_key(session_token: str, api_key: str) -> None:
    with _session_keys_lock:
        _session_keys[authdb._hash(session_token)] = (api_key,
                                                      key_hint(api_key))


def session_key(session_token: str | None) -> tuple[str, str] | None:
    if not session_token:
        return None
    with _session_keys_lock:
        return _session_keys.get(authdb._hash(session_token))


def forget_session_key(session_token: str | None) -> None:
    if not session_token:
        return
    with _session_keys_lock:
        _session_keys.pop(authdb._hash(session_token), None)


# ---------------------------------------------------------------------------
# Encryption at rest
# ---------------------------------------------------------------------------

def _fernet():
    """The Fernet for this deployment. APP_SECRET_KEY (any passphrase) wins;
    otherwise a generated secret persisted beside auth.db — created once,
    chmod 600 where the OS honours it."""
    from cryptography.fernet import Fernet
    passphrase = os.environ.get("APP_SECRET_KEY", "").strip()
    if passphrase:
        digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))
    path = Path(authdb.auth_db_path()).parent / _KEY_FILE
    if not path.exists():
        secret = Fernet.generate_key()
        path.write_bytes(secret)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return Fernet(path.read_bytes())


def encrypt_key(api_key: str) -> str:
    return _fernet().encrypt(api_key.encode("utf-8")).decode("ascii")


def _decrypt(token: str) -> str | None:
    """None when undecryptable (APP_SECRET_KEY changed) — surfaced as
    'no key' so the user simply re-enters it; never a crash."""
    from cryptography.fernet import InvalidToken
    try:
        return _fernet().decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None


def key_hint(api_key: str) -> str:
    if len(api_key) <= 14:
        return "…" + api_key[-4:]
    return f"{api_key[:10]}…{api_key[-4:]}"


# ---------------------------------------------------------------------------
# Store / read / policy
# ---------------------------------------------------------------------------

def stored_key(user_id: int) -> str | None:
    enc = authdb.get_user_settings(user_id).get("api_key_enc")
    return _decrypt(enc) if enc else None


def require_user_keys() -> bool:
    return os.environ.get("REQUIRE_USER_KEYS", "").strip() == "1"


# ---------------------------------------------------------------------------
# The sponsored trial (R3.6) — a free go on the HOST'S key, hard-capped
# ---------------------------------------------------------------------------

def trial_budget_usd() -> float | None:
    """Per-user sponsored budget. Unset/zero = no trial. Only meaningful
    alongside REQUIRE_USER_KEYS=1 (without it, keyless users fall back to
    the server key uncapped anyway — friends mode)."""
    raw = os.environ.get("TRIAL_BUDGET_USD", "").strip()
    try:
        value = float(raw)
    except ValueError:
        return None
    return value if value > 0 else None


def trial_pool_usd() -> float:
    """The GLOBAL cap across every account — the host's absolute worst
    case, chosen in advance. Farming Google accounts cannot exceed it."""
    raw = os.environ.get("TRIAL_POOL_USD", "").strip()
    try:
        return float(raw)
    except ValueError:
        return 50.0


def trial_state(user_id: int) -> dict | None:
    """None when no trial is configured; otherwise the numbers the modal
    shows. `active` = this user can still spend sponsored money (their own
    budget has room AND the pool is not dry). A per-request overshoot past
    the cap is possible (the cap is checked at request start) — bounded by
    one action and absorbed by the pool."""
    budget = trial_budget_usd()
    if budget is None or not require_user_keys():
        return None
    used = float(authdb.get_user_settings(user_id).get("trial_spent_usd", 0))
    pool_open = authdb.total_trial_spend() < trial_pool_usd()
    return {"budget_usd": budget, "used_usd": round(used, 2),
            "active": used < budget and pool_open}


def _server_key_present() -> bool:
    from dotenv import load_dotenv
    load_dotenv()
    return bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())


def binding_for(user_id: int | None,
                session_token: str | None = None) -> tuple:
    """(api_key_override, cost_scope, on_trial) for the middleware. A
    session-only key wins over a stored one for its session — the user
    chose the more cautious mode; honour it. `on_trial` tells the
    middleware to accumulate this request's spend against the user's
    sponsored budget (engine.llm.bind_request takes the first two)."""
    if user_id is None:
        return None, "shared", False
    scope = f"user-{user_id}"
    sess = session_key(session_token)
    if sess:
        return sess[0], scope, False
    key = stored_key(user_id)
    if key:
        return key, scope, False
    if require_user_keys():
        trial = trial_state(user_id)
        if trial and trial["active"]:
            # the sponsored go: the HOST'S key, this user's meter, spend
            # accumulated durably by the middleware until the cap
            return None, scope, True
        return "", scope, False   # spend attempts get the friendly refusal
    return None, scope, False     # server-key fallback, own meter


def settings_info(user_id: int | None,
                  session_token: str | None = None) -> dict:
    """What GET /api/settings shows. key_source says whose money a paid
    action would spend right now ('session' = a key held for this login
    session only, never stored)."""
    if user_id is None:
        return {"key_source": "server" if _server_key_present() else "none",
                "key_hint": None, "scheduled_checks": True,
                "require_user_keys": require_user_keys(), "trial": None}
    s = authdb.get_user_settings(user_id)
    sess = session_key(session_token)
    trial = None
    if sess:
        source, hint = "session", sess[1]
    elif s["api_key_enc"] and _decrypt(s["api_key_enc"]):
        source, hint = "own", s["api_key_hint"]
    elif not require_user_keys() and _server_key_present():
        source, hint = "server", None
    else:
        trial = trial_state(user_id)
        if trial and trial["active"]:
            source, hint = "trial", None
        else:
            source, hint = "none", None
    return {"key_source": source,
            "key_hint": hint,
            "scheduled_checks": s["scheduled_checks"],
            "require_user_keys": require_user_keys(),
            "trial": trial}


def current_user_id_or_400():
    from fastapi import HTTPException
    user_id = tenancy.current_user_id()
    if user_id is None:
        raise HTTPException(
            status_code=400,
            detail=("API keys are per-account — sign in with Google to "
                    "store one."))
    return user_id


# ---------------------------------------------------------------------------
# Validation — one FREE call before anything is stored
# ---------------------------------------------------------------------------

def validate_api_key(api_key: str) -> None:
    """Raises ValueError with a readable reason; returns None when the key
    works. count_tokens requires valid auth and bills nothing."""
    import anthropic
    from engine import prompts
    try:
        client = anthropic.Anthropic(api_key=api_key)
        client.messages.count_tokens(
            model=prompts.EXTRACTION_MODEL,
            messages=[{"role": "user", "content": "key check"}])
    except anthropic.AuthenticationError:
        raise ValueError("Anthropic rejected that key — check you copied "
                         "the whole key (it starts with sk-ant-).")
    except anthropic.PermissionDeniedError:
        raise ValueError("That key was recognised but lacks permission — "
                         "check its workspace settings in the Anthropic "
                         "console.")
    except Exception:
        raise ValueError("Could not reach Anthropic to verify the key — "
                         "try again in a moment.")


# ---------------------------------------------------------------------------
# The cron's view (deploy/checks_cron.py)
# ---------------------------------------------------------------------------

def cron_binding(db_path: str) -> dict:
    """How the scheduled heartbeat should treat one record database:
    {skip: bool, reason, api_key_override, scope}. The shared file runs on
    the server key as ever; a user file runs on that user's stored key,
    honours their scheduled-checks toggle, and is SKIPPED (never billed to
    the server) when they have no key."""
    m = re.fullmatch(r"thesis-(\d+)\.db", Path(db_path).name)
    if not m:
        return {"skip": False, "reason": "", "api_key_override": None,
                "scope": "shared"}
    user_id = int(m.group(1))
    settings = authdb.get_user_settings(user_id)
    if not settings["scheduled_checks"]:
        return {"skip": True, "reason": "scheduled checks turned off",
                "api_key_override": None, "scope": f"user-{user_id}"}
    key = stored_key(user_id)
    if key is None:
        return {"skip": True, "reason": "no API key stored",
                "api_key_override": None, "scope": f"user-{user_id}"}
    return {"skip": False, "reason": "", "api_key_override": key,
            "scope": f"user-{user_id}"}
