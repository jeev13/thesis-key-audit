"""
api/authdb.py — the central auth store (SHARING.md Round 3, R3.1).

A SEPARATE SQLite file (auth.db) beside the record database. Identities and
sessions are infrastructure, not part of any thesis record — and R3.2 will
shard the record into one file per user, so the auth store is the one thing
that must stay central. Unlike thesis.db (which only feature4a may create),
auth.db is created on demand: an empty auth store is meaningful, an empty
record is not.

Tables:
  users          one row per Google identity (google_sub is the natural key)
  auth_sessions  DB-backed login sessions. The token cookie holds the RAW
                 token; the store keeps only its sha256, so a leaked auth.db
                 cannot impersonate anyone. Sessions surviving a server
                 restart is the point of this table — strangers must not be
                 logged out by a deploy the way friends acceptably were with
                 the old in-process set. Password (shared-workspace) sessions
                 are rows with user_id NULL.
  invite_codes   the signup valve for the Reddit beta: single-use codes,
                 required for NEW Google sign-ups when INVITE_REQUIRED=1.
                 Minted with `python -m api.invites_cli new [n]`.
  oauth_states   short-lived CSRF states for the Google redirect flow (a
                 state also carries the invite code typed on the login
                 screen, since the OAuth round-trip loses form fields).

Everything here is plain sqlite3 with short-lived connections — auth checks
are one indexed read per request, fine at beta scale on one worker.
"""

import hashlib
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from engine.config import CONFIG

SESSION_DAYS = 30          # matches the cookie max_age in api/auth.py
STATE_MINUTES = 10         # an OAuth round-trip older than this is stale


def auth_db_path() -> str:
    """AUTH_DB_PATH env wins (tests, unusual layouts); default is auth.db
    beside the record database, so the server's data dir holds both."""
    env = os.environ.get("AUTH_DB_PATH", "").strip()
    if env:
        return env
    return str(Path(CONFIG["db_path"]).resolve().parent / "auth.db")


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    google_sub  TEXT NOT NULL UNIQUE,
    email       TEXT NOT NULL,
    name        TEXT,
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER,            -- NULL = shared-password session
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invite_codes (
    code        TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    used_by     INTEGER,            -- users.user_id once redeemed
    used_at     TEXT
);
CREATE TABLE IF NOT EXISTS oauth_states (
    state       TEXT PRIMARY KEY,
    invite_code TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_settings (
    user_id          INTEGER PRIMARY KEY,
    api_key_enc      TEXT,               -- Fernet-encrypted; never plaintext
    api_key_hint     TEXT,               -- "sk-ant-ap…wxyz" for display only
    scheduled_checks INTEGER NOT NULL DEFAULT 1,
    trial_spent_usd  REAL NOT NULL DEFAULT 0,   -- sponsored trial (R3.6)
    updated_at       TEXT NOT NULL
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(auth_db_path())
    conn.executescript(_SCHEMA)
    # additive migration for auth stores created before R3.6 (CREATE IF NOT
    # EXISTS never alters an existing table)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(user_settings)")]
    if "trial_spent_usd" not in cols:
        conn.execute("ALTER TABLE user_settings "
                     "ADD COLUMN trial_spent_usd REAL NOT NULL DEFAULT 0")
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def create_session(user_id: int | None = None) -> str:
    """Issue a session; returns the RAW token (goes in the cookie, is never
    stored). Expired rows are swept here — login is the natural GC moment."""
    token = secrets.token_urlsafe(32)
    now = _now()
    with connect() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?",
                     (_iso(now),))
        conn.execute(
            "INSERT INTO auth_sessions (token_hash, user_id, created_at, "
            "expires_at) VALUES (?, ?, ?, ?)",
            (_hash(token), user_id, _iso(now),
             _iso(now + timedelta(days=SESSION_DAYS))))
    return token


def session_user(token: str) -> dict | None:
    """None if the token is unknown or expired; otherwise a dict with
    user_id/email/name (all None for a shared-password session)."""
    if not token:
        return None
    with connect() as conn:
        row = conn.execute(
            "SELECT s.user_id, u.email, u.name FROM auth_sessions s "
            "LEFT JOIN users u ON u.user_id = s.user_id "
            "WHERE s.token_hash = ? AND s.expires_at >= ?",
            (_hash(token), _iso(_now()))).fetchone()
    if row is None:
        return None
    return {"user_id": row["user_id"], "email": row["email"],
            "name": row["name"]}


def delete_session(token: str) -> None:
    if not token:
        return
    with connect() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE token_hash = ?",
                     (_hash(token),))


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def find_user(google_sub: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE google_sub = ?",
                           (google_sub,)).fetchone()
    return dict(row) if row else None


def upsert_user(google_sub: str, email: str, name: str | None) -> int:
    """First sign-in creates the row; later sign-ins refresh email/name (a
    user may rename their Google account) and last_seen. Returns user_id."""
    now = _iso(_now())
    with connect() as conn:
        existing = conn.execute(
            "SELECT user_id FROM users WHERE google_sub = ?",
            (google_sub,)).fetchone()
        if existing:
            conn.execute(
                "UPDATE users SET email = ?, name = ?, last_seen = ? "
                "WHERE user_id = ?",
                (email, name, now, existing["user_id"]))
            return existing["user_id"]
        cur = conn.execute(
            "INSERT INTO users (google_sub, email, name, created_at, "
            "last_seen) VALUES (?, ?, ?, ?, ?)",
            (google_sub, email, name, now, now))
        return cur.lastrowid


def list_users() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY created_at").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Per-user settings (R3.3 — the BYO key + the scheduled-checks toggle)
# ---------------------------------------------------------------------------

def get_user_settings(user_id: int) -> dict:
    with connect() as conn:
        row = conn.execute("SELECT * FROM user_settings WHERE user_id = ?",
                           (user_id,)).fetchone()
    if row is None:
        return {"user_id": user_id, "api_key_enc": None, "api_key_hint": None,
                "scheduled_checks": True, "trial_spent_usd": 0.0}
    d = dict(row)
    d["scheduled_checks"] = bool(d["scheduled_checks"])
    return d


def _upsert_settings(user_id: int, **fields) -> None:
    now = _iso(_now())
    with connect() as conn:
        conn.execute(
            "INSERT INTO user_settings (user_id, updated_at) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO NOTHING", (user_id, now))
        sets = ", ".join(f"{k} = ?" for k in fields)
        conn.execute(
            f"UPDATE user_settings SET {sets}, updated_at = ? "
            f"WHERE user_id = ?",
            (*fields.values(), now, user_id))


def set_user_key(user_id: int, api_key_enc: str, api_key_hint: str) -> None:
    _upsert_settings(user_id, api_key_enc=api_key_enc,
                     api_key_hint=api_key_hint)


def clear_user_key(user_id: int) -> None:
    _upsert_settings(user_id, api_key_enc=None, api_key_hint=None)


def set_scheduled_checks(user_id: int, enabled: bool) -> None:
    _upsert_settings(user_id, scheduled_checks=1 if enabled else 0)


def add_trial_spend(user_id: int, usd: float) -> None:
    """Accumulate sponsored-trial spend (R3.6). Atomic increment, durable
    across restarts — the middleware calls this after each trial request."""
    now = _iso(_now())
    with connect() as conn:
        conn.execute(
            "INSERT INTO user_settings (user_id, updated_at) VALUES (?, ?) "
            "ON CONFLICT(user_id) DO NOTHING", (user_id, now))
        conn.execute(
            "UPDATE user_settings SET trial_spent_usd = trial_spent_usd + ?, "
            "updated_at = ? WHERE user_id = ?", (usd, now, user_id))


def total_trial_spend() -> float:
    """The whole pool's consumption — every user's sponsored spend."""
    with connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(trial_spent_usd), 0) FROM user_settings"
        ).fetchone()
    return float(row[0])


# ---------------------------------------------------------------------------
# Invite codes
# ---------------------------------------------------------------------------

def new_invite_codes(n: int = 1) -> list[str]:
    """Mint n single-use codes (short, unambiguous, paste-friendly)."""
    codes = []
    now = _iso(_now())
    with connect() as conn:
        for _ in range(n):
            code = secrets.token_urlsafe(8)
            conn.execute(
                "INSERT INTO invite_codes (code, created_at) VALUES (?, ?)",
                (code, now))
            codes.append(code)
    return codes


def invite_valid(code: str) -> bool:
    """True iff the code exists and is unused."""
    if not code:
        return False
    with connect() as conn:
        row = conn.execute(
            "SELECT used_by FROM invite_codes WHERE code = ?",
            (code,)).fetchone()
    return row is not None and row["used_by"] is None


def redeem_invite(code: str, user_id: int) -> bool:
    """Atomically consume an unused code for this user. False if the code
    is unknown or already spent (two people racing the same code: one wins)."""
    with connect() as conn:
        cur = conn.execute(
            "UPDATE invite_codes SET used_by = ?, used_at = ? "
            "WHERE code = ? AND used_by IS NULL",
            (user_id, _iso(_now()), code))
        return cur.rowcount == 1


def list_invites() -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT i.*, u.email AS used_by_email FROM invite_codes i "
            "LEFT JOIN users u ON u.user_id = i.used_by "
            "ORDER BY i.created_at").fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# OAuth CSRF states
# ---------------------------------------------------------------------------

def new_state(invite_code: str | None = None) -> str:
    """One state per Google redirect; carries the invite code across the
    round-trip. Stale states are swept on creation."""
    state = secrets.token_urlsafe(24)
    now = _now()
    with connect() as conn:
        conn.execute(
            "DELETE FROM oauth_states WHERE created_at < ?",
            (_iso(now - timedelta(minutes=STATE_MINUTES)),))
        conn.execute(
            "INSERT INTO oauth_states (state, invite_code, created_at) "
            "VALUES (?, ?, ?)", (state, invite_code, _iso(now)))
    return state


def pop_state(state: str) -> dict | None:
    """Single-use: validates AND deletes. None = unknown, reused, or stale."""
    if not state:
        return None
    with connect() as conn:
        row = conn.execute(
            "SELECT * FROM oauth_states WHERE state = ? AND created_at >= ?",
            (state, _iso(_now() - timedelta(minutes=STATE_MINUTES)))
        ).fetchone()
        conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
    return dict(row) if row else None
