"""
engine/llm.py — everything that talks to the Anthropic API.

Copied from feature4b_monitor.py's "Claude API plumbing" section. One
structural change: feature4b kept the running session cost in a global
dict and print()ed it after every call. The engine keeps it in a
CostTracker object (one per server process) and RETURNS each call's
cost, so the API can show the number on screen. Hard rule 5: the
session cost total must always be visible — this object is where that
number comes from.
"""

import json
import os
import threading
import time
from contextvars import ContextVar

from .config import CONFIG, PRICE


class CostTracker:
    """Running total of what this server process has spent on the
    Anthropic API. One instance lives for the lifetime of the process
    (created below); every paid call adds to it.

    `add` is guarded by a lock because the bear case now fires its
    per-assumption calls in PARALLEL threads (Phase D, P7), which would
    otherwise race on the running total."""

    def __init__(self):
        self.usd = 0.0
        self.calls = 0
        self._lock = threading.Lock()

    def add(self, cost: float) -> None:
        with self._lock:
            self.usd += cost
            self.calls += 1

    def snapshot(self) -> dict:
        """The numbers the cost meter displays."""
        with self._lock:
            return {"session_usd": round(self.usd, 4), "calls": self.calls}


# The process-wide tracker: everything this server has spent, whoever
# spent it. The process budget cap (create_with_retry) reads this one.
session_cost = CostTracker()

# ---------------------------------------------------------------------------
# Per-request binding (SHARING.md R3.3 — bring-your-own key).
#
# The engine knows nothing about users; it only honours two stdlib
# contextvars the API layer binds per request:
#   _api_key_override   None  -> the server's env key (dev / shared / CLI)
#                       "sk…" -> this request runs on the USER'S key
#                       ""    -> a key is REQUIRED but the user has none:
#                                refuse at spend time with a friendly message
#   _cost_scope         which meter this request's spend lands on
#                       ("shared", or "user-N")
# ThreadPoolExecutor workers do NOT inherit the submitting thread's
# contextvars — a naive pool.map would run a user's parallel bear-case /
# watch-baseline calls on the SERVER key and the shared meter. The two
# fan-out sites (generate.generate_bear_case, library.baseline_watches)
# therefore go through map_with_context below, which copies this thread's
# context into every worker task.
# ---------------------------------------------------------------------------

_api_key_override: ContextVar[str | None] = ContextVar(
    "api_key_override", default=None)
_cost_scope: ContextVar[str] = ContextVar("cost_scope", default="shared")

_scoped_trackers: dict[str, CostTracker] = {}
_scoped_lock = threading.Lock()


def bind_request(api_key: str | None, scope: str) -> tuple:
    """Bind this request's key + meter; returns tokens for unbind_request.
    Called by the API middleware (and the cron, per database file)."""
    return (_api_key_override.set(api_key), _cost_scope.set(scope))


def unbind_request(tokens: tuple) -> None:
    key_token, scope_token = tokens
    _api_key_override.reset(key_token)
    _cost_scope.reset(scope_token)


def _tracker_for_scope() -> CostTracker:
    scope = _cost_scope.get()
    if scope == "shared":
        return session_cost
    with _scoped_lock:
        if scope not in _scoped_trackers:
            _scoped_trackers[scope] = CostTracker()
        return _scoped_trackers[scope]


def scoped_cost_snapshot() -> dict:
    """The numbers the cost meter shows THIS caller: their own spend when
    a user scope is bound, the process total otherwise."""
    return _tracker_for_scope().snapshot()


def resolve_api_key() -> str:
    """The key this request spends on. Raises RuntimeError (never sys.exit)
    with an honest, actionable message when there is nothing to spend on."""
    override = _api_key_override.get()
    if override:
        return override
    if override == "":
        raise RuntimeError(
            "This account has no API key yet — open Settings (the key icon "
            "in the top bar) and add your Anthropic API key to run paid "
            "actions. Reading your record is always free.")
    from dotenv import load_dotenv
    load_dotenv()
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY not found — check your .env file.")
    return key


def get_client():
    """Create the Anthropic client on this request's key. Imported lazily
    so the zero-cost read paths (queries.py) work even if the key is
    missing."""
    import anthropic
    return anthropic.Anthropic(api_key=resolve_api_key())


def map_with_context(fn, items, max_workers: int) -> list:
    """Parallel map that CARRIES this thread's contextvars (the request's
    key + cost-scope binding) into the worker threads — one copy_context()
    per task, made here in the submitting thread. Order preserved, like
    executor.map, so code-assigned ids stay deterministic."""
    from concurrent.futures import ThreadPoolExecutor
    from contextvars import copy_context
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(copy_context().run, fn, item)
                   for item in items]
        return [f.result() for f in futures]


def usage_cost(resp, model: str, n_searches: int = 0) -> float:
    """Convert an API response's token usage into dollars, add it to
    the session tracker, and return this call's cost.

    Bills ALL FOUR input buckets, not just plain input: prompt caching splits
    usage into uncached input, cache WRITES (cache_creation_input_tokens) and
    cache READS (cache_read_input_tokens, 0.1x input). The write multiplier is
    2x because the engine caches its long-lived blocks with the 1-hour TTL (the
    5-minute TTL would be 1.25x); see config.PRICE. The old meter counted only
    `input_tokens`, so every cached system block (10-15k tokens on bear/defence
    turns) went unbilled and the on-screen total drifted far below the real API
    spend. Output and per-call search cost are unchanged."""
    p = PRICE[model]
    u = resp.usage
    in_tok = getattr(u, "input_tokens", 0) or 0
    out_tok = getattr(u, "output_tokens", 0) or 0
    cache_write = getattr(u, "cache_creation_input_tokens", 0) or 0
    cache_read = getattr(u, "cache_read_input_tokens", 0) or 0
    cost = (
        in_tok * p["in"]
        + cache_write * p["in"] * PRICE["cache_write_mult"]
        + cache_read * p["in"] * PRICE["cache_read_mult"]
        + out_tok * p["out"]
    ) / 1_000_000
    cost += n_searches * PRICE["search_per_call"]
    tracker = _tracker_for_scope()
    tracker.add(cost)
    if tracker is not session_cost:
        # the process-wide total still sees everything — the process budget
        # cap and the host's own view of server spend depend on it
        session_cost.add(cost)
    return cost


def create_with_retry(client, **kwargs):
    """Retry on rate limits (the account tier limits input tokens/minute).

    A 429 is a refusal, not a charge — the right response is wait and
    retry with backoff, not crash. The waiting message goes to the
    server log (print), which is the right place for it: the browser
    just sees the request take longer.

    This is also THE spending choke point: every paid call in the app goes
    through here, so the process-lifetime budget cap is enforced in one
    place. Past the cap, the call is refused BEFORE any money is spent —
    RuntimeError, which the API surfaces as an honest HTTP error."""
    cap = CONFIG.get("process_budget_usd")
    if cap is not None and session_cost.snapshot()["session_usd"] >= cap:
        raise RuntimeError(
            f"The server's spending cap has been reached "
            f"(${session_cost.snapshot()['session_usd']:.2f} of the "
            f"${cap:.2f} process budget). No further paid calls will run "
            f"until the server restarts or CONFIG['process_budget_usd'] is "
            f"raised. Everything already captured is saved.")
    import anthropic
    delay = 10
    for attempt in range(5):
        try:
            return client.messages.create(**kwargs)
        except (anthropic.RateLimitError, anthropic.APIStatusError) as e:
            status = getattr(e, "status_code", None)
            if isinstance(e, anthropic.RateLimitError) or status in (429, 529):
                print(f"    rate limited — waiting {delay}s (attempt {attempt + 1}/5)")
                time.sleep(delay)
                delay = min(delay * 2, 120)
            else:
                raise
    raise RuntimeError("rate-limited 5 times in a row — try later")


def count_searches(resp) -> int:
    """How many web searches the API ran server-side during this call.
    Needed for the cost meter — searches are billed separately."""
    try:
        return resp.usage.server_tool_use.web_search_requests
    except AttributeError:
        return 0


def text_of(resp) -> str:
    """Join the text blocks of a response. With search enabled the
    content list mixes text blocks with search blocks, so
    resp.content[0].text is unreliable — this is the safe way."""
    return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


def extract_json(text: str) -> dict:
    """The established pattern from Feature 2: models wrap JSON in prose,
    so take everything between the first '{' and the last '}'."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("no JSON object found in model output")
    return json.loads(text[start:end + 1])
