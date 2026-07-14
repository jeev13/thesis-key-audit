# How Investment Thesis handles your API key

[Investment Thesis](https://investmentthesis.app) is a tool for
structuring, stress-testing and monitoring your own investment thinking.
It runs on **your own Anthropic API key** — so before you paste a key into
a website, you can read the exact code that touches it. That is what this
repository is.

## What these files are

This is a **verbatim mirror of the key- and session-handling source** from
the app (the full application is not open source). Every file here ships
unmodified in the running app:

| File | What it does |
|---|---|
| `api/keys.py` | Everything about your key: Fernet encryption at rest, the hint-only display, the free validation call, and the policy for whose key a request spends |
| `api/routers/settings.py` | The four HTTP routes: read settings, store key, delete key, toggle scheduled checks |
| `engine/llm.py` | How the key is bound per request, how the Anthropic client is built, and the per-user cost meters |
| `api/auth.py` | The login gate: Google OAuth flow, session cookies, CSRF states |
| `api/authdb.py` | The auth store: session tokens are stored **hashed**, your key is stored **encrypted**, plus invite codes |

## The properties you can verify by reading

- **Validated for free.** A pasted key is checked with one
  `count_tokens` call — it requires valid auth but bills nothing
  (`api/keys.py`, `validate_api_key`).
- **Encrypted at rest.** Keys are Fernet-encrypted before touching the
  database; the plaintext is never written anywhere
  (`api/keys.py`, `encrypt_key` / `_decrypt`).
- **Never shown again, never logged.** The API returns only a hint like
  `sk-ant-api…wxyz` (`key_hint`); no code path echoes or logs the key.
- **Spent only on your actions.** Your key is bound to your requests and
  to the scheduled monitoring checks you consented to when storing it —
  which you can turn off, or avoid entirely by removing the key
  (`api/keys.py`, `binding_for` / `cron_binding`).
- **Deletable any time.** `DELETE /api/settings/key` clears the encrypted
  blob (`api/routers/settings.py`).
- **Sessions can't be stolen from the database.** Login tokens are stored
  as SHA-256 hashes (`api/authdb.py`).

## The honest caveat

Publishing source code cannot *prove* that the server is running exactly
this code — no BYO-key service can prove that, open source or not. What
this repository gives you is the design, the intent, and something
concrete to hold the operator to. The two protections that don't depend
on trusting anyone: **create your key inside a dedicated Anthropic
workspace with a monthly spend limit**, and revoke it in the Anthropic
console whenever you like.

## Sync policy

This mirror is updated whenever the key- or session-handling code in the
app changes. Each update names the app commit it mirrors in its commit
message. If you spot a problem in these files, please open an issue —
that's the point of publishing them.

## License

MIT — see [LICENSE](LICENSE). (The license covers the files in this
repository, not the rest of the application.)
