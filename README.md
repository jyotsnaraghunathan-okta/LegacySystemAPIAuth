# Legacy Platform API — Basic Auth + Session

A sample internal platform API that authenticates with **HTTP Basic Auth
(username + password)** and then issues a **session ID** that persists the
session for subsequent requests. It stands in for the older internal systems
that work this way, so you can develop and test clients against it without
touching a real platform.

## Auth model

```
POST /login     Authorization: Basic base64(user:pass)
                  -> { "session_id": "..." }  +  Set-Cookie: SESSIONID=...

GET  /api/...   Cookie: SESSIONID=...            (browser-style)
                X-Session-Id: ...                (API client style)
                Authorization: Basic ...         (credentials every call)

POST /logout    revokes the session server-side
```

Protected endpoints resolve the caller in that order: session cookie, then
`X-Session-Id`, then Basic Auth. If a session is present but dead **and**
Basic credentials are also supplied, it falls back to the credentials rather
than failing — otherwise a long-running agent holding a stale cookie would
break even though it has everything it needs to authenticate.

Sessions are **sliding** by default: each authenticated request pushes the
expiry out by the full TTL. Set `SLIDING_EXPIRY=false` for a fixed window from
login.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/` | none | Service description |
| GET | `/health` | none | Liveness probe for Render |
| POST | `/login` | Basic | Exchange credentials for a session ID |
| POST | `/logout` | session | Revoke the current session |
| GET | `/whoami` | session or Basic | Current identity and auth method |
| GET | `/api/accounts` | session or Basic | List accounts |
| GET | `/api/accounts/{id}` | session or Basic | One account |
| GET | `/api/accounts/{id}/transactions` | session or Basic | Account transactions |
| GET | `/api/sessions` | session or Basic, `service` role | Active sessions |

Interactive docs at `/docs`.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp env.example .env          # then edit API_USERS
.venv/bin/python main.py     # http://localhost:8000
```

Exercise it:

```bash
# login -> session
SID=$(curl -s -u svc_agent:local-dev-password -X POST \
  http://localhost:8000/login | python3 -c "import sys,json;print(json.load(sys.stdin)['session_id'])")

# use the session
curl -s -H "X-Session-Id: $SID" http://localhost:8000/api/accounts

# or skip the login hop and send credentials directly
curl -s -u svc_agent:local-dev-password http://localhost:8000/whoami
```

Run the test suite (46 checks, in-process, no server needed):

```bash
.venv/bin/python smoke_test.py
```

## Deploy to Render

1. Push this directory to a Git repo.
2. In Render, **New > Blueprint** and point it at the repo — `render.yaml`
   configures the service.
3. Set **`API_USERS`** in the Render dashboard to a JSON object of
   credentials. It is marked `sync: false` so it is never committed:

   ```json
   {"svc_agent":"<strong-password>","analyst":"<another-password>"}
   ```

   Without it the service boots with insecure development defaults and logs a
   warning to stderr.
4. Health check path is already set to `/health`.

Other env vars (`SESSION_TTL_SECONDS`, `SLIDING_EXPIRY`,
`SESSION_COOKIE_NAME`, `COOKIE_SECURE`, `BASIC_AUTH_REALM`) have sane defaults
in `render.yaml`. Set `SESSION_COOKIE_NAME=JSESSIONID` if you want it to look
like a Java platform.

### Sample-grade limitations

These are deliberate, and they matter if this ever stops being a sample:

- **Sessions are in memory.** They are lost on restart or deploy, and are not
  shared across instances. Render's free plan also sleeps idle services. Use
  Redis or a database for anything real.
- **Passwords are compared in plaintext** (via `hmac.compare_digest`, so the
  comparison is constant-time, but the stored value is not hashed). A real
  system stores a bcrypt/argon2 hash.
- **No rate limiting or lockout** on `/login`, so it is brute-forceable.
- **Business data is mock** and lives in dicts in `main.py`.

## Why this exists

Plenty of internal systems still authenticate exactly like this: present a
username and password once, receive an opaque session token, carry that token
on every later call. That model predates OAuth and does not map cleanly onto
how modern clients — including AI agents — expect to authenticate.

If you are building something that has to call a system like this, you need a
target to develop against that behaves the same way but holds no real data and
no real credentials. That is what this service is for.

### The integration shape

A client that holds a long-lived credential and needs to call a
session-based API generally ends up with a broker in the middle:

```
Client  --modern auth (OAuth/JWT)-->  broker service
                                        |
                                        |-- 1. fetch the service account
                                        |      credential from a secrets store
                                        |
                                        |-- 2. POST /login -> session_id
                                        |      cache it for its TTL
                                        |
                                        |-- 3. call /api/... with the session
                                        |      on 401, drop the cache, re-login
                                        v
                                  this service
```

The broker owns the session lifecycle, because that is the part no secrets
manager does for you. Credential vaults store and audit access to *credentials*;
they do not hold a third-party app's session cookie, watch it expire, and
re-authenticate on your behalf. Exchanging the credential for a session,
caching it, noticing the 401, and logging back in is application code.

Two properties worth designing for:

- **The client never sees the service account password.** It authenticates to
  the broker with its own identity; only the broker touches the credential.
- **Authorization and audit stay per-client**, even though the downstream
  system only understands one shared service account. The broker is the only
  place that mapping exists, so it is also the only place it can be enforced.

Both of the auth paths this service supports map onto that design. The
`/login`-then-session flow is what the broker does when it wants to amortize
one login across many calls. Sending Basic credentials on every request is the
simpler option when calls are infrequent and caching a session is not worth
the state — which is why this service accepts both, and why it falls back to
credentials when a cached session has gone stale.

## MCP server

`mcp_server.py` is that broker, implemented. It exposes the platform to MCP
clients as eight tools, holding the credentials and owning the session
lifecycle so the client never sees either.

| Tool | Description |
|---|---|
| `list_accounts` | List all accounts |
| `get_account` | Get one account by ID |
| `get_account_transactions` | List an account's transactions |
| `whoami` | Which platform identity the broker is using |
| `list_platform_sessions` | Active platform sessions (needs `service` role) |
| `platform_health` | Reachability check; no auth, wakes a sleeping instance |
| `session_status` | Whether a session is cached and when it expires |
| `refresh_session` | Force a re-login |

### Run it

```bash
# configure the broker in .env: PLATFORM_BASE_URL / USERNAME / PASSWORD
.venv/bin/python mcp_server.py                 # stdio, for MCP clients
.venv/bin/python mcp_server.py --http 8001     # HTTP, at /mcp
```

Tests (44 checks, runs the broker against the platform in-process):

```bash
.venv/bin/python mcp_smoke_test.py
```

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "legacy-platform": {
      "command": "/absolute/path/to/APIBasicAuth/.venv/bin/python",
      "args": ["/absolute/path/to/APIBasicAuth/mcp_server.py"],
      "env": {
        "PLATFORM_BASE_URL": "https://your-service.onrender.com",
        "PLATFORM_USERNAME": "svc_agent",
        "PLATFORM_PASSWORD": "your-password"
      }
    }
  }
}
```

Absolute paths are required, and the Python must be the venv's so the
dependencies resolve.

### What the broker handles

- **One login, many calls.** The session is cached for its TTL rather than
  re-authenticating per request.
- **Re-login on 401.** The platform's sessions are in-memory, so a restart or
  a free-tier sleep invalidates them silently. A 401 triggers one re-login and
  a retry; the tool call succeeds and the client never learns anything
  happened.
- **Proactive refresh.** A session inside `EXPIRY_SKEW_SECONDS` of expiry is
  replaced before use, so it cannot lapse between the check and the platform
  receiving the request.
- **One login under concurrent cold calls.** A lock serializes the exchange,
  so a burst of simultaneous tool calls with no cached session produces a
  single login rather than one per call.
- **Errors come back as values**, not exceptions: every tool returns
  `{"success": false, "error": "..."}` so the model can read what went wrong.
  A 403 says explicitly that authentication worked and authorization did not,
  since those imply different fixes.
- **No credential leakage.** `session_status` reports an 8-character session
  prefix and a `credentials_configured` boolean — never the password or the
  full session ID.
