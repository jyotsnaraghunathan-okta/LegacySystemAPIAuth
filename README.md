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

`mcp_server.py` exposes the platform to MCP clients as seven tools. It holds
**no credentials**. An upstream gateway authenticates the agent, retrieves the
vaulted service account credential, and injects it as an `Authorization: Basic`
header on the inbound MCP request; this server reads that header per call and
forwards it to the platform.

```
Agent --(its own identity)--> Gateway --(Authorization: Basic)--> MCP server
                        holds the vaulted credential                   |
                                                                       v
                                                                  Platform
```

The gateway is the component that brokers credentials. Keeping that
responsibility there rather than here means:

- **No secret exists in this process**, its environment, or its config.
  Nothing here can leak a credential it never had.
- **No session cache.** Credentials arrive per request, so there is no shared
  state to go stale, no re-login logic, and no risk of one agent reusing
  another's session.
- **Credential rotation and audit stay in one place** — the gateway.

Because the credential is per-request, each call carries whichever identity the
gateway resolved. The platform's role check then applies to *that* identity: a
reader-role agent is refused `list_platform_sessions` while a service-role
agent is not, with no logic here.

| Tool | Description |
|---|---|
| `list_accounts` | List all accounts |
| `get_account` | Get one account by ID |
| `get_account_transactions` | List an account's transactions |
| `whoami` | Which platform identity this call authenticated as |
| `list_platform_sessions` | Active platform sessions (needs `service` role) |
| `platform_health` | Reachability check; no credential, wakes a sleeping instance |
| `credential_source` | Whether a credential was injected, and which username |

Tools return `{"success": false, "error": "..."}` rather than raising, so the
model can act on failures. The errors distinguish cases that need different
fixes: a rejected credential, a role refusal (authentication worked,
authorization did not), and an unreachable platform.

`credential_source` is the tool to call when injection appears not to be
working. It reports the username and auth scheme — never the password.

### Run it

```bash
.venv/bin/python mcp_server.py --http 8001     # HTTP at /mcp; required for injection
```

Point the gateway at `http://host:8001/mcp` and configure it to inject the
vaulted credential as an `Authorization: Basic` header.

Only `PLATFORM_BASE_URL` needs setting. Leave `PLATFORM_USERNAME` and
`PLATFORM_PASSWORD` **unset** behind a gateway — they exist only as a local
fallback (see below) and the server logs a warning when they are present.

Tests (43 checks: tool logic in-process, plus a real-HTTP layer that runs both
servers and injects the header the way a gateway would):

```bash
.venv/bin/python mcp_smoke_test.py
```

### Local development without a gateway

stdio carries no HTTP headers, so there is nothing to inject. For local
testing, set `PLATFORM_USERNAME` and `PLATFORM_PASSWORD` and the server uses
them when no header arrives:

```bash
.venv/bin/python mcp_server.py                 # stdio, uses the fallback
```

This is a development convenience, not a deployment mode — it reintroduces
exactly the stored credential the injection model is designed to avoid.

### If the gateway forwards a Bearer token

A `Bearer` token in the `Authorization` header is rejected with an explanatory
error rather than forwarded. The platform only understands Basic auth, so
passing the agent's own token through would produce a confusing 401 from the
platform instead of a clear message here. The gateway needs to *exchange* the
agent's token for the vaulted credential, not relay it.
