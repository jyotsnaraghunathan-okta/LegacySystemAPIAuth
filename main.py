"""
Legacy Platform API — simulates an internal system that authenticates with
HTTP Basic Auth (username + password) and then issues a session ID that
persists the session for subsequent calls.

This mirrors the auth style of older internal platforms: credentials are
presented once to a login endpoint, and everything after that rides on an
opaque session token carried in a cookie or header.

Flow:
    1. POST /login            with Basic Auth  -> issues session_id (+ Set-Cookie)
    2. GET  /api/...          with session     -> business data
    3. POST /logout           with session     -> revokes session

Protected endpoints accept the session three ways, in priority order:
    - Cookie:        SESSIONID=<id>
    - Header:        X-Session-Id: <id>
    - Header:        Authorization: Basic <base64(user:pass)>   (direct, no session)

The third form exists because many legacy systems let a caller skip the login
hop and send credentials on every request. It is the simpler path for a client
that holds service account credentials and does not want to cache a session.
"""

import base64
import hmac
import json
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

# Load environment variables from .env file
from dotenv import load_dotenv

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(env_path)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Session lifetime in seconds. Idle sessions past this window are rejected.
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "1800"))

# When True, each authenticated request pushes the expiry forward (sliding
# window) — the behaviour most legacy session managers use.
SLIDING_EXPIRY = os.getenv("SLIDING_EXPIRY", "true").strip().lower() in ("true", "1", "yes")

# Name of the session cookie. Legacy platforms love JSESSIONID / ASP.NET_SessionId.
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "SESSIONID")

# Set Secure on the session cookie. Render terminates TLS, so default to True.
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").strip().lower() in ("true", "1", "yes")

# Realm advertised in the WWW-Authenticate challenge.
BASIC_AUTH_REALM = os.getenv("BASIC_AUTH_REALM", "Legacy Platform")

# ---------------------------------------------------------------------------
# User store
# ---------------------------------------------------------------------------
# Credentials come from the API_USERS env var as JSON: {"user": "password", ...}
# This keeps real credentials out of the repo. The fallback below is for local
# development only — override it in Render.
#
# Example:
#   API_USERS={"svc_agent":"s3cr3t","analyst":"hunter2"}

DEFAULT_USERS = {
    "svc_agent": "change-me-in-render",
    "analyst": "change-me-too",
}


def _load_users() -> dict:
    raw = os.getenv("API_USERS", "").strip()
    if not raw:
        print(
            "WARNING: API_USERS not set — using development defaults. "
            "Set API_USERS in Render before exposing this service.",
            file=sys.stderr,
        )
        return dict(DEFAULT_USERS)
    try:
        users = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"API_USERS is not valid JSON: {exc}") from exc
    if not isinstance(users, dict) or not users:
        raise ValueError('API_USERS must be a non-empty JSON object, e.g. {"user":"pass"}')
    for name, password in users.items():
        if not isinstance(password, str):
            raise ValueError(f"API_USERS password for {name!r} must be a string")
    return users


USERS = _load_users()

# Roles drive what each identity may read. Anything unlisted gets "reader".
ROLES = {
    "svc_agent": "service",
    "analyst": "reader",
}

# ---------------------------------------------------------------------------
# Session store
# ---------------------------------------------------------------------------
# In-memory, so sessions are lost on restart and are not shared across Render
# instances. That is fine for a sample. A real deployment would put this in
# Redis or a database.

SESSIONS: dict[str, dict] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def _prune_sessions() -> None:
    """Drop expired sessions. Called on each session lookup to keep the dict bounded."""
    now = _now()
    expired = [sid for sid, s in SESSIONS.items() if s["expires_at"] <= now]
    for sid in expired:
        del SESSIONS[sid]


def create_session(username: str, user_agent: str = "", client_ip: str = "") -> dict:
    session_id = secrets.token_urlsafe(32)
    now = _now()
    session = {
        "session_id": session_id,
        "username": username,
        "role": ROLES.get(username, "reader"),
        "created_at": now,
        "last_seen_at": now,
        "expires_at": now + timedelta(seconds=SESSION_TTL_SECONDS),
        "user_agent": user_agent,
        "client_ip": client_ip,
        "request_count": 0,
    }
    SESSIONS[session_id] = session
    return session


def get_session(session_id: str) -> Optional[dict]:
    _prune_sessions()
    session = SESSIONS.get(session_id)
    if session is None:
        return None
    if session["expires_at"] <= _now():
        del SESSIONS[session_id]
        return None
    return session


def touch_session(session: dict) -> None:
    """Record activity and, when sliding expiry is on, extend the window."""
    session["last_seen_at"] = _now()
    session["request_count"] += 1
    if SLIDING_EXPIRY:
        session["expires_at"] = session["last_seen_at"] + timedelta(seconds=SESSION_TTL_SECONDS)


# ---------------------------------------------------------------------------
# Credential verification
# ---------------------------------------------------------------------------


def verify_credentials(username: str, password: str) -> bool:
    """Constant-time credential check.

    Always runs a comparison even for unknown users so that response timing
    does not reveal whether a username exists.
    """
    expected = USERS.get(username)
    if expected is None:
        # Compare against a dummy of comparable length to keep timing flat.
        hmac.compare_digest(password.encode(), b"\x00" * max(len(password), 1))
        return False
    return hmac.compare_digest(password.encode(), expected.encode())


def parse_basic_auth(header_value: str) -> tuple[str, str]:
    """Decode an `Authorization: Basic <base64>` header into (username, password).

    Raises HTTPException(400) when the header is malformed — a 400 rather than
    a 401 because the credentials could not be read at all.
    """
    scheme, _, encoded = header_value.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        raise HTTPException(
            status_code=400,
            detail="Authorization header must be in the form 'Basic <base64>'",
        )
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400, detail=f"Basic credentials are not valid base64 UTF-8: {exc}"
        ) from exc
    # The password may itself contain ':', so split only on the first one.
    username, sep, password = decoded.partition(":")
    if not sep:
        raise HTTPException(
            status_code=400, detail="Basic credentials must be 'username:password'"
        )
    return username, password


def _unauthorized(detail: str, challenge: bool = False) -> HTTPException:
    headers = {}
    if challenge:
        headers["WWW-Authenticate"] = f'Basic realm="{BASIC_AUTH_REALM}", charset="UTF-8"'
    return HTTPException(status_code=401, detail=detail, headers=headers or None)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------


async def require_basic_auth(
    authorization: Optional[str] = Header(default=None),
) -> str:
    """Require HTTP Basic Auth. Used by /login only."""
    if authorization is None:
        raise _unauthorized("Basic authentication required", challenge=True)
    username, password = parse_basic_auth(authorization)
    if not verify_credentials(username, password):
        raise _unauthorized("Invalid username or password", challenge=True)
    return username


async def require_session(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_session_id: Optional[str] = Header(default=None),
) -> dict:
    """Resolve the caller from a session cookie, a session header, or Basic Auth.

    Returns a session-shaped dict. For the Basic Auth path the dict is
    synthesized per-request and never stored, so credential-per-call traffic
    does not accumulate sessions.
    """
    # 1. Session cookie, then 2. X-Session-Id header
    sid = request.cookies.get(SESSION_COOKIE_NAME) or x_session_id
    if sid:
        session = get_session(sid)
        if session is not None:
            touch_session(session)
            return session
        # The session is dead. Only fail outright if there are no credentials
        # to fall back on — otherwise a client holding a stale cookie alongside
        # valid Basic credentials would be rejected for no good reason.
        if authorization is None:
            raise _unauthorized("Session is invalid or has expired", challenge=True)

    # 3. Basic Auth passed directly on the request
    if authorization is not None:
        username, password = parse_basic_auth(authorization)
        if not verify_credentials(username, password):
            raise _unauthorized("Invalid username or password", challenge=True)
        now = _now()
        return {
            "session_id": None,
            "username": username,
            "role": ROLES.get(username, "reader"),
            "created_at": now,
            "last_seen_at": now,
            "expires_at": now,
            "user_agent": request.headers.get("user-agent", ""),
            "client_ip": request.client.host if request.client else "",
            "request_count": 0,
            "auth_method": "basic",
        }

    raise _unauthorized(
        f"Provide a session via the {SESSION_COOKIE_NAME} cookie or X-Session-Id "
        "header, or send Basic credentials directly",
        challenge=True,
    )


# ---------------------------------------------------------------------------
# Mock business data
# ---------------------------------------------------------------------------

ACCOUNTS = {
    "ACCT-1001": {
        "account_id": "ACCT-1001",
        "name": "Northwind Trading",
        "status": "active",
        "balance": 48250.75,
        "currency": "USD",
        "opened_date": "2019-04-12",
    },
    "ACCT-1002": {
        "account_id": "ACCT-1002",
        "name": "Globex Industrial",
        "status": "active",
        "balance": 1322900.00,
        "currency": "USD",
        "opened_date": "2016-11-03",
    },
    "ACCT-1003": {
        "account_id": "ACCT-1003",
        "name": "Initech Holdings",
        "status": "suspended",
        "balance": 0.00,
        "currency": "USD",
        "opened_date": "2021-08-27",
    },
}

TRANSACTIONS = {
    "ACCT-1001": [
        {"txn_id": "TXN-88213", "date": "2026-09-28", "amount": -1250.00, "memo": "Vendor payment"},
        {"txn_id": "TXN-88402", "date": "2026-10-01", "amount": 9800.00, "memo": "Customer deposit"},
    ],
    "ACCT-1002": [
        {"txn_id": "TXN-88511", "date": "2026-10-02", "amount": -45000.00, "memo": "Payroll run"},
    ],
    "ACCT-1003": [],
}

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Legacy Platform API",
    description=(
        "Sample internal platform that authenticates with HTTP Basic Auth and "
        "issues a session ID for subsequent requests."
    ),
    version="1.0.0",
)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return errors in a consistent envelope while preserving auth challenges."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.detail, "status": exc.status_code},
        headers=exc.headers,
    )


@app.get("/health")
async def health() -> dict:
    """Unauthenticated liveness probe for Render."""
    _prune_sessions()
    return {
        "status": "ok",
        "time": _iso(_now()),
        "active_sessions": len(SESSIONS),
    }


@app.get("/")
async def root() -> dict:
    """Unauthenticated service description."""
    return {
        "service": "Legacy Platform API",
        "auth": "HTTP Basic Auth at POST /login, then session ID on subsequent calls",
        "session": {
            "cookie": SESSION_COOKIE_NAME,
            "header": "X-Session-Id",
            "ttl_seconds": SESSION_TTL_SECONDS,
            "sliding_expiry": SLIDING_EXPIRY,
        },
        "endpoints": {
            "POST /login": "Basic Auth -> session ID",
            "POST /logout": "Revoke the current session",
            "GET /whoami": "Describe the current session",
            "GET /api/accounts": "List accounts",
            "GET /api/accounts/{account_id}": "Get one account",
            "GET /api/accounts/{account_id}/transactions": "List account transactions",
            "GET /health": "Liveness probe (unauthenticated)",
        },
    }


@app.post("/login")
async def login(
    request: Request,
    response: Response,
    username: str = Depends(require_basic_auth),
) -> dict:
    """Exchange Basic Auth credentials for a session ID.

    Sets the session cookie and also returns the ID in the body so that
    non-browser clients can carry it in X-Session-Id.
    """
    session = create_session(
        username=username,
        user_agent=request.headers.get("user-agent", ""),
        client_ip=request.client.host if request.client else "",
    )

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session["session_id"],
        max_age=SESSION_TTL_SECONDS,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        path="/",
    )

    return {
        "session_id": session["session_id"],
        "username": session["username"],
        "role": session["role"],
        "issued_at": _iso(session["created_at"]),
        "expires_at": _iso(session["expires_at"]),
        "token_type": "session",
        "usage": {
            "cookie": f"{SESSION_COOKIE_NAME}={session['session_id']}",
            "header": f"X-Session-Id: {session['session_id']}",
        },
    }


@app.post("/logout")
async def logout(
    response: Response,
    session: dict = Depends(require_session),
) -> dict:
    """Revoke the current session.

    A caller authenticated by Basic Auth has no stored session to revoke, so
    this reports that rather than pretending to delete something.
    """
    sid = session.get("session_id")
    revoked = False
    if sid and sid in SESSIONS:
        del SESSIONS[sid]
        revoked = True

    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")

    return {
        "revoked": revoked,
        "username": session["username"],
        "detail": (
            "Session revoked"
            if revoked
            else "No stored session to revoke (request was authenticated with Basic Auth)"
        ),
    }


@app.get("/whoami")
async def whoami(session: dict = Depends(require_session)) -> dict:
    """Describe the calling identity and how it authenticated."""
    return {
        "username": session["username"],
        "role": session["role"],
        "auth_method": session.get("auth_method", "session"),
        "session_id": session.get("session_id"),
        "created_at": _iso(session["created_at"]),
        "last_seen_at": _iso(session["last_seen_at"]),
        "expires_at": _iso(session["expires_at"]) if session.get("session_id") else None,
        "request_count": session["request_count"],
    }


@app.get("/api/accounts")
async def list_accounts(session: dict = Depends(require_session)) -> dict:
    return {
        "accounts": list(ACCOUNTS.values()),
        "count": len(ACCOUNTS),
        "requested_by": session["username"],
    }


@app.get("/api/accounts/{account_id}")
async def get_account(account_id: str, session: dict = Depends(require_session)) -> dict:
    account = ACCOUNTS.get(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail=f"No account with id {account_id}")
    return {"account": account, "requested_by": session["username"]}


@app.get("/api/accounts/{account_id}/transactions")
async def get_account_transactions(
    account_id: str, session: dict = Depends(require_session)
) -> dict:
    if account_id not in ACCOUNTS:
        raise HTTPException(status_code=404, detail=f"No account with id {account_id}")
    txns = TRANSACTIONS.get(account_id, [])
    return {
        "account_id": account_id,
        "transactions": txns,
        "count": len(txns),
        "requested_by": session["username"],
    }


@app.get("/api/sessions")
async def list_sessions(session: dict = Depends(require_session)) -> dict:
    """Show currently active sessions. Restricted to the 'service' role.

    Useful for demonstrating that the platform tracks server-side session state.
    """
    if session["role"] != "service":
        raise HTTPException(
            status_code=403, detail="Requires the 'service' role"
        )
    _prune_sessions()
    return {
        "sessions": [
            {
                # Never return full session IDs — a prefix is enough to identify one.
                "session_id_prefix": sid[:8],
                "username": s["username"],
                "role": s["role"],
                "created_at": _iso(s["created_at"]),
                "last_seen_at": _iso(s["last_seen_at"]),
                "expires_at": _iso(s["expires_at"]),
                "request_count": s["request_count"],
            }
            for sid, s in SESSIONS.items()
        ],
        "count": len(SESSIONS),
    }


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
