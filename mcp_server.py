"""
MCP server wrapping the Legacy Platform API.

This is the broker described in README.md. It holds the service account
credentials, exchanges them for a session, caches that session for its TTL,
and re-authenticates when the platform rejects it. Agents call the tools below
and never see the password or the session ID.

Why a cache at all: the platform issues a session precisely so callers can
amortize one credential check across many requests. Sending Basic Auth on
every call would work (the platform accepts it) but throws that away.

Run:
    python mcp_server.py                 # stdio, for Claude Desktop / MCP clients
    python mcp_server.py --http 8001     # HTTP, for remote clients

Config:
    PLATFORM_BASE_URL   platform root, e.g. https://api-basic-auth.onrender.com
    PLATFORM_USERNAME   service account username
    PLATFORM_PASSWORD   service account password
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP

# Trust the OS certificate store rather than only certifi's bundle. Without
# this, any network that terminates TLS for inspection (common on corporate
# laptops and VPNs) fails with CERTIFICATE_VERIFY_FAILED, because its CA is
# installed in the system keychain and not in certifi.
try:
    import truststore

    truststore.inject_into_ssl()
except ImportError:
    # Optional dependency. On a network without TLS interception, certifi is fine.
    pass

env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
load_dotenv(env_path)

BASE_URL = os.getenv("PLATFORM_BASE_URL", "http://localhost:8000").rstrip("/")
USERNAME = os.getenv("PLATFORM_USERNAME", "svc_agent")
PASSWORD = os.getenv("PLATFORM_PASSWORD", "")

# Re-login this many seconds before the platform's stated expiry, so a session
# cannot lapse between our check and the platform receiving the request.
EXPIRY_SKEW_SECONDS = int(os.getenv("EXPIRY_SKEW_SECONDS", "30"))

HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "90"))

if not PASSWORD:
    print(
        "WARNING: PLATFORM_PASSWORD is not set. Every tool call will fail "
        "authentication until it is configured.",
        file=sys.stderr,
    )

mcp = FastMCP("Legacy Platform")


# ---------------------------------------------------------------------------
# Session broker
# ---------------------------------------------------------------------------


class SessionBroker:
    """Owns the credential -> session exchange and the cached session.

    The lock matters: tools run concurrently, and without it a burst of calls
    arriving with no cached session would each kick off their own login,
    minting a pile of sessions on the platform and racing to overwrite the
    cache. One login, everyone else waits.
    """

    def __init__(self) -> None:
        self._session_id: Optional[str] = None
        self._expires_at: Optional[datetime] = None
        self._lock = asyncio.Lock()
        self.login_count = 0

    def _is_fresh(self) -> bool:
        if self._session_id is None or self._expires_at is None:
            return False
        return datetime.now(timezone.utc) < self._expires_at - timedelta(
            seconds=EXPIRY_SKEW_SECONDS
        )

    def invalidate(self) -> None:
        self._session_id = None
        self._expires_at = None

    async def _login(self, client: httpx.AsyncClient) -> str:
        """Exchange credentials for a session. Caller must hold the lock."""
        response = await client.post(f"{BASE_URL}/login", auth=(USERNAME, PASSWORD))
        if response.status_code == 401:
            raise PlatformAuthError(
                "The platform rejected the service account credentials. Check "
                "PLATFORM_USERNAME and PLATFORM_PASSWORD."
            )
        response.raise_for_status()
        body = response.json()

        self._session_id = body["session_id"]
        # Trust the platform's own expiry rather than assuming the TTL, since
        # the platform may apply a different one than we expect.
        try:
            self._expires_at = datetime.fromisoformat(
                body["expires_at"].replace("Z", "+00:00")
            )
        except (KeyError, ValueError):
            self._expires_at = datetime.now(timezone.utc) + timedelta(minutes=25)

        self.login_count += 1
        return self._session_id

    async def session_id(self, client: httpx.AsyncClient) -> str:
        """Return a usable session ID, logging in only when needed."""
        if self._is_fresh():
            return self._session_id  # type: ignore[return-value]
        async with self._lock:
            # Re-check: another coroutine may have logged in while we waited.
            if self._is_fresh():
                return self._session_id  # type: ignore[return-value]
            return await self._login(client)

    def describe(self) -> dict:
        return {
            "has_cached_session": self._session_id is not None,
            "session_id_prefix": self._session_id[:8] if self._session_id else None,
            "expires_at": self._expires_at.isoformat().replace("+00:00", "Z")
            if self._expires_at
            else None,
            "considered_fresh": self._is_fresh(),
            "logins_performed": self.login_count,
        }


class PlatformAuthError(Exception):
    """The service account credentials themselves are bad — retrying won't help."""


broker = SessionBroker()


async def call_platform(method: str, path: str) -> dict:
    """Call the platform with the cached session, re-authenticating once on 401.

    The single retry is the point of the whole broker: the platform's sessions
    are in-memory, so a restart or a free-tier sleep silently invalidates them.
    A 401 means "log in again", not "fail".
    """
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        try:
            sid = await broker.session_id(client)
        except PlatformAuthError as exc:
            return {"success": False, "error": str(exc)}
        except httpx.HTTPError as exc:
            return {"success": False, "error": f"Could not reach the platform: {exc}"}

        async def attempt(session_id: str) -> httpx.Response:
            return await client.request(
                method,
                f"{BASE_URL}{path}",
                headers={"X-Session-Id": session_id},
            )

        try:
            response = await attempt(sid)

            if response.status_code == 401:
                # Session died underneath us. Drop it and log in once more.
                broker.invalidate()
                try:
                    sid = await broker.session_id(client)
                except PlatformAuthError as exc:
                    return {"success": False, "error": str(exc)}
                response = await attempt(sid)

            if response.status_code == 401:
                return {
                    "success": False,
                    "error": "Still unauthorized after re-authenticating.",
                }
            if response.status_code == 403:
                return {
                    "success": False,
                    "error": (
                        "The platform refused this action for the service account's "
                        "role. Authentication worked; authorization did not."
                    ),
                }
            if response.status_code == 404:
                return {"success": False, "error": _detail(response, "Not found")}
            response.raise_for_status()
            return {"success": True, **response.json()}

        except httpx.TimeoutException:
            return {
                "success": False,
                "error": (
                    f"The platform did not respond within {HTTP_TIMEOUT:.0f}s. On a "
                    "free hosting tier the first request after idle can be slow; "
                    "try again."
                ),
            }
        except httpx.HTTPStatusError as exc:
            return {
                "success": False,
                "error": f"Platform returned {exc.response.status_code}: "
                f"{_detail(exc.response, 'unexpected error')}",
            }
        except httpx.HTTPError as exc:
            return {"success": False, "error": f"Could not reach the platform: {exc}"}


def _detail(response: httpx.Response, fallback: str) -> str:
    """Pull the platform's error message out of its JSON envelope."""
    try:
        return response.json().get("error", fallback)
    except ValueError:
        return fallback


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool
async def list_accounts() -> dict:
    """List all accounts on the platform, with balance and status for each."""
    return await call_platform("GET", "/api/accounts")


@mcp.tool
async def get_account(account_id: str) -> dict:
    """Get one account by ID.

    Args:
        account_id: Account identifier, e.g. ACCT-1001.
    """
    return await call_platform("GET", f"/api/accounts/{account_id}")


@mcp.tool
async def get_account_transactions(account_id: str) -> dict:
    """List the transactions recorded against an account.

    Args:
        account_id: Account identifier, e.g. ACCT-1001.
    """
    return await call_platform("GET", f"/api/accounts/{account_id}/transactions")


@mcp.tool
async def whoami() -> dict:
    """Show which platform identity the broker is authenticating as, and how."""
    return await call_platform("GET", "/whoami")


@mcp.tool
async def list_platform_sessions() -> dict:
    """List sessions currently active on the platform.

    Requires the service account to hold the platform's 'service' role; a
    reader-role account gets a refusal.
    """
    return await call_platform("GET", "/api/sessions")


@mcp.tool
async def platform_health() -> dict:
    """Check that the platform is reachable. Needs no authentication.

    Use this to wake a sleeping free-tier deployment before other calls, or to
    tell "the platform is down" apart from "the credentials are wrong".
    """
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        try:
            response = await client.get(f"{BASE_URL}/health")
            response.raise_for_status()
            return {"success": True, "platform": BASE_URL, **response.json()}
        except httpx.TimeoutException:
            return {
                "success": False,
                "platform": BASE_URL,
                "error": f"No response within {HTTP_TIMEOUT:.0f}s.",
            }
        except httpx.HTTPError as exc:
            return {"success": False, "platform": BASE_URL, "error": str(exc)}


@mcp.tool
async def session_status() -> dict:
    """Inspect the broker's cached session: whether one is held and when it expires.

    Diagnostic. Reports only a short prefix of the session ID, never the full
    value or the credentials.
    """
    return {
        "success": True,
        "platform": BASE_URL,
        "authenticating_as": USERNAME,
        "credentials_configured": bool(PASSWORD),
        **broker.describe(),
    }


@mcp.tool
async def refresh_session() -> dict:
    """Discard the cached session and log in again.

    Rarely needed — a 401 triggers this automatically. Useful after rotating
    the service account password, or to confirm login works on demand.
    """
    broker.invalidate()
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        try:
            await broker.session_id(client)
        except PlatformAuthError as exc:
            return {"success": False, "error": str(exc)}
        except httpx.HTTPError as exc:
            return {"success": False, "error": f"Could not reach the platform: {exc}"}
    return {"success": True, "detail": "Re-authenticated.", **broker.describe()}


if __name__ == "__main__":
    if "--http" in sys.argv:
        idx = sys.argv.index("--http")
        port = int(sys.argv[idx + 1]) if len(sys.argv) > idx + 1 else int(
            os.getenv("PORT", "8001")
        )
        print(
            f"Legacy Platform MCP server on http://0.0.0.0:{port}/mcp "
            f"-> {BASE_URL} as {USERNAME}",
            file=sys.stderr,
        )
        mcp.run(transport="http", host="0.0.0.0", port=port)
    else:
        # stdio: nothing may touch stdout except the protocol itself.
        print(f"Legacy Platform MCP server (stdio) -> {BASE_URL}", file=sys.stderr)
        mcp.run()
