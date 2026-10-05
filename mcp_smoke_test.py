"""Tests for the MCP server's session broker.

Runs the broker against the real platform app in-process (no network, no
running server) by pointing httpx at an ASGI transport. Verifies the parts
that are easy to get wrong: caching, re-auth on 401, and the login stampede.

    python mcp_smoke_test.py
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ["API_USERS"] = '{"svc_agent":"test-pass","analyst":"reader-pass"}'
os.environ["COOKIE_SECURE"] = "false"
os.environ["PLATFORM_BASE_URL"] = "http://platform"
os.environ["PLATFORM_USERNAME"] = "svc_agent"
os.environ["PLATFORM_PASSWORD"] = "test-pass"

import httpx  # noqa: E402

import main as platform  # noqa: E402
import mcp_server  # noqa: E402

PASSED = 0
FAILED = 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  PASS  {label}")
    else:
        FAILED += 1
        print(f"  FAIL  {label}" + (f" -- {detail}" if detail else ""))


# Route the broker's httpx calls into the platform app instead of the network.
_real_client = httpx.AsyncClient


def _patched_client(*args, **kwargs):
    kwargs.pop("follow_redirects", None)
    kwargs["transport"] = httpx.ASGITransport(app=platform.app)
    return _real_client(*args, follow_redirects=True, **kwargs)


mcp_server.httpx.AsyncClient = _patched_client


def reset() -> None:
    mcp_server.broker.invalidate()
    mcp_server.broker.login_count = 0
    platform.SESSIONS.clear()


async def run() -> None:
    print("\n-- health (unauthenticated) --")
    reset()
    r = await mcp_server.platform_health()
    check("platform_health succeeds", r.get("success") is True, str(r))
    check("no login was needed", mcp_server.broker.login_count == 0, str(r))

    print("\n-- first call logs in, subsequent calls reuse the session --")
    reset()
    r = await mcp_server.list_accounts()
    check("list_accounts succeeds", r.get("success") is True, str(r))
    check("returned 3 accounts", r.get("count") == 3, str(r))
    check("logged in exactly once", mcp_server.broker.login_count == 1, str(r))

    r = await mcp_server.list_accounts()
    r2 = await mcp_server.get_account("ACCT-1002")
    check("second call still succeeds", r.get("success") is True, str(r))
    check("get_account succeeds", r2.get("success") is True, str(r2))
    check(
        "session was reused, not re-minted",
        mcp_server.broker.login_count == 1,
        f"login_count={mcp_server.broker.login_count}",
    )
    check(
        "platform holds a single session",
        len(platform.SESSIONS) == 1,
        f"{len(platform.SESSIONS)} sessions",
    )

    print("\n-- data passes through correctly --")
    r = await mcp_server.get_account("ACCT-1002")
    check(
        "correct account returned",
        r.get("account", {}).get("name") == "Globex Industrial",
        str(r),
    )
    r = await mcp_server.get_account_transactions("ACCT-1001")
    check("two transactions", r.get("count") == 2, str(r))
    r = await mcp_server.whoami()
    check("whoami reports svc_agent", r.get("username") == "svc_agent", str(r))
    check("authenticated by session, not basic", r.get("auth_method") == "session", str(r))

    print("\n-- platform errors surface as failures, not crashes --")
    r = await mcp_server.get_account("ACCT-9999")
    check("unknown account -> success False", r.get("success") is False, str(r))
    check("error message is present", bool(r.get("error")), str(r))
    r = await mcp_server.get_account_transactions("ACCT-9999")
    check("unknown account transactions -> failure", r.get("success") is False, str(r))

    print("\n-- session revoked server-side: re-authenticates and succeeds --")
    reset()
    await mcp_server.list_accounts()
    check("logged in once", mcp_server.broker.login_count == 1)
    # Simulate the platform restarting / sleeping: every session disappears,
    # but the broker still believes its cached one is good.
    platform.SESSIONS.clear()
    r = await mcp_server.list_accounts()
    check("call still succeeds after session loss", r.get("success") is True, str(r))
    check(
        "re-authenticated exactly once",
        mcp_server.broker.login_count == 2,
        f"login_count={mcp_server.broker.login_count}",
    )

    print("\n-- expired cache re-logs in proactively --")
    reset()
    await mcp_server.list_accounts()
    # Push the cached expiry into the past; the broker should not even try it.
    mcp_server.broker._expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    check("cache reports not fresh", mcp_server.broker._is_fresh() is False)
    r = await mcp_server.list_accounts()
    check("call succeeds", r.get("success") is True, str(r))
    check("logged in again", mcp_server.broker.login_count == 2)

    print("\n-- expiry skew: a session about to lapse is replaced early --")
    reset()
    await mcp_server.list_accounts()
    # Inside the skew window but not yet expired.
    mcp_server.broker._expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=mcp_server.EXPIRY_SKEW_SECONDS - 5
    )
    check(
        "session inside skew window is treated as stale",
        mcp_server.broker._is_fresh() is False,
    )
    r = await mcp_server.list_accounts()
    check("call succeeds", r.get("success") is True, str(r))
    check("re-logged in before expiry", mcp_server.broker.login_count == 2)

    print("\n-- concurrent cold calls cause only one login --")
    reset()
    results = await asyncio.gather(*[mcp_server.list_accounts() for _ in range(8)])
    check("all 8 calls succeeded", all(x.get("success") for x in results), str(results[:1]))
    check(
        "exactly one login despite 8 concurrent cold calls",
        mcp_server.broker.login_count == 1,
        f"login_count={mcp_server.broker.login_count} (lock failed to serialize)",
    )
    check(
        "only one session on the platform",
        len(platform.SESSIONS) == 1,
        f"{len(platform.SESSIONS)} sessions",
    )

    print("\n-- role enforcement passes through --")
    reset()
    r = await mcp_server.list_platform_sessions()
    check("service role can list sessions", r.get("success") is True, str(r))
    # Re-point the broker at the reader account.
    mcp_server.USERNAME, mcp_server.PASSWORD = "analyst", "reader-pass"
    reset()
    r = await mcp_server.list_platform_sessions()
    check("reader role is refused", r.get("success") is False, str(r))
    check(
        "refusal explains it is authorization, not auth",
        "authorization" in r.get("error", "").lower(),
        str(r),
    )
    r = await mcp_server.list_accounts()
    check("reader can still read accounts", r.get("success") is True, str(r))
    mcp_server.USERNAME, mcp_server.PASSWORD = "svc_agent", "test-pass"

    print("\n-- bad credentials fail clearly and do not retry forever --")
    reset()
    mcp_server.PASSWORD = "wrong-password"
    r = await mcp_server.list_accounts()
    check("call fails", r.get("success") is False, str(r))
    check(
        "error names the credential config",
        "PLATFORM_PASSWORD" in r.get("error", ""),
        str(r),
    )
    check("no session was cached", mcp_server.broker._session_id is None)
    mcp_server.PASSWORD = "test-pass"

    print("\n-- diagnostics leak neither password nor full session id --")
    reset()
    await mcp_server.list_accounts()
    r = await mcp_server.session_status()
    check("reports a cached session", r.get("has_cached_session") is True, str(r))
    check("confirms credentials configured", r.get("credentials_configured") is True, str(r))
    blob = str(r)
    check("password absent from output", "test-pass" not in blob, blob)
    full_sid = mcp_server.broker._session_id
    check("full session id absent from output", full_sid not in blob, blob)
    check("only a prefix is exposed", len(r.get("session_id_prefix") or "") == 8, str(r))

    print("\n-- refresh_session forces a new login --")
    before = mcp_server.broker.login_count
    r = await mcp_server.refresh_session()
    check("refresh succeeds", r.get("success") is True, str(r))
    check("login count increased", mcp_server.broker.login_count == before + 1)

    print("\n-- tools are registered with the MCP server --")
    tools = await mcp_server.mcp.list_tools()
    names = {t.name for t in tools}
    expected = {
        "list_accounts",
        "get_account",
        "get_account_transactions",
        "whoami",
        "list_platform_sessions",
        "platform_health",
        "session_status",
        "refresh_session",
    }
    check(f"all 8 tools registered (found {len(names)})", expected <= names, str(sorted(names)))
    undocumented = [t.name for t in tools if not (t.description or "").strip()]
    check("every tool has a description", not undocumented, str(undocumented))

    print(f"\n{PASSED} passed, {FAILED} failed")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    asyncio.run(run())
