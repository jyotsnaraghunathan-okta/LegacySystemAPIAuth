"""End-to-end smoke test for the Basic Auth -> session flow.

Runs against the app in-process via httpx ASGI transport, so it needs no
running server. Exits non-zero on the first failure.

    python smoke_test.py
"""

import asyncio
import base64
import os
import sys

# Fix the credentials before main is imported, so the test does not depend on
# whatever happens to be in .env.
os.environ["API_USERS"] = '{"svc_agent":"test-pass","analyst":"reader-pass"}'
os.environ["COOKIE_SECURE"] = "false"

import httpx  # noqa: E402

import main  # noqa: E402

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


def basic(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


async def run() -> None:
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        print("\n-- unauthenticated endpoints --")
        r = await client.get("/health")
        check("GET /health returns 200", r.status_code == 200, r.text)
        r = await client.get("/")
        check("GET / returns 200", r.status_code == 200, r.text)

        print("\n-- login rejects bad credentials --")
        r = await client.post("/login")
        check("no credentials -> 401", r.status_code == 401, r.text)
        check(
            "401 carries WWW-Authenticate challenge",
            "www-authenticate" in r.headers,
            str(dict(r.headers)),
        )
        r = await client.post("/login", headers={"Authorization": basic("svc_agent", "wrong")})
        check("wrong password -> 401", r.status_code == 401, r.text)
        r = await client.post("/login", headers={"Authorization": basic("nobody", "x")})
        check("unknown user -> 401", r.status_code == 401, r.text)
        r = await client.post("/login", headers={"Authorization": "Basic not-base64!!"})
        check("malformed base64 -> 400", r.status_code == 400, r.text)
        r = await client.post("/login", headers={"Authorization": "Bearer abc123"})
        check("wrong scheme -> 400", r.status_code == 400, r.text)

        print("\n-- login issues a session --")
        r = await client.post("/login", headers={"Authorization": basic("svc_agent", "test-pass")})
        check("valid credentials -> 200", r.status_code == 200, r.text)
        body = r.json()
        session_id = body.get("session_id")
        check("response body contains session_id", bool(session_id), r.text)
        check("role resolved to 'service'", body.get("role") == "service", r.text)
        check("expires_at present", bool(body.get("expires_at")), r.text)
        check(
            "Set-Cookie carries the session",
            main.SESSION_COOKIE_NAME in r.cookies,
            str(dict(r.cookies)),
        )
        check(
            "session cookie is HttpOnly",
            "httponly" in r.headers.get("set-cookie", "").lower(),
            r.headers.get("set-cookie", ""),
        )

        print("\n-- protected endpoints reject missing/bad sessions --")
        bare = httpx.AsyncClient(transport=transport, base_url="http://test")
        r = await bare.get("/api/accounts")
        check("no session -> 401", r.status_code == 401, r.text)
        r = await bare.get("/api/accounts", headers={"X-Session-Id": "fabricated-session"})
        check("invalid session id -> 401", r.status_code == 401, r.text)

        print("\n-- session via X-Session-Id header --")
        hdr = {"X-Session-Id": session_id}
        r = await bare.get("/api/accounts", headers=hdr)
        check("header session -> 200", r.status_code == 200, r.text)
        check("returns 3 accounts", r.json().get("count") == 3, r.text)
        r = await bare.get("/api/accounts/ACCT-1002", headers=hdr)
        check("single account -> 200", r.status_code == 200, r.text)
        check(
            "correct account returned",
            r.json()["account"]["name"] == "Globex Industrial",
            r.text,
        )
        r = await bare.get("/api/accounts/ACCT-9999", headers=hdr)
        check("unknown account -> 404", r.status_code == 404, r.text)
        r = await bare.get("/api/accounts/ACCT-1001/transactions", headers=hdr)
        check("transactions -> 200", r.status_code == 200, r.text)
        check("two transactions", r.json().get("count") == 2, r.text)

        print("\n-- session via cookie (client retains it from /login) --")
        r = await client.get("/whoami")
        check("cookie session -> 200", r.status_code == 200, r.text)
        who = r.json()
        check("auth_method is 'session'", who.get("auth_method") == "session", r.text)
        check("username is svc_agent", who.get("username") == "svc_agent", r.text)
        check("request_count is tracked", who.get("request_count", 0) > 0, r.text)

        print("\n-- Basic Auth directly on a protected endpoint --")
        r = await bare.get(
            "/whoami", headers={"Authorization": basic("analyst", "reader-pass")}
        )
        check("basic on protected endpoint -> 200", r.status_code == 200, r.text)
        who = r.json()
        check("auth_method is 'basic'", who.get("auth_method") == "basic", r.text)
        check("role resolved to 'reader'", who.get("role") == "reader", r.text)
        check("no session_id was minted", who.get("session_id") is None, r.text)
        before = len(main.SESSIONS)
        await bare.get("/whoami", headers={"Authorization": basic("analyst", "reader-pass")})
        check(
            "basic auth does not accumulate sessions",
            len(main.SESSIONS) == before,
            f"{before} -> {len(main.SESSIONS)}",
        )

        print("\n-- role enforcement --")
        r = await bare.get("/api/sessions", headers=hdr)
        check("service role can list sessions", r.status_code == 200, r.text)
        check(
            "session ids are not exposed in full",
            all("session_id" not in s for s in r.json()["sessions"]),
            r.text,
        )
        r = await bare.get(
            "/api/sessions", headers={"Authorization": basic("analyst", "reader-pass")}
        )
        check("reader role -> 403", r.status_code == 403, r.text)

        print("\n-- expired session is rejected --")
        r2 = await bare.post("/login", headers={"Authorization": basic("analyst", "reader-pass")})
        short_sid = r2.json()["session_id"]
        main.SESSIONS[short_sid]["expires_at"] = main._now() - main.timedelta(seconds=1)
        r = await bare.get("/whoami", headers={"X-Session-Id": short_sid})
        check("expired session -> 401", r.status_code == 401, r.text)
        check("expired session was pruned", short_sid not in main.SESSIONS)

        print("\n-- logout --")
        r = await client.post("/logout")
        check("logout -> 200", r.status_code == 200, r.text)
        check("logout reports revoked", r.json().get("revoked") is True, r.text)
        r = await bare.get("/whoami", headers={"X-Session-Id": session_id})
        check("revoked session -> 401", r.status_code == 401, r.text)
        # bare still holds a stale cookie here, which is the point: valid Basic
        # credentials must still get through.
        r = await bare.post("/logout", headers={"Authorization": basic("analyst", "reader-pass")})
        check("logout under basic auth -> 200", r.status_code == 200, r.text)
        check("nothing to revoke under basic auth", r.json().get("revoked") is False, r.text)

        print("\n-- stale cookie falls back to Basic credentials --")
        stale = httpx.AsyncClient(transport=transport, base_url="http://test")
        stale.cookies.set(main.SESSION_COOKIE_NAME, "long-dead-session")
        r = await stale.get("/whoami", headers={"Authorization": basic("svc_agent", "test-pass")})
        check("stale cookie + valid basic -> 200", r.status_code == 200, r.text)
        check("fell back to basic auth", r.json().get("auth_method") == "basic", r.text)
        r = await stale.get("/whoami")
        check("stale cookie alone -> 401", r.status_code == 401, r.text)
        r = await stale.get("/whoami", headers={"Authorization": basic("svc_agent", "wrong")})
        check("stale cookie + bad basic -> 401", r.status_code == 401, r.text)
        await stale.aclose()

        await bare.aclose()

    print(f"\n{PASSED} passed, {FAILED} failed")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    asyncio.run(run())
