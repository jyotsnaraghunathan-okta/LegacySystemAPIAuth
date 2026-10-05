"""Tests for the MCP server's credential-injection passthrough.

Two layers:

  1. In-process: the platform app is mounted on an ASGI transport and the
     inbound Authorization header is simulated, so tool logic is checked with
     no network and no servers.
  2. Over real HTTP: the MCP server runs for real and a client injects the
     header the way a gateway would. This is the layer that proves injection
     survives the transport, which is the part that can silently not work.

    python mcp_smoke_test.py
"""

import asyncio
import base64
import contextlib
import os
import socket
import subprocess
import sys
import time

os.environ["API_USERS"] = '{"svc_agent":"test-pass","analyst":"reader-pass"}'
os.environ["COOKIE_SECURE"] = "false"
os.environ["PLATFORM_BASE_URL"] = "http://platform"
# No stored credentials: the server under test must rely on injection.
os.environ.pop("PLATFORM_USERNAME", None)
os.environ.pop("PLATFORM_PASSWORD", None)

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


def basic(username: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()


# Route the server's outbound httpx calls into the platform app.
_real_client = httpx.AsyncClient


def _patched_client(*args, **kwargs):
    kwargs.pop("follow_redirects", None)
    kwargs["transport"] = httpx.ASGITransport(app=platform.app)
    return _real_client(*args, follow_redirects=True, **kwargs)


mcp_server.httpx.AsyncClient = _patched_client

# Simulate the header a gateway would inject. The real implementation reads it
# from the active HTTP request; in-process there is none, so patch the getter.
_injected: dict[str, str] = {}
mcp_server.get_http_headers = lambda include_all=False: dict(_injected)


@contextlib.contextmanager
def injected(authorization: str | None):
    """Run a block as if a gateway had injected this Authorization header."""
    _injected.clear()
    if authorization is not None:
        _injected["authorization"] = authorization
    try:
        yield
    finally:
        _injected.clear()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def run_in_process() -> None:
    print("\n-- no credential injected and no fallback: fails clearly --")
    with injected(None):
        r = await mcp_server.list_accounts()
        check("call fails", r.get("success") is False, str(r))
        check(
            "error explains the gateway is expected to inject",
            "inject" in r.get("error", "").lower(),
            str(r),
        )
        check(
            "error names the dev fallback vars",
            "PLATFORM_USERNAME" in r.get("error", ""),
            str(r),
        )

    print("\n-- injected credential is forwarded and works --")
    with injected(basic("svc_agent", "test-pass")):
        r = await mcp_server.list_accounts()
        check("list_accounts succeeds", r.get("success") is True, str(r))
        check("returned 3 accounts", r.get("count") == 3, str(r))
        r = await mcp_server.get_account("ACCT-1002")
        check(
            "correct account returned",
            r.get("account", {}).get("name") == "Globex Industrial",
            str(r),
        )
        r = await mcp_server.get_account_transactions("ACCT-1001")
        check("two transactions", r.get("count") == 2, str(r))

    print("\n-- the platform sees Basic auth, not a session --")
    with injected(basic("svc_agent", "test-pass")):
        r = await mcp_server.whoami()
        check("whoami succeeds", r.get("success") is True, str(r))
        check("username is svc_agent", r.get("username") == "svc_agent", str(r))
        check("auth_method is 'basic'", r.get("auth_method") == "basic", str(r))
        check("no session was minted", r.get("session_id") is None, str(r))

    print("\n-- stateless: no session accumulates on the platform --")
    platform.SESSIONS.clear()
    with injected(basic("svc_agent", "test-pass")):
        for _ in range(6):
            await mcp_server.list_accounts()
    check(
        "6 calls created 0 platform sessions",
        len(platform.SESSIONS) == 0,
        f"{len(platform.SESSIONS)} sessions",
    )

    print("\n-- the injected identity determines authorization --")
    with injected(basic("svc_agent", "test-pass")):
        r = await mcp_server.list_platform_sessions()
        check("service-role identity allowed", r.get("success") is True, str(r))
    with injected(basic("analyst", "reader-pass")):
        r = await mcp_server.list_platform_sessions()
        check("reader-role identity refused", r.get("success") is False, str(r))
        check(
            "refusal distinguishes authz from authn",
            "authorization" in r.get("error", "").lower(),
            str(r),
        )
        r = await mcp_server.list_accounts()
        check("reader can still read accounts", r.get("success") is True, str(r))
        r = await mcp_server.whoami()
        check("whoami reflects the reader identity", r.get("username") == "analyst", str(r))

    print("\n-- a bad injected credential surfaces as a 401 failure --")
    with injected(basic("svc_agent", "wrong-password")):
        r = await mcp_server.list_accounts()
        check("call fails", r.get("success") is False, str(r))
        check(
            "error points at the credential, not the platform",
            "credential" in r.get("error", "").lower(),
            str(r),
        )

    print("\n-- a Bearer token is rejected rather than forwarded blindly --")
    with injected("Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake.token"):
        r = await mcp_server.list_accounts()
        check("call fails", r.get("success") is False, str(r))
        check(
            "error explains the scheme mismatch",
            "basic" in r.get("error", "").lower() and "bearer" in r.get("error", "").lower(),
            str(r),
        )
        check(
            "error says the gateway should exchange the token",
            "exchange" in r.get("error", "").lower(),
            str(r),
        )

    print("\n-- platform errors still surface as values --")
    with injected(basic("svc_agent", "test-pass")):
        r = await mcp_server.get_account("ACCT-9999")
        check("unknown account -> success False", r.get("success") is False, str(r))
        check("platform's own message is passed through", "ACCT-9999" in r.get("error", ""), str(r))

    print("\n-- health needs no credential --")
    with injected(None):
        r = await mcp_server.platform_health()
        check("platform_health succeeds without a credential", r.get("success") is True, str(r))

    print("\n-- diagnostics report the source without leaking the secret --")
    with injected(basic("svc_agent", "test-pass")):
        r = await mcp_server.credential_source()
        check("reports injection as the source", "injected" in r.get("credential_source", ""), str(r))
        check("reports the username", r.get("username") == "svc_agent", str(r))
        check("reports the scheme", r.get("auth_scheme") == "Basic", str(r))
        check("confirms no stored credentials", r.get("holds_stored_credentials") is False, str(r))
        blob = str(r)
        check("password absent from output", "test-pass" not in blob, blob)
        check("raw header absent from output", "c3ZjX2FnZW50" not in blob, blob)

    print("\n-- the server holds no credentials of its own --")
    check("FALLBACK_PASSWORD is empty", mcp_server.FALLBACK_PASSWORD == "")
    check("FALLBACK_USERNAME is empty", mcp_server.FALLBACK_USERNAME == "")
    check(
        "no session cache exists on the module",
        not hasattr(mcp_server, "broker"),
        "a stateful broker is still present",
    )

    print("\n-- tools are registered --")
    tools = await mcp_server.mcp.list_tools()
    names = {t.name for t in tools}
    expected = {
        "list_accounts",
        "get_account",
        "get_account_transactions",
        "whoami",
        "list_platform_sessions",
        "platform_health",
        "credential_source",
    }
    check(f"all 7 tools registered (found {len(names)})", expected <= names, str(sorted(names)))
    undocumented = [t.name for t in tools if not (t.description or "").strip()]
    check("every tool has a description", not undocumented, str(undocumented))


def run_over_http() -> None:
    """Prove header injection survives a real HTTP transport.

    The in-process tests patch get_http_headers, so they cannot catch the case
    where fastmcp strips or never exposes the header. This runs both servers
    for real and injects the way a gateway would.
    """
    print("\n-- end to end over real HTTP (gateway-style injection) --")

    platform_port = free_port()
    mcp_port = free_port()
    here = os.path.dirname(os.path.abspath(__file__))
    env = {
        **os.environ,
        "API_USERS": '{"svc_agent":"test-pass","analyst":"reader-pass"}',
        "COOKIE_SECURE": "false",
        "PORT": str(platform_port),
        "PLATFORM_BASE_URL": f"http://127.0.0.1:{platform_port}",
    }
    env.pop("PLATFORM_USERNAME", None)
    env.pop("PLATFORM_PASSWORD", None)

    platform_proc = subprocess.Popen(
        [sys.executable, os.path.join(here, "main.py")],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    mcp_proc = subprocess.Popen(
        [sys.executable, os.path.join(here, "mcp_server.py"), "--http", str(mcp_port)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        base = f"http://127.0.0.1:{mcp_port}/mcp"
        deadline = time.time() + 30
        ready = False
        while time.time() < deadline:
            try:
                httpx.get(f"http://127.0.0.1:{platform_port}/health", timeout=2)
                httpx.post(base, timeout=2)
                ready = True
                break
            except httpx.HTTPError:
                time.sleep(0.4)
        check("both servers came up", ready)
        if not ready:
            return

        def mcp_call(tool: str, authorization: str | None) -> dict:
            """Minimal MCP client: initialize, then call one tool."""
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            }
            if authorization:
                headers["Authorization"] = authorization
            with httpx.Client(timeout=30) as client:
                init = client.post(
                    base,
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "gateway-sim", "version": "1"},
                        },
                    },
                )
                sid = init.headers.get("mcp-session-id")
                if sid:
                    headers["mcp-session-id"] = sid
                client.post(
                    base,
                    headers=headers,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                )
                resp = client.post(
                    base,
                    headers=headers,
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {"name": tool, "arguments": {}},
                    },
                )
                # Responses may arrive as SSE; pull out the JSON payload.
                text = resp.text
                for line in text.splitlines():
                    line = line.strip()
                    if line.startswith("data:"):
                        line = line[5:].strip()
                    if line.startswith('{"jsonrpc"') and '"id":2' in line.replace(" ", ""):
                        import json

                        d = json.loads(line)
                        content = d.get("result", {}).get("content", [])
                        if content and content[0].get("type") == "text":
                            return json.loads(content[0]["text"])
                        return d.get("result", d)
                import json

                try:
                    d = json.loads(text)
                    content = d.get("result", {}).get("content", [])
                    if content and content[0].get("type") == "text":
                        return json.loads(content[0]["text"])
                    return d.get("result", d)
                except json.JSONDecodeError:
                    return {"success": False, "error": f"unparseable: {text[:200]}"}

        r = mcp_call("whoami", basic("svc_agent", "test-pass"))
        check("injected header reached the platform", r.get("success") is True, str(r)[:300])
        check("platform saw svc_agent", r.get("username") == "svc_agent", str(r)[:300])
        check("platform saw Basic auth", r.get("auth_method") == "basic", str(r)[:300])

        r = mcp_call("whoami", basic("analyst", "reader-pass"))
        check("a different injected identity is honoured", r.get("username") == "analyst", str(r)[:300])

        r = mcp_call("list_accounts", None)
        check("no injected header -> failure", r.get("success") is False, str(r)[:300])

        r = mcp_call("list_platform_sessions", basic("analyst", "reader-pass"))
        check("reader refused over HTTP too", r.get("success") is False, str(r)[:300])

    finally:
        for proc in (mcp_proc, platform_proc):
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    asyncio.run(run_in_process())
    run_over_http()
    print(f"\n{PASSED} passed, {FAILED} failed")
    sys.exit(1 if FAILED else 0)
