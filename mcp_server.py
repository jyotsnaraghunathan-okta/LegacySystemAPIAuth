"""
MCP server exposing the Legacy Platform API as tools.

This server holds no credentials. An upstream gateway authenticates the agent,
retrieves the vaulted service account credential, and injects it as an
`Authorization: Basic` header on the inbound MCP request. This server reads
that header per call and forwards it to the platform.

    Agent --(agent's own identity)--> Gateway --(Authorization: Basic)--> this
                                     holds the vaulted credential            |
                                                                             v
                                                                        Platform

Consequences of that design, and the reason it is preferable:

  - No secret exists in this process, its environment, or its config. Nothing
    here can leak a credential it never had.
  - No session cache. Credentials arrive per request, so there is no shared
    state to go stale, no re-login logic, and no cross-agent session reuse.
  - The gateway stays the single point of credential rotation and audit.

Because the credential is per-request, each call carries whichever identity
the gateway resolved for that agent. The platform's own role check then
applies to that identity — a reader-role agent is refused
`list_platform_sessions` even though a service-role agent is not.

Run:
    python mcp_server.py --http 8001     # HTTP; required for header injection
    python mcp_server.py                 # stdio; see FALLBACK below

FALLBACK (local development only): stdio has no inbound HTTP headers, so
there is nothing to inject. If PLATFORM_USERNAME and PLATFORM_PASSWORD are
set, they are used instead, letting you exercise the tools without a gateway
in front. Leave them unset in any deployment that sits behind one.

Config:
    PLATFORM_BASE_URL        platform root, e.g. https://api-basic-auth.onrender.com
    HTTP_TIMEOUT_SECONDS     request timeout (default 90)
    PLATFORM_USERNAME        dev fallback only; omit behind a gateway
    PLATFORM_PASSWORD        dev fallback only; omit behind a gateway
"""

import base64
import os
import sys
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

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
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT_SECONDS", "90"))

# Development fallback only. Unset behind a gateway.
FALLBACK_USERNAME = os.getenv("PLATFORM_USERNAME", "")
FALLBACK_PASSWORD = os.getenv("PLATFORM_PASSWORD", "")

if FALLBACK_PASSWORD:
    print(
        "NOTE: PLATFORM_PASSWORD is set, so calls without an injected "
        "Authorization header will fall back to it. Unset it when running "
        "behind a gateway that injects credentials.",
        file=sys.stderr,
    )

mcp = FastMCP("Legacy Platform")


class MissingCredential(Exception):
    """No credential was injected and no fallback is configured."""


def inbound_credential() -> str:
    """Return the `Authorization` header value to forward to the platform.

    Prefers the header injected by the upstream gateway. Falls back to
    configured credentials only when nothing was injected, which is the local
    stdio development case.
    """
    headers = get_http_headers()
    injected = headers.get("authorization")

    if injected:
        scheme = injected.split(" ", 1)[0].lower()
        if scheme != "basic":
            # A Bearer token here means the gateway forwarded the agent's own
            # token rather than exchanging it for the platform credential.
            # Forwarding it would just produce a confusing 401 downstream.
            raise MissingCredential(
                f"The injected Authorization header uses the '{scheme}' scheme, but "
                "the platform only accepts Basic. The gateway should exchange the "
                "agent's token for the vaulted service account credential before "
                "forwarding."
            )
        return injected

    if FALLBACK_USERNAME and FALLBACK_PASSWORD:
        token = base64.b64encode(
            f"{FALLBACK_USERNAME}:{FALLBACK_PASSWORD}".encode()
        ).decode()
        return f"Basic {token}"

    raise MissingCredential(
        "No credential available. This server expects an upstream gateway to "
        "inject an 'Authorization: Basic' header carrying the vaulted service "
        "account credential. For local development without a gateway, set "
        "PLATFORM_USERNAME and PLATFORM_PASSWORD instead."
    )


async def call_platform(method: str, path: str) -> dict:
    """Call the platform, forwarding the injected credential.

    Sends Basic credentials directly rather than logging in for a session.
    With a per-request credential there is nothing to amortize a session
    across — and no shared cache means no stale-session failure mode.
    """
    try:
        authorization = inbound_credential()
    except MissingCredential as exc:
        return {"success": False, "error": str(exc)}

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
        try:
            response = await client.request(
                method,
                f"{BASE_URL}{path}",
                headers={"Authorization": authorization},
            )

            if response.status_code == 401:
                return {
                    "success": False,
                    "error": (
                        "The platform rejected the credential. It may be stale in "
                        "the vault, or scoped to a different platform instance."
                    ),
                }
            if response.status_code == 403:
                return {
                    "success": False,
                    "error": (
                        "The platform refused this action for this identity's role. "
                        "Authentication worked; authorization did not."
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
    """Show which platform identity this call authenticated as, and how."""
    return await call_platform("GET", "/whoami")


@mcp.tool
async def list_platform_sessions() -> dict:
    """List sessions currently active on the platform.

    Requires the platform's 'service' role; a reader-role identity is refused.
    """
    return await call_platform("GET", "/api/sessions")


@mcp.tool
async def platform_health() -> dict:
    """Check that the platform is reachable. Needs no credential.

    Use this to wake a sleeping free-tier deployment, or to tell "the platform
    is down" apart from "the credential was rejected".
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
async def credential_source() -> dict:
    """Report where this call's credential came from, without revealing it.

    Diagnostic for confirming the gateway is injecting correctly. Reports the
    username and auth scheme only — never the password.
    """
    headers = get_http_headers()
    injected = headers.get("authorization")

    source = "injected by gateway" if injected else (
        "local fallback (PLATFORM_USERNAME/PASSWORD)"
        if FALLBACK_USERNAME and FALLBACK_PASSWORD
        else "none available"
    )

    username: Optional[str] = None
    scheme: Optional[str] = None
    if injected:
        parts = injected.split(" ", 1)
        scheme = parts[0]
        if len(parts) == 2 and scheme.lower() == "basic":
            try:
                username = base64.b64decode(parts[1]).decode("utf-8").split(":", 1)[0]
            except (ValueError, UnicodeDecodeError):
                username = None
    elif FALLBACK_USERNAME:
        scheme, username = "Basic", FALLBACK_USERNAME

    return {
        "success": True,
        "platform": BASE_URL,
        "credential_source": source,
        "auth_scheme": scheme,
        "username": username,
        "holds_stored_credentials": bool(FALLBACK_PASSWORD),
    }


if __name__ == "__main__":
    if "--http" in sys.argv:
        idx = sys.argv.index("--http")
        port = int(sys.argv[idx + 1]) if len(sys.argv) > idx + 1 else int(
            os.getenv("PORT", "8001")
        )
        print(
            f"Legacy Platform MCP server on http://0.0.0.0:{port}/mcp -> {BASE_URL} "
            "(credentials expected via injected Authorization header)",
            file=sys.stderr,
        )
        mcp.run(transport="http", host="0.0.0.0", port=port)
    else:
        # stdio: nothing may touch stdout except the protocol itself.
        print(
            f"Legacy Platform MCP server (stdio) -> {BASE_URL}. stdio carries no "
            "HTTP headers, so credential injection is unavailable; using the "
            "PLATFORM_USERNAME/PASSWORD fallback if set.",
            file=sys.stderr,
        )
        mcp.run()
