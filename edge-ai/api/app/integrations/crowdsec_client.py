"""CrowdSec LAPI client (read-only in this skeleton).

Auth model on LAPI:
- Machine (watcher) credentials -> JWT -> management endpoints (/v1/alerts)
- Bouncer API key               -> decisions endpoints (GET /v1/decisions)

Create the machine and bouncer on the crowdsec container first:
  docker compose exec crowdsec cscli machines add edge-ai --password "..." -o raw
"""

import time

import httpx

from app.config import settings

_token: str | None = None
_token_exp: float = 0.0


async def _login_token() -> str:
    global _token, _token_exp
    if _token and time.time() < _token_exp:
        return _token
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{settings.crowdsec_lapi_url}/v1/watchers/login",
            json={
                "machine_id": settings.crowdsec_machine_id,
                "password": settings.crowdsec_machine_password,
            },
        )
        resp.raise_for_status()
        data = resp.json()
    _token = data["token"]
    # Refresh a bit before real expiry (default 1h).
    _token_exp = time.time() + 45 * 60
    return _token


async def _authed_client() -> httpx.AsyncClient:
    token = await _login_token()
    headers = {"Authorization": f"Bearer {token}"}
    return httpx.AsyncClient(
        base_url=settings.crowdsec_lapi_url, headers=headers, timeout=15.0
    )


async def list_alerts(limit: int = 20) -> list[dict]:
    async with await _authed_client() as client:
        resp = await client.get("/v1/alerts", params={"limit": str(limit)})
        resp.raise_for_status()
        return resp.json()


async def list_decisions() -> list[dict]:
    """Active ban decisions (read-only; bouncer-style access)."""
    if not settings.crowdsec_bouncer_key:
        raise RuntimeError(
            "CROWDSEC_BOUNCER_KEY not set — create one with: "
            "cscli bouncers add edge-ai-readonly -o raw"
        )
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(
            f"{settings.crowdsec_lapi_url}/v1/decisions",
            headers={"X-Api-Key": settings.crowdsec_bouncer_key},
        )
        resp.raise_for_status()
        return resp.json()
