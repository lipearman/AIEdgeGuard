"""Defense executor — the ONLY component allowed to touch enforcement.

Restricted verb set (per LACD architecture — the LLM never talks here):
  1. temporary_ip_block  -> CrowdSec decision (auto-expires by duration)
  2. remove_ip_block     -> delete CrowdSec decisions for an IP

Every call is audit-logged by the caller (decisions table). The executor
does not decide anything — it executes what the Policy Engine approved.
"""

import sys

from app.integrations import crowdsec_client


async def execute(action: str, target: str, duration_seconds: int,
                  justification: str) -> dict:
    """Execute one approved action. Returns {ok, detail}."""
    if action == "temporary_ip_block":
        if not target:
            return {"ok": False, "detail": "no target IP"}
        seconds = max(1, min(int(duration_seconds or 900), 86400))
        await crowdsec_client.add_decision(
            ip=target,
            duration_seconds=seconds,
            reason=f"edgeguard-ai: {justification}"[:120],
        )
        sys.stderr.write(f"[defense] BANNED {target} for {seconds}s — {justification}\n")
        return {"ok": True, "detail": f"crowdsec decision added: {target} for {seconds}s"}

    if action == "remove_ip_block":
        if not target:
            return {"ok": False, "detail": "no target IP"}
        await crowdsec_client.remove_decisions_for_ip(target)
        sys.stderr.write(f"[defense] UNBANNED {target}\n")
        return {"ok": True, "detail": f"crowdsec decisions removed for {target}"}

    return {"ok": False, "detail": f"unsupported action '{action}'"}
