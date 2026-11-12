"""Defense executor — the ONLY component allowed to touch enforcement.

Restricted verb set (per LACD architecture — the LLM never talks here):
  1. temporary_ip_block  -> CrowdSec decision (auto-expires by duration)
  2. remove_ip_block     -> delete CrowdSec decisions for an IP

Every call is audit-logged by the caller (decisions table). The executor
does not decide anything — it executes what the Policy Engine approved.
"""

import ipaddress
import sys

from app.integrations import crowdsec_client, db


async def execute_stored(
    decision_id: int, expected_status: str = "pending_approval"
) -> dict:
    """Claim a proposal atomically, so concurrent approvals cannot execute twice.

    A network failure may mean CrowdSec accepted the ban but its reply was lost.
    Preserve that uncertainty for reconciliation; never retry it automatically.
    """
    claimed = await db.update_decision_status(
        decision_id, "executing", expected_status=expected_status
    )
    if not claimed:
        raise ValueError("decision is no longer available for execution")
    try:
        d = await db.get_decision(decision_id)
        result = await execute(
            d["action"],
            d["target"],
            d["duration_seconds"],
            justification=f"approved decision #{decision_id}: {d['policy_reason']}",
        )
    except Exception as exc:
        await db.update_decision_status(
            decision_id, "execution_unknown", result=str(exc)
        )
        raise
    await db.update_decision_status(
        decision_id, "executed" if result.get("ok") else "failed", result=str(result)
    )
    return result


async def execute(
    action: str, target: str, duration_seconds: int, justification: str
) -> dict:
    """Execute one approved action. Returns {ok, detail}."""
    if action == "temporary_ip_block":
        if not target:
            return {"ok": False, "detail": "no target IP"}
        try:
            target = str(ipaddress.ip_address(target))
        except ValueError:
            return {"ok": False, "detail": "invalid target IP"}
        seconds = max(1, min(int(duration_seconds or 900), 86400))
        await crowdsec_client.add_decision(
            ip=target,
            duration_seconds=seconds,
            reason=f"edgeguard-ai: {justification}"[:120],
        )
        sys.stderr.write(
            f"[defense] BANNED {target} for {seconds}s — {justification}\n"
        )
        return {
            "ok": True,
            "detail": f"crowdsec decision added: {target} for {seconds}s",
        }

    if action == "remove_ip_block":
        if not target:
            return {"ok": False, "detail": "no target IP"}
        await crowdsec_client.remove_decisions_for_ip(target)
        sys.stderr.write(f"[defense] UNBANNED {target}\n")
        return {"ok": True, "detail": f"crowdsec decisions removed for {target}"}

    return {"ok": False, "detail": f"unsupported action '{action}'"}
