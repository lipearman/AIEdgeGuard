"""Decision loop — converts analyzed incidents into policy-gated decisions.

Flow per newly-analyzed incident:
  Analysis Agent proposal (recommended_action)
    -> decision.evaluate()  (deterministic Policy Engine)
    -> INSERT decisions row:
         verdict=approve  + defense_auto_execute -> status=auto_execute -> executed
         verdict=approve  + dry-run mode         -> status=pending_approval
         verdict=pending_approval                -> status=pending_approval
         verdict=deny                            -> status=rejected
"""

import asyncio
import sys

from app.agents import decision, defense
from app.config import settings
from app.integrations import db


async def decide_pending_once() -> int:
    pending = await db.list_analyzed_without_decision()
    decided = 0
    for inc in pending:
        analysis = inc["analysis"] or {}
        proposal = analysis.get("recommended_action") or {}
        d = decision.evaluate(
            proposal=proposal,
            attack_type=analysis.get("attack_type") or "",
            confidence=float(analysis.get("confidence") or 0),
            severity=inc["severity"] or "medium",
            source_ip=inc["source_ip"] or "",
        )
        if d.verdict == "approve" and settings.defense_auto_execute:
            status = "auto_execute"
        elif d.verdict == "deny":
            status = "rejected"
        else:
            status = "pending_approval"

        decision_id = await db.create_decision(
            incident_alert_id=inc["alert_id"],
            action=d.action,
            target=d.target,
            duration_seconds=d.duration_seconds,
            confidence=float(analysis.get("confidence") or 0),
            severity=inc["severity"] or "medium",
            policy_verdict=d.verdict,
            policy_reason=d.reason,
            policy_checks=d.checks,
            status=status,
        )
        decided += 1
        sys.stderr.write(
            f"[decider] {inc['alert_id']} -> decision #{decision_id} "
            f"({d.verdict}/{status}): {d.action} {d.target} — {d.reason}\n"
        )

        # L1 auto-execution ONLY when explicitly enabled AND policy approved
        if status == "auto_execute":
            result = await defense.execute(
                d.action, d.target, d.duration_seconds, justification=d.reason
            )
            await db.update_decision_status(
                decision_id, "executed", result=str(result)
            )
            sys.stderr.write(f"[decider] decision #{decision_id} AUTO-EXECUTED: {result}\n")
    return decided


async def run() -> None:
    interval = 30
    sys.stderr.write("[decider] started, evaluating every 30s\n")
    while True:
        try:
            await decide_pending_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[decider] failed: {exc}\n")
        await asyncio.sleep(interval)
