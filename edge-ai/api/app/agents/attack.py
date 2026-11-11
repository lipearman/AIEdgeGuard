"""Attack Simulator Agent — Phase 8.

Authorized lab-only module: plans and executes attack campaigns against the
isolated Attack Lab victim (OWASP Juice Shop) to MEASURE the defensive chain.

Safety rules (enforced here, non-negotiable):
1. settings.attack_enabled must be true (kill switch, default OFF)
2. target host must be in settings.attack_target_allowlist (never real apps)
3. the LLM only SELECTS techniques from the attacker container's FIXED catalog
   — it never generates raw payloads (deterministic payloads, AI-driven choice)
4. every run + result is stored in PostgreSQL for the report
"""

import asyncio
import json
import sys
import time

import httpx

from app.config import settings
from app.integrations import crowdsec_client, db, ollama_client

PLAN_SYSTEM = """You are the Attack Simulator Agent of EdgeGuard, running an
AUTHORIZED security test against an isolated lab victim (OWASP Juice Shop).
Purpose: measure whether the defensive chain (WAF/CRS/CrowdSec) detects attacks.

HARD RULES:
1. Select ONLY technique ids from the provided catalog. Never invent ids,
   payloads, or targets. You choose WHAT to test and explain WHY.
2. Prefer a mix that covers different MITRE tactics (exploit, probe, brute force).
3. Respond with a single JSON object: {"selected": ["id1", "id2", ...],
   "rationale": "2-3 sentences"}. No other fields."""


async def _plan_with_llm(catalog_ids: list[str]) -> dict:
    user = (
        "Select 3-6 technique ids from this catalog to best test the defensive "
        "chain of the lab victim. Respond as JSON {\"selected\": [...], "
        "\"rationale\": \"...\"}.\n\nCATALOG:\n" + "\n".join(catalog_ids)
    )[:2000]
    try:
        raw = await asyncio.wait_for(
            ollama_client.chat_json(PLAN_SYSTEM, user), timeout=90.0
        )
        selected = [t for t in (raw.get("selected") or []) if t]
        return {"selected": selected, "rationale": str(raw.get("rationale") or "")}
    except Exception as exc:  # noqa: BLE001 — LLM failure must not abort the run
        sys.stderr.write(f"[attack] planner failed ({exc}) — running full catalog\n")
        return {"selected": catalog_ids, "rationale": "fallback: full catalog (LLM planner unavailable)"}


async def run_attack(target_host: str) -> dict:
    """Plan, execute, and score one attack campaign. Returns the stored run."""
    # --- safety gate ---
    if not settings.attack_enabled:
        raise PermissionError("attack kill switch is OFF (ATTACK_ENABLED=false)")
    allowed = [h.strip() for h in settings.attack_target_allowlist.split(",") if h.strip()]
    if target_host not in allowed:
        raise PermissionError(
            f"target '{target_host}' not in attack allowlist {allowed}"
        )

    async with httpx.AsyncClient(timeout=15) as client:
        cat = (await client.get(f"{settings.attacker_url}/catalog")).json()
        catalog_ids = cat.get("techniques") or []
        if not catalog_ids:
            raise RuntimeError("attacker catalog empty")

        plan = await _plan_with_llm(catalog_ids)
        # final safety: intersect LLM selection with the real catalog
        selected = [t for t in plan["selected"] if t in catalog_ids] or catalog_ids

        run_started = datetime_utc()
        resp = await client.post(
            f"{settings.attacker_url}/execute",
            json={"techniques": selected, "target_host": target_host,
                  "delay_ms": 150},
        )
        resp.raise_for_status()
        results = resp.json()
        attacker_ip = results.get("attacker_ip", "")

        # let CrowdSec finish writing alerts for the campaign
        await asyncio.sleep(8)
        alerts = await crowdsec_client.list_alerts(limit=100)
        new_alerts = [
            a for a in alerts
            if str((a.get("created_at") or "")) >= run_started
            and str(((a.get("source") or {}).get("ip") or "")) == attacker_ip
        ]

        detected = sum(1 for t in results.get("techniques", []) if t.get("detected"))
        total = len(results.get("techniques", []))
        run = {
            "target_host": target_host,
            "attacker_ip": attacker_ip,
            "plan": {"selected": selected, "rationale": plan["rationale"]},
            "results": results,
            "techniques_total": total,
            "techniques_detected": detected,
            "new_alerts": len(new_alerts),
        }
        attack_id = await db.insert_attack(run)
        sys.stderr.write(
            f"[attack] run #{attack_id}: {detected}/{total} techniques detected by WAF, "
            f"{len(new_alerts)} crowdsec alerts\n"
        )
        run.update({"id": attack_id, "run_started": run_started})
        return run


def datetime_utc() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


async def list_attacks(limit: int = 20):
    return await db.list_attacks(limit)


async def get_attack(attack_id: int):
    return await db.get_attack(attack_id)
