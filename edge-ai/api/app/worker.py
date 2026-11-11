"""Worker — consumes the `edge:events` Redis stream and runs the Analysis Agent.

- consumer group `workers` (created with id 0 so backlog is replayed)
- XACK only after the analysis is stored (crash-safe; replay skips analyzed)
- serial processing on purpose: the 9B/4B local model is the bottleneck and
  analysis must never run concurrent per event (VRAM + coherence)
"""

import asyncio
import json
import sys

import redis.asyncio as aioredis

from app.agents.analysis import analyze_event
from app.config import settings
from app.integrations import db

STREAM = "edge:events"
GROUP = "workers"
CONSUMER = "edge-ai-worker"


async def _ensure_group(r) -> None:
    try:
        await r.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except Exception as exc:  # BUSYGROUP = already exists — fine
        if "BUSYGROUP" not in str(exc):
            raise


async def _drain_pending(r) -> int:
    """Re-claim pending stream entries from previous runs (crash recovery).

    XREADGROUP '>' never returns entries already delivered to a consumer;
    XAUTOCLAIM with min_idle_time=0 takes them back so the backlog is processed.
    """
    claimed = 0
    cursor = "0-0"
    while True:
        resp = await r.xautoclaim(
            STREAM, GROUP, CONSUMER, min_idle_time=0, start_id=cursor, count=10
        )
        if not resp or len(resp) < 2:
            break
        cursor, messages = resp[0], resp[1]
        if not messages:
            break
        for msg_id, fields in messages:
            try:
                await _process(r, msg_id, fields)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write(f"[worker] drain {msg_id} failed: {exc}\n")
                await r.xack(STREAM, GROUP, msg_id)
            claimed += 1
        if len(messages) < 10:
            break
    return claimed


async def run() -> None:
    # socket_timeout=None so BLOCK reads may wait server-side without raising;
    # decode_responses=True so stream fields are str (not bytes) — fields.get("json")
    # silently returned None without it and every event was acked as "empty"
    r = aioredis.from_url(settings.redis_url, socket_timeout=None, decode_responses=True)
    await _ensure_group(r)
    pending = await _drain_pending(r)
    if pending:
        sys.stderr.write(f"[worker] drained {pending} pending events from previous run\n")
    sys.stderr.write("[worker] started, analyzing stream events\n")
    while True:
        try:
            resp = await r.xreadgroup(
                GROUP, CONSUMER, {STREAM: ">"}, count=10, block=5000
            )
            for _stream, messages in resp or []:
                for msg_id, fields in messages:
                    try:
                        await _process(r, msg_id, fields)
                    except Exception as exc:  # noqa: BLE001 — one bad event must not kill the worker
                        sys.stderr.write(f"[worker] event {msg_id} failed: {exc}\n")
                        await r.xack(STREAM, GROUP, msg_id)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — read retry loop (incl. block timeouts)
            sys.stderr.write(f"[worker] read failed: {exc}\n")
            await asyncio.sleep(5)


def _compact_evidence(incident: dict) -> dict:
    """Build a small evidence dict for the LLM from the raw alert.

    WAF alerts carry full request dumps (events[]) that can be huge; feeding
    everything into the prompt wastes context and stalls small local models.
    """
    raw = incident.get("event") or {}
    events = raw.get("events") or []
    return {
        "alert_message": incident.get("reason") or raw.get("message"),
        "scenario": raw.get("scenario"),
        "kind": incident.get("kind"),
        "source_ip": incident.get("source_ip"),
        "created_at": str(raw.get("created_at") or incident.get("created_at")),
        "meta": (raw.get("meta") or [])[:12],
        "events_sample": [
            {
                k: ev.get(k)
                for k in ("timestamp", "meta", "message")
                if ev.get(k) is not None
            }
            for ev in events[-3:]
        ],
        "decisions": [
            {k: d.get(k) for k in ("type", "value", "duration", "reason")}
            for d in (raw.get("decisions") or [])[:5]
        ],
    }


def _fallback_analysis(reason: str, severity: str) -> dict:
    """Deterministic classification from the CRS/vpatch reason text.

    EdgeGuard principle: the AI assists, the deterministic core decides. When
    the LLM returns a degenerate (empty) analysis, this fallback keeps the
    incident usable — flagged for human review.
    """
    r = (reason or "").lower()
    if "sql_injection" in r or "sqli" in r:
        at, mitre = "SQL Injection Attempt", "T1190"
    elif "xss" in r:
        at, mitre = "Cross-Site Scripting Attempt", "T1059.007"
    elif "lfi" in r or "traversal" in r:
        at, mitre = "Path Traversal / Local File Inclusion", "T1083"
    elif "rce" in r:
        at, mitre = "Remote Code Execution Attempt", "T1059"
    else:
        at, mitre = "Web Attack (anomaly scoring)", "T1190"
    return {
        "attack_type": at,
        "severity": severity or "medium",
        "confidence": 0.6,
        "mitre_id": mitre,
        "reasoning": f"Deterministic fallback classification from rule reason: {reason[:120]}",
        "prompt_injection_suspected": False,
        "needs_human_review": True,
        "recommended_action": {
            "action_type": "none", "duration_seconds": 0, "target": "",
        },
    }


async def _process(r, msg_id, fields) -> None:
    payload = json.loads(fields.get("json", "{}"))
    alert_id = payload.get("event_id", "")
    sys.stderr.write(f"[worker] processing {alert_id or msg_id}\n")
    if not alert_id:
        await r.xack(STREAM, GROUP, msg_id)
        return

    incident = await db.get_incident(alert_id)
    if incident is None:
        sys.stderr.write(f"[worker] {alert_id}: no incident row (manual event) — skip\n")
        # manual/test events (not alert-backed) — nothing to analyze here
        await r.xack(STREAM, GROUP, msg_id)
        return
    if incident.get("analysis"):
        sys.stderr.write(f"[worker] {alert_id}: already analyzed — skip\n")
        await r.xack(STREAM, GROUP, msg_id)
        return

    event = {
        "source": incident.get("source"),
        "event_type": incident.get("kind"),
        "severity": incident.get("severity"),
        "source_ip": incident.get("source_ip"),
        "destination": "(from alert context)",
        "evidence": _compact_evidence(incident),
    }
    force = False
    try:
        result = await asyncio.wait_for(analyze_event(event), timeout=120.0)
        analysis = result.model_dump()
        summary = f"{result.attack_type} ({result.severity}, conf {result.confidence})"
        sys.stderr.write(f"[worker] {alert_id}: llm done -> {summary}\n")
    except asyncio.TimeoutError:
        analysis = {
            "attack_type": "analysis_timeout",
            "severity": incident.get("severity") or "medium",
            "confidence": 0.0,
            "reasoning": "Analysis Agent timed out; requeue manually or increase timeout",
            "needs_human_review": True,
            "recommended_action": {"action_type": "none", "duration_seconds": 0, "target": ""},
        }
        summary = "TIMEOUT"
        sys.stderr.write(f"[worker] {alert_id}: llm TIMEOUT\n")

    if not analysis.get("attack_type"):
        # LLM returned a degenerate (empty) analysis — deterministic fallback
        analysis = _fallback_analysis(
            incident.get("reason") or "", incident.get("severity") or "medium"
        )
        force = True
        summary = f"[fallback] {summary}"

    stored = await db.set_analysis(alert_id, analysis, force=force)
    await r.xack(STREAM, GROUP, msg_id)
    sys.stderr.write(f"[worker] {alert_id}: stored={stored} summary={summary}\n")
