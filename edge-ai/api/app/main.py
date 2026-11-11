"""EdgeGuard orchestrator API (FastAPI).

Phases:
- Phase 4  auto-ingestion: watcher (CrowdSec -> Redis) + worker (Analysis Agent -> PG)
- Phase 5  detection: clusters analyzed incidents into campaigns
- Phase 6  decision: deterministic Policy Engine evaluates AI proposals
- Phase 7  defense: restricted executor (CrowdSec ban/unban), gated by
           DEFENSE_AUTO_EXECUTE (dry-run default) + human approval endpoints

Safety invariants:
- the LLM never talks to enforcement; only the Defense executor does
- protected ranges are NEVER auto-blocked (human approval overrides)
- every proposal/verdict/execution is stored in the decisions table
"""

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.agents import decision, defense
from app.agents.analysis import AnalysisResult, analyze_event
from app.agents import decider, detection
from app.config import settings
from app.integrations import crowdsec_client, db, ollama_client
from app import watcher, worker

EVENT_STREAM = "edge:events"
_background: list[asyncio.Task] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_schema()
    if settings.ingest_enabled:
        _background.append(asyncio.create_task(watcher.run()))
    if settings.analyze_enabled:
        _background.append(asyncio.create_task(worker.run()))
    if settings.detection_enabled:
        _background.append(asyncio.create_task(detection.run()))
    if settings.decide_enabled:
        _background.append(asyncio.create_task(decider.run()))
    yield
    for task in _background:
        task.cancel()


app = FastAPI(title="EdgeGuard Orchestrator", version="0.3.0", lifespan=lifespan)


# ---------------------------------------------------------------- health


@app.get("/health")
async def health() -> dict:
    status = {
        "ollama": "unknown", "crowdsec": "unknown",
        "redis": "unknown", "postgres": "unknown",
    }

    try:
        models = await ollama_client.list_models()
        status["ollama"] = "ok" if settings.ollama_model in models else (
            f"model '{settings.ollama_model}' not pulled (available: {models[:8]})"
        )
    except Exception as exc:  # noqa: BLE001 — health must not raise
        status["ollama"] = f"error: {exc}"

    try:
        await crowdsec_client.list_alerts(limit=1)
        status["crowdsec"] = "ok"
    except Exception as exc:  # noqa: BLE001
        status["crowdsec"] = f"error: {exc}"

    try:
        client = aioredis.from_url(settings.redis_url)
        await client.ping()
        status["redis"] = "ok"
    except Exception as exc:  # noqa: BLE001
        status["redis"] = f"error: {exc}"

    status["postgres"] = "ok" if await db.db_ok() else "error"

    return status


# ------------------------------------------------------------ event bus


class EventIn(BaseModel):
    source: str = Field(description="suricata | crowdsec | waf | manual")
    event_type: str
    severity: str = Field(default="medium")
    source_ip: str = Field(default="")
    destination: str = Field(default="")
    evidence: dict = Field(default_factory=dict)


@app.post("/api/v1/events")
async def ingest_event(event: EventIn) -> dict:
    """Normalize one security event into the pipeline stream (manual/test path)."""
    event_id = f"EVT-{uuid.uuid4().hex[:10]}"
    payload = event.model_dump()
    payload.update({"event_id": event_id, "received_at": int(time.time())})

    client = aioredis.from_url(settings.redis_url)
    await client.xadd(EVENT_STREAM, {"json": json.dumps(payload)})

    return {"event_id": event_id, "queued": True}


# ------------------------------------------------------- analysis (AI)


@app.post("/api/v1/analyze", response_model=AnalysisResult)
async def analyze(event: EventIn) -> AnalysisResult:
    """Run the Analysis Agent over one event. Read-only; proposes, never enforces."""
    try:
        return await analyze_event(event.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"analysis failed: {exc}") from exc


# ------------------------------------------------- incidents (Phase 4)


@app.get("/api/v1/incidents")
async def incidents(limit: int = 50) -> list[dict]:
    """Latest incidents; `analyzed=true` means the Analysis Agent has run."""
    try:
        return await db.list_incidents(limit)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc


@app.get("/api/v1/incidents/{alert_id}")
async def incident_detail(alert_id: str) -> dict:
    try:
        incident = await db.get_incident(alert_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@app.post("/api/v1/incidents/requeue")
async def requeue_unanalyzed(limit: int = 50) -> dict:
    """Re-push unanalyzed incidents into the stream for the worker."""
    try:
        rows = await db.list_incidents(limit)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    client = aioredis.from_url(settings.redis_url)
    count = 0
    for row in rows:
        if not row["analyzed"]:
            await client.xadd(
                EVENT_STREAM, {"json": json.dumps({"event_id": row["alert_id"]})}
            )
            count += 1
    return {"requeued": count}


# -------------------------------------------------------- crowdsec read


@app.get("/api/v1/crowdsec/alerts")
async def crowdsec_alerts(limit: int = 20) -> list[dict]:
    try:
        return await crowdsec_client.list_alerts(limit=min(limit, 100))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"crowdsec: {exc}") from exc


@app.get("/api/v1/crowdsec/decisions")
async def crowdsec_decisions() -> list[dict]:
    try:
        return await crowdsec_client.list_decisions()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"crowdsec: {exc}") from exc


# ------------------------------------------- campaigns (Phase 5)


@app.get("/api/v1/campaigns")
async def campaigns(limit: int = 50) -> list[dict]:
    """Attack campaigns: clustered incidents by source_ip + attack_type."""
    try:
        return await db.list_campaigns(limit)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc


# --------------------------- decisions + approval (Phases 6-7)


@app.get("/api/v1/decisions")
async def decisions_list(limit: int = 50) -> list[dict]:
    """All AI-proposed responses with their Policy Engine verdict + status."""
    try:
        return await db.list_decisions(limit)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc


@app.post("/api/v1/decisions/{decision_id}/approve")
async def decision_approve(decision_id: int) -> dict:
    """Human approval — executes the proposed action via the Defense executor."""
    try:
        d = await db.get_decision(decision_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    if not d:
        raise HTTPException(status_code=404, detail="decision not found")
    if d["status"] in ("executed",):
        raise HTTPException(status_code=409, detail="already executed")
    if d["status"] == "rejected":
        raise HTTPException(status_code=409, detail="decision was rejected")

    result = await defense.execute(
        d["action"], d["target"], d["duration_seconds"],
        justification=f"human-approved decision #{decision_id}",
    )
    status = "executed" if result.get("ok") else "failed"
    await db.update_decision_status(decision_id, status, result=str(result))
    return {"decision_id": decision_id, "status": status, "result": result}


@app.post("/api/v1/decisions/{decision_id}/reject")
async def decision_reject(decision_id: int) -> dict:
    """Human rejection — marks the proposal rejected (nothing executes)."""
    try:
        d = await db.get_decision(decision_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    if not d:
        raise HTTPException(status_code=404, detail="decision not found")
    if d["status"] == "executed":
        raise HTTPException(status_code=409, detail="already executed")
    await db.update_decision_status(decision_id, "rejected", result="rejected by human")
    return {"decision_id": decision_id, "status": "rejected"}


@app.get("/api/v1/policy")
async def policy_view() -> dict:
    """The live deterministic Policy (what the Decision Agent enforces)."""
    try:
        policy = decision.load_policy()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"policy load: {exc}") from exc
    return {
        "mode": "auto_execute" if settings.defense_auto_execute else "dry_run (human approval)",
        "policy": policy,
    }


@app.get("/api/v1/agents/status")
async def agents_status() -> dict:
    return {
        "analysis": {
            "implemented": True,
            "model": settings.ollama_model,
            "mode": "auto-ingestion" if settings.ingest_enabled and settings.analyze_enabled else "manual",
        },
        "detection": {"implemented": True, "mode": "clustering every 60s" if settings.detection_enabled else "off"},
        "decision": {"implemented": True, "mode": "deterministic Policy Engine" if settings.decide_enabled else "off"},
        "defense": {
            "implemented": True,
            "mode": "auto_execute" if settings.defense_auto_execute else "dry_run (human approval required)",
        },
        "learning": {"implemented": False, "note": "Phase 9: pgvector incident memory + feedback loop"},
        "attack": {"implemented": False, "note": "Phase 8: lab-only, isolated VLAN"},
    }
