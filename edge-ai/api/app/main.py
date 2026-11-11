"""EdgeGuard orchestrator API (FastAPI).

Phase 4 (auto-ingestion):
- watcher: polls CrowdSec LAPI -> dedupes -> Redis stream  (background task)
- worker:  consumes stream -> Analysis Agent -> PostgreSQL  (background task)
- /api/v1/incidents: read the accumulated, AI-analyzed incidents

Safety invariants (unchanged):
- the Analysis Agent only reads evidence and proposes; it never enforces
- /api/v1/defense/* stays behind the DEFENSE_ENABLED gate (off by default)
"""

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.agents.analysis import AnalysisResult, analyze_event
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
    yield
    for task in _background:
        task.cancel()


app = FastAPI(title="EdgeGuard Orchestrator", version="0.2.0", lifespan=lifespan)


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


# --------------------------------------------------- defense (DISABLED)


@app.post("/api/v1/defense/decision")
async def defense_decision() -> dict:
    """Intentionally disabled until the deterministic Policy Engine exists.

    Roadmap (feasibility-study.md section 3/9): the Defense executor will only
    ever accept 4 fixed verbs validated by the Policy Engine. The LLM never
    generates shell commands and never talks to enforcement directly.
    """
    if not settings.defense_enabled:
        raise HTTPException(
            status_code=503,
            detail=(
                "Defense disabled by safety gate (DEFENSE_ENABLED=false). "
                "Requires: Policy Engine (Phase 6) + human approval workflow (Phase 7)."
            ),
        )
    # Even with the gate open, no executor exists yet (Phase 7).
    raise HTTPException(status_code=501, detail="Defense executor not implemented yet")


@app.get("/api/v1/agents/status")
async def agents_status() -> dict:
    return {
        "analysis": {
            "implemented": True,
            "model": settings.ollama_model,
            "mode": "auto-ingestion" if settings.ingest_enabled and settings.analyze_enabled else "manual",
        },
        "detection": {"implemented": False, "note": "Phase 5: alert clustering/dedup over Redis stream"},
        "decision": {"implemented": False, "note": "Phase 6: Policy Engine gate"},
        "defense": {"implemented": False, "note": "Phase 7: restricted executor, DEFENSE_ENABLED=false"},
        "learning": {"implemented": False, "note": "Phase 9: pgvector incident memory + feedback loop"},
        "attack": {"implemented": False, "note": "Phase 8: lab-only, isolated VLAN"},
    }
