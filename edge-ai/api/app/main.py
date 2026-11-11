"""EdgeGuard orchestrator API (FastAPI).

Pilot scope:
- health check against Ollama / CrowdSec / Redis
- event ingestion into a Redis stream (event bus)
- Analysis Agent endpoint (single model, JSON-validated)
- read-only CrowdSec visibility
- defense endpoint that is DISABLED by default (safety gate)
"""

import json
import time
import uuid

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.agents.analysis import AnalysisResult, analyze_event
from app.agents.stubs import defense_agent, detection_agent, learning_agent
from app.config import settings
from app.integrations import crowdsec_client, ollama_client

app = FastAPI(title="EdgeGuard Orchestrator", version="0.1.0")

EVENT_STREAM = "edge:events"


# ---------------------------------------------------------------- health


@app.get("/health")
async def health() -> dict:
    status = {"ollama": "unknown", "crowdsec": "unknown", "redis": "unknown"}

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
    """Normalize one security event into the pipeline stream."""
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
        "analysis": {"implemented": True, "model": settings.ollama_model},
        "detection": {"implemented": False, "note": detection_agent.reason},
        "decision": {"implemented": False, "note": "Phase 6: Policy Engine gate"},
        "defense": {"implemented": False, "note": defense_agent.reason},
        "learning": {"implemented": False, "note": learning_agent.reason},
        "attack": {"implemented": False, "note": "Phase 8: lab-only, isolated VLAN"},
    }
