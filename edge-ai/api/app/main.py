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
import secrets
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import httpx
import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import telemetry, traffic, triage, watcher, worker
from app.agents import attack, decider, decision, defense, detection, learning
from app.agents.analysis import AnalysisResult, analyze_event
from app.config import settings
from app.integrations import crowdsec_client, dashboard_db, db, ollama_client

EVENT_STREAM = "edge:events"
_background: list[asyncio.Task] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_schema()
    await dashboard_db.init_schema()
    if settings.request_history_enabled:
        _background.append(asyncio.create_task(traffic.run()))
    if settings.telemetry_enabled:
        _background.append(asyncio.create_task(telemetry.run()))
    if settings.ingest_enabled:
        _background.append(asyncio.create_task(watcher.run()))
    if settings.analyze_enabled:
        _background.append(asyncio.create_task(worker.run()))
    if settings.detection_enabled:
        _background.append(asyncio.create_task(detection.run()))
    if settings.decide_enabled:
        _background.append(asyncio.create_task(decider.run()))
    if settings.learning_enabled:
        _background.append(asyncio.create_task(learning.run()))
    yield
    for task in _background:
        task.cancel()
    await asyncio.gather(*_background, return_exceptions=True)
    _background.clear()


app = FastAPI(title="EdgeGuard Orchestrator", version="0.3.0", lifespan=lifespan)
app.include_router(triage.router)

Collection = Literal[
    "requests", "incidents", "campaigns", "decisions", "approvals", "attacks"
]


@app.get("/api/v1/dashboard/summary")
async def dashboard_summary():
    return await dashboard_db.summary()


@app.get("/api/v1/dashboard/data/{collection}")
async def dashboard_page(
    collection: Collection,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    q: str = Query("", max_length=200),
    source: str = Query("", max_length=40),
    severity: str = Query("", max_length=20),
    status: str = Query("", max_length=40),
    snapshot: int | None = Query(None, ge=0),
):
    try:
        return await dashboard_db.page(
            collection, page, page_size, q, source, severity, status, snapshot
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/dashboard/data/{collection}/{item_id}")
async def dashboard_item(collection: Collection, item_id: int):
    result = await dashboard_db.detail(collection, item_id)
    if result is None:
        raise HTTPException(
            status_code=404, detail="record not found or no longer retained"
        )
    return result


@app.get("/api/v1/visibility")
async def visibility() -> dict:
    """Actual sensor heartbeat and source counts, never inferred from artwork."""
    return await telemetry.visibility()


_STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=_STATIC), name="static")


async def require_operation_key(
    x_operation_key: str | None = Header(
        default=None, alias="X-Operation-Key"
    ),
) -> None:
    """Server-side gate for state-changing endpoints.

    These endpoints are exposed on the public funnel (/AIEdgeGuard/*), so a
    shared operation key is required. The browser prompts for the key and
    sends it via the X-Operation-Key header; the comparison happens here
    (client-side popups are UX only, never security).

    Gate behavior: OPERATION_KEY set in edge-ai/.env = enforced.
    Unset = ungated (dev/tests only — production MUST set it).
    """
    if not settings.operation_key:
        return  # dev mode: gate disabled when no key configured
    if not x_operation_key or not secrets.compare_digest(
        x_operation_key, settings.operation_key
    ):
        raise HTTPException(
            status_code=403, detail="invalid or missing operation key"
        )


@app.get("/", include_in_schema=False)
async def home(request: Request):
    """Open the preview at its base URL, retaining a validated gateway prefix."""
    prefix = request.headers.get("x-forwarded-prefix", "").rstrip("/")
    if prefix not in ("/AIEdgeGuard", "/aiedge"):
        prefix = ""
    return RedirectResponse(f"{prefix}/mission", status_code=307)


@app.get("/dashboard", include_in_schema=False)
async def dashboard():
    """SOC dashboard (single-page, auto-refresh, served by this API)."""
    return FileResponse(_STATIC / "dashboard.html")


@app.get("/DashBoard", include_in_schema=False)
async def dashboard_alias():
    """Alias for funnel access: /AIEdgeGuard/DashBoard (strip-prefix via Traefik)."""
    return FileResponse(_STATIC / "dashboard.html")


@app.get("/mission", include_in_schema=False)
async def mission():
    """Mission Control view — cinematic real-time defense visualization."""
    return FileResponse(_STATIC / "mission.html")


@app.get("/Mission", include_in_schema=False)
async def mission_alias():
    """Alias for funnel access: /AIEdgeGuard/Mission."""
    return FileResponse(_STATIC / "mission.html")


# ---------------------------------------------------------------- health


@app.get("/health")
async def health() -> dict:
    status = {
        "ollama": "unknown",
        "crowdsec": "unknown",
        "redis": "unknown",
        "postgres": "unknown",
    }

    try:
        models = await ollama_client.list_models()
        status["ollama"] = (
            "ok"
            if settings.ollama_model in models
            else (
                f"model '{settings.ollama_model}' not pulled (available: {models[:8]})"
            )
        )
    except Exception as exc:  # noqa: BLE001 — health must not raise
        status["ollama"] = f"error: {exc}"

    try:
        await crowdsec_client.list_alerts(limit=1)
        status["crowdsec"] = "ok"
    except Exception as exc:  # noqa: BLE001
        status["crowdsec"] = f"error: {exc}"

    try:
        async with aioredis.from_url(settings.redis_url) as client:
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
async def ingest_event(
        event: EventIn, _op: None = Depends(require_operation_key)
    ) -> dict:
    """Normalize one security event into the pipeline (manual/test path).

    The event is persisted as an incident row BEFORE it is queued: the worker
    loads that row for evidence and skips stream entries that have none, so a
    stream-only event was previously acknowledged and silently dropped.
    """
    event_id = f"EVT-{uuid.uuid4().hex[:10]}"
    payload = event.model_dump()
    payload.update({"event_id": event_id, "received_at": int(time.time())})

    incident = {
        "alert_id": event_id,
        "source": event.source,
        "kind": event.event_type,
        "severity": event.severity,
        "reason": str(
            event.evidence.get("reason") or f"{event.source}: {event.event_type}"
        ),
        "source_ip": event.source_ip,
        "event": payload,
    }
    try:
        await db.insert_incident(incident)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc

    try:
        async with aioredis.from_url(settings.redis_url) as client:
            await client.xadd(EVENT_STREAM, {"json": json.dumps(payload)})
        await db.mark_queued(event_id)
    except Exception as exc:
        # The durable outbox lets the watcher publish this event after recovery.
        raise HTTPException(
            status_code=503,
            detail={
                "event_id": event_id,
                "queued": False,
                "message": "event saved; queue unavailable, awaiting recovery",
            },
        ) from exc

    return {"event_id": event_id, "queued": True}


# ------------------------------------------------------- analysis (AI)


@app.post("/api/v1/analyze", response_model=AnalysisResult)
async def analyze(event: EventIn) -> AnalysisResult:
    """Run the Analysis Agent over one event. Read-only; proposes, never enforces."""
    try:
        return await analyze_event(event.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"analysis failed: {exc}") from exc


# ------------------------------------------------- incidents (Phase 4)


@app.get("/api/v1/incidents")
async def incidents(limit: int = 50) -> list[dict]:
    """Latest incidents; `analyzed=true` means the Analysis Agent has run."""
    try:
        return await db.list_incidents(limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc


@app.get("/api/v1/incidents/{alert_id}")
async def incident_detail(alert_id: str) -> dict:
    try:
        incident = await db.get_incident(alert_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    if incident is None:
        raise HTTPException(status_code=404, detail="incident not found")
    return incident


@app.post("/api/v1/incidents/requeue")
async def requeue_unanalyzed(
        limit: int = 50, _op: None = Depends(require_operation_key)
    ) -> dict:
    """Re-push unanalyzed incidents into the stream for the worker."""
    try:
        rows = await db.list_incidents(limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    count = 0
    async with aioredis.from_url(settings.redis_url) as client:
        for row in rows:
            if not row["analyzed"]:
                await client.xadd(
                    EVENT_STREAM, {"json": json.dumps({"event_id": row["alert_id"]})}
                )
                await db.mark_queued(row["alert_id"])
                count += 1
    return {"requeued": count}


# -------------------------------------------------------- crowdsec read


@app.get("/api/v1/crowdsec/alerts")
async def crowdsec_alerts(limit: int = 20) -> list[dict]:
    try:
        return await crowdsec_client.list_alerts(limit=min(limit, 100))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"crowdsec: {exc}") from exc


@app.get("/api/v1/crowdsec/decisions")
async def crowdsec_decisions() -> list[dict]:
    try:
        return await crowdsec_client.list_decisions()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"crowdsec: {exc}") from exc


# ------------------------------------------- campaigns (Phase 5)


@app.get("/api/v1/campaigns")
async def campaigns(limit: int = 50) -> list[dict]:
    """Attack campaigns: clustered incidents by source_ip + attack_type."""
    try:
        return await db.list_campaigns(limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc


# --------------------------- decisions + approval (Phases 6-7)


@app.get("/api/v1/decisions")
async def decisions_list(limit: int = 50) -> list[dict]:
    """All AI-proposed responses with their Policy Engine verdict + status."""
    try:
        return await db.list_decisions(limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc


@app.post("/api/v1/decisions/{decision_id}/approve")
async def decision_approve(
        decision_id: int, _op: None = Depends(require_operation_key)
    ) -> dict:
    """Human approval — executes the proposed action via the Defense executor."""
    try:
        d = await db.get_decision(decision_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    if not d:
        raise HTTPException(status_code=404, detail="decision not found")
    if d["status"] != "pending_approval":
        raise HTTPException(status_code=409, detail=f"decision status is {d['status']}")
    try:
        result = await defense.execute_stored(decision_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="execution could not be confirmed; check CrowdSec before retrying",
        ) from exc
    status = "executed" if result.get("ok") else "failed"
    return {"decision_id": decision_id, "status": status, "result": result}


@app.post("/api/v1/decisions/{decision_id}/reject")
async def decision_reject(
        decision_id: int, _op: None = Depends(require_operation_key)
    ) -> dict:
    """Human rejection — marks the proposal rejected (nothing executes)."""
    try:
        d = await db.get_decision(decision_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    if not d:
        raise HTTPException(status_code=404, detail="decision not found")
    changed = await db.update_decision_status(
        decision_id,
        "rejected",
        result="rejected by human",
        expected_status="pending_approval",
    )
    if not changed:
        raise HTTPException(
            status_code=409, detail="decision is no longer pending approval"
        )
    return {"decision_id": decision_id, "status": "rejected"}


@app.get("/api/v1/policy")
async def policy_view() -> dict:
    """The live deterministic Policy (what the Decision Agent enforces)."""
    try:
        policy = decision.load_policy()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"policy load: {exc}") from exc
    return {
        "mode": "auto_execute"
        if settings.defense_auto_execute
        else "dry_run (human approval)",
        "policy": policy,
    }


# ------------------------------------------- learning (Phase 9)


@app.get("/api/v1/learning/stats")
async def learning_stats() -> dict:
    try:
        stats = await db.embedding_stats()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    return {
        **stats,
        "model": settings.embedding_model,
        "dim": settings.embedding_dim,
        "enabled": settings.learning_enabled,
    }


class SimilarIn(BaseModel):
    text: str
    k: int = Field(default=3)


@app.post("/api/v1/learning/similar")
async def learning_similar(body: SimilarIn) -> list[dict]:
    """Find past incidents similar to free text (RAG lookup)."""
    try:
        return await learning.similar_context(body.text, k=body.k)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"embedding: {exc}") from exc


# ------------------------------------------- packets (Phase 10 mission view)


def _tail_access_log(lines: int) -> list[dict]:
    """Read the last N JSON lines of the gateway traefik access log."""
    path = "/var/log/traefik/access.log"
    out: list[dict] = []
    try:
        with open(path, "rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 400_000))
            chunk = fh.read().decode("utf-8", errors="replace")
        for line in chunk.splitlines()[-lines:]:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            out.append(
                {
                    "ts": d.get("StartUTC", "")[:19].replace("T", " "),
                    "method": d.get("RequestMethod", ""),
                    "path": str(d.get("RequestPath", ""))[:90],
                    "host": d.get("RequestHost", ""),
                    "status": d.get("DownstreamStatus", 0),
                    "source_ip": d.get("ClientHost", ""),
                    "router": str(d.get("RouterName", "")).replace("@docker", ""),
                    "ms": d.get("Duration", 0) // 1_000_000,
                }
            )
    except FileNotFoundError:
        return [{"error": "access log not mounted (gateway_traefik_logs volume)"}]
    except Exception as exc:  # noqa: BLE001
        return [{"error": str(exc)[:120]}]
    return out


@app.get("/api/v1/packets")
async def packets(limit: int = 80) -> dict:
    """Latest raw requests hitting the gateway (live packet feed)."""
    lines = min(max(limit, 1), 300)
    rows = await asyncio.to_thread(_tail_access_log, lines)
    rows.reverse()  # newest first
    blocked = sum(1 for r in rows if str(r.get("status")) == "403")
    return {"count": len(rows), "blocked_403": blocked, "packets": rows}


# ------------------------------------------- attack lab (Phase 8)


class AttackRun(BaseModel):
    target: str = Field(default="juicelab.lab.local")


@app.get("/api/v1/attacks/catalog")
async def attack_catalog() -> dict:
    """Techniques available in the attacker container (for the UI)."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{settings.attacker_url}/catalog")
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"attacker: {exc}") from exc


@app.post("/api/v1/attacks/run")
async def attack_run(
        run: AttackRun, _op: None = Depends(require_operation_key)
    ) -> dict:
    """Run one AI-planned attack campaign against the LAB victim.

    Safety: ATTACK_ENABLED kill switch + target allowlist + deterministic
    payload catalog (the LLM only selects techniques, never crafts payloads).
    """
    try:
        return await attack.run_attack(run.target)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"attack failed: {exc}") from exc


@app.get("/api/v1/attacks")
async def attacks_list(limit: int = 20) -> list[dict]:
    try:
        return await attack.list_attacks(limit)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc


@app.get("/api/v1/attacks/{attack_id}")
async def attack_detail(attack_id: int) -> dict:
    try:
        run = await attack.get_attack(attack_id)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"db: {exc}") from exc
    if not run:
        raise HTTPException(status_code=404, detail="attack not found")
    return run


@app.get("/api/v1/agents/status")
async def agents_status() -> dict:
    return {
        "analysis": {
            "implemented": True,
            "model": settings.ollama_model,
            "mode": "auto-ingestion"
            if settings.ingest_enabled and settings.analyze_enabled
            else "manual",
        },
        "detection": {
            "implemented": True,
            "mode": "clustering every 60s" if settings.detection_enabled else "off",
        },
        "decision": {
            "implemented": True,
            "mode": "deterministic Policy Engine" if settings.decide_enabled else "off",
        },
        "defense": {
            "implemented": True,
            "mode": "auto_execute"
            if settings.defense_auto_execute
            else "dry_run (human approval required)",
        },
        "attack": {
            "implemented": True,
            "mode": "lab"
            if settings.attack_enabled
            else "kill switch OFF (ATTACK_ENABLED=false)",
            "targets": settings.attack_target_allowlist,
        },
        "learning": {
            "implemented": True,
            "mode": f"pgvector ({settings.embedding_model}, {settings.embedding_dim}d)"
            if settings.learning_enabled
            else "off",
        },
    }
