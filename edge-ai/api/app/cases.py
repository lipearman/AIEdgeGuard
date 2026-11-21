"""Immutable, bounded one-hop evidence graphs. Associations never imply causation."""

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from psycopg.errors import SerializationFailure, UniqueViolation
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field

from app import assets, investigation
from app.config import settings
from app.evaluation import operation_key
from app.event_time import extract
from app.integrations import db

router = APIRouter(prefix="/api/v1/cases", tags=["Candidate evidence graphs"])
VERSION = "candidate-one-hop-v1-20261121"
CODE_HASH = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
SCOPE = "One-hop candidate associations around an anchor, not a verified attack chain. Source clocks/identities and current asset declarations are unverified. No enforcement or model judgement."
log = logging.getLogger(__name__)
SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_cases (
 id uuid PRIMARY KEY, input_hash text NOT NULL, specification jsonb NOT NULL,
 graph jsonb NOT NULL, content_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS evidence_cases_anchor ON evidence_cases((specification->>'anchor_kind'),(specification->>'anchor_id'),created_at);
CREATE OR REPLACE FUNCTION reject_case_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Evidence case snapshots are append-only'; END; $$;
DROP TRIGGER IF EXISTS immutable_evidence_cases ON evidence_cases;
CREATE TRIGGER immutable_evidence_cases BEFORE UPDATE OR DELETE ON evidence_cases
 FOR EACH ROW EXECUTE FUNCTION reject_case_mutation();
"""


class CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    anchor_kind: Literal["requests", "incidents"]
    anchor_id: int = Field(ge=1)
    minutes: int = Field(default=15, ge=1, le=60)
    declared_by: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000, pattern=r"^[^\x00]*$")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


async def index_batch():
    """Backfill derived metadata only, bounded and concurrent-worker safe."""
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id,source,event,created_at FROM incidents WHERE event_time_state='not_indexed' ORDER BY id LIMIT 500 FOR UPDATE SKIP LOCKED"
        )
        rows = await cur.fetchall()
        for row in rows:
            observed, field, state = extract(
                row["source"], row["event"], row["created_at"]
            )
            await cur.execute(
                "UPDATE incidents SET event_observed_at=%s,event_time_field=%s,event_time_state=%s WHERE id=%s",
                (observed, field, state, row["id"]),
            )
        await conn.commit()
    return len(rows)


async def run():
    while True:
        try:
            count = await index_batch()
        except asyncio.CancelledError:
            raise
        except Exception:
            count = 0
            log.exception("Event-time indexing failed; will retry")
        await asyncio.sleep(1 if count == 500 else 15)


def raw_event(row):
    wrapper = row.get("event") or {}
    raw = wrapper.get("event", wrapper) if isinstance(wrapper, dict) else {}
    return raw if isinstance(raw, dict) else {}


def event_node(kind, row):
    """Retain minimal source facts/hashes; no raw body, query or AI inference."""
    keys = investigation.identity(kind, row)
    raw = raw_event(row) if kind == "incidents" else row.get("raw") or {}
    http = raw.get("http")
    http = http if isinstance(http, dict) else {}
    recorded_id = (
        raw.get("request_X-Request-ID")
        or raw.get("request_id")
        or http.get("request_id")
    )
    if not isinstance(recorded_id, str) or len(recorded_id) > 200:
        keys["request_id"] = ""
    endpoints = set()
    for value in [keys["endpoint_ip"], raw.get("src_ip"), raw.get("dest_ip")]:
        ip = investigation.useful_ip(str(value or ""))
        if ip:
            endpoints.add(ip)
    observed = (
        row["observed_at"] if kind == "requests" else row.get("event_observed_at")
    )
    ingested = row["collected_at"] if kind == "requests" else row["created_at"]
    observed = observed.astimezone(UTC) if observed else None
    ingested = ingested.astimezone(UTC)
    effective = observed or ingested
    delay = (ingested - observed).total_seconds() if observed else None
    return {
        "id": f"{kind}:{row['id']}",
        "kind": kind,
        "record_id": row["id"],
        "source": "http_gateway" if kind == "requests" else row["source"],
        "title": f"{row.get('method', 'HTTP')} {row.get('host', '')}"
        if kind == "requests"
        else str(row.get("reason") or row.get("kind") or "Incident")[:300],
        "source_evidence_sha256": row.get("fingerprint") or digest(row.get("event")),
        "observed_at": observed.isoformat() if observed else None,
        "ingested_at": ingested.isoformat(),
        "effective_at": effective.isoformat(),
        "time_basis": "source_reported" if observed else "ingestion_fallback",
        "time_field": "StartUTC" if kind == "requests" else row.get("event_time_field"),
        "time_state": "source_reported"
        if kind == "requests"
        else row.get("event_time_state"),
        "arrival_delay_seconds": round(delay, 3) if delay is not None else None,
        "late_arrival": delay > 300 if delay is not None else None,
        "clock_warning": bool(delay is not None and delay < 0),
        "identity": {**keys, "endpoint_ips": sorted(endpoints)},
        "severity": row.get("severity"),
        "alert_id": row.get("alert_id"),
    }


def associations(anchor, other, bindings):
    a, b = anchor["identity"], other["identity"]
    matches = []
    if a["request_id"] and a["request_id"] == b["request_id"]:
        matches.append(
            (
                "same_recorded_request_id",
                "low",
                "Client-supplied request IDs may be reused or spoofed",
            )
        )
    if a["agent_id"] and a["agent_id"] == b["agent_id"]:
        matches.append(
            (
                "same_wazuh_agent_id",
                "medium",
                "Same sensor-reported agent ID; not independent endpoint identity verification",
            )
        )
    if a["source_ip"] and a["source_ip"] == b["source_ip"]:
        matches.append(
            (
                "same_observed_source_ip",
                "low",
                "Shared NAT/proxy IP does not establish a common actor",
            )
        )
    if set(a["endpoint_ips"]) & set(b["endpoint_ips"]):
        matches.append(
            (
                "shared_observed_endpoint_ip",
                "low",
                "Same address in telemetry; shared/reassigned addresses remain ambiguous",
            )
        )
    if (b["agent_id"] and b["agent_id"] in bindings["agent_ids"]) or set(
        b["endpoint_ips"]
    ) & set(bindings["ips"]):
        matches.append(
            (
                "current_operator_asset_binding",
                "low",
                "Pinned current declaration, not historical event-time identity",
            )
        )
    return [
        {
            "from": anchor["id"],
            "to": other["id"],
            "type": kind,
            "confidence": confidence,
            "meaning": "association_only",
            "direction": "undirected",
            "reason": reason,
        }
        for kind, confidence, reason in matches
    ]


def candidate_conditions(keys, bindings, kind):
    clauses, values = [], []
    if keys["source_ip"]:
        clauses.append("source_ip=%s")
        values.append(keys["source_ip"])
    request_id = (
        "COALESCE(raw->>'request_X-Request-ID',raw->>'request_id',raw->'http'->>'request_id')"
        if kind == "requests"
        else "COALESCE(event->'event'->>'request_X-Request-ID',event->'event'->>'request_id',event->'event'->'http'->>'request_id')"
    )
    if keys["request_id"]:
        clauses.append(f"{request_id}=%s")
        values.append(keys["request_id"])
    if kind == "incidents":
        agents = sorted(
            set(
                bindings["agent_ids"] + ([keys["agent_id"]] if keys["agent_id"] else [])
            )
        )
        ips = sorted(set(bindings["ips"] + keys["endpoint_ips"]))
        if agents:
            clauses.append(
                "(source='wazuh' AND event->'event'->'agent'->>'id'=ANY(%s))"
            )
            values.append(agents)
        if ips:
            clauses.append(
                "(event->'event'->'agent'->>'ip'=ANY(%s) OR event->'event'->>'src_ip'=ANY(%s) OR event->'event'->>'dest_ip'=ANY(%s))"
            )
            values.extend([ips, ips, ips])
    return " OR ".join(clauses) or "FALSE", values


async def _create(identity, body):
    spec = body.model_dump(mode="json")
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        await cur.execute("SELECT pg_advisory_xact_lock(84320115)")
        await cur.execute("SELECT * FROM evidence_cases WHERE id=%s", (identity,))
        existing = await cur.fetchone()
        if existing:
            if existing["input_hash"] != digest(spec):
                raise HTTPException(409, "Case UUID already used for different input")
            return existing
        await cur.execute(
            "SELECT count(*) AS pending FROM incidents WHERE event_time_state='not_indexed'"
        )
        if (await cur.fetchone())["pending"]:
            raise HTTPException(
                409, "Event-time indexing incomplete; wait and retry the same case UUID"
            )
        table = "gateway_requests" if body.anchor_kind == "requests" else "incidents"
        await cur.execute(f"SELECT * FROM {table} WHERE id=%s", (body.anchor_id,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Anchor no longer retained")
        anchor = event_node(body.anchor_kind, row)
        await cur.execute(
            f"SELECT * FROM ({assets.LATEST}) a WHERE payload->>'status'='active' ORDER BY asset_id LIMIT 1001"
        )
        registry = await cur.fetchall()
        if len(registry) > 1000:
            raise HTTPException(409, "Asset registry exceeds supported mapping bound")
        context = assets.resolve(body.anchor_kind, row, registry)
        bindings = context["bindings"]
        moment = datetime.fromisoformat(anchor["effective_at"])
        start, end = (
            moment - timedelta(minutes=body.minutes),
            moment + timedelta(minutes=body.minutes),
        )
        candidates, bounds = [], {}
        for kind, table, time_col in [
            ("incidents", "incidents", "COALESCE(event_observed_at,created_at)"),
            ("requests", "gateway_requests", "observed_at"),
        ]:
            await cur.execute(f"SELECT COALESCE(max(id),0) AS high_water FROM {table}")
            high_water = (await cur.fetchone())["high_water"]
            bounds[kind] = high_water
            clause, values = candidate_conditions(anchor["identity"], bindings, kind)
            await cur.execute(
                f"SELECT * FROM {table} WHERE id<=%s AND {time_col} BETWEEN %s AND %s AND ({clause}) ORDER BY {time_col},id LIMIT 81",
                (high_water, start, end, *values),
            )
            candidates.extend(
                event_node(kind, r)
                for r in await cur.fetchall()
                if f"{kind}:{r['id']}" != anchor["id"]
            )
        candidates.sort(key=lambda r: (r["effective_at"], r["kind"], r["record_id"]))
        truncated = len(candidates) > 79
        nodes, edges = [anchor], []
        for candidate in candidates[:79]:
            links = associations(anchor, candidate, bindings)
            if links:
                nodes.append(candidate)
                edges.extend(links)
        if body.anchor_kind == "incidents":
            await cur.execute(
                "SELECT id,created_at,incident_alert_id,action,target,status,policy_verdict,executed_at FROM decisions WHERE incident_alert_id=%s ORDER BY created_at,id LIMIT 21",
                (row["alert_id"],),
            )
            decisions = await cur.fetchall()
        else:
            decisions = []
        for decision in decisions[:20]:
            node_id = f"decisions:{decision['id']}"
            nodes.append(
                {
                    "id": node_id,
                    "kind": "decisions",
                    "record_id": decision["id"],
                    "source": "stored_policy_record",
                    "title": f"{decision['action']} · {decision['status']}",
                    "observed_at": None,
                    "ingested_at": decision["created_at"].isoformat(),
                    "effective_at": decision["created_at"].isoformat(),
                    "time_basis": "stored_decision_created_at",
                    "evidence": decision,
                }
            )
            edges.append(
                {
                    "from": anchor["id"],
                    "to": node_id,
                    "type": "stored_incident_decision_reference",
                    "confidence": "high",
                    "meaning": "stored_reference_only",
                    "direction": "directed",
                    "reason": "Exact stored incident_alert_id; does not independently verify execution or causal attack linkage",
                }
            )
        nodes.sort(key=lambda r: (r["effective_at"], r["id"]))
        graph = {
            "version": VERSION,
            "implementation_sha256": CODE_HASH,
            "scope": SCOPE,
            "anchor": anchor["id"],
            "window": {
                "start": start,
                "end": end,
                "basis": "source_reported_else_ingestion",
            },
            "nodes": nodes,
            "edges": edges,
            "asset_context": context,
            "source_high_water": bounds,
            "event_nodes_truncated": truncated,
            "decisions_truncated": len(decisions) > 20,
            "limits": {"event_nodes": 80, "decisions": 20, "expansion_hops": 1},
            "late_arrival_policy": "Snapshot membership is fixed; later ingestion requires a new case UUID, even for older event times",
            "confidence_scope": "Ordinal strength of the stated association/reference, not probability of attack or causation",
            "authentication": "shared_operation_key"
            if settings.operation_key
            else "operation_key_disabled",
        }
        await cur.execute(
            "INSERT INTO evidence_cases(id,input_hash,specification,graph,content_hash) VALUES (%s,%s,%s::jsonb,%s::jsonb,%s) RETURNING *",
            (
                identity,
                digest(spec),
                json.dumps(spec),
                json.dumps(graph, default=str),
                digest(graph),
            ),
        )
        saved = await cur.fetchone()
        await conn.commit()
        return saved


async def create(identity, body):
    for attempt in range(3):
        try:
            return await _create(identity, body)
        except (SerializationFailure, UniqueViolation) as error:
            if (
                isinstance(error, UniqueViolation)
                and error.diag.constraint_name != "evidence_cases_pkey"
            ):
                raise
            if attempt == 2:
                raise HTTPException(
                    409, "Concurrent snapshot creation; retry the same UUID"
                ) from None


@router.put("/{identity}", dependencies=[Depends(operation_key)])
async def create_case(identity: UUID, body: CaseInput):
    return await create(identity, body)


@router.get("/index/status")
async def index_status():
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT event_time_state,count(*) AS total FROM incidents GROUP BY event_time_state ORDER BY event_time_state"
        )
        return {
            "items": await cur.fetchall(),
            "scope": "Derived timestamp metadata only; source clocks remain unverified",
        }


@router.get("")
async def listing(
    anchor_kind: Literal["requests", "incidents"],
    anchor_id: int = Query(ge=1),
    page: int = Query(1, ge=1),
):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        args = (anchor_kind, str(anchor_id))
        await cur.execute(
            "SELECT count(*) AS total FROM evidence_cases WHERE specification->>'anchor_kind'=%s AND specification->>'anchor_id'=%s",
            args,
        )
        total = (await cur.fetchone())["total"]
        await cur.execute(
            "SELECT id,specification,content_hash,created_at FROM evidence_cases WHERE specification->>'anchor_kind'=%s AND specification->>'anchor_id'=%s ORDER BY created_at DESC,id LIMIT 10 OFFSET %s",
            (*args, (page - 1) * 10),
        )
        return {"items": await cur.fetchall(), "total": total, "page": page}


@router.get("/{identity}")
async def detail(identity: UUID):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM evidence_cases WHERE id=%s", (identity,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Case snapshot not found")
        return row
