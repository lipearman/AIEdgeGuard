"""Deterministic retained-evidence checks and append-only operator review.

Does not call the graph maker, LLM, executor or external services. Consistency
against the same retained sources is not independent ground-truth verification.
"""

import hashlib
import ipaddress
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field

from app.config import settings
from app.evaluation import operation_key
from app.integrations import db

router = APIRouter(prefix="/api/v1/case-checks", tags=["Case consistency and review"])
VERSION = "retained-evidence-check-v1-20261122"
CODE_HASH = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
SCOPE = "Consistency against retained source facts and pinned declarations, not independent source authenticity, causal attack confirmation, completeness or permission to act."
SCHEMA = """
CREATE TABLE IF NOT EXISTS case_checks (
 id uuid PRIMARY KEY, case_id uuid NOT NULL REFERENCES evidence_cases(id),
 input_hash text NOT NULL, specification jsonb NOT NULL, report jsonb NOT NULL,
 content_hash text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS case_checks_case ON case_checks(case_id,created_at);
CREATE TABLE IF NOT EXISTS case_operator_reviews (
 id bigserial PRIMARY KEY,case_id uuid NOT NULL REFERENCES evidence_cases(id),
 check_id uuid NOT NULL REFERENCES case_checks(id),revision integer NOT NULL CHECK(revision>0),
 verdict text NOT NULL CHECK(verdict IN ('supported_association','needs_more_evidence','disputed')),
 reviewer_label text NOT NULL,rationale text NOT NULL,authentication text NOT NULL,
 request_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(case_id,revision),UNIQUE(case_id,request_id)
);
CREATE OR REPLACE FUNCTION reject_case_check_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Case check/review history is append-only'; END; $$;
DROP TRIGGER IF EXISTS immutable_case_checks ON case_checks;
CREATE TRIGGER immutable_case_checks BEFORE UPDATE OR DELETE ON case_checks
 FOR EACH ROW EXECUTE FUNCTION reject_case_check_mutation();
DROP TRIGGER IF EXISTS immutable_case_operator_reviews ON case_operator_reviews;
CREATE TRIGGER immutable_case_operator_reviews BEFORE UPDATE OR DELETE ON case_operator_reviews
 FOR EACH ROW EXECUTE FUNCTION reject_case_check_mutation();
"""


class CheckInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    case_id: UUID
    declared_by: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000, pattern=r"^[^\x00]*$")


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    check_id: UUID
    expected_revision: int = Field(ge=0)
    verdict: Literal["supported_association", "needs_more_evidence", "disputed"]
    reviewer_label: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000, pattern=r"^[^\x00]*$")
    request_id: UUID


def sha(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def ip(value, public=False):
    try:
        address = ipaddress.ip_address(str(value or ""))
        if (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
            or (public and not address.is_global)
        ):
            return ""
        return str(address)
    except ValueError:
        return ""


def facts(kind, row):
    """Separate parser/check path; never trust the maker's derived identity/time."""
    wrapper = row.get("raw") if kind == "requests" else row.get("event")
    wrapper = wrapper if isinstance(wrapper, dict) else {}
    raw = wrapper if kind == "requests" else wrapper.get("event", wrapper)
    raw = raw if isinstance(raw, dict) else {}
    agent = raw.get("agent")
    agent = agent if isinstance(agent, dict) else {}
    http = raw.get("http")
    http = http if isinstance(http, dict) else {}
    rid = (
        raw.get("request_X-Request-ID")
        or raw.get("request_id")
        or http.get("request_id")
        or ""
    )
    rid = rid if isinstance(rid, str) and len(rid) <= 200 else ""
    aid = str(agent.get("id") or "") if row.get("source") == "wazuh" else ""
    aid = "" if aid == "000" else aid
    endpoint = ip(agent.get("ip"))
    endpoints = sorted(
        {
            address
            for v in [endpoint, raw.get("src_ip"), raw.get("dest_ip")]
            if (address := ip(v))
        }
    )
    ingested = row["collected_at"] if kind == "requests" else row["created_at"]
    field = (
        "StartUTC"
        if kind == "requests"
        else {
            "wazuh": "timestamp",
            "suricata": "timestamp",
            "crowdsec": "start_at",
        }.get(row.get("source"), "")
    )
    value = raw.get(field) if field else None
    observed = None
    state = "missing" if field else "unsupported_source"
    if kind == "requests":
        # Compare retained normalized HTTP time and raw parsing where available.
        observed = row["observed_at"]
        state = "source_reported"
    elif value not in (None, ""):
        state = "invalid"
        if isinstance(value, str) and len(value) <= 80:
            try:
                parsed = datetime.fromisoformat(value)
                if parsed.tzinfo is None:
                    state = "timezone_missing"
                elif parsed > ingested + timedelta(minutes=5):
                    state = "future_clock_untrusted"
                else:
                    observed = parsed.astimezone(UTC)
                    state = "source_reported"
            except (ValueError, OverflowError):
                pass
    source_hash = (
        hashlib.sha256(
            json.dumps(wrapper, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()
        if kind == "requests"
        else sha(wrapper)
    )
    return {
        "source_hash": source_hash,
        "observed_at": observed,
        "ingested_at": ingested,
        "time_state": state,
        "time_field": field,
        "source": "http_gateway" if kind == "requests" else row.get("source"),
        "source_ip": ip(row.get("source_ip"), public=kind == "requests"),
        "agent_id": aid,
        "endpoint_ips": endpoints,
        "request_id": rid,
        "alert_id": row.get("alert_id"),
    }


def equal_time(value, actual):
    if value is None or actual is None:
        return value is None and actual is None
    try:
        return datetime.fromisoformat(value).astimezone(UTC) == actual.astimezone(UTC)
    except (ValueError, TypeError, OverflowError):
        return False


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


async def inspect_case(cur, case):
    graph = case["graph"]
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    result = {
        "version": VERSION,
        "implementation_sha256": CODE_HASH,
        "case_id": str(case["id"]),
        "case_content_hash": case["content_hash"],
        "case_hash_matches": sha(graph) == case["content_hash"],
        "scope": SCOPE,
        "independent_identity_verified": False,
        "source_authenticity_verified": False,
        "model_used": False,
        "nodes": [],
        "edges": [],
        "assets": [],
    }
    observed = {}
    states = {}
    stored = {}
    mapping = {}
    if (
        not nodes
        or len(nodes) > 100
        or len(edges) > 500
        or len({n.get("id") for n in nodes}) != len(nodes)
        or graph.get("anchor") not in {n.get("id") for n in nodes}
    ):
        return {
            **result,
            "state": "unsupported_bounds",
            "reason": "Case exceeds supported node/edge bounds",
        }
    for node in nodes:
        identity = node.get("id")
        kind = node.get("kind")
        record_id = node.get("record_id")
        if kind not in ("requests", "incidents", "decisions") or not isinstance(
            record_id, int
        ):
            result["nodes"].append(
                {
                    "node": identity,
                    "state": "unsupported",
                    "issues": ["Unsupported source reference"],
                }
            )
            states[identity] = "unsupported"
            continue
        table = {
            "requests": "gateway_requests",
            "incidents": "incidents",
            "decisions": "decisions",
        }[kind]
        await cur.execute(f"SELECT * FROM {table} WHERE id=%s", (record_id,))
        row = await cur.fetchone()
        if not row:
            states[identity] = "unavailable"
            result["nodes"].append(
                {
                    "node": identity,
                    "state": "unavailable",
                    "issues": [
                        "Source record is no longer retained; snapshot hash cannot recover it"
                    ],
                }
            )
            continue
        issues = []
        stored[identity] = row
        if identity != f"{kind}:{record_id}":
            issues.append("Source reference ID disagrees with pinned node ID")
        if kind == "decisions":
            pinned = node.get("evidence") or {}
            current = {k: row.get(k) for k in pinned}
            if sha(current) != sha(pinned):
                issues.append(
                    "Stored decision fields changed since snapshot; lifecycle changes are not proof of tampering"
                )
        else:
            f = facts(kind, row)
            observed[identity] = f
            if f["source_hash"] != node.get("source_evidence_sha256"):
                issues.append("Retained source content hash differs from snapshot")
            for key in ("observed_at", "ingested_at"):
                if not equal_time(node.get(key), f[key]):
                    issues.append(key + " differs from retained source")
            if not equal_time(
                node.get("effective_at"), f["observed_at"] or f["ingested_at"]
            ):
                issues.append(
                    "Effective time differs from independently derived source basis"
                )
            if node.get("time_basis") != (
                "source_reported" if f["observed_at"] else "ingestion_fallback"
            ):
                issues.append("Time basis differs from retained source")
            try:
                effective = f["observed_at"] or f["ingested_at"]
                if (
                    not datetime.fromisoformat(graph["window"]["start"])
                    <= effective
                    <= datetime.fromisoformat(graph["window"]["end"])
                ):
                    issues.append("Event node falls outside pinned event window")
                if record_id > graph["source_high_water"][kind]:
                    issues.append("Event node exceeds pinned source high-water ID")
            except (KeyError, ValueError, TypeError):
                issues.append("Unsupported window/source-boundary metadata")
            if (
                node.get("source") != f["source"]
                or node.get("time_state") != f["time_state"]
            ):
                issues.append(
                    "Source/time classification differs from retained evidence"
                )
            pinned = node.get("identity") or {}
            if any(
                pinned.get(k) != f[k]
                for k in ("source_ip", "agent_id", "request_id", "endpoint_ips")
            ):
                issues.append("Pinned identifiers disagree with retained source")
        states[identity] = "changed_since_snapshot" if issues else "consistent"
        result["nodes"].append(
            {"node": identity, "state": states[identity], "issues": issues}
        )
    context = graph.get("asset_context") or {}
    for part in ("asset", "parent_host"):
        ref = context.get(part)
        if not ref:
            continue
        await cur.execute(
            "SELECT payload FROM asset_revisions WHERE asset_id=%s AND revision=%s",
            (ref["asset_id"], ref["revision"]),
        )
        row = await cur.fetchone()
        state = (
            "unavailable"
            if not row
            else "consistent"
            if row["payload"] == ref.get("payload")
            else "changed_since_snapshot"
        )
        result["assets"].append(
            {
                "asset_id": ref["asset_id"],
                "revision": ref["revision"],
                "state": state,
                "scope": "Pinned declaration only, not real-world or event-time identity",
            }
        )
        if state == "consistent":
            mapping[part] = row["payload"]
    bindings = context.get("bindings") or {"agent_ids": [], "ips": []}
    host = mapping.get("parent_host") or (
        mapping.get("asset")
        if (mapping.get("asset") or {}).get("kind") == "host"
        else {}
    )
    binding_ok = (
        bool(host)
        and set(bindings.get("agent_ids", [])) <= set(host.get("agent_ids", []))
        and set(bindings.get("ips", [])) <= set(host.get("ips", []))
    )
    anchor = graph.get("anchor")
    a = observed.get(anchor)
    if binding_ok:
        ar = stored.get(anchor, {})
        selected = mapping.get("asset") or {}
        if anchor.startswith("requests:"):
            try:
                parsed = urlsplit("//" + str(ar.get("host") or ""))
                hostname = (
                    (parsed.hostname or "").rstrip(".").encode("idna").decode().lower()
                )
                hostname = ("[" + hostname + "]") if ":" in hostname else hostname
                hostname += ":" + str(parsed.port) if parsed.port is not None else ""
                path = str(ar.get("path") or "").split("?", 1)[0]
                binding_ok = selected.get("parent_host_id") == (
                    (context.get("parent_host") or {}).get("asset_id")
                ) and any(
                    r.get("host") == hostname
                    and r.get("router") == ar.get("router")
                    and (
                        r.get("path_prefix") == "/"
                        or path == r.get("path_prefix")
                        or path.startswith(str(r.get("path_prefix")) + "/")
                    )
                    for r in selected.get("routes", [])
                )
            except (ValueError, UnicodeError):
                binding_ok = False
        else:
            binding_ok = bool(
                a
                and (
                    (a["agent_id"] and a["agent_id"] in host.get("agent_ids", []))
                    or set(a["endpoint_ips"]) & set(host.get("ips", []))
                )
            )
    confidence = {
        "same_recorded_request_id": "low",
        "same_wazuh_agent_id": "medium",
        "same_observed_source_ip": "low",
        "shared_observed_endpoint_ip": "low",
        "current_operator_asset_binding": "low",
        "stored_incident_decision_reference": "high",
    }
    for i, edge in enumerate(edges):
        target = edge.get("to")
        b = observed.get(target)
        kind = edge.get("type")
        state = "unverifiable"
        reason = (
            "Source evidence missing, changed, or unsupported; no causal conclusion"
        )
        reference = kind == "stored_incident_decision_reference"
        schema_ok = (
            edge.get("from") == anchor
            and target in states
            and edge.get("confidence") == confidence.get(kind)
            and edge.get("meaning")
            == ("stored_reference_only" if reference else "association_only")
            and edge.get("direction") == ("directed" if reference else "undirected")
        )
        if not schema_ok or kind not in confidence:
            state = "contradicted"
            reason = "Edge type, endpoints, confidence or meaning violates supported case rules"
        elif (
            a and states.get(anchor) == "consistent" and reference and target in stored
        ):
            supported = (
                stored[target].get("incident_alert_id") == a["alert_id"]
                and a["alert_id"] is not None
            )
            state = "supported_reference" if supported else "contradicted"
            reason = "Retained incident_alert_id reference only; execution is not independently verified"
        elif (
            a
            and b
            and states.get(anchor) == "consistent"
            and states.get(target) == "consistent"
        ):
            checks = {
                "same_recorded_request_id": bool(
                    a["request_id"] and a["request_id"] == b["request_id"]
                ),
                "same_wazuh_agent_id": bool(
                    a["agent_id"] and a["agent_id"] == b["agent_id"]
                ),
                "same_observed_source_ip": bool(
                    a["source_ip"] and a["source_ip"] == b["source_ip"]
                ),
                "shared_observed_endpoint_ip": bool(
                    set(a["endpoint_ips"]) & set(b["endpoint_ips"])
                ),
                "current_operator_asset_binding": binding_ok
                and bool(
                    (b["agent_id"] and b["agent_id"] in bindings.get("agent_ids", []))
                    or set(b["endpoint_ips"]) & set(bindings.get("ips", []))
                ),
            }
            if kind == "current_operator_asset_binding" and not binding_ok:
                reason = "Pinned host declaration unavailable or inconsistent; cannot establish historical identity"
            else:
                state = "supported_association" if checks.get(kind) else "contradicted"
                reason = "Retained facts support only this typed association, not source authenticity or causation"
        result["edges"].append(
            {
                "index": i,
                "from": edge.get("from"),
                "to": target,
                "type": kind,
                "state": state,
                "reason": reason,
            }
        )
    all_states = [
        r["state"] for key in ("nodes", "edges", "assets") for r in result[key]
    ]
    result["state"] = (
        "inconsistent"
        if not result["case_hash_matches"] or "contradicted" in all_states
        else "incomplete_or_changed"
        if any(
            s not in ("consistent", "supported_association", "supported_reference")
            for s in all_states
        )
        else "consistent_with_retained_evidence"
    )
    result["counts"] = {s: all_states.count(s) for s in sorted(set(all_states))}
    result["limits"] = (
        "No exhaustive membership check, source authenticity, trusted identity, clock attestation, causal validation or defense action"
    )
    return result


async def save_check(identity, body):
    spec = body.model_dump(mode="json")
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Fresh per-op connection: session lock survives commit, then closes on every exit.
        # Take it before opening the repeatable snapshot so concurrent retries see the winner.
        await cur.execute("SELECT pg_advisory_lock(84320116)")
        await conn.commit()
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        await cur.execute("SELECT * FROM case_checks WHERE id=%s", (identity,))
        old = await cur.fetchone()
        if old:
            if old["input_hash"] != sha(spec):
                raise HTTPException(409, "Check UUID already used for different input")
            return old
        await cur.execute("SELECT * FROM evidence_cases WHERE id=%s", (body.case_id,))
        case = await cur.fetchone()
        if not case:
            raise HTTPException(404, "Case snapshot not found")
        report = await inspect_case(cur, case)
        report.update(
            checked_at=datetime.now(UTC).isoformat(),
            authentication="shared_operation_key"
            if settings.operation_key
            else "operation_key_disabled",
        )
        await cur.execute(
            "INSERT INTO case_checks(id,case_id,input_hash,specification,report,content_hash) VALUES (%s,%s,%s,%s::jsonb,%s::jsonb,%s) RETURNING *",
            (
                identity,
                body.case_id,
                sha(spec),
                json.dumps(spec),
                json.dumps(report),
                sha(report),
            ),
        )
        row = await cur.fetchone()
        await conn.commit()
        return row


async def save_review(case_id, body):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT pg_advisory_xact_lock(84320116)")
        await cur.execute(
            "SELECT * FROM case_operator_reviews WHERE case_id=%s AND request_id=%s",
            (case_id, body.request_id),
        )
        old = await cur.fetchone()
        if old:
            if any(
                str(old[k]) != str(getattr(body, k))
                for k in ("check_id", "verdict", "reviewer_label", "rationale")
            ):
                raise HTTPException(
                    409, "Request UUID already used for different review"
                )
            return old
        await cur.execute(
            "SELECT report FROM case_checks WHERE id=%s AND case_id=%s",
            (body.check_id, case_id),
        )
        check = await cur.fetchone()
        if not check:
            raise HTTPException(422, "Select a retained check belonging to this case")
        await cur.execute(
            "SELECT COALESCE(max(revision),0) AS revision FROM case_operator_reviews WHERE case_id=%s",
            (case_id,),
        )
        revision = (await cur.fetchone())["revision"]
        if revision != body.expected_revision:
            raise HTTPException(
                409, "Case review changed; reload latest revision before resubmitting"
            )
        await cur.execute(
            "INSERT INTO case_operator_reviews(case_id,check_id,revision,verdict,reviewer_label,rationale,authentication,request_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *",
            (
                case_id,
                body.check_id,
                revision + 1,
                body.verdict,
                body.reviewer_label,
                body.rationale,
                "shared_operation_key"
                if settings.operation_key
                else "operation_key_disabled",
                body.request_id,
            ),
        )
        row = await cur.fetchone()
        await conn.commit()
        return row


@router.put("/{identity}", dependencies=[Depends(operation_key)])
async def create_check(identity: UUID, body: CheckInput):
    return await save_check(identity, body)


@router.get("")
async def history(case_id: UUID, page: int = Query(1, ge=1)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        await cur.execute(
            "SELECT count(*) AS total FROM case_checks WHERE case_id=%s", (case_id,)
        )
        total = (await cur.fetchone())["total"]
        await cur.execute(
            "SELECT id,created_at,report->>'state' AS state FROM case_checks WHERE case_id=%s ORDER BY created_at DESC,id LIMIT 10 OFFSET %s",
            (case_id, (page - 1) * 10),
        )
        return {"items": await cur.fetchall(), "total": total, "page": page}


@router.post("/reviews/{case_id}", dependencies=[Depends(operation_key)])
async def review(case_id: UUID, body: ReviewInput):
    return await save_review(case_id, body)


@router.get("/reviews/{case_id}")
async def reviews(case_id: UUID, page: int = Query(1, ge=1)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        await cur.execute(
            "SELECT count(*) AS total,COALESCE(max(revision),0) AS revision FROM case_operator_reviews WHERE case_id=%s",
            (case_id,),
        )
        meta = await cur.fetchone()
        await cur.execute(
            "SELECT * FROM case_operator_reviews WHERE case_id=%s ORDER BY revision DESC LIMIT 10 OFFSET %s",
            (case_id, (page - 1) * 10),
        )
        return {
            **meta,
            "items": await cur.fetchall(),
            "page": page,
            "independent_identity_verified": False,
        }


@router.get("/{identity}")
async def detail(identity: UUID):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM case_checks WHERE id=%s", (identity,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Case check not found")
        return row
