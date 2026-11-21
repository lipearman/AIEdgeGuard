"""Explainable traffic deviation and candidate correlations; never enforcement."""

import ipaddress
import json
import math
import re
import statistics
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import parse_qsl, unquote, urlsplit

from fastapi import APIRouter, HTTPException, Query
from psycopg.rows import dict_row

from app import intelligence
from app.integrations import dashboard_db, db

router = APIRouter(prefix="/api/v1/investigation", tags=["Investigation"])


def inspection(path):
    target = path[:16000]
    try:
        parsed = urlsplit(target)
        path_part, query_part = parsed.path, parsed.query
    except ValueError:
        path_part, _, query_part = target.partition("?")
    pairs = parse_qsl("&".join(query_part.split("&")[:100]), keep_blank_values=True)
    query = []
    for key, value in pairs:
        k = unquote(key, errors="replace")
        query.append(
            {
                "key": k[:200],
                "value": "[redacted]"
                if re.search(r"password|token|secret|key|cookie", k, re.IGNORECASE)
                else unquote(value, errors="replace")[:1000],
            }
        )
    decoded = unquote(unquote(path_part, errors="replace"), errors="replace")
    if query:
        decoded += "?" + "&".join(x["key"] + "=" + x["value"] for x in query)
    patterns = {
        "path traversal syntax": r"\.\.[/\\]",
        "script markup": r"<\s*script\b",
        "SQL union/select syntax": r"\bunion\s+(?:all\s+)?select\b",
        "PHP opening tag": r"<\?php",
    }
    return {
        "path": path_part,
        "query": query,
        "decoded_target": decoded,
        "signals": [
            name
            for name, pattern in patterns.items()
            if re.search(pattern, decoded, re.IGNORECASE)
        ],
        "truncated": len(path) > 16000 or len(query_part.split("&")) > 100,
        "scope": "Normalized URL view; common secret query keys masked. Syntax hints are not proof of an attack. Up to two decoding passes; no HTTP body collected.",
    }


def useful_ip(value, public_only=False):
    try:
        address = ipaddress.ip_address(value)
        if (
            address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address.is_link_local
        ):
            return ""
        return str(address) if not public_only or address.is_global else ""
    except ValueError:
        return ""


def identity(kind, row):
    wrapper = row.get("event") or {}
    wrapper = wrapper if isinstance(wrapper, dict) else {}
    raw = row.get("raw", {}) if kind == "requests" else wrapper.get("event", wrapper)
    raw = raw if isinstance(raw, dict) else {}
    agent = raw.get("agent") or {}
    agent = agent if isinstance(agent, dict) else {}
    http = raw.get("http") or {}
    http = http if isinstance(http, dict) else {}
    # A gateway peer may be a shared proxy/NAT. Never infer an attacker from its private IP.
    source = useful_ip(str(row.get("source_ip") or ""), public_only=kind == "requests")
    agent_id = str(agent.get("id") or "") if row.get("source") == "wazuh" else ""
    if agent_id == "000":
        agent_id = ""
    endpoint = useful_ip(str(agent.get("ip") or ""))
    request_id = str(
        raw.get("request_X-Request-ID")
        or raw.get("request_id")
        or http.get("request_id")
        or ""
    )[:200]
    return {
        "source_ip": source,
        "agent_id": agent_id,
        "endpoint_ip": endpoint,
        "request_id": request_id,
    }


def correlation_reasons(keys, candidate):
    reasons = []
    if keys["source_ip"] and candidate.get("source_ip") == keys["source_ip"]:
        reasons.append("same observed source IP")
    if (
        keys["agent_id"]
        and candidate.get("source") == "wazuh"
        and candidate.get("agent_id") == keys["agent_id"]
    ):
        reasons.append("same Wazuh agent ID")
    if keys["endpoint_ip"] and keys["endpoint_ip"] in (
        candidate.get("agent_ip"),
        candidate.get("src_ip"),
        candidate.get("dest_ip"),
    ):
        reasons.append("endpoint IP appears in telemetry")
    if keys["request_id"] and candidate.get("request_id") == keys["request_id"]:
        reasons.append("same recorded request ID (may be client supplied)")
    return reasons


@router.get("/timeline/{kind}/{item_id}")
async def timeline(
    kind: Literal["requests", "incidents"],
    item_id: int,
    minutes: int = Query(15, ge=1, le=60),
    page: int = Query(1, ge=1, le=1000),
):
    anchor = await dashboard_db.detail(kind, item_id)
    if not anchor:
        raise HTTPException(404, "Anchor record no longer retained")
    timestamp = anchor["observed_at" if kind == "requests" else "created_at"]
    keys = identity(kind, anchor)
    conditions, values = [], []
    if keys["source_ip"]:
        conditions.append("source_ip=%s")
        values.append(keys["source_ip"])
    if keys["agent_id"]:
        conditions.append("(source='wazuh' AND event->'event'->'agent'->>'id'=%s)")
        values.append(keys["agent_id"])
    if keys["endpoint_ip"]:
        conditions.append(
            "(event->'event'->'agent'->>'ip'=%s OR event->'event'->>'src_ip'=%s OR event->'event'->>'dest_ip'=%s)"
        )
        values.extend([keys["endpoint_ip"]] * 3)
    request_id_sql = (
        "COALESCE(event->'event'->>'request_id',event->'event'->'http'->>'request_id')"
    )
    if keys["request_id"]:
        conditions.append(f"{request_id_sql}=%s")
        values.append(keys["request_id"])
    candidates, decisions = [], []
    cves = sorted(
        {
            x.upper()
            for x in intelligence.CVE.findall(
                anchor["path"]
                if kind == "requests"
                else json.dumps(anchor.get("event") or {}, ensure_ascii=False)
            )
        }
    )[:20]
    ai_cves = sorted(
        {
            x.upper()
            for x in intelligence.CVE.findall(
                json.dumps(anchor.get("analysis") or {}, ensure_ascii=False)
            )
        }
        - set(cves)
    )[:20]
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        if conditions:
            await cur.execute(
                f"""SELECT id,alert_id,created_at,source,severity,reason,source_ip,
                event->'event'->'agent'->>'id' AS agent_id,event->'event'->'agent'->>'name' AS endpoint,
                event->'event'->'agent'->>'ip' AS agent_ip,event->'event'->>'src_ip' AS src_ip,
                event->'event'->>'dest_ip' AS dest_ip,{request_id_sql} AS request_id,
                analysis->>'attack_type' AS attack_type,analysis->>'mitre_id' AS mitre_id
                FROM incidents WHERE created_at BETWEEN %s AND %s AND ({" OR ".join(conditions)})
                ORDER BY created_at,id LIMIT 51 OFFSET %s""",
                (
                    timestamp - timedelta(minutes=minutes),
                    timestamp + timedelta(minutes=minutes),
                    *values,
                    (page - 1) * 50,
                ),
            )
            candidates = await cur.fetchall()
        if kind == "incidents":
            await cur.execute(
                """SELECT id,created_at,action,target,status,policy_verdict,policy_reason,
                policy_checks,executed_at,result FROM decisions WHERE incident_alert_id=%s
                ORDER BY created_at DESC,id DESC LIMIT 21""",
                (anchor["alert_id"],),
            )
            decisions = await cur.fetchall()
    records = [
        {**r, "match_reasons": correlation_reasons(keys, r)} for r in candidates[:50]
    ]
    return {
        "anchor": {"kind": kind, "id": item_id, "time": timestamp},
        "identity": keys,
        "window_minutes": minutes,
        "page": page,
        "has_more": len(candidates) > 50,
        "items": records,
        "decisions": decisions[:20],
        "decisions_truncated": len(decisions) > 20,
        "evidence_cves": cves,
        "analysis_only_cves": ai_cves,
        "known_exploited": await intelligence.lookup(cves),
        "intelligence_status": await intelligence.status(),
        "inspection": inspection(anchor["path"]) if kind == "requests" else None,
        "scope": "Candidate correlations within a time window, not a verified attack chain or proof of causation. Incident times are ingestion times; proxy/NAT can share IPs. No identity match means no candidates, not no attack.",
    }


def deviation(series, coverage):
    baseline, current = series[:-1], series[-1]
    if not coverage:
        return {
            "state": "warming_up",
            "current": current,
            "baseline_median": None,
            "robust_score": None,
            "reason": "Need at least 60 minutes of retained history for this host/router",
        }
    median = statistics.median(baseline)
    mad = statistics.median(abs(x - median) for x in baseline)
    scale = max(3, math.sqrt(median), 1.4826 * mad)
    score = max(0, (current - median) / scale)
    unusual = current >= 20 and current >= max(3 * median, 20) and score >= 6
    return {
        "state": "unusual" if unusual else "within_baseline",
        "current": current,
        "baseline_median": median,
        "robust_score": round(score, 2),
        "reason": "Volume exceeds median/MAD and minimum-volume thresholds"
        if unusual
        else "No volume deviation above configured thresholds in this window",
    }


@router.get("/behavior")
async def behavior():
    now = datetime.now(UTC)
    end = datetime.fromtimestamp(int(now.timestamp()) // 300 * 300, UTC)
    start = end - timedelta(minutes=65)
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """WITH groups AS (
            SELECT host,router FROM gateway_requests WHERE observed_at >= %s AND observed_at < %s
            GROUP BY host,router ORDER BY count(*) DESC,host,router LIMIT 50
        ) SELECT r.host,r.router,floor(extract(epoch FROM r.observed_at)/300)::bigint AS bucket,
          count(*)::int AS requests,count(*) FILTER(WHERE status>=400)::int AS errors
          FROM gateway_requests r JOIN groups g ON r.host=g.host AND r.router=g.router
          WHERE observed_at >= %s AND observed_at < %s GROUP BY r.host,r.router,bucket""",
            (start, end, start, end),
        )
        rows = await cur.fetchall()
        await cur.execute(
            "SELECT host,router,min(observed_at) AS first_seen FROM gateway_requests GROUP BY host,router"
        )
        first = {
            (x["host"], x["router"]): x["first_seen"] for x in await cur.fetchall()
        }
        await cur.execute("SELECT max(observed_at) AS latest FROM gateway_requests")
        latest = (await cur.fetchone())["latest"]
    grouped = {}
    first_bucket = int(start.timestamp()) // 300
    for row in rows:
        key = (row["host"], row["router"])
        group = grouped.setdefault(key, {"counts": [0] * 13, "errors": [0] * 13})
        index = row["bucket"] - first_bucket
        if 0 <= index < 13:
            group["counts"][index] = row["requests"]
            group["errors"][index] = row["errors"]
    output = []
    for (host, router), group in grouped.items():
        result = deviation(group["counts"], first.get((host, router), now) <= start)
        output.append(
            {
                "host": host,
                "router": router,
                **result,
                "series": group["counts"],
                "error_responses": group["errors"][-1],
            }
        )
    output.sort(
        key=lambda r: (
            r["state"] != "unusual",
            -(r["robust_score"] or 0),
            -r["current"],
            r["host"],
            r["router"],
        )
    )
    return {
        "state": "no_data"
        if not latest
        else "stale"
        if now - latest > timedelta(minutes=10)
        else "available",
        "latest_request": latest,
        "window_start": end - timedelta(minutes=5),
        "window_end": end,
        "baseline_start": start,
        "items": output,
        "group_limit": 50,
        "method": "12 preceding five-minute windows; median/MAD with count floor. Top 50 host/router groups by volume.",
        "scope": "Explainable CPU volume heuristic, not trained ML or proof of malicious behavior. Missing collector data can resemble zero traffic. No automatic enforcement.",
    }
