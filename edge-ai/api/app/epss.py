"""Bounded, operator-triggered FIRST EPSS lookups with durable provenance."""

import hashlib
import json
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation

import httpx
from fastapi import APIRouter, HTTPException, Path
from psycopg.rows import dict_row

from app.integrations import db
from app.intelligence import CVE

router = APIRouter(prefix="/api/v1/intelligence/epss", tags=["EPSS"])
SOURCE = "https://api.first.org/data/v1/epss"
SCOPE = "FIRST EPSS estimates observed exploitation activity for a CVE over the next 30 days. It is not severity, asset applicability, proof of exploitation or an automatic response decision. Percentile is rank, not probability. On-demand lookup; no automatic daily EPSS sync."
SCHEMA = """
CREATE TABLE IF NOT EXISTS epss_snapshots (
 id bigserial PRIMARY KEY,cve text NOT NULL,score_date date NOT NULL,
 epss numeric NOT NULL CHECK(epss BETWEEN 0 AND 1),
 percentile numeric NOT NULL CHECK(percentile BETWEEN 0 AND 1),
 api_version text NOT NULL,source_url text NOT NULL,fingerprint text NOT NULL UNIQUE,
 fetched_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS epss_cache (
 cve text PRIMARY KEY,last_attempt timestamptz,last_success timestamptz,
 last_result text NOT NULL DEFAULT 'never_fetched',error text NOT NULL DEFAULT '',
 snapshot_id bigint REFERENCES epss_snapshots(id)
);
CREATE TABLE IF NOT EXISTS epss_request_budget (
 id integer PRIMARY KEY CHECK(id=1),last_attempt timestamptz
);
INSERT INTO epss_request_budget(id) VALUES (1) ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION reject_epss_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'EPSS snapshots are append-only'; END; $$;
DROP TRIGGER IF EXISTS immutable_epss_snapshot ON epss_snapshots;
CREATE TRIGGER immutable_epss_snapshot BEFORE UPDATE OR DELETE ON epss_snapshots
 FOR EACH ROW EXECUTE FUNCTION reject_epss_snapshot_mutation();
"""


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


def canonical(value):
    if not CVE.fullmatch(value):
        raise HTTPException(422, "Use one complete CVE ID, e.g. CVE-2024-4577")
    return value.upper()


def validate(document, cve):
    if (
        not isinstance(document, dict)
        or document.get("status") != "OK"
        or document.get("status-code") != 200
    ):
        raise ValueError("Invalid FIRST response status")
    rows = document.get("data")
    if (
        not isinstance(rows, list)
        or len(rows) > 1
        or type(document.get("total")) is not int
        or document["total"] != len(rows)
        or document.get("offset") != 0
    ):
        raise ValueError("Incomplete or unexpected EPSS response")
    version = document.get("version")
    if not isinstance(version, str) or not 1 <= len(version) <= 64:
        raise ValueError("Invalid API version")
    if not rows:
        return None, version
    row = rows[0]
    if not isinstance(row, dict) or row.get("cve") != cve:
        raise ValueError("Unrequested CVE")
    values = []
    for key in ("epss", "percentile"):
        value = row.get(key)
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise TypeError("Invalid score type")
        try:
            score = Decimal(str(value))
        except InvalidOperation:
            raise ValueError("Invalid score") from None
        if not score.is_finite() or not 0 <= score <= 1:
            raise ValueError("Score outside 0–1")
        values.append(score)
    score_date = date.fromisoformat(str(row.get("date")))
    if score_date > datetime.now(UTC).date():
        raise ValueError("Future score date")
    return {
        "cve": cve,
        "score_date": score_date,
        "epss": values[0],
        "percentile": values[1],
    }, version


async def download(cve):
    chunks = []
    size = 0
    async with (
        httpx.AsyncClient(timeout=15, follow_redirects=False) as client,
        client.stream("GET", SOURCE, params={"cve": cve, "limit": 1}) as response,
    ):
        response.raise_for_status()
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > 65536:
                raise ValueError("EPSS response exceeds 64 KB")
            chunks.append(chunk)
    return json.loads(b"".join(chunks))


async def cached(cve):
    cve = canonical(cve)
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """SELECT c.*,s.score_date,s.epss,s.percentile,s.api_version,s.source_url,s.fetched_at
            FROM epss_cache c LEFT JOIN epss_snapshots s ON s.id=c.snapshot_id WHERE c.cve=%s""",
            (cve,),
        )
        row = await cur.fetchone()
    now = datetime.now(UTC)
    state = "never_fetched"
    score = None
    if row:
        state = "refresh_failed" if row["error"] else row["last_result"]
        if row["snapshot_id"]:
            current = (
                now - row["last_success"] < timedelta(hours=24)
                and timedelta(0) <= now.date() - row["score_date"] <= timedelta(days=2)
                and not row["error"]
                and row["last_result"] == "scored"
            )
            score = {
                key: row[key]
                for key in (
                    "snapshot_id",
                    "score_date",
                    "epss",
                    "percentile",
                    "api_version",
                    "source_url",
                    "fetched_at",
                )
            }
            score["state"] = "current" if current else "stale"
            if state == "scored":
                state = score["state"]
        elif (
            row["last_success"]
            and now - row["last_success"] >= timedelta(hours=24)
            and state == "not_scored"
        ):
            state = "stale_not_scored"
    return {
        "cve": cve,
        "state": state,
        "score": score,
        "last_attempt": row["last_attempt"] if row else None,
        "last_success": row["last_success"] if row else None,
        "error": row["error"] if row else "",
        "source_url": SOURCE,
        "scope": SCOPE,
        "cache_hours": 24,
    }


async def refresh(cve):
    cve = canonical(cve)
    # Global database budget works across API processes and different requested CVEs.
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT last_attempt FROM epss_request_budget WHERE id=1 FOR UPDATE"
        )
        budget = await cur.fetchone()
        await cur.execute(
            "SELECT last_success,error FROM epss_cache WHERE cve=%s", (cve,)
        )
        previous = await cur.fetchone()
        now = datetime.now(UTC)
        if (
            previous
            and previous["last_success"]
            and not previous["error"]
            and now - previous["last_success"] < timedelta(hours=24)
        ):
            return {"action": "cache_hit", "result": await cached(cve)}
        if budget["last_attempt"] and now - budget["last_attempt"] < timedelta(
            seconds=30
        ):
            raise HTTPException(
                429,
                "EPSS fetch budget: wait 30 seconds between external lookups",
                headers={"Retry-After": "30"},
            )
        await cur.execute(
            "UPDATE epss_request_budget SET last_attempt=now() WHERE id=1"
        )
        await cur.execute(
            "INSERT INTO epss_cache(cve,last_attempt) VALUES (%s,now()) ON CONFLICT(cve) DO UPDATE SET last_attempt=now() RETURNING last_attempt",
            (cve,),
        )
        attempt = (await cur.fetchone())["last_attempt"]
        await conn.commit()
    try:
        score, version = validate(await download(cve), cve)
        async with (
            await db._connect() as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(
                "SELECT c.last_attempt,s.score_date FROM epss_cache c LEFT JOIN epss_snapshots s ON s.id=c.snapshot_id WHERE c.cve=%s FOR UPDATE OF c",
                (cve,),
            )
            prior = await cur.fetchone()
            if prior["last_attempt"] != attempt:
                return {"action": "superseded", "result": await cached(cve)}
            if (
                score
                and prior["score_date"]
                and score["score_date"] < prior["score_date"]
            ):
                raise ValueError("EPSS score predates stored snapshot")
            snapshot_id = None
            if score:
                fingerprint = hashlib.sha256(
                    json.dumps(
                        {**score, "api_version": version}, sort_keys=True, default=str
                    ).encode()
                ).hexdigest()
                url = SOURCE + "?cve=" + cve
                await cur.execute(
                    """INSERT INTO epss_snapshots(cve,score_date,epss,percentile,api_version,source_url,fingerprint)
                    VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(fingerprint) DO NOTHING""",
                    (
                        cve,
                        score["score_date"],
                        score["epss"],
                        score["percentile"],
                        version,
                        url,
                        fingerprint,
                    ),
                )
                await cur.execute(
                    "SELECT id FROM epss_snapshots WHERE fingerprint=%s", (fingerprint,)
                )
                snapshot_id = (await cur.fetchone())["id"]
            await cur.execute(
                """UPDATE epss_cache SET last_success=now(),last_result=%s,error='',snapshot_id=COALESCE(%s,snapshot_id) WHERE cve=%s""",
                ("scored" if score else "not_scored", snapshot_id, cve),
            )
            await conn.commit()
        return {"action": "fetched", "result": await cached(cve)}
    except (httpx.HTTPError, ValueError, TypeError, KeyError, OverflowError):
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE epss_cache SET error='FIRST lookup failed or response invalid; last stored score retained' WHERE cve=%s AND last_attempt=%s",
                (cve, attempt),
            )
            await conn.commit()
        return {"action": "failed", "result": await cached(cve)}


@router.get("/snapshots/{snapshot_id}")
async def snapshot(snapshot_id: int = Path(ge=1, le=9223372036854775807)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM epss_snapshots WHERE id=%s", (snapshot_id,))
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "EPSS snapshot not found")
    return {
        **row,
        "scope": SCOPE,
        "version_scope": "api_version describes FIRST API, not the EPSS model version",
    }


@router.get("/{cve}")
async def lookup(cve: str):
    return await cached(cve)
