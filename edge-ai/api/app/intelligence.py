"""Validated public KEV snapshots. Never generates rules or changes enforcement."""

import asyncio
import json
import logging
import re
from datetime import UTC, date, datetime, timedelta

import httpx
from fastapi import APIRouter, Query
from psycopg.rows import dict_row

from app.config import settings
from app.integrations import db

router = APIRouter(prefix="/api/v1/intelligence", tags=["Intelligence"])
log = logging.getLogger(__name__)
FEEDS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.IGNORECASE)
_sync = asyncio.Lock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS intelligence_feed (
 name text PRIMARY KEY, last_attempt timestamptz, last_success timestamptz,
 source_url text NOT NULL DEFAULT '', version text NOT NULL DEFAULT '',
 released_at timestamptz, error text NOT NULL DEFAULT '', record_count integer NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS known_vulnerabilities (
 cve text PRIMARY KEY, vendor text NOT NULL, product text NOT NULL,
 title text NOT NULL, description text NOT NULL, required_action text NOT NULL,
 date_added date NOT NULL, due_date date NOT NULL, ransomware text NOT NULL,
 active boolean NOT NULL DEFAULT true, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS kev_date ON known_vulnerabilities(date_added DESC);
INSERT INTO intelligence_feed(name) VALUES ('cisa-kev') ON CONFLICT DO NOTHING;
"""


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


def validate_feed(document):
    if not isinstance(document, dict):
        raise TypeError("KEV document must be an object")
    entries = document.get("vulnerabilities")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 50000:
        raise ValueError("KEV entries missing or exceed limit")
    if type(document.get("count")) is not int or document["count"] != len(entries):
        raise ValueError("KEV count mismatch")
    version = document.get("catalogVersion")
    if not isinstance(version, str) or not 1 <= len(version) <= 80:
        raise ValueError("Invalid KEV version")
    released = datetime.fromisoformat(str(document.get("dateReleased", "")))
    if released.tzinfo is None:
        raise ValueError("KEV release timestamp needs timezone")
    rows, seen = [], set()
    for item in entries:
        if not isinstance(item, dict):
            raise TypeError("Invalid KEV row")
        cve = item.get("cveID", "")
        if not isinstance(cve, str) or not CVE.fullmatch(cve) or cve.upper() in seen:
            raise ValueError("Invalid or duplicate KEV CVE")
        seen.add(cve.upper())
        fields = []
        for key in (
            "vendorProject",
            "product",
            "vulnerabilityName",
            "shortDescription",
            "requiredAction",
        ):
            value = item.get(key)
            if not isinstance(value, str) or not value.strip() or len(value) > 16000:
                raise ValueError("Invalid KEV text field")
            fields.append(value)
        dates = [
            date.fromisoformat(str(item.get(k, ""))) for k in ("dateAdded", "dueDate")
        ]
        ransomware = item.get("knownRansomwareCampaignUse", "Unknown")
        if ransomware not in ("Known", "Unknown"):
            raise ValueError("Invalid KEV ransomware flag")
        rows.append((cve.upper(), *fields, *dates, ransomware))
    return version, released, rows


async def download(url):
    chunks, size = [], 0
    async with (
        httpx.AsyncClient(timeout=30, follow_redirects=False) as client,
        client.stream("GET", url) as response,
    ):
        response.raise_for_status()
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > 12_000_000:
                raise ValueError("KEV feed exceeds 12 MB")
            chunks.append(chunk)
    return json.loads(b"".join(chunks))


async def sync_once():
    if _sync.locked():
        return {"status": "busy"}
    async with _sync:
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE intelligence_feed SET last_attempt=now() WHERE name='cisa-kev'"
            )
            await conn.commit()
        failure = ""
        for url in FEEDS:
            try:
                version, released, rows = validate_feed(await download(url))
                async with await db._connect() as conn:
                    # Reject a stale mirror and keep the last successful snapshot intact.
                    cursor = await conn.execute(
                        "SELECT released_at FROM intelligence_feed WHERE name='cisa-kev' FOR UPDATE"
                    )
                    previous = (await cursor.fetchone())[0]
                    if previous and released < previous:
                        raise ValueError("KEV release predates stored snapshot")
                    await conn.execute("UPDATE known_vulnerabilities SET active=false")
                    async with conn.cursor() as cur:
                        await cur.executemany(
                            """INSERT INTO known_vulnerabilities
                            (cve,vendor,product,title,description,required_action,date_added,due_date,ransomware)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            ON CONFLICT(cve) DO UPDATE SET vendor=excluded.vendor,product=excluded.product,
                            title=excluded.title,description=excluded.description,required_action=excluded.required_action,
                            date_added=excluded.date_added,due_date=excluded.due_date,ransomware=excluded.ransomware,
                            active=true,updated_at=now()""",
                            rows,
                        )
                    await conn.execute(
                        """UPDATE intelligence_feed SET last_success=now(),source_url=%s,
                        version=%s,released_at=%s,error='',record_count=%s WHERE name='cisa-kev'""",
                        (url, version, released, len(rows)),
                    )
                    await conn.commit()
                return {"status": "updated", "count": len(rows), "version": version}
            except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
                failure = f"{type(exc).__name__}: unable to retrieve a valid current KEV snapshot"
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE intelligence_feed SET error=%s WHERE name='cisa-kev'",
                (failure,),
            )
            await conn.commit()
        return {"status": "failed", "error": failure}


@router.get("/status")
async def status():
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM intelligence_feed WHERE name='cisa-kev'")
        feed = await cur.fetchone()
    if not feed:
        return {"state": "unavailable", "automatic": settings.intelligence_enabled}
    age = datetime.now(UTC) - feed["last_success"] if feed["last_success"] else None
    return {
        **feed,
        "state": "unavailable"
        if age is None
        else "stale"
        if age > timedelta(hours=48) or feed["error"]
        else "current",
        "automatic": settings.intelligence_enabled,
        "interval_hours": 24,
        "scope": "CISA KEV membership is not proof this asset is vulnerable or this request exploited it.",
    }


@router.get("/vulnerabilities")
async def vulnerabilities(
    q: str = Query("", max_length=120),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    query = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    where = "active AND (cve ILIKE %s OR vendor ILIKE %s OR product ILIKE %s OR title ILIKE %s)"
    async with await db._connect() as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"SELECT count(*) AS total FROM known_vulnerabilities WHERE {where}",
                (query,) * 4,
            )
            total = (await cur.fetchone())["total"]
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            await cur.execute(
                f"SELECT * FROM known_vulnerabilities WHERE {where} ORDER BY date_added DESC,cve LIMIT %s OFFSET %s",
                (*((query,) * 4), page_size, (page - 1) * page_size),
            )
            items = await cur.fetchall()
    return {"items": items, "total": total, "page": page, "pages": pages}


async def lookup(cves):
    if not cves:
        return []
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT cve,title,vendor,product,required_action,date_added FROM known_vulnerabilities WHERE active AND cve=ANY(%s)",
            (list(cves)[:20],),
        )
        return await cur.fetchall()


async def event_context(event):
    """Only exact CVE mentions in source evidence; never infer asset applicability."""
    cves = sorted(
        {value.upper() for value in CVE.findall(json.dumps(event, ensure_ascii=False))}
    )[:20]
    if not cves:
        return None
    rows = await lookup(cves)
    if not rows:
        return None
    feed = await status()
    return {
        "source": "CISA KEV",
        "snapshot_state": feed["state"],
        "version": feed.get("version"),
        "last_fetched": str(feed.get("last_success")),
        "scope": "Exact CVE mention in event, not confirmation of an exploit or vulnerable asset.",
        "matches": [
            {
                "cve": r["cve"],
                "title": r["title"][:180],
                "required_action": r["required_action"][:240],
            }
            for r in rows[:3]
        ],
    }


async def run():
    while True:
        delay = 1800
        try:
            current = await status()
            last = current.get("last_success")
            if (
                last
                and datetime.now(UTC) - last < timedelta(hours=24)
                and not current.get("error")
            ):
                delay = min(
                    86400, max(60, 86400 - (datetime.now(UTC) - last).total_seconds())
                )
            else:
                result = await sync_once()
                delay = 86400 if result["status"] == "updated" else 1800
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("Threat intelligence sync failed; keeping stored catalog")
        await asyncio.sleep(delay)
