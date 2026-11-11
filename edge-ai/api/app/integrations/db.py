"""PostgreSQL access (async psycopg3, fresh connection per operation).

Traffic volume is low (security events), so per-op connections keep the code
simple and robust; a pool can be added if volume ever justifies it.

Schema (Phase 4): incidents holds one row per CrowdSec alert.
- alert_id unique  -> dedupe across watcher restarts (INSERT ... ON CONFLICT)
- analysis jsonb   -> filled by the worker after the Analysis Agent runs
- (pgvector)       -> phase 9 will add an embedding column; extension enabled now
"""

import json
import sys

import psycopg

from app.config import settings

SCHEMA = """
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE IF NOT EXISTS incidents (
    id          serial PRIMARY KEY,
    alert_id    text UNIQUE NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    source      text NOT NULL,
    kind        text NOT NULL,
    severity    text NOT NULL DEFAULT 'medium',
    reason      text NOT NULL DEFAULT '',
    source_ip   text NOT NULL DEFAULT '',
    event       jsonb NOT NULL,
    analysis    jsonb,
    analyzed_at timestamptz
);
"""


async def init_schema() -> None:
    async with await _connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


async def _connect() -> psycopg.AsyncConnection:
    return await psycopg.AsyncConnection.connect(
        settings.database_url, connect_timeout=10, autocommit=False
    )


async def insert_incident(alert: dict) -> int | None:
    """Insert one normalized alert. Returns row id if NEW, None if duplicate."""
    alert_id = alert["alert_id"]
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            INSERT INTO incidents (alert_id, source, kind, severity, reason, source_ip, event)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (alert_id) DO NOTHING
            RETURNING id
            """,
            (
                alert_id,
                alert["source"],
                alert["kind"],
                alert["severity"],
                alert["reason"],
                alert["source_ip"],
                json.dumps(alert, ensure_ascii=False),
            ),
        )
        row = await cur.fetchone()
        await conn.commit()
        return row[0] if row else None


async def set_analysis(alert_id: str, analysis: dict, force: bool = False) -> bool:
    """Store the Analysis Agent result.

    force=False: only fill empty analyses (first write wins).
    force=True:  overwrite (used for deterministic fallback corrections).
    Returns False if nothing was updated (e.g. already analyzed).
    """
    cond = "TRUE" if force else "analysis IS NULL"
    async with await _connect() as conn:
        cur = await conn.execute(
            f"""
            UPDATE incidents
               SET analysis = %s, analyzed_at = now()
             WHERE alert_id = %s AND {cond}
            RETURNING id
            """,
            (json.dumps(analysis, ensure_ascii=False), alert_id),
        )
        row = await cur.fetchone()
        await conn.commit()
        return row is not None


async def get_incident(alert_id: str) -> dict | None:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT alert_id, created_at, source, kind, severity, reason,
                   source_ip, event, analysis, analyzed_at
              FROM incidents WHERE alert_id = %s
            """,
            (alert_id,),
        )
        row = await cur.fetchone()
    if not row:
        return None
    cols = [
        "alert_id", "created_at", "source", "kind", "severity", "reason",
        "source_ip", "event", "analysis", "analyzed_at",
    ]
    return dict(zip(cols, row))


async def list_incidents(limit: int = 50) -> list[dict]:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT id, alert_id, created_at, source, kind, severity, reason,
                   source_ip, (analysis IS NOT NULL) AS analyzed
              FROM incidents ORDER BY id DESC LIMIT %s
            """,
            (min(limit, 200),),
        )
        rows = await cur.fetchall()
    cols = ["id", "alert_id", "created_at", "source", "kind", "severity",
            "reason", "source_ip", "analyzed"]
    return [dict(zip(cols, r)) for r in rows]


async def db_ok() -> bool:
    try:
        async with await _connect() as conn:
            await conn.execute("SELECT 1")
        return True
    except Exception:  # noqa: BLE001 — health check must not raise
        print(f"[db] health check failed: {sys.exc_info()[1]}", file=sys.stderr)
        return False
