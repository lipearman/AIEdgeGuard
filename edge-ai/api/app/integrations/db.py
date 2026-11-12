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
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS campaign_id integer;
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS queued_at timestamptz;
CREATE TABLE IF NOT EXISTS campaigns (
    id            serial PRIMARY KEY,
    title         text NOT NULL,
    source_ip     text NOT NULL DEFAULT '',
    attack_type   text NOT NULL DEFAULT '',
    severity      text NOT NULL DEFAULT 'medium',
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    incident_count int NOT NULL DEFAULT 0,
    incident_ids  jsonb NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS decisions (
    id               serial PRIMARY KEY,
    created_at       timestamptz NOT NULL DEFAULT now(),
    incident_alert_id text NOT NULL DEFAULT '',
    campaign_id      integer,
    action           text NOT NULL,
    target           text NOT NULL DEFAULT '',
    duration_seconds int NOT NULL DEFAULT 0,
    proposed_by      text NOT NULL DEFAULT 'analysis-agent',
    confidence       real NOT NULL DEFAULT 0,
    severity         text NOT NULL DEFAULT 'medium',
    policy_verdict   text NOT NULL,
    policy_reason    text NOT NULL DEFAULT '',
    policy_checks    jsonb NOT NULL DEFAULT '[]',
    status           text NOT NULL,
    executed_at      timestamptz,
    result           text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS attacks (
    id                serial PRIMARY KEY,
    created_at        timestamptz NOT NULL DEFAULT now(),
    target_host       text NOT NULL,
    attacker_ip       text NOT NULL DEFAULT '',
    plan              jsonb NOT NULL,
    results           jsonb NOT NULL,
    techniques_total  int NOT NULL DEFAULT 0,
    techniques_detected int NOT NULL DEFAULT 0,
    new_alerts        int NOT NULL DEFAULT 0
);
"""


async def init_schema() -> None:
    async with await _connect() as conn:
        await conn.execute(SCHEMA)
        # embedding dimension comes from the loaded embedding model
        await conn.execute(
            f"ALTER TABLE incidents ADD COLUMN IF NOT EXISTS "
            f"embedding vector({settings.embedding_dim})"
        )
        await conn.commit()


async def list_unembedded(limit: int = 10) -> list[dict]:
    """Analyzed incidents that have no embedding yet."""
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT alert_id, kind, severity, reason, source_ip,
                   analysis->>'attack_type' AS attack_type,
                   analysis->>'reasoning'   AS reasoning
              FROM incidents
             WHERE analysis IS NOT NULL AND embedding IS NULL
             ORDER BY id DESC LIMIT %s
            """,
            (min(limit, 100),),
        )
        rows = await cur.fetchall()
    cols = [
        "alert_id",
        "kind",
        "severity",
        "reason",
        "source_ip",
        "attack_type",
        "reasoning",
    ]
    return [dict(zip(cols, r)) for r in rows]


async def set_embedding(alert_id: str, embedding: list[float]) -> None:
    async with await _connect() as conn:
        await conn.execute(
            "UPDATE incidents SET embedding = %s::vector WHERE alert_id = %s",
            ("[" + ",".join(f"{x:.7f}" for x in embedding) + "]", alert_id),
        )
        await conn.commit()


async def search_similar(
    embedding: list[float], k: int = 3, exclude_alert_id: str | None = None
) -> list[dict]:
    """Top-k similar analyzed incidents by cosine distance (pgvector <=>)."""
    vec = "[" + ",".join(f"{x:.7f}" for x in embedding) + "]"
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT alert_id, kind, severity, reason, source_ip,
                   analysis->>'attack_type' AS attack_type,
                   1 - (embedding <=> %s::vector) AS similarity
              FROM incidents
             WHERE embedding IS NOT NULL AND alert_id <> COALESCE(%s, '')
             ORDER BY embedding <=> %s::vector
             LIMIT %s
            """,
            (vec, exclude_alert_id or "", vec, max(1, min(k, 20))),
        )
        rows = await cur.fetchall()
    cols = [
        "alert_id",
        "kind",
        "severity",
        "reason",
        "source_ip",
        "attack_type",
        "similarity",
    ]
    return [dict(zip(cols, r)) for r in rows]


async def embedding_stats() -> dict:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT count(*) FILTER (WHERE embedding IS NOT NULL) AS embedded,
                   count(*) FILTER (WHERE analysis IS NOT NULL)  AS analyzed
              FROM incidents
            """
        )
        row = await cur.fetchone()
    return {"embedded": row[0], "analyzed": row[1]}


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


async def list_unqueued(limit: int = 100) -> list[dict]:
    """Durable outbox: recover inserts whose Redis publish did not succeed."""
    async with await _connect() as conn:
        cur = await conn.execute(
            "SELECT alert_id FROM incidents WHERE analysis IS NULL AND queued_at IS NULL "
            "ORDER BY id LIMIT %s",
            (limit,),
        )
        return [{"event_id": row[0]} for row in await cur.fetchall()]


async def mark_queued(alert_id: str) -> None:
    async with await _connect() as conn:
        await conn.execute(
            "UPDATE incidents SET queued_at = now() WHERE alert_id = %s", (alert_id,)
        )
        await conn.commit()


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
        "alert_id",
        "created_at",
        "source",
        "kind",
        "severity",
        "reason",
        "source_ip",
        "event",
        "analysis",
        "analyzed_at",
    ]
    return dict(zip(cols, row))


async def list_incidents(limit: int = 50) -> list[dict]:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT id, alert_id, created_at, source_ip, kind, severity, reason,
                   source, event->'event'->'agent'->>'name' AS endpoint,
                   analysis->>'attack_type' AS attack_type,
                   (analysis IS NOT NULL) AS analyzed
              FROM incidents ORDER BY id DESC LIMIT %s
            """,
            (min(limit, 200),),
        )
        rows = await cur.fetchall()
    cols = [
        "id",
        "alert_id",
        "created_at",
        "source_ip",
        "kind",
        "severity",
        "reason",
        "source",
        "endpoint",
        "attack_type",
        "analyzed",
    ]
    return [dict(zip(cols, r)) for r in rows]


async def db_ok() -> bool:
    try:
        async with await _connect() as conn:
            await conn.execute("SELECT 1")
        return True
    except Exception:  # noqa: BLE001 — health check must not raise
        print(f"[db] health check failed: {sys.exc_info()[1]}", file=sys.stderr)
        return False


# ------------------------------------------------------------ campaigns


async def list_unclustered_analyzed() -> list[dict]:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT alert_id, source_ip, severity, reason,
                   analysis->>'attack_type' AS attack_type
              FROM incidents
             WHERE analysis IS NOT NULL AND campaign_id IS NULL
             ORDER BY id DESC LIMIT 200
            """
        )
        rows = await cur.fetchall()
    cols = ["alert_id", "source_ip", "severity", "reason", "attack_type"]
    return [dict(zip(cols, r)) for r in rows]


async def find_open_campaign(source_ip: str, attack_type: str) -> int | None:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT id FROM campaigns
             WHERE source_ip = %s AND attack_type = %s
               AND last_seen > now() - interval '24 hours'
             ORDER BY id DESC LIMIT 1
            """,
            (source_ip, attack_type),
        )
        row = await cur.fetchone()
    return row[0] if row else None


async def create_campaign(
    source_ip: str, attack_type: str, severity: str, incident_ids: list[str]
) -> int:
    title = f"{attack_type} from {source_ip} — {len(incident_ids)} incident(s)"
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            INSERT INTO campaigns (title, source_ip, attack_type, severity,
                                   incident_count, incident_ids)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                title,
                source_ip,
                attack_type,
                severity,
                len(incident_ids),
                json.dumps(incident_ids),
            ),
        )
        row = await cur.fetchone()
        await conn.execute(
            "UPDATE incidents SET campaign_id = %s WHERE alert_id = ANY(%s)",
            (row[0], incident_ids),
        )
        await conn.commit()
        return row[0]


async def add_incidents_to_campaign(campaign_id: int, alert_ids: list[str]) -> None:
    async with await _connect() as conn:
        await conn.execute(
            """
            UPDATE incidents SET campaign_id = %s
             WHERE alert_id = ANY(%s)
            """,
            (campaign_id, alert_ids),
        )
        await conn.execute(
            """
            UPDATE campaigns
               SET incident_count = incident_count + %s,
                   incident_ids = incident_ids || %s,
                   last_seen = now()
             WHERE id = %s
            """,
            (len(alert_ids), json.dumps(alert_ids), campaign_id),
        )
        await conn.commit()


async def list_campaigns(limit: int = 50) -> list[dict]:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT id, title, source_ip, attack_type, severity, first_seen,
                   last_seen, incident_count
              FROM campaigns ORDER BY last_seen DESC LIMIT %s
            """,
            (min(limit, 200),),
        )
        rows = await cur.fetchall()
    cols = [
        "id",
        "title",
        "source_ip",
        "attack_type",
        "severity",
        "first_seen",
        "last_seen",
        "incident_count",
    ]
    return [dict(zip(cols, r)) for r in rows]


# ------------------------------------------------------------ decisions


async def create_decision(
    incident_alert_id: str,
    action: str,
    target: str,
    duration_seconds: int,
    confidence: float,
    severity: str,
    policy_verdict: str,
    policy_reason: str,
    policy_checks: list,
    status: str,
) -> int:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            INSERT INTO decisions (incident_alert_id, action, target,
                duration_seconds, confidence, severity, policy_verdict,
                policy_reason, policy_checks, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                incident_alert_id,
                action,
                target,
                duration_seconds,
                confidence,
                severity,
                policy_verdict,
                policy_reason,
                json.dumps(policy_checks),
                status,
            ),
        )
        row = await cur.fetchone()
        await conn.commit()
        return row[0]


async def list_decisions(limit: int = 50) -> list[dict]:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT id, created_at, incident_alert_id, action, target,
                   duration_seconds, confidence, severity, policy_verdict,
                   policy_reason, status, executed_at, result
              FROM decisions ORDER BY id DESC LIMIT %s
            """,
            (min(limit, 200),),
        )
        rows = await cur.fetchall()
    cols = [
        "id",
        "created_at",
        "incident_alert_id",
        "action",
        "target",
        "duration_seconds",
        "confidence",
        "severity",
        "policy_verdict",
        "policy_reason",
        "status",
        "executed_at",
        "result",
    ]
    return [dict(zip(cols, r)) for r in rows]


async def get_decision(decision_id: int) -> dict | None:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT id, created_at, incident_alert_id, action, target,
                   duration_seconds, confidence, severity, policy_verdict,
                   policy_reason, policy_checks, status, executed_at, result
              FROM decisions WHERE id = %s
            """,
            (decision_id,),
        )
        row = await cur.fetchone()
    if not row:
        return None
    cols = [
        "id",
        "created_at",
        "incident_alert_id",
        "action",
        "target",
        "duration_seconds",
        "confidence",
        "severity",
        "policy_verdict",
        "policy_reason",
        "policy_checks",
        "status",
        "executed_at",
        "result",
    ]
    return dict(zip(cols, row))


async def update_decision_status(
    decision_id: int, status: str, result: str = "", expected_status: str | None = None
) -> bool:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            UPDATE decisions
               SET status = %s,
                   executed_at = CASE WHEN %s IN ('executed') THEN now()
                                      ELSE executed_at END,
                   result = %s
             WHERE id = %s AND (%s::text IS NULL OR status = %s)
            RETURNING id
            """,
            (status, status, result, decision_id, expected_status, expected_status),
        )
        row = await cur.fetchone()
        await conn.commit()
        return row is not None


async def count_recent_blocks(target: str, window_seconds: int) -> int:
    """Enforced blocks for one target inside the cooldown window (repeat guard).

    Only decisions that actually reached CrowdSec count: a proposal that was
    rejected or failed did not ban anything, so it must not start a cooldown.
    """
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT count(*) FROM decisions
             WHERE target = %s
               AND action = 'temporary_ip_block'
               AND status = 'executed'
               AND executed_at > now() - make_interval(secs => %s)
            """,
            (target, max(0, int(window_seconds))),
        )
        row = await cur.fetchone()
    return int(row[0]) if row else 0


async def list_analyzed_without_decision() -> list[dict]:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT i.alert_id, i.source_ip, i.severity, i.reason, i.analysis
              FROM incidents i
             WHERE i.analysis IS NOT NULL
               AND NOT EXISTS (
                   SELECT 1 FROM decisions d
                    WHERE d.incident_alert_id = i.alert_id)
             ORDER BY i.id DESC LIMIT 50
            """
        )
        rows = await cur.fetchall()
    cols = ["alert_id", "source_ip", "severity", "reason", "analysis"]
    out = []
    for r in rows:
        d = dict(zip(cols, r))
        # psycopg returns jsonb as parsed dicts already; be defensive
        if isinstance(d["analysis"], str):
            d["analysis"] = json.loads(d["analysis"])
        out.append(d)
    return out


# ------------------------------------------------------------ attacks


async def insert_attack(run: dict) -> int:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            INSERT INTO attacks (target_host, attacker_ip, plan, results,
                                 techniques_total, techniques_detected, new_alerts)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                run["target_host"],
                run["attacker_ip"],
                json.dumps(run["plan"], ensure_ascii=False),
                json.dumps(run["results"], ensure_ascii=False),
                run["techniques_total"],
                run["techniques_detected"],
                run["new_alerts"],
            ),
        )
        row = await cur.fetchone()
        await conn.commit()
        return row[0]


async def list_attacks(limit: int = 20) -> list[dict]:
    async with await _connect() as conn:
        cur = await conn.execute(
            """
            SELECT id, created_at, target_host, attacker_ip, techniques_total,
                   techniques_detected, new_alerts
              FROM attacks ORDER BY id DESC LIMIT %s
            """,
            (min(limit, 100),),
        )
        rows = await cur.fetchall()
    cols = [
        "id",
        "created_at",
        "target_host",
        "attacker_ip",
        "techniques_total",
        "techniques_detected",
        "new_alerts",
    ]
    return [dict(zip(cols, r)) for r in rows]


async def get_attack(attack_id: int) -> dict | None:
    async with await _connect() as conn:
        cur = await conn.execute("SELECT * FROM attacks WHERE id = %s", (attack_id,))
        row = await cur.fetchone()
        if not row:
            return None
        cols = [d[0] for d in cur.description]
    return dict(zip(cols, row))
