"""Paginated operator views. Table/column names are fixed; filters are bound values."""

import json
import math

from psycopg.rows import dict_row

from app.integrations import db

SCHEMA = """
CREATE TABLE IF NOT EXISTS gateway_requests (
 id bigserial PRIMARY KEY, fingerprint text UNIQUE NOT NULL,
 observed_at timestamptz NOT NULL, source_ip text NOT NULL DEFAULT '',
 method text NOT NULL DEFAULT '', path text NOT NULL DEFAULT '',
 host text NOT NULL DEFAULT '', status integer NOT NULL DEFAULT 0,
 duration_ns bigint NOT NULL DEFAULT 0, router text NOT NULL DEFAULT '',
 raw jsonb NOT NULL, collected_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS gateway_requests_observed ON gateway_requests(observed_at);
"""

SPECS = {
    "requests": (
        "gateway_requests",
        "id,observed_at,source_ip,method,path,host,status,duration_ns,router",
        ["path", "host", "source_ip", "method", "router"],
    ),
    "incidents": (
        "incidents",
        "id,alert_id,created_at,source,source_ip,kind,severity,reason,analysis->>'attack_type' AS attack_type,(analysis IS NOT NULL) AS analyzed,event->'event'->'agent'->>'name' AS endpoint",
        ["alert_id", "source_ip", "reason", "source"],
    ),
    "campaigns": (
        "campaigns",
        "id,title,source_ip,attack_type,severity,first_seen,last_seen,incident_count",
        ["title", "source_ip", "attack_type"],
    ),
    "decisions": (
        "decisions",
        "id,created_at,incident_alert_id,action,target,duration_seconds,confidence,severity,policy_verdict,policy_reason,status,executed_at,result",
        ["incident_alert_id", "target", "action", "policy_reason", "status"],
    ),
    "approvals": (
        "decisions",
        "id,created_at,incident_alert_id,action,target,duration_seconds,confidence,severity,policy_verdict,policy_reason,status",
        ["incident_alert_id", "target", "action", "policy_reason"],
    ),
    "attacks": (
        "attacks",
        "id,created_at,target_host,attacker_ip,techniques_total,techniques_detected,new_alerts",
        ["target_host", "attacker_ip"],
    ),
}


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


async def insert_requests(rows: list[dict]):
    if not rows:
        return
    async with await db._connect() as conn:
        async with conn.cursor() as cursor:
            await cursor.executemany(
                """INSERT INTO gateway_requests(fingerprint,observed_at,source_ip,method,path,host,status,duration_ns,router,raw)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(fingerprint) DO NOTHING""",
                [
                    (
                        r["fingerprint"],
                        r["observed_at"],
                        r["source_ip"],
                        r["method"],
                        r["path"],
                        r["host"],
                        r["status"],
                        r["duration_ns"],
                        r["router"],
                        json.dumps(r["raw"], ensure_ascii=False),
                    )
                    for r in rows
                ],
            )
        await conn.commit()


async def prune_requests(max_rows: int, days: int):
    async with await db._connect() as conn:
        await conn.execute(
            "DELETE FROM gateway_requests WHERE observed_at < now()-make_interval(days=>%s)",
            (max(1, days),),
        )
        await conn.execute(
            "DELETE FROM gateway_requests WHERE id < (SELECT id FROM gateway_requests ORDER BY id DESC OFFSET %s LIMIT 1)",
            (max(1, max_rows) - 1,),
        )
        await conn.commit()


async def page(
    kind: str,
    page_number: int,
    page_size: int,
    query: str = "",
    source: str = "",
    severity: str = "",
    status: str = "",
    snapshot: int | None = None,
):
    table, columns, searchable = SPECS[kind]
    clauses, values = ["TRUE"], []
    if kind == "approvals":
        clauses.append("status='pending_approval'")
    if query:
        pattern = (
            "%"
            + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            + "%"
        )
        clauses.append(
            "(" + " OR ".join(f"{column} ILIKE %s" for column in searchable) + ")"
        )
        values.extend([pattern] * len(searchable))
    if source and kind == "incidents":
        clauses.append("source=%s")
        values.append(source)
    if severity and kind in ("incidents", "campaigns", "decisions", "approvals"):
        clauses.append("severity=%s")
        values.append(severity)
    if status and kind == "requests":
        if status in ("2xx", "3xx", "4xx", "5xx"):
            clauses.append("status >= %s AND status < %s")
            values.extend([int(status[0]) * 100, (int(status[0]) + 1) * 100])
        elif status.isdigit() and 100 <= int(status) <= 599:
            clauses.append("status=%s")
            values.append(int(status))
        else:
            raise ValueError("invalid HTTP status filter")
    elif status and kind == "decisions":
        clauses.append("status=%s")
        values.append(status)
    async with await db._connect() as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        async with conn.cursor(row_factory=dict_row) as cursor:
            if snapshot is None:
                await cursor.execute(
                    f"SELECT COALESCE(max(id),0) AS anchor FROM {table}"
                )
                snapshot = (await cursor.fetchone())["anchor"]
            clauses.append("id <= %s")
            values.append(snapshot)
            where = " AND ".join(clauses)
            await cursor.execute(
                f"SELECT count(*) AS total FROM {table} WHERE {where}", values
            )
            total = (await cursor.fetchone())["total"]
            pages = max(1, math.ceil(total / page_size))
            page_number = min(page_number, pages)
            await cursor.execute(
                f"SELECT {columns} FROM {table} WHERE {where} ORDER BY id DESC LIMIT %s OFFSET %s",
                [*values, page_size, (page_number - 1) * page_size],
            )
            items = await cursor.fetchall()
    return {
        "items": items,
        "total": total,
        "page": page_number,
        "page_size": page_size,
        "pages": pages,
        "snapshot": snapshot,
    }


async def detail(kind: str, item_id: int):
    table = SPECS[kind][0]
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cursor:
        await cursor.execute(f"SELECT * FROM {table} WHERE id=%s", (item_id,))
        result = await cursor.fetchone()
    if result and kind == "requests":
        result["capture"] = {
            "body_captured": False,
            "pcap_captured": False,
            "format": "Traefik HTTP access log",
            "headers": {
                k.removeprefix("request_"): v
                for k, v in result["raw"].items()
                if k.startswith("request_")
            },
        }
    return result


async def summary():
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cursor:
        await cursor.execute("""SELECT
          (SELECT count(*) FROM incidents) AS incidents,
          (SELECT count(*) FROM incidents WHERE analysis IS NOT NULL) AS analyzed,
          (SELECT count(*) FROM campaigns) AS campaigns,
          (SELECT count(*) FROM decisions WHERE status='pending_approval') AS pending,
          (SELECT count(*) FROM decisions WHERE status='executed') AS executed,
          (SELECT count(*) FROM attacks) AS attacks,
          (SELECT count(*) FROM gateway_requests) AS requests,
          (SELECT count(*) FROM gateway_requests WHERE status=403) AS returned_403,
          (SELECT min(observed_at) FROM gateway_requests) AS requests_since,
          (SELECT max(observed_at) FROM gateway_requests) AS requests_latest""")
        return await cursor.fetchone()
