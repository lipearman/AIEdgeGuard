"""Append-only analyst labels and revision-bound reviewed memory, not enforcement."""

import hashlib
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field

from app.config import settings
from app.integrations import db

router = APIRouter(prefix="/api/v1/reviews", tags=["Analyst reviews"])
SCHEMA = """
CREATE TABLE IF NOT EXISTS incident_reviews (
 id bigserial PRIMARY KEY, incident_id integer NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
 revision integer NOT NULL CHECK(revision>0),
 verdict text NOT NULL CHECK(verdict IN ('true_positive','false_positive','unknown')),
 reviewer_label text NOT NULL, rationale text NOT NULL,
 corrected_attack_type text NOT NULL DEFAULT '', corrected_severity text NOT NULL DEFAULT '',
 authentication text NOT NULL, request_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(incident_id,revision), UNIQUE(incident_id,request_id)
);
CREATE OR REPLACE FUNCTION reject_review_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Analyst review history is append-only'; END;
$$;
DROP TRIGGER IF EXISTS immutable_incident_reviews ON incident_reviews;
CREATE TRIGGER immutable_incident_reviews BEFORE UPDATE OR DELETE ON incident_reviews
 FOR EACH ROW EXECUTE FUNCTION reject_review_mutation();
"""
LATEST = "SELECT DISTINCT ON (incident_id) * FROM incident_reviews ORDER BY incident_id,revision DESC"


class ReviewInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    verdict: Literal["true_positive", "false_positive", "unknown"]
    reviewer_label: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000)
    corrected_attack_type: str = Field(
        default="", max_length=160, pattern=r"^[^\x00-\x1f]*$"
    )
    corrected_severity: Literal["", "low", "medium", "high", "critical"] = ""
    expected_revision: int = Field(ge=0)
    request_id: UUID


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        # A new vector is always associated with the exact reviewed revision and model.
        await conn.execute(f"""CREATE TABLE IF NOT EXISTS reviewed_memory (
            incident_id integer PRIMARY KEY REFERENCES incidents(id) ON DELETE RESTRICT,
            review_id bigint NOT NULL REFERENCES incident_reviews(id) ON DELETE RESTRICT,
            embedding vector({settings.embedding_dim}) NOT NULL,
            embedding_model text NOT NULL,text_hash text NOT NULL,
            embedded_at timestamptz NOT NULL DEFAULT now()
        )""")
        await conn.commit()


async def save(incident_id, body):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id,analysis FROM incidents WHERE id=%s FOR UPDATE", (incident_id,)
        )
        incident = await cur.fetchone()
        if not incident:
            raise HTTPException(404, "Incident not found")
        await cur.execute(
            "SELECT * FROM incident_reviews WHERE incident_id=%s AND request_id=%s",
            (incident_id, body.request_id),
        )
        existing = await cur.fetchone()
        comparable = (
            "verdict",
            "reviewer_label",
            "rationale",
            "corrected_attack_type",
            "corrected_severity",
        )
        if existing:
            if any(existing[k] != getattr(body, k) for k in comparable):
                raise HTTPException(
                    409, "This request ID was already used for a different review"
                )
            return {"review": existing, "replayed": True}
        await cur.execute(
            "SELECT COALESCE(max(revision),0) AS revision FROM incident_reviews WHERE incident_id=%s",
            (incident_id,),
        )
        revision = (await cur.fetchone())["revision"]
        if body.expected_revision != revision:
            raise HTTPException(
                409,
                "Review changed since you opened it. Reload the latest revision before saving.",
            )
        await cur.execute(
            """INSERT INTO incident_reviews
            (incident_id,revision,verdict,reviewer_label,rationale,corrected_attack_type,corrected_severity,authentication,request_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (
                incident_id,
                revision + 1,
                body.verdict,
                body.reviewer_label,
                body.rationale,
                body.corrected_attack_type,
                body.corrected_severity,
                "shared_operation_key"
                if settings.operation_key
                else "development_ungated",
                body.request_id,
            ),
        )
        review = await cur.fetchone()
        await conn.commit()
    return {"review": review, "replayed": False}


@router.get("/stats")
async def stats():
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            f"""WITH latest AS ({LATEST}) SELECT
            (SELECT count(*) FROM incidents) AS incidents,
            count(*) AS reviewed,
            count(*) FILTER(WHERE verdict='true_positive') AS true_positive,
            count(*) FILTER(WHERE verdict='false_positive') AS false_positive,
            count(*) FILTER(WHERE verdict='unknown') AS unknown,
            count(*) FILTER(WHERE verdict='true_positive' AND i.analysis IS NOT NULL) AS eligible,
            count(*) FILTER(WHERE verdict='true_positive' AND i.analysis IS NOT NULL AND m.review_id=r.id
                AND m.embedding_model=%s) AS memory_ready
            FROM latest r JOIN incidents i ON i.id=r.incident_id LEFT JOIN reviewed_memory m ON m.incident_id=i.id""",
            (settings.embedding_model,),
        )
        result = await cur.fetchone()
    return {
        **result,
        "unreviewed": result["incidents"] - result["reviewed"],
        "memory_policy": "Only latest true-positive reviews with completed incident analysis and a matching revision/model vector are retrieved.",
        "identity_scope": "Operation Key authorizes writes; reviewer labels are self-declared, not authenticated user identities.",
    }


@router.get("/{incident_id}")
async def detail(
    incident_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    async with await db._connect() as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT id,alert_id,analysis FROM incidents WHERE id=%s", (incident_id,)
            )
            incident = await cur.fetchone()
            if not incident:
                raise HTTPException(404, "Incident not found")
            await cur.execute(
                "SELECT count(*) AS total FROM incident_reviews WHERE incident_id=%s",
                (incident_id,),
            )
            total = (await cur.fetchone())["total"]
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            await cur.execute(
                "SELECT * FROM incident_reviews WHERE incident_id=%s ORDER BY revision DESC LIMIT %s OFFSET %s",
                (incident_id, page_size, (page - 1) * page_size),
            )
            items = await cur.fetchall()
            await cur.execute(
                "SELECT * FROM incident_reviews WHERE incident_id=%s ORDER BY revision DESC LIMIT 1",
                (incident_id,),
            )
            current = await cur.fetchone()
            await cur.execute(
                "SELECT review_id,embedding_model,embedded_at,text_hash FROM reviewed_memory WHERE incident_id=%s",
                (incident_id,),
            )
            memory = await cur.fetchone()
    eligible = bool(
        current and current["verdict"] == "true_positive" and incident["analysis"]
    )
    ready = bool(
        eligible
        and memory
        and memory["review_id"] == current["id"]
        and memory["embedding_model"] == settings.embedding_model
    )
    return {
        "incident_id": incident_id,
        "alert_id": incident["alert_id"],
        "current": current,
        "revision": current["revision"] if current else 0,
        "items": items,
        "page": page,
        "pages": pages,
        "total": total,
        "memory": {
            "eligible": eligible,
            "ready": ready,
            "embedded_at": memory["embedded_at"] if ready else None,
            "state": "ready"
            if ready
            else "pending_embedding"
            if eligible
            else "analysis_pending"
            if current and current["verdict"] == "true_positive"
            else "excluded",
        },
        "identity_scope": "Reviewer label is self-declared; authorization uses the shared Operation Key. Raw evidence, AI analysis and decisions are not edited.",
    }


@router.get("/history/{review_id}")
async def historical_review(review_id: int):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM incident_reviews WHERE id=%s", (review_id,))
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Review revision not found")
    return row


async def list_pending(limit):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            f"""WITH latest AS ({LATEST}) SELECT i.id AS incident_id,i.alert_id,i.kind,i.reason,i.source_ip,
            COALESCE(NULLIF(r.corrected_severity,''),i.severity) AS severity,
            COALESCE(NULLIF(r.corrected_attack_type,''),i.analysis->>'attack_type') AS attack_type,
            i.analysis->>'reasoning' AS reasoning,r.id AS review_id,r.revision AS review_revision,r.rationale AS review_rationale
            FROM latest r JOIN incidents i ON i.id=r.incident_id LEFT JOIN reviewed_memory m ON m.incident_id=i.id
            WHERE r.verdict='true_positive' AND i.analysis IS NOT NULL
              AND (m.review_id IS DISTINCT FROM r.id OR m.embedding_model IS DISTINCT FROM %s)
            ORDER BY r.id LIMIT %s""",
            (settings.embedding_model, max(1, min(limit, 100))),
        )
        return await cur.fetchall()


async def set_memory(row, embedding, text):
    vec = "[" + ",".join(f"{x:.7f}" for x in embedding) + "]"
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT id FROM incidents WHERE id=%s FOR UPDATE", (row["incident_id"],)
        )
        if not await cur.fetchone():
            return False
        await cur.execute(
            "SELECT id,verdict FROM incident_reviews WHERE incident_id=%s ORDER BY revision DESC LIMIT 1",
            (row["incident_id"],),
        )
        current = await cur.fetchone()
        if (
            not current
            or current["id"] != row["review_id"]
            or current["verdict"] != "true_positive"
        ):
            return False  # An in-flight embedding may never resurrect an excluded/revised record.
        await cur.execute(
            """INSERT INTO reviewed_memory(incident_id,review_id,embedding,embedding_model,text_hash)
            VALUES (%s,%s,%s::vector,%s,%s) ON CONFLICT(incident_id) DO UPDATE SET
            review_id=excluded.review_id,embedding=excluded.embedding,embedding_model=excluded.embedding_model,
            text_hash=excluded.text_hash,embedded_at=now()""",
            (
                row["incident_id"],
                row["review_id"],
                vec,
                settings.embedding_model,
                hashlib.sha256(text.encode()).hexdigest(),
            ),
        )
        await conn.commit()
    return True


async def search_memory(embedding, k, exclude_alert_id=None):
    vec = "[" + ",".join(f"{x:.7f}" for x in embedding) + "]"
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            f"""WITH latest AS ({LATEST}) SELECT i.id AS incident_id,i.alert_id,i.kind,i.reason,i.source_ip,
            COALESCE(NULLIF(r.corrected_severity,''),i.severity) AS severity,
            COALESCE(NULLIF(r.corrected_attack_type,''),i.analysis->>'attack_type') AS attack_type,
            r.id AS review_id,r.revision AS review_revision,r.verdict AS review_verdict,
            r.rationale AS review_rationale,r.reviewer_label,r.authentication,
            1-(m.embedding <=> %s::vector) AS similarity
            FROM reviewed_memory m JOIN incidents i ON i.id=m.incident_id JOIN latest r ON r.incident_id=i.id
            WHERE r.verdict='true_positive' AND m.review_id=r.id AND m.embedding_model=%s
              AND i.analysis IS NOT NULL AND i.alert_id<>%s
            ORDER BY m.embedding <=> %s::vector,i.id LIMIT %s""",
            (
                vec,
                settings.embedding_model,
                exclude_alert_id or "",
                vec,
                max(1, min(k, 20)),
            ),
        )
        return await cur.fetchall()


async def has_memory(exclude_alert_id=None):
    async with await db._connect() as conn:
        cur = await conn.execute(
            f"""WITH latest AS ({LATEST}) SELECT EXISTS (
            SELECT 1 FROM reviewed_memory m JOIN latest r ON r.incident_id=m.incident_id
            JOIN incidents i ON i.id=m.incident_id WHERE r.verdict='true_positive'
            AND m.review_id=r.id AND m.embedding_model=%s AND i.analysis IS NOT NULL
            AND i.alert_id<>%s)""",
            (settings.embedding_model, exclude_alert_id or ""),
        )
        return (await cur.fetchone())[0]
