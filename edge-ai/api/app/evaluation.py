"""Offline, revision-pinned HTTP volume evaluation. Never invokes enforcement/LLMs."""

import hashlib
import json
import math
import secrets
import statistics
from bisect import bisect_left
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.integrations import db

router = APIRouter(prefix="/api/v1/evaluation", tags=["Offline evaluation"])
VERSION = "http-volume-replay-v1-20261121"
IMPLEMENTATION_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
SCOPE = (
    "Operator-labeled HTTP host/router volume windows only; not general attack detection. "
    "Collector continuity is prospective, not proof of upstream log completeness. "
    "No automatic action, model selection or production threshold change."
)
SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic_collection_ticks (
 observed_at timestamptz PRIMARY KEY, interval_start timestamptz,
 state text NOT NULL, CHECK(interval_start IS NULL OR interval_start<observed_at)
);
CREATE TABLE IF NOT EXISTS evaluation_datasets (
 id uuid PRIMARY KEY, input_hash text NOT NULL, specification jsonb NOT NULL,
 snapshot jsonb NOT NULL, content_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evaluation_labels (
 id bigserial PRIMARY KEY, dataset_id uuid NOT NULL REFERENCES evaluation_datasets(id),
 window_index integer NOT NULL, revision integer NOT NULL,
 label text NOT NULL CHECK(label IN ('normal','lab_attack','unknown')),
 declared_by text NOT NULL, rationale text NOT NULL, authentication text NOT NULL,
 request_id uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(dataset_id,window_index,revision), UNIQUE(dataset_id,request_id)
);
CREATE TABLE IF NOT EXISTS evaluation_runs (
 id uuid PRIMARY KEY, dataset_id uuid NOT NULL REFERENCES evaluation_datasets(id),
 input_hash text NOT NULL, report jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE FUNCTION reject_evaluation_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Evaluation history is append-only'; END; $$;
DROP TRIGGER IF EXISTS immutable_evaluation_datasets ON evaluation_datasets;
CREATE TRIGGER immutable_evaluation_datasets BEFORE UPDATE OR DELETE ON evaluation_datasets
 FOR EACH ROW EXECUTE FUNCTION reject_evaluation_mutation();
DROP TRIGGER IF EXISTS immutable_evaluation_labels ON evaluation_labels;
CREATE TRIGGER immutable_evaluation_labels BEFORE UPDATE OR DELETE ON evaluation_labels
 FOR EACH ROW EXECUTE FUNCTION reject_evaluation_mutation();
DROP TRIGGER IF EXISTS immutable_evaluation_runs ON evaluation_runs;
CREATE TRIGGER immutable_evaluation_runs BEFORE UPDATE OR DELETE ON evaluation_runs
 FOR EACH ROW EXECUTE FUNCTION reject_evaluation_mutation();
"""


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DatasetInput(Input):
    host: str = Field(min_length=1, max_length=255, pattern=r"^[^\x00-\x1f]+$")
    router: str = Field(max_length=255, pattern=r"^[^\x00-\x1f]*$")
    start: datetime
    end: datetime
    declared_by: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000, pattern=r"^[^\x00]*$")

    @model_validator(mode="after")
    def validate_range(self):
        for value in (self.start, self.end):
            if value.tzinfo is None or value.timestamp() % 300:
                raise ValueError("Use timezone-aware five-minute boundaries")
        self.start = self.start.astimezone(UTC)
        self.end = self.end.astimezone(UTC)
        if not timedelta(hours=5) <= self.end - self.start <= timedelta(days=7):
            raise ValueError("Dataset range must be 5 hours to 7 days")
        if self.end > datetime.now(UTC) - timedelta(minutes=10):
            raise ValueError("Wait at least 10 minutes after the final window")
        return self


class LabelInput(Input):
    window_index: int = Field(ge=0, le=2015)
    expected_revision: int = Field(ge=0)
    label: Literal["normal", "lab_attack", "unknown"]
    declared_by: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000, pattern=r"^[^\x00]*$")
    request_id: UUID


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


async def record_tick(observed_at, interval_start, state):
    if (
        interval_start is not None
        and not 0 < (observed_at - interval_start).total_seconds() <= 15
    ):
        interval_start = None
        state = "invalid_interval"
    async with await db._connect() as conn:
        await conn.execute(
            "INSERT INTO traffic_collection_ticks VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
            (observed_at, interval_start, state),
        )
        await conn.commit()


def covered_seconds(start, end, intervals):
    """Union (not sum): overlapping collectors must not fabricate coverage."""
    cursor, seconds = start, 0.0
    for left, right in sorted(intervals):
        left, right = max(left, start, cursor), min(right, end)
        if right > left:
            seconds += (right - left).total_seconds()
            cursor = right
    return round(seconds, 6)


async def snapshot(identity, body):
    specification = body.model_dump(mode="json")
    input_hash = digest(specification)
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Serialize creation/label/replay; one transaction pins the retained rows/ticks.
        await cur.execute("SELECT pg_advisory_xact_lock(84320114)")
        await cur.execute("SELECT * FROM evaluation_datasets WHERE id=%s", (identity,))
        existing = await cur.fetchone()
        if existing:
            if existing["input_hash"] != input_hash:
                raise HTTPException(409, "Dataset ID already has different inputs")
            return existing
        await cur.execute(
            "LOCK TABLE gateway_requests,traffic_collection_ticks IN SHARE MODE"
        )
        await cur.execute(
            """SELECT floor(extract(epoch FROM observed_at)/300)::bigint AS bucket,
          count(*)::int AS requests, count(*) FILTER(WHERE status>=400)::int AS errors,
          max(id) AS max_request_id, max(collected_at) AS last_collected_at,
          array_agg(fingerprint ORDER BY fingerprint) AS members
          FROM gateway_requests WHERE host=%s AND router=%s AND observed_at>=%s AND observed_at<%s
          GROUP BY bucket ORDER BY bucket""",
            (body.host, body.router, body.start, body.end),
        )
        aggregates = {int(r["bucket"]): r for r in await cur.fetchall()}
        await cur.execute(
            """SELECT interval_start,observed_at FROM traffic_collection_ticks
          WHERE interval_start IS NOT NULL AND observed_at>%s AND interval_start<%s ORDER BY interval_start""",
            (body.start, body.end),
        )
        ticks = [(r["interval_start"], r["observed_at"]) for r in await cur.fetchall()]
        starts = [left for left, _ in ticks]
        # Retention deletion is not evidence for a genuine zero-count window.
        await cur.execute("SELECT min(collected_at) AS earliest FROM gateway_requests")
        earliest = (await cur.fetchone())["earliest"]
        windows = []
        for i in range(int((body.end - body.start).total_seconds() / 300)):
            start = body.start + timedelta(seconds=i * 300)
            end = start + timedelta(seconds=300)
            row = aggregates.get(int(start.timestamp()) // 300, {})
            candidates = ticks[
                bisect_left(starts, start - timedelta(seconds=15)) : bisect_left(
                    starts, end
                )
            ]
            coverage = covered_seconds(start, end, candidates)
            retained = earliest is not None and earliest <= start
            windows.append(
                {
                    "index": i,
                    "start": start.isoformat(),
                    "end": end.isoformat(),
                    "requests": row.get("requests", 0),
                    "errors": row.get("errors", 0),
                    "membership_sha256": digest(row.get("members", [])),
                    "max_request_id": row.get("max_request_id"),
                    "last_collected_at": str(row.get("last_collected_at"))
                    if row
                    else None,
                    "collector_covered_seconds": coverage,
                    "eligible": coverage >= 300 and retained,
                    "reason": "eligible"
                    if coverage >= 300 and retained
                    else "collector_gap_or_retention_unknown",
                }
            )
        result = {
            "version": VERSION,
            "scope": SCOPE,
            "windows": windows,
            "late_arrivals": "Excluded after snapshot creation; resnapshot to observe changes",
            "authentication": authentication(),
            "created_at": datetime.now(UTC).isoformat(),
        }
        await cur.execute(
            """INSERT INTO evaluation_datasets(id,input_hash,specification,snapshot,content_hash)
          VALUES (%s,%s,%s::jsonb,%s::jsonb,%s) RETURNING *""",
            (
                identity,
                input_hash,
                json.dumps(specification),
                json.dumps(result),
                digest(result),
            ),
        )
        saved = await cur.fetchone()
        await conn.commit()
        return saved


def authentication():
    from app.config import settings

    return (
        "shared_operation_key" if settings.operation_key else "operation_key_disabled"
    )


async def save_label(identity, body):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT pg_advisory_xact_lock(84320114)")
        await cur.execute(
            "SELECT snapshot FROM evaluation_datasets WHERE id=%s", (identity,)
        )
        dataset = await cur.fetchone()
        if not dataset or body.window_index >= len(dataset["snapshot"]["windows"]):
            raise HTTPException(404, "Dataset/window not found")
        await cur.execute(
            "SELECT * FROM evaluation_labels WHERE dataset_id=%s AND request_id=%s",
            (identity, body.request_id),
        )
        existing = await cur.fetchone()
        if existing:
            if any(
                existing[k] != getattr(body, k)
                for k in ("window_index", "label", "declared_by", "rationale")
            ):
                raise HTTPException(
                    409, "Request ID already used for a different label"
                )
            return existing
        await cur.execute(
            "SELECT COALESCE(max(revision),0) AS revision FROM evaluation_labels WHERE dataset_id=%s AND window_index=%s",
            (identity, body.window_index),
        )
        revision = (await cur.fetchone())["revision"]
        if revision != body.expected_revision:
            raise HTTPException(409, "Label changed; reload before resubmitting")
        await cur.execute(
            """INSERT INTO evaluation_labels(dataset_id,window_index,revision,label,
          declared_by,rationale,authentication,request_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (
                identity,
                body.window_index,
                revision + 1,
                body.label,
                body.declared_by,
                body.rationale,
                authentication(),
                body.request_id,
            ),
        )
        saved = await cur.fetchone()
        await conn.commit()
        return saved


def metric(predictions):
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "excluded": 0}
    for actual, predicted in predictions:
        if actual not in ("normal", "lab_attack") or predicted is None:
            counts["excluded"] += 1
        else:
            counts[
                ("t" if predicted == (actual == "lab_attack") else "f")
                + ("p" if predicted else "n")
            ] += 1
    positives, negatives = counts["tp"] + counts["fn"], counts["tn"] + counts["fp"]
    enough = positives >= 5 and negatives >= 20
    return {
        **counts,
        "state": "descriptive_only" if enough else "insufficient_labeled_test_data",
        "recall": counts["tp"] / positives if enough else None,
        "false_positive_rate": counts["fp"] / negatives if enough else None,
        "normal_windows": negatives,
        "lab_attack_windows": positives,
        "scope": "Window-level operator labels; correlated samples, not a generalization or SLA claim",
    }


def replay(dataset, labels):
    """Fixed parameters; training only in the past. Test labels never enter detector state."""
    windows = dataset["snapshot"]["windows"]
    train_end, test_start = len(windows) * 3 // 5, len(windows) * 4 // 5
    truth = {r["window_index"]: r["label"] for r in labels}
    train = windows[:train_end]
    report = {
        "algorithm_version": VERSION,
        "implementation_sha256": IMPLEMENTATION_SHA256,
        "dataset_id": str(dataset["id"]),
        "dataset_sha256": dataset["content_hash"],
        "scope": SCOPE,
        "parameters": {
            "lambda": 0.2,
            "k": 3,
            "minimum_volume": 20,
            "median_score": 6,
            "median_ratio": 3,
        },
        "split": {
            "train": [0, train_end],
            "calibration": [train_end, test_start],
            "test": [test_start, len(windows)],
            "end_exclusive": True,
            "policy": "Chronological 60/20/20, no tuning; frozen training statistics",
        },
        "label_revisions": [
            {
                k: str(r[k]) if k in ("id", "created_at") else r[k]
                for k in (
                    "id",
                    "window_index",
                    "revision",
                    "label",
                    "declared_by",
                    "rationale",
                    "authentication",
                    "created_at",
                )
            }
            for r in labels
        ],
    }
    if len(train) < 12 or any(
        not w["eligible"] or truth.get(w["index"]) != "normal" for w in train
    ):
        return {
            **report,
            "state": "needs_complete_normal_training",
            "reason": "Every training window must have collector coverage, retained history and an explicit normal label; minimum 12 windows",
            "metrics": None,
            "predictions": [],
        }
    values = [w["requests"] for w in train]
    median, mean = statistics.median(values), statistics.mean(values)
    mad = statistics.median(abs(x - median) for x in values)
    robust_scale = max(3, math.sqrt(median), 1.4826 * mad)
    sigma = max(3, math.sqrt(mean), statistics.pstdev(values))
    report["training_statistics"] = {
        "median": median,
        "mean": mean,
        "mad": mad,
        "sigma_with_floor": sigma,
    }
    z, age, predictions = mean, 0, []
    for w in windows[train_end:]:
        if not w["eligible"]:
            z, age = mean, 0
            base, ewma = None, None
        else:
            x = w["requests"]
            base = x >= 20 and x >= 3 * median and (x - median) / robust_scale >= 6
            z, age = 0.2 * x + 0.8 * z, age + 1
            upper = mean + 3 * sigma * math.sqrt(0.2 / 1.8 * (1 - 0.8 ** (2 * age)))
            ewma = x >= 20 and z > upper
        predictions.append(
            {
                "index": w["index"],
                "split": "test" if w["index"] >= test_start else "calibration",
                "label": truth.get(w["index"], "unknown"),
                "median_mad": base,
                "ewma": ewma,
            }
        )
    report.update(state="replayed", predictions=predictions, metrics={})
    for split in ("calibration", "test"):
        report["metrics"][split] = {
            method: metric(
                [(p["label"], p[method]) for p in predictions if p["split"] == split]
            )
            for method in ("median_mad", "ewma")
        }
    return report


async def run_replay(identity, run_id):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT pg_advisory_xact_lock(84320114)")
        await cur.execute("SELECT * FROM evaluation_runs WHERE id=%s", (run_id,))
        existing = await cur.fetchone()
        if existing:
            if existing["dataset_id"] != identity:
                raise HTTPException(409, "Run ID belongs to another dataset")
            return existing
        await cur.execute("SELECT * FROM evaluation_datasets WHERE id=%s", (identity,))
        dataset = await cur.fetchone()
        if not dataset:
            raise HTTPException(404, "Dataset not found")
        await cur.execute(
            "SELECT DISTINCT ON(window_index) * FROM evaluation_labels WHERE dataset_id=%s ORDER BY window_index,revision DESC",
            (identity,),
        )
        labels = await cur.fetchall()
        report = replay(dataset, labels)
        report["created_at"] = datetime.now(UTC).isoformat()
        report["authentication"] = authentication()
        await cur.execute(
            "INSERT INTO evaluation_runs VALUES (%s,%s,%s,%s::jsonb,now()) RETURNING *",
            (
                run_id,
                identity,
                digest(
                    {
                        "dataset": dataset["content_hash"],
                        "labels": [r["id"] for r in labels],
                        "version": VERSION,
                    }
                ),
                json.dumps(report),
            ),
        )
        saved = await cur.fetchone()
        await conn.commit()
        return saved


async def operation_key(x_operation_key: str | None = Header(None)):
    from app.config import settings

    if settings.operation_key and not secrets.compare_digest(
        x_operation_key or "", settings.operation_key
    ):
        raise HTTPException(403, "Operation key required")


@router.put("/datasets/{identity}", dependencies=[Depends(operation_key)])
async def create_dataset(identity: UUID, body: DatasetInput):
    return await snapshot(identity, body)


@router.post("/datasets/{identity}/labels", dependencies=[Depends(operation_key)])
async def label_window(identity: UUID, body: LabelInput):
    return await save_label(identity, body)


@router.post(
    "/datasets/{identity}/runs/{run_id}", dependencies=[Depends(operation_key)]
)
async def create_run(identity: UUID, run_id: UUID):
    return await run_replay(identity, run_id)


@router.get("/datasets")
async def datasets(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=50)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT count(*) AS total FROM evaluation_datasets")
        total = (await cur.fetchone())["total"]
        await cur.execute(
            "SELECT id,specification,content_hash,created_at FROM evaluation_datasets ORDER BY created_at DESC,id LIMIT %s OFFSET %s",
            (page_size, (page - 1) * page_size),
        )
        return {
            "items": await cur.fetchall(),
            "total": total,
            "page": page,
            "scope": SCOPE,
        }


@router.get("/segments")
async def segments(page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=50)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        await cur.execute(
            "SELECT count(*) AS total FROM (SELECT host,router FROM gateway_requests WHERE host<>'' GROUP BY host,router) s"
        )
        total = (await cur.fetchone())["total"]
        await cur.execute(
            """SELECT host,router,count(*)::int AS requests,min(observed_at) AS first_seen,
            max(observed_at) AS last_seen FROM gateway_requests WHERE host<>'' GROUP BY host,router
            ORDER BY host,router LIMIT %s OFFSET %s""",
            (page_size, (page - 1) * page_size),
        )
        return {
            "items": await cur.fetchall(),
            "total": total,
            "page": page,
            "scope": "Retained observed HTTP host/router pairs, not a verified inventory or continuity guarantee",
        }


@router.get("/datasets/{identity}/runs")
async def dataset_runs(
    identity: UUID, page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=50)
):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        await cur.execute(
            "SELECT count(*) AS total FROM evaluation_runs WHERE dataset_id=%s",
            (identity,),
        )
        total = (await cur.fetchone())["total"]
        await cur.execute(
            "SELECT id,created_at,report->>'state' AS state FROM evaluation_runs WHERE dataset_id=%s ORDER BY created_at DESC,id LIMIT %s OFFSET %s",
            (identity, page_size, (page - 1) * page_size),
        )
        return {"items": await cur.fetchall(), "total": total, "page": page}


@router.get("/datasets/{identity}")
async def detail(identity: UUID):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM evaluation_datasets WHERE id=%s", (identity,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Dataset not found")
        await cur.execute(
            "SELECT DISTINCT ON(window_index) * FROM evaluation_labels WHERE dataset_id=%s ORDER BY window_index,revision DESC",
            (identity,),
        )
        row["labels"] = await cur.fetchall()
        await cur.execute(
            "SELECT id,created_at,report->>'state' AS state FROM evaluation_runs WHERE dataset_id=%s ORDER BY created_at DESC LIMIT 50",
            (identity,),
        )
        row["runs"] = await cur.fetchall()
        return row


@router.get("/datasets/{identity}/labels/{window_index}")
async def label_history(identity: UUID, window_index: int, page: int = Query(1, ge=1)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT count(*) AS total FROM evaluation_labels WHERE dataset_id=%s AND window_index=%s",
            (identity, window_index),
        )
        total = (await cur.fetchone())["total"]
        await cur.execute(
            "SELECT * FROM evaluation_labels WHERE dataset_id=%s AND window_index=%s ORDER BY revision DESC LIMIT 50 OFFSET %s",
            (identity, window_index, (page - 1) * 50),
        )
        return {"items": await cur.fetchall(), "total": total, "page": page}


@router.get("/runs/{identity}")
async def run_detail(identity: UUID):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT * FROM evaluation_runs WHERE id=%s", (identity,))
        row = await cur.fetchone()
        if not row:
            raise HTTPException(404, "Run not found")
        return row


@router.get("/status")
async def status():
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT min(observed_at) AS first_tick,max(observed_at) AS latest_tick FROM traffic_collection_ticks"
        )
        row = await cur.fetchone()
        await cur.execute(
            "SELECT state FROM traffic_collection_ticks ORDER BY observed_at DESC LIMIT 1"
        )
        latest = await cur.fetchone()
        row["latest_collector_state"] = latest["state"] if latest else "not_started"
        row["state"] = (
            (
                "collecting"
                if latest and latest["state"] == "caught_up"
                else "gap_or_not_started"
            )
            if row["latest_tick"]
            and (datetime.now(UTC) - row["latest_tick"]).total_seconds() <= 15
            else "stale_or_not_started"
        )
        await cur.execute("SELECT count(*) AS datasets FROM evaluation_datasets")
        row.update(await cur.fetchone())
        row["scope"] = SCOPE
        row["algorithm_version"] = VERSION
        return row
