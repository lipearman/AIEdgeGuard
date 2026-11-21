"""Conservative declared-product checks, never a complete CPE applicability engine."""

import json
import re
from uuid import UUID

from fastapi import APIRouter, HTTPException, Path
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field

from app import assets, knowledge
from app.config import settings
from app.cpe import cpe_parts
from app.integrations import db

router = APIRouter(prefix="/api/v1/applicability", tags=["Declared product checks"])
SCHEMA = """
CREATE TABLE IF NOT EXISTS applicability_assessments(
 id bigserial PRIMARY KEY,asset_id uuid NOT NULL REFERENCES asset_registry(id),asset_revision integer NOT NULL,
 nvd_snapshot_id bigint NOT NULL REFERENCES knowledge_snapshots(id),cve text NOT NULL,
 report jsonb NOT NULL,declared_by text NOT NULL,rationale text NOT NULL,authentication text NOT NULL,
 request_id uuid NOT NULL UNIQUE,input jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(asset_id,asset_revision) REFERENCES asset_revisions(asset_id,revision)
);
CREATE OR REPLACE FUNCTION reject_applicability_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Applicability assessments are append-only'; END; $$;
DROP TRIGGER IF EXISTS immutable_applicability ON applicability_assessments;
CREATE TRIGGER immutable_applicability BEFORE UPDATE OR DELETE ON applicability_assessments
 FOR EACH ROW EXECUTE FUNCTION reject_applicability_mutation();
"""
RULE_VERSION = "declared-cpe-candidates-v1"
SCOPE = "Checks operator-declared product CPEs and versions against retained NVD vulnerable criteria. Results are candidates, not verified vulnerability or a clean-asset finding. Inventory may be incomplete; complex environment/negation conditions and unknown version schemes require human review."


def numeric(value):
    if not re.fullmatch(r"[0-9]{1,9}(?:\.[0-9]{1,9}){0,7}", value):
        return None
    parts = [int(p) for p in value.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def version_compare(left, right):
    a, b = numeric(left), numeric(right)
    if a is None or b is None:
        return None
    size = max(len(a), len(b))
    a = a + (0,) * (size - len(a))
    b = b + (0,) * (size - len(b))
    return (a > b) - (a < b)


def match(software, criterion):
    if not software.get("cpe23"):
        return "unknown", "No operator CPE mapping"
    try:
        declared = cpe_parts(software["cpe23"])
        required = cpe_parts(criterion["criteria"])
    except (ValueError, KeyError, TypeError):
        return "unknown", "Unsupported CPE criterion"
    for i in (2, 3, 4):
        if required[i].casefold() != declared[i].casefold():
            if "*" in required[i] or "?" in required[i] or "\\" in required[i]:
                return "unknown", "Unsupported CPE name pattern"
            return "no_match", "Different declared product identity"
    for i in range(6, 13):
        if required[i] == "*":
            continue
        if declared[i] == "*" or any(c in required[i] for c in "?\\*"):
            return "unknown", "Missing or patterned platform/edition constraint"
        if required[i].casefold() != declared[i].casefold():
            return "no_match", "Different declared platform/edition"
    version = software.get("version") or ""
    if not version:
        return "unknown", "Declared version is missing"
    if declared[5] != "*" and declared[5].casefold() != version.casefold():
        return "unknown", "CPE and declared version conflict"
    if required[5] not in ("*", "-"):
        if any(c in required[5] for c in "?\\*"):
            return "unknown", "Unsupported version pattern"
        if version.casefold() != required[5].casefold():
            return "no_match", "Different exact version"
    if required[5] == "-":
        return "unknown", "Not-applicable version criterion requires review"
    ranges = [
        ("versionStartIncluding", lambda n: n >= 0),
        ("versionStartExcluding", lambda n: n > 0),
        ("versionEndIncluding", lambda n: n <= 0),
        ("versionEndExcluding", lambda n: n < 0),
    ]
    for key, predicate in ranges:
        if key not in criterion:
            continue
        if software.get("version_scheme") != "numeric_dot":
            return (
                "unknown",
                "Range requires explicit numeric_dot version scheme; no guessed ordering",
            )
        comparison = version_compare(version, str(criterion[key]))
        if comparison is None:
            return "unknown", "Unsupported version syntax"
        if not predicate(comparison):
            return "no_match", "Outside declared numeric version bounds"
    return "candidate", "Declared CPE/version matches this vulnerable criterion"


def evaluate(software, record):
    configurations = record.get("configurations") or []
    criteria = []
    complexity = False
    count = 0

    def walk(node, complex_parent=False, depth=0):
        nonlocal complexity, count
        count += 1
        if depth > 12 or count > 5000:
            raise ValueError("Configuration exceeds supported evaluation bounds")
        complex_here = (
            complex_parent
            or node.get("operator", "OR") != "OR"
            or bool(node.get("negate"))
        )
        complexity |= complex_here
        for criterion in node.get("cpeMatch", []):
            if criterion.get("vulnerable") is True:
                criteria.append((criterion, complex_here))
                if len(criteria) > 5000:
                    raise ValueError("Too many CPE criteria")
            else:
                complexity = True
        for child in node.get("nodes", []) + node.get("children", []):
            walk(child, complex_here, depth + 1)

    try:
        for configuration in configurations:
            walk(configuration)
    except (ValueError, TypeError, AttributeError):
        return {
            "state": "needs_review",
            "reason": "Unsupported or excessive NVD configuration",
            "items": [],
            "scope": SCOPE,
            "rule_version": RULE_VERSION,
        }
    results = []
    for product in software:
        matches = []
        unknown = []
        for criterion, complex_here in criteria:
            state, reason = match(product, criterion)
            if state == "candidate":
                matches.append(
                    {
                        "criteria": criterion,
                        "reason": reason,
                        "environment_review": complex_here or complexity,
                    }
                )
            elif state == "unknown":
                unknown.append(reason)
        state = (
            "needs_environment_review"
            if matches and (complexity or any(m["environment_review"] for m in matches))
            else "candidate_affected"
            if matches
            else "unknown"
            if unknown or not criteria
            else "no_match_in_declared_product"
        )
        results.append(
            {
                "product": product,
                "state": state,
                "matches": matches[:30],
                "matches_truncated": len(matches) > 30,
                "uncertainties": sorted(set(unknown))[:10],
            }
        )
    state = (
        "candidate_affected"
        if any(r["state"] == "candidate_affected" for r in results)
        else "needs_review"
        if not results
        or not criteria
        or any(r["state"] in ("unknown", "needs_environment_review") for r in results)
        else "no_match_in_declared_products"
    )
    if record.get("vulnStatus") != "Analyzed":
        state = "needs_review"
    return {
        "state": state,
        "items": results,
        "cve_status": record.get("vulnStatus"),
        "complex_conditions": complexity,
        "scope": SCOPE,
        "rule_version": RULE_VERSION,
    }


class AssessmentInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    asset_id: UUID
    asset_revision: int = Field(ge=1)
    cve: str = Field(max_length=28)
    declared_by: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000)
    request_id: UUID


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


async def assess(body):
    cve = knowledge.key_for("nvd", body.cve)
    data = body.model_dump(mode="json")
    data["cve"] = cve
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("SELECT pg_advisory_xact_lock(84320113)")
        await cur.execute(
            "SELECT * FROM applicability_assessments WHERE request_id=%s",
            (body.request_id,),
        )
        old = await cur.fetchone()
        if old:
            if old["input"] != data:
                raise HTTPException(
                    409, "Assessment request ID reused with different input"
                )
            return {"assessment": old, "replayed": True}
        # Shares lifecycle serialization with asset saves; report pins an exact declaration revision.
        await cur.execute("SELECT pg_advisory_xact_lock(84320112)")
        await cur.execute(
            f"SELECT * FROM ({assets.LATEST}) r WHERE asset_id=%s", (body.asset_id,)
        )
        asset = await cur.fetchone()
        if not asset:
            raise HTTPException(404, "Asset not found")
        if asset["revision"] != body.asset_revision:
            raise HTTPException(409, "Asset revision changed; reload before assessing")
        source = await knowledge.get("nvd", cve)
        record = (source.get("payload") or {}).get("record")
        if not source.get("snapshot_id") or not record:
            raise HTTPException(
                422, "Fetch and inspect an NVD CVE record before assessment"
            )
        report = {
            **evaluate(asset["payload"].get("software", []), record),
            "asset_name": asset["payload"]["name"],
            "asset_status": asset["payload"]["status"],
            "nvd_state": source["state"],
            "nvd_last_success": str(source["last_success"]),
            "identity_scope": "Operator-attested asset declaration; not independently verified identity or inventory completeness",
        }
        await cur.execute(
            """INSERT INTO applicability_assessments(asset_id,asset_revision,nvd_snapshot_id,cve,report,declared_by,rationale,authentication,request_id,input)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (
                body.asset_id,
                body.asset_revision,
                source["snapshot_id"],
                cve,
                json.dumps(report),
                body.declared_by,
                body.rationale,
                "shared_operation_key"
                if settings.operation_key
                else "development_ungated",
                body.request_id,
                json.dumps(data),
            ),
        )
        row = await cur.fetchone()
        await conn.commit()
    return {"assessment": row, "replayed": False}


@router.get("/{assessment_id}")
async def detail(assessment_id: int = Path(ge=1, le=9223372036854775807)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT * FROM applicability_assessments WHERE id=%s", (assessment_id,)
        )
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Assessment not found")
    return row


@router.get("/asset/{asset_id}")
async def history(asset_id: UUID, page: int = 1):
    page = max(1, min(page, 100000))
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT count(*) AS total FROM applicability_assessments WHERE asset_id=%s",
            (asset_id,),
        )
        total = (await cur.fetchone())["total"]
        pages = max(1, (total + 9) // 10)
        page = min(page, pages)
        await cur.execute(
            "SELECT * FROM applicability_assessments WHERE asset_id=%s ORDER BY id DESC LIMIT 10 OFFSET %s",
            (asset_id, (page - 1) * 10),
        )
        items = await cur.fetchall()
    return {"items": items, "total": total, "page": page, "pages": pages}
