"""Operator-attested inventory and explicit target mappings, never a vulnerability scanner."""

import ipaddress
import json
import re
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config import settings
from app.integrations import db

router = APIRouter(prefix="/api/v1/assets", tags=["Asset inventory"])
LATEST = "SELECT DISTINCT ON(asset_id) * FROM asset_revisions ORDER BY asset_id,revision DESC"
REGISTRY_LIMIT = 1000
SCHEMA = """
CREATE TABLE IF NOT EXISTS asset_registry (id uuid PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS asset_revisions (
 id bigserial PRIMARY KEY,asset_id uuid NOT NULL REFERENCES asset_registry(id) ON DELETE RESTRICT,
 revision integer NOT NULL CHECK(revision>0),payload jsonb NOT NULL,declared_by text NOT NULL,
 rationale text NOT NULL,authentication text NOT NULL,request_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),UNIQUE(asset_id,revision),UNIQUE(asset_id,request_id)
);
CREATE OR REPLACE FUNCTION reject_asset_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Asset revision history is append-only'; END; $$;
DROP TRIGGER IF EXISTS immutable_asset_revisions ON asset_revisions;
CREATE TRIGGER immutable_asset_revisions BEFORE UPDATE OR DELETE ON asset_revisions
 FOR EACH ROW EXECUTE FUNCTION reject_asset_mutation();
"""


def canonical_ip(value):
    address = ipaddress.ip_address(value.strip())
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
    ):
        raise ValueError(
            "Use a specific endpoint IP, not loopback/link-local/multicast"
        )
    return str(
        address.ipv4_mapped
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped
        else address
    )


def canonical_host(value):
    if any(c in value for c in "/?#@\\") or any(ord(c) < 33 for c in value.strip()):
        raise ValueError("Enter only the observed host, optionally with port")
    parsed = urlsplit("//" + value.strip())
    host = (parsed.hostname or "").rstrip(".").encode("idna").decode().lower()
    try:
        host = str(ipaddress.ip_address(host))
        if ":" in host:
            host = "[" + host + "]"
    except ValueError:
        if (
            len(host) > 253
            or not host
            or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                for part in host.split(".")
            )
        ):
            raise ValueError("Invalid host name") from None
    port = parsed.port
    return host + (":" + str(port) if port is not None else "")


class Software(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    vendor: str = Field(default="", max_length=120)
    product: str = Field(min_length=1, max_length=120)
    version: str = Field(default="", max_length=100)


class RouteBinding(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    host: str = Field(min_length=1, max_length=260)
    router: str = Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f]+$")
    path_prefix: str = Field(min_length=1, max_length=200)

    @field_validator("host")
    @classmethod
    def host_value(cls, value):
        return canonical_host(value)

    @field_validator("path_prefix")
    @classmethod
    def prefix_value(cls, value):
        if (
            not value.startswith("/")
            or value.startswith("//")
            or any(c in value for c in "?#\\")
            or any(ord(c) < 32 for c in value)
            or ".." in value.split("/")
        ):
            raise ValueError(
                "Use an absolute literal path prefix without query, fragments or dot traversal"
            )
        return value.rstrip("/") or "/"


class AssetPayload(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=2, max_length=120, pattern=r"^[^\x00-\x1f]+$")
    kind: Literal["host", "application", "service"]
    owner: str = Field(default="", max_length=120, pattern=r"^[^\x00-\x1f]*$")
    criticality: Literal["unknown", "low", "medium", "high", "critical"] = "unknown"
    status: Literal["active", "retired"] = "active"
    os_name: str = Field(default="", max_length=120)
    os_version: str = Field(default="", max_length=100)
    software: list[Software] = Field(default_factory=list, max_length=20)
    agent_ids: list[str] = Field(default_factory=list, max_length=20)
    ips: list[str] = Field(default_factory=list, max_length=20)
    routes: list[RouteBinding] = Field(default_factory=list, max_length=20)
    parent_host_id: UUID | None = None

    @field_validator("agent_ids")
    @classmethod
    def agent_values(cls, values):
        if any(not re.fullmatch(r"[0-9]{3,8}", v) or int(v) == 0 for v in values):
            raise ValueError("Use a non-manager Wazuh agent ID as recorded, e.g. 001")
        if len(set(values)) != len(values):
            raise ValueError("Duplicate agent IDs")
        return sorted(values)

    @field_validator("ips")
    @classmethod
    def ip_values(cls, values):
        canonical = [canonical_ip(v) for v in values]
        if len(set(canonical)) != len(canonical):
            raise ValueError("Duplicate endpoint IPs")
        return sorted(canonical)

    @model_validator(mode="after")
    def binding_scope(self):
        if self.kind == "host" and (self.routes or self.parent_host_id):
            raise ValueError(
                "Hosts use agent/IP bindings, not application routes or parent hosts"
            )
        if self.kind != "host" and (self.agent_ids or self.ips):
            raise ValueError(
                "Applications/services use routes and a parent host; endpoint bindings belong to hosts"
            )
        routes = [(r.host, r.router, r.path_prefix) for r in self.routes]
        if len(set(routes)) != len(routes):
            raise ValueError("Duplicate route bindings")
        return self


class AssetInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    payload: AssetPayload
    declared_by: str = Field(min_length=2, max_length=80, pattern=r"^[^\x00-\x1f]+$")
    rationale: str = Field(min_length=8, max_length=2000)
    expected_revision: int = Field(ge=0)
    request_id: UUID


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


async def current_registry(cur=None):
    if cur is not None:
        await cur.execute(
            f"SELECT * FROM ({LATEST}) r WHERE payload->>'status'='active' ORDER BY asset_id LIMIT %s",
            (REGISTRY_LIMIT + 1,),
        )
        return await cur.fetchall()
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cursor:
        return await current_registry(cursor)


def indexes(records):
    hosts, agents, ips = {}, {}, {}
    for row in records:
        p = row["payload"]
        if p["kind"] != "host":
            continue
        hosts[str(row["asset_id"])] = row
        for agent in p["agent_ids"]:
            agents.setdefault(agent, []).append(row)
        for ip in p["ips"]:
            ips.setdefault(ip, []).append(row)
    return hosts, agents, ips


def resolve(kind, row, records):
    """Resolve current explicit target mappings. Never equate an HTTP peer with its target."""
    hosts, agents, ips = indexes(records)
    selected, host, reasons, warnings = None, None, [], []
    if kind == "requests":
        try:
            hostname = canonical_host(row.get("host") or "")
        except ValueError:
            hostname = ""
        path = str(row.get("path") or "").split("?", 1)[0]
        matches = []
        for record in records:
            for route in record["payload"]["routes"]:
                prefix = route["path_prefix"]
                if (
                    route["host"] == hostname
                    and route["router"] == row.get("router")
                    and (
                        prefix == "/" or path == prefix or path.startswith(prefix + "/")
                    )
                ):
                    matches.append((len(prefix), record))
        if matches:
            specificity = max(m[0] for m in matches)
            best = {str(m[1]["asset_id"]): m[1] for m in matches if m[0] == specificity}
            if len(best) == 1:
                selected = next(iter(best.values()))
                host = hosts.get(selected["payload"].get("parent_host_id"))
                reasons.append(
                    "exact observed host/router and longest literal path prefix"
                )
    else:
        wrapper = row.get("event") or {}
        raw = wrapper.get("event", wrapper) if isinstance(wrapper, dict) else {}
        raw = raw if isinstance(raw, dict) else {}
        agent = raw.get("agent") or {}
        agent = agent if isinstance(agent, dict) else {}
        candidates = {}
        if row.get("source") == "wazuh":
            for record in agents.get(str(agent.get("id") or ""), []):
                candidates[str(record["asset_id"])] = record
            if candidates:
                reasons.append("operator-bound Wazuh agent ID")
            addresses = [agent.get("ip")]
        elif row.get("source") == "suricata":
            addresses = [raw.get("src_ip"), raw.get("dest_ip")]
        else:
            addresses = []  # WAF source IP is not target identity.
        for address in addresses:
            try:
                bound = ips.get(canonical_ip(str(address or "")), [])
            except ValueError:
                continue
            if len(bound) > 1:
                warnings.append("Shared endpoint IP ignored for identity")
            elif len(bound) == 1:
                candidates[str(bound[0]["asset_id"])] = bound[0]
        if len(candidates) == 1:
            host = selected = next(iter(candidates.values()))
            if not reasons:
                reasons.append(
                    "unique operator-bound endpoint IP appears in sensor evidence"
                )
        elif len(candidates) > 1:
            reasons = []
            warnings.append(
                "Multiple mapped endpoints or conflicting agent/IP evidence; no single target selected"
            )

    def summary(record):
        if not record:
            return None
        return {
            "asset_id": str(record["asset_id"]),
            "revision": record["revision"],
            "mapped_at": record["created_at"],
            "payload": record["payload"],
        }

    # Only unambiguous IP bindings can broaden a candidate timeline.
    bindings = {"agent_ids": [], "ips": []}
    if host:
        bindings["agent_ids"] = host["payload"]["agent_ids"]
        bindings["ips"] = [
            ip for ip in host["payload"]["ips"] if len(ips.get(ip, [])) == 1
        ]
    return {
        "asset": summary(selected),
        "parent_host": summary(host) if host != selected else None,
        "match_reasons": reasons,
        "warnings": sorted(set(warnings)),
        "bindings": bindings,
        "scope": "Current operator-attested mapping, not identity as of event time or independently verified identity. IPs can be reused. Correlated events are candidates, not causation or proof of exploitation.",
    }


async def save(asset_id, body):
    payload = body.payload.model_dump(mode="json")
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Serializes validation of shared selectors, parent lifecycle and creation, including separate asset IDs.
        await cur.execute("SELECT pg_advisory_xact_lock(84320112)")
        await cur.execute(
            "INSERT INTO asset_registry(id) VALUES (%s) ON CONFLICT DO NOTHING",
            (asset_id,),
        )
        await cur.execute(
            "SELECT id FROM asset_registry WHERE id=%s FOR UPDATE", (asset_id,)
        )
        await cur.fetchone()
        await cur.execute(
            "SELECT * FROM asset_revisions WHERE asset_id=%s AND request_id=%s",
            (asset_id, body.request_id),
        )
        old = await cur.fetchone()
        if old:
            if (
                old["payload"] != payload
                or old["declared_by"] != body.declared_by
                or old["rationale"] != body.rationale
            ):
                raise HTTPException(
                    409, "Request ID already used for different asset content"
                )
            return {"asset": old, "replayed": True}
        await cur.execute(
            "SELECT * FROM asset_revisions WHERE asset_id=%s ORDER BY revision DESC LIMIT 1",
            (asset_id,),
        )
        previous = await cur.fetchone()
        revision = previous["revision"] if previous else 0
        if revision != body.expected_revision:
            raise HTTPException(
                409,
                "Asset changed. Reload the latest revision; your draft can be retained.",
            )
        if previous and previous["payload"]["kind"] != payload["kind"]:
            raise HTTPException(
                422,
                "Asset kind is immutable; retire this identity and create a new asset",
            )
        registry = await current_registry(cur)
        others = [r for r in registry if str(r["asset_id"]) != str(asset_id)]
        if payload["status"] == "active" and len(others) >= REGISTRY_LIMIT:
            raise HTTPException(422, "Active registry capacity reached")
        if payload["parent_host_id"]:
            await cur.execute(
                f"SELECT payload FROM ({LATEST}) r WHERE asset_id=%s",
                (body.payload.parent_host_id,),
            )
            parent = await cur.fetchone()
            if (
                not parent
                or parent["payload"]["kind"] != "host"
                or (
                    payload["status"] == "active"
                    and parent["payload"]["status"] != "active"
                )
            ):
                raise HTTPException(
                    422,
                    "An active application/service needs an existing active parent host",
                )
        if (
            payload["kind"] == "host"
            and payload["status"] == "retired"
            and any(r["payload"].get("parent_host_id") == str(asset_id) for r in others)
        ):
            raise HTTPException(
                409,
                "Retire or reassign active child applications/services before retiring this host",
            )
        warnings = []
        if payload["status"] == "active":
            for r in others:
                p = r["payload"]
                if set(p["agent_ids"]) & set(payload["agent_ids"]):
                    raise HTTPException(
                        409,
                        "A Wazuh agent ID is already assigned to another active host",
                    )
                selectors = {
                    (x["host"], x["router"], x["path_prefix"]) for x in p["routes"]
                }
                if selectors & {
                    (x["host"], x["router"], x["path_prefix"])
                    for x in payload["routes"]
                }:
                    raise HTTPException(
                        409, "This exact host/router/path selector is already assigned"
                    )
                if set(p["ips"]) & set(payload["ips"]):
                    warnings.append(
                        "Shared endpoint IP: ambiguous addresses will not be used for asset correlation"
                    )
        await cur.execute(
            """INSERT INTO asset_revisions(asset_id,revision,payload,declared_by,rationale,authentication,request_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
            (
                asset_id,
                revision + 1,
                json.dumps(payload),
                body.declared_by,
                body.rationale,
                "shared_operation_key"
                if settings.operation_key
                else "development_ungated",
                body.request_id,
            ),
        )
        row = await cur.fetchone()
        await conn.commit()
    return {"asset": row, "warnings": sorted(set(warnings)), "replayed": False}


@router.get("")
async def listing(
    q: str = Query("", max_length=120),
    status: Literal["all", "active", "retired"] = "active",
    kind: Literal["all", "host", "application", "service"] = "all",
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    clauses = ["TRUE"]
    values = []
    for field, value in (("status", status), ("kind", kind)):
        if value != "all":
            clauses.append(f"payload->>'{field}'=%s")
            values.append(value)
    if q:
        pattern = (
            "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        )
        clauses.append(
            "(payload->>'name' ILIKE %s OR payload->>'owner' ILIKE %s OR (payload->'software')::text ILIKE %s)"
        )
        values.extend([pattern] * 3)
    where = " AND ".join(clauses)
    async with await db._connect() as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                f"WITH latest AS ({LATEST}) SELECT count(*) AS total FROM latest WHERE {where}",
                values,
            )
            total = (await cur.fetchone())["total"]
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            await cur.execute(
                f"WITH latest AS ({LATEST}) SELECT r.* FROM latest r JOIN asset_registry a ON a.id=r.asset_id WHERE {where} ORDER BY a.created_at DESC,a.id LIMIT %s OFFSET %s",
                (*values, page_size, (page - 1) * page_size),
            )
            items = await cur.fetchall()
    return {
        "items": items,
        "total": total,
        "page": page,
        "pages": pages,
        "scope": "Current operator-attested inventory; not automatic discovery, authenticated identity or vulnerability verification.",
    }


@router.get("/hosts")
async def hosts():
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            f"SELECT asset_id,revision,payload->>'name' AS name,payload->>'status' AS status FROM ({LATEST}) r WHERE payload->>'kind'='host' AND payload->>'status'='active' ORDER BY payload->>'name',asset_id LIMIT 1000"
        )
        return {"items": await cur.fetchall()}


@router.get("/observed")
async def observed():
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute("""SELECT DISTINCT ON(event->'event'->'agent'->>'id') event->'event'->'agent'->>'id' AS agent_id,
            event->'event'->'agent'->>'name' AS name,event->'event'->'agent'->>'ip' AS ip,created_at AS last_seen
            FROM incidents WHERE source='wazuh' AND event->'event'->'agent'->>'id' ~ '^[0-9]{3,8}$'
              AND event->'event'->'agent'->>'id' !~ '^0+$'
            ORDER BY event->'event'->'agent'->>'id',created_at DESC,id DESC LIMIT 50""")
        return {
            "items": await cur.fetchall(),
            "scope": "Latest retained Wazuh evidence; observed does not mean operator-attested, currently online or a complete inventory.",
        }


@router.get("/{asset_id}")
async def detail(
    asset_id: UUID, page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=50)
):
    async with await db._connect() as conn:
        await conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        async with conn.cursor(row_factory=dict_row) as cur:
            await cur.execute(
                "SELECT * FROM asset_revisions WHERE asset_id=%s ORDER BY revision DESC LIMIT 1",
                (asset_id,),
            )
            current = await cur.fetchone()
            if not current:
                raise HTTPException(404, "Asset not found")
            await cur.execute(
                "SELECT count(*) AS total FROM asset_revisions WHERE asset_id=%s",
                (asset_id,),
            )
            total = (await cur.fetchone())["total"]
            pages = max(1, (total + page_size - 1) // page_size)
            page = min(page, pages)
            await cur.execute(
                "SELECT * FROM asset_revisions WHERE asset_id=%s ORDER BY revision DESC LIMIT %s OFFSET %s",
                (asset_id, page_size, (page - 1) * page_size),
            )
            items = await cur.fetchall()
    return {
        "current": current,
        "items": items,
        "total": total,
        "page": page,
        "pages": pages,
    }
