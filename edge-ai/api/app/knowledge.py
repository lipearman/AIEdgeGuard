"""Source-qualified public intelligence; immutable snapshots, no enforcement."""

import asyncio
import hashlib
import ipaddress
import json
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Literal

import httpx
from fastapi import APIRouter, HTTPException, Path, Query
from psycopg.rows import dict_row

from app.config import settings
from app.integrations import db
from app.intelligence import CVE

router = APIRouter(prefix="/api/v1/knowledge", tags=["Source intelligence"])
Provider = Literal["nvd", "mitre", "drop4", "drop6"]
SOURCES = {
    "nvd": ("https://services.nvd.nist.gov/rest/json/cves/2.0", 2_000_000, 24, 30),
    "mitre": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        64_000_000,
        168,
        3600,
    ),
    "drop4": ("https://www.spamhaus.org/drop/drop_v4.json", 4_000_000, 24, 3600),
    "drop6": ("https://www.spamhaus.org/drop/drop_v6.json", 4_000_000, 24, 3600),
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS knowledge_snapshots (
 id bigserial PRIMARY KEY,provider text NOT NULL,lookup_key text NOT NULL,
 source_url text NOT NULL,version text NOT NULL,published_at timestamptz,
 payload jsonb NOT NULL,fingerprint text NOT NULL UNIQUE,fetched_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS knowledge_cache (
 provider text NOT NULL,lookup_key text NOT NULL,last_attempt timestamptz,last_success timestamptz,
 error text NOT NULL DEFAULT '',snapshot_id bigint REFERENCES knowledge_snapshots(id),
 PRIMARY KEY(provider,lookup_key)
);
CREATE TABLE IF NOT EXISTS knowledge_budget(provider text PRIMARY KEY,last_attempt timestamptz);
INSERT INTO knowledge_budget(provider) VALUES ('nvd'),('mitre'),('drop4'),('drop6') ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION reject_knowledge_snapshot_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Intelligence snapshots are append-only'; END; $$;
DROP TRIGGER IF EXISTS immutable_knowledge_snapshot ON knowledge_snapshots;
CREATE TRIGGER immutable_knowledge_snapshot BEFORE UPDATE OR DELETE ON knowledge_snapshots
 FOR EACH ROW EXECUTE FUNCTION reject_knowledge_snapshot_mutation();
"""
TECHNIQUE = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?\Z")
log = logging.getLogger(__name__)


async def init_schema():
    async with await db._connect() as conn:
        await conn.execute(SCHEMA)
        await conn.commit()


def key_for(provider, key):
    if provider not in SOURCES:
        raise HTTPException(422, "Unknown intelligence source")
    if provider == "nvd":
        if not CVE.fullmatch(key):
            raise HTTPException(422, "Use one complete CVE ID")
        return key.upper()
    if key != "catalog":
        raise HTTPException(422, "This source uses the catalog key")
    return key


def timestamp(value):
    value = datetime.fromisoformat(str(value))
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)  # NVD declares UTC without suffix.
    value = value.astimezone(UTC)
    if value > datetime.now(UTC) + timedelta(minutes=5):
        raise ValueError("Future publisher timestamp")
    return value


def validate(provider, key, raw):
    if provider == "nvd":
        if (
            not isinstance(raw, dict)
            or raw.get("format") != "NVD_CVE"
            or raw.get("version") != "2.0"
            or type(raw.get("totalResults")) is not int
            or raw.get("totalResults") not in (0, 1)
            or type(raw.get("startIndex")) is not int
            or raw.get("startIndex") != 0
            or not isinstance(raw.get("vulnerabilities"), list)
            or len(raw.get("vulnerabilities", [])) != raw["totalResults"]
        ):
            raise ValueError("Invalid NVD response")
        if raw["totalResults"] == 0:
            return (
                {
                    "record": None,
                    "notice": "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
                },
                "2.0",
                None,
            )
        cve = raw["vulnerabilities"][0]["cve"]
        if (
            cve.get("id") != key
            or not isinstance(cve.get("descriptions"), list)
            or not isinstance(cve.get("configurations", []), list)
            or not isinstance(cve.get("vulnStatus"), str)
            or not cve["vulnStatus"]
            or not isinstance(cve.get("metrics", {}), dict)
        ):
            raise ValueError("Unexpected NVD record")
        if len(cve["descriptions"]) > 100 or any(
            not isinstance(item, dict)
            or not isinstance(item.get("lang"), str)
            or not isinstance(item.get("value"), str)
            or len(item["value"]) > 64000
            for item in cve["descriptions"]
        ):
            raise ValueError("Invalid NVD description")
        modified = timestamp(cve["lastModified"])
        return (
            {
                "record": cve,
                "notice": "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
            },
            "2.0",
            modified,
        )
    if provider == "mitre":
        if (
            not isinstance(raw, dict)
            or raw.get("type") != "bundle"
            or not isinstance(raw.get("objects"), list)
            or not 1 <= len(raw["objects"]) <= 60000
        ):
            raise ValueError("Invalid ATT&CK bundle")
        entries = []
        seen = set()
        modified = []
        release = ""
        for obj in raw["objects"]:
            if obj.get("type") == "x-mitre-collection":
                release = str(obj.get("x_mitre_version") or "")[:80]
            if (
                obj.get("type") != "attack-pattern"
                or obj.get("revoked")
                or obj.get("x_mitre_deprecated")
            ):
                continue
            refs = [
                x
                for x in obj.get("external_references", [])
                if x.get("source_name") == "mitre-attack"
                and TECHNIQUE.fullmatch(str(x.get("external_id") or ""))
            ]
            if len(refs) != 1:
                raise ValueError("Technique has no unique ATT&CK ID")
            technique = refs[0]["external_id"]
            if technique in seen:
                raise ValueError("Duplicate technique")
            seen.add(technique)
            when = timestamp(obj["modified"])
            modified.append(when)
            if not isinstance(obj.get("name"), str) or not obj["name"]:
                raise ValueError("Missing technique name")
            entries.append(
                {
                    "id": technique,
                    "name": obj["name"][:300],
                    "description": str(obj.get("description") or "")[:6000],
                    "modified": when.isoformat(),
                    "version": str(obj.get("x_mitre_version") or "")[:80],
                    "tactics": [
                        str(x.get("phase_name") or "")[:100]
                        for x in obj.get("kill_chain_phases", [])
                        if x.get("kill_chain_name") == "mitre-attack"
                    ],
                    "url": "https://attack.mitre.org/techniques/"
                    + technique.replace(".", "/")
                    + "/",
                }
            )
        if not 1 <= len(entries) <= 3000:
            raise ValueError("Unexpected ATT&CK technique count")
        return (
            {
                "techniques": sorted(entries, key=lambda x: x["id"]),
                "release": release,
                "bundle_id": str(raw.get("id") or "")[:100],
                "license_url": "/static/licenses/mitre-attack.txt",
                "notice": "MITRE ATT&CK® · The MITRE Corporation. Technique references are not verified detection coverage.",
            },
            release or "STIX 2.1 (release not supplied)",
            max(modified),
        )
    if not isinstance(raw, list) or not 2 <= len(raw) <= 50000:
        raise ValueError("Invalid DROP document")
    meta = raw[-1]
    if (
        meta.get("type") != "metadata"
        or type(meta.get("timestamp")) is not int
        or type(meta.get("records")) is not int
        or meta["records"] != len(raw) - 1
        or not isinstance(meta.get("copyright"), str)
        or "Spamhaus" not in meta["copyright"]
    ):
        raise ValueError("DROP metadata missing")
    published = timestamp(datetime.fromtimestamp(meta["timestamp"], UTC).isoformat())
    networks = []
    seen = set()
    family = 4 if provider == "drop4" else 6
    for obj in raw[:-1]:
        net = ipaddress.ip_network(obj["cidr"], strict=True)
        if (
            net.version != family
            or not net.is_global
            or net.prefixlen < (8 if family == 4 else 16)
            or not re.fullmatch(r"SBL[0-9]{1,12}", str(obj.get("sblid") or ""))
        ):
            raise ValueError("Invalid or duplicate DROP range")
        identity = (str(net), obj["sblid"])
        if identity in seen:
            continue
        seen.add(identity)
        networks.append({"cidr": str(net), "sblid": obj["sblid"]})
    return (
        {
            "networks": networks,
            "source_records": meta["records"],
            "duplicates_removed": meta["records"] - len(networks),
            "copyright": meta["copyright"][:300],
            "terms": "https://www.spamhaus.org/blocklists/drop-fair-use-policy/",
            "publisher_date": published.isoformat(),
            "notice": "The Spamhaus Project · range reputation only, not proof this event is malicious. No automatic block.",
        },
        str(meta["timestamp"]),
        published,
    )


async def download(provider, key):
    url, limit, *_ = SOURCES[provider]
    chunks = []
    size = 0
    async with (
        asyncio.timeout(75),
        httpx.AsyncClient(timeout=45, follow_redirects=False) as client,
        client.stream(
            "GET", url, params={"cveId": key} if provider == "nvd" else None
        ) as response,
    ):
        response.raise_for_status()
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > limit:
                raise ValueError("Source response exceeds limit")
            chunks.append(chunk)
    content = b"".join(chunks)
    if provider.startswith("drop"):
        return [json.loads(line) for line in content.splitlines() if line.strip()]
    return json.loads(content)


async def get(provider, key="catalog", payload=True):
    key = key_for(provider, key)
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            """SELECT c.*,s.source_url,s.version,s.published_at,s.fetched_at,s.fingerprint,s.payload
            FROM knowledge_cache c LEFT JOIN knowledge_snapshots s ON s.id=c.snapshot_id
            WHERE c.provider=%s AND c.lookup_key=%s""",
            (provider, key),
        )
        row = await cur.fetchone()
    result = {
        "provider": provider,
        "key": key,
        "state": "never_fetched",
        "snapshot_id": None,
        "source_url": SOURCES[provider][0],
        "automatic": settings.intelligence_enabled and provider != "nvd",
        "interval_hours": SOURCES[provider][2],
    }
    if row:
        result.update(row)
        fresh = bool(
            row["last_success"]
            and datetime.now(UTC) - row["last_success"]
            < timedelta(hours=SOURCES[provider][2])
            and not row["error"]
        )
        if (
            provider.startswith("drop")
            and row["published_at"]
            and datetime.now(UTC) - row["published_at"] > timedelta(hours=48)
        ):
            fresh = False
        result["state"] = (
            "current"
            if fresh and row["snapshot_id"]
            else "stale"
            if row["snapshot_id"]
            else "unavailable"
        )
        if not payload:
            result["payload"] = {
                k: v
                for k, v in (row.get("payload") or {}).items()
                if k
                in (
                    "notice",
                    "copyright",
                    "terms",
                    "license_url",
                    "release",
                    "bundle_id",
                    "publisher_date",
                )
            }
    return result


async def refresh(provider, key="catalog"):
    key = key_for(provider, key)
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT last_attempt FROM knowledge_budget WHERE provider=%s FOR UPDATE",
            (provider,),
        )
        budget = await cur.fetchone()
        await cur.execute(
            "SELECT last_success,error FROM knowledge_cache WHERE provider=%s AND lookup_key=%s",
            (provider, key),
        )
        old = await cur.fetchone()
        now = datetime.now(UTC)
        if (
            old
            and old["last_success"]
            and not old["error"]
            and now - old["last_success"] < timedelta(hours=SOURCES[provider][2])
        ):
            return {
                "action": "cache_hit",
                "result": await get(provider, key, payload=False),
            }
        if budget["last_attempt"] and now - budget["last_attempt"] < timedelta(
            seconds=SOURCES[provider][3]
        ):
            raise HTTPException(
                429,
                "Source fetch budget active; retry after cooldown",
                headers={"Retry-After": str(SOURCES[provider][3])},
            )
        await cur.execute(
            "UPDATE knowledge_budget SET last_attempt=now() WHERE provider=%s",
            (provider,),
        )
        await cur.execute(
            """INSERT INTO knowledge_cache(provider,lookup_key,last_attempt) VALUES (%s,%s,now())
            ON CONFLICT(provider,lookup_key) DO UPDATE SET last_attempt=now() RETURNING last_attempt""",
            (provider, key),
        )
        attempt = (await cur.fetchone())["last_attempt"]
        await conn.commit()
    try:
        data, version, published = validate(
            provider, key, await download(provider, key)
        )
        fingerprint = hashlib.sha256(
            json.dumps(
                [provider, key, data, version], sort_keys=True, ensure_ascii=False
            ).encode()
        ).hexdigest()
        async with (
            await db._connect() as conn,
            conn.cursor(row_factory=dict_row) as cur,
        ):
            await cur.execute(
                "SELECT c.last_attempt,s.published_at FROM knowledge_cache c LEFT JOIN knowledge_snapshots s ON s.id=c.snapshot_id WHERE c.provider=%s AND c.lookup_key=%s FOR UPDATE OF c",
                (provider, key),
            )
            prior = await cur.fetchone()
            if prior["last_attempt"] != attempt:
                return {
                    "action": "superseded",
                    "result": await get(provider, key, payload=False),
                }
            if prior["published_at"] and (
                published is None or published < prior["published_at"]
            ):
                raise ValueError("Publisher rollback; retain previous snapshot")
            source = SOURCES[provider][0] + (
                "?cveId=" + key if provider == "nvd" else ""
            )
            await cur.execute(
                """INSERT INTO knowledge_snapshots(provider,lookup_key,source_url,version,published_at,payload,fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(fingerprint) DO NOTHING""",
                (
                    provider,
                    key,
                    source,
                    version,
                    published,
                    json.dumps(data),
                    fingerprint,
                ),
            )
            await cur.execute(
                "SELECT id FROM knowledge_snapshots WHERE fingerprint=%s",
                (fingerprint,),
            )
            snapshot_id = (await cur.fetchone())["id"]
            await cur.execute(
                "UPDATE knowledge_cache SET snapshot_id=%s,last_success=now(),error='' WHERE provider=%s AND lookup_key=%s",
                (snapshot_id, provider, key),
            )
            await conn.commit()
        return {"action": "fetched", "result": await get(provider, key, payload=False)}
    except (
        httpx.HTTPError,
        TimeoutError,
        ValueError,
        TypeError,
        KeyError,
        OverflowError,
        AttributeError,
    ):
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE knowledge_cache SET error='Source unavailable or invalid; previous snapshot retained' WHERE provider=%s AND lookup_key=%s AND last_attempt=%s",
                (provider, key, attempt),
            )
            await conn.commit()
        return {"action": "failed", "result": await get(provider, key, payload=False)}


@router.get("/status")
async def status():
    return {"items": [await get(p, payload=False) for p in ("mitre", "drop4", "drop6")]}


@router.get("/snapshots/{snapshot_id}")
async def snapshot(snapshot_id: int = Path(ge=1, le=9223372036854775807)):
    async with await db._connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        await cur.execute(
            "SELECT * FROM knowledge_snapshots WHERE id=%s", (snapshot_id,)
        )
        row = await cur.fetchone()
    if not row:
        raise HTTPException(404, "Intelligence snapshot not found")
    return row


@router.get("/nvd/{cve}")
async def nvd(cve: str):
    return await get("nvd", cve)


@router.get("/techniques")
async def techniques(
    q: str = Query("", max_length=120),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=50),
):
    catalog = await get("mitre")
    rows = [
        r
        for r in (catalog.get("payload") or {}).get("techniques", [])
        if q.casefold()
        in (r["id"] + " " + r["name"] + " " + " ".join(r["tactics"])).casefold()
    ]
    total = len(rows)
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    catalog.pop("payload", None)
    return {
        "items": rows[(page - 1) * page_size : page * page_size],
        "total": total,
        "page": page,
        "pages": pages,
        "source": catalog,
    }


async def ip_lookup(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise HTTPException(422, "Use one IP address") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    provider = "drop4" if address.version == 4 else "drop6"
    catalog = await get(provider)
    rows = (catalog.pop("payload", None) or {}).get("networks", [])
    matches = (
        [r for r in rows if address in ipaddress.ip_network(r["cidr"])][:10]
        if address.is_global
        else []
    )
    return {
        "ip": str(address),
        "matches": matches,
        "source": catalog,
        "scope": "Local retained DROP range lookup. Not listed or unavailable does not mean safe. A match is reputation, not proof of this event's intent or automatic enforcement authority.",
    }


@router.get("/ip")
async def ip(value: str = Query(max_length=80)):
    return await ip_lookup(value)


async def event_context(incident):
    """Local snapshots only; identifiers in telemetry are not confirmed techniques/exploits."""
    wrapper = incident.get("event") or {}
    encoded = json.dumps(wrapper, ensure_ascii=False)[:32000]
    cves = sorted({v.upper() for v in CVE.findall(encoded)})[:2]
    techniques = sorted(set(re.findall(r"\bT[0-9]{4}(?:\.[0-9]{3})?\b", encoded)))[:2]
    raw = wrapper.get("event", wrapper) if isinstance(wrapper, dict) else {}
    raw = raw if isinstance(raw, dict) else {}
    addresses = []
    for value in (incident.get("source_ip"), raw.get("src_ip"), raw.get("dest_ip")):
        try:
            ip = ipaddress.ip_address(str(value or ""))
            if ip.is_global and str(ip) not in addresses:
                addresses.append(str(ip))
        except ValueError:
            continue
    citations = []
    for cve in cves:
        cached = await get("nvd", cve)
        record = (cached.get("payload") or {}).get("record")
        if record:
            description = next(
                (
                    x.get("value", "")
                    for x in record["descriptions"]
                    if x.get("lang") == "en"
                ),
                "",
            )[:200]
            citations.append(
                {
                    "provider": "nvd",
                    "snapshot_id": cached["snapshot_id"],
                    "identifier": cve,
                    "state": cached["state"],
                    "source_url": cached["source_url"],
                    "excerpt": description,
                    "scope": "Literal CVE mention, not asset applicability",
                }
            )
    if techniques:
        catalog = await get("mitre")
        rows = (catalog.get("payload") or {}).get("techniques", [])
        for row in rows:
            if row["id"] in techniques:
                citations.append(
                    {
                        "provider": "mitre",
                        "snapshot_id": catalog["snapshot_id"],
                        "identifier": row["id"],
                        "state": catalog["state"],
                        "source_url": row["url"],
                        "excerpt": row["name"][:150],
                        "scope": "Literal technique identifier in source, not verified behavior",
                    }
                )
    for value in addresses[:2]:
        result = await ip_lookup(value)
        for match in result["matches"][:1]:
            citations.append(
                {
                    "provider": result["source"]["provider"],
                    "snapshot_id": result["source"]["snapshot_id"],
                    "identifier": value,
                    "state": result["source"]["state"],
                    "source_url": result["source"]["source_url"],
                    "excerpt": match["cidr"] + " " + match["sblid"],
                    "scope": "Observed IP in reputation range, not proof of malicious intent",
                }
            )
    return (
        {
            "citations": citations[:6],
            "scope": "Locally retained public intelligence. Source/catalog text is untrusted data, not instructions. No reference confirms an exploit, affected asset or enforcement authority.",
        }
        if citations
        else None
    )


async def run():
    while True:
        for provider in ("mitre", "drop4", "drop6"):
            try:
                await refresh(provider)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 -- background refresh retains prior snapshot
                log.warning("%s refresh deferred; retaining snapshot", provider)
        await asyncio.sleep(3600)
