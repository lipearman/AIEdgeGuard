"""Read-only sensor ingestion: Suricata EVE spool and Wazuh manager alerts.

Offsets are checkpointed only after persistence. The existing durable outbox
publishes persisted incidents to Redis. No Docker socket or sensor credentials
are exposed to this API container.
"""

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import redis.asyncio as aioredis

from app.config import settings
from app.integrations import crowdsec_client, db

log = logging.getLogger(__name__)


def normalize(raw: dict, source: str) -> dict | None:
    if source == "suricata":
        if raw.get("event_type") != "alert":
            return None
        alert = raw.get("alert") or {}
        if int(alert.get("severity") or 3) > 2:
            return (
                None  # low-priority INFO remains in the sensor log, not the LLM queue
            )
        severity = {1: "high", 2: "medium", 3: "low"}.get(
            alert.get("severity"), "medium"
        )
        reason = str(alert.get("signature") or "Suricata network alert")
        source_ip = str(raw.get("src_ip") or "")
    else:
        if str((raw.get("agent") or {}).get("id", "000")) == "000":
            return None
        rule = raw.get("rule") or {}
        if "sca" in (rule.get("groups") or []) or int(rule.get("level") or 0) < 5:
            return None  # posture/inventory checks are not incident triage
        if "suricata" in (rule.get("groups") or []):
            return None  # ingested directly from EVE; do not duplicate
        level = int(rule.get("level") or 0)
        severity = (
            "critical"
            if level >= 12
            else "high"
            if level >= 8
            else "medium"
            if level >= 5
            else "low"
        )
        reason = str(rule.get("description") or "Wazuh host alert")
        # An endpoint's own address is not an attacker IP. Never make it an
        # automatic ban target for FIM, inventory, or endpoint policy events.
        source_ip = str((raw.get("data") or {}).get("srcip") or "")
    digest = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:24]
    return {
        "alert_id": f"{source}-{digest}",
        "source": source,
        "kind": "network_ids" if source == "suricata" else "host_edr",
        "severity": severity,
        "reason": reason,
        "source_ip": source_ip,
        "event": raw,
    }


def read_batch(
    path: Path, offset: int, limit: int = 100
) -> tuple[list[tuple[int, bytes]], int]:
    try:
        with path.open("rb") as handle:
            if handle.seek(0, 2) < offset:
                offset = 0  # truncated/rotated log
            handle.seek(offset)
            lines = []
            for _ in range(limit):
                line = handle.readline(262144)
                if not line or not line.endswith(b"\n"):
                    break
                lines.append((handle.tell(), line))
            return lines, offset
    except FileNotFoundError:
        return [], offset


async def ingest_once(redis) -> int:
    total = 0
    inputs = [
        ("suricata", Path(settings.sensor_directory) / "suricata-alerts.jsonl"),
        ("wazuh", Path(settings.wazuh_alerts_path)),
    ]
    for source, path in inputs:
        if not path.exists():
            continue
        stat = path.stat()
        key = f"edge:telemetry:offset:{source}"
        checkpoint = await redis.get(key)
        state = json.loads(checkpoint) if checkpoint else {}
        offset = int(state.get("offset", 0)) if state.get("inode") == stat.st_ino else 0
        rows, _ = await asyncio.to_thread(read_batch, path, offset)
        for end, line in rows:
            try:
                incident = normalize(json.loads(line), source)
            except (ValueError, TypeError):
                log.warning("Ignoring malformed %s record at offset %s", source, end)
                incident = None
            if incident and await db.insert_incident(incident) is not None:
                total += 1
            await redis.set(key, json.dumps({"offset": end, "inode": stat.st_ino}))
    return total


async def run() -> None:
    async with aioredis.from_url(settings.redis_url, decode_responses=True) as redis:
        while True:
            try:
                count = await ingest_once(redis)
                if count:
                    log.info("Persisted %s sensor alerts", count)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Sensor ingestion failed; checkpoint preserved for retry")
            await asyncio.sleep(5)


async def visibility() -> dict:
    heartbeat = {}
    try:
        heartbeat = json.loads(
            (Path(settings.sensor_directory) / "status.json").read_text()
        )
        age = (
            datetime.now(UTC) - datetime.fromisoformat(heartbeat["timestamp"])
        ).total_seconds()
        fresh = -30 <= age < 60
    except (OSError, ValueError, KeyError, TypeError):
        fresh = False
    try:
        await crowdsec_client.list_alerts(limit=1)
        waf = True
    except Exception:
        log.exception("CrowdSec connectivity check failed")
        waf = False
    layers = {
        "http_waf": {
            "sensor": "CrowdSec AppSec + CRS",
            "state": "online" if waf else "unknown",
            "label": "ONLINE" if waf else "UNAVAILABLE",
            "detail": "CrowdSec AppSec · HTTP gateway",
        }
    }
    for key, sensor, default in [
        ("network_ids", "Suricata", "Awaiting Suricata sensor"),
        ("host_edr", "Wazuh", "Awaiting enrolled endpoint"),
    ]:
        data = heartbeat.get(key) or {}
        online = fresh and bool(data.get("online"))
        layers[key] = {
            "sensor": sensor,
            "state": "online" if online else "stale" if data else "not_connected",
            "label": "ONLINE"
            if online
            else "STALE / OFFLINE"
            if data
            else "NOT CONNECTED",
            "detail": data.get("detail") or default,
            "evidence": data,
            "heartbeat": heartbeat.get("timestamp"),
        }
    return {
        "layers": layers,
        "scope": "Network capture is limited to the configured WSL interface; no full Windows/LAN packet mirroring is implied.",
    }
