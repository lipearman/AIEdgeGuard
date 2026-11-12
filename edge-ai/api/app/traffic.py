"""Persist bounded access-log history for paging; never captures HTTP bodies."""

import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import redis.asyncio as aioredis

from app.config import settings
from app.integrations import dashboard_db

log = logging.getLogger(__name__)


def normalize(raw: dict) -> dict | None:
    if not raw.get("StartUTC") or not raw.get("RequestMethod"):
        return None
    observed = datetime.fromisoformat(str(raw["StartUTC"]))
    if observed.tzinfo is None:
        observed = observed.replace(tzinfo=UTC)
    encoded = json.dumps(raw, sort_keys=True, ensure_ascii=False)
    return {
        "fingerprint": hashlib.sha256(encoded.encode()).hexdigest(),
        "observed_at": observed,
        "source_ip": str(raw.get("ClientHost") or ""),
        "method": str(raw.get("RequestMethod") or ""),
        "path": str(raw.get("RequestPath") or ""),
        "host": str(raw.get("RequestHost") or ""),
        "status": int(raw.get("DownstreamStatus") or 0),
        "duration_ns": int(raw.get("Duration") or 0),
        "router": str(raw.get("RouterName") or ""),
        "raw": raw,
    }


def read_batch(path: Path, state: dict):
    stat = path.stat()
    offset = (
        state.get("offset", 0)
        if state.get("inode") == stat.st_ino
        else max(0, stat.st_size - 2_000_000)
    )
    if offset > stat.st_size:
        offset = 0
    rows = []
    with path.open("rb") as reader:
        reader.seek(offset)
        if not state and offset:
            reader.readline()  # bootstrap tail may start halfway through a line
        position = reader.tell()
        for _ in range(500):
            line = reader.readline()
            if not line or not line.endswith(b"\n"):
                break
            position = reader.tell()
            try:
                row = normalize(json.loads(line))
                if row:
                    rows.append(row)
            except (ValueError, TypeError):
                log.warning("Malformed access log at offset %s", position)
    return rows, {"inode": stat.st_ino, "offset": position}


async def collect_once(redis):
    path = Path(settings.request_log_path)
    if not path.exists():
        return 0
    checkpoint = await redis.get("edge:requests:checkpoint")
    rows, state = await asyncio.to_thread(
        read_batch, path, json.loads(checkpoint) if checkpoint else {}
    )
    await dashboard_db.insert_requests(rows)
    await redis.set("edge:requests:checkpoint", json.dumps(state))
    return len(rows)


async def run():
    tick = 0
    async with aioredis.from_url(settings.redis_url, decode_responses=True) as redis:
        while True:
            try:
                await collect_once(redis)
                if tick % 60 == 0:
                    await dashboard_db.prune_requests(
                        settings.request_max_rows, settings.request_retention_days
                    )
                tick += 1
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Request-history collector failed; will retry")
            await asyncio.sleep(3)
