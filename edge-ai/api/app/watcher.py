"""Watcher — polls CrowdSec LAPI for new alerts and ingests them.

Flow: LAPI /v1/alerts (latest 100) -> dedupe (DB, alert_id UNIQUE)
      -> new ones: INSERT incident + XADD to Redis stream `edge:events`
      -> the worker consumes the stream and runs the Analysis Agent.

Notes:
- dedup survives restarts because alert_id is UNIQUE in PostgreSQL, so we
  simply re-read the latest alerts each poll instead of relying on `since`
  (the `since` query param returns HTTP 500 on CrowdSec v1.8.2)
"""

import asyncio
import json
import sys

import redis.asyncio as aioredis

from app.config import settings
from app.integrations import crowdsec_client, db

STREAM = "edge:events"


def _normalize(alert: dict) -> dict:
    """Map a LAPI alert into our incident shape.

    LAPI v1.8 JSON field notes (verified against a live response):
    - 'message'/'scenario' carry what `cscli alerts list` shows as "reason"
      (the JSON 'reason' key is null)
    - 'source' is a single object (not a list)
    - 'meta' is a list of {key,value}
    """
    source = alert.get("source") or {}
    source_ip = str(source.get("ip") or source.get("value") or "")
    kind = str(alert.get("kind") or "unknown")
    severity = "high" if kind in ("waf", "ban") else "medium"
    reason = str(alert.get("message") or alert.get("scenario") or "")
    alert_id = f"c-{alert.get('id')}"  # LAPI ids are ints; prefix avoids clashing with EVT-*
    return {
        "alert_id": alert_id,
        "source": "crowdsec",
        "kind": kind,
        "severity": severity,
        "reason": reason,
        "source_ip": source_ip,
        "event": alert,  # raw alert preserved as evidence
    }


async def run() -> None:
    """Poll loop. Cancelled on app shutdown."""
    r = aioredis.from_url(settings.redis_url, socket_timeout=None, decode_responses=True)
    interval = max(10, settings.poll_interval_seconds)
    sys.stderr.write(f"[watcher] started, poll every {interval}s\n")
    while True:
        try:
            alerts = await crowdsec_client.list_alerts(limit=100)
            new_count = 0
            for alert in alerts:
                normalized = _normalize(alert)
                if await db.insert_incident(normalized) is not None:
                    await r.xadd(
                        STREAM,
                        {"json": json.dumps(
                            {"event_id": normalized["alert_id"],
                             "source": normalized["source"],
                             "kind": normalized["kind"],
                             "severity": normalized["severity"],
                             "reason": normalized["reason"]},
                            ensure_ascii=False)},
                    )
                    new_count += 1
            if new_count:
                sys.stderr.write(f"[watcher] ingested {new_count}/{len(alerts)} alerts\n")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — poller must survive errors
            sys.stderr.write(f"[watcher] poll failed: {exc}\n")
        await asyncio.sleep(interval)
