"""Detection Agent — clusters analyzed incidents into attack campaigns.

Deterministic clustering (no LLM): group by (source_ip, attack_type) where
the campaign is still "open" (last incident seen within 24h). This gives the
Decision Agent and humans a campaign-level view instead of scattered alerts.
"""

import asyncio
import sys
from collections import defaultdict

from app.config import settings
from app.integrations import db

OPEN_WINDOW_HOURS = 24


async def cluster_once() -> int:
    unclustered = await db.list_unclustered_analyzed()
    if not unclustered:
        return 0
    groups = defaultdict(list)
    for inc in unclustered:
        groups[(inc["source_ip"], inc["attack_type"])].append(inc)

    touched = 0
    for (source_ip, attack_type), items in groups.items():
        alert_ids = [i["alert_id"] for i in items]
        campaign_id = await db.find_open_campaign(source_ip, attack_type)
        if campaign_id:
            await db.add_incidents_to_campaign(campaign_id, alert_ids)
        else:
            campaign_id = await db.create_campaign(
                source_ip=source_ip,
                attack_type=attack_type,
                severity=items[0]["severity"],
                incident_ids=alert_ids,
            )
        sys.stderr.write(
            f"[detection] campaign #{campaign_id}: {attack_type} from {source_ip} "
            f"+{len(alert_ids)} incident(s)\n"
        )
        touched += len(alert_ids)
    return touched


async def run() -> None:
    interval = 60
    sys.stderr.write("[detection] started, clustering every 60s\n")
    while True:
        try:
            await cluster_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"[detection] cluster failed: {exc}\n")
        await asyncio.sleep(interval)
