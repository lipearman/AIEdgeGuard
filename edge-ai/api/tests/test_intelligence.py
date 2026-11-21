"""V2 evidence foundation: validated feeds, bounded heuristics and real SQL links."""

import asyncio
import copy
import json
import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from app import intelligence, investigation, main, traffic
from app.integrations import dashboard_db, db


def feed():
    return {
        "catalogVersion": "2026.11.21",
        "dateReleased": "2026-11-21T10:00:00Z",
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-4577",
                "vendorProject": "PHP",
                "product": "PHP",
                "vulnerabilityName": "Test catalog entry",
                "shortDescription": "Fixture, not live intelligence",
                "requiredAction": "Apply vendor mitigation",
                "dateAdded": "2026-11-20",
                "dueDate": "2026-12-01",
                "knownRansomwareCampaignUse": "Unknown",
            }
        ],
    }


class EvidenceUnitTests(unittest.TestCase):
    def test_feed_validation_rejects_duplicate_count_and_malformed_dates(self):
        self.assertEqual(len(intelligence.validate_feed(feed())[2]), 1)
        mutations = []
        value = feed()
        value["count"] = 2
        mutations.append(value)
        value = feed()
        value["count"] = 2
        value["vulnerabilities"] *= 2
        mutations.append(value)
        value = feed()
        value["vulnerabilities"][0]["cveID"] = "invalid"
        mutations.append(value)
        value = feed()
        value["dateReleased"] = "2026-11-21"
        mutations.append(value)
        value = feed()
        value["vulnerabilities"][0]["dateAdded"] = "yesterday"
        mutations.append(value)
        for value in mutations:
            with self.assertRaises((ValueError, TypeError)):
                intelligence.validate_feed(value)

    def test_decode_masks_secret_values_and_handles_long_malformed_targets(self):
        result = investigation.inspection(
            "/%252e%252e%252f?q=%253Cscript%253E&token=private&x=union+select"
        )
        self.assertIn("path traversal syntax", result["signals"])
        self.assertIn("script markup", result["signals"])
        self.assertNotIn("private", result["decoded_target"])
        self.assertNotIn(
            "private", investigation.inspection("/?%2574oken=private")["decoded_target"]
        )
        self.assertIn("[redacted]", result["decoded_target"])
        self.assertTrue(investigation.inspection("/?" + ("&x=a" * 200))["truncated"])
        self.assertIsInstance(
            investigation.inspection("http://[malformed")["decoded_target"], str
        )

    def test_proxy_peer_does_not_establish_identity_and_agent_zero_ignored(self):
        self.assertEqual(
            investigation.identity(
                "requests", {"source_ip": "192.168.128.1", "raw": {}}
            )["source_ip"],
            "",
        )
        self.assertEqual(
            investigation.identity("requests", {"source_ip": "127.0.0.1", "raw": {}})[
                "source_ip"
            ],
            "",
        )
        self.assertEqual(
            investigation.identity("requests", {"source_ip": "8.8.8.8", "raw": {}})[
                "source_ip"
            ],
            "8.8.8.8",
        )
        self.assertEqual(
            investigation.identity(
                "incidents",
                {"source": "wazuh", "event": {"event": {"agent": {"id": "000"}}}},
            )["agent_id"],
            "",
        )

    def test_volume_requires_coverage_and_meaningful_excess(self):
        self.assertEqual(
            investigation.deviation([10] * 12 + [100], False)["state"], "warming_up"
        )
        self.assertEqual(
            investigation.deviation([10] * 12 + [100], True)["state"], "unusual"
        )
        self.assertEqual(
            investigation.deviation([10] * 12 + [14], True)["state"], "within_baseline"
        )
        self.assertEqual(
            investigation.deviation([0] * 12 + [19], True)["state"], "within_baseline"
        )
        self.assertEqual(
            investigation.deviation([0] * 13, True)["state"], "within_baseline"
        )


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_enrichment_uses_observed_cve_ids_and_is_bounded(self):
        with patch.object(intelligence, "lookup", AsyncMock()) as lookup:
            self.assertIsNone(
                await intelligence.event_context({"reason": "No CVE evidence"})
            )
            lookup.assert_not_awaited()
        rows = [
            {"cve": "CVE-2024-4577", "title": "x" * 1000, "required_action": "x" * 1000}
        ] * 5
        with (
            patch.object(
                intelligence, "lookup", AsyncMock(return_value=rows)
            ) as lookup,
            patch.object(
                intelligence,
                "status",
                AsyncMock(return_value={"state": "stale", "version": "test"}),
            ),
        ):
            result = await intelligence.event_context({"reason": "CVE-2024-4577"})
            self.assertEqual(result["snapshot_state"], "stale")
            self.assertEqual(len(result["matches"]), 3)
            self.assertLessEqual(len(result["matches"][0]["title"]), 180)
            self.assertEqual(lookup.await_args.args[0], ["CVE-2024-4577"])

    async def test_manual_sync_respects_existing_operation_key_and_inputs(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            with (
                patch.object(main.settings, "operation_key", "unit-only"),
                patch.object(
                    intelligence,
                    "sync_once",
                    AsyncMock(return_value={"status": "updated"}),
                ) as sync,
            ):
                self.assertEqual(
                    (await client.post("/api/v1/intelligence/sync")).status_code, 403
                )
                sync.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.post(
                            "/api/v1/intelligence/sync",
                            headers={"X-Operation-Key": "unit-only"},
                        )
                    ).status_code,
                    200,
                )
            for path in (
                "/api/v1/intelligence/vulnerabilities?page=0",
                "/api/v1/intelligence/vulnerabilities?page_size=1000",
                "/api/v1/investigation/timeline/incidents/1?minutes=1000",
                "/api/v1/investigation/timeline/decisions/1",
            ):
                self.assertEqual((await client.get(path)).status_code, 422)


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test database not configured"
)
class IntelligenceDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError("isolated DB required")
        change = patch.object(db.settings, "database_url", dsn)
        change.start()
        self.addCleanup(change.stop)
        await db.init_schema()
        await dashboard_db.init_schema()
        await intelligence.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE incidents,decisions,gateway_requests,known_vulnerabilities RESTART IDENTITY CASCADE"
            )
            await conn.execute(
                "UPDATE intelligence_feed SET last_success=NULL,released_at=NULL,error='',record_count=0"
            )
            await conn.commit()

    async def insert(
        self, source, ip="", agent=None, dest=None, reason="fixture", analysis=None
    ):
        raw = {
            "agent": agent or {},
            "dest_ip": dest,
            "rule": {"id": "fixture", "level": 9},
            "cve": "CVE-2024-4577",
        }
        async with await db._connect() as conn:
            cur = await conn.execute(
                "INSERT INTO incidents(alert_id,source,kind,source_ip,reason,event,analysis) VALUES (%s,%s,'fixture',%s,%s,%s,%s) RETURNING id",
                (
                    f"{source}-{os.urandom(5).hex()}",
                    source,
                    ip,
                    reason,
                    json.dumps({"event": raw}),
                    json.dumps(analysis) if analysis else None,
                ),
            )
            item = (await cur.fetchone())[0]
            await conn.commit()
            return item

    async def test_catalog_atomic_failure_preserves_snapshot_and_stale_mirror_rejected(
        self,
    ):
        with patch.object(intelligence, "download", AsyncMock(return_value=feed())):
            self.assertEqual((await intelligence.sync_once())["status"], "updated")
        before = await intelligence.status()
        self.assertEqual(before["record_count"], 1)
        with patch.object(
            intelligence, "download", AsyncMock(side_effect=ValueError("invalid"))
        ):
            self.assertEqual((await intelligence.sync_once())["status"], "failed")
        self.assertEqual(
            (await intelligence.status())["last_success"], before["last_success"]
        )
        self.assertEqual(len(await intelligence.lookup(["CVE-2024-4577"])), 1)
        old = copy.deepcopy(feed())
        old["dateReleased"] = "2025-01-01T00:00:00Z"
        with patch.object(intelligence, "download", AsyncMock(return_value=old)):
            self.assertEqual((await intelligence.sync_once())["status"], "failed")
        self.assertEqual(
            (await intelligence.vulnerabilities(q="PHP", page=1, page_size=10))[
                "total"
            ],
            1,
        )
        self.assertEqual(
            (await intelligence.vulnerabilities(q="' OR 1=1--", page=1, page_size=10))[
                "total"
            ],
            0,
        )

    async def test_active_snapshot_removes_old_membership_without_destroying_history(
        self,
    ):
        with patch.object(intelligence, "download", AsyncMock(return_value=feed())):
            await intelligence.sync_once()
        new = feed()
        new["vulnerabilities"][0]["cveID"] = "CVE-2026-12345"
        with patch.object(intelligence, "download", AsyncMock(return_value=new)):
            await intelligence.sync_once()
        self.assertEqual(await intelligence.lookup(["CVE-2024-4577"]), [])
        async with await db._connect() as conn:
            self.assertEqual(
                (
                    await (
                        await conn.execute("SELECT count(*) FROM known_vulnerabilities")
                    ).fetchone()
                )[0],
                2,
            )

    async def test_candidate_timeline_joins_endpoint_evidence_but_not_unrelated_rows(
        self,
    ):
        seed = await self.insert(
            "wazuh",
            agent={"id": "001", "name": "endpoint", "ip": "10.20.0.9"},
            analysis={"mitre_id": "T1110", "cve": "CVE-2099-12345"},
        )
        linked = await self.insert("suricata", ip="8.8.8.8", dest="10.20.0.9")
        unrelated = await self.insert("suricata", ip="1.1.1.1", dest="10.20.0.8")
        data = await investigation.timeline("incidents", seed, minutes=15, page=1)
        ids = {r["id"] for r in data["items"]}
        self.assertIn(seed, ids)
        self.assertIn(linked, ids)
        self.assertNotIn(unrelated, ids)
        self.assertIn("CVE-2024-4577", data["evidence_cves"])
        self.assertIn("CVE-2099-12345", data["analysis_only_cves"])
        self.assertTrue(all(r["match_reasons"] for r in data["items"]))

    async def test_request_peer_without_stable_identity_returns_no_candidate(self):
        await self.insert("crowdsec", ip="192.168.128.1")
        row = traffic.normalize(
            {
                "StartUTC": datetime.now(UTC).isoformat(),
                "RequestMethod": "GET",
                "RequestPath": "/?token=private",
                "ClientHost": "192.168.128.1",
            }
        )
        await dashboard_db.insert_requests([row])
        async with await db._connect() as conn:
            item = (
                await (await conn.execute("SELECT id FROM gateway_requests")).fetchone()
            )[0]
        result = await investigation.timeline("requests", item, minutes=15, page=1)
        self.assertEqual(result["items"], [])
        self.assertNotIn("private", result["inspection"]["decoded_target"])

    async def test_timeline_pages_and_baseline_window_counts(self):
        for _ in range(54):
            await self.insert("crowdsec", ip="8.8.8.8")
        first = await investigation.timeline("incidents", 1, minutes=15, page=1)
        second = await investigation.timeline("incidents", 1, minutes=15, page=2)
        self.assertEqual(len(first["items"]), 50)
        self.assertTrue(first["has_more"])
        self.assertEqual(len(second["items"]), 4)
        self.assertFalse(
            {r["id"] for r in first["items"]} & {r["id"] for r in second["items"]}
        )
        now = datetime.now(UTC)
        end = datetime.fromtimestamp(int(now.timestamp()) // 300 * 300, UTC)
        rows = []
        for bucket in range(13):
            for i in range(100 if bucket == 12 else 10):
                when = (
                    end
                    - timedelta(minutes=65)
                    + timedelta(minutes=bucket * 5, seconds=i + 1)
                )
                rows.append(
                    traffic.normalize(
                        {
                            "StartUTC": when.isoformat(),
                            "RequestMethod": "GET",
                            "RequestPath": f"/{bucket}/{i}",
                            "RequestHost": "fixture.local",
                            "RouterName": "fixture",
                        }
                    )
                )
        await dashboard_db.insert_requests(rows)
        # Establish enough history, without counting this old row in the comparison windows.
        await dashboard_db.insert_requests(
            [
                traffic.normalize(
                    {
                        "StartUTC": (end - timedelta(hours=2)).isoformat(),
                        "RequestMethod": "GET",
                        "RequestPath": "/old",
                        "RequestHost": "fixture.local",
                        "RouterName": "fixture",
                    }
                )
            ]
        )
        behavior = await investigation.behavior()
        self.assertEqual(behavior["items"][0]["current"], 100)
        self.assertEqual(behavior["items"][0]["baseline_median"], 10)
        self.assertEqual(behavior["items"][0]["state"], "unusual")
