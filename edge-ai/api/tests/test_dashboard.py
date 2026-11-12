"""Request-history and server paging regressions; only isolated DB is writable."""

import asyncio
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from app import main, traffic
from app.integrations import dashboard_db, db


def record(index):
    return traffic.normalize(
        {
            "StartUTC": f"2026-11-12T10:00:{index % 60:02d}.123456789Z",
            "RequestMethod": "GET",
            "RequestPath": f"/request/{index}",
            "RequestHost": "lab.example",
            "ClientHost": "10.0.0.5",
            "DownstreamStatus": 403 if index % 3 == 0 else 200,
            "Duration": index * 1000,
            "RouterName": "lab@file",
            "request_User-Agent": "test-agent",
        }
    )


class CollectorTests(unittest.IsolatedAsyncioTestCase):
    def test_long_unicode_target_is_not_truncated(self):
        raw = {
            "StartUTC": "2026-11-12T10:00:00Z",
            "RequestMethod": "GET",
            "RequestPath": "/ทดสอบ?query=" + "x" * 500,
        }
        self.assertEqual(traffic.normalize(raw)["path"], raw["RequestPath"])

    def test_partial_log_line_waits_for_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            line = json.dumps(record(1)["raw"]).encode()
            path.write_bytes(line + b"\n" + line[:20])
            rows, state = traffic.read_batch(path, {})
            self.assertEqual(len(rows), 1)
            with path.open("ab") as writer:
                writer.write(line[20:] + b"\n")
            rows, _ = traffic.read_batch(path, state)
            self.assertEqual(len(rows), 1)

    async def test_failed_db_write_never_advances_log_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "access.log"
            path.write_text(json.dumps(record(1)["raw"]) + "\n")
            redis = AsyncMock()
            redis.get.return_value = None
            with (
                patch.object(traffic.settings, "request_log_path", str(path)),
                patch.object(
                    dashboard_db,
                    "insert_requests",
                    side_effect=RuntimeError("database offline"),
                ),
                self.assertRaises(RuntimeError),
            ):
                await traffic.collect_once(redis)
            redis.set.assert_not_awaited()


class PagingApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_bad_collection_and_page_parameters_are_rejected(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            for path in [
                "/api/v1/dashboard/data/unknown",
                "/api/v1/dashboard/data/requests?page=0",
                "/api/v1/dashboard/data/requests?page_size=1000",
                "/api/v1/dashboard/data/requests?snapshot=-1",
            ]:
                response = await client.get(path)
                self.assertEqual(response.status_code, 422, path)


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test database not configured"
)
class PagingDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError("Test database name required")
        settings_patch = patch.object(db.settings, "database_url", dsn)
        settings_patch.start()
        self.addCleanup(settings_patch.stop)
        await db.init_schema()
        await dashboard_db.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE gateway_requests,incidents,campaigns,decisions,attacks RESTART IDENTITY"
            )
            await conn.commit()

    async def test_snapshot_paging_has_no_duplicates_when_new_requests_arrive(self):
        await dashboard_db.insert_requests([record(i) for i in range(53)])
        first = await dashboard_db.page("requests", 1, 10)
        await dashboard_db.insert_requests([record(1000)])
        second = await dashboard_db.page("requests", 2, 10, snapshot=first["snapshot"])
        self.assertEqual(first["total"], 53)
        self.assertEqual(second["total"], 53)
        self.assertFalse(
            {r["id"] for r in first["items"]} & {r["id"] for r in second["items"]}
        )
        fresh = await dashboard_db.page("requests", 1, 10)
        self.assertEqual(fresh["total"], 54)

    async def test_search_is_literal_and_http_filters_apply_before_paging(self):
        rows = [record(i) for i in range(30)]
        rows[0]["path"] = "/ทดสอบ/100%_real"
        await dashboard_db.insert_requests(rows)
        filtered = await dashboard_db.page("requests", 1, 5, status="403")
        self.assertEqual(filtered["total"], 10)
        self.assertTrue(all(r["status"] == 403 for r in filtered["items"]))
        self.assertEqual(
            (await dashboard_db.page("requests", 1, 10, query="%_real"))["total"], 1
        )
        self.assertEqual(
            (await dashboard_db.page("requests", 1, 10, query="' OR 1=1--"))["total"], 0
        )
        with self.assertRaises(ValueError):
            await dashboard_db.page("requests", 1, 10, status="bad")

    async def test_approval_paging_filters_the_full_table(self):
        async with await db._connect() as conn:
            async with conn.cursor() as cursor:
                await cursor.executemany(
                    """INSERT INTO decisions(incident_alert_id,action,policy_verdict,status)
                VALUES('test','temporary_ip_block','approve',%s)""",
                    [
                        ("pending_approval" if i < 30 else "executed",)
                        for i in range(180)
                    ],
                )
            await conn.commit()
        result = await dashboard_db.page("approvals", 2, 10)
        self.assertEqual(result["total"], 30)
        self.assertEqual(result["pages"], 3)
        self.assertTrue(all(r["status"] == "pending_approval" for r in result["items"]))

    async def test_detail_keeps_headers_full_path_and_honest_capture_flags(self):
        item = record(1)
        item["path"] = "/long/" + "a" * 300
        await dashboard_db.insert_requests([item, item])
        result = await dashboard_db.detail("requests", 1)
        self.assertEqual(result["path"], item["path"])
        self.assertEqual(result["capture"]["headers"]["User-Agent"], "test-agent")
        self.assertFalse(result["capture"]["body_captured"])
        self.assertFalse(result["capture"]["pcap_captured"])
        self.assertEqual((await dashboard_db.summary())["requests"], 1)
        self.assertIsNone(await dashboard_db.detail("requests", 99999))

    async def test_retention_and_out_of_range_pages_are_bounded(self):
        # Use current times so only the row-count retention branch applies.
        from datetime import UTC, datetime

        rows = [record(i) for i in range(25)]
        for item in rows:
            item["observed_at"] = datetime.now(UTC)
        await dashboard_db.insert_requests(rows)
        await dashboard_db.prune_requests(10, 7)
        result = await dashboard_db.page("requests", 9999, 6)
        self.assertEqual(result["total"], 10)
        self.assertEqual(result["page"], 2)
        self.assertEqual(len(result["items"]), 4)
