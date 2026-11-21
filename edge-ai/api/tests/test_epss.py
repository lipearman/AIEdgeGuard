"""EPSS schema, cache semantics, provenance and bounded external lookup contracts."""

import asyncio
import copy
import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from app import epss, main
from app.integrations import db

CVE = "CVE-2024-4577"


def document():
    return {
        "status": "OK",
        "status-code": 200,
        "version": "1.0",
        "offset": 0,
        "total": 1,
        "data": [
            {
                "cve": CVE,
                "epss": "0.81",
                "percentile": "0.99",
                "date": datetime.now(UTC).date().isoformat(),
            }
        ],
    }


class EpssContracts(unittest.IsolatedAsyncioTestCase):
    async def test_validate_types_bounds_dates_and_unrequested_results(self):
        self.assertEqual(float(epss.validate(document(), CVE)[0]["epss"]), 0.81)
        for field, values in (
            ("epss", [True, None, "NaN", "Infinity", "-0.1", "1.01"]),
            ("percentile", [None, False, "NaN", "2"]),
            (
                "date",
                ["invalid", (datetime.now(UTC) + timedelta(days=2)).date().isoformat()],
            ),
            ("cve", ["CVE-2025-12345"]),
        ):
            for value in values:
                d = document()
                d["data"][0][field] = value
                with self.assertRaises((ValueError, TypeError)):
                    epss.validate(d, CVE)
        for changes in (
            {"total": 2},
            {"total": True},
            {"offset": 1},
            {"data": [document()["data"][0]] * 2},
            {"status": "FAILED"},
            {"version": {}},
        ):
            with self.assertRaises((ValueError, TypeError)):
                epss.validate({**document(), **changes}, CVE)
        self.assertIsNone(epss.validate({**document(), "total": 0, "data": []}, CVE)[0])

    async def test_operation_gate_and_read_only_get(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            with (
                patch.object(main.settings, "operation_key", "fixture-key"),
                patch.object(
                    epss, "refresh", AsyncMock(return_value={"action": "fetched"})
                ) as refresh,
                patch.object(
                    epss, "cached", AsyncMock(return_value={"state": "never_fetched"})
                ),
            ):
                self.assertEqual(
                    (await client.post("/api/v1/intelligence/epss/" + CVE)).status_code,
                    403,
                )
                self.assertEqual(
                    (await client.get("/api/v1/intelligence/epss/" + CVE)).status_code,
                    200,
                )
                refresh.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.post(
                            "/api/v1/intelligence/epss/" + CVE,
                            headers={"X-Operation-Key": "fixture-key"},
                        )
                    ).status_code,
                    200,
                )
        for value in ("CVE-2024", "https://example.com", CVE + ",CVE-2025-12345"):
            with self.assertRaises(main.HTTPException):
                epss.canonical(value)

    async def test_download_does_not_follow_redirect_or_accept_oversized_response(self):
        original = httpx.AsyncClient
        for response in (
            httpx.Response(302, headers={"location": "http://127.0.0.1/"}),
            httpx.Response(200, content=b"x" * 66000),
        ):
            with (
                patch.object(
                    epss.httpx,
                    "AsyncClient",
                    lambda response=response, **options: original(
                        **options,
                        transport=httpx.MockTransport(lambda request: response),
                    ),
                ),
                self.assertRaises((httpx.HTTPError, ValueError)),
            ):
                await epss.download(CVE)


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test DB not configured"
)
class EpssDatabase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError("isolated DB required")
        change = patch.object(db.settings, "database_url", dsn)
        change.start()
        self.addCleanup(change.stop)
        await epss.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE epss_cache,epss_snapshots RESTART IDENTITY CASCADE"
            )
            await conn.execute("UPDATE epss_request_budget SET last_attempt=NULL")
            await conn.commit()

    async def expire(self):
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE epss_cache SET last_success=now()-interval '25 hours'"
            )
            await conn.execute("UPDATE epss_request_budget SET last_attempt=NULL")
            await conn.commit()

    async def test_fresh_cache_skips_network_and_snapshot_provenance_is_immutable(self):
        self.assertEqual((await epss.cached(CVE))["state"], "never_fetched")
        with patch.object(
            epss, "download", AsyncMock(return_value=document())
        ) as download:
            first = await epss.refresh(CVE)
            second = await epss.refresh(CVE)
        self.assertEqual(download.await_count, 1)
        self.assertEqual(second["action"], "cache_hit")
        snap = await epss.snapshot(first["result"]["score"]["snapshot_id"])
        self.assertEqual(snap["cve"], CVE)
        self.assertEqual(snap["api_version"], "1.0")
        for sql in ("UPDATE epss_snapshots SET epss=0", "DELETE FROM epss_snapshots"):
            with self.assertRaises(psycopg.errors.RaiseException):
                async with await db._connect() as conn:
                    await conn.execute(sql)
        await self.expire()
        with patch.object(epss, "download", AsyncMock(return_value=document())):
            third = await epss.refresh(CVE)
        self.assertEqual(third["result"]["score"]["snapshot_id"], snap["id"])

    async def test_failure_and_not_scored_keep_earlier_score_separate(self):
        with patch.object(epss, "download", AsyncMock(return_value=document())):
            first = await epss.refresh(CVE)
        await self.expire()
        with patch.object(
            epss, "download", AsyncMock(side_effect=ValueError("invalid response"))
        ):
            result = await epss.refresh(CVE)
        self.assertEqual(result["result"]["state"], "refresh_failed")
        self.assertEqual(
            result["result"]["score"]["snapshot_id"],
            first["result"]["score"]["snapshot_id"],
        )
        self.assertEqual(result["result"]["score"]["state"], "stale")
        await self.expire()
        with patch.object(
            epss,
            "download",
            AsyncMock(return_value={**document(), "data": [], "total": 0}),
        ):
            result = await epss.refresh(CVE)
        self.assertEqual(result["result"]["state"], "not_scored")
        self.assertIsNotNone(result["result"]["score"])
        self.assertEqual(result["result"]["score"]["state"], "stale")

    async def test_global_budget_serializes_different_cves(self):
        with patch.object(
            epss, "download", AsyncMock(return_value=document())
        ) as download:
            results = await asyncio.gather(
                epss.refresh(CVE),
                epss.refresh("CVE-2025-12345"),
                return_exceptions=True,
            )
        self.assertEqual(download.await_count, 1)
        self.assertEqual(
            sum(
                isinstance(r, main.HTTPException) and r.status_code == 429
                for r in results
            ),
            1,
        )

    async def test_late_response_cannot_overwrite_a_newer_attempt(self):
        async def supersede(cve, fail=False):
            async with await db._connect() as conn:
                await conn.execute(
                    "UPDATE epss_cache SET last_attempt=now()+interval '1 minute' WHERE cve=%s",
                    (cve,),
                )
                await conn.commit()
            if fail:
                raise ValueError("late failed request")
            return document()

        with patch.object(epss, "download", side_effect=supersede):
            result = await epss.refresh(CVE)
        self.assertEqual(result["action"], "superseded")
        self.assertIsNone(result["result"]["score"])
        await self.expire()

        async def late_failure(cve):
            return await supersede(cve, fail=True)

        with patch.object(epss, "download", side_effect=late_failure):
            result = await epss.refresh(CVE)
        self.assertEqual(result["result"]["error"], "")

    async def test_old_publisher_date_is_stale_and_downgrade_does_not_replace(self):
        doc = document()
        doc["data"][0]["date"] = (
            (datetime.now(UTC) - timedelta(days=7)).date().isoformat()
        )
        with patch.object(epss, "download", AsyncMock(return_value=doc)):
            first = await epss.refresh(CVE)
        self.assertEqual(first["result"]["score"]["state"], "stale")
        await self.expire()
        older = copy.deepcopy(doc)
        older["data"][0]["date"] = (
            (datetime.now(UTC) - timedelta(days=8)).date().isoformat()
        )
        with patch.object(epss, "download", AsyncMock(return_value=older)):
            result = await epss.refresh(CVE)
        self.assertEqual(result["action"], "failed")
        self.assertEqual(
            result["result"]["score"]["snapshot_id"],
            first["result"]["score"]["snapshot_id"],
        )


if __name__ == "__main__":
    unittest.main()
