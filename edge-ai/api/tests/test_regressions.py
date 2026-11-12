"""Run: python -m unittest discover -s edge-ai/api/tests -v (no live enforcement)."""

import asyncio
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
import yaml

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from app import main, watcher, worker
from app.agents import decider, decision, defense
from app.integrations import db


class PolicyTests(unittest.TestCase):
    def evaluate(self, **changes):
        args = {
            "proposal": {
                "action_type": "temporary_ip_block",
                "target": "source_ip",
                "duration_seconds": 1200,
            },
            "attack_type": "SQL Injection Attempt",
            "confidence": 0.9,
            "severity": "high",
            "source_ip": "8.8.8.8",
        }
        args.update(changes)
        return decision.evaluate(**args)

    def test_external_proposal_and_cooldown(self):
        self.assertEqual(self.evaluate().verdict, "approve")
        self.assertEqual(
            self.evaluate(recent_same_target=1).verdict, "pending_approval"
        )

    def test_model_cannot_choose_a_different_victim(self):
        d = self.evaluate(
            proposal={"action_type": "temporary_ip_block", "target": "1.1.1.1"}
        )
        self.assertEqual(d.verdict, "deny")

    def test_invalid_source_is_never_approved(self):
        self.assertEqual(self.evaluate(source_ip="bad-ip").verdict, "pending_approval")

    def test_protected_ipv4_ipv6_and_mapped_addresses(self):
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.20.0.5",
            "192.168.1.2",
            "100.99.80.84",
            "169.254.1.1",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.2",
        ]:
            with self.subTest(ip=ip):
                self.assertEqual(
                    self.evaluate(source_ip=ip).verdict, "pending_approval"
                )

    def test_review_and_injection_flags_prevent_auto_execution(self):
        for key in ["needs_human_review", "prompt_injection_suspected"]:
            self.assertEqual(self.evaluate(**{key: True}).verdict, "pending_approval")

    def test_bad_confidence_requires_review(self):
        for confidence in [0.2, -1, 2, float("nan"), float("inf")]:
            self.assertEqual(
                self.evaluate(confidence=confidence).verdict, "pending_approval"
            )

    def test_review_keeps_clamped_duration(self):
        for changes in [
            {"confidence": 0.2},
            {"attack_type": "unknown"},
            {"severity": "low"},
        ]:
            d = self.evaluate(
                proposal={
                    "action_type": "temporary_ip_block",
                    "duration_seconds": 99999,
                },
                **changes,
            )
            self.assertEqual(d.verdict, "pending_approval")
            self.assertEqual(d.duration_seconds, 3600)
        self.assertGreater(
            self.evaluate(
                proposal={"action_type": "temporary_ip_block", "duration_seconds": -20}
            ).duration_seconds,
            0,
        )


class PipelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_pending_work_is_not_acknowledged(self):
        redis = AsyncMock()
        redis.xautoclaim.return_value = [
            "0-0",
            [("1-0", {"json": '{"event_id":"x"}'})],
            [],
        ]
        with patch.object(db, "get_incident", side_effect=RuntimeError("DB offline")):
            await worker._drain_pending(redis)
        redis.xack.assert_not_awaited()

    async def test_claim_cursor_is_scanned_even_when_batch_is_empty(self):
        redis = AsyncMock()
        redis.xautoclaim.side_effect = [
            ["20-0", [], []],
            ["0-0", [("1-0", {"json": '{"event_id":"x"}'})], []],
        ]
        with patch.object(
            db, "get_incident", return_value={"analysis": {"attack_type": "known"}}
        ):
            self.assertEqual(await worker._drain_pending(redis), 1)
        redis.xack.assert_awaited_once()

    async def test_outbox_failure_can_be_retried(self):
        redis = AsyncMock()
        redis.xadd.side_effect = [RuntimeError("Redis offline"), "1-0"]
        with (
            patch.object(db, "list_unqueued", return_value=[{"event_id": "persisted"}]),
            patch.object(db, "mark_queued") as marked,
        ):
            with self.assertRaises(RuntimeError):
                await watcher.publish_pending(redis)
            marked.assert_not_awaited()
            self.assertEqual(await watcher.publish_pending(redis), 1)
            marked.assert_awaited_once_with("persisted")

    def test_nested_and_manual_evidence_is_preserved(self):
        evidence = worker._compact_evidence(
            {"event": {"event": {"evidence": {"payload": "sample"}, "meta": ["rule"]}}}
        )
        self.assertEqual(evidence["event_evidence"]["payload"], "sample")
        self.assertEqual(evidence["meta"], ["rule"])

    async def test_concurrent_approvals_execute_only_once(self):
        state = "pending_approval"

        async def update(_id, status, result="", expected_status=None):
            nonlocal state
            if expected_status is not None and state != expected_status:
                return False
            state = status
            return True

        with (
            patch.object(db, "update_decision_status", side_effect=update),
            patch.object(
                db,
                "get_decision",
                return_value={
                    "action": "temporary_ip_block",
                    "target": "8.8.8.8",
                    "duration_seconds": 60,
                    "policy_reason": "test",
                },
            ),
            patch.object(defense, "execute", return_value={"ok": True}) as execute,
        ):
            results = await asyncio.gather(
                defense.execute_stored(1),
                defense.execute_stored(1),
                return_exceptions=True,
            )
            self.assertEqual(sum(isinstance(r, ValueError) for r in results), 1)
            execute.assert_awaited_once()
            self.assertEqual(state, "executed")

    async def test_executor_failure_is_not_reported_as_executed(self):
        with (
            patch.object(db, "update_decision_status", return_value=True) as update,
            patch.object(
                db,
                "get_decision",
                return_value={
                    "action": "bad",
                    "target": "8.8.8.8",
                    "duration_seconds": 60,
                    "policy_reason": "test",
                },
            ),
        ):
            self.assertFalse((await defense.execute_stored(1))["ok"])
            self.assertEqual(update.await_args_list[-1].args[1], "failed")

    async def test_lost_execution_reply_requires_reconciliation(self):
        with (
            patch.object(db, "update_decision_status", return_value=True) as update,
            patch.object(
                db,
                "get_decision",
                return_value={
                    "action": "temporary_ip_block",
                    "target": "8.8.8.8",
                    "duration_seconds": 60,
                    "policy_reason": "test",
                },
            ),
            patch.object(defense, "execute", side_effect=TimeoutError()),
        ):
            with self.assertRaises(TimeoutError):
                await defense.execute_stored(1)
            self.assertEqual(update.await_args_list[-1].args[1], "execution_unknown")

    async def test_decider_passes_human_review_flags(self):
        incident = {
            "alert_id": "x",
            "source_ip": "8.8.8.8",
            "severity": "high",
            "analysis": {
                "confidence": 0.9,
                "attack_type": "SQL Injection Attempt",
                "needs_human_review": True,
                "recommended_action": {"action_type": "temporary_ip_block"},
            },
        }
        with (
            patch.object(db, "list_analyzed_without_decision", return_value=[incident]),
            patch.object(db, "count_recent_blocks", return_value=0),
            patch.object(db, "create_decision", return_value=1) as create,
            patch.object(defense, "execute_stored") as execute,
            patch.object(decider.settings, "defense_auto_execute", True),
        ):
            await decider.decide_pending_once()
            self.assertEqual(create.await_args.kwargs["status"], "pending_approval")
            execute.assert_not_awaited()


class ApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_base_url_redirect_preserves_only_known_prefixes(self):
        for prefix, expected in [
            ("", "/mission"),
            ("/AIEdgeGuard", "/AIEdgeGuard/mission"),
            ("/aiedge", "/aiedge/mission"),
            ("//other.example", "/mission"),
        ]:
            response = await self.client.get(
                "/", headers={"x-forwarded-prefix": prefix}
            )
            self.assertEqual(response.status_code, 307)
            self.assertEqual(response.headers["location"], expected)

    async def asyncSetUp(self):
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def test_manual_event_persists_before_queueing(self):
        redis = AsyncMock()
        redis.__aenter__.return_value = redis
        calls = []

        async def insert(_):
            calls.append("persist")

        async def publish(*_):
            calls.append("publish")

        redis.xadd.side_effect = publish
        with (
            patch.object(db, "insert_incident", side_effect=insert),
            patch.object(db, "mark_queued"),
            patch.object(main.aioredis, "from_url", return_value=redis),
        ):
            response = await self.client.post(
                "/api/v1/events", json={"source": "manual", "event_type": "test"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(calls, ["persist", "publish"])

    async def test_queue_outage_returns_saved_event_id(self):
        redis = AsyncMock()
        redis.__aenter__.return_value = redis
        redis.xadd.side_effect = RuntimeError("offline")
        with (
            patch.object(db, "insert_incident", return_value=1),
            patch.object(main.aioredis, "from_url", return_value=redis),
        ):
            response = await self.client.post(
                "/api/v1/events", json={"source": "manual", "event_type": "test"}
            )
        self.assertEqual(response.status_code, 503)
        self.assertTrue(response.json()["detail"]["event_id"].startswith("EVT-"))

    async def test_approval_cannot_retry_unknown_execution(self):
        with (
            patch.object(
                db, "get_decision", return_value={"status": "execution_unknown"}
            ),
            patch.object(defense, "execute_stored") as execute,
        ):
            response = await self.client.post("/api/v1/decisions/1/approve")
        self.assertEqual(response.status_code, 409)
        execute.assert_not_awaited()

    async def test_rejection_losing_a_race_returns_conflict(self):
        with (
            patch.object(
                db, "get_decision", return_value={"status": "pending_approval"}
            ),
            patch.object(db, "update_decision_status", return_value=False),
        ):
            response = await self.client.post("/api/v1/decisions/1/reject")
        self.assertEqual(response.status_code, 409)


class GatewayTests(unittest.TestCase):
    def test_funnel_routes_enforce_waf_and_only_explicit_preview_can_skip_auth(self):
        root = Path(__file__).resolve().parents[3]
        text = (root / "edge-guard/traefik/dynamic/funnel.yml").read_text(
            encoding="utf-8"
        )
        config = yaml.safe_load(text)["http"]
        for name, router in config["routers"].items():
            with self.subTest(router=name):
                self.assertIn("crowdsec@docker", router["middlewares"])
                if router["service"] == "edge-ai-api":
                    if (
                        name == "funnel-aiedge"
                        and "# EDGEGUARD_PREVIEW_AUTH=disabled" in text
                    ):
                        self.assertNotIn("aiedge-auth", router["middlewares"])
                    else:
                        self.assertIn("aiedge-auth", router["middlewares"])


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test database not configured"
)
class DatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError(
                "integration tests require a separate edgeguard_test database"
            )
        self.settings_patch = patch.object(db.settings, "database_url", dsn)
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        await db.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE incidents, campaigns, decisions, attacks RESTART IDENTITY"
            )
            await conn.commit()

    async def asyncTearDown(self):
        self.settings_patch.stop()

    async def incident(self):
        await db.insert_incident(
            {
                "alert_id": "x",
                "source": "manual",
                "kind": "waf",
                "severity": "high",
                "reason": "test",
                "source_ip": "8.8.8.8",
                "event": {},
            }
        )

    async def proposal(self):
        return await db.create_decision(
            "x",
            "temporary_ip_block",
            "8.8.8.8",
            60,
            0.9,
            "high",
            "approve",
            "test",
            [],
            "pending_approval",
        )

    async def test_campaign_links_first_incidents(self):
        await self.incident()
        listed = await db.list_incidents()
        self.assertEqual(listed[0]["source"], "manual")
        self.assertIsNone(listed[0]["endpoint"])
        await db.set_analysis("x", {"attack_type": "test"})
        campaign = await db.create_campaign("8.8.8.8", "test", "high", ["x"])
        self.assertGreater(campaign, 0)
        self.assertEqual(await db.list_unclustered_analyzed(), [])
        self.assertEqual((await db.list_campaigns())[0]["incident_count"], 1)

    async def test_database_claim_is_atomic(self):
        key = await self.proposal()
        results = await asyncio.gather(
            *(
                db.update_decision_status(
                    key, "executing", expected_status="pending_approval"
                )
                for _ in range(5)
            )
        )
        self.assertEqual(sum(results), 1)

    async def test_cooldown_uses_enforcement_time(self):
        key = await self.proposal()
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE decisions SET created_at = now() - interval '1 day' WHERE id = %s",
                (key,),
            )
            await conn.commit()
        self.assertEqual(await db.count_recent_blocks("8.8.8.8", 1800), 0)
        await db.update_decision_status(key, "executed")
        self.assertEqual(await db.count_recent_blocks("8.8.8.8", 1800), 1)

    async def test_persisted_unqueued_event_survives_until_publish(self):
        await self.incident()
        self.assertEqual(await db.list_unqueued(), [{"event_id": "x"}])
        await db.mark_queued("x")
        self.assertEqual(await db.list_unqueued(), [])


if __name__ == "__main__":
    unittest.main()
