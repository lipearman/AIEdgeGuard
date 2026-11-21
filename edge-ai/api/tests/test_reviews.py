"""Reviewed knowledge contracts: immutable history, CAS, retry and vector eligibility."""

import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from app import main, reviews, worker
from app.agents import learning
from app.integrations import db


def review(revision=0, verdict="true_positive", **changes):
    return reviews.ReviewInput(
        verdict=verdict,
        reviewer_label="Test analyst",
        rationale="Verified fixture evidence only",
        expected_revision=revision,
        request_id=uuid4(),
        **changes,
    )


class ReviewApiTests(unittest.IsolatedAsyncioTestCase):
    async def test_operation_gate_and_validation_do_not_trust_actor_fields(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            payload = json.loads(review().model_dump_json())
            with (
                patch.object(main.settings, "operation_key", "test-only"),
                patch.object(
                    reviews, "save", AsyncMock(return_value={"review": {"revision": 1}})
                ) as save,
            ):
                self.assertEqual(
                    (await client.post("/api/v1/reviews/1", json=payload)).status_code,
                    403,
                )
                save.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.post(
                            "/api/v1/reviews/1",
                            json=payload,
                            headers={"X-Operation-Key": "test-only"},
                        )
                    ).status_code,
                    200,
                )
            for key, value in [
                ("verdict", "confirmed"),
                ("rationale", " " * 20),
                ("reviewer_label", "fake\nname"),
                ("expected_revision", -1),
                ("authentication", "trusted-admin"),
            ]:
                invalid = {**payload, key: value}
                self.assertEqual(
                    (await client.post("/api/v1/reviews/1", json=invalid)).status_code,
                    422,
                    key,
                )

    async def test_no_reviewed_candidates_does_not_call_embedding_model(self):
        with (
            patch.object(reviews, "list_pending", AsyncMock(return_value=[])),
            patch.object(learning.ollama_client, "embed", AsyncMock()) as embed,
        ):
            self.assertEqual(await learning.embed_once(), 0)
            embed.assert_not_awaited()
        with (
            patch.object(reviews, "has_memory", AsyncMock(return_value=False)),
            patch.object(learning.ollama_client, "embed", AsyncMock()) as embed,
        ):
            self.assertEqual(await learning.similar_context("new event"), [])
            embed.assert_not_awaited()

    async def test_worker_persists_exact_reviewed_memory_reference(self):
        incident = {
            "alert_id": "new",
            "source": "manual",
            "kind": "web_attack",
            "severity": "medium",
            "reason": "test",
            "event": {},
            "analysis": None,
        }
        model = {
            "attack_type": "Web Attack",
            "severity": "medium",
            "confidence": 0.8,
            "reasoning": "Fixture only",
            "recommended_action": {"action_type": "none"},
        }
        result = SimpleNamespace(
            attack_type="Web Attack",
            severity="medium",
            confidence=0.8,
            model_dump=lambda: dict(model),
        )
        similar = [
            {
                "incident_id": 7,
                "alert_id": "old",
                "review_id": 11,
                "review_revision": 2,
                "review_verdict": "true_positive",
                "similarity": 0.9,
                "reason": "old fixture",
                "attack_type": "Web Attack",
                "review_rationale": "operator observation",
            }
        ]
        with (
            patch.object(db, "get_incident", AsyncMock(return_value=incident)),
            patch.object(db, "set_analysis", AsyncMock(return_value=True)) as store,
            patch.object(
                worker.intelligence, "event_context", AsyncMock(return_value=None)
            ),
            patch.object(worker.settings, "learning_enabled", True),
            patch.object(
                worker.learning, "similar_context", AsyncMock(return_value=similar)
            ),
            patch.object(worker, "analyze_event", AsyncMock(return_value=result)),
        ):
            await worker._process(AsyncMock(), "1-0", {"json": '{"event_id":"new"}'})
        analysis = store.await_args.args[1]
        self.assertEqual(analysis["memory_policy"], "latest_true_positive_reviews_only")
        self.assertEqual(
            analysis["reviewed_memory_sources"][0],
            {
                "incident_id": 7,
                "alert_id": "old",
                "review_id": 11,
                "review_revision": 2,
            },
        )


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test DB not configured"
)
class ReviewsDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError("isolated DB required")
        change = patch.object(db.settings, "database_url", dsn)
        change.start()
        self.addCleanup(change.stop)
        await db.init_schema()
        await reviews.init_schema()
        async with await db._connect() as conn:
            await conn.execute("TRUNCATE incidents,decisions RESTART IDENTITY CASCADE")
            await conn.execute(
                "INSERT INTO incidents(alert_id,source,kind,severity,reason,event,analysis) VALUES ('fixture','manual','test','medium','original evidence','{}',%s)",
                (
                    json.dumps(
                        {
                            "attack_type": "Original AI",
                            "reasoning": "Original reasoning",
                        }
                    ),
                ),
            )
            await conn.commit()
        self.vector = [1.0] + [0.0] * (db.settings.embedding_dim - 1)

    async def test_append_preserves_original_and_reviewer_is_explicitly_self_declared(
        self,
    ):
        with patch.object(reviews.settings, "operation_key", "test-only"):
            result = await reviews.save(
                1,
                review(
                    corrected_attack_type="Reviewed class", corrected_severity="low"
                ),
            )
        self.assertEqual(result["review"]["authentication"], "shared_operation_key")
        data = await reviews.detail(1, page=1, page_size=10)
        self.assertEqual(data["revision"], 1)
        self.assertEqual(data["memory"]["state"], "pending_embedding")
        self.assertIn("self-declared", data["identity_scope"])
        async with await db._connect() as conn:
            row = await (
                await conn.execute("SELECT reason,analysis FROM incidents WHERE id=1")
            ).fetchone()
        self.assertEqual(row[0], "original evidence")
        self.assertEqual(row[1]["attack_type"], "Original AI")
        self.assertEqual(
            (await reviews.historical_review(result["review"]["id"]))["revision"], 1
        )

    async def test_idempotent_retry_conflicting_payload_and_stale_revision(self):
        body = review()
        saved = await reviews.save(1, body)
        self.assertTrue((await reviews.save(1, body))["replayed"])
        other = body.model_copy(update={"rationale": "Different explanation"})
        with self.assertRaises(main.HTTPException) as error:
            await reviews.save(1, other)
        self.assertEqual(error.exception.status_code, 409)
        with self.assertRaises(main.HTTPException) as error:
            await reviews.save(1, review())
        self.assertEqual(error.exception.status_code, 409)
        await reviews.save(1, review(1, "unknown"))
        self.assertEqual(
            (await reviews.save(1, body))["review"]["id"], saved["review"]["id"]
        )
        self.assertEqual((await reviews.detail(1, page=1, page_size=10))["total"], 2)

    async def test_two_concurrent_edits_only_one_claims_revision(self):
        results = await asyncio.gather(
            reviews.save(1, review()),
            reviews.save(1, review(verdict="false_positive")),
            return_exceptions=True,
        )
        self.assertEqual(sum(isinstance(x, dict) for x in results), 1)
        self.assertEqual(
            sum(
                isinstance(x, main.HTTPException) and x.status_code == 409
                for x in results
            ),
            1,
        )
        self.assertEqual((await reviews.detail(1, page=1, page_size=10))["total"], 1)

    async def test_database_blocks_history_updates_and_deletes(self):
        await reviews.save(1, review())
        for sql in (
            "UPDATE incident_reviews SET verdict='unknown'",
            "DELETE FROM incident_reviews",
        ):
            with self.assertRaises(psycopg.errors.RaiseException):
                async with await db._connect() as conn:
                    await conn.execute(sql)
        self.assertEqual((await reviews.detail(1, page=1, page_size=10))["total"], 1)

    async def test_latest_positive_only_and_inflight_embedding_cannot_resurrect_false_positive(
        self,
    ):
        self.assertEqual(await reviews.list_pending(10), [])
        self.assertEqual(await reviews.search_memory(self.vector, 3), [])
        await reviews.save(1, review(corrected_attack_type="Reviewed type"))
        job = (await reviews.list_pending(10))[0]
        self.assertTrue(
            await reviews.set_memory(job, self.vector, learning.incident_text(job))
        )
        self.assertTrue(
            (await reviews.detail(1, page=1, page_size=10))["memory"]["ready"]
        )
        found = await db.search_similar(self.vector, k=3)
        self.assertEqual(found[0]["attack_type"], "Reviewed type")
        self.assertEqual(found[0]["review_revision"], 1)
        await reviews.save(1, review(1, "false_positive"))
        self.assertEqual(await reviews.search_memory(self.vector, 3), [])
        self.assertFalse(await reviews.set_memory(job, self.vector, "late old job"))
        self.assertEqual(
            (await reviews.detail(1, page=1, page_size=10))["memory"]["state"],
            "excluded",
        )
        await reviews.save(1, review(2, "unknown"))
        self.assertEqual(await reviews.list_pending(10), [])
        self.assertEqual(await reviews.search_memory(self.vector, 3), [])

    async def test_corrected_revision_requires_new_vector_and_model_change_is_excluded(
        self,
    ):
        await reviews.save(1, review())
        first = (await reviews.list_pending(10))[0]
        await reviews.set_memory(first, self.vector, "first text")
        await reviews.save(
            1,
            review(
                1,
                corrected_attack_type="Updated reviewed class",
                corrected_severity="high",
            ),
        )
        self.assertEqual(await reviews.search_memory(self.vector, 3), [])
        self.assertFalse(
            await reviews.set_memory(first, self.vector, "late first vector")
        )
        current = (await reviews.list_pending(10))[0]
        self.assertEqual(current["attack_type"], "Updated reviewed class")
        self.assertTrue(await reviews.set_memory(current, self.vector, "new text"))
        self.assertEqual(
            (await reviews.search_memory(self.vector, 3))[0]["severity"], "high"
        )
        with patch.object(reviews.settings, "embedding_model", "different-model"):
            self.assertEqual(await reviews.search_memory(self.vector, 3), [])
            self.assertEqual(len(await reviews.list_pending(10)), 1)
        stats = await db.embedding_stats()
        self.assertEqual(stats["embedded"], 1)
        self.assertEqual(stats["eligible"], 1)

    async def test_history_paging_always_exposes_latest_revision_and_summary(self):
        for version in range(12):
            await reviews.save(1, review(version, "unknown"))
        data = await reviews.detail(1, page=2, page_size=10)
        self.assertEqual(data["revision"], 12)
        self.assertEqual([x["revision"] for x in data["items"]], [2, 1])
        stats = await reviews.stats()
        self.assertEqual(stats["unknown"], 1)
        self.assertEqual(stats["unreviewed"], 0)
        self.assertEqual(stats["memory_ready"], 0)
