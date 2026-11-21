"""Leakage, gaps, immutable replay and gated write contracts; fixtures stay isolated."""

import asyncio
import copy
import json
import os
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import psycopg
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from app import evaluation as ev
from app import main, traffic
from app.integrations import dashboard_db, db


def corpus():
    return {
        "id": uuid4(),
        "content_hash": "fixture-only",
        "snapshot": {
            "windows": [
                {
                    "index": i,
                    "requests": 150 if i >= 120 and i % 5 == 0 else 10,
                    "eligible": True,
                }
                for i in range(150)
            ]
        },
    }


def labels(count=150):
    return [
        {
            "id": i + 1,
            "window_index": i,
            "revision": 1,
            "label": "normal" if i < 90 or i % 5 else "lab_attack",
            "declared_by": "Fixture operator",
            "rationale": "Known fixture traffic",
            "authentication": "fixture",
            "created_at": datetime.now(UTC),
        }
        for i in range(count)
    ]


class ReplayTests(unittest.IsolatedAsyncioTestCase):
    def test_gap_union_and_no_future_leakage(self):
        now = datetime.now(UTC)
        spans = [
            (now, now + timedelta(seconds=10)),
            (now + timedelta(seconds=5), now + timedelta(seconds=15)),
        ]
        self.assertEqual(
            ev.covered_seconds(now, now + timedelta(seconds=20), spans), 15
        )
        data, truth = corpus(), labels()
        first = ev.replay(data, truth)
        self.assertTrue(
            all(
                not p["ewma"] and not p["median_mad"]
                for p in first["predictions"]
                if p["split"] == "calibration"
            )
        )
        self.assertTrue(
            next(p for p in first["predictions"] if p["index"] == 120)["ewma"]
        )
        self.assertEqual(first["metrics"]["test"]["median_mad"]["tp"], 6)
        self.assertEqual(first["metrics"]["test"]["median_mad"]["fp"], 0)
        changed = copy.deepcopy(data)
        changed["snapshot"]["windows"][-1]["requests"] = 100000
        second = ev.replay(changed, truth)
        self.assertEqual(first["training_statistics"], second["training_statistics"])
        self.assertEqual(first["predictions"][:-1], second["predictions"][:-1])
        # Changing test labels cannot affect predictions or detector statistics.
        for label in truth[120:]:
            label["label"] = "unknown"
        third = ev.replay(data, truth)
        self.assertEqual(
            [p["ewma"] for p in first["predictions"]],
            [p["ewma"] for p in third["predictions"]],
        )
        self.assertIsNone(third["metrics"]["test"]["ewma"]["recall"])

    def test_unknown_training_gaps_and_sample_floor(self):
        data, truth = corpus(), labels()
        truth[0]["label"] = "unknown"
        self.assertEqual(
            ev.replay(data, truth)["state"], "needs_complete_normal_training"
        )
        truth[0]["label"] = "normal"
        data["snapshot"]["windows"][0]["eligible"] = False
        self.assertIsNone(ev.replay(data, truth)["metrics"])
        data["snapshot"]["windows"][0]["eligible"] = True
        data["snapshot"]["windows"][130]["eligible"] = False
        report = ev.replay(data, truth)
        gap = next(p for p in report["predictions"] if p["index"] == 130)
        self.assertIsNone(gap["ewma"])
        self.assertEqual(report["metrics"]["test"]["ewma"]["excluded"], 1)
        self.assertEqual(
            ev.metric([("normal", True), ("lab_attack", False), ("unknown", True)]),
            {
                "tp": 0,
                "fp": 1,
                "tn": 0,
                "fn": 1,
                "excluded": 1,
                "state": "insufficient_labeled_test_data",
                "recall": None,
                "false_positive_rate": None,
                "normal_windows": 1,
                "lab_attack_windows": 1,
                "scope": "Window-level operator labels; correlated samples, not a generalization or SLA claim",
            },
        )

    async def test_write_gates_and_validation(self):
        identity = uuid4()
        start = datetime(2026, 1, 1, tzinfo=UTC)
        body = {
            "host": "fixture.test",
            "router": "fixture@file",
            "start": start.isoformat(),
            "end": (start + timedelta(hours=5)).isoformat(),
            "declared_by": "Fixture",
            "rationale": "Fixture evaluation only",
        }
        with self.assertRaises(ValidationError):
            ev.DatasetInput(**{**body, "start": "2026-01-01T00:01:00Z"})
        with self.assertRaises(ValidationError):
            ev.DatasetInput(**{**body, "authentication": "admin"})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            with (
                patch.object(main.settings, "operation_key", "fixture"),
                patch.object(
                    ev, "snapshot", AsyncMock(return_value={"ok": True})
                ) as save,
            ):
                response = await client.put(
                    f"/api/v1/evaluation/datasets/{identity}", json=body
                )
                self.assertEqual(response.status_code, 403)
                save.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.put(
                            f"/api/v1/evaluation/datasets/{identity}",
                            json=body,
                            headers={"X-Operation-Key": "fixture"},
                        )
                    ).status_code,
                    200,
                )
                for suffix in ("labels", f"runs/{uuid4()}"):
                    payload = (
                        {
                            "window_index": 0,
                            "expected_revision": 0,
                            "label": "normal",
                            "declared_by": "Fixture",
                            "rationale": "Fixture only label",
                            "request_id": str(uuid4()),
                        }
                        if suffix == "labels"
                        else None
                    )
                    self.assertEqual(
                        (
                            await client.post(
                                f"/api/v1/evaluation/datasets/{identity}/{suffix}",
                                json=payload,
                            )
                        ).status_code,
                        403,
                    )

    async def test_collector_restart_partial_malformed_backlog_and_healthy_ticks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.jsonl"
            path.write_text(
                json.dumps({"StartUTC": "2026-01-01T00:00:00Z", "RequestMethod": "GET"})
                + "\n"
            )
            redis = AsyncMock()
            state = None

            async def get(_):
                return state

            async def put(_, value):
                nonlocal state
                state = value

            redis.get.side_effect, redis.set.side_effect = get, put
            with (
                patch.object(traffic.settings, "request_log_path", str(path)),
                patch.object(dashboard_db, "insert_requests", AsyncMock()),
                patch.object(ev, "record_tick", AsyncMock()) as tick,
            ):
                await traffic.collect_once(redis)
                self.assertIsNone(tick.await_args.args[1])
                await traffic.collect_once(redis)
                self.assertIsNone(tick.await_args.args[1])
                await traffic.collect_once(redis)
                self.assertIsNotNone(tick.await_args.args[1])
                with patch.object(traffic, "COLLECTOR_INSTANCE", "restarted-fixture"):
                    await traffic.collect_once(redis)
                    self.assertIsNone(tick.await_args.args[1])
                previous = json.loads(state)
                previous["polled_at"] = (
                    datetime.now(UTC) - timedelta(seconds=20)
                ).isoformat()
                state = json.dumps(previous)
                await traffic.collect_once(redis)
                self.assertIsNone(tick.await_args.args[1])
                with path.open("a") as f:
                    f.write("invalid json\n")
                await traffic.collect_once(redis)
                self.assertIsNone(tick.await_args.args[1])
                with path.open("a") as f:
                    f.write('{"partial":')
                await traffic.collect_once(redis)
                self.assertIsNone(tick.await_args.args[1])

    def test_backlog_and_unrecognized_lines_never_claim_caught_up(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.jsonl"
            line = (
                json.dumps({"StartUTC": "2026-01-01T00:00:00Z", "RequestMethod": "GET"})
                + "\n"
            )
            path.write_text(line * 501)
            stat = path.stat()
            rows, checkpoint = traffic.read_batch(
                path, {"inode": stat.st_ino, "offset": 0}
            )
            self.assertEqual(len(rows), 500)
            self.assertFalse(checkpoint["caught_up"])
            rows, checkpoint = traffic.read_batch(path, checkpoint)
            self.assertEqual(len(rows), 1)
            self.assertTrue(checkpoint["caught_up"])
            with path.open("a") as writer:
                writer.write("{}\n")
            _, checkpoint = traffic.read_batch(path, checkpoint)
            self.assertFalse(checkpoint["caught_up"])


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test DB not configured"
)
class EvaluationDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError("isolated DB required")
        change = patch.object(db.settings, "database_url", dsn)
        change.start()
        self.addCleanup(change.stop)
        await dashboard_db.init_schema()
        await ev.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE evaluation_datasets,traffic_collection_ticks,gateway_requests RESTART IDENTITY CASCADE"
            )
            await conn.commit()

    async def test_pinned_snapshot_label_cas_immutable_run_and_late_arrivals(self):
        start = datetime.now(UTC).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=2)
        body = ev.DatasetInput(
            host="fixture.test",
            router="fixture@file",
            start=start,
            end=start + timedelta(hours=5),
            declared_by="Fixture",
            rationale="Known fixture corpus only",
        )
        async with await db._connect() as conn:
            # One retained real-shaped fixture; no production writes.
            await conn.execute(
                """INSERT INTO gateway_requests(fingerprint,observed_at,collected_at,host,router,raw,method,status,path)
                VALUES ('fixture',%s,%s,'fixture.test','fixture@file','{}','POST',404,'/private/value?token=fixture-secret')""",
                (start, start - timedelta(seconds=1)),
            )
            await conn.execute(
                """INSERT INTO traffic_collection_ticks(observed_at,interval_start,state)
                SELECT t,t-interval '3 seconds','caught_up' FROM generate_series(%s::timestamptz+interval '3 seconds',%s::timestamptz,interval '3 seconds') AS t""",
                (start, body.end),
            )
            await conn.commit()
        identity = uuid4()
        dataset = await ev.snapshot(identity, body)
        windows = dataset["snapshot"]["windows"]
        self.assertTrue(all(w["eligible"] for w in windows))
        self.assertEqual(windows[0]["requests"], 1)
        self.assertEqual(
            windows[0]["http_mix"],
            {
                "method": {"POST": 1},
                "status": {"4xx": 1},
                "path_shape": {"multiple_segments": 1},
            },
        )
        self.assertEqual(
            windows[1]["http_mix"], {"method": {}, "status": {}, "path_shape": {}}
        )
        self.assertNotIn("fixture-secret", str(dataset["snapshot"]))
        self.assertEqual(
            (await ev.snapshot(identity, body))["content_hash"], dataset["content_hash"]
        )
        with self.assertRaises(main.HTTPException):
            await ev.snapshot(identity, body.model_copy(update={"host": "other.test"}))
        label = ev.LabelInput(
            window_index=0,
            expected_revision=0,
            label="normal",
            declared_by="Fixture",
            rationale="Known fixture request",
            request_id=uuid4(),
        )
        saved = await ev.save_label(identity, label)
        self.assertEqual((await ev.save_label(identity, label))["id"], saved["id"])
        with self.assertRaises(main.HTTPException):
            await ev.save_label(
                identity, label.model_copy(update={"request_id": uuid4()})
            )
        with self.assertRaises(main.HTTPException):
            await ev.save_label(identity, label.model_copy(update={"label": "unknown"}))
        run_id = uuid4()
        run = await ev.run_replay(identity, run_id)
        self.assertEqual(run["report"]["state"], "needs_complete_normal_training")
        await ev.save_label(
            identity,
            label.model_copy(
                update={
                    "expected_revision": 1,
                    "label": "unknown",
                    "request_id": uuid4(),
                }
            ),
        )
        self.assertEqual(
            (await ev.run_replay(identity, run_id))["report"], run["report"]
        )
        newer = await ev.run_replay(identity, uuid4())
        self.assertNotEqual(newer["input_hash"], run["input_hash"])
        async with await db._connect() as conn:
            await conn.execute(
                """INSERT INTO gateway_requests(fingerprint,observed_at,host,router,raw)
                VALUES ('late',%s,'fixture.test','fixture@file','{}')""",
                (start,),
            )
            await conn.commit()
        self.assertEqual(
            (await ev.detail(identity))["snapshot"]["windows"][0]["requests"], 1
        )
        self.assertEqual(
            (await ev.snapshot(uuid4(), body))["snapshot"]["windows"][0]["requests"], 2
        )
        for table in ("evaluation_datasets", "evaluation_labels", "evaluation_runs"):
            async with await db._connect() as conn:
                with self.assertRaises(psycopg.Error):
                    await conn.execute(f"DELETE FROM {table}")

    async def test_historical_zero_is_not_coverage_and_new_snapshot_gaps(self):
        start = datetime(2026, 1, 1, tzinfo=UTC)
        body = ev.DatasetInput(
            host="fixture.test",
            router="fixture@file",
            start=start,
            end=start + timedelta(hours=5),
            declared_by="Fixture",
            rationale="Unknown history fixture",
        )
        dataset = await ev.snapshot(uuid4(), body)
        self.assertFalse(any(w["eligible"] for w in dataset["snapshot"]["windows"]))
        self.assertEqual((await ev.datasets(1, 20))["total"], 1)

    async def test_observed_segments_and_saved_run_paging(self):
        start = datetime(2026, 1, 1, tzinfo=UTC)
        async with await db._connect() as conn:
            for i in range(12):
                await conn.execute(
                    """INSERT INTO gateway_requests(fingerprint,observed_at,host,router,raw)
                    VALUES (%s,%s,%s,'fixture@file','{}')""",
                    (str(i), start, f"fixture-{i:02}.test"),
                )
            await conn.commit()
        first, second = await ev.segments(1, 10), await ev.segments(2, 10)
        self.assertEqual(
            (first["total"], len(first["items"]), len(second["items"])), (12, 10, 2)
        )
        self.assertFalse(
            {x["host"] for x in first["items"]} & {x["host"] for x in second["items"]}
        )
        identity = uuid4()
        await ev.snapshot(
            identity,
            ev.DatasetInput(
                host="fixture-00.test",
                router="fixture@file",
                start=start,
                end=start + timedelta(hours=5),
                declared_by="Fixture",
                rationale="Fixture paging verification",
            ),
        )
        for _ in range(3):
            await ev.run_replay(identity, uuid4())
        first, second = (
            await ev.dataset_runs(identity, 1, 2),
            await ev.dataset_runs(identity, 2, 2),
        )
        self.assertEqual(
            (first["total"], len(first["items"]), len(second["items"])), (3, 2, 1)
        )
        self.assertFalse(
            {x["id"] for x in first["items"]} & {x["id"] for x in second["items"]}
        )
