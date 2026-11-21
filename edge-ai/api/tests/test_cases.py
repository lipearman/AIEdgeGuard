"""Candidate-only semantics, source times, repeatable membership and gated writes."""

import asyncio
import json
import os
import sys
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from app import assets, cases, main
from app.event_time import extract
from app.integrations import dashboard_db, db

NOW = datetime(2026, 11, 20, 12, tzinfo=UTC)


class CaseContracts(unittest.IsolatedAsyncioTestCase):
    def test_source_time_has_no_ai_or_timezone_fallback(self):
        for source, field in [
            ("wazuh", "timestamp"),
            ("suricata", "timestamp"),
            ("crowdsec", "start_at"),
        ]:
            result = extract(
                source, {"event": {field: "2026-11-20T14:00:00+02:00"}}, NOW
            )
            self.assertEqual(result, (NOW, field, "source_reported"))
        for value, expected in [
            (None, "missing"),
            ("bad", "invalid"),
            ("2026-11-20T12:00:00", "timezone_missing"),
            ("2026-11-20T13:00:00Z", "future_clock_untrusted"),
        ]:
            self.assertEqual(
                extract(
                    "wazuh",
                    {
                        "event": {"timestamp": value},
                        "analysis": {"timestamp": NOW.isoformat()},
                    },
                    NOW,
                )[2],
                expected,
            )
        self.assertEqual(
            extract("manual", {"timestamp": NOW.isoformat()}, NOW)[2],
            "unsupported_source",
        )
        # Excessive request IDs must not be prefix-matched as equal identities.
        node = cases.event_node(
            "requests",
            {
                "id": 1,
                "observed_at": NOW,
                "collected_at": NOW,
                "source_ip": "10.0.0.1",
                "raw": {"request_id": "x" * 300},
                "host": "fixture",
                "method": "GET",
            },
        )
        self.assertEqual(node["identity"]["request_id"], "")

    def test_low_confidence_shared_addresses_are_never_causal(self):
        row = {
            "id": 1,
            "created_at": NOW,
            "source": "wazuh",
            "source_ip": "8.8.8.8",
            "event_observed_at": NOW - timedelta(hours=2),
            "event_time_state": "source_reported",
            "event_time_field": "timestamp",
            "event": {"event": {"agent": {"id": "001", "ip": "10.1.1.1"}}},
        }
        a = cases.event_node("incidents", row)
        b = cases.event_node("incidents", {**row, "id": 2})
        edges = cases.associations(a, b, {"agent_ids": [], "ips": []})
        self.assertTrue(a["late_arrival"])
        self.assertEqual({e["confidence"] for e in edges}, {"low", "medium"})
        self.assertTrue(
            all(
                e["meaning"] == "association_only" and e["direction"] == "undirected"
                for e in edges
            )
        )
        self.assertNotIn("high", [e["confidence"] for e in edges])

    async def test_api_requires_key_and_rejects_forged_metadata(self):
        data = {
            "anchor_kind": "incidents",
            "anchor_id": 1,
            "minutes": 15,
            "declared_by": "Fixture",
            "rationale": "Fixture investigation",
        }
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            with (
                patch.object(main.settings, "operation_key", "fixture-key"),
                patch.object(
                    cases, "create", AsyncMock(return_value={"ok": True})
                ) as create,
            ):
                url = f"/api/v1/cases/{uuid4()}"
                self.assertEqual((await client.put(url, json=data)).status_code, 403)
                create.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.put(
                            url, json=data, headers={"X-Operation-Key": "fixture-key"}
                        )
                    ).status_code,
                    200,
                )
                for change in (
                    {"minutes": 61},
                    {"authentication": "admin"},
                    {"anchor_kind": "decisions"},
                ):
                    self.assertEqual(
                        (
                            await client.put(
                                url,
                                json={**data, **change},
                                headers={"X-Operation-Key": "fixture-key"},
                            )
                        ).status_code,
                        422,
                    )


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test DB not configured"
)
class CaseDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError("isolated DB required")
        change = patch.object(db.settings, "database_url", dsn)
        change.start()
        self.addCleanup(change.stop)
        await db.init_schema()
        await dashboard_db.init_schema()
        await assets.init_schema()
        await cases.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE evidence_cases,decisions,incidents,gateway_requests,asset_registry RESTART IDENTITY CASCADE"
            )
            await conn.commit()

    async def insert(
        self, identity, observed=NOW, ingested=NOW, source_ip="8.8.8.8", source="wazuh"
    ):
        raw = {
            "timestamp": observed.isoformat(),
            "agent": {"id": "001", "ip": "10.1.1.1"},
            "request_id": "fixture-request",
        }
        async with await db._connect() as conn:
            cur = await conn.execute(
                """INSERT INTO incidents(alert_id,created_at,source,kind,source_ip,event)
                VALUES (%s,%s,%s,'fixture',%s,%s::jsonb) RETURNING id""",
                (identity, ingested, source, source_ip, json.dumps({"event": raw})),
            )
            result = (await cur.fetchone())[0]
            await conn.commit()
            return result

    def body(self, identity):
        return cases.CaseInput(
            anchor_kind="incidents",
            anchor_id=identity,
            declared_by="Fixture analyst",
            rationale="Fixture investigation evidence",
        )

    async def test_event_time_backfill_late_arrival_immutable_and_idempotent(self):
        anchor = await self.insert("anchor")
        await self.insert(
            "late",
            observed=NOW + timedelta(minutes=1),
            ingested=NOW + timedelta(hours=2),
        )
        await self.insert(
            "outside",
            observed=NOW + timedelta(hours=1),
            ingested=NOW + timedelta(hours=1),
        )
        with self.assertRaises(main.HTTPException):
            await cases.create(uuid4(), self.body(anchor))
        self.assertEqual(await cases.index_batch(), 3)
        identity = uuid4()
        saved = await cases.create(identity, self.body(anchor))
        graph = saved["graph"]
        self.assertEqual(
            {n.get("alert_id") for n in graph["nodes"]}, {"anchor", "late"}
        )
        self.assertTrue(
            next(n for n in graph["nodes"] if n.get("alert_id") == "late")[
                "late_arrival"
            ]
        )
        self.assertEqual(cases.digest(graph), saved["content_hash"])
        await self.insert(
            "later_arrival",
            observed=NOW + timedelta(minutes=2),
            ingested=NOW + timedelta(hours=3),
        )
        await cases.index_batch()
        self.assertEqual(
            (await cases.create(identity, self.body(anchor)))["graph"], graph
        )
        self.assertEqual((await cases.detail(identity))["graph"], graph)
        newer = await cases.create(uuid4(), self.body(anchor))
        self.assertEqual(len(newer["graph"]["nodes"]), 3)
        self.assertEqual((await cases.listing("incidents", anchor, 1))["total"], 2)
        with self.assertRaises(main.HTTPException):
            await cases.create(
                identity, self.body(anchor).model_copy(update={"minutes": 30})
            )
        async with await db._connect() as conn:
            cur = await conn.execute(
                "SELECT event->'event'->>'timestamp',created_at FROM incidents WHERE id=%s",
                (anchor,),
            )
            raw_time, ingested = await cur.fetchone()
            self.assertEqual(raw_time, NOW.isoformat())
            self.assertEqual(ingested, NOW)
            with self.assertRaises(psycopg.Error):
                await conn.execute("DELETE FROM evidence_cases")

    async def test_concurrent_snapshot_and_bounded_nodes_and_decisions(self):
        anchor = await self.insert("anchor")
        async with await db._connect() as conn:
            await conn.execute(
                """INSERT INTO incidents(alert_id,created_at,source,kind,source_ip,event,event_observed_at,event_time_state)
                SELECT 'bulk-'||i,%s,'manual','fixture','8.8.8.8','{}',%s,'source_reported' FROM generate_series(1,90) i""",
                (NOW, NOW),
            )
            await conn.execute("""INSERT INTO decisions(incident_alert_id,action,target,policy_verdict,status)
                SELECT 'anchor','temporary_ip_block','8.8.8.8','pending_approval','pending_approval' FROM generate_series(1,22)""")
            await conn.commit()
        await cases.index_batch()
        identity = uuid4()
        first, second = await asyncio.gather(
            cases.create(identity, self.body(anchor)),
            cases.create(identity, self.body(anchor)),
        )
        self.assertEqual(first["id"], second["id"])
        graph = first["graph"]
        self.assertTrue(graph["event_nodes_truncated"])
        self.assertTrue(graph["decisions_truncated"])
        self.assertEqual(len(graph["nodes"]), 100)
        references = [e for e in graph["edges"] if e["confidence"] == "high"]
        self.assertEqual(len(references), 20)
        self.assertTrue(
            all(e["meaning"] == "stored_reference_only" for e in references)
        )

    async def test_insert_incident_indexes_timestamp_and_unknown_anchor_has_no_invented_match(
        self,
    ):
        identity = await db.insert_incident(
            {
                "alert_id": "ingested",
                "source": "suricata",
                "kind": "fixture",
                "severity": "medium",
                "reason": "Fixture",
                "source_ip": "",
                "event": {"timestamp": "2026-11-20T12:00:00Z"},
            }
        )
        async with await db._connect() as conn:
            cur = await conn.execute(
                "SELECT event_observed_at,event_time_state FROM incidents WHERE id=%s",
                (identity,),
            )
            values = await cur.fetchone()
        self.assertEqual(values, (NOW, "source_reported"))
        saved = await cases.create(uuid4(), self.body(identity))
        self.assertEqual(len(saved["graph"]["nodes"]), 1)
        self.assertEqual(saved["graph"]["edges"], [])

    async def test_request_to_host_binding_is_current_and_pinned(self):
        host, app = uuid4(), uuid4()

        async def save(identity, payload, revision=0):
            return await assets.save(
                identity,
                assets.AssetInput(
                    payload=payload,
                    declared_by="Fixture",
                    rationale="Fixture mapping evidence",
                    expected_revision=revision,
                    request_id=uuid4(),
                ),
            )

        host_payload = assets.AssetPayload(
            name="Fixture host", kind="host", agent_ids=["001"], ips=["10.1.1.1"]
        )
        await save(host, host_payload)
        await save(
            app,
            assets.AssetPayload(
                name="Fixture app",
                kind="application",
                parent_host_id=host,
                routes=[
                    assets.RouteBinding(
                        host="fixture.test", router="fixture@file", path_prefix="/"
                    )
                ],
            ),
        )
        await self.insert("host-event", source_ip="")
        await cases.index_batch()
        async with await db._connect() as conn:
            cur = await conn.execute(
                """INSERT INTO gateway_requests(fingerprint,observed_at,collected_at,source_ip,host,router,path,raw)
                VALUES ('fixture',%s,%s,'10.9.9.9','fixture.test','fixture@file','/','{}') RETURNING id""",
                (NOW, NOW),
            )
            request_id = (await cur.fetchone())[0]
            await conn.commit()
        body = cases.CaseInput(
            anchor_kind="requests",
            anchor_id=request_id,
            declared_by="Fixture",
            rationale="Fixture cross-layer case",
        )
        old = await cases.create(uuid4(), body)
        self.assertEqual(len(old["graph"]["nodes"]), 2)
        self.assertEqual(
            old["graph"]["edges"][0]["type"], "current_operator_asset_binding"
        )
        self.assertEqual(old["graph"]["asset_context"]["parent_host"]["revision"], 1)
        await save(
            host,
            host_payload.model_copy(update={"agent_ids": ["002"], "ips": ["10.2.2.2"]}),
            1,
        )
        self.assertEqual(
            (await cases.detail(old["id"]))["graph"]["asset_context"]["parent_host"][
                "revision"
            ],
            1,
        )
        new = await cases.create(uuid4(), body)
        self.assertEqual(len(new["graph"]["nodes"]), 1)
