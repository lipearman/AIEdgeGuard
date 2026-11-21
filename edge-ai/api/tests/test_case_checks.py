"""Retained-source consistency is not ground truth; only isolated DB is writable."""

import asyncio
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import psycopg

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from app import assets, cases, main, traffic
from app import case_checks as cc
from app.integrations import dashboard_db, db


def check_body(case_id):
    return cc.CheckInput(
        case_id=case_id,
        declared_by="Fixture checker",
        rationale="Compare retained fixture source facts",
    )


def review_body(check_id, **changes):
    return cc.ReviewInput(
        check_id=check_id,
        expected_revision=0,
        verdict="needs_more_evidence",
        reviewer_label="Fixture reviewer",
        rationale="Fixture scope is not independently authenticated",
        request_id=uuid4(),
        **changes,
    )


class CheckContracts(unittest.IsolatedAsyncioTestCase):
    async def test_gates_and_no_forged_independence(self):
        data = json.loads(check_body(uuid4()).model_dump_json())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            with (
                patch.object(main.settings, "operation_key", "fixture"),
                patch.object(
                    cc, "save_check", AsyncMock(return_value={"ok": True})
                ) as save,
            ):
                url = "/api/v1/case-checks/" + str(uuid4())
                self.assertEqual((await client.put(url, json=data)).status_code, 403)
                save.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.put(
                            url, json=data, headers={"X-Operation-Key": "fixture"}
                        )
                    ).status_code,
                    200,
                )
                self.assertEqual(
                    (
                        await client.put(
                            url,
                            json={**data, "independent_identity_verified": True},
                            headers={"X-Operation-Key": "fixture"},
                        )
                    ).status_code,
                    422,
                )
                r = json.loads(review_body(uuid4()).model_dump_json())
                self.assertEqual(
                    (
                        await client.post(
                            "/api/v1/case-checks/reviews/" + str(uuid4()), json=r
                        )
                    ).status_code,
                    403,
                )


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test DB not configured"
)
class CheckDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def request_fixture(self, peer="8.8.8.8"):
        row = traffic.normalize(
            {
                "StartUTC": "2026-11-20T12:00:00Z",
                "RequestMethod": "GET",
                "RequestHost": "fixture.test",
                "RequestPath": "/fixture",
                "RouterName": "fixture@file",
                "ClientHost": peer,
                "DownstreamStatus": 200,
            }
        )
        await dashboard_db.insert_requests([row])
        return await cases.create(
            uuid4(),
            cases.CaseInput(
                anchor_kind="requests",
                anchor_id=1,
                declared_by="Fixture",
                rationale="Retained HTTP source fixture",
            ),
        )

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
        await cc.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE evidence_cases,decisions,incidents,gateway_requests,asset_registry RESTART IDENTITY CASCADE"
            )
            await conn.commit()
        for i in range(2):
            await db.insert_incident(
                {
                    "alert_id": "fixture-" + str(i),
                    "source": "wazuh",
                    "kind": "host_edr",
                    "severity": "medium",
                    "reason": "Fixture event",
                    "source_ip": "8.8.8.8",
                    "event": {
                        "timestamp": "2026-11-20T12:00:00Z",
                        "agent": {"id": "001", "ip": "10.1.1.1"},
                        "request_id": "fixture-request",
                    },
                }
            )
        self.case = await cases.create(
            uuid4(),
            cases.CaseInput(
                anchor_kind="incidents",
                anchor_id=1,
                declared_by="Fixture maker",
                rationale="Fixture case for evidence checking",
            ),
        )

    async def test_pinned_report_concurrent_retry_and_no_model_or_identity_claim(self):
        identity = uuid4()
        body = check_body(self.case["id"])
        first, second = await asyncio.gather(
            cc.save_check(identity, body), cc.save_check(identity, body)
        )
        self.assertEqual(first["id"], second["id"])
        report = first["report"]
        self.assertEqual(report["state"], "consistent_with_retained_evidence")
        self.assertFalse(report["independent_identity_verified"])
        self.assertFalse(report["source_authenticity_verified"])
        self.assertFalse(report["model_used"])
        self.assertTrue(
            all(x["state"] == "supported_association" for x in report["edges"])
        )
        self.assertEqual(cc.sha(report), first["content_hash"])
        with self.assertRaises(main.HTTPException):
            await cc.save_check(
                identity,
                body.model_copy(
                    update={"rationale": "Different purpose with reused UUID"}
                ),
            )
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE incidents SET event=jsonb_set(event,'{event,request_id}','\"changed\"') WHERE id=2"
            )
            await conn.commit()
        self.assertEqual((await cc.save_check(identity, body))["report"], report)
        newer = await cc.save_check(uuid4(), body)
        self.assertEqual(newer["report"]["state"], "incomplete_or_changed")
        self.assertTrue(
            any(
                n["state"] == "changed_since_snapshot" for n in newer["report"]["nodes"]
            )
        )
        self.assertTrue(
            all(e["state"] == "unverifiable" for e in newer["report"]["edges"])
        )
        self.assertEqual((await cc.history(self.case["id"], 1))["total"], 2)

    async def test_missing_source_is_unavailable_not_supported(self):
        async with await db._connect() as conn:
            await conn.execute("DELETE FROM incidents WHERE id=2")
            await conn.commit()
        saved = await cc.save_check(uuid4(), check_body(self.case["id"]))
        self.assertEqual(saved["report"]["state"], "incomplete_or_changed")
        self.assertEqual(saved["report"]["nodes"][1]["state"], "unavailable")
        self.assertTrue(
            all(e["state"] == "unverifiable" for e in saved["report"]["edges"])
        )

    async def test_http_raw_content_is_rehashed_instead_of_trusting_fingerprint(self):
        case = await self.request_fixture()
        first = await cc.save_check(uuid4(), check_body(case["id"]))
        self.assertEqual(first["report"]["state"], "consistent_with_retained_evidence")
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE gateway_requests SET raw=jsonb_set(raw,'{RequestPath}','\"/changed\"') WHERE id=1"
            )
            await conn.commit()
        changed = await cc.save_check(uuid4(), check_body(case["id"]))
        self.assertEqual(changed["report"]["state"], "incomplete_or_changed")
        self.assertTrue(
            any(
                "content hash" in issue
                for n in changed["report"]["nodes"]
                for issue in n["issues"]
            )
        )

    async def test_pinned_asset_declaration_not_replaced_by_current_revision(self):
        host, app = uuid4(), uuid4()
        payload = assets.AssetPayload(
            name="Fixture host", kind="host", agent_ids=["001"], ips=["10.1.1.1"]
        )

        async def save(identity, payload, revision=0):
            return await assets.save(
                identity,
                assets.AssetInput(
                    payload=payload,
                    declared_by="Fixture",
                    rationale="Known fixture mapping only",
                    expected_revision=revision,
                    request_id=uuid4(),
                ),
            )

        await save(host, payload)
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
        case = await self.request_fixture("10.9.9.9")
        await save(
            host,
            payload.model_copy(update={"agent_ids": ["002"], "ips": ["10.2.2.2"]}),
            1,
        )
        result = await cc.save_check(uuid4(), check_body(case["id"]))
        self.assertEqual(result["report"]["state"], "consistent_with_retained_evidence")
        self.assertTrue(
            all(
                x["state"] == "consistent" and x["revision"] == 1
                for x in result["report"]["assets"]
            )
        )
        self.assertTrue(
            any(
                e["type"] == "current_operator_asset_binding"
                and e["state"] == "supported_association"
                for e in result["report"]["edges"]
            )
        )

    async def test_wrong_edge_and_event_window_are_not_passed(self):
        # Deliberately build a corrupted fixture in memory, never overwrite immutable case.
        bad = json.loads(json.dumps(self.case, default=str))
        bad["graph"]["edges"][0]["confidence"] = "high"
        bad["graph"]["window"]["start"] = "2026-11-21T00:00:00+00:00"
        async with (
            await db._connect() as conn,
            conn.cursor(row_factory=cc.dict_row) as cur,
        ):
            report = await cc.inspect_case(cur, bad)
        self.assertEqual(report["state"], "inconsistent")
        self.assertFalse(report["case_hash_matches"])
        self.assertEqual(report["edges"][0]["state"], "contradicted")
        self.assertTrue(
            any("outside" in issue for n in report["nodes"] for issue in n["issues"])
        )

    async def test_reviews_pin_check_cas_history_and_append_only(self):
        check = await cc.save_check(uuid4(), check_body(self.case["id"]))
        body = review_body(check["id"])
        saved = await cc.save_review(self.case["id"], body)
        self.assertEqual(
            (await cc.save_review(self.case["id"], body))["id"], saved["id"]
        )
        with self.assertRaises(main.HTTPException):
            await cc.save_review(
                self.case["id"], body.model_copy(update={"verdict": "disputed"})
            )
        with self.assertRaises(main.HTTPException):
            await cc.save_review(
                self.case["id"], body.model_copy(update={"request_id": uuid4()})
            )
        second = await cc.save_review(
            self.case["id"],
            body.model_copy(
                update={
                    "expected_revision": 1,
                    "request_id": uuid4(),
                    "verdict": "supported_association",
                }
            ),
        )
        self.assertEqual(second["revision"], 2)
        history = await cc.reviews(self.case["id"], 1)
        self.assertEqual((history["total"], history["revision"]), (2, 2))
        self.assertFalse(history["independent_identity_verified"])
        with self.assertRaises(main.HTTPException):
            await cc.save_review(
                uuid4(), body.model_copy(update={"request_id": uuid4()})
            )
        for table in ("case_checks", "case_operator_reviews"):
            async with await db._connect() as conn:
                with self.assertRaises(psycopg.Error):
                    await conn.execute(f"DELETE FROM {table}")

    async def test_decision_lifecycle_change_is_not_causal_confirmation(self):
        async with await db._connect() as conn:
            await conn.execute(
                "INSERT INTO decisions(incident_alert_id,action,target,policy_verdict,status) VALUES ('fixture-0','temporary_ip_block','8.8.8.8','pending_approval','pending_approval')"
            )
            await conn.commit()
        case = await cases.create(
            uuid4(),
            cases.CaseInput(
                anchor_kind="incidents",
                anchor_id=1,
                declared_by="Fixture",
                rationale="Inspect decision lifecycle reference",
            ),
        )
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE decisions SET status='executed',executed_at=now() WHERE incident_alert_id='fixture-0'"
            )
            await conn.commit()
        saved = await cc.save_check(uuid4(), check_body(case["id"]))
        self.assertEqual(saved["report"]["state"], "incomplete_or_changed")
        self.assertTrue(
            any(e["state"] == "supported_reference" for e in saved["report"]["edges"])
        )
        self.assertTrue(
            any(
                n["state"] == "changed_since_snapshot" for n in saved["report"]["nodes"]
            )
        )
