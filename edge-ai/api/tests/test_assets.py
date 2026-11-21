"""Inventory contracts and target identity; isolated PostgreSQL only for writes."""

import asyncio
import json
import os
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import httpx
import psycopg
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
from app import assets, investigation, main
from app.integrations import dashboard_db, db


def payload(**changes):
    return assets.AssetPayload(
        name="Fixture endpoint",
        kind="host",
        agent_ids=["001"],
        ips=["10.20.30.40"],
        **changes,
    )


def body(p=None, revision=0, **changes):
    return assets.AssetInput(
        payload=p or payload(),
        declared_by="Fixture operator",
        rationale="Verified fixture configuration",
        expected_revision=revision,
        request_id=uuid4(),
        **changes,
    )


def record(p=None, asset_id=None):
    return {
        "asset_id": asset_id or uuid4(),
        "revision": 1,
        "created_at": datetime.now(UTC),
        "payload": (p or payload()).model_dump(mode="json"),
    }


class AssetContracts(unittest.IsolatedAsyncioTestCase):
    async def test_api_gate_and_forbid_spoofed_authentication(self):
        identity = uuid4()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            data = json.loads(body().model_dump_json())
            with (
                patch.object(main.settings, "operation_key", "fixture-key"),
                patch.object(
                    assets, "save", AsyncMock(return_value={"ok": True})
                ) as save,
            ):
                self.assertEqual(
                    (
                        await client.post(f"/api/v1/assets/{identity}", json=data)
                    ).status_code,
                    403,
                )
                save.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.post(
                            f"/api/v1/assets/{identity}",
                            json=data,
                            headers={"X-Operation-Key": "fixture-key"},
                        )
                    ).status_code,
                    200,
                )
            self.assertEqual(
                (
                    await client.post(
                        f"/api/v1/assets/{identity}",
                        json={**data, "authentication": "verified-admin"},
                    )
                ).status_code,
                422,
            )

    async def test_binding_validation_rejects_manager_mapped_loopback_and_bad_route(
        self,
    ):
        self.assertEqual(
            assets.canonical_host("APP.Example.com.:443"), "app.example.com:443"
        )
        self.assertEqual(
            assets.canonical_host("app.example.com:0"), "app.example.com:0"
        )
        for changes in (
            {"agent_ids": ["000"]},
            {"agent_ids": ["001", "001"]},
            {"ips": ["127.0.0.1"]},
            {"ips": ["::ffff:127.0.0.1"]},
            {"ips": ["fe80::1"]},
            {"parent_host_id": uuid4()},
        ):
            base = {"name": "Fixture", "kind": "host", **changes}
            with self.assertRaises(ValidationError):
                assets.AssetPayload(**base)
        for host in ("bad host", "https://example.com", "user@example.com", "a\nb.com"):
            with self.assertRaises(ValueError):
                assets.canonical_host(host)
        for path in ("relative", "//host", "/a/../b", "/app?x=1", "/a#b"):
            with self.assertRaises(ValidationError):
                assets.RouteBinding(
                    host="app.example.com", router="app@docker", path_prefix=path
                )

    async def test_route_boundary_specificity_and_parent_are_explicit(self):
        host = record()
        app = record(
            assets.AssetPayload(
                name="Fixture app",
                kind="application",
                parent_host_id=host["asset_id"],
                routes=[
                    assets.RouteBinding(
                        host="APP.Example.com.",
                        router="app@docker",
                        path_prefix="/app/",
                    )
                ],
            )
        )
        nested = record(
            assets.AssetPayload(
                name="Specific service",
                kind="service",
                routes=[
                    assets.RouteBinding(
                        host="app.example.com",
                        router="app@docker",
                        path_prefix="/app/api",
                    )
                ],
            )
        )
        base = {
            "host": "app.example.com",
            "router": "app@docker",
            "source_ip": "10.20.30.40",
        }
        for path, expected in (
            ("/app", app),
            ("/app/x?q=1", app),
            ("/app/api/v1", nested),
        ):
            result = assets.resolve(
                "requests", {**base, "path": path}, [host, app, nested]
            )
            self.assertEqual(result["asset"]["asset_id"], str(expected["asset_id"]))
        result = assets.resolve("requests", {**base, "path": "/app"}, [host, app])
        self.assertEqual(result["parent_host"]["asset_id"], str(host["asset_id"]))
        self.assertEqual(result["bindings"]["agent_ids"], ["001"])
        for changes in (
            {"path": "/application"},
            {"path": "/%61pp"},
            {"path": "/app", "router": "other"},
        ):
            self.assertIsNone(
                assets.resolve("requests", {**base, **changes}, [host, app])["asset"]
            )

    async def test_shared_ips_and_two_endpoints_do_not_select_unique_target(self):
        host = record()
        other = record(
            assets.AssetPayload(
                name="Other fixture",
                kind="host",
                agent_ids=["002"],
                ips=["10.20.30.40"],
            )
        )
        event = {
            "source": "suricata",
            "event": {"event": {"src_ip": "10.20.30.40", "dest_ip": "8.8.8.8"}},
        }
        result = assets.resolve("incidents", event, [host, other])
        self.assertIsNone(result["asset"])
        self.assertTrue(result["warnings"])
        wazuh = {
            "source": "wazuh",
            "event": {"event": {"agent": {"id": "001", "ip": "10.20.30.40"}}},
        }
        result = assets.resolve("incidents", wazuh, [host, other])
        self.assertEqual(result["asset"]["asset_id"], str(host["asset_id"]))
        self.assertEqual(result["bindings"]["ips"], [])
        other["payload"]["ips"] = ["10.20.30.41"]
        wazuh["event"]["event"]["agent"]["ip"] = "10.20.30.41"
        self.assertIsNone(assets.resolve("incidents", wazuh, [host, other])["asset"])
        # HTTP peer IP is never a target binding; WAF source IP neither.
        self.assertIsNone(
            assets.resolve("requests", {"source_ip": "10.20.30.40"}, [host])["asset"]
        )
        self.assertIsNone(
            assets.resolve(
                "incidents", {"source": "crowdsec", "source_ip": "10.20.30.40"}, [host]
            )["asset"]
        )


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test DB not configured"
)
class AssetDatabaseTests(unittest.IsolatedAsyncioTestCase):
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
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE asset_registry,incidents,gateway_requests RESTART IDENTITY CASCADE"
            )
            await conn.commit()

    async def test_history_cas_idempotency_and_append_only(self):
        identity = uuid4()
        first = body()
        row = (await assets.save(identity, first))["asset"]
        self.assertEqual((await assets.save(identity, first))["asset"]["id"], row["id"])
        with self.assertRaises(main.HTTPException):
            await assets.save(
                identity,
                first.model_copy(update={"rationale": "Conflicting retry content"}),
            )
        with self.assertRaises(main.HTTPException):
            await assets.save(identity, body())
        await assets.save(identity, body(payload(owner="New fixture owner"), 1))
        history = await assets.detail(identity, page=1, page_size=1)
        self.assertEqual(
            (history["total"], history["pages"], history["current"]["revision"]),
            (2, 2, 2),
        )
        self.assertEqual((await assets.save(identity, first))["asset"]["revision"], 1)
        for sql in (
            "UPDATE asset_revisions SET declared_by='changed'",
            "DELETE FROM asset_revisions",
        ):
            with self.assertRaises(psycopg.errors.RaiseException):
                async with await db._connect() as conn:
                    await conn.execute(sql)

    async def test_cross_asset_selector_race_and_shared_ip_warning(self):
        results = await asyncio.gather(
            assets.save(uuid4(), body()),
            assets.save(uuid4(), body()),
            return_exceptions=True,
        )
        self.assertEqual(sum(isinstance(r, dict) for r in results), 1)
        self.assertEqual(
            sum(
                isinstance(r, main.HTTPException) and r.status_code == 409
                for r in results
            ),
            1,
        )
        result = await assets.save(
            uuid4(),
            body(
                assets.AssetPayload(
                    name="Shared IP host",
                    kind="host",
                    agent_ids=["002"],
                    ips=["10.20.30.40"],
                )
            ),
        )
        self.assertTrue(result["warnings"])
        self.assertEqual(
            (
                await assets.listing(
                    q="Fixture", status="all", kind="all", page=1, page_size=10
                )
            )["total"],
            1,
        )

    async def test_parent_lifecycle_and_route_collision(self):
        host = uuid4()
        app = uuid4()
        await assets.save(host, body())
        p = assets.AssetPayload(
            name="Fixture app",
            kind="application",
            parent_host_id=host,
            routes=[
                assets.RouteBinding(
                    host="app.example.com", router="app@docker", path_prefix="/app"
                )
            ],
        )
        await assets.save(app, body(p))
        with self.assertRaises(main.HTTPException):
            await assets.save(uuid4(), body(p))
        with self.assertRaises(main.HTTPException):
            await assets.save(host, body(payload(status="retired"), 1))
        await assets.save(app, body(p.model_copy(update={"status": "retired"}), 1))
        await assets.save(host, body(payload(status="retired"), 1))
        with self.assertRaises(main.HTTPException):
            await assets.save(app, body(p, 2))
        self.assertEqual(await assets.current_registry(), [])

    async def test_observed_untrusted_ids_and_software_search(self):
        async with await db._connect() as conn:
            for agent in ("001", "000", "bad-id"):
                await conn.execute(
                    "INSERT INTO incidents(alert_id,source,kind,severity,reason,event) VALUES (%s,'wazuh','host','medium','fixture',%s)",
                    (
                        agent,
                        json.dumps(
                            {
                                "event": {
                                    "agent": {
                                        "id": agent,
                                        "name": "Fixture observed",
                                        "ip": "10.20.30.40",
                                    }
                                }
                            }
                        ),
                    ),
                )
            await conn.commit()
        self.assertEqual(
            [r["agent_id"] for r in (await assets.observed())["items"]], ["001"]
        )
        await assets.save(
            uuid4(),
            body(
                payload(
                    software=[
                        assets.Software(
                            vendor="Fixture vendor",
                            product="Fixture product",
                            version="1.2",
                        )
                    ]
                )
            ),
        )
        self.assertEqual(
            (
                await assets.listing(
                    q="Fixture product",
                    status="active",
                    kind="host",
                    page=99,
                    page_size=10,
                )
            )["page"],
            1,
        )

    async def test_request_to_parent_host_sensor_timeline_uses_mapping_revision(self):
        host = uuid4()
        await assets.save(host, body())
        app = assets.AssetPayload(
            name="Fixture app",
            kind="application",
            parent_host_id=host,
            routes=[
                assets.RouteBinding(
                    host="app.example.com", router="app@docker", path_prefix="/app"
                )
            ],
        )
        await assets.save(uuid4(), body(app))
        async with await db._connect() as conn:
            request = await (
                await conn.execute(
                    "INSERT INTO gateway_requests(fingerprint,observed_at,host,router,path,source_ip,raw) VALUES ('fixture',now(),'app.example.com','app@docker','/app/x','172.18.0.1','{}') RETURNING id"
                )
            ).fetchone()
            await conn.execute(
                "INSERT INTO incidents(alert_id,source,kind,severity,reason,event) VALUES ('endpoint','wazuh','host','medium','fixture',%s)",
                (json.dumps({"event": {"agent": {"id": "001", "ip": "10.20.30.40"}}}),),
            )
            await conn.commit()
        with (
            patch.object(
                investigation.intelligence, "lookup", AsyncMock(return_value=[])
            ),
            patch.object(
                investigation.intelligence, "status", AsyncMock(return_value={})
            ),
        ):
            data = await investigation.timeline(
                "requests", request[0], minutes=15, page=1
            )
        self.assertEqual(data["asset_context"]["asset"]["revision"], 1)
        self.assertEqual(len(data["items"]), 1)
        self.assertIn(
            "current operator-mapped host binding", data["items"][0]["match_reasons"][0]
        )


if __name__ == "__main__":
    unittest.main()
