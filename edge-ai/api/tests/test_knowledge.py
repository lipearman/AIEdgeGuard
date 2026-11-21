"""Phase2 source, declared-product and execution-provenance contracts."""

import asyncio
import copy
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
from app import applicability, assets, knowledge, main, triage
from app.agents import analysis
from app.integrations import db, ollama_client

CVE = "CVE-2024-4577"
CPE = "cpe:2.3:a:fixture:product:*:*:*:*:*:*:*:*"


def nvd():
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "totalResults": 1,
        "startIndex": 0,
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE,
                    "lastModified": datetime.now(UTC).isoformat(),
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Fixture CVE description"}
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": CPE,
                                            "versionStartIncluding": "1.0",
                                            "versionEndExcluding": "2.0",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }


def mitre():
    return {
        "type": "bundle",
        "id": "bundle--fixture",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--fixture",
                "name": "Fixture technique",
                "description": "Fixture description",
                "modified": datetime.now(UTC).isoformat(),
                "x_mitre_version": "1.0",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1190"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
            }
        ],
    }


def drop():
    return [
        {"cidr": "45.0.0.0/24", "sblid": "SBL123"},
        {
            "type": "metadata",
            "timestamp": int(datetime.now(UTC).timestamp()),
            "records": 1,
            "copyright": "(c) Fixture The Spamhaus Project",
        },
    ]


def software(version="1.5", **changes):
    return {
        "vendor": "Fixture",
        "product": "Product",
        "version": version,
        "cpe23": CPE,
        "version_scheme": "numeric_dot",
        **changes,
    }


class KnowledgeUnit(unittest.IsolatedAsyncioTestCase):
    async def test_model_tag_digest_is_observed_and_cached_not_runtime_attestation(
        self,
    ):
        original = httpx.AsyncClient
        calls = []

        def handler(request):
            calls.append(str(request.url))
            return httpx.Response(
                200, json={"models": [{"name": "fixture-model", "digest": "a" * 64}]}
            )

        with (
            patch.object(ollama_client, "_model_catalog_at", None),
            patch.object(ollama_client, "_model_catalog", {}),
            patch.object(
                ollama_client.httpx,
                "AsyncClient",
                lambda **options: original(
                    **options, transport=httpx.MockTransport(handler)
                ),
            ),
        ):
            first = await ollama_client.model_metadata("fixture-model")
            second = await ollama_client.model_metadata("fixture-model")
        self.assertEqual(len(calls), 1)
        self.assertEqual(first["observed_model_digest"], "a" * 64)
        self.assertEqual(first, second)
        self.assertIn("not an immutable runtime attestation", first["digest_scope"])

    async def test_nvd_rejects_unrequested_partial_future_and_missing_data(self):
        self.assertEqual(knowledge.validate("nvd", CVE, nvd())[0]["record"]["id"], CVE)
        for mutate in (
            lambda d: d.update(totalResults=2),
            lambda d: d.update(startIndex=1),
            lambda d: d["vulnerabilities"][0]["cve"].update(id="CVE-2025-12345"),
            lambda d: d["vulnerabilities"][0]["cve"].update(
                lastModified=(datetime.now(UTC) + timedelta(days=2)).isoformat()
            ),
        ):
            d = nvd()
            mutate(d)
            with self.assertRaises((ValueError, TypeError)):
                knowledge.validate("nvd", CVE, d)
        for change in (
            {"descriptions": [None]},
            {"descriptions": [{"lang": "en", "value": None}]},
            {"metrics": []},
            {"vulnStatus": None},
        ):
            malformed = nvd()
            malformed["vulnerabilities"][0]["cve"].update(change)
            with self.assertRaises((ValueError, TypeError)):
                knowledge.validate("nvd", CVE, malformed)
        self.assertIsNone(
            knowledge.validate(
                "nvd", CVE, {**nvd(), "totalResults": 0, "vulnerabilities": []}
            )[0]["record"]
        )

    async def test_mitre_excludes_revoked_and_rejects_duplicate_or_unknown_ids(self):
        d = mitre()
        old = copy.deepcopy(d["objects"][0])
        old["revoked"] = True
        d["objects"].append(old)
        self.assertEqual(
            len(knowledge.validate("mitre", "catalog", d)[0]["techniques"]), 1
        )
        for changes in ({"external_references": []}, {"modified": "bad-date"}):
            d = mitre()
            d["objects"][0].update(changes)
            with self.assertRaises((ValueError, TypeError)):
                knowledge.validate("mitre", "catalog", d)
        d = mitre()
        d["objects"] *= 2
        with self.assertRaises(ValueError):
            knowledge.validate("mitre", "catalog", d)

    async def test_drop_requires_correct_family_metadata_count_and_public_specific_ranges(
        self,
    ):
        self.assertEqual(
            knowledge.validate("drop4", "catalog", drop())[0]["networks"][0]["sblid"],
            "SBL123",
        )
        duplicate = drop()
        duplicate.insert(1, {**duplicate[0], "sblid": "SBL456"})
        duplicate.insert(2, dict(duplicate[0]))
        duplicate[-1]["records"] = 3
        normalized = knowledge.validate("drop4", "catalog", duplicate)[0]
        self.assertEqual(len(normalized["networks"]), 2)
        self.assertEqual(normalized["duplicates_removed"], 1)

        for network in (
            "0.0.0.0/0",
            "127.0.0.0/8",
            "10.0.0.0/8",
            "2001:4860::/32",
            "45.0.0.1/24",
        ):
            d = drop()
            d[0]["cidr"] = network
            with self.assertRaises(ValueError):
                knowledge.validate("drop4", "catalog", d)
        d = drop()
        d[-1]["records"] = 2
        with self.assertRaises(ValueError):
            knowledge.validate("drop4", "catalog", d)

    async def test_declared_versions_boundaries_and_unknown_schemes(self):
        criterion = nvd()["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0][
            "cpeMatch"
        ][0]
        for version, expected in [
            ("0.9", "no_match"),
            ("1.0", "candidate"),
            ("1.99.0", "candidate"),
            ("2.0", "no_match"),
        ]:
            self.assertEqual(
                applicability.match(software(version), criterion)[0], expected
            )
        for product in (
            software("1.5", version_scheme="unknown"),
            software("1.5rc1"),
            software(cpe23=""),
            software(cpe23=CPE.replace(":*:*:*:*:*:*:*:*", ":1.4:*:*:*:*:*:*:*")),
        ):
            self.assertEqual(applicability.match(product, criterion)[0], "unknown")
        self.assertEqual(applicability.version_compare("1.2", "1.2.0"), 0)
        self.assertIsNone(applicability.version_compare("1.2b", "1.2"))

    async def test_environment_negation_and_incomplete_inventory_never_claim_clean_or_confirmed(
        self,
    ):
        record = nvd()["vulnerabilities"][0]["cve"]
        self.assertEqual(
            applicability.evaluate([software()], record)["state"], "candidate_affected"
        )
        for changes in ({"operator": "AND"}, {"negate": True}):
            d = copy.deepcopy(record)
            d["configurations"][0]["nodes"][0].update(changes)
            self.assertEqual(
                applicability.evaluate([software()], d)["state"], "needs_review"
            )
        self.assertEqual(applicability.evaluate([], record)["state"], "needs_review")
        self.assertEqual(
            applicability.evaluate([software("3.0")], record)["state"],
            "no_match_in_declared_products",
        )
        self.assertIn("not verified", applicability.SCOPE)
        for state in ("Rejected", "Deferred", "Modified", "Received", None):
            pending = {**record, "vulnStatus": state}
            self.assertEqual(
                applicability.evaluate([software()], pending)["state"], "needs_review"
            )

    async def test_model_cannot_forge_execution_provenance_or_citations(self):
        raw = {
            "attack_type": "Fixture",
            "severity": "medium",
            "confidence": 0.5,
            "reasoning": "Fixture evidence",
            "needs_human_review": True,
            "recommended_action": {"action_type": "none"},
            "source_citations": [{"snapshot_id": 999}],
            "execution_provenance": {"prompt_version": "forged"},
            "_edgeguard_runtime": {"returned_model": "fixture-model"},
        }
        event = {
            "reference_context": {
                "citations": [{"provider": "nvd", "snapshot_id": 1, "identifier": CVE}]
            },
            "evidence": {"value": "Fixture evidence"},
        }
        with patch.object(
            analysis.ollama_client, "chat_json", AsyncMock(return_value=raw)
        ):
            result = await analysis.analyze_event(event)
        self.assertEqual(
            result.execution_provenance["prompt_version"], analysis.PROMPT_VERSION
        )
        self.assertEqual(result.execution_provenance["returned_model"], "fixture-model")
        self.assertIsNone(result.execution_provenance["runtime_digest"])
        self.assertEqual(result.source_citations[0]["snapshot_id"], 1)
        large = {**event, "evidence": {"value": "x" * 20000}}
        self.assertEqual(len(analysis.build_prompt(large)), 6000)
        self.assertEqual(analysis.provided_citations(large), [])
        self.assertTrue(analysis.provenance(large)["primary_evidence_truncated"])
        self.assertEqual(len(result.execution_provenance["input_sha256"]), 64)
        self.assertEqual(
            triage.provenance({"payload": {}}, "fixture-model", "th")["prompt_version"],
            triage.VERSION,
        )

    async def test_gates_reject_fetch_and_assessment_without_operation_key(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=main.app), base_url="http://test"
        ) as client:
            body = {
                "asset_id": str(uuid4()),
                "asset_revision": 1,
                "cve": CVE,
                "declared_by": "Fixture operator",
                "rationale": "Fixture rationale",
                "request_id": str(uuid4()),
            }
            with (
                patch.object(main.settings, "operation_key", "fixture-key"),
                patch.object(
                    knowledge,
                    "refresh",
                    AsyncMock(return_value={"action": "cache_hit"}),
                ) as refresh,
                patch.object(
                    applicability, "assess", AsyncMock(return_value={"ok": True})
                ) as assess,
            ):
                self.assertEqual(
                    (
                        await client.post("/api/v1/knowledge/refresh/nvd/" + CVE)
                    ).status_code,
                    403,
                )
                self.assertEqual(
                    (await client.post("/api/v1/applicability", json=body)).status_code,
                    403,
                )
                refresh.assert_not_awaited()
                assess.assert_not_awaited()
                self.assertEqual(
                    (
                        await client.post(
                            "/api/v1/knowledge/refresh/other/catalog",
                            headers={"X-Operation-Key": "fixture-key"},
                        )
                    ).status_code,
                    422,
                )
                self.assertEqual(
                    (
                        await client.post(
                            "/api/v1/applicability",
                            json=body,
                            headers={"X-Operation-Key": "fixture-key"},
                        )
                    ).status_code,
                    200,
                )


@unittest.skipUnless(
    os.getenv("EDGEGUARD_TEST_DATABASE_URL"), "isolated test DB not configured"
)
class KnowledgeDatabase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        dsn = os.environ["EDGEGUARD_TEST_DATABASE_URL"]
        if not dsn.endswith("/edgeguard_test"):
            raise RuntimeError("isolated DB required")
        change = patch.object(db.settings, "database_url", dsn)
        change.start()
        self.addCleanup(change.stop)
        await assets.init_schema()
        await knowledge.init_schema()
        await applicability.init_schema()
        async with await db._connect() as conn:
            await conn.execute(
                "TRUNCATE knowledge_cache,knowledge_snapshots,asset_registry RESTART IDENTITY CASCADE"
            )
            await conn.execute("UPDATE knowledge_budget SET last_attempt=NULL")
            await conn.commit()

    async def expire(self, provider):
        async with await db._connect() as conn:
            await conn.execute(
                "UPDATE knowledge_cache SET last_success=now()-interval '30 days' WHERE provider=%s",
                (provider,),
            )
            await conn.execute(
                "UPDATE knowledge_budget SET last_attempt=NULL WHERE provider=%s",
                (provider,),
            )
            await conn.commit()

    async def fetch(self, provider, document, key="catalog"):
        with patch.object(
            knowledge, "download", AsyncMock(return_value=document)
        ) as download:
            result = await knowledge.refresh(provider, key)
        return result, download

    async def test_read_only_cache_positive_negative_cache_and_immutable_dedup(self):
        self.assertEqual((await knowledge.get("nvd", CVE))["state"], "never_fetched")
        doc = nvd()
        first, _ = await self.fetch("nvd", doc, CVE)
        second, download = await self.fetch("nvd", doc, CVE)
        download.assert_not_awaited()
        self.assertEqual(second["action"], "cache_hit")
        await self.expire("nvd")
        again, _ = await self.fetch("nvd", doc, CVE)
        self.assertEqual(first["result"]["snapshot_id"], again["result"]["snapshot_id"])
        for sql in (
            "UPDATE knowledge_snapshots SET version='bad'",
            "DELETE FROM knowledge_snapshots",
        ):
            with self.assertRaises(psycopg.errors.RaiseException):
                async with await db._connect() as conn:
                    await conn.execute(sql)
        other = "CVE-2025-12345"
        await self.expire("nvd")
        empty, _ = await self.fetch(
            "nvd", {**doc, "totalResults": 0, "vulnerabilities": []}, other
        )
        self.assertIsNone((await knowledge.get("nvd", other))["payload"]["record"])
        self.assertEqual(empty["action"], "fetched")

    async def test_failed_old_and_late_sources_retain_last_snapshot(self):
        doc = nvd()
        first, _ = await self.fetch("nvd", doc, CVE)
        await self.expire("nvd")
        doc["vulnerabilities"][0]["cve"]["lastModified"] = (
            datetime.now(UTC) - timedelta(days=2)
        ).isoformat()
        result, _ = await self.fetch("nvd", doc, CVE)
        self.assertEqual(result["action"], "failed")
        self.assertEqual(
            result["result"]["snapshot_id"], first["result"]["snapshot_id"]
        )
        self.assertEqual(result["result"]["state"], "stale")
        await self.expire("nvd")

        async def late(provider, key):
            async with await db._connect() as conn:
                await conn.execute(
                    "UPDATE knowledge_cache SET last_attempt=now()+interval '1 minute' WHERE provider=%s AND lookup_key=%s",
                    (provider, key),
                )
                await conn.commit()
            return nvd()

        with patch.object(knowledge, "download", side_effect=late):
            self.assertEqual(
                (await knowledge.refresh("nvd", CVE))["action"], "superseded"
            )

    async def test_per_source_budget_and_paged_techniques(self):
        with patch.object(
            knowledge, "download", AsyncMock(return_value=nvd())
        ) as download:
            rows = await asyncio.gather(
                knowledge.refresh("nvd", CVE),
                knowledge.refresh("nvd", "CVE-2025-12345"),
                return_exceptions=True,
            )
        self.assertEqual(download.await_count, 1)
        self.assertEqual(
            sum(
                isinstance(r, main.HTTPException) and r.status_code == 429 for r in rows
            ),
            1,
        )
        await self.fetch("mitre", mitre())
        data = await knowledge.techniques(q="T1190", page=99, page_size=1)
        self.assertEqual((data["total"], data["page"]), (1, 1))
        self.assertEqual(
            (await knowledge.techniques(q="absent", page=1, page_size=1))["total"], 0
        )

    async def test_local_ip_reputation_freshness_and_source_citations(self):
        await self.fetch("drop4", drop())
        await self.fetch("mitre", mitre())
        await self.fetch("nvd", nvd(), CVE)
        self.assertEqual(len((await knowledge.ip_lookup("45.0.0.1"))["matches"]), 1)
        self.assertEqual((await knowledge.ip_lookup("127.0.0.1"))["matches"], [])
        self.assertEqual((await knowledge.ip_lookup("1.1.1.1"))["matches"], [])
        with patch.object(knowledge, "download", AsyncMock()) as download:
            context = await knowledge.event_context(
                {
                    "source_ip": "45.0.0.1",
                    "event": {
                        "event": {"rule": {"mitre": {"id": ["T1190"]}}, "cve": CVE}
                    },
                }
            )
            download.assert_not_awaited()
        self.assertEqual(
            {c["provider"] for c in context["citations"]}, {"nvd", "mitre", "drop4"}
        )
        for citation in context["citations"]:
            self.assertIsNotNone(
                (await knowledge.snapshot(citation["snapshot_id"]))["fingerprint"]
            )

    async def test_revision_bound_assessment_is_audited_immutable_and_retry_safe(self):
        await self.fetch("nvd", nvd(), CVE)
        identity = uuid4()
        p = assets.AssetPayload(
            name="Fixture asset", kind="host", software=[assets.Software(**software())]
        )
        await assets.save(
            identity,
            assets.AssetInput(
                payload=p,
                declared_by="Fixture operator",
                rationale="Fixture mapped product",
                expected_revision=0,
                request_id=uuid4(),
            ),
        )
        body = applicability.AssessmentInput(
            asset_id=identity,
            asset_revision=1,
            cve=CVE,
            declared_by="Fixture operator",
            rationale="Checked declared product",
            request_id=uuid4(),
        )
        first = await applicability.assess(body)
        again = await applicability.assess(body)
        self.assertTrue(again["replayed"])
        self.assertEqual(first["assessment"]["id"], again["assessment"]["id"])
        self.assertEqual(first["assessment"]["report"]["state"], "candidate_affected")
        with self.assertRaises(main.HTTPException):
            await applicability.assess(
                body.model_copy(update={"rationale": "different input"})
            )
        await assets.save(
            identity,
            assets.AssetInput(
                payload=p.model_copy(update={"owner": "Changed"}),
                declared_by="Fixture operator",
                rationale="Fixture new revision",
                expected_revision=1,
                request_id=uuid4(),
            ),
        )
        with self.assertRaises(main.HTTPException):
            await applicability.assess(body.model_copy(update={"request_id": uuid4()}))
        self.assertEqual(
            (await applicability.detail(first["assessment"]["id"]))["asset_revision"], 1
        )
        self.assertEqual((await applicability.history(identity, page=1))["total"], 1)
        for sql in (
            "UPDATE applicability_assessments SET rationale='changed'",
            "DELETE FROM applicability_assessments",
        ):
            with self.assertRaises(psycopg.errors.RaiseException):
                async with await db._connect() as conn:
                    await conn.execute(sql)


if __name__ == "__main__":
    unittest.main()
