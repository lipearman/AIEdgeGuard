"""Fully synthetic source-library workflow. No real assets/reports/sync writes."""

import copy
import mimetypes
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "edge-ai/api/app/static"
OUT = ROOT / ".impeccable/review"
IDENTITY = "a1130e53-d727-4c7c-9431-0ce47d49bf6a"
CVE = "CVE-2024-4577"


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, channel="chrome")
        for width, prefix in (
            (1440, ""),
            (768, "/AIEdgeGuard"),
            (390, "/aiedge"),
            (320, ""),
        ):
            page = browser.new_page(viewport={"width": width, "height": 1000})
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.on(
                "dialog",
                lambda d: (
                    d.accept("fixture-operation-key")
                    if d.type == "prompt"
                    else d.accept()
                ),
            )
            state = {
                "nvd": False,
                "fail": False,
                "lost": True,
                "conflict": False,
                "revision": 1,
                "reports": [],
                "posts": [],
                "fetches": 0,
            }
            source = {
                "provider": "nvd",
                "state": "current",
                "snapshot_id": 8,
                "last_success": "2026-11-21T06:00:00Z",
                "published_at": "2026-11-20T06:00:00Z",
                "error": "",
            }
            asset = {
                "asset_id": IDENTITY,
                "revision": 1,
                "payload": {
                    "name": "Fixture endpoint",
                    "kind": "host",
                    "software": [
                        {
                            "vendor": "Fixture",
                            "product": "Product",
                            "version": "1.5",
                            "cpe23": "cpe:2.3:a:fixture:product:*:*:*:*:*:*:*:*",
                            "version_scheme": "numeric_dot",
                        }
                    ],
                },
            }
            incident = {
                "id": 1,
                "alert_id": "fixture-incident",
                "source": "wazuh",
                "created_at": "2026-11-21T06:00:00Z",
                "reason": "Fixture host evidence",
                "severity": "medium",
                "source_ip": "",
                "event": {
                    "event": {"agent": {"id": "001", "name": "Fixture endpoint"}}
                },
                "analysis": {
                    "attack_type": "Host Authentication Alert",
                    "reasoning": "Fixture evidence only",
                    "execution_provenance": {
                        "prompt_version": "analysis-v2-fixture",
                        "requested_model": "fixture-model",
                        "observed_model_digest": "a" * 64,
                        "runtime_digest": None,
                        "digest_scope": "Observed tag, not runtime attestation",
                    },
                    "source_citations": [
                        {
                            "provider": "nvd",
                            "snapshot_id": 8,
                            "identifier": CVE,
                            "state": "current",
                            "scope": "Literal source identifier, not proven exploitation",
                        }
                    ],
                },
            }

            def route(r):
                url = urlparse(r.request.url)
                path = url.path.removeprefix(prefix)
                q = parse_qs(url.query)
                if path == "/dashboard":
                    r.fulfill(
                        path=str(STATIC / "dashboard.html"), content_type="text/html"
                    )
                    return
                if path.startswith("/static/"):
                    f = STATIC / path.removeprefix("/static/")
                    r.fulfill(
                        path=str(f),
                        content_type=mimetypes.guess_type(str(f))[0]
                        or "application/octet-stream",
                    )
                    return
                if path == "/api/v1/knowledge/status":
                    data = {
                        "items": [
                            {
                                **source,
                                "provider": provider,
                                "snapshot_id": 10 + i,
                                "payload": {
                                    "copyright": "(c) Fixture The Spamhaus Project" if provider != "mitre" else "",
                                    "publisher_date": "2026-11-20",
                                    "notice": "Synthetic catalog fixture; no automatic enforcement",
                                },
                            }
                            for i, provider in enumerate(("mitre", "drop4", "drop6"))
                        ]
                    }
                elif path.startswith("/api/v1/knowledge/refresh/"):
                    state["fetches"] += 1
                    assert (
                        r.request.headers["x-operation-key"] == "fixture-operation-key"
                    )
                    state["nvd"] = True
                    data = {"action": "fetched", "result": source}
                elif path.startswith("/api/v1/knowledge/nvd/"):
                    if state["fail"]:
                        r.fulfill(
                            status=503, json={"detail": "Fixture source unavailable"}
                        )
                        return
                    data = {
                        **source,
                        "state": "current" if state["nvd"] else "never_fetched",
                        "snapshot_id": 8 if state["nvd"] else None,
                        "payload": {
                            "record": {
                                "id": CVE,
                                "vulnStatus": "Analyzed",
                                "lastModified": "2026-11-20",
                                "descriptions": [
                                    {
                                        "lang": "en",
                                        "value": "Fixture <img src=x onerror=window.injected=1>",
                                    }
                                ],
                                "metrics": {"fixture": "not a benchmark"},
                                "configurations": [],
                            }
                            if state["nvd"]
                            else None,
                            "notice": "NVD fixture attribution",
                        },
                    }
                elif path == "/api/v1/knowledge/techniques":
                    number = int(q.get("page", [1])[0])
                    search = q.get("q", [""])[0]
                    data = {
                        "items": []
                        if search == "absent"
                        else [
                            {
                                "id": "T1190" if number == 1 else "T1110",
                                "name": "Fixture technique <script>window.injected=1</script>",
                                "description": "Synthetic technique description",
                                "tactics": ["initial-access"],
                                "version": "1.0",
                                "modified": "2026-11-20",
                            }
                        ],
                        "total": 0 if search == "absent" else 6,
                        "page": 1 if search == "absent" else number,
                        "pages": 1 if search == "absent" else 2,
                        "source": {**source, "provider": "mitre"},
                    }
                elif path == "/api/v1/knowledge/ip":
                    if q.get("value") == ["invalid"]:
                        r.fulfill(status=422, json={"detail": "Use one IP address"})
                        return
                    data = {
                        "ip": q.get("value", [""])[0],
                        "matches": [{"cidr": "45.0.0.0/24", "sblid": "SBL123"}],
                        "source": {**source, "provider": "drop4", "snapshot_id":11},
                        "scope": "Range reputation, not proof of malicious intent. No automatic enforcement.",
                    }
                elif path == "/api/v1/assets":
                    data = {"items": [asset], "total": 1, "page": 1, "pages": 1}
                elif path == "/api/v1/assets/" + IDENTITY:
                    data = {
                        "current": {**asset, "revision": state["revision"]},
                        "items": [asset],
                        "total": 1,
                        "page": 1,
                        "pages": 1,
                    }
                elif path.startswith("/api/v1/applicability/asset/"):
                    number = int(q.get("page", [1])[0])
                    data = {
                        "items": state["reports"],
                        "total": len(state["reports"]),
                        "page": number,
                        "pages": 2 if state["reports"] else 1,
                    }
                elif path == "/api/v1/applicability":
                    body = r.request.post_data_json
                    state["posts"].append(copy.deepcopy(body))
                    assert (
                        r.request.headers["x-operation-key"] == "fixture-operation-key"
                    )
                    if state["conflict"]:
                        r.fulfill(
                            status=409,
                            json={
                                "detail": "Asset revision changed; reload before assessing"
                            },
                        )
                        return
                    old = next(
                        (
                            x
                            for x in state["reports"]
                            if x["request_id"] == body["request_id"]
                        ),
                        None,
                    )
                    row = old or {
                        **body,
                        "id": len(state["reports"]) + 1,
                        "nvd_snapshot_id": 8,
                        "created_at": "2026-11-21T06:00:00Z",
                        "report": {
                            "state": "candidate_affected",
                            "scope": "Candidate from operator declarations, not verified vulnerability. No-match is not a clean asset.",
                            "items": [
                                {
                                    "product": "Fixture <img src=x onerror=window.injected=1>",
                                    "state": "candidate_affected",
                                }
                            ],
                        },
                    }
                    if not old:
                        state["reports"].append(row)
                    if state["lost"]:
                        state["lost"] = False
                        r.abort("failed")
                        return
                    data = {"assessment": row, "replayed": bool(old)}
                elif path == "/api/v1/reviews/1":
                    data={"revision":0,"current":None,"memory":{"state":"unreviewed"},"items":[],"page":1,"pages":1,"total":0,"identity_scope":"Self-reported fixture operator"}
                elif path == "/health":
                    data = {
                        k: "ok" for k in ("ollama", "redis", "postgres", "crowdsec")
                    }
                elif path.endswith("/visibility"):
                    data = {"layers": {}}
                elif path.endswith("/agents/status"):
                    data = {"defense": {"mode": "dry_run"}, "attack": {"mode": "off"}}
                elif path.endswith("/dashboard/summary"):
                    data = {
                        "requests": 0,
                        "incidents": 1,
                        "analyzed": 1,
                        "pending": 0,
                        "campaigns": 0,
                    }
                elif "/dashboard/data/incidents" in path:
                    data = (
                        incident
                        if path.endswith("/1")
                        else {
                            "items": [incident],
                            "total": 1,
                            "page": 1,
                            "pages": 1,
                            "snapshot": 1,
                        }
                    )
                elif "/dashboard/data/" in path:
                    data = {
                        "items": [],
                        "total": 0,
                        "page": 1,
                        "pages": 1,
                        "snapshot": 0,
                    }
                else:
                    data = {}
                r.fulfill(json=data)

            page.route("**/*", route)
            page.goto("http://demo.test" + prefix + "/dashboard#sources")
            page.wait_for_selector(
                '#sourceAsset option[value="' + IDENTITY + '"]', state="attached"
            )
            assert page.locator("#dataView").is_hidden()
            page.locator("#sourceCve").fill(CVE)
            page.locator("#sourceNvdView").click()
            page.wait_for_function(
                "document.querySelector('#sourceNvdStatus').textContent.includes('never_fetched')"
            )
            assert state["fetches"] == 0
            page.locator("#sourceNvdFetch").click()
            page.wait_for_function(
                "document.querySelector('#sourceNvdStatus').textContent.includes('fetched')"
            )
            assert page.locator("#sourceNvdResult img").count() == 0
            page.locator("#sourceAsset").select_option(IDENTITY)
            page.wait_for_function(
                "document.querySelector('#sourceAssetStatus').textContent.includes('revision 1')"
            )
            page.locator("#sourceAuthor").fill("Fixture operator")
            page.locator("#sourceRationale").fill(
                "Checked fixture declared product and CPE"
            )
            page.locator("#sourceAssess").click()
            page.wait_for_function(
                "document.querySelector('#sourceAssessmentStatus').textContent.includes('Draft retained')"
            )
            page.locator("#sourceAssess").click()
            page.wait_for_function(
                "document.querySelector('#sourceAssessmentStatus').textContent.includes('Saved assessment')"
            )
            assert state["posts"][0]["request_id"] == state["posts"][1]["request_id"]
            assert (
                "Candidate match"
                in page.locator("#sourceAssessmentResult").inner_text()
            )
            assert (
                page.locator("#sourceAssessmentResult a").nth(1).get_attribute("href")
                == prefix + "/api/v1/knowledge/snapshots/8"
            )
            page.locator("#sourceRationale").fill(
                "Different fixture assessment rationale"
            )
            state["conflict"] = True
            page.locator("#sourceAssess").click()
            page.wait_for_function(
                "document.querySelector('#sourceAssessmentStatus').textContent.includes('revision changed')"
            )
            assert (
                page.locator("#sourceRationale").input_value()
                == "Different fixture assessment rationale"
            )
            state["conflict"] = False
            state["revision"] = 2
            page.locator("#sourceAssetReload").click()
            page.wait_for_function(
                "document.querySelector('#sourceAssetStatus').textContent.includes('revision 2')"
            )
            page.locator("#sourceAssess").click()
            page.wait_for_function(
                "document.querySelector('#sourceAssessmentStatus').textContent.includes('Saved assessment #2')"
            )
            assert state["posts"][-1]["asset_revision"] == 2
            page.locator("#sourceAssessmentHistory").evaluate("e=>e.open=true")
            page.locator("#sourceHistoryNext").click()
            page.wait_for_function(
                "document.querySelector('#sourceHistoryPage').textContent==='2 / 2'"
            )
            page.locator("#sourceHistoryPrevious").click()
            page.locator("#sourceHistoryItems button").first.click()
            assert "Checked fixture declared product and CPE" in page.locator("#sourceAssessmentResult").inner_text()
            assert page.locator("#sourceRationale").input_value() == "Different fixture assessment rationale"
            page.locator("#sourceHistoryItems button").last.click()

            page.locator("#sourceTechniqueNext").click()
            page.wait_for_function(
                "document.querySelector('#sourceTechniquePage').textContent==='2 / 2'"
            )
            page.locator("#sourceTechniqueQuery").fill("absent")
            page.locator("#sourceTechniqueForm button").click()
            page.wait_for_function(
                "document.querySelector('#sourceTechniqueStatus').textContent.includes('0 techniques')"
            )
            page.locator("#sourceTechniqueQuery").fill("")
            page.locator("#sourceTechniqueForm button").click()
            page.wait_for_selector(".source-technique")
            page.locator("#sourceIp").fill("invalid")
            page.locator("#sourceIpForm button").click()
            page.wait_for_function(
                "document.querySelector('#sourceIpStatus').textContent.includes('Use one IP')"
            )
            page.locator("#sourceIp").fill("45.0.0.1")
            page.locator("#sourceIpForm button").click()
            page.wait_for_function(
                "document.querySelector('#sourceIpStatus').textContent.includes('current')"
            )
            assert "SBL123" in page.locator("#sourceIpResult").inner_text()
            state["fail"] = True
            page.locator("#sourceNvdView").click()
            page.wait_for_function(
                "document.querySelector('#sourceNvdStatus').textContent.includes('unavailable')"
            )
            assert page.locator("#sourceNvdFetch").is_enabled()
            state["fail"] = False
            page.locator("#sourceNvdView").click()
            page.wait_for_function(
                "document.querySelector('#sourceNvdStatus').textContent.includes('current')"
            )
            page.evaluate("document.fonts.ready")
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (
                width
            )
            assert (
                page.locator(
                    "#knowledgeWorkspace img,#knowledgeWorkspace script"
                ).count()
                == 0
            )
            assert page.evaluate("window.injected") is None
            if width in (1440, 768, 390):
                page.evaluate("document.activeElement.blur();window.scrollTo(0,0)")
                page.screenshot(path=str(OUT / f"sources-{width}.png"), full_page=True)
            page.locator("#tab-incidents").click()
            page.locator(".record-open").first.click()
            page.wait_for_selector(".source-analysis-provenance")
            assert (
                "Snapshot #8"
                in page.locator(".source-analysis-provenance").inner_text()
            )
            page.locator(".source-analysis-provenance details").evaluate(
                "e=>e.open=true"
            )
            page.locator("#detailDialog").evaluate(
                "d=>{const e=d.querySelector('.source-analysis-provenance');d.scrollTop+=e.getBoundingClientRect().top-d.getBoundingClientRect().top-120}"
            )
            if width in (1440, 390):
                page.screenshot(
                    path=str(OUT / f"source-provenance-{width}.png"), full_page=False
                )
            assert not errors, errors
            page.close()
        browser.close()
    print(
        "Knowledge UI PASS:4 widths/3 prefixes; source/cache/fetch, NVD/XSS, CPE assessment retry/CAS/reload/pinned snapshot/history, technique paging/search, IP lookup/error/recovery, analysis provenance"
    )


if __name__ == "__main__":
    run()
