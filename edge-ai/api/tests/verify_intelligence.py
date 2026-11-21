"""V2 UI contracts with synthetic evidence; no live sync or enforcement."""

import mimetypes
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "edge-ai/api/app/static"
OUT = ROOT / ".impeccable/review"


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
            state = {"fail": False, "sync": 0}
            errors = []
            page.on("pageerror", lambda e, errors=errors: errors.append(str(e)))
            row = {
                "id": 1,
                "observed_at": "2026-11-21T01:00:00Z",
                "source_ip": "192.168.128.1",
                "method": "GET",
                "path": "/%252e%252e%252f?q=%253Cscript%253E&token=private",
                "host": "fixture.local",
                "status": 403,
                "duration_ns": 1000,
                "router": "fixture",
                "raw": {"RequestProtocol": "HTTP/1.1"},
                "capture": {"headers": {}, "body_captured": False},
            }

            def route(r, _req, *, prefix=prefix, state=state, row=row):
                u = urlparse(r.request.url)
                path = u.path.removeprefix(prefix)
                q = parse_qs(u.query)
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
                if path == "/health":
                    data = {
                        x: "ok" for x in ("ollama", "crowdsec", "redis", "postgres")
                    }
                elif path.endswith("/visibility"):
                    data = {
                        "layers": {
                            x: {"state": "online", "label": "ONLINE"}
                            for x in ("http_waf", "network_ids", "host_edr")
                        }
                    }
                elif path.endswith("/agents/status"):
                    data = {
                        "defense": {"mode": "dry_run (human approval required)"},
                        "attack": {"mode": "off"},
                    }
                elif path.endswith("/dashboard/summary"):
                    data = {
                        "requests": 1,
                        "incidents": 1,
                        "analyzed": 1,
                        "pending": 0,
                        "campaigns": 1,
                    }
                elif "/dashboard/data/" in path:
                    data = (
                        row
                        if path.endswith("/1")
                        else {
                            "items": [row],
                            "total": 1,
                            "page": 1,
                            "pages": 1,
                            "snapshot": 1,
                        }
                    )
                elif "/intelligence/" in path or "/investigation/" in path:
                    if state["fail"]:
                        r.fulfill(status=503, json={"detail": "Database unavailable"})
                        return
                    if path.endswith("/status"):
                        data = {
                            "state": "current",
                            "record_count": 11,
                            "last_success": "2026-11-21T01:00:00Z",
                            "source_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "version": "fixture",
                            "automatic": True,
                            "error": "",
                        }
                    elif path.endswith("/sync"):
                        assert (
                            r.request.headers.get("x-operation-key")
                            == "browser-test-key"
                        )
                        state["sync"] += 1
                        data = {"status": "updated"}
                    elif path.endswith("/vulnerabilities"):
                        number = int(q.get("page", ["1"])[0])
                        search = q.get("q", [""])[0]
                        data = {
                            "items": []
                            if search == "none"
                            else [
                                {
                                    "cve": "CVE-2024-4577",
                                    "vendor": "PHP",
                                    "product": "PHP",
                                    "title": "Fixture <img src=x onerror=window.injected=1>",
                                    "date_added": "2026-11-20",
                                    "due_date": "2026-12-01",
                                    "description": "A bounded test description",
                                    "required_action": "Apply vendor mitigation",
                                    "ransomware": "Unknown",
                                }
                            ],
                            "total": 0 if search == "none" else 11,
                            "page": number,
                            "pages": 2,
                        }
                    elif path.endswith("/behavior"):
                        data = {
                            "state": "available",
                            "window_start": "2026-11-21T01:00:00Z",
                            "window_end": "2026-11-21T01:05:00Z",
                            "latest_request": "2026-11-21T01:05:00Z",
                            "method": "12 preceding windows",
                            "scope": "Heuristic only, no automatic enforcement.",
                            "items": [
                                {
                                    "host": "fixture.local",
                                    "router": "gateway-router-with-long-name-"
                                    + "x" * 100,
                                    "state": "unusual",
                                    "reason": "Volume exceeded baseline",
                                    "current": 120,
                                    "baseline_median": 10,
                                    "robust_score": 11,
                                },
                                {
                                    "host": "new.local",
                                    "router": "new",
                                    "state": "warming_up",
                                    "reason": "Need 60 minutes of history",
                                    "current": 5,
                                    "baseline_median": None,
                                    "robust_score": None,
                                },
                            ],
                        }
                    else:
                        data = {
                            "scope": "Candidate correlation, not proof of causation.",
                            "asset_context": {
                                "asset": {
                                    "asset_id": "fixture-app",
                                    "revision": 3,
                                    "mapped_at": "2026-11-21T01:00:00Z",
                                    "payload": {
                                        "name": "Fixture mapped app <img src=x onerror=window.injected=1>",
                                        "kind": "application",
                                        "owner": "Fixture owner",
                                        "criticality": "high",
                                    },
                                },
                                "parent_host": {
                                    "asset_id": "fixture-host",
                                    "revision": 2,
                                    "mapped_at": "2026-11-21T01:00:00Z",
                                    "payload": {
                                        "name": "Fixture mapped host",
                                        "kind": "host",
                                        "owner": "Fixture host owner",
                                        "criticality": "critical",
                                    },
                                },
                                "match_reasons": [
                                    "exact observed host/router and longest literal path prefix"
                                ],
                                "warnings": [],
                                "scope": "Current operator-attested mapping, not event-time identity.",
                            },
                            "inspection": {
                                "decoded_target": "/../?q=<script>&token=[redacted]",
                                "scope": "Syntax only",
                                "signals": ["path traversal syntax", "script markup"],
                                "truncated": False,
                            },
                            "evidence_cves": ["CVE-2024-4577"],
                            "analysis_only_cves": ["CVE-2099-12345"],
                            "known_exploited": [
                                {
                                    "cve": "CVE-2024-4577",
                                    "title": "PHP fixture",
                                    "required_action": "Patch after verification",
                                }
                            ],
                            "items": [
                                {
                                    "id": 7,
                                    "reason": "Fixture <script>window.injected=1</script>",
                                    "created_at": "2026-11-21T01:00:00Z",
                                    "source": "suricata",
                                    "severity": "high",
                                    "match_reasons": [
                                        "endpoint IP appears in telemetry"
                                    ],
                                    "endpoint": "fixture",
                                    "attack_type": "Network alert",
                                    "mitre_id": "T1190",
                                }
                            ],
                            "decisions": [
                                {
                                    "id": 5,
                                    "action": "none",
                                    "status": "pending_approval",
                                    "policy_reason": "Requires evidence review",
                                    "policy_checks": [
                                        "protected range requires human approval"
                                    ],
                                }
                            ],
                            "decisions_truncated": False,
                            "has_more": False,
                        }
                else:
                    data = {}
                r.fulfill(json=data)

            page.route("**/*", route)
            page.goto("http://demo.test" + prefix + "/dashboard#intelligence")
            page.wait_for_function(
                "document.querySelector('#intelPage').textContent.includes('11 entries')"
            )
            page.evaluate("document.fonts.ready")
            assert page.locator("#dataView").is_hidden()
            assert (
                page.locator("#intelCatalog img").count() == 0
                and page.evaluate("window.injected") is None
            )
            assert "Warming up" in page.locator("#behaviorResults").inner_text()
            if width in (1440, 768, 390):
                page.screenshot(
                    path=str(OUT / f"intelligence-{width}.png"), full_page=True
                )
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (
                width
            )
            page.locator("#intelNext").click()
            page.wait_for_function(
                "document.querySelector('#intelPage').textContent.includes('2 / 2')"
            )
            page.locator("#intelSearch").fill("none")
            page.locator("#intelSearchForm button").click()
            page.wait_for_function(
                "document.querySelector('#intelPage').textContent.includes('0 entries')"
            )
            page.on(
                "dialog",
                lambda d: (
                    d.accept("browser-test-key") if d.type == "prompt" else d.accept()
                ),
            )
            page.locator("#intelSync").click()
            page.wait_for_function("!document.querySelector('#intelSync').disabled")
            assert state["sync"] == 1
            state["fail"] = True
            page.locator("#refreshDashboard").click()
            page.wait_for_function(
                "document.querySelector('#intelPage').textContent==='Unavailable'"
            )
            assert page.locator("#intelNext").is_disabled()
            assert page.locator("#behaviorResults").inner_text() == ""
            state["fail"] = False
            page.locator("#intelSearch").fill("")
            page.locator("#refreshDashboard").click()
            page.wait_for_selector(".intel-entry")
            page.locator("#tab-requests").click()
            page.locator(".record-open").first.click()
            page.wait_for_selector(".investigation-section button")
            page.locator(".investigation-section > button").click()
            page.wait_for_function(
                "document.querySelector('.investigation-results').textContent.includes('Candidate incident timeline')"
            )
            assert (
                page.locator(
                    ".investigation-results img,.investigation-results script"
                ).count()
                == 0
            )
            assert page.evaluate("window.injected") is None
            assert (
                "AI-only mentions (unverified)"
                in page.locator(".investigation-results").inner_text()
            )
            if width in (1440, 390):
                page.locator("#detailDialog").evaluate(
                    "d => { const e=d.querySelector('.investigation-results h4'); d.scrollTop += e.getBoundingClientRect().top-d.getBoundingClientRect().top-120; }"
                )
                page.screenshot(
                    path=str(OUT / f"investigation-{width}.png"), full_page=False
                )
                page.locator(".investigation-results details").last.evaluate(
                    "d => d.open=true"
                )
                page.locator("#detailDialog").evaluate(
                    "d => { const e=d.querySelector('.investigation-results details'); d.scrollTop += e.getBoundingClientRect().top-d.getBoundingClientRect().top-120; }"
                )
                page.screenshot(
                    path=str(OUT / f"investigation-policy-{width}.png"), full_page=False
                )
            assert not errors, errors
            page.keyboard.press("Escape")
            page.close()
        browser.close()
    print(
        "Intelligence UI PASS:4 widths/3 prefixes, catalog/search/paging, gated mock sync, baseline/warmup, timeline/decoded target/policy evidence, safe XSS, error/recovery"
    )


if __name__ == "__main__":
    run()
