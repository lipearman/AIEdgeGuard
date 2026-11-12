"""Playwright checks with mocked telemetry; never runs a real attack."""

import json
import mimetypes
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "edge-ai/api/app/static"
ARTIFACTS = ROOT / ".impeccable/review"


def run():
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel="chrome")
        for prefix, width in [
            ("", 1440),
            ("/AIEdgeGuard", 1392),
            ("/aiedge", 390),
            ("", 768),
            ("", 320),
        ]:
            page = browser.new_page(viewport={"width": width, "height": 1000})
            errors = []
            page.on("pageerror", lambda error, errors=errors: errors.append(str(error)))
            state = {
                "offline": False,
                "attack": False,
                "runs": 0,
                "fail_metrics": False,
            }

            def route(request, _request, *, prefix=prefix, state=state):
                path = request.request.url.split("edgeguard.test", 1)[-1].removeprefix(
                    prefix
                )
                if state["fail_metrics"] and any(
                    key in path
                    for key in [
                        "/visibility",
                        "/decisions",
                        "/packets",
                        "/learning/stats",
                    ]
                ):
                    request.fulfill(status=503, json={"detail": "Metrics unavailable"})
                    return
                if path.endswith("/mission"):
                    request.fulfill(
                        path=str(STATIC / "mission.html"), content_type="text/html"
                    )
                    return
                if path.startswith("/static/"):
                    file = STATIC / path.removeprefix("/static/").split("?", 1)[0]
                    request.fulfill(
                        path=str(file),
                        content_type=mimetypes.guess_type(file)[0]
                        or "application/octet-stream",
                    )
                    return
                if path == "/health":
                    data = {
                        "ollama": "ok",
                        "crowdsec": "ok",
                        "redis": "ok",
                        "postgres": "ok",
                    }
                elif path == "/api/v1/agents/status":
                    data = {
                        name: {"mode": mode}
                        for name, mode in [
                            ("analysis", "auto-ingestion"),
                            ("detection", "clustering every 60s"),
                            ("decision", "deterministic Policy Engine"),
                            ("learning", "pgvector · 768d"),
                            ("defense", "dry_run (human approval required)"),
                            ("attack", "lab" if state["attack"] else "off"),
                        ]
                    }
                elif path.startswith("/api/v1/incidents?"):
                    if state["offline"]:
                        request.fulfill(status=502, json={"detail": "DB offline"})
                        return
                    data = [
                        {
                            "alert_id": "test-1",
                            "source_ip": "10.1.2.3",
                            "created_at": "2026-11-12T06:00:00Z",
                            "attack_type": '<img src=x onerror="window.injected=true">',
                            "severity": "high",
                            "analyzed": True,
                        },
                        {
                            "alert_id": "test-2",
                            "created_at": "2026-11-12T05:40:00Z",
                            "attack_type": "SQL Injection Attempt",
                            "severity": "medium",
                            "analyzed": True,
                        },
                    ]
                elif path.startswith("/api/v1/incidents/test-"):
                    data = {
                        "source_ip": "10.1.2.3",
                        "created_at": "2026-11-12T06:00:00Z",
                        "kind": "waf",
                        "reason": "Controlled evidence",
                        "analysis": {
                            "attack_type": "Test incident",
                            "reasoning": "This is mocked evidence.",
                        },
                    }
                elif path.startswith("/api/v1/decisions"):
                    data = [{"status": "pending_approval"}, {"status": "executed"}]
                elif path.startswith("/api/v1/packets"):
                    data = {
                        "count": 80,
                        "blocked_403": 3,
                        "packets": [
                            {"status": 200, "ms": 20},
                            {"status": 403, "ms": 4},
                        ],
                    }
                elif path == "/api/v1/learning/stats":
                    data = {"embedded": 441, "analyzed": 441, "dim": 768}
                elif path == "/api/v1/visibility":
                    data = {
                        "layers": {
                            name: {
                                "state": "online",
                                "label": "ONLINE",
                                "detail": description,
                            }
                            for name, description in [
                                ("http_waf", "CrowdSec · HTTP gateway"),
                                ("network_ids", "Suricata · WSL eth0"),
                                ("host_edr", "Wazuh · Windows + Ubuntu"),
                            ]
                        }
                    }
                elif path == "/api/v1/attacks/run":
                    state["runs"] += 1
                    assert json.loads(request.request.post_data) == {
                        "target": "juicelab.lab.local"
                    }
                    data = {
                        "id": 7,
                        "techniques_detected": 4,
                        "techniques_total": 5,
                        "new_alerts": 4,
                    }
                else:
                    request.fulfill(status=404)
                    return
                request.fulfill(json=data)

            page.route("http://edgeguard.test/**", route)
            page.goto(f"http://edgeguard.test{prefix}/mission")
            page.wait_for_function(
                "document.querySelector('#refreshInfo').textContent.includes('อัปเดต')"
            )
            page.evaluate("document.fonts.ready")
            assert "auto-ingestion" in page.locator("#engine").inner_text()
            assert page.locator("#coverageCount").inner_text() == "3 / 3 layers"
            assert page.locator("#pendingCount").inner_text() == "1"
            assert page.locator("#attack").is_disabled()
            assert page.locator("#feed img").count() == 0
            assert page.evaluate("window.injected") is None
            assert (
                page.locator("#dashboardLink").get_attribute("href")
                == prefix + "/dashboard#requests"
            )
            assert page.evaluate(
                "document.documentElement.scrollWidth <= innerWidth"
            ), f"overflow at {width}"
            if width in [1440, 1392, 390]:
                filename = (
                    "desktop.png"
                    if width == 1440
                    else "mobile.png"
                    if width == 390
                    else "user-1392.png"
                )
                page.screenshot(path=str(ARTIFACTS / filename), full_page=True)
            page.locator("#severityFilter").select_option("medium")
            assert "SQL Injection Attempt" in page.locator("#vectors").inner_text()
            assert "<img" not in page.locator("#vectors").inner_text()
            page.locator(".feed-item").first.click()
            assert page.locator("#incidentDialog").is_visible()
            page.wait_for_function(
                "document.querySelector('#incidentDetail').textContent.includes('Controlled evidence')"
            )
            page.keyboard.press("Escape")
            state["offline"] = True
            page.locator("#refresh").click()
            page.wait_for_function(
                "document.querySelector('#refreshInfo').textContent.includes('DB offline')"
            )
            assert "อ่านเหตุการณ์ไม่ได้" in page.locator("#vectors").inner_text()
            assert "POSTGRES" in page.locator("#services").inner_text()
            assert page.locator("#chartLine").get_attribute("d") == ""
            assert (
                page.locator("#severityRing").evaluate(
                    "e=>getComputedStyle(e).backgroundImage"
                )
                == "none"
            )
            state["fail_metrics"] = True
            page.locator("#refresh").click()
            page.wait_for_function(
                "document.querySelector('#coverageCount').textContent.includes('—')"
            )
            assert "ONLINE" not in page.locator("#visibilityLayers").inner_text()
            for field in ["pendingCount", "requestCount", "embeddedCount"]:
                assert page.locator("#" + field).inner_text() == "—"
            state["fail_metrics"] = False
            state.update(offline=False, attack=True)
            page.locator("#refresh").click()
            page.wait_for_function("!document.querySelector('#attack').disabled")
            page.on("dialog", lambda dialog: dialog.accept())
            page.locator("#attack").click()
            page.wait_for_function(
                "document.querySelector('#attackResult').textContent.includes('4/5')"
            )
            assert state["runs"] == 1
            if not page.locator("#defenseCanvas").is_hidden():
                page.locator("#motionToggle").click()
                assert (
                    page.locator("#motionToggle").get_attribute("aria-pressed")
                    == "true"
                )
                before = page.locator("#defenseCanvas").get_attribute("data-frames")
                page.wait_for_timeout(150)
                assert before == page.locator("#defenseCanvas").get_attribute(
                    "data-frames"
                )
            assert not errors, errors
            page.close()
        page = browser.new_page(
            viewport={"width": 390, "height": 844}, reduced_motion="reduce"
        )
        page.route("http://edgeguard.test/**", route)
        page.goto("http://edgeguard.test/mission")
        page.wait_for_function(
            "document.querySelector('#refreshInfo').textContent.includes('อัปเดต')"
        )
        if not page.locator("#defenseCanvas").is_hidden():
            assert page.locator("#defenseCanvas").get_attribute("data-paused") == "false"
        browser.close()
    print(
        "Mission checks passed: five widths, 3 prefixes, 3 defense layers, filters, incident detail, XSS, partial API failure, recovery, lab controls, motion/reduced-motion"
    )


if __name__ == "__main__":
    run()
