"""Synthetic FIRST lookup UX; all writes and external scores mocked."""

import mimetypes
from pathlib import Path
from urllib.parse import urlparse

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
            errors = []
            state = {"mode": "empty", "posts": 0, "gets": 0, "prompts": 0}
            page.on("pageerror", lambda e: errors.append(str(e)))

            def dialog(d):
                if d.type == "prompt":
                    state["prompts"] += 1
                    d.accept("fixture-operation-key")
                else:
                    d.accept()

            page.on("dialog", dialog)

            def route(r):
                path = urlparse(r.request.url).path.removeprefix(prefix)
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
                if "/intelligence/epss/" in path:
                    if r.request.method == "POST":
                        state["posts"] += 1
                        assert (
                            r.request.headers["x-operation-key"]
                            == "fixture-operation-key"
                        )
                        if state["mode"] in ("forbidden", "limited"):
                            r.fulfill(
                                status=403 if state["mode"] == "forbidden" else 429,
                                json={
                                    "detail": "invalid or missing operation key"
                                    if state["mode"] == "forbidden"
                                    else "EPSS fetch budget: wait 30 seconds between external lookups"
                                },
                            )
                            return
                    else:
                        state["gets"] += 1
                    data = {
                        "cve": "CVE-2024-4577",
                        "state": "never_fetched",
                        "score": None,
                        "last_success": None,
                        "last_attempt": None,
                        "error": "",
                        "scope": "FIRST EPSS is probability, not severity, asset applicability or proof of exploitation.",
                    }
                    if state["mode"] != "empty":
                        data.update(
                            state="current",
                            last_success="2026-11-21T06:00:00Z",
                            last_attempt="2026-11-21T06:00:00Z",
                            score={
                                "snapshot_id": 7,
                                "score_date": "2026-11-21",
                                "epss": 0.81,
                                "percentile": 0.99,
                                "state": "current",
                                "fetched_at": "2026-11-21T06:00:00Z",
                                "api_version": "1.0 <img src=x onerror=window.injected=1>",
                            },
                        )
                    if state["mode"] == "failed":
                        data.update(
                            state="refresh_failed",
                            error="FIRST unavailable; last stored score retained",
                        )
                        data["score"]["state"] = "stale"
                    if state["mode"] == "missing":
                        data.update(state="not_scored", score=None)
                    if r.request.method == "POST":
                        data = {
                            "action": "failed"
                            if state["mode"] == "failed"
                            else "cache_hit"
                            if state["posts"] > 1
                            else "fetched",
                            "result": data,
                        }
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
                        "incidents": 0,
                        "analyzed": 0,
                        "pending": 0,
                        "campaigns": 0,
                    }
                elif "/dashboard/data/" in path:
                    data = {
                        "items": [],
                        "total": 0,
                        "page": 1,
                        "pages": 1,
                        "snapshot": 0,
                    }
                elif path.endswith("/intelligence/status"):
                    data = {
                        "state": "current",
                        "record_count": 1,
                        "last_success": "2026-11-21T06:00:00Z",
                        "automatic": True,
                    }
                elif path.endswith("/intelligence/vulnerabilities"):
                    data = {
                        "items": [
                            {
                                "cve": "CVE-2024-4577",
                                "title": "Synthetic KEV fixture",
                                "vendor": "Fixture",
                                "product": "Fixture",
                                "description": "Mock only",
                                "required_action": "Verify first",
                                "date_added": "2026-11-20",
                                "due_date": "2026-12-01",
                                "ransomware": "Unknown",
                            }
                        ],
                        "total": 1,
                        "page": 1,
                        "pages": 1,
                    }
                elif path.endswith("/investigation/behavior"):
                    data = {
                        "state": "warming_up",
                        "items": [],
                        "method": "Fixture",
                        "scope": "Insufficient evidence",
                    }
                elif path.endswith("/reviews/stats"):
                    data = {
                        "memory_ready": 0,
                        "eligible": 0,
                        "unreviewed": 0,
                        "true_positive": 0,
                        "false_positive": 0,
                        "unknown": 0,
                        "identity_scope": "Self-declared labels",
                    }
                else:
                    data = {}
                r.fulfill(json=data)

            page.route("**/*", route)
            page.goto("http://demo.test" + prefix + "/dashboard#intelligence")
            page.wait_for_selector(".intel-entry")
            assert state["gets"] == state["posts"] == 0
            page.locator('button[aria-label^="View EPSS for"]').click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('never_fetched')"
            )
            assert "No cached lookup" in page.locator("#epssResult").inner_text()
            assert state["posts"] == 0
            page.locator("#epssCve").fill("invalid")
            page.locator("#epssView").click()
            assert "complete CVE" in page.locator("#epssStatus").inner_text()
            state["mode"] = "current"
            page.locator("#epssCve").fill("cve-2024-4577")
            page.locator("#epssFetch").click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('fetched')"
            )
            assert page.locator("#epssCve").input_value() == "CVE-2024-4577"
            assert "81%" in page.locator("#epssResult").inner_text()
            assert "99%" in page.locator("#epssResult").inner_text()
            assert (
                page.locator("#epssResult img").count() == 0
                and page.evaluate("window.injected") is None
            )
            assert (
                page.locator("#epssResult a").first.get_attribute("href")
                == prefix + "/api/v1/intelligence/epss/snapshots/7"
            )
            page.locator("#epssFetch").click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('cache_hit')"
            )
            state["mode"] = "limited"
            page.locator("#epssFetch").click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('30 seconds')"
            )
            assert page.locator("#epssFetch").is_enabled()
            state["mode"] = "forbidden"
            page.locator("#epssFetch").click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('operation key')"
            )
            assert page.evaluate("sessionStorage.getItem('opkey')") is None
            state["mode"] = "failed"
            page.locator("#epssFetch").click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('refresh_failed')"
            )
            assert state["prompts"] == 2
            assert "Retained earlier score" in page.locator("#epssResult").inner_text()
            state["mode"] = "missing"
            page.locator("#epssView").click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('not_scored')"
            )
            assert (
                "Missing EPSS does not mean zero"
                in page.locator("#epssResult").inner_text()
            )
            state["mode"] = "current"
            page.locator("#epssView").click()
            page.wait_for_function(
                "document.querySelector('#epssStatus').textContent.includes('current')"
            )
            page.evaluate("document.fonts.ready")
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (
                width
            )
            assert not errors, errors
            if width in (1440, 768, 390):
                page.evaluate("document.activeElement.blur();window.scrollTo(0,0)")
                page.screenshot(path=str(OUT / f"epss-{width}.png"), full_page=True)
            page.close()
        browser.close()
    print(
        "EPSS UI PASS:4 widths/3 prefixes; cached-only GET, catalog selection, gated fetch/cache, 403 re-prompt, 429 recovery, retained stale score, missing-score semantics, source snapshot, hostile-text safety"
    )


if __name__ == "__main__":
    run()
