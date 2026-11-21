"""Synthetic review UX; exercises retry/CAS/draft safety without real labels or actions."""

import mimetypes
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "edge-ai/api/app/static"
OUT = ROOT / ".impeccable/review"


def run():
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
            page.on("pageerror", lambda e, errors=errors: errors.append(str(e)))
            state = {
                "reviews": [],
                "requests": [],
                "lose": True,
                "conflict": False,
                "fail": False,
            }
            row = {
                "id": 1,
                "alert_id": "wazuh-fixture",
                "source": "wazuh",
                "source_ip": "",
                "endpoint": "fixture-host",
                "created_at": "2026-11-21T05:00:00Z",
                "reason": "Fixture authentication evidence",
                "severity": "medium",
                "analyzed": True,
                "event": {"event": {"agent": {"name": "fixture-host"}}},
                "analysis": {
                    "attack_type": "Original AI classification",
                    "reasoning": "Original AI reasoning preserved",
                    "reviewed_memory_sources": [
                        {
                            "alert_id": "earlier-fixture",
                            "review_id": 7,
                            "review_revision": 2,
                        }
                    ],
                },
            }

            def route(r, _request, *, prefix=prefix, state=state, row=row):
                u = urlparse(r.request.url)
                path = u.path.removeprefix(prefix)
                query = parse_qs(u.query)
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
                elif path.startswith("/api/v1/reviews"):
                    if state["fail"]:
                        r.fulfill(status=503, json={"detail": "Review DB unavailable"})
                        return
                    current = state["reviews"][-1] if state["reviews"] else None
                    if path.endswith("/stats"):
                        verdict = current["verdict"] if current else None
                        data = {
                            "incidents": 1,
                            "reviewed": int(bool(current)),
                            "true_positive": int(verdict == "true_positive"),
                            "false_positive": int(verdict == "false_positive"),
                            "unknown": int(verdict == "unknown"),
                            "eligible": int(verdict == "true_positive"),
                            "memory_ready": 0,
                            "unreviewed": int(not current),
                            "identity_scope": "Reviewer labels self-declared.",
                        }
                    elif r.request.method == "POST":
                        assert (
                            r.request.headers.get("x-operation-key")
                            == "browser-test-key"
                        )
                        body = r.request.post_data_json
                        state["requests"].append(body)
                        old = next(
                            (
                                x
                                for x in state["reviews"]
                                if x["request_id"] == body["request_id"]
                            ),
                            None,
                        )
                        if old:
                            r.fulfill(json={"review": old, "replayed": True})
                            return
                        if state["conflict"]:
                            state["conflict"] = False
                            state["reviews"].append(
                                {
                                    **current,
                                    "id": 2,
                                    "revision": 2,
                                    "request_id": "another-request",
                                    "verdict": "unknown",
                                    "reviewer_label": "Other analyst",
                                    "rationale": "Concurrent review by another operator",
                                }
                            )
                            r.fulfill(
                                status=409,
                                json={
                                    "detail": "Review changed. Reload latest revision."
                                },
                            )
                            return
                        assert body["expected_revision"] == len(state["reviews"])
                        record = {
                            **body,
                            "id": len(state["reviews"]) + 1,
                            "revision": len(state["reviews"]) + 1,
                            "created_at": "2026-11-21T05:00:00Z",
                            "authentication": "shared_operation_key",
                        }
                        state["reviews"].append(record)
                        if state["lose"]:
                            state["lose"] = False
                            r.abort()
                            return
                        r.fulfill(json={"review": record, "replayed": False})
                        return
                    else:
                        page_number = int(query.get("page", ["1"])[0])
                        history = list(reversed(state["reviews"]))
                        data = {
                            "current": current,
                            "revision": len(history),
                            "items": history[(page_number - 1) * 10 : page_number * 10],
                            "page": page_number,
                            "pages": max(1, (len(history) + 9) // 10),
                            "total": len(history),
                            "memory": {
                                "state": "pending_embedding"
                                if current and current["verdict"] == "true_positive"
                                else "excluded",
                                "ready": False,
                                "eligible": bool(
                                    current and current["verdict"] == "true_positive"
                                ),
                            },
                        }
                else:
                    data = {}
                r.fulfill(json=data)

            page.route("**/*", route)
            page.on(
                "dialog",
                lambda d: (
                    d.accept("browser-test-key") if d.type == "prompt" else d.accept()
                ),
            )
            page.goto("http://demo.test" + prefix + "/dashboard#incidents")
            page.locator(".record-open").first.click()
            page.wait_for_function(
                "document.querySelector('.review-status')?.textContent.includes('Unreviewed')"
            )
            page.evaluate("document.fonts.ready")
            section = page.locator(".review-section")
            section.locator("[name=reviewer_label]").fill("Test analyst")
            section.locator("[name=verdict]").select_option("true_positive")
            section.locator("[name=corrected_attack_type]").fill(
                "Reviewed host authentication alert"
            )
            section.locator("[name=corrected_severity]").select_option("low")
            section.locator("[name=rationale]").fill(
                "Verified fixture only <img src=x onerror=window.injected=1>"
            )
            section.locator("button[type=submit]").click()
            page.wait_for_function(
                "document.querySelector('.review-status').textContent.includes('not confirmed')"
            )
            first_id = state["requests"][-1]["request_id"]
            section.locator("button[type=submit]").click()
            page.wait_for_function(
                "document.querySelector('.review-status').textContent.includes('Saved revision 1')"
            )
            assert (
                len(state["reviews"]) == 1
                and state["requests"][-1]["request_id"] == first_id
            )
            assert "retry confirmed" in section.locator(".review-status").inner_text()
            assert section.locator("[name=rationale]").input_value() == ""
            assert (
                "Original AI reasoning preserved"
                in page.locator("#detailBody").inner_text()
            )
            section.locator(".review-history summary").click()
            assert (
                section.locator("img,script").count() == 0
                and page.evaluate("window.injected") is None
            )
            assert (
                section.locator(".review-sources a")
                .get_attribute("href")
                .endswith("/history/7")
            )
            if width in (1440, 768, 390):
                page.locator("#detailDialog").evaluate(
                    "d=>{const e=d.querySelector('.review-section');d.scrollTop+=e.getBoundingClientRect().top-d.getBoundingClientRect().top-110;}"
                )
                page.screenshot(path=str(OUT / f"reviews-{width}.png"), full_page=False)
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (
                width
            )
            state["conflict"] = True
            section.locator("[name=verdict]").select_option("false_positive")
            section.locator("[name=rationale]").fill(
                "Corrected fixture after checking the evidence"
            )
            section.locator("button[type=submit]").click()
            page.wait_for_function(
                "document.querySelector('.review-status').textContent.includes('draft is retained')"
            )
            assert section.locator("button[type=submit]").is_disabled()
            section.get_by_role("button", name="Reload latest", exact=True).click()
            page.wait_for_function(
                "document.querySelector('.review-status').textContent.includes('revision 2')"
            )
            assert section.locator("[name=verdict]").input_value() == "false_positive"
            assert (
                "Corrected fixture" in section.locator("[name=rationale]").input_value()
            )
            section.locator("button[type=submit]").click()
            page.wait_for_function(
                "document.querySelector('.review-status').textContent.includes('Saved revision 3')"
            )
            assert state["requests"][-1]["expected_revision"] == 2
            assert "memory excluded" in section.locator(".review-status").inner_text()
            if width in (1440, 390):
                page.locator("#detailDialog").evaluate(
                    "d=>{const e=d.querySelector('.review-history');d.scrollTop+=e.getBoundingClientRect().top-d.getBoundingClientRect().top-110;}"
                )
                page.screenshot(
                    path=str(OUT / f"reviews-history-{width}.png"), full_page=False
                )
            state["fail"] = True
            section.get_by_role("button", name="Reload latest", exact=True).click()
            page.wait_for_function(
                "document.querySelector('.review-status').textContent.includes('unavailable')"
            )
            assert section.locator("button[type=submit]").is_disabled()
            state["fail"] = False
            section.get_by_role("button", name="Reload latest", exact=True).click()
            page.wait_for_function(
                "document.querySelector('.review-status').textContent.includes('revision 3')"
            )
            assert not section.locator("button[type=submit]").is_disabled()
            assert not errors, errors
            page.keyboard.press("Escape")
            page.close()
        browser.close()
    print(
        "Review UI PASS:4 widths/3 prefixes, lost-response retry ID, CAS conflict/draft/reload, TP→FP memory exclusion, history/XSS, provenance, API failure/recovery; all writes mocked"
    )


if __name__ == "__main__":
    run()
