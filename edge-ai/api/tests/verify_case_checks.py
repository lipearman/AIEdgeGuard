"""Isolated drawer fixture for checker/review; every API write is intercepted."""

import mimetypes
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "edge-ai/api/app/static"
OUT = ROOT / ".impeccable/review"
CASE = "a1130e53-d727-4c7c-9431-0ce47d49bf6a"


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, channel="chrome")
        for width, prefix in [
            (1440, ""),
            (768, "/AIEdgeGuard"),
            (390, "/aiedge"),
            (320, ""),
        ]:
            page = browser.new_page(viewport={"width": width, "height": 1000})
            page.set_default_timeout(12000)
            errors = []
            page.on("pageerror", lambda e, errors=errors: errors.append(str(e)))
            page.on(
                "dialog",
                lambda d: d.accept("fixture-key") if d.type == "prompt" else d.accept(),
            )
            state = {
                "checks": [],
                "reviews": [],
                "check_ids": [],
                "review_ids": [],
                "lost_check": True,
                "lost_review": True,
                "conflict": False,
                "fail": False,
                "mode": "incomplete_or_changed",
                "many": False,
                "hold_report": None,
                "held": None,
                "fail_report": None,
            }

            def route(r, request=None, *, prefix=prefix, state=state):
                req = r.request
                url = urlparse(req.url)
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
                if not path.startswith(("/api/", "/health")):
                    r.abort()
                    return
                data = {}
                if path == "/health":
                    data = {
                        k: "ok" for k in ["ollama", "crowdsec", "redis", "postgres"]
                    }
                elif path.endswith("/visibility"):
                    data = {"layers": {}}
                elif path.endswith("/agents/status"):
                    data = {"defense": {"mode": "dry_run"}, "attack": {"mode": "off"}}
                elif path.endswith("/dashboard/summary"):
                    data = {"requests": 0, "incidents": 0, "campaigns": 0, "pending": 0}
                elif "/dashboard/data/" in path:
                    data = {
                        "items": [],
                        "total": 0,
                        "page": 1,
                        "pages": 1,
                        "snapshot": 0,
                    }
                elif path == "/api/v1/case-checks":
                    if state["fail"]:
                        r.fulfill(
                            status=503, json={"detail": "Fixture history unavailable"}
                        )
                        return
                    number = int(q.get("page", [1])[0])
                    items = [
                        {
                            "id": x["id"],
                            "state": x["report"]["state"],
                            "created_at": "2026-11-22T01:00:00Z",
                        }
                        for x in reversed(state["checks"])
                    ]
                    data = {
                        "items": items if number == 1 else items[:1],
                        "total": 11 if state["many"] else len(items),
                        "page": number,
                    }
                elif "/case-checks/reviews/" in path:
                    if req.method == "POST":
                        body = req.post_data_json
                        state["review_ids"].append(body["request_id"])
                        if state["conflict"]:
                            state["conflict"] = False
                            external = {
                                **body,
                                "id": 999,
                                "revision": len(state["reviews"]) + 1,
                                "reviewer_label": "Other fixture reviewer",
                                "rationale": "Concurrent fixture annotation",
                                "created_at": "2026-11-22T01:00:00Z",
                            }
                            state["reviews"].append(external)
                            r.fulfill(
                                status=409, json={"detail": "Case review changed"}
                            )
                            return
                        saved = next(
                            (
                                x
                                for x in state["reviews"]
                                if x["request_id"] == body["request_id"]
                            ),
                            None,
                        )
                        if not saved:
                            saved = {
                                **body,
                                "id": len(state["reviews"]) + 1,
                                "case_id": CASE,
                                "revision": len(state["reviews"]) + 1,
                                "created_at": "2026-11-22T01:00:00Z",
                                "authentication": "shared_operation_key",
                            }
                            state["reviews"].append(saved)
                        if state["lost_review"]:
                            state["lost_review"] = False
                            r.abort("failed")
                            return
                        data = saved
                    else:
                        number = int(q.get("page", [1])[0])
                        items = list(reversed(state["reviews"]))
                        data = {
                            "items": items if number == 1 else items[-1:],
                            "revision": len(items),
                            "total": 11 if state["many"] else len(items),
                            "page": number,
                            "independent_identity_verified": False,
                        }
                elif path.startswith("/api/v1/case-checks/"):
                    identity = path.split("/")[-1]
                    if req.method == "GET" and state["hold_report"] == identity:
                        state["held"] = r
                        return
                    if req.method == "GET" and state["fail_report"] == identity:
                        state["fail_report"] = None
                        r.fulfill(
                            status=503, json={"detail": "Fixture report load failed"}
                        )
                        return
                    if req.method == "PUT":
                        state["check_ids"].append(identity)
                        saved = next(
                            (x for x in state["checks"] if x["id"] == identity), None
                        )
                        if not saved:
                            report = {
                                "version": "fixture-v1",
                                "implementation_sha256": "fixture-only",
                                "case_id": CASE,
                                "case_hash_matches": True,
                                "case_content_hash": "fixture-case-hash",
                                "state": state["mode"],
                                "checked_at": "2026-11-22T01:00:00Z",
                                "independent_identity_verified": False,
                                "source_authenticity_verified": False,
                                "model_used": False,
                                "scope": "Fixture retained-evidence consistency only",
                                "nodes": [
                                    {
                                        "node": f"incidents:{i + 1}",
                                        "state": "unavailable"
                                        if i == 1
                                        and state["mode"]
                                        != "consistent_with_retained_evidence"
                                        else "consistent",
                                        "issues": [
                                            "Source record no longer retained <img src=x onerror=window.injected=1>"
                                        ]
                                        if i == 1
                                        and state["mode"]
                                        != "consistent_with_retained_evidence"
                                        else [],
                                    }
                                    for i in range(8)
                                ],
                                "edges": [
                                    {
                                        "index": 0,
                                        "from": "incidents:1",
                                        "to": "incidents:2",
                                        "type": "same_observed_source_ip",
                                        "state": "unverifiable"
                                        if state["mode"]
                                        != "consistent_with_retained_evidence"
                                        else "supported_association",
                                        "reason": "Shared NAT cannot establish a common actor",
                                    }
                                ],
                                "assets": [],
                            }
                            saved = {
                                "id": identity,
                                "case_id": CASE,
                                "content_hash": "fixture-check-hash",
                                "specification": req.post_data_json,
                                "report": report,
                            }
                            state["checks"].append(saved)
                        if state["lost_check"]:
                            state["lost_check"] = False
                            r.abort("failed")
                            return
                    data = next(x for x in state["checks"] if x["id"] == identity)
                r.fulfill(json=data)

            page.route("**/*", route)

            def mount(page=page, prefix=prefix):
                page.goto("http://demo.test" + prefix + "/dashboard#requests")
                page.evaluate(
                    "id=>{const d=document.querySelector('#detailDialog');document.querySelector('#detailTitle').textContent='Case evidence review';const body=document.querySelector('#detailBody');body.replaceChildren();const s=document.createElement('section');s.className='case-section';body.append(s);window.EdgeCaseChecks.attach(s,{id,content_hash:'fixture-case-hash'});d.showModal();}",
                    CASE,
                )
                page.locator(".case-checks").evaluate("e=>e.open=true")

            def scroll_to(selector, page=page):
                page.locator("#detailDialog").evaluate(
                    "(d,s)=>{const e=d.querySelector(s);d.scrollTop+=e.getBoundingClientRect().top-d.getBoundingClientRect().top-120}",
                    selector,
                )

            mount()
            page.wait_for_function(
                "document.querySelector('.check-list-status').textContent.includes('No saved')"
            )
            assert page.locator(".check-review-save").is_disabled()
            page.locator(".check-create summary").click()
            page.locator(".check-form input").fill("Fixture checker")
            page.locator(".check-form textarea").fill(
                "Compare the retained fixture evidence"
            )
            page.locator(".check-save").click()
            page.wait_for_function(
                "document.querySelector('.check-save-status').textContent.includes('retry')"
            )
            assert page.locator(".check-form input").is_disabled()
            mount()
            page.wait_for_function(
                "document.querySelector('.check-save-status').textContent.includes('restored')"
            )
            page.locator(".check-save").click()
            page.wait_for_function(
                "document.querySelector('.check-result').textContent.includes('incomplete_or_changed')"
            )
            assert len(set(state["check_ids"])) == 1
            assert "unavailable" in page.locator(".check-findings").inner_text()
            assert not page.locator(".case-checks img,.case-checks script").count()
            page.locator(".finding-pager button").last.click()
            assert "unverifiable" in page.locator(".check-findings").inner_text()
            page.locator(".finding-pager button").first.click()
            with page.expect_download() as download:
                page.get_by_role("button", name="Export check JSON").click()
            assert download.value.suggested_filename.startswith("edgeguard-case-check-")
            # Existing report remains incomplete even after a newer check sees consistent facts.
            state["mode"] = "consistent_with_retained_evidence"
            page.locator(".check-save").click()
            page.wait_for_function(
                "document.querySelector('.check-state').textContent==='consistent_with_retained_evidence'"
            )
            original = state["checks"][0]
            newer = state["checks"][1]
            state["hold_report"] = original["id"]
            page.locator(".check-reports").select_option(original["id"])
            page.wait_for_function(
                "document.querySelector('.check-review-save').disabled"
            )
            assert page.locator(".check-reports").input_value() == newer["id"]
            assert (
                page.locator(".check-state").inner_text()
                == "consistent_with_retained_evidence"
            )
            page.wait_for_timeout(50)
            assert state["held"] is not None
            scroll_to(".check-reports")
            if width in [1440, 390]:
                page.screenshot(path=str(OUT / f"case-check-loading-{width}.png"))
            state["hold_report"] = None
            state["held"].fulfill(json=original)
            page.wait_for_function(
                "document.querySelector('.check-state').textContent==='incomplete_or_changed'"
            )
            assert page.locator(".check-reports").input_value() == original["id"]
            state["fail_report"] = newer["id"]
            page.locator(".check-reports").select_option(newer["id"])
            page.wait_for_function(
                "document.querySelector('.check-save-status').textContent.includes('load failed')"
            )
            assert page.locator(".check-reports").input_value() == original["id"]
            assert page.locator(".check-state").inner_text() == "incomplete_or_changed"
            page.locator(".check-review-form textarea").fill(
                "Keep this draft on the original check"
            )
            page.locator(".check-reports").select_option(newer["id"])
            page.wait_for_function(
                "document.querySelector('.check-review-status').textContent.includes('Save or Clear draft')"
            )
            assert page.locator(".check-reports").input_value() == original["id"]
            assert (
                page.locator(".check-review-form textarea").input_value()
                == "Keep this draft on the original check"
            )
            page.locator(".check-review-clear").click()
            page.locator(".check-review-form input").fill("Fixture reviewer")
            page.locator(".check-review-form textarea").fill(
                "Retained sources are incomplete; investigate further"
            )
            page.locator(".check-review-save").click()
            page.wait_for_function(
                "document.querySelector('.check-review-save').textContent.includes('Retry')"
            )
            mount()
            page.wait_for_function(
                "document.querySelector('.check-review-status').textContent.includes('restored')"
            )
            page.locator(".check-review-save").click()
            page.wait_for_function(
                "document.querySelector('.check-review-status').textContent.includes('Review saved')"
            )
            assert len(set(state["review_ids"])) == 1
            state["conflict"] = True
            page.locator(".check-review-form textarea").fill(
                "Keep this draft through a concurrent revision"
            )
            page.locator(".check-review-save").click()
            page.wait_for_function(
                "document.querySelector('.check-review-status').textContent.includes('Reload latest')"
            )
            assert page.locator(".check-review-save").is_disabled()
            page.locator(".check-review-reload").click()
            page.wait_for_function(
                "document.querySelector('.check-review-status').textContent.includes('Latest revision loaded')"
            )
            assert (
                page.locator(".check-review-form textarea").input_value()
                == "Keep this draft through a concurrent revision"
            )
            page.locator(".check-review-clear").click()
            state["many"] = True
            page.get_by_role("button", name="Reload checks", exact=True).click()
            page.wait_for_function("!document.querySelector('.check-next').disabled")
            page.locator(".check-next").click()
            page.wait_for_function(
                "document.querySelector('.check-pager span').textContent.includes('2 / 2')"
            )
            page.locator(".check-prev").click()
            page.locator(".review-pager").locator("xpath=..").evaluate("e=>e.open=true")
            page.locator(".check-review-reload").click()
            page.wait_for_function("!document.querySelector('.review-next').disabled")
            page.locator(".review-next").click()
            page.wait_for_function(
                "document.querySelector('.review-pager span').textContent.includes('2 / 2')"
            )
            page.locator(".review-prev").click()
            state["fail"] = True
            page.get_by_role("button", name="Reload checks", exact=True).click()
            page.wait_for_function(
                "document.querySelector('.check-list-status').textContent.includes('unavailable')"
            )
            state["fail"] = False
            page.get_by_role("button", name="Reload checks", exact=True).click()
            page.wait_for_function(
                "document.querySelector('.check-list-status').textContent.includes('Reports describe')"
            )
            page.locator(".check-review-form input").focus()
            page.keyboard.press("Tab")
            assert page.locator(".check-review-form textarea").evaluate(
                "e=>e===document.activeElement"
            )
            page.evaluate("document.fonts.ready")
            page.evaluate("document.activeElement.blur()")
            scroll_to(".check-result")
            if width in [1440, 768, 390]:
                page.screenshot(path=str(OUT / f"case-checks-{width}.png"))
            scroll_to(".case-check-review")
            if width in [1440, 390]:
                page.screenshot(path=str(OUT / f"case-check-review-{width}.png"))
            assert page.locator("#detailDialog").evaluate(
                "d=>d.scrollWidth<=d.clientWidth"
            )
            assert not page.evaluate("window.injected||false")
            assert not errors, errors
            page.close()
        browser.close()
    print(
        "Case checker UI PASS:4 widths/3 prefixes; source missing vs consistent, immutable reports, atomic check selection on blocked/failed/delayed load, disabled review during load, check/review retry UUID across reload, CAS/draft, paging/export/keyboard/XSS/error recovery/no overflow"
    )


if __name__ == "__main__":
    run()
