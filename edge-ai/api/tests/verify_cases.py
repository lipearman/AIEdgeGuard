"""Fully intercepted case-graph UI fixtures; no live writes or sensor actions."""

import copy
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
            row = {
                "id": 1,
                "observed_at": "2026-11-21T01:00:00Z",
                "collected_at": "2026-11-21T01:00:01Z",
                "source_ip": "8.8.8.8",
                "method": "GET",
                "path": "/fixture",
                "host": "fixture.test",
                "router": "fixture@file",
                "status": 200,
                "duration_ns": 1000,
                "raw": {},
                "capture": {"headers": {}},
            }
            anchor = {
                "id": "requests:1",
                "kind": "requests",
                "record_id": 1,
                "source": "http_gateway",
                "title": "GET fixture.test",
                "observed_at": "2026-11-21T01:00:00Z",
                "ingested_at": "2026-11-21T01:00:01Z",
                "effective_at": "2026-11-21T01:00:00Z",
                "time_basis": "source_reported",
                "time_field": "StartUTC",
                "time_state": "source_reported",
                "arrival_delay_seconds": 1,
                "late_arrival": False,
                "clock_warning": False,
                "source_evidence_sha256": "fixture-sha",
            }
            nodes = [anchor]
            edges = []
            for i in range(10):
                node = {
                    **anchor,
                    "id": f"incidents:{i + 1}",
                    "kind": "incidents",
                    "record_id": i + 1,
                    "source": "wazuh",
                    "title": "Fixture sensor <img src=x onerror=window.injected=1>"
                    if i == 0
                    else f"Fixture event {i + 1}",
                    "observed_at": "2026-11-21T01:01:00Z" if i else None,
                    "ingested_at": "2026-11-21T03:00:00Z",
                    "effective_at": "2026-11-21T01:01:00Z",
                    "time_basis": "source_reported" if i else "ingestion_fallback",
                    "time_state": "source_reported" if i else "timezone_missing",
                    "time_field": "timestamp",
                    "arrival_delay_seconds": 7140 if i else None,
                    "late_arrival": bool(i),
                }
                nodes.append(node)
                edges.append(
                    {
                        "from": "requests:1",
                        "to": node["id"],
                        "type": "same_observed_source_ip",
                        "confidence": "low",
                        "meaning": "association_only",
                        "direction": "undirected",
                        "reason": "Shared NAT/proxy IP does not establish a common actor",
                    }
                )
            graph = {
                "anchor": "requests:1",
                "nodes": nodes,
                "edges": edges,
                "window": {
                    "start": "2026-11-21T00:45:00Z",
                    "end": "2026-11-21T01:15:00Z",
                },
                "event_nodes_truncated": False,
                "decisions_truncated": False,
                "version": "fixture-v1",
                "scope": "Synthetic association fixture, not confirmed attack chain",
                "limits": {"event_nodes": 80, "decisions": 20, "expansion_hops": 1},
                "source_high_water": {"incidents": 10, "requests": 1},
                "late_arrival_policy": "Fixed membership; late records require a new snapshot",
                "asset_context": {
                    "scope": "Current declarations, not event-time identity"
                },
            }
            state = {
                "records": {},
                "ids": [],
                "lost": True,
                "fail": False,
                "empty": False,
                "many": False,
            }

            def handler(
                route, request=None, *, prefix=prefix, row=row, state=state, graph=graph
            ):
                req = route.request
                u = urlparse(req.url)
                path = u.path.removeprefix(prefix)
                q = parse_qs(u.query)
                if path == "/dashboard":
                    route.fulfill(
                        path=str(STATIC / "dashboard.html"), content_type="text/html"
                    )
                    return
                if path.startswith("/static/"):
                    f = STATIC / path.removeprefix("/static/")
                    route.fulfill(
                        path=str(f),
                        content_type=mimetypes.guess_type(str(f))[0]
                        or "application/octet-stream",
                    )
                    return
                if not path.startswith(("/api/", "/health")):
                    route.abort()
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
                    data = {"requests": 1, "incidents": 0, "pending": 0, "campaigns": 0}
                elif path.endswith("/dashboard/data/requests/1"):
                    data = row
                elif "/dashboard/data/" in path:
                    data = {
                        "items": [row],
                        "page": 1,
                        "pages": 1,
                        "total": 1,
                        "snapshot": 1,
                    }
                elif path == "/api/v1/cases":
                    if state["fail"]:
                        route.fulfill(
                            status=503,
                            json={"detail": "Fixture case history unavailable"},
                        )
                        return
                    items = [
                        {"id": r["id"], "created_at": "2026-11-21T04:00:00Z"}
                        for r in state["records"].values()
                    ]
                    number = int(q.get("page", [1])[0])
                    data = {
                        "items": items if number == 1 else items[:1],
                        "page": number,
                        "total": 11 if state["many"] else len(items),
                    }
                elif path.startswith("/api/v1/cases/"):
                    identity = path.split("/")[-1]
                    if req.method == "PUT":
                        state["ids"].append(identity)
                        if identity not in state["records"]:
                            g = copy.deepcopy(graph)
                            if state["empty"]:
                                g["nodes"] = g["nodes"][:1]
                                g["edges"] = []
                            state["records"][identity] = {
                                "id": identity,
                                "created_at": "2026-11-21T04:00:00Z",
                                "content_hash": "fixture-case-hash",
                                "specification": req.post_data_json,
                                "graph": g,
                            }
                        if state["lost"]:
                            state["lost"] = False
                            route.abort("failed")
                            return
                    data = state["records"][identity]
                route.fulfill(json=data)

            page.route("**/*", handler)

            def open_drawer(page=page):
                page.locator(".record-open").first.click()
                page.wait_for_selector(".case-section")

            def scroll_to(selector, page=page):
                page.locator("#detailDialog").evaluate(
                    "(d,s)=>{const e=d.querySelector(s);d.scrollTop+=e.getBoundingClientRect().top-d.getBoundingClientRect().top-120}",
                    selector,
                )

            page.goto("http://demo.test" + prefix + "/dashboard#requests")
            open_drawer()
            page.wait_for_function(
                "document.querySelector('.case-saved').textContent.includes('ยังไม่มี')"
            )
            page.locator(".case-create summary").click()
            page.locator('.case-form input[name="author"]').fill("Fixture operator")
            page.locator(".case-form textarea").fill(
                "Authorized fixture investigation only"
            )
            page.locator(".case-save").click()
            page.wait_for_function(
                "document.querySelector('.case-status').textContent.includes('retry same')"
            )
            assert page.locator(".case-form input").is_disabled()
            page.reload()
            open_drawer()
            page.wait_for_function(
                "document.querySelector('.case-status').textContent.includes('restored')"
            )
            page.locator(".case-save").click()
            page.wait_for_selector(".case-chart")
            assert page.locator(".case-chart").evaluate(
                "e=>e.getBoundingClientRect().height>150"
            )
            assert len(set(state["ids"])) == 1
            assert (
                "same_observed_source_ip"
                in page.locator(".case-node-evidence").inner_text()
            )
            page.locator(".case-node-next").click()
            assert ("incidents:5" if width <= 600 else "incidents:9") in page.locator(
                ".case-node-list"
            ).inner_text()
            page.locator(".case-node-prev").click()
            assert page.locator(".case-node-prev").is_disabled()
            page.locator(".case-node-list button").nth(1).click()
            assert (
                "ingestion_fallback" in page.locator(".case-node-evidence").inner_text()
            )
            assert not page.locator(".case-section img,.case-section script").count()
            page.locator(".case-node-list button").nth(2).click()
            assert ">5 min" in page.locator(".case-node-evidence").inner_text()
            page.locator(".case-node-list button").nth(2).focus()
            page.keyboard.press("Enter")
            with page.expect_download() as download:
                page.get_by_role("button", name="Export case JSON").click()
            assert download.value.suggested_filename.startswith("edgeguard-case-")
            state["many"] = True
            page.locator(".case-load").click()
            page.wait_for_function("!document.querySelector('.case-next').disabled")
            page.locator(".case-next").click()
            page.wait_for_function(
                "document.querySelector('.case-history-pager span').textContent.includes('2 / 2')"
            )
            page.locator(".case-previous").click()
            state["fail"] = True
            page.locator(".case-load").click()
            page.wait_for_function(
                "document.querySelector('.case-status').textContent.includes('unavailable')"
            )
            state["fail"] = False
            page.locator(".case-load").click()
            page.wait_for_selector(".case-saved button")
            # Captures are the visible drawer viewport, positioned at the named section.
            page.evaluate("document.fonts.ready")
            page.evaluate("document.activeElement.blur()")
            scroll_to(".case-result")
            if width in [1440, 768, 390]:
                page.screenshot(path=str(OUT / f"cases-{width}.png"))
            scroll_to(".case-node-evidence")
            if width in [1440, 390]:
                page.screenshot(path=str(OUT / f"case-node-{width}.png"))
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth")
            assert page.locator("#detailDialog").evaluate(
                "d=>d.scrollWidth<=d.clientWidth"
            )
            assert not page.evaluate("window.injected||false")
            state["empty"] = True
            page.locator(".case-save").click()
            page.wait_for_function(
                "document.querySelector('.case-result').textContent.includes('No linked candidates')"
            )
            assert not errors, errors
            page.close()
        browser.close()
    print(
        "Case UI PASS:4 widths/3 prefixes, immutable snapshot retry across reload, one-hop SVG + accessible node facts, unknown/late times, graph/history paging, JSON export, empty/error recovery, XSS and no overflow"
    )


if __name__ == "__main__":
    run()
