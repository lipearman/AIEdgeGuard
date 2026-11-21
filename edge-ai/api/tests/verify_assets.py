"""Fully mocked inventory UI; no production asset writes or identity claims."""

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
                "items": [],
                "writes": [],
                "lose": True,
                "conflict": False,
                "fail": False,
            }

            def route(r):
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
                if path == "/api/v1/assets/observed":
                    data = {
                        "items": [
                            {
                                "agent_id": "001",
                                "name": "Fixture endpoint <img src=x onerror=window.injected=1>",
                                "ip": "10.20.30.40",
                                "last_seen": "2026-11-21T05:00:00Z",
                            }
                        ]
                    }
                elif path == "/api/v1/assets/hosts":
                    data = {
                        "items": [
                            {
                                "asset_id": row["asset_id"],
                                "name": row["payload"]["name"],
                                "status": row["payload"]["status"],
                            }
                            for row in state["items"]
                            if row["payload"]["kind"] == "host"
                        ]
                    }
                elif path == "/api/v1/assets":
                    if state["fail"]:
                        r.fulfill(
                            status=503, json={"detail": "Fixture database unavailable"}
                        )
                        return
                    items = state["items"] if not q.get("q") else []
                    data = {
                        "items": items,
                        "total": len(items),
                        "page": int(q.get("page", [1])[0]),
                        "pages": 2 if items else 1,
                    }
                elif path.startswith("/api/v1/assets/"):
                    identity = path.split("/")[-1]
                    if r.request.method == "POST":
                        body = r.request.post_data_json
                        state["writes"].append(copy.deepcopy(body))
                        assert (
                            r.request.headers["x-operation-key"]
                            == "fixture-operation-key"
                        )
                        if state["conflict"]:
                            r.fulfill(
                                status=409,
                                json={
                                    "detail": "Asset changed. Reload the latest revision; your draft can be retained."
                                },
                            )
                            return
                        prior = next(
                            (
                                row
                                for row in state["items"]
                                if row["asset_id"] == identity
                            ),
                            None,
                        )
                        same = prior and prior["request_id"] == body["request_id"]
                        row = (
                            prior
                            if same
                            else {
                                **body,
                                "asset_id": identity,
                                "revision": body["expected_revision"] + 1,
                                "created_at": "2026-11-21T05:00:00Z",
                                "authentication": "shared_operation_key",
                            }
                        )
                        if not same:
                            if prior:
                                state["items"].remove(prior)
                            state["items"].append(row)
                        if state["lose"]:
                            state["lose"] = False
                            r.abort("failed")
                            return
                        data = {"asset": row, "warnings": [], "replayed": bool(same)}
                    else:
                        row = next(
                            row for row in state["items"] if row["asset_id"] == identity
                        )
                        data = {
                            "current": row,
                            "items": [row],
                            "page": int(q.get("page", [1])[0]),
                            "pages": 2,
                            "total": 2,
                        }
                elif path == "/health":
                    data = {
                        k: "ok" for k in ("ollama", "crowdsec", "redis", "postgres")
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
                else:
                    data = {}
                r.fulfill(json=data)

            page.route("**/*", route)
            page.goto("http://demo.test" + prefix + "/dashboard#assets")
            page.wait_for_function(
                "document.querySelector('#assetListStatus').textContent.includes('0 registered')"
            )
            page.evaluate("document.fonts.ready")
            assert page.locator("#dataView").is_hidden()
            assert page.locator("#assetHistory").is_hidden()
            assert page.locator("#assetRouteFields").is_hidden()
            page.locator("#assetObserved").select_option("0")
            assert page.locator("#assetAgents").input_value() == "001"
            assert page.locator("#assetIps").input_value() == "10.20.30.40"
            page.locator("#assetOwner").fill("Fixture security team")
            page.locator("#assetCriticality").select_option("high")
            page.locator("#assetOs").fill("Fixture OS")
            page.locator("#assetOsVersion").fill("1.2")
            page.locator("#assetSoftware").fill(
                "Fixture vendor | Fixture product | 1.0 | cpe:2.3:a:fixture:product:*:*:*:*:*:*:*:* | numeric_dot"
            )
            page.locator("#assetDeclaredBy").fill("Fixture operator")
            page.locator("#assetRationale").fill(
                "Checked fixture endpoint configuration"
            )
            page.locator("#assetSave").click()
            page.wait_for_function(
                "document.querySelector('#assetEditStatus').textContent.includes('Draft retained')"
            )
            page.locator("#assetSave").click()
            page.wait_for_function(
                "document.querySelector('#assetEditStatus').textContent.includes('Saved revision 1')"
            )
            assert state["writes"][0]["request_id"] == state["writes"][1]["request_id"]
            assert state["writes"][0]["payload"]["software"][0]["version"] == "1.0"
            assert state["writes"][0]["payload"]["software"][0]["version_scheme"] == "numeric_dot"
            assert state["writes"][0]["payload"]["software"][0]["cpe23"].startswith("cpe:2.3:")
            assert len(state["items"]) == 1
            assert (
                page.locator("#assetList img").count() == 0
                and page.evaluate("window.injected") is None
            )
            page.locator("#assetName").fill("Fixture server")
            page.locator("#assetRationale").fill(
                "Fixture evidence changed after review"
            )
            state["conflict"] = True
            page.locator("#assetSave").click()
            page.wait_for_function(
                "document.querySelector('#assetEditStatus').textContent.includes('Draft retained. Reload')"
            )
            assert page.locator("#assetSave").is_disabled()
            assert page.locator("#assetName").input_value() == "Fixture server"
            state["conflict"] = False
            page.locator("#assetReload").click()
            page.wait_for_function(
                "document.querySelector('#assetEditStatus').textContent.includes('Reloaded revision 1')"
            )
            page.locator("#assetName").fill("Fixture server")
            page.locator("#assetRationale").fill("Updated fixture server display name")
            page.locator("#assetSave").click()
            page.wait_for_function(
                "document.querySelector('#assetEditStatus').textContent.includes('Saved revision 2')"
            )
            page.locator("#assetHistory").evaluate("e=>e.open=true")
            page.wait_for_selector("#assetHistoryItems details")
            page.locator("#assetHistoryNext").click()
            page.wait_for_function(
                "document.querySelector('#assetHistoryPage').textContent==='2 / 2'"
            )
            page.locator("#assetHistoryPrevious").click()
            page.locator("#assetNext").click()
            page.wait_for_function(
                "document.querySelector('#assetPage').textContent==='2 / 2'"
            )
            page.locator("#assetSearch").fill("absent")
            page.locator("#assetFilters button").click()
            page.wait_for_function(
                "document.querySelector('#assetListStatus').textContent.includes('0 registered')"
            )
            page.locator("#assetSearch").fill("")
            page.locator("#assetFilters button").click()
            page.wait_for_selector(".asset-entry")
            page.locator("#assetNew").click()
            page.locator("#assetKind").select_option("application")
            assert page.locator("#assetEndpointFields").is_hidden()
            assert page.locator("#assetRouteFields").is_visible()
            page.locator("#assetName").fill("Fixture application")
            page.locator("#assetParent").select_option(state["items"][0]["asset_id"])
            page.locator("#assetRoutes").fill("app.example.com | app@docker | /app")
            page.locator("#assetOwner").fill("Fixture app owner")
            page.locator("#assetDeclaredBy").fill("Fixture operator")
            page.locator("#assetRationale").fill(
                "Verified fixture gateway route binding"
            )
            page.locator("#assetSave").click()
            page.wait_for_function(
                "document.querySelector('#assetEditStatus').textContent.includes('Saved revision 1')"
            )
            assert (
                state["writes"][-1]["payload"]["parent_host_id"]
                == state["items"][0]["asset_id"]
            )
            assert state["writes"][-1]["payload"]["routes"][0]["path_prefix"] == "/app"
            page.locator("#assetOwner").fill("Unsaved owner draft")
            page.locator("#tab-requests").click()
            page.locator("#tab-assets").click()
            assert page.locator("#assetOwner").input_value() == "Unsaved owner draft"
            state["fail"] = True
            page.locator("#assetFilters button").click()
            page.wait_for_function(
                "document.querySelector('#assetListStatus').textContent.includes('Inventory unavailable')"
            )
            assert page.locator("#assetNext").is_disabled()
            state["fail"] = False
            page.locator("#assetFilters button").click()
            page.wait_for_selector(".asset-entry")
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (
                width
            )
            assert not errors, errors
            if width in (1440, 768, 390):
                page.evaluate("document.activeElement.blur(); window.scrollTo(0,0)")
                page.screenshot(path=str(OUT / f"assets-{width}.png"), full_page=True)
            page.close()
        browser.close()
    print(
        "Assets UI PASS: 4 widths/3 prefixes; observed-prefill, host/app bindings, paged registry/history, idempotent lost-response retry, CAS draft/reload, XSS, error/recovery, tab draft retention"
    )


if __name__ == "__main__":
    run()
