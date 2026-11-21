"""Synthetic browser workflow only; all API requests are intercepted locally."""

import copy
import json
import mimetypes
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
STATIC = ROOT / "edge-ai/api/app/static"
OUT = ROOT / ".impeccable/review"


def replay(dataset, labels):
    # Use backend dependencies from its venv; browser Python has Playwright only.
    result = subprocess.run(
        [
            str(ROOT / ".venv/Scripts/python.exe"),
            "-c",
            "import json,sys;from app.evaluation import replay;d,l=json.load(sys.stdin);print(json.dumps(replay(d,l)))",
        ],
        cwd=ROOT / "edge-ai/api",
        input=json.dumps([dataset, labels]),
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(result.stdout)


def run(drift=False):
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
            page.on("pageerror", lambda error, errors=errors: errors.append(str(error)))
            page.on(
                "dialog",
                lambda d: d.accept("fixture-key") if d.type == "prompt" else d.accept(),
            )
            identity = str(uuid4())
            start = datetime(2026, 11, 20, tzinfo=UTC)
            windows = [
                {
                    "index": i,
                    "start": (start + timedelta(minutes=5 * i)).isoformat(),
                    "end": (start + timedelta(minutes=5 * (i + 1))).isoformat(),
                    "requests": 1200
                    if drift and i >= 120
                    else 180
                    if i >= 120 and i % 5 == 0
                    else 10,
                    "errors": 600 if drift and i >= 120 else 0,
                    "eligible": i != 149,
                    "collector_covered_seconds": 300 if i != 149 else 285,
                    "membership_sha256": "fixture-only",
                }
                for i in range(150)
            ]
            labels = [
                {
                    "id": i + 1,
                    "window_index": i,
                    "revision": 1,
                    "label": "lab_attack" if i >= 120 and i % 5 == 0 else "normal",
                    "declared_by": "Fixture analyst",
                    "rationale": "Synthetic known traffic classification",
                    "created_at": start.isoformat(),
                    "authentication": "fixture",
                }
                for i in range(150)
            ]
            dataset = {
                "id": identity,
                "content_hash": "fixture-sha256",
                "created_at": start.isoformat(),
                "specification": {
                    "host": "lab.example.test",
                    "router": "lab@file",
                    "start": start.isoformat(),
                    "end": (start + timedelta(minutes=750)).isoformat(),
                    "declared_by": "Fixture <img src=x onerror=window.injected=1>",
                    "rationale": "Authorized synthetic fixture measurement",
                },
                "snapshot": {
                    "scope": "Synthetic fixture, not production benchmark",
                    "windows": windows,
                },
                "labels": labels,
                "runs": [],
            }
            state = {
                "list": [],
                "datasets": {identity: dataset},
                "reports": [],
                "lost_create": True,
                "lost_label": True,
                "conflict": False,
                "lost_run": True,
                "create_ids": [],
                "label_ids": [],
                "run_ids": [],
                "fail_status": False,
                "hold_run": None,
                "held_run": None,
                "fail_run": None,
            }

            def handler(
                route,
                request=None,
                *,
                prefix=prefix,
                state=state,
                start=start,
                dataset=dataset,
            ):
                request = route.request
                parsed = urlparse(request.url)
                path = parsed.path.removeprefix(prefix)
                q = parse_qs(parsed.query)
                if path == "/dashboard":
                    route.fulfill(
                        path=str(STATIC / "dashboard.html"), content_type="text/html"
                    )
                    return
                if path.startswith("/static/"):
                    asset = STATIC / path.removeprefix("/static/")
                    route.fulfill(
                        path=str(asset),
                        content_type=mimetypes.guess_type(str(asset))[0]
                        or "application/octet-stream",
                    )
                    return
                if not path.startswith(("/api/", "/health")):
                    route.abort()
                    return
                ev = path.removeprefix("/api/v1/evaluation")
                data = {}
                if ev == "/status":
                    if state["fail_status"]:
                        route.fulfill(
                            status=503, json={"detail": "Fixture collector unavailable"}
                        )
                        return
                    data = {
                        "state": "collecting",
                        "first_tick": start.isoformat(),
                        "latest_tick": start.isoformat(),
                        "datasets": len(state["list"]),
                    }
                elif ev == "/segments":
                    number = int(q.get("page", [1])[0])
                    data = {
                        "items": [
                            {
                                "host": "lab.example.test"
                                if number == 1
                                else "second.example.test",
                                "router": "lab@file",
                                "requests": 100,
                            }
                        ],
                        "total": 11,
                        "page": number,
                    }
                elif ev == "/datasets":
                    number = int(q.get("page", [1])[0])
                    data = {
                        "items": state["list"][(number - 1) * 10 : number * 10],
                        "total": len(state["list"]),
                        "page": number,
                    }
                elif ev.startswith("/datasets/"):
                    parts = ev.strip("/").split("/")
                    did = parts[1]
                    if len(parts) == 2 and request.method == "PUT":
                        state["create_ids"].append(did)
                        body = request.post_data_json
                        if did not in state["datasets"]:
                            record = copy.deepcopy(dataset)
                            record["id"] = did
                            record["specification"] = body
                            state["datasets"][did] = record
                            state["list"].insert(0, record)
                        if state["lost_create"]:
                            state["lost_create"] = False
                            route.abort("failed")
                            return
                        data = state["datasets"][did]
                    elif len(parts) == 3 and parts[2] == "labels":
                        body = request.post_data_json
                        state["label_ids"].append(body["request_id"])
                        if state["conflict"]:
                            state["conflict"] = False
                            route.fulfill(
                                status=409, json={"detail": "Fixture label changed"}
                            )
                            return
                        record = state["datasets"][did]
                        existing = next(
                            (
                                x
                                for x in record["labels"]
                                if x.get("request_id") == body["request_id"]
                            ),
                            None,
                        )
                        if not existing:
                            existing = {
                                **body,
                                "id": 999,
                                "revision": body["expected_revision"] + 1,
                                "created_at": start.isoformat(),
                                "authentication": "fixture",
                            }
                            record["labels"] = [
                                x
                                for x in record["labels"]
                                if x["window_index"] != body["window_index"]
                            ] + [existing]
                        if state["lost_label"]:
                            state["lost_label"] = False
                            route.abort("failed")
                            return
                        data = existing
                    elif len(parts) == 4 and parts[2] == "labels":
                        data = {
                            "items": [
                                x
                                for x in state["datasets"][did]["labels"]
                                if x["window_index"] == int(parts[3])
                            ],
                            "total": 1,
                            "page": 1,
                        }
                    elif len(parts) == 4 and parts[2] == "runs":
                        rid = parts[3]
                        state["run_ids"].append(rid)
                        existing = next(
                            (x for x in state["reports"] if x["id"] == rid), None
                        )
                        if not existing:
                            record = state["datasets"][did]
                            existing = {
                                "id": rid,
                                "dataset_id": did,
                                "created_at": start.isoformat(),
                                "report": replay(record, record["labels"]),
                            }
                            state["reports"].insert(0, existing)
                        if state["lost_run"]:
                            state["lost_run"] = False
                            route.abort("failed")
                            return
                        data = existing
                    elif len(parts) == 3 and parts[2] == "runs":
                        items = [
                            {
                                "id": x["id"],
                                "created_at": x["created_at"],
                                "state": x["report"]["state"],
                            }
                            for x in state["reports"]
                            if x["dataset_id"] == did
                        ]
                        data = {"items": items, "total": len(items), "page": 1}
                    else:
                        data = state["datasets"][did]
                elif ev.startswith("/runs/"):
                    if state["hold_run"] == ev.split("/")[-1]:
                        state["held_run"] = route
                        return
                    if state["fail_run"] == ev.split("/")[-1]:
                        state["fail_run"] = None
                        route.fulfill(
                            status=503, json={"detail": "Fixture replay load failed"}
                        )
                        return
                    data = next(
                        x for x in state["reports"] if x["id"] == ev.split("/")[-1]
                    )
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
                        "requests": 100,
                        "incidents": 0,
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
                route.fulfill(json=data)

            page.route("**/*", handler)
            page.goto("http://demo.test" + prefix + "/dashboard#evaluation")
            page.wait_for_function(
                "document.querySelector('#evalCollector').textContent.includes('collecting')"
            )
            assert page.locator("#evalDatasets").inner_text().startswith("ยังไม่มี")
            assert page.locator("#dataView").is_hidden()
            if width == 390:
                page.evaluate("document.activeElement.blur();window.scrollTo(0,0)")
                page.screenshot(
                    path=str(OUT / "evaluation-empty-390.png"), full_page=True
                )
            page.locator("#evalCreate details summary").click()
            page.locator("#evalSegmentNext").click()
            page.wait_for_function(
                "document.querySelector('#evalSegments').textContent.includes('second.example')"
            )
            page.locator("#evalSegmentPrev").click()
            page.locator("#evalSegments button").first.click()
            page.locator("#evalStart").fill("2026-11-20T00:00")
            page.locator("#evalEnd").fill("2026-11-20T12:30")
            page.locator("#evalCreator").fill("Fixture analyst")
            page.locator("#evalCreateReason").fill("Synthetic fixture measurement only")
            page.locator("#evalCreateSave").click()
            page.wait_for_function(
                "document.querySelector('#evalCreateSave').textContent.includes('Retry')"
            )
            assert page.locator("#evalHost").is_disabled()
            page.reload()
            page.wait_for_function(
                "document.querySelector('#evalCreateSave').textContent.includes('Retry')"
            )
            page.locator("#evalCreateSave").click()
            page.wait_for_selector("#evalSelected:not([hidden])")
            assert len(set(state["create_ids"])) == 1
            page.locator("#evalWindowNext").click()
            assert ("#4" if width <= 600 else "#8") in page.locator(
                "#evalWindows"
            ).inner_text()
            page.locator("#evalWindowPrev").click()
            page.get_by_role("button", name="Label #0", exact=True).click()
            page.locator("#evalLabelAuthor").fill("Fixture operator")
            page.locator("#evalLabelReason").fill("Verified synthetic baseline window")
            page.locator("#evalLabelSave").click()
            page.wait_for_function(
                "document.querySelector('#evalLabelSave').textContent.includes('Retry')"
            )
            page.reload()
            page.wait_for_function(
                "document.querySelector('#evalLabelStatus').textContent.includes('restored')"
            )
            page.locator("#evalLabelSave").click()
            page.wait_for_function(
                "document.querySelector('#evalLabelStatus').textContent.includes('Label saved')"
            )
            assert len(set(state["label_ids"])) == 1
            assert page.get_by_role("button", name="Label #1", exact=True).is_enabled()
            state["conflict"] = True
            page.locator("#evalLabelReason").fill(
                "Retained draft following concurrent update"
            )
            page.locator("#evalLabelSave").click()
            page.wait_for_function(
                "document.querySelector('#evalLabelStatus').textContent.includes('Reload latest')"
            )
            assert page.locator("#evalLabelSave").is_disabled()
            page.locator("#evalLabelReload").click()
            page.wait_for_function(
                "document.querySelector('#evalLabelStatus').textContent.includes('Latest revision loaded')"
            )
            assert (
                page.locator("#evalLabelReason").input_value()
                == "Retained draft following concurrent update"
            )
            page.get_by_role("button", name="Clear draft", exact=True).click()
            page.locator("#evalVerdict").focus()
            page.keyboard.press("Tab")
            assert page.locator("#evalLabelAuthor").evaluate(
                "e => e === document.activeElement"
            )
            if width in (1440, 390):
                page.locator("#evalHistory").evaluate("e => e.open=true")
                page.evaluate("document.activeElement.blur();window.scrollTo(0,0)")
                page.screenshot(
                    path=str(OUT / f"evaluation-label-{width}.png"), full_page=True
                )
            page.locator("#evalRun").click()
            page.wait_for_function(
                "document.querySelector('#evalRun').textContent.includes('Retry')"
            )
            page.reload()
            page.wait_for_function(
                "document.querySelector('#evalRunStatus').textContent.includes('restored')"
            )
            page.locator("#evalRun").click()
            page.wait_for_function(
                "document.querySelector('#evalRunStatus').textContent.includes('Saved immutable')"
            )
            assert len(set(state["run_ids"])) == 1
            assert "Held-out test windows" in page.locator("#evalReport").inner_text()
            with page.expect_download() as download:
                page.get_by_role("button", name="Export pinned report JSON").click()
            assert download.value.suggested_filename.startswith("edgeguard-replay-")
            # Unknown training must yield a truthful unavailable result, not fabricated rates.
            did = state["create_ids"][0]
            state["datasets"][did]["labels"][1]["label"] = "unknown"
            page.locator("#evalRun").click()
            page.wait_for_function(
                "document.querySelector('#evalReport').textContent.includes('Not ready')"
            )
            assert "Recall" not in page.locator("#evalReport").inner_text()
            if drift:
                assert (
                    "Training baseline not ready"
                    in page.locator(".drift-section").inner_text()
                )
            # Restore the original pinned report for visual evidence; its labels cannot mutate.
            page.locator("#evalRuns").select_option(state["run_ids"][0])
            page.wait_for_function(
                "document.querySelector('#evalReport').textContent.includes('Held-out')"
            )
            if drift:
                pinned = next(
                    x for x in state["reports"] if x["id"] == state["run_ids"][0]
                )
                other = state["reports"][0]
                state["hold_run"] = other["id"]
                page.locator("#evalRuns").select_option(other["id"])
                page.wait_for_function("document.querySelector('#evalRuns').disabled")
                assert page.locator("#evalRuns").input_value() == pinned["id"]
                page.wait_for_timeout(50)
                assert state["held_run"] is not None
                state["hold_run"] = None
                state["held_run"].fulfill(json=other)
                page.wait_for_function(
                    "document.querySelector('#evalReport').textContent.includes('Not ready')"
                )
                assert page.locator("#evalRuns").input_value() == other["id"]
                state["fail_run"] = pinned["id"]
                page.locator("#evalRuns").select_option(pinned["id"])
                page.wait_for_function(
                    "document.querySelector('#evalRunStatus').textContent.includes('load failed')"
                )
                assert page.locator("#evalRuns").input_value() == other["id"]
                page.locator("#evalRuns").select_option(pinned["id"])
                page.wait_for_function(
                    "document.querySelector('.drift-section')?.textContent.includes('Candidate input-distribution change')"
                )
                page.locator(".drift-period details").evaluate_all(
                    "items=>items.forEach(d=>d.open=true)"
                )
                page.evaluate("document.fonts.ready")
                if width in (1440, 768, 390):
                    page.locator(".drift-section").screenshot(
                        path=str(OUT / f"drift-{width}.png")
                    )
                # A legacy report remains legacy; no invented zero drift or backfill.
                legacy = copy.deepcopy(state["reports"][0])
                legacy["id"] = str(uuid4())
                legacy["report"].pop("input_drift", None)
                legacy["report"]["algorithm_version"] = "http-volume-replay-v1-20261121"
                legacy["report"]["implementation_sha256"] = "0" * 64
                state["reports"].append(legacy)
                page.locator("#evalDatasets button").first.click()
                page.wait_for_selector(
                    f'#evalRuns option[value="{legacy["id"]}"]', state="attached"
                )
                page.locator("#evalRuns").select_option(legacy["id"])
                page.wait_for_function(
                    "document.querySelector('.drift-section')?.textContent.includes('Not recorded for this saved replay')"
                )
                assert page.locator(".drift-period").count() == 0
                if width == 390:
                    page.locator(".drift-section").screenshot(
                        path=str(OUT / "drift-legacy-390.png")
                    )
                # A separate gapped fixture dataset yields no clean distribution result.
                gap = copy.deepcopy(dataset)
                gap_id = str(uuid4())
                gap["id"] = gap_id
                gap["specification"]["host"] = "gap.fixture.test"
                gap["content_hash"] = "fixture-gap-sha"
                for window in gap["snapshot"]["windows"][120:130]:
                    window["eligible"] = False
                    window["collector_covered_seconds"] = 0
                state["datasets"][gap_id] = gap
                state["list"].append(gap)
                page.evaluate("window.EdgeEvaluation.refresh()")
                page.locator("#evalDatasets button").filter(
                    has_text="gap.fixture.test"
                ).click()
                page.wait_for_function(
                    "document.querySelector('#evalSelectionTitle').textContent==='gap.fixture.test'"
                )
                page.locator("#evalRun").click()
                page.wait_for_function(
                    "document.querySelector('.drift-section')?.textContent.includes('Insufficient eligible coverage')"
                )
                assert (
                    page.locator(".drift-period").first.locator("details").count() == 0
                )
                if width == 390:
                    page.locator(".drift-section").screenshot(
                        path=str(OUT / "drift-gap-390.png")
                    )
            state["fail_status"] = True
            page.locator("#refreshButton").click() if page.locator(
                "#refreshButton"
            ).count() else page.evaluate("window.EdgeEvaluation.refresh()")
            page.wait_for_function(
                "document.querySelector('#evalCollector').textContent.includes('unavailable')"
            )
            state["fail_status"] = False
            page.evaluate("window.EdgeEvaluation.refresh()")
            page.wait_for_function(
                "document.querySelector('#evalCollector').textContent.includes('collecting')"
            )
            page.evaluate("document.activeElement.blur();window.scrollTo(0,0)")
            page.evaluate("document.fonts.ready")
            assert page.evaluate(
                "document.documentElement.scrollWidth <= innerWidth"
            ), width
            assert not page.evaluate("window.injected || false")
            if width in (1440, 768, 390) and not drift:
                page.screenshot(
                    path=str(OUT / f"evaluation-{width}.png"), full_page=True
                )
            assert not errors, errors
            page.close()
        browser.close()
    print(
        "Evaluation UI PASS: 4 widths/3 prefixes; empty/error/recovery, segments/windows paging, snapshot/label/run lost-response UUID recovery across reload, CAS/draft, pinned report/export, insufficient data and XSS"
    )
    if drift:
        print(
            "Drift UI PASS: candidate/error-share, baseline readiness, legacy unavailable and gap handling; actual immutable replay integration at4 widths/3 prefixes"
        )


if __name__ == "__main__":
    run()
