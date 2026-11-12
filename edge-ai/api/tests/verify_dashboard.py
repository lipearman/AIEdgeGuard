"""Responsive browser checks with mock paging/evidence; no live commands execute."""

import json
import math
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
            (1440, "/AIEdgeGuard"),
            (1024, ""),
            (768, ""),
            (390, "/aiedge"),
            (320, ""),
        ]:
            page = browser.new_page(
                viewport={"width": width, "height": 1000}, accept_downloads=True
            )
            errors = []
            page.on("pageerror", lambda e, errors=errors: errors.append(str(e)))
            state = {
                "fail": False,
                "summary_fail": False,
                "lab": False,
                "actions": 0,
                "runs": 0,
                "rejected": set(),
            }
            rows = [
                {
                    "id": i,
                    "observed_at": "2026-11-12T10:00:00Z",
                    "source_ip": "10.0.0.5",
                    "method": "GET",
                    "path": f"/record-{i}/search?q="
                    + ("x" * 220 if i == 53 else "test"),
                    "host": "demo.example",
                    "status": 403 if i % 3 == 0 else 200,
                    "duration_ns": 1_500_000,
                    "router": "gateway@file",
                }
                for i in range(53, 0, -1)
            ]

            def route(r, _request, *, prefix=prefix, state=state, rows=rows):
                url = urlparse(r.request.url)
                path = url.path.removeprefix(prefix)
                query = parse_qs(url.query)
                if path.endswith("/dashboard"):
                    r.fulfill(
                        path=str(STATIC / "dashboard.html"), content_type="text/html"
                    )
                    return
                if path.startswith("/static/"):
                    asset = STATIC / path.removeprefix("/static/")
                    r.fulfill(
                        path=str(asset),
                        content_type=mimetypes.guess_type(asset)[0]
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
                elif path == "/api/v1/visibility":
                    data = {
                        "layers": {
                            key: {"state": "online", "label": "ONLINE", "detail": key}
                            for key in ["http_waf", "network_ids", "host_edr"]
                        }
                    }
                elif path == "/api/v1/agents/status":
                    data = {
                        "defense": {"mode": "dry_run (human approval required)"},
                        "attack": {"mode": "lab" if state["lab"] else "off"},
                    }
                elif path == "/api/v1/policy":
                    data = {
                        "mode": "dry_run",
                        "policy": {
                            "version": 1,
                            "allowlist": {"actions": ["temporary_ip_block"]},
                        },
                    }
                elif path == "/api/v1/dashboard/summary":
                    if state["summary_fail"]:
                        r.fulfill(status=503, json={"detail": "Summary offline"})
                        return
                    data = {
                        "requests": 53,
                        "incidents": 54,
                        "analyzed": 50,
                        "pending": 9 - len(state["rejected"]),
                        "campaigns": 33,
                        "requests_since": "2026-11-12T10:00:00Z",
                    }
                elif path.startswith("/api/v1/decisions/"):
                    state["actions"] += 1
                    state["rejected"].add(int(path.split("/")[-2]))
                    data = {"status": "rejected"}
                elif path == "/api/v1/attacks/run":
                    state["runs"] += 1
                    data = {
                        "id": 7,
                        "techniques_detected": 4,
                        "techniques_total": 5,
                        "new_alerts": 4,
                    }
                elif path.startswith("/api/v1/dashboard/data/"):
                    if state["fail"]:
                        r.fulfill(status=503, json={"detail": "Database offline"})
                        return
                    pieces = path.split("/")
                    kind = pieces[5]
                    if kind == "requests":
                        source = rows
                    elif kind == "incidents":
                        source = [
                            {
                                "id": i,
                                "alert_id": f"evt-{i}",
                                "created_at": "2026-11-12T10:00:00Z",
                                "source": "suricata" if i % 2 else "wazuh",
                                "source_ip": "10.1.2.3",
                                "severity": "high" if i % 2 else "medium",
                                "reason": "Controlled incident",
                                "attack_type": "Network alert",
                                "analyzed": True,
                            }
                            for i in range(54, 0, -1)
                        ]
                    elif kind in ["decisions", "approvals"]:
                        source = [
                            {
                                "id": i,
                                "created_at": "2026-11-12T10:00:00Z",
                                "incident_alert_id": "evt-1",
                                "action": "temporary_ip_block",
                                "target": "203.0.113.10",
                                "duration_seconds": 900,
                                "policy_reason": "human approval required",
                                "status": "pending_approval",
                                "policy_verdict": "pending_approval",
                                "severity": "medium",
                            }
                            for i in range(9, 0, -1)
                            if i not in state["rejected"]
                        ]
                    elif kind == "campaigns":
                        source = [
                            {
                                "id": i,
                                "last_seen": "2026-11-12T10:00:00Z",
                                "attack_type": "Network intrusion",
                                "title": "Correlated incidents",
                                "source_ip": "10.1.2.3",
                                "severity": "medium",
                                "incident_count": 4,
                            }
                            for i in range(33, 0, -1)
                        ]
                    else:
                        source = [
                            {
                                "id": i,
                                "created_at": "2026-11-12T10:00:00Z",
                                "target_host": "juicelab.lab.local",
                                "attacker_ip": "10.1.1.5",
                                "techniques_detected": 4,
                                "techniques_total": 5,
                                "new_alerts": 3,
                                "results": {
                                    "techniques": [{"id": "test", "detected": True}]
                                },
                            }
                            for i in range(5, 0, -1)
                        ]
                    if len(pieces) > 6:
                        data = dict(
                            next(
                                item for item in source if item["id"] == int(pieces[6])
                            )
                        )
                        if kind == "requests":
                            data.update(
                                raw={
                                    "RequestProtocol": "HTTP/1.1",
                                    "RequestPath": data["path"],
                                    "DownstreamContentSize": 123,
                                },
                                capture={
                                    "body_captured": False,
                                    "pcap_captured": False,
                                    "headers": {
                                        "User-Agent": '<img src=x onerror="window.injected=true">'
                                    },
                                },
                            )
                        if kind == "incidents":
                            data.update(
                                analysis={
                                    "attack_type": "Network alert",
                                    "reasoning": "Controlled sensor evidence",
                                },
                                event={
                                    "event": {
                                        "event_type": "alert",
                                        "src_ip": "10.1.2.3",
                                        "dest_ip": "10.2.3.4",
                                        "src_port": 1234,
                                        "dest_port": 80,
                                        "proto": "TCP",
                                        "packet": "R0VUIC90ZXN0IEhUVFAvMS4x",
                                        "payload_printable": "' OR 1=1-- <script>window.injected=true</script>",
                                    }
                                },
                            )
                    else:
                        q = query.get("q", [""])[0]
                        source = [
                            item
                            for item in source
                            if q.lower() in json.dumps(item).lower()
                        ]
                        for key in ["severity", "source", "status"]:
                            value = query.get(key, [""])[0]
                            if value:
                                source = [
                                    item
                                    for item in source
                                    if (
                                        str(item.get("status", "")).startswith(value[0])
                                        if value.endswith("xx")
                                        else str(item.get(key, "")) == value
                                    )
                                ]
                        size = int(query.get("page_size", ["25"])[0])
                        pages = max(1, math.ceil(len(source) / size))
                        number = min(pages, int(query.get("page", ["1"])[0]))
                        data = {
                            "items": source[(number - 1) * size : number * size],
                            "page": number,
                            "pages": pages,
                            "total": len(source),
                            "page_size": size,
                            "snapshot": 1000,
                        }
                else:
                    r.fulfill(status=404)
                    return
                r.fulfill(json=data)

            page.route("http://edgeguard.test/**", route)
            page.goto(f"http://edgeguard.test{prefix}/dashboard")
            page.wait_for_function(
                "document.querySelector('#pageInfo').textContent.includes('53')"
            )
            page.evaluate("document.fonts.ready")
            assert page.locator(".record-table tbody tr").count() == (
                5 if width <= 600 else 10
            )
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (
                width
            )
            if width in [1440, 768, 390]:
                page.screenshot(
                    path=str(OUT / f"dashboard-{width}.png"), full_page=True
                )
            page.locator("#nextPage").click()
            page.wait_for_function(
                "document.querySelector('.record-open').textContent==='Inspect #"
                + str(48 if width <= 600 else 43)
                + "'"
            )
            page.locator("#prevPage").click()
            page.wait_for_function(
                "document.querySelector('.record-open').textContent==='Inspect #53'"
            )
            page.locator(".record-open").first.click()
            page.wait_for_function(
                "document.querySelector('#detailBody').textContent.includes('User-Agent')"
            )
            assert page.locator("#detailBody img").count() == 0
            assert page.evaluate("window.injected") is None
            assert "x" * 220 in page.locator("#detailBody").inner_text()
            with page.expect_download() as download:
                page.locator("#downloadRecord").click()
            data = json.loads(Path(download.value.path()).read_text())
            assert data["capture"]["body_captured"] is False
            if width in [1440, 390]:
                page.screenshot(
                    path=str(OUT / f"dashboard-inspector-{width}.png"), full_page=False
                )
            page.keyboard.press("Escape")
            page.locator("#pageSize").select_option("10")
            page.wait_for_function(
                "document.querySelectorAll('.record-table tbody tr').length===10"
            )
            page.locator("#pageNumber").fill("4")
            page.locator("#goPage").click()
            page.wait_for_function("document.querySelector('#pageNumber').value==='4'")
            page.locator("#recordStatus").select_option("403")
            page.wait_for_function("document.querySelector('#pageNumber').value==='1'")
            page.wait_for_function(
                "[...document.querySelectorAll('.record-badge')].every(e=>e.textContent==='403')"
            )
            page.locator("#recordSearch").fill("not-present")
            page.wait_for_function(
                "document.querySelector('#dataView').textContent.includes('ไม่พบข้อมูล')"
            )
            page.locator("#tab-incidents").click()
            page.wait_for_function(
                "document.querySelector('#recordsTitle').textContent==='Incident center'"
            )
            page.locator("#sourceFilter").select_option("suricata")
            page.locator("#recordSeverity").select_option("high")
            page.wait_for_function("document.querySelectorAll('.record-open').length>0")
            page.locator(".record-open").first.click()
            page.wait_for_function(
                "document.querySelector('#detailBody').textContent.includes('payload_printable')"
            )
            assert (
                page.locator("#detailBody script").count() == 0
                and page.evaluate("window.injected") is None
            )
            assert "47 45 54" in page.locator("#detailBody").inner_text()
            page.keyboard.press("Escape")
            page.locator("#tab-approvals").click()
            page.wait_for_function(
                "document.querySelectorAll('.row-actions button').length>0"
            )
            page.on("dialog", lambda dialog: dialog.accept())
            page.locator(".row-actions .reject").first.click()
            page.wait_for_function(
                "document.querySelector('#statPending').textContent==='8'"
            )
            assert state["actions"] == 1
            for tab in ["campaigns", "decisions", "attacks", "policy"]:
                page.locator("#tab-" + tab).click()
                page.wait_for_timeout(80)
                if tab != "policy":
                    page.wait_for_selector(".record-open")
            page.wait_for_selector(".policy-view")
            page.locator("#tab-requests").click()
            page.wait_for_selector(".record-open")
            state["fail"] = True
            page.locator("#refreshDashboard").click()
            page.wait_for_function(
                "document.querySelector('#dataView').textContent.includes('Database offline')"
            )
            assert page.locator("#nextPage").is_disabled()
            state["fail"] = False
            state["summary_fail"] = True
            page.locator("#refreshDashboard").click()
            page.wait_for_function(
                "document.querySelector('#statRequests').textContent==='—'"
            )
            page.wait_for_selector(".record-open")
            state["summary_fail"] = False
            state["lab"] = True
            page.locator("#refreshDashboard").click()
            page.locator("#tab-attacks").click()
            page.wait_for_function("!document.querySelector('#runLab').disabled")
            page.locator("#runLab").click()
            page.wait_for_function(
                "document.querySelector('#labResult').textContent.includes('4/5')"
            )
            assert state["runs"] == 1
            assert not errors, errors
            page.close()
        browser.close()
    print(
        "Dashboard checks passed: 5 widths, 3 prefixes, server paging, filters/search, raw headers/payload XSS, JSON export, inspector, all tabs, mock approval/lab, partial errors/recovery"
    )


if __name__ == "__main__":
    run()

