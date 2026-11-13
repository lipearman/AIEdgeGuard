"""Browser contract tests: synthetic SIEM/API responses, no live AI or actions."""

import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / ".impeccable/review"
STATIC = ROOT / "edge-ai/api/app/static"


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, channel="chrome")
        for width in (1440, 768, 390, 320):
            page = browser.new_page(viewport={"width": width, "height": 1000})
            errors = []
            page.on("pageerror", lambda e, errors=errors: errors.append(str(e)))
            state = {"fail": False, "posts": [], "stream_error": False}
            payload = {
                "payload": {
                    "alert_id": "wazuh-test",
                    "data": {
                        "command": "<img src=x onerror=window.injected=1>",
                        "token": "[redacted]",
                    },
                },
                "original_bytes": 2048,
                "cleaned_bytes": 350,
                "note": "Bounded context; secret patterns redacted.",
            }

            def route(r, _request, *, state=state, payload=payload):
                parsed = urlparse(r.request.url)
                path = parsed.path
                # Always test current source, independent of image build timing.
                if path.startswith("/static/"):
                    file = STATIC / path.removeprefix("/static/")
                    if file.is_file():
                        r.fulfill(path=str(file))
                        return
                if path == "/dashboard":
                    r.fulfill(
                        path=str(STATIC / "dashboard.html"), content_type="text/html"
                    )
                    return
                if "/api/v1/ai/" not in path:
                    r.continue_()
                    return
                if path.endswith("/queue"):
                    if state["fail"]:
                        r.fulfill(status=503, json={"detail": "Queue unavailable"})
                        return
                    page_number = int(parse_qs(parsed.query).get("page", ["1"])[0])
                    r.fulfill(
                        json={
                            "items": [
                                {
                                    "id": i,
                                    "alert_id": f"wazuh-test-{i}",
                                    "created_at": "2026-11-12T12:00:00Z",
                                    "reason": "Repeated authentication failure on endpoint · "
                                    + "long-evidence " * 8,
                                    "severity": "high",
                                    "level": 9,
                                    "rule_id": "5710",
                                    "mitre": ["T1110"],
                                    "hostname": "workstation-01",
                                }
                                for i in range(
                                    20 - (page_number - 1) * 10,
                                    10 - (page_number - 1) * 10,
                                    -1,
                                )
                            ],
                            "total": 20,
                            "page": page_number,
                            "pages": 2,
                            "snapshot": 20,
                        }
                    )
                elif path.endswith("/config"):
                    r.fulfill(
                        json={
                            "default_model": "local:9b",
                            "models": ["local:9b", "other:4b"],
                            "cache_ttl": 600,
                        }
                    )
                elif "/payload/" in path:
                    r.fulfill(json=payload)
                elif path.endswith("/triage"):
                    body = r.request.post_data_json
                    state["posts"].append(body)

                    def event(name, data):
                        return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"

                    result = event(
                        "meta",
                        {
                            "model": body["model"] or "local:9b",
                            "language": body["language"],
                            "cached": not body["bypass_cache"],
                            **payload,
                        },
                    )
                    result += event(
                        "token",
                        {
                            "text": "1. สรุปเหตุการณ์\nพบ authentication failure จากหลักฐานจริง\n"
                        },
                    ) + event(
                        "token",
                        {"text": "2. ตรวจสอบ\n<img src=x onerror=window.injected=1>"},
                    )
                    result += (
                        event("error", {"message": "Model interrupted; retry analysis"})
                        if state["stream_error"]
                        else event(
                            "done",
                            {
                                "cached": not body["bypass_cache"],
                                "cache_saved": True,
                                "generated_at": "2026-11-12T12:00:00Z",
                            },
                        )
                    )
                    r.fulfill(content_type="text/event-stream", body=result)
                else:
                    r.fulfill(status=404, json={"detail": "Unknown mock"})

            page.route("**/*", route)
            page.goto("http://127.0.0.1:8099/dashboard#triage")
            page.locator(".triage-alert").first.wait_for()
            page.evaluate("document.fonts.ready")
            assert page.locator("#tableToolbar").is_hidden()
            assert page.locator("#dataView").is_hidden()
            assert page.locator("#triageSettings").is_hidden()
            page.locator(".triage-alert").first.click()
            page.locator("#triageSettingsToggle").click()
            page.locator("#triageModel").select_option("other:4b")
            page.locator("#triageLanguage").select_option("en")
            page.locator("#triageHostname").fill("analyst-host")
            page.locator("#triageInspect").click()
            page.wait_for_function(
                "document.querySelector('#triagePayloadBody').textContent.includes('[redacted]')"
            )
            assert page.locator("#triagePayloadBody img").count() == 0
            page.locator("#triageStart").click()
            page.wait_for_function(
                "document.querySelector('#triageStreamStatus').textContent.includes('Cached report')"
            )
            assert state["posts"][-1]["language"] == "en"
            assert state["posts"][-1]["model"] == "other:4b"
            assert state["posts"][-1]["hostname"] == "analyst-host"
            assert page.evaluate("window.injected") is None
            assert page.locator("#triageReport img").count() == 0
            assert not page.locator("#triageStart").is_disabled()
            page.locator("#triageLanguage").select_option("th")
            assert "Not generated" in page.locator("#triageModelInfo").inner_text()
            page.locator("#triageLanguage").select_option("en")
            page.locator("#triageBypass").check()
            page.locator("#triageStart").click()
            page.wait_for_function(
                "document.querySelector('#triageStreamStatus').textContent.includes('Completed')"
            )
            assert state["posts"][-1]["bypass_cache"] is True
            page.locator("#triageSettingsToggle").click()
            if width in (1440, 768, 390):
                page.screenshot(path=str(OUT / f"triage-{width}.png"), full_page=True)
            assert page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (
                width
            )
            # Split UTF-8 and SSE frames across network chunks, then stop an idle stream.
            page.evaluate(
                """payload => {
              window.__triageOriginalFetch = window.fetch;
              window.fetch = (url, options) => {
                if (!String(url).endsWith('/ai/triage')) return window.__triageOriginalFetch(url, options);
                const bytes = new TextEncoder().encode('event: meta\\ndata: '+JSON.stringify({...payload,model:'local:9b',language:'th',cached:false})+'\\n\\nevent: token\\ndata: '+JSON.stringify({text:'รายงานทดสอบแบบสตรีม'})+'\\n\\n');
                return Promise.resolve(new Response(new ReadableStream({start(controller) {
                  let offset=0;
                  const timer=setInterval(()=>{if(offset<bytes.length){controller.enqueue(bytes.slice(offset,offset+7));offset+=7;}else clearInterval(timer);},1);
                  options.signal.addEventListener('abort',()=>{clearInterval(timer);controller.error(new DOMException('Aborted','AbortError'));});
                }}),{headers:{'Content-Type':'text/event-stream'}}));
              };
            }""",
                payload,
            )
            page.locator("#triageStart").click()
            page.wait_for_function(
                "document.querySelector('#triageReport').textContent==='รายงานทดสอบแบบสตรีม'"
            )
            page.locator("#triageStop").click()
            page.wait_for_function(
                "document.querySelector('#triageStreamStatus').textContent.includes('Stopped')"
            )
            assert not page.locator("#triageStart").is_disabled()
            page.evaluate("window.fetch=window.__triageOriginalFetch")
            page.locator("#triageNext").click()
            page.wait_for_function(
                "document.querySelector('#triagePage').textContent==='2 / 2'"
            )
            page.locator(".triage-alert").first.click()
            assert "Not generated" in page.locator("#triageModelInfo").inner_text()
            state["stream_error"] = True
            page.locator("#triageStart").click()
            page.wait_for_function(
                "document.querySelector('#triageStreamStatus').textContent.includes('Model interrupted')"
            )
            assert (
                page.locator("#triageStreamStatus")
                .get_attribute("class")
                .endswith("error")
            )
            state["fail"] = True
            page.locator("#triageSync").click()
            page.wait_for_function(
                "document.querySelector('#triageQueueStatus').textContent.includes('Queue unavailable')"
            )
            assert page.locator("#triageNext").is_disabled()
            state["fail"] = False
            page.locator("#triageSync").click()
            page.locator(".triage-alert").first.wait_for()
            page.locator("#tab-requests").click()
            page.locator(".record-open").first.wait_for()
            assert page.locator("#triageWorkspace").is_hidden()
            assert not errors, errors
            page.close()
        browser.close()
    print(
        "Triage checks passed at4 widths: queue/paging, settings/language/hostname, payload, cache/bypass, SSE report, XSS, failure/recovery and existing Traffic"
    )


if __name__ == "__main__":
    run()
