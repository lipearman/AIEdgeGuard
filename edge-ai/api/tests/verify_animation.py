"""Measure visible pixel changes, pause/resume and cached-page lifecycle.

Uses the local deployed API read-only; --preview serves the new scene script
before deployment. Requires Playwright, Chrome and Pillow.
"""

import io
import json
import sys
from pathlib import Path

from PIL import Image, ImageChops
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / ".artifacts/animation"


def difference(a, b):
    first, second = Image.open(io.BytesIO(a)), Image.open(io.BytesIO(b))
    assert first.size == second.size
    mask = (
        ImageChops.difference(first.convert("RGB"), second.convert("RGB"))
        .convert("L")
        .point(lambda value: 255 if value > 8 else 0)
    )
    return mask.histogram()[255] / (first.width * first.height) * 100


def ready(page):
    page.goto("http://127.0.0.1:8099/mission")
    page.wait_for_function(
        "document.querySelector('#refreshInfo').textContent.includes('อัปเดต')"
    )
    page.evaluate("document.fonts.ready")


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, channel="chrome")
        for width in [1440, 390]:
            page = browser.new_page(viewport={"width": width, "height": 1000})
            errors = []
            page.on("pageerror", lambda error, errors=errors: errors.append(str(error)))
            if "--preview" in sys.argv:
                page.route(
                    "**/static/mission-scene.js*",
                    lambda route: route.fulfill(
                        path=str(ROOT / "edge-ai/api/app/static/mission-scene.js"),
                        content_type="text/javascript",
                    ),
                )
            ready(page)
            page.wait_for_function(
                "Number(document.querySelector('#defenseCanvas').dataset.frames)>3"
            )
            region = page.locator("#scene")
            a = region.screenshot(path=str(OUT / f"{width}-frame-a.png"))
            page.wait_for_timeout(1100)
            b = region.screenshot(path=str(OUT / f"{width}-frame-b.png"))
            moving = difference(a, b)
            assert moving > 0.4, (width, "insufficient visible motion", moving)
            button = page.locator("#motionToggle")
            button.click()
            assert button.get_attribute("aria-pressed") == "true"
            page.wait_for_timeout(100)
            frozen = region.screenshot()
            page.wait_for_timeout(400)
            assert difference(frozen, region.screenshot()) == 0, (
                "Pause did not freeze pixels"
            )
            button.click()
            page.wait_for_timeout(700)
            resumed = difference(frozen, region.screenshot())
            assert resumed > 0.4, ("Play did not resume visible motion", resumed)
            page.evaluate(
                "window.dispatchEvent(new PageTransitionEvent('pagehide',{persisted:true}))"
            )
            before = page.locator("#defenseCanvas").get_attribute("data-frames")
            page.wait_for_timeout(150)
            assert before == page.locator("#defenseCanvas").get_attribute("data-frames")
            page.evaluate(
                "window.dispatchEvent(new PageTransitionEvent('pageshow',{persisted:true}))"
            )
            page.wait_for_timeout(250)
            assert int(
                page.locator("#defenseCanvas").get_attribute("data-frames")
            ) > int(before)
            if width == 390:
                page.locator("#enginePanel").scroll_into_view_if_needed()
                page.wait_for_timeout(150)
                before = page.locator("#defenseCanvas").get_attribute("data-frames")
                page.wait_for_timeout(200)
                assert before == page.locator("#defenseCanvas").get_attribute(
                    "data-frames"
                ), "Offscreen scene kept rendering"
                region.scroll_into_view_if_needed()
                page.wait_for_timeout(250)
                assert int(
                    page.locator("#defenseCanvas").get_attribute("data-frames")
                ) > int(before)
            assert not errors, errors
            results.append(
                {
                    "width": width,
                    "changed_pixels_percent": round(moving, 2),
                    "resumed_pixels_percent": round(resumed, 2),
                    "pause_pixels_percent": 0,
                    "cached_page_lifecycle": "passed",
                }
            )
            page.screenshot(path=str(OUT / f"{width}-page.png"), full_page=True)
            page.close()

        reduced = browser.new_page(reduced_motion="reduce")
        if "--preview" in sys.argv:
            reduced.route(
                "**/static/mission-scene.js*",
                lambda route: route.fulfill(
                    path=str(ROOT / "edge-ai/api/app/static/mission-scene.js"),
                    content_type="text/javascript",
                ),
            )
        ready(reduced)
        assert reduced.locator("#motionToggle").get_attribute("aria-pressed") == "false"
        reduced.wait_for_function(
            "Number(document.querySelector('#defenseCanvas').dataset.frames)>1"
        )
        reduced.close()

        fallback = browser.new_page()
        fallback.add_init_script("""const getContext=HTMLCanvasElement.prototype.getContext;
            HTMLCanvasElement.prototype.getContext=function(type,...args){
              return type.includes('webgl') ? null : getContext.call(this,type,...args);
            };""")
        if "--preview" in sys.argv:
            fallback.route(
                "**/static/mission-scene.js*",
                lambda route: route.fulfill(
                    path=str(ROOT / "edge-ai/api/app/static/mission-scene.js"),
                    content_type="text/javascript",
                ),
            )
        ready(fallback)
        assert fallback.locator("#motionToggle").is_disabled()
        assert "unavailable" in fallback.locator("#motionToggle").inner_text()
        assert fallback.locator(".hero-art").is_visible()
        browser.close()
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results))
    print("Autoplay with reduced-motion pacing and WebGL fallback passed")


if __name__ == "__main__":
    run()
