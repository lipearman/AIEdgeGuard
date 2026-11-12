"""Toggle Basic Auth for the canonical preview route in repo and live config.

Usage: python tools/set_preview_auth.py --disable
       python tools/set_preview_auth.py --enable
Reload Traefik after running. The /aiedge alias and WAF are preserved.
"""

import argparse
import re
from pathlib import Path

import yaml

parser = argparse.ArgumentParser(description=__doc__)
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument("--enable", action="store_true")
mode.add_argument("--disable", action="store_true")
parser.add_argument("--close-public", action="store_true", help="With --enable, detach the canonical route from the public root entrypoint")
args = parser.parse_args()
if args.close_public and not args.enable:
    parser.error("--close-public requires --enable")
paths = [
    Path(__file__).resolve().parents[1] / "edge-guard/traefik/dynamic/funnel.yml",
    Path("C:/Docker/gateway/traefik/dynamic/funnel.yml"),
]
prepared = []
for path in paths:
    text = path.read_text(encoding="utf-8")
    config = yaml.safe_load(text)["http"]
    assert "aiedge-auth" in config["middlewares"], "Auth middleware definition missing"
    assert "crowdsec@docker" in config["routers"]["funnel-aiedge"]["middlewares"]
    pattern = r"(?ms)(^    funnel-aiedge:\n)(.*?)(?=^    [a-zA-Z0-9_-]+:|\Z)"
    match = re.search(pattern, text)
    if not match:
        raise RuntimeError(f"Canonical router block missing: {path}")
    block = match.group(0).replace("        - aiedge-auth\n", "")
    if args.enable:
        block = block.replace(
            "        - strip-aiedge\n",
            "        - aiedge-auth\n        - strip-aiedge\n",
        )
    if args.close_public:
        block = block.replace("        - funnelroot443\n", "")
    text = text[: match.start()] + block + text[match.end() :]
    marker = "# EDGEGUARD_PREVIEW_AUTH=" + ("enabled" if args.enable else "disabled")
    text = re.sub(r"(?m)^# EDGEGUARD_PREVIEW_AUTH=.*\n", "", text)
    text = marker + "\n" + text
    yaml.safe_load(text)
    prepared.append((path, text))
for path, text in prepared:
    path.write_text(text, encoding="utf-8")
print("Canonical /AIEdgeGuard Basic Auth:", "enabled" if args.enable else "disabled")
