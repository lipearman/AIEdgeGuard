"""Attach the EdgeGuard CrowdSec middleware to the Windows-host traefik.

- backs up traefik.yml + dynamic/*.yml to <name>.bak-edgeguard
- traefik.yml: experimental.plugins (crowdsec bouncer plugin) + forwardedHeaders
  trust on web9002 (Tailscale Funnel proxy runs locally, adds X-Forwarded-For)
- dynamic yamls: prepend `crowdsec` to every router's middlewares and add the
  middleware definition (LAPI + AppSec on host loopback 8085/8086)

Idempotent: skips routers that already reference crowdsec.
"""
import glob
import shutil
import sys

import yaml

BASE = r"C:\tools\traefik"
LAPI_KEY_FILE = r"C:\Docker\gateway\host-traefik-bouncer.key"

MIDDLEWARE_DEF = {
    "crowdsec": {
        "plugin": {
            "crowdsec-bouncer-traefik-plugin": {
                "enabled": True,
                "crowdsecLapiUrl": "http://100.99.80.84:8085",
                "crowdsecLapiKey": open(LAPI_KEY_FILE, encoding="utf-8").read().strip(),
                "forwardedHeadersTrustedIps": ["127.0.0.1/32"],
                "crowdsecAppsecEnabled": True,
                "crowdsecAppsecHost": "100.99.80.84:8086",
                "crowdsecAppsecFailureBlock": True,
            }
        }
    }
}


def backup(path: str) -> str:
    bak = path + ".bak-edgeguard"
    shutil.copyfile(path, bak)
    return bak


def attach_middlewares(doc: dict) -> int:
    """Prepend crowdsec to every router missing it. Returns count."""
    routers = (doc.get("http") or {}).get("routers") or {}
    changed = 0
    for name, router in routers.items():
        if not isinstance(router, dict):
            continue
        mw = router.get("middlewares")
        if mw is None:
            router["middlewares"] = ["crowdsec"]
            changed += 1
        elif isinstance(mw, list) and "crowdsec" not in mw:
            router["middlewares"] = ["crowdsec"] + list(mw)
            changed += 1
    return changed


def main() -> None:
    key = open(LAPI_KEY_FILE, encoding="utf-8").read().strip()
    mw_def = MIDDLEWARE_DEF
    mw_def["crowdsec"]["plugin"]["crowdsec-bouncer-traefik-plugin"][
        "crowdsecLapiKey"] = key

    # ---- traefik.yml (static) ----
    static_path = BASE + r"\traefik.yml"
    backup(static_path)
    static = yaml.safe_load(open(static_path, encoding="utf-8"))
    exp = static.setdefault("experimental", {}).setdefault("plugins", {})
    exp["crowdsec-bouncer-traefik-plugin"] = {
        "moduleName": "github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin",
        "version": "v1.3.5",
    }
    ep = static["entryPoints"]["web9002"]
    fh = ep.setdefault("forwardedHeaders", {"trustedIPs": []})
    for ip in ("127.0.0.1/32",):
        if ip not in fh["trustedIPs"]:
            fh["trustedIPs"].append(ip)
    yaml.safe_dump(static, open(static_path, "w", encoding="utf-8"),
                   sort_keys=False, allow_unicode=True)
    print(f"[ok] {static_path}: plugin + forwardedHeaders added")

    # ---- dynamic yamls ----
    for path in sorted(glob.glob(BASE + r"\dynamic\*.yml")):
        backup(path)
        doc = yaml.safe_load(open(path, encoding="utf-8")) or {}
        http = doc.setdefault("http", {})
        changed = attach_middlewares(doc)
        # middleware definition goes into routes.yml (the main file)
        if path.endswith("routes.yml"):
            http.setdefault("middlewares", {}).update(mw_def)
            changed += 1
        if changed:
            yaml.safe_dump(doc, open(path, "w", encoding="utf-8"),
                           sort_keys=False, allow_unicode=True)
        print(f"[ok] {path}: {changed} router(s) updated")

    print("\nDONE — restart the sanuk-traefik service to apply.")


if __name__ == "__main__":
    sys.exit(main())
