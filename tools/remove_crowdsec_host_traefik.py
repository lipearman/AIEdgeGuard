"""TEMPORARY: remove the crowdsec middleware from the Windows-host traefik.

Use when the plugin cannot reach LAPI/AppSec (fail-closed 403s block real
traffic). The EdgeGuard gateway stack keeps protecting its own routes; the
host traefik portal returns to its pre-EdgeGuard state until the
connectivity issue from the service context is resolved.
"""
import glob
import shutil
import sys

import yaml

BASE = r"C:\tools\traefik"


def main() -> None:
    # ---- dynamic yamls: strip crowdsec from routers + remove definition ----
    for path in sorted(glob.glob(BASE + r"\dynamic\*.yml")):
        shutil.copyfile(path, path + ".bak-crowdsec-removal")
        doc = yaml.safe_load(open(path, encoding="utf-8")) or {}
        http = doc.get("http") or {}
        changed = 0
        for name, router in (http.get("routers") or {}).items():
            if not isinstance(router, dict):
                continue
            mw = router.get("middlewares")
            if isinstance(mw, list) and "crowdsec" in mw:
                router["middlewares"] = [m for m in mw if m != "crowdsec"]
                if not router["middlewares"]:
                    del router["middlewares"]
                changed += 1
        if "crowdsec" in (http.get("middlewares") or {}):
            del http["middlewares"]["crowdsec"]
            changed += 1
        if changed:
            yaml.safe_dump(doc, open(path, "w", encoding="utf-8"),
                           sort_keys=False, allow_unicode=True)
        print(f"[ok] {path}: {changed} change(s)")

    print("\nDONE — traefik live-reloads (watch: true); portal returns to the "
          "pre-EdgeGuard state (no WAF/ban on the portal paths).")


if __name__ == "__main__":
    sys.exit(main())
