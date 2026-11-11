#!/usr/bin/env bash
# CVAT route (now behind crowdsec@docker) — FP + attack test suite
H='Host: llm-server'
B='http://localhost:8080'
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$H" "$1"; }

echo "=== NORMAL CVAT ENDPOINTS (200/401/302 = passed WAF; 403-with-alert = FP!) ==="
echo "[1] /api/server/about   -> $(code "$B/api/server/about")  (expect 200)"
echo "[2] /api/tasks          -> $(code "$B/api/tasks")  (expect 401 = auth gate, WAF passed)"
echo "[3] /api/users          -> $(code "$B/api/users")  (expect 401)"
echo "[4] /api/tasks?page=1&sort=name -> $(code "$B/api/tasks?page=1&sort=name")  (expect 401)"
echo "[5] /api/tasks/123/annotations -> $(code "$B/api/tasks/123/annotations")  (expect 401/404)"
echo "[6] /api/tasks?search=car%20crash -> $(code "$B/api/tasks?search=car%20crash")  (expect 401)"
echo "[7] /admin              -> $(code "$B/admin")  (expect 301/302)"
echo "[8] /django-rq          -> $(code "$B/django-rq")  (expect 401/200/302)"
echo "[9] /static/            -> $(code "$B/static/")  (expect 401/404)"

echo
echo "=== ATTACK PROBES (expect 403) ==="
echo "[A] /api/.env           -> $(code "$B/api/.env")"
echo "[B] /api/?id=1 OR 1=1   -> $(code "$B/api/?id=1%20OR%201=1")"
echo "[C] /api/tasks?id=1 UNION SELECT -> $(code "$B/api/tasks?id=1%20UNION%20SELECT%20NULL--")"
echo "[D] /api/?q=<script>    -> $(code "$B/api/?q=%3Cscript%3Ealert(1)%3C/script%3E")"
echo "[E] /api/admin/../../etc/passwd -> $(code "$B/api/admin/../../etc/passwd")"

echo
echo "=== CVAT UI (separate router, NO middleware yet — informational) ==="
echo "[X] / (cvat_ui)         -> $(code "$B/")  (200 expected)"
