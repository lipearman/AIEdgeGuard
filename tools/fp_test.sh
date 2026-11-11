#!/usr/bin/env bash
# False-positive checks against the CRS-enabled AppSec — every case should return 200
H='Host: test.edgeguard.local'
U='http://localhost:80'
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 8 -H "$H" "$1"; }

echo "[1] search with space:   $(code "$U/?search=iphone%2015%20pro%20max")  (expect 200)"
echo "[2] Thai UTF-8 text:     $(code "$U/?q=%E0%B8%AA%E0%B8%A7%E0%B8%B1%E0%B8%AA%E0%B8%94%E0%B8%B5%20%E0%B8%84%E0%B8%A3%E0%B8%B1%E0%B8%9A")  (expect 200)"
echo "[3] quotes in search:    $(code "$U/?q=it's%20a%20test&sort=desc")  (expect 200)"
echo "[4] pagination+filter:   $(code "$U/products?page=2&sort=price&order=desc&filter=red%20shoes")  (expect 200)"
echo "[5] base64-like token:   $(code "$U/verify?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123xyz")  (expect 200)"
echo "[6] math formula text:   $(code "$U/calc?a=1+1%3D2")  (expect 200)"
echo "[7] REST-style path:     $(code "$U/api/users/123/comments")  (expect 200)"
echo "[8] html fragment text:  $(code "$U/comment?text=hello%20%3Cb%3Ebold%3C/b%3E%20world")  (expect 200)"

echo
echo "=== CVAT ROUTE SANITY (no middleware attached, expect 200) ==="
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: llm-server" http://localhost:8080/api/server/about

echo
echo "=== ALERTS GENERATED ==="
cd "C:/Docker/gateway" && docker compose exec -T crowdsec cscli alerts list 2>/dev/null | head -10
