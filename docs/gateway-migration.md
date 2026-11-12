# Gateway Migration Record — Traefik ย้ายออกจาก CVAT (2026-11-12)

> สถานะ: **เสร็จสมบูรณ์ + ตรวจสอบแล้ว** — Traefik เป็น gateway อิสระพร้อม CrowdSec AppSec

## สิ่งที่เปลี่ยน

| รายการ | ก่อน | หลัง |
|---|---|---|
| Traefik | service ใน `C:\Docker\cvat\docker-compose.yml` (line 265) | stack อิสระที่ `C:\Docker\gateway\` (image v3.6 เดิม) |
| Config แหล่งเดียวกัน | env vars `TRAEFIK_*` | file `traefik.yml` (mount) + env `CVAT_HOST`/`DJANGO_LOG_VIEWER_*` สำหรับ template rule |
| Access log | stdout (`docker logs`) | ไฟล์ `/var/log/traefik/access.log` (volume `traefik_logs`, format/fields เดิม) |
| CrowdSec | ไม่มี | container `gateway-crowdsec` (AppSec WAF :7422 + LAPI :8080, ไม่เปิด port สู่ host) |
| PostgreSQL | ไม่มี | `gateway-postgres` (pgvector/pg16) สำหรับเฟส Learning |
| Entry points | web :8080 | web :8080 + **pilot :80** + **pilotsecure :8443** (ใหม่, ยังไม่มี router) |
| Ports ที่ host | 8080, 28080, 8090 | เหมือนเดิม + 80, 8443 |
| Networks | cvat_cvat | cvat_cvat + gateway_net (10.210.2.0/24) + edge_web (10.210.1.0/24) |
| Rule files | `C:\Docker\cvat\components\analytics\*.yml` | **mount จากที่เดิม ไม่ได้ย้ายไฟล์** |

## สิ่งที่ตรวจสอบแล้ว (ผลจริงหลัง cutover)

| Test | ผล |
|---|---|
| CVAT API `/api/server/about` | 200 = baseline ✓ |
| CVAT UI `/` | 200 ✓ |
| agents-office | 200 ✓ |
| grafana `/analytics` | 401 (forwardauth ทำงาน) ✓ |
| AppSec: `/.env` | **403 + alert (kind=waf)** ✓ |
| AppSec: `/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841) | **403** ✓ |
| AppSec: `/.git/config` | **403** ✓ |
| IP ban (`cscli decisions add`) | **403 Forbidden** ทุก route + ปลดแล้วกลับมา 200 ✓ |
| Plugin ↔ LAPI | query `/v1/decisions` ทุก request ✓ |

## จุดที่ต้องรู้

1. **CVAT compose** — traefik block ถูกคอมเมนต์ (`#[gateway-migration]` lines 265–316), backup ที่ `docker-compose.yml.bak-gateway-migration`
2. **ห้ามรัน** `docker compose up` ใน C:\Docker\cvat ก่อนเว้นแต่ restore ครบ — port 8080 จะชนกับ gateway
3. `docker logs traefik` ไม่มี access log แล้ว (อยู่ที่ไฟล์ใน volume) — ดูด้วย `docker exec traefik tail /var/log/traefik/access.log`
4. Error `grafana_https@file: EntryPoint doesn't exist` เป็น **noise เดิม** (rule อ้าง websecure ที่ไม่เคยมีมาตั้งแต่แรก — router ตัวนั้นไม่เคย active) ไม่กระทบอะไร
5. CrowdSec v1.8: acquis ต้องใช้ `listen_addr: 0.0.0.0:7422` (field `appsec_port` ถูกถอดแล้ว) และ mount ต้องเป็นชื่อไฟล์ `acquis.yaml` เท่านั้น
6. Plugin v1.3.5 option ที่ถูกต้อง: `crowdsecAppsecEnabled`, `crowdsecAppsecHost`, `crowdsecAppsecFailureBlock` (ตรวจจากซอร์สใน /plugins-storage)

## OWASP CRS เปิดใช้แล้ว (2026-11-12) — defense-in-depth ครบ

AppSec ตอนนี้โหลด **3 ชั้น rules พร้อมกัน** ผ่าน config เดียว (`custom/edge-crs-full`):

| ชั้น | จับอะไร | ผลทดสอบ |
|---|---|---|
| vpatch-CVE-* | โจมตีช่องโหว่ที่รู้จัก (200+ rules, อัปเดตถึง CVE-2026) | 403 ✓ |
| generic-rules | .env/.git probe, RCE ทั่วไป | 403 ✓ |
| **OWASP CRS (in-band)** | SQLi/XSS/LFI/RCE แบบ anomaly scoring (เกณฑ์ block ที่ 5) | **403 ทุก payload** ✓ |

- FP check ผ่าน 8/8 (Thai UTF-8, quotes, base64 token, pagination, HTML fragment, REST path)
- Alert แสดงรายละเอียด scoring เช่น `sql_injection: 30, anomaly: 30` → มีข้อมูลป้อน edge-ai วิเคราะห์
- ข้อจำกัดเทคนิคที่ต้องรู้ (บันทึกไว้เพื่อไม่ให้เจอซ้ำ):
  1. CrowdSec v1.8.2 ยังไม่รองรับ `appsec-configs:` (list) ใน acquis — ใช้ singular `appsec_config:` + merged config แทน (รองรับเมื่อ CrowdSec รุ่นใหม่ออก)
  2. `crowdsecurity/crs` appsec-rule ต้องอยู่ใน COLLECTIONS env ของ compose (ไฟล์ hub อยู่บน container fs — recreate แล้วหายถ้าไม่ใส่)
  3. CRS ใช้เวลาโหลดครั้งแรก ~30-60 วิ — AppSec port 7422 ขึ้นช้ากว่า LAPI เสมอ
- หากเจอ FP ตอนผูก route จริง: เปลี่ยน CRS เป็น out-of-band (monitor) ชั่วคราว หรือติดตั้ง exclusion plugin จาก hub เช่น `crowdsecurity/appsec-crs-exclusion-plugin-wordpress`

## แก้ ewiki 502: Docker Desktop WSL integration (2026-11-12) ✅

/ewiki → upstream 127.0.0.1:18490 (ewiki-caddy) ที่รันผ่าน compose **ใน WSL Ubuntu**
แต่ Docker Desktop settings: IntegratedWslDistros = [] (integration ปิด — น่าจะหลัง crash/reinstall)
→ docker CLI หายจาก Ubuntu → compose up ไม่ได้ → caddy หาย → 502

**แก้:** settings-store.json → IntegratedWslDistros = ['Ubuntu'] + restart Docker Desktop
→ compose up ใหม่ใน Ubuntu → caddy Started → 18490 → /ewiki 200 ✓

**สอนเทียบ:** เวลา app ใน WSL compose หาย ให้เช็ค Docker Desktop → Settings →
Resources → WSL Integration → เปิด distro ที่เกี่ยว → Apply

## ความพยายามผนวก host traefik (sanuk-traefik) — ยังไม่สำเร็จ (2026-11-12)

**สิ่งที่พบ:**
1. Host traefik = Windows service `sanuk-traefik` (`C:\tools\traefik\`, LocalSystem, v3.7.17)
   เป็นประตูหลัก: Funnel :443 → :9000 → พอร์ทัล + 15 apps (routes.yml 44 routers)
2. ผูก crowdsec plugin (v1.3.5) สำเร็จ (Plugins loaded ✓) แต่ plugin **ต่อ LAPI/AppSec ไม่ได้**
   → fail-closed 403 ทุก request (2.6s timeout) รวมถึง PC จริงของผู้ใช้ (100.96.132.9)
3. สาเหตุที่พบ: **Docker loopback publish (127.0.0.1:8085/8086) ใช้ไม่ได้จาก service context**
   (host shell curl ได้ ✓ แต่ plugin ไม่ถึง — zero LAPI/AppSec hits) + Docker Desktop
   crash-loop ซ้ำหลายรอบทำให้ port forwarding ทั้งเครื่องพังเป็นระยะ
4. ย้ายไป bind Tailscale IP (100.99.80.84:8085/8086) ก็ยัง fail จาก service context
   (host shell ถึง ✓) — น่าจะเป็นข้อจำกัดระดับ OS ของ LocalSystem + docker proxy chain

**สถานะปัจจุบัน:** ผนวกกลับถอย (remove_crowdsec_host_traefik.py) — พอร์ทัลกลับสู่สภาพ
pre-EdgeGuard (ทำงานปกติ 200 ทุก path, ไม่มี WAF) — EdgeGuard stack เองยังคุ้ม
CVAT/funnel ERPNext paths ครบ ✓

**ทางไปต่อ (ต้อง elevated terminal จากผู้ใช้):**
1. ยืนยันสมมุติฐาน: รัน curl ไป 127.0.0.1:8085 ในบริบท SYSTEM (schtasks /ru SYSTEM)
2. ถ้ายืนยันว่า SYSTEM เข้า docker loopback publish ไม่ได้ → ทางเลือก:
   a. publish LAPI/AppSec บน TS IP (100.99.80.84:8085/8086 ทำแล้ว ✓) + ตรวจ firewall
   b. เปลี่ยน service LogOnAccount ของ sanuk-traefik เป็น user account
   c. วินิจฉัย Docker Desktop loopback forwarding (อาจต้อง update/reinstall)
3. เมื่อ plugin ต่อ LAPI ได้ → รัน attach_crowdsec_host_traefik.py (URL TS IP พร้อมแล้ว)
   → restart service → พอร์ทัลครอบ WAF ครบ + ใส่ allow rule เฉพาะ Origin ตามแผน

**ไฟล์/script ที่เกี่ยว:** tools/attach_crowdsec_host_traefik.py (URL TS IP พร้อม),
tools/remove_crowdsec_host_traefik.py (ย้อนกลับ), backups ที่ <file>.bak-crowdsec-removal
+ .bak-edgeguard ใน C:\tools\traefik\

## เฟส 10c: Funnel (อินเทอร์เน็ต) เข้า EdgeGuard (2026-11-12) ✅

**ช่องโจมตีจากอินเทอร์เน็ตจริง** เดิม: `Funnel → caddy (18112/18480/8101/18110)` ไม่มี WAF เลย
ตอนนี้: `Funnel :10000 → Traefik :8080 → crowdsec → upstream เดิม`

| Funnel path | ผลทดสอบ (ผ่าน ts.net จริง) |
|---|---|
| /desk, /app, /api/*, /login (ERPNext) | 200/301/401 ปกติ ✓ |
| /forgemind, /demo | 200/308 ✓ |
| /desk/.env probe | **403** ✓ |
| /api/v2?id=1 OR 1=1 | **403** ✓ |
| **Real client IP** | CrowdSec เห็น `100.99.80.84` (XFF trusted) ไม่ใช่ NAT ✓ |

### การตั้งค่าที่เพิ่ม
1. `traefik/dynamic/funnel.yml` — routers ERPNext/forgemind/demo (priority 1000) → upstream containers ตรง (traefik join 4 networks ใหม่)
2. Traefik entrypoint `web` + plugin: `forwardedHeaders.trustedIPs = 127.0.0.1/32, 172.16.0.0/12` (docker proxy hairpin + tailscale funnel) → **CrowdSec เห็น IP ผู้โจมตีจริง**
3. Tailscale serve: 15 paths บน :10000 เปลี่ยน backend → 127.0.0.1:8080 (Traefik)

### Rollback (คืนเส้นทางเดิมทีละ path)
```bash
tailscale funnel --bg --https=10000 --set-path=/app http://127.0.0.1:18112/app
tailscale funnel --bg --https=10000 --set-path=/desk http://127.0.0.1:18112/desk
# ... (ทุก path กลับไป 18112/8101/18110 ตามเดิม — รายการเต็มอยู่ใน git history ของไฟล์นี้)
```

### ช่องที่ยังเหลือ (ถัดไป)
- Funnel `/` → 18480 (insureai) ยังไม่ผ่าน WAF (ต้องหา path ที่ไม่ชน agents-office ก่อน)
- Funnel `:443` → 127.0.0.1:9000 = host "traefik" process (config ของเดิม ต้องการข้อมูลจากเจ้าของ)
- `:8443/:8445` tailnet-only (ความเสี่ยงต่ำ — ต้องมี Tailscale identity)

## เฟส 5-7: Detection + Decision + Defense ครบวงจร (2026-11-12) ✅

**วงจร 6 Agent ปิดครบครั้งแรก:**

```
probe → WAF บล็อก → alert → watcher → Analysis Agent → incident (PG)
  → Detection Agent: cluster เป็น campaigns
  → Decision Agent: Policy Engine (deterministic YAML) ตัดสิน proposal
      verdict=approve + dry-run → pending_approval (รอคน)
      verdict=approve + auto   → executed (L1 เท่านั้น)
      protected range          → pending_approval เสมอ
      unknown action/type      → rejected
  → Human: POST /api/v1/decisions/{id}/approve → Defense executor
  → CrowdSec ban (origin=edgeguard-ai, auto-expire = Automatic Unblock)
```

ผลทดสอบจริง: approve decision #1 → ban 172.20.0.1 (30m) → ยืนยันใน cscli → unban cleanup ✓
26 decisions ถูกประเมินถูกต้อง: protected range → pending, proposal ผิดประเภท → rejected

**บทเรียนเทคนิค:**
1. CrowdSec v1.8.2 push decision ผ่าน **POST /v1/alerts** (POST /v1/decisions = 405) — body ต้องมี origin/scenario/events_count/leakspeed/scenario_hash/meta/source.scope ครบ (validation เข้ม)
2. `labels` เป็น []string ไม่ใช่ object
3. Decision ของ edgeguard-ai auto-expire ตาม duration = "Automatic Unblock" ตาม policy L1
4. Docker Desktop บนเครื่องเจอ crash-loop 1 ครั้ง (engine pipe หาย) — container ทุกตัว auto-recover ตาม restart policy ถูกต้อง, แก้ด้วย start Docker Desktop.exe ใหม่

**สถานะ safety:** DEFENSE_AUTO_EXECUTE=false (dry-run) — auto mode จะเปิดหลังเฝ้าดู dry-run ผ่าน 3-7 วัน; protected ranges (LAN/Tailscale) ต้อง approve ด้วยมนุษย์เสมอ

## เฟส 4: Auto-ingestion เสร็จ (2026-11-12) ✅

pipeline อัตโนมัติเต็มรูปแบบ:

```
CrowdSec alert → watcher (poll 30s, dedupe by alert_id UNIQUE in PG)
  → Redis stream edge:events (consumer group workers)
  → worker → Analysis Agent (typhoon2.5-qwen3-4b, compact evidence, 120s timeout)
  → PostgreSQL incidents (event jsonb + analysis jsonb)
  → GET /api/v1/incidents
```

ผลทดสอบ: backlog 25 alerts วิเคราะห์ครบ + ยิง alert ใหม่ → auto-analyze ใน ~45 วิ ได้ "Path Traversal / LFI (high, conf 0.9)"

**บทเรียนเทคนิค (เจอตอน debug):**
1. LAPI v1.8.2: JSON ใช้ `message`/`scenario` (ไม่ใช่ `reason` — เป็น null), `source` เอกพจน์, `since` param ให้ HTTP 500 (ใช้ "ล่าสุด 100 + DB dedupe" แทน)
2. redis-py asyncio คืน stream fields เป็น **bytes** — ต้อง `decode_responses=True` ไม่งั้น `fields.get("json")` เจอ None และทุก event ถูก silent-ack (ตรวจยากเพราะไม่มี error!)
3. โมเดล 4B ตอบ JSON เปล่าเมื่อ evidence สั้น → มี **deterministic fallback classifier** (จาก reason keyword) + `needs_human_review=true` เสมอเมื่อ fallback
4. Worker มี pending-drain (XAUTOCLAIM) กัน event ค้างเวลา restart + per-event timeout 120s
5. POST /api/v1/incidents/requeue = ยิง backlog วิเคราะห์ซ้ำได้

## Route ที่ 3-4: agents-office + grafana (2026-11-12) ✅

ผ่าน rule file (Traefik file provider) — เพิ่ม `crowdsec@docker` เข้า middleware chain:

- **agents-office** (`agents-office.yml`): `/` 200, probe (.env/SQLi/.git) 403 ครบ
- **grafana** (`grafana_conf.yml`): `/analytics` 401 (forwardauth เดิมทำงาน), SQLi/.env 403 ครบ — ใส่ `crowdsec@docker` **ก่อน** analytics-auth เพื่อบล็อกก่อน forward

### บทเรียน: rule file edits ไม่ reload เอง

Traefik fsnotify **ไม่ทำงานข้าม Windows→WSL2 bind mount** — แก้ไฟล์ rule ที่ `C:\Docker\cvat\components\analytics\` แล้วต้อง `docker restart traefik` (blip ~5 วิ) เสมอ ตรวจว่า reload แล้วด้วย probe test

copy ของ rule file เก็บที่ repo: `edge-guard/cvat-rules/` (live ยัง mount จาก C:\Docker\cvat)

## Route ที่ 2: cvat_ui (2026-11-12) ✅

| ทดสอบ | ผล |
|---|---|
| UI ปกติ: /, /login, /tasks/123, /projects/1/jobs, /favicon.ico | 200 ครบ (SPA fallback ทำงาน) ✓ |
| /.env, /.git/config, /phpunit/..., /?id=1 OR 1=1 | **403** ✓ |
| /wp-login.php, /actuator/env | 200 — probe เฉพาะแพลตฟอร์มที่ ruleset ไม่ครอบ (gap รู้ก่อน, เสริม rule ภายหลังได้) |
| alert "Enabling body inspection" | informational — AppSec เตือนว่าต้อง forward body เพื่อตรวจ POST (plugin จัดการอยู่แล้ว) |

สถานะ route ทั้งหมดของ CVAT-family: cvat_server ✅ → cvat_ui ✅ → agents-office ⬜ → grafana ⬜ → aitradinghunter ⬜

## Route แรกที่ผูกจริง: cvat_server (2026-11-12) ✅

`cvat_server` เป็น route แรกที่อยู่หลัง `crowdsec@docker` — ผลทดสอบบน route จริง:

| ประเภท | ผล |
|---|---|
| /api/server/about, /api/tasks?page=.., /api/users, /admin, /django-rq | 200/401/301 ปกติ — **ไม่มี FP** ✓ |
| /api/.env, /api/?id=1 OR 1=1, UNION SELECT, `<script>` | **403 + alert (anomaly scoring ระบุชนิด)** ✓ |
| `/api/?file=..%2f..%2fetc%2fpasswd`, double-encoded | 403 + alert (lfi: 40) ✓ |
| `/static/` 403 | ไม่ใช่ WAF — nginx ปฏิเสธ directory listing เอง (ไม่มี alert) ✓ |
| `/api/admin/../../etc/passwd` (raw) และ `%2e%2e` (single-encoded) ผ่าน | Traefik normalize path ก่อน router matching → backend nginx ก็ไม่ serve — risk ต่ำ, จดไว้ตรวจซ้ำ |

### บทเรียนสำคัญ: CVAT_HOST (อย่าให้เจอซ้ำ)

Label rule ของ CVAT ใช้ `${CVAT_HOST:-localhost}` — ถ้ารัน `docker compose up` โดย session ไม่มี CVAT_HOST จะได้ rule `Host('localhost')` → router จับ `/api/*` ไม่ตอบ ทุก request หล่นไป router ของ cvat-ui (200 index.html หมด — ดูเหมือน "ปกติ" แต่จริง ๆ คือ routing พัง และไม่ผ่าน WAF!)

**แก้ถาวรแล้ว:** เพิ่ม `CVAT_HOST=llm-server` ลง `C:\Docker\cvat\.env` (compose อ่านอัตโนมัติทุกครั้ง)
**วิธีตรวจ:** `docker inspect cvat_server --format '{{index .Config.Labels "traefik.http.routers.cvat.rule"}}'` ต้องขึ้น `Host('llm-server')`

### คำสั่งทดสอบซ้ำ

```bash
bash tools/cvat_route_test.sh      # FP + probe บน cvat_server
bash tools/fp_test.sh              # FP ชุดกลาง (test router)
```

## Rollback (ถ้าต้องการกลับไปของเดิม)

```bash
cd C:\Docker\gateway && docker compose down     # ปล่อย ports
cd C:\Docker\cvat
copy docker-compose.yml.bak-gateway-migration docker-compose.yml   # คืน compose เดิม (แทนที่แบบ overwrite)
docker rename traefik-cvat-old traefik
docker start traefik
# ผลลัพธ์: routing กลับสู่สถานะก่อน migration ทุกอย่าง (ยกเว้น CrowdSec หายไป)
```

## การป้องกัน route ต่อไป (ทีละเส้น, ไม่กระทบทั้งระบบ)

ผูก middleware ให้ router ใด ๆ ได้ด้วย label เดียว:

```yaml
# ใน compose ของ project นั้น (container ที่มี traefik labels อยู่แล้ว)
labels:
  - traefik.http.routers.<router-name>.middlewares=crowdsec@docker
```

หรือสำหรับ route ที่นิยามใน rule file (agents-office/grafana):

```yaml
# เพิ่มใน routers ของ C:\Docker\cvat\components\analytics\*.yml
routers:
  agentsoffice:
    middlewares:
      - crowdsec@docker
```

ลำดับแนะนำ: cvat_server → cvat_ui → agents-office → grafana → aitradinghunter (ทดสอบ false positive หลังแต่ละตัว)

---

## สรุปปัญหา Docker port-forwarding + สถานะสุดท้าย (2026-11-12 ดึก)

**อาการ:** หลัง Docker Desktop crash ×5 (วันเดียว) — port publishing บางตัวส่ง traffic
ไม่ได้เป็นระยะ (000/502/403 สลับกัน) แม้ netstat เห็น LISTENING (com.docker.backend
PID 4812) — ทดสอบครบแล้ว: NAT mode / mirrored mode / loopback vs TS-IP binds /
Hyper-V firewall Allow — **ต้อง machine reboot เท่านั้น** (reset com.docker.backend
port-forwarding state + WSL + network stack)

**ตาราง port ตรวจสอบสุดท้าย (หลัง restart containers อีกรอบ):**
- 8080 (EdgeGuard traefik) : 200 ✓ recovered
- 100.99.80.84:8099 (edge-ai) : health ok ✓
- 100.99.80.84:8085 (LAPI) : alive ✓ (ตอบแล้ว — ตรวจ path ซ้ำหลัง reboot)
- 100.99.80.84:55000 (Wazuh API HTTPS) : 000 — boot ช้า/forwarding ตาย — retest หลัง reboot
- 9000 (host traefik native) : 200 ✓ (native process ไม่กระทบ)

**เช็คหลัง reboot (ลำดับ):**
1. curl http://100.99.80.84:8085/health → ตรวจ LAPI
2. curl -H Host llm-server http://localhost:8080/api/server/about → 200
3. curl http://100.99.80.84:8099/health → ok
4. Wazuh https://100.99.80.84:55000 (HTTPS) → 200
5. ถ้าครบ = ระบบกลับมาเต็ม 100% — ต่อด้วย Windows agent install (MSI พร้อมที่ wazuh/)
