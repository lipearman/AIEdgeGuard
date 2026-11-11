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
