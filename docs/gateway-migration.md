# Gateway Migration Record — Traefik ย้ายออกจาก CVAT (2026-11-12)

> ผลตรวจและการเก็บงานรอบล่าสุดดู [current-status.md](current-status.md): API อัปเดตแล้ว health ผ่านทั้ง 4 บริการ ส่วนข้อความด้านล่างเก็บเป็นประวัติตามแต่ละช่วงเวลา

> สถานะ: **เสร็จสมบูรณ์ + ตรวจสอบแล้ว** — Traefik เป็น gateway อิสระพร้อม CrowdSec AppSec

## สิ่งที่เปลี่ยน

| รายการ               | ก่อน                                                      | หลัง                                                                                    |
| -------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Traefik              | service ใน `C:\Docker\cvat\docker-compose.yml` (line 265) | stack อิสระที่ `C:\Docker\gateway\` (image v3.6 เดิม)                                   |
| Config แหล่งเดียวกัน | env vars `TRAEFIK_*`                                      | file `traefik.yml` (mount) + env `CVAT_HOST`/`DJANGO_LOG_VIEWER_*` สำหรับ template rule |
| Access log           | stdout (`docker logs`)                                    | ไฟล์ `/var/log/traefik/access.log` (volume `traefik_logs`, format/fields เดิม)          |
| CrowdSec             | ไม่มี                                                     | container `gateway-crowdsec` (AppSec WAF :7422 + LAPI :8080, ไม่เปิด port สู่ host)     |
| PostgreSQL           | ไม่มี                                                     | `gateway-postgres` (pgvector/pg16) สำหรับเฟส Learning                                   |
| Entry points         | web :8080                                                 | web :8080 + **pilot :80** + **pilotsecure :8443** (ใหม่, ยังไม่มี router)               |
| Ports ที่ host       | 8080, 28080, 8090                                         | เหมือนเดิม + 80, 8443                                                                   |
| Networks             | cvat_cvat                                                 | cvat_cvat + gateway_net (10.210.2.0/24) + edge_web (10.210.1.0/24)                      |
| Rule files           | `C:\Docker\cvat\components\analytics\*.yml`               | **mount จากที่เดิม ไม่ได้ย้ายไฟล์**                                                     |

## สิ่งที่ตรวจสอบแล้ว (ผลจริงหลัง cutover)

| Test                                                           | ผล                                                |
| -------------------------------------------------------------- | ------------------------------------------------- |
| CVAT API `/api/server/about`                                   | 200 = baseline ✓                                  |
| CVAT UI `/`                                                    | 200 ✓                                             |
| agents-office                                                  | 200 ✓                                             |
| grafana `/analytics`                                           | 401 (forwardauth ทำงาน) ✓                         |
| AppSec: `/.env`                                                | **403 + alert (kind=waf)** ✓                      |
| AppSec: `/phpunit/src/Util/PHP/eval-stdin.php` (CVE-2017-9841) | **403** ✓                                         |
| AppSec: `/.git/config`                                         | **403** ✓                                         |
| IP ban (`cscli decisions add`)                                 | **403 Forbidden** ทุก route + ปลดแล้วกลับมา 200 ✓ |
| Plugin ↔ LAPI                                                  | query `/v1/decisions` ทุก request ✓               |

## จุดที่ต้องรู้

1. **CVAT compose** — traefik block ถูกคอมเมนต์ (`#[gateway-migration]` lines 265–316), backup ที่ `docker-compose.yml.bak-gateway-migration`
2. **ห้ามรัน** `docker compose up` ใน C:\Docker\cvat ก่อนเว้นแต่ restore ครบ — port 8080 จะชนกับ gateway
3. `docker logs traefik` ไม่มี access log แล้ว (อยู่ที่ไฟล์ใน volume) — ดูด้วย `docker exec traefik tail /var/log/traefik/access.log`
4. Error `grafana_https@file: EntryPoint doesn't exist` เป็น **noise เดิม** (rule อ้าง websecure ที่ไม่เคยมีมาตั้งแต่แรก — router ตัวนั้นไม่เคย active) ไม่กระทบอะไร
5. CrowdSec v1.8: acquis ต้องใช้ `listen_addr: 0.0.0.0:7422` (field `appsec_port` ถูกถอดแล้ว) และ mount ต้องเป็นชื่อไฟล์ `acquis.yaml` เท่านั้น
6. Plugin v1.3.5 option ที่ถูกต้อง: `crowdsecAppsecEnabled`, `crowdsecAppsecHost`, `crowdsecAppsecFailureBlock` (ตรวจจากซอร์สใน /plugins-storage)

## OWASP CRS เปิดใช้แล้ว (2026-11-12) — defense-in-depth ครบ

AppSec ตอนนี้โหลด **3 ชั้น rules พร้อมกัน** ผ่าน config เดียว (`custom/edge-crs-full`):

| ชั้น                    | จับอะไร                                                  | ผลทดสอบ               |
| ----------------------- | -------------------------------------------------------- | --------------------- |
| vpatch-CVE-*            | โจมตีช่องโหว่ที่รู้จัก (200+ rules, อัปเดตถึง CVE-2026)  | 403 ✓                 |
| generic-rules           | .env/.git probe, RCE ทั่วไป                              | 403 ✓                 |
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

- .bak-edgeguard ใน C:\tools\traefik\

## เฟส 10c: Funnel (อินเทอร์เน็ต) เข้า EdgeGuard (2026-11-12) ✅

**ช่องโจมตีจากอินเทอร์เน็ตจริง** เดิม: `Funnel → caddy (18112/18480/8101/18110)` ไม่มี WAF เลย
ตอนนี้: `Funnel :10000 → Traefik :8080 → crowdsec → upstream เดิม`

| Funnel path                           | ผลทดสอบ (ผ่าน ts.net จริง)                                      |
| ------------------------------------- | --------------------------------------------------------------- |
| /desk, /app, /api/*, /login (ERPNext) | 200/301/401 ปกติ ✓                                              |
| /forgemind, /demo                     | 200/308 ✓                                                       |
| /desk/.env probe                      | **403** ✓                                                       |
| /api/v2?id=1 OR 1=1                   | **403** ✓                                                       |
| **Real client IP**                    | CrowdSec เห็น tailnet IP จริงจาก XFF ที่ trust ไว้ ไม่ใช่ NAT ✓ |

### การตั้งค่าที่เพิ่ม

1. `traefik/dynamic/funnel.yml` — routers ERPNext/forgemind/demo (priority 1000) → upstream containers ตรง (traefik join 4 networks ใหม่)
2. Traefik entrypoint `web` + plugin: `forwardedHeaders.trustedIPs = 127.0.0.1/32, 172.16.0.0/12` (docker proxy hairpin + tailscale funnel) → **CrowdSec เห็น IP ผู้โจมตีจริง**
3. Tailscale serve: 15 paths บน :10000 เปลี่ยน backend → 127.0.0.1:8080 (Traefik)

### ⚠️ บทเรียนสำคัญ: tailscale serve/funnel **ตัด `--set-path` ทิ้ง** (2026-11-12)

อาการที่เจอ: เปิด `https://llm-server.tail923b9a.ts.net:10000/erpnext` แล้วได้หน้า **agents-office**
(ไม่ตรงกับ path) — ทุก path บน :10000 แสดงหน้าเดียวกันหมด

**สาเหตุ:** `tailscale serve/funnel` ตัด prefix ที่ mount ออกก่อน proxy (ไม่มี `X-Forwarded-Prefix`)
handler ที่ mount ที่ `/desk` และ target เป็น `http://127.0.0.1:8080` จะทำให้ Traefik ได้ path `/`
→ ไป match router `agentsoffice` ที่ rule เป็น Host-only (ไม่ระบุ path) → ตอบหน้า agents-office ทุกครั้ง

พิสูจน์ด้วย path-echo probe (2026-11-12):

```text
mount /__probe, target http://127.0.0.1:18098        → proxy เห็น path "/abc/def"      (prefix หาย)
mount /__probe, target http://127.0.0.1:18098/__probe → proxy เห็น path "/__probe/abc/def" (ครบ)
```

**แก้:** ทุก handler ต้อง "ใส่ path เดิมซ้ำ" ใน target:

```bash
tailscale funnel --bg --https=10000 --set-path=/desk http://127.0.0.1:8080/desk
tailscale funnel --bg --https=10000 --set-path=/erpnext http://127.0.0.1:8080/erpnext
# ... ทุก path ของ :10000 และ path ของ :8443 ที่ชี้ 8080
```

สคริปต์ที่ใช้แก้ทั้งชุด: `C:\Users\Admin\AppData\Local\Temp\opencode\fix_funnel_prefix.ps1`
(อ่าน `tailscale serve status --json`, เติม path ให้ handler ที่ target เป็น `http://127.0.0.1:8080` และ path ≠ `/`)

**ตรวจซ้ำ:** `docker exec traefik tail /var/log/traefik/access.log` ต้องเห็น
`"RouterName":"funnel-erpnext@file"` (ไม่ใช่ `agentsoffice@file`) และ `/erpnext` → 302 `/desk`

### ปิดช่องสาธารณะ `:443 /AIEdgeGuard` + ใส่ WAF/auth (2026-11-12) ✅

**ช่องโหว่ที่พบ:** `AllowFunnel` เปิดทั้ง port `:443` (ไม่ใช่แค่ path ที่ตั้งใจ) ทำให้
`https://llm-server.tail923b9a.ts.net/AIEdgeGuard/*` ออกอินเทอร์เน็ตได้จริง **โดยไม่มี WAF
และไม่มี auth** — ยืนยันด้วย `GET /AIEdgeGuard/api/v1/policy` = 200 และ
`/AIEdgeGuard/DashBoard` = 200 (ใครก็สั่ง approve/ban ผ่าน API ได้)

**แก้ 2 ชั้น:**

1. ลบ handler สาธารณะออกจาก funnel (dashboard ยังใช้ผ่าน tailnet `:8443` ได้):
   ```powershell
   tailscale serve --https=443 --set-path=/AIEdgeGuard off
   ```
   ตรวจแล้ว: `/AIEdgeGuard/api/v1/policy` และ `/AIEdgeGuard/DashBoard` บน `:443` → **404**
2. router `funnel-aiedge` (ใช้โดย tailnet `:8443`) เพิ่ม middleware:
   ```yaml
   middlewares:
     - crowdsec@docker # WAF ก่อน
     - aiedge-auth # HTTP Basic auth
     - strip-aiedge
   ```
   พร้อม middleware ใหม่ใน `funnel.yml`:
   ```yaml
   aiedge-auth:
     basicAuth:
       users:
         - "admin:$2b$10$tyYD/jsheM09lTc5QYJCU.TKRbPqwc3uE8ymIzBbe0EChn5XbjokK"
   ```

**ผลทดสอบ:** `:8443/AIEdgeGuard/health` → **401** ไม่ใส่ creds, **200** ใส่ creds;
`/AIEdgeGuard/.env` (มี creds) → **403** = WAF ทำงาน; `/DashBoard` → 200
(bcrypt `$2b$` ใช้ได้กับ Traefik v3.6)

**การหมุนรหัสผ่าน:**

```bash
python -c "import bcrypt;print(bcrypt.hashpw(b'NEWPASS',bcrypt.gensalt(rounds=10)).decode())"
# แทนที่ users: ใน aiedge-auth แล้ว docker restart traefik (ดูเหตุผลด้านล่าง)
```

**Rollback:** ลบ `aiedge-auth` ออกจาก middlewares ของ `funnel-aiedge` (คง `crowdsec@docker`)
แล้ว `docker restart traefik` — แต่ **อย่า** ใส่ `:443 /AIEdgeGuard` กลับเข้า funnel

### ⚠️ Self-ban: WAF probe จากเครื่อง gateway เองทำให้ gateway ล่ม 4 ชม. (2026-11-12) ✅ แก้แล้ว

หลังทดสอบ `.env` หลายครั้งจากเครื่องนี้เอง CrowdSec สร้าง decision
`Ip:100.99.80.84 / crowdsecurity/http-probing` (4h) → **ทุก path ตอบ 403**
รวม dashboard (`:8443`) และ ERPNext (`:10000`) — อาการเหมือน config พัง แต่จริง ๆ คือ IP ถูกแบน

**สาเหตุ:** curl จากเครื่อง gateway ไปที่ funnel จะได้ `X-Forwarded-For: 100.99.80.84`
(IP tailnet ของเครื่องเอง) → scenario นับว่าเป็น probe → ban IP ตัวเอง

**แก้:** เพิ่ม whitelist (`crowdsec/whitelist-edgeguard.yaml`, mount เป็น
`/etc/crowdsec/parsers/s02-enrich/edgeguard-whitelist.yaml`) ครอบ `100.99.80.84`
และ loopback — CrowdSec จะไม่ ban IP เหล่านี้ แต่ **AppSec ยังตรวจ/บล็อกปกติ**
(`.env` ยังได้ 403 และยังมี WAF alert ป้อน edge-ai) และ client จริงจากอินเทอร์เน็ต
ยังได้ IP ตัวเองใน XFF จึงไม่ถูกกระทบ

**ถ้าเจอ 403 ทั้งระบบอีก:** เช็คก่อนว่าไม่ใช่ config —

```bash
docker exec gateway-crowdsec cscli decisions list
docker exec gateway-crowdsec cscli decisions delete -i <IP>
```

ถ้า recreate container: `cd C:\Docker\gateway && docker compose up -d crowdsec`
(ใช้เวลา ~30-60 วิ กว่า AppSec/CRS จะพร้อม)

### ✅ ย้าย funnel เข้า EdgeGuard ครบ 100% (2026-11-12)

หลัง audit พบว่าเหลือ 6 handler ที่ยังอ้อม Traefik — ย้ายครบแล้วทั้งหมด:

| Tailscale       | path                                 | ปลายทางใหม่ (ผ่าน EdgeGuard)                         |
| --------------- | ------------------------------------ | ---------------------------------------------------- |
| :10000 (funnel) | 15 paths ERPNext/forgemind/demo      | Traefik :8080 (เดิม)                                 |
| :10000 (funnel) | **`/`** (+ ทุก path ที่ไม่ถูก mount) | **entrypoint :8091 → 18480** (insureai caddy)        |
| :443 (funnel)   | **`/`**                              | **entrypoint :8092 → 9000** (portal `sanuk-traefik`) |
| :443 (funnel)   | ~~`/AIEdgeGuard`~~                   | ปิดแล้ว (404)                                        |
| :8443 (tailnet) | `/AIEdgeGuard`, `/aiedge`            | Traefik → edge-ai-api (WAF + Basic auth)             |
| :8443 (tailnet) | `/demo`                              | Traefik → demo portal                                |
| :8443 (tailnet) | **`/`**                              | **entrypoint :8093 → 3100** (forgemind-web)          |
| :8445 (tailnet) | **`/`**                              | **entrypoint :8094 → erpnext-gateway**               |

**ทำไมต้องมี entrypoint แยกต่อพอร์ต:** tailscale ทุกพอร์ตส่ง `Host` เดียวกัน
(`llm-server.tail923b9a.ts.net`) เข้า Traefik ตัวเดียว — ถ้าใช้ catch-all router
`PathPrefix(/)` บน entrypoint `web` ตัวเดียว มันจะจับ root ของ **ทุก** พอร์ตพร้อมกัน
จึงแยก entrypoint ต่อพอร์ต (`funnelroot10000/443/8443/8445` → ในคอนเทนเนอร์ :8091-8094,
publish เฉพาะ `127.0.0.1:18081-18084`) แล้ว tailscale แต่ละพอร์ตชี้ entrypoint ของตัวเอง

**การตั้งค่า:**

1. `traefik/traefik.yml` — เพิ่ม entrypoints `funnelroot10000/443/8443/8445`
   (มี `forwardedHeaders.trustedIPs` เหมือน `web` เพื่อให้ CrowdSec เห็น IP จริง)
2. `docker-compose.yml` — publish `127.0.0.1:18081-18084` (ไม่เปิดสู่ LAN/อินเทอร์เน็ต)
3. `traefik/dynamic/funnel.yml` — routers `funnel-root-10000/443/8443/8445`
   (rule = Host เดียว, priority 1, middleware `crowdsec@docker`) + services
   `funnel-insureai/portal/forgemind-web/erpnext-gateway`
4. tailscale handler เปลี่ยนเฉพาะ root:
   ```powershell
   tailscale funnel --bg --https=10000 --set-path=/ http://127.0.0.1:18081
   tailscale funnel --bg --https=443   --set-path=/ http://127.0.0.1:18082
   tailscale serve  --bg --https=8443  --set-path=/ http://127.0.0.1:18083
   tailscale serve  --bg --https=8445  --set-path=/ http://127.0.0.1:18084
   ```
5. อีก 2 path ของ :8443 ชี้เข้า Traefik ตรง ๆ:
   ```powershell
   tailscale serve --bg --https=8443 --set-path=/demo   http://127.0.0.1:8080/demo
   tailscale serve --bg --https=8443 --set-path=/aiedge http://127.0.0.1:8080/aiedge
   ```
   (`/aiedge` มี router `funnel-aiedge-lower` + `strip-aiedge-lower` + WAF + Basic auth)

**ผลทดสอบจริงหลังสลับ (ผ่าน ts.net):**

| ทดสอบ                                        | ผล                                                            |
| -------------------------------------------- | ------------------------------------------------------------- |
| `:8445 /`, `/login`                          | 200 ✓ (redirect `/desk` → login ถูกต้อง)                      |
| `:8445 /.env`                                | **403** ✓                                                     |
| `:8443 /`                                    | 404 (เหมือนก่อนย้าย — app ไม่มีหน้า root), `/forgemind` 200 ✓ |
| `:8443 /demo/`                               | 200 ✓, `/.env` 403 ✓                                          |
| `:8443 /aiedge/health`                       | **401** ไม่มี creds / **200** มี creds ✓                      |
| `:10000 /`                                   | 307 → `/th` (เหมือนก่อนย้าย) ✓, `/.env` 403 ✓                 |
| `:10000 /claimplus/docs`                     | 307 เหมือนก่อนย้าย (เทียบ baseline 18480 ตรงกัน) ✓            |
| `:443 /` → `/index.html`                     | 302 → 200 (portal "AI Gateway") ✓                             |
| `:443 /.env`                                 | **403** ✓                                                     |
| `:443 /AIEdgeGuard`                          | 404 (ปิดอยู่) ✓                                               |
| portal apps `/ewiki`, `/litellm/ui`          | ผลเท่ากับ baseline 9000 ทุกตัว ✓                              |
| `cscli decisions list` หลังยิง probe ทั้งชุด | **No active decisions** (whitelist ทำงาน) ✓                   |

**ข้อควรระวัง:**

- entrypoint ใหม่ผูก `127.0.0.1` เท่านั้น — ห้ามเปลี่ยนเป็น `0.0.0.0` เพราะจะเปิด root ของ
  app ที่ tailnet-only (`:8443`→3100, `:8445`→ERPNext) สู่อินเทอร์เน็ตโดยข้าม Tailscale identity
- หลัง recreate traefik ต้องรอ ~10-20 วิ ให้ docker provider โหลด middleware `crowdsec@docker`
  (ช่วงนั้น router ที่อ้าง crowdsec จะ error/fail-closed — ไม่ใช่ช่องโหว่)
- ตอนนี้ WAF ครอบ portal `:443` ทั้งหมด รวม API ของ 15 apps — ถ้าเจอ FP ให้ดู alert
  แล้วเพิ่ม exclusion/allow rule

### Rollback (ย้อนการย้าย root ทั้งชุด)

```bash
tailscale funnel --bg --https=10000 --set-path=/ http://127.0.0.1:18480
tailscale funnel --bg --https=443   --set-path=/ http://127.0.0.1:9000
tailscale serve  --bg --https=8443  --set-path=/ http://127.0.0.1:3100
tailscale serve  --bg --https=8443  --set-path=/demo http://127.0.0.1:8101
tailscale serve  --bg --https=8443  --set-path=/aiedge http://127.0.0.1:8080/aiedge
tailscale serve  --bg --https=8445  --set-path=/ http://127.0.0.1:8081
```

ถ้าต้องย้อน config ด้วย: copy จาก `edge-guard/{traefik,docker-compose.yml}` กลับไป
`C:\Docker\gateway\` แล้ว `docker compose up -d traefik`

### Audit เดิม (ก่อนย้าย — เก็บไว้เป็นประวัติ)

### Audit: funnel path ไหนยังไม่ผ่าน EdgeGuard (2026-11-12)

| Tailscale       | path                            | ปลายทาง                                           | ผ่าน EdgeGuard?              |
| --------------- | ------------------------------- | ------------------------------------------------- | ---------------------------- |
| :10000 (funnel) | 15 paths ERPNext/forgemind/demo | Traefik :8080                                     | ✅ WAF (`.env` → 403)        |
| :10000 (funnel) | **`/`**                         | 127.0.0.1:**18480** (insureai caddy)              | ❌ ยังไม่อ้อมเข้า Traefik    |
| :443 (funnel)   | **`/`**                         | 127.0.0.1:**9000** (host traefik `sanuk-traefik`) | ❌ ยังไม่อ้อมเข้า Traefik    |
| :443 (funnel)   | ~~`/AIEdgeGuard`~~              | —                                                 | ✅ **ลบออกแล้ว** (404)       |
| :8443 (tailnet) | `/AIEdgeGuard`                  | Traefik → edge-ai-api                             | ✅ WAF + Basic auth          |
| :8443 (tailnet) | `/`, `/demo`                    | 3100 / 8101                                       | ❌ tailnet-only, ไม่ผ่าน WAF |
| :8443 (tailnet) | `/aiedge`                       | 8080 (ไม่มี router รองรับ)                        | ❌ tailnet-only, 404         |
| :8445 (tailnet) | `/`                             | 8081 (erpnext-gateway)                            | ❌ tailnet-only, ไม่ผ่าน WAF |

สรุป: **15/16 handler ของ funnel `:10000` ผ่าน EdgeGuard** และ `:443 /AIEdgeGuard` ถูกปิดแล้ว;
ที่เหลือคือ `/` ของ `:10000`→18480, `/` ของ `:443`→9000 (สาธารณะ) และ path ที่ tailnet-only

### Rollback (คืนเส้นทางเดิมทีละ path)

```bash
# (ประวัติ) เป้าหมายเดิมก่อนย้ายเข้า Traefik คือ 18112 / 18110 / 8101
# คำสั่ง rollback ปัจจุบันอยู่ที่หัวข้อ "Rollback (ย้อนการย้าย root ทั้งชุด)" ด้านบน
```

หมายเหตุ: ตอน rollback ก็ยังต้องใส่ path ใน target ของ tailscale อยู่ดี
(`http://127.0.0.1:18112/desk`) เพราะ tailscale ตัด prefix ก่อน proxy เหมือนกัน

### ช่องที่ยังเหลือ: ไม่มี (ครอบ 100% แล้ว)

ทุก handler ของ Tailscale (funnel `:10000`, funnel `:443`, tailnet `:8443`/`:8445`)
ชี้เข้า Traefik ที่มี `crowdsec@docker` แล้ว — ตรวจซ้ำได้ด้วย:

```powershell
# ทุก target ต้องเป็น 8080 หรือ 18081-18084 (EdgeGuard entrypoints)
(tailscale serve status --json | ConvertFrom-Json).Web.PSObject.Properties |
  ForEach-Object { $_.Value.Handlers.PSObject.Properties |
    ForEach-Object { "$($_.Name) -> $($_.Value.Proxy)" } }

# WAF ต้องตอบ 403 กับ probe ทุกพอร์ต
foreach ($u in @(
  'https://llm-server.tail923b9a.ts.net/.env',
  'https://llm-server.tail923b9a.ts.net:10000/.env',
  'https://llm-server.tail923b9a.ts.net:8443/.env',
  'https://llm-server.tail923b9a.ts.net:8445/.env')) {
  "$u -> " + (curl.exe -s -o NUL -w "%{http_code}" --max-time 20 $u)
}
```

### Audit end-to-end: 22 handler ผ่าน WAF ครบ + ปิดช่อง bypass `Origin: vercel.app` (2026-11-12)

ตรวจแบบ end-to-end: ยิงจริงผ่าน hostname ทุก handler แล้วเอา token ใน query ไปค้นใน
`/var/log/traefik/access.log` เพื่อดู `RouterName` ที่จับ request นั้นจริง ๆ
และยิง `/.env` ใต้ path เดียวกันเพื่อทดสอบ WAF

**ผลรวม: 22/22 handler ตอบ `403` กับ `/.env` และทุก request ปกติถูกจับโดย router
`funnel-*` (ไม่มีตัวไหนไหลไป `agentsoffice` อีก)**

| กลุ่ม            | handler                                                                                                                                                              | router ที่จับ       | WAF    |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- | ------ |
| `:10000` root    | `/`                                                                                                                                                                  | `funnel-root-10000` | ✅ 403 |
| `:10000` ERPNext | `/app`, `/desk`, `/erpnext`, `/login`, `/files`, `/assets`, `/method`, `/favicon.ico`, `/website_script.js`, `/socket.io`, `/api/v2`, `/api/method`, `/api/resource` | `funnel-erpnext`    | ✅ 403 |
| `:10000` อื่น    | `/forgemind` → `funnel-forgemind`, `/demo` → `funnel-demo`                                                                                                           | —                   | ✅ 403 |
| `:443`           | `/`                                                                                                                                                                  | `funnel-root-443`   | ✅ 403 |
| `:8443`          | `/` → `funnel-root-8443`, `/demo`, `/forgemind`, `/aiedge`, `/AIEdgeGuard`                                                                                           | —                   | ✅ 403 |
| `:8445`          | `/`                                                                                                                                                                  | `funnel-root-8445`  | ✅ 403 |

**ช่องที่พบและปิดแล้ว: `funnel-*-vercel@file` ข้าม WAF ได้**

เดิมมี router 3 ตัว (`funnel-erpnext-vercel`, `funnel-forgemind-vercel`,
`funnel-demo-vercel`) ที่ rule เป็น `HeaderRegexp(Origin, vercel\.app$)` และ
**ไม่มี `crowdsec@docker`** (ใส่ไว้เพื่อกัน false positive จาก frontend Vercel ของเราเอง)
แต่ `Origin` เป็น header ที่ client ควบคุมเองได้ทั้งหมด — ใครก็ส่ง
`Origin: https://evil.vercel.app` แล้วข้าม WAF ได้:

```
ก่อนแก้:  /desk/.env     + Origin: evil.vercel.app -> 301   (ผ่าน WAF ไปแล้ว)
          /forgemind/.env + Origin: evil.vercel.app -> 404
          /demo/.env      + Origin: evil.vercel.app -> 404
          /api/v2?id=1' OR 1=1-- + Origin          -> 404
หลังแก้:  ทั้ง 4 เคส -> 403
          (request ปกติ /login 200, /desk 301, /demo/ 200, /forgemind 200 ไม่กระทบ)
```

แก้โดย **ลบ router ทั้ง 3 ตัวออก** (`edge-guard/traefik/dynamic/funnel.yml`) —
ไม่มี router ไหนที่ข้าม middleware WAF ได้อีก

> **ถ้า WAF กัด frontend Vercel ของเราเองจริง ๆ ในอนาคต:** ห้ามแก้ด้วยการทำ
> bypass ตาม `Origin` (ปลอมได้) ให้ใช้ **AppSec exclusion แคบ ๆ** แทน เช่น
> ยกเว้นเฉพาะ rule id + path ที่ชน (`edge-guard/crowdsec/appsec-rules-edgeguard/`)
> แล้วรีสตาร์ต CrowdSec (ใช้เวลา ~30-60 วิ ให้ CRS/AppSec load ครบ)

### ดู log WAF: request เข้ามาไหม และตัดสินถูกหรือไม่ (2026-11-12)

ต้องดู 3 ชั้นคู่กัน — ชั้นเดียวตอบไม่ได้

| ชั้น                  | เก็บอะไร                                         | คำสั่ง                                                               |
| --------------------- | ------------------------------------------------ | -------------------------------------------------------------------- |
| 1. Traefik access log | ทุก request: path, status, router (มี/ไม่มี WAF) | `docker exec traefik sh -c "tail -n 50 /var/log/traefik/access.log"` |
| 2. CrowdSec alerts    | WAF ตัดสินด้วย rule อะไร + score                 | `docker exec gateway-crowdsec cscli alerts list -l 20`               |
| 3. CrowdSec decisions | IP ที่ถูกแบนจริง (bouncer ใช้ค่านี้)             | `docker exec gateway-crowdsec cscli decisions list`                  |

มีสคริปต์ช่วยแล้ว: `tools/waf-log.ps1`

```powershell
.\tools\waf-log.ps1                 # 30 request ล่าสุด (ทุกสถานะ)
.\tools\waf-log.ps1 -Blocked 50     # 50 ครั้งล่าสุดที่ตอบ 403
.\tools\waf-log.ps1 -Port 8443      # เฉพาะพอร์ต 8443
.\tools\waf-log.ps1 -Alerts 10      # WAF alerts ล่าสุด
.\tools\waf-log.ps1 -Inspect 438    # rule/zones/score ของ alert 438
.\tools\waf-log.ps1 -Decisions      # IP ที่ถูกแบนตอนนี้
.\tools\waf-log.ps1 -Metrics        # สรุปจำนวนบรรทัด/alert
.\tools\waf-log.ps1 -Watch          # ตามสด
```

**อ่านผลอย่างไร**

| สิ่งที่เห็น                                          | แปลว่า                                                                                         |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| access log `403` + alert `kind=waf` ในวินาทีเดียวกัน | WAF บล็อก — ดู `reason` (lfi / sql_injection / xss / vpatch-*) ว่า rule ตรงกับ attack นั้นจริง |
| access log `403` แต่ไม่มี alert                      | **ไม่ใช่ WAF** — แอปปลายทางตอบ 403 เอง (เช่น permission)                                       |
| access log `200`/`3xx` + ไม่มี alert                 | ผ่านปกติ                                                                                       |
| alert มี แต่ `decisions list` ว่าง                   | whitelist กัน ban ไว้ (เคส 100.99.80.84 ของเรา) — ยังบล็อก request อยู่ แต่ไม่แบน IP           |

ตัวอย่างจริง (`.env` probe ที่เรายิงทดสอบ):

```
alert 439 | Ip:100.99.80.84 | anomaly score block: lfi: 5, anomaly: 5, | kind: waf
  matched_zones: REQUEST_FILENAME        <-- ตรงกับ /.env จริง
access log: 403  /login/.env  router=funnel-erpnext@file  port=10000
```

**ข้อควรระวัง**

- access log มี router ของแอปอื่นปนอยู่ด้วย (`aith@docker` จาก docker provider) —
  เวลาตรวจ path ของ hostname ให้กรอง `RouterName -like 'funnel-*'`
- `docker logs gateway-crowdsec` มี warning `falling-water ... ClientAddr` ทุก request
  (parser traefik ของ CrowdSec อ่าน field `ClientAddr` ที่ Traefik v3 เปลี่ยนชื่อ) —
  `cscli metrics` ยังรายงาน `Lines parsed 8.38k / unparsed 0` และ scenario ทำงาน
  (`http-probing`, `vpatch-env-access` ยังขึ้น) จึงเป็น noise ไม่ใช่ของหลุด
- ยังพบ router ที่ไม่มี WAF: `aith@docker` (`PathPrefix(/AiTradingHunter)`, entrypoint `web`)
  → เฉพาะการยิง `:8080` ตรงจาก tailnet/LAN (SQLi → 200) **ไม่กระทบ path ที่ publish ผ่าน
  hostname** (`:443/AiTradingHunter` ยัง 403 เพราะ `funnel-root-443` มี crowdsec)

### บังคับให้เข้าผ่าน hostname (EdgeGuard) เท่านั้น (2026-11-12)

เป้าหมาย: ให้ทางเข้าเดียวคือ `llm-server.tail923b9a.ts.net` (Tailscale serve → EdgeGuard)
— ห้าม tailnet ยิง `http://<tailnet-ip>:<port>` ตรงไปยัง service ที่ publish ไว้

**แก้แล้ว (ไม่ต้องใช้ admin):**

| บริการ      | ก่อน                | หลัง                 | ผลทดสอบ                                                                             |
| ----------- | ------------------- | -------------------- | ----------------------------------------------------------------------------------- |
| edge-ai API | `100.99.80.84:8099` | **`127.0.0.1:8099`** | hostname:8099 → **000**, 127.0.0.1:8099 → 200, ทาง `:8443/AIEdgeGuard` (auth) → 200 |

แก้ที่ `edge-ai/docker-compose.yml` (`ports: "127.0.0.1:8099:8000"`) แล้ว
`docker compose up -d api` — container อื่นไม่กระทบ (worker/watcher คุยผ่าน service name)

**ต้องรันครั้งเดียวด้วยสิทธิ์ Administrator** (พอร์ตที่ publish จาก Docker/native process ซึ่งแก้ได้แค่ firewall):

```powershell
# เปิด PowerShell as Administrator
powershell -ExecutionPolicy Bypass -File D:\GitHub\AIEdgeGuard\tools\lockdown_tailnet_ports.ps1
```

สคริปต์บล็อก inbound TCP จาก `100.64.0.0/10` (tailnet) ไปยัง:
`3100` (forgemind-web), `8101` (demo portal), `9000` (portal), `8085`/`8086` (CrowdSec LAPI/AppSec)

- **ไม่แตะ** พอร์ตที่ Tailscale serve ใช้ (`443`, `10000`, `8443`, `8445`) — ถ้าบล็อกจะทำให้ hostname ใช้งานไม่ได้
- rollback: `... -Remove`
- ถ้าต้องการบล็อก LAN ด้วย: `... -ExtraRemoteRanges 192.168.0.0/16,10.0.0.0/8`
- ทางเลือกที่ไม่ต้องใช้ admin: จำกัดที่ Tailscale ACL (admin console) ให้ grant เฉพาะ
  `llm-server:443`, `:10000`, `:8443`, `:8445`

**หมายเหตุ:**

- พอร์ต `8443` ที่ Docker publish (`0.0.0.0:8443`) ถูก tailscale serve บังอยู่แล้ว —
  ยิงแบบ HTTP ตรงจะได้ 400 และ HTTPS จะไปโดน serve (ไม่เป็นช่อง bypass)
- หลังรันสคริปต์ ตรวจซ้ำ: พอร์ตในลิสต์ต้องได้ `000`, ส่วน
  `https://llm-server.tail923b9a.ts.net/index.html` และ `:8443/AIEdgeGuard/health` ต้องยังทำงาน

**สถานะ: ติดตั้งแล้ว 2026-11-12** — rule 5 ตัวถูกสร้างครบ (`Get-NetFirewallRule` เห็นทั้ง 5,
`RemoteAddress=100.64.0.0/255.192.0.0`, `Action=Block`, `Profile=Any`)
แต่ยัง **รอตรวจจากเครื่องอื่นใน tailnet** เพราะ self-test จากเครื่องเดียวกันใช้ตัดสินไม่ได้ (ดูหมายเหตุล่าง)

**⚠️ ทดสอบจากเครื่องตัวเอง (llm-server) ไม่นับ** — การต่อ `http://100.99.80.84:3100`
จากเครื่องเดียวกันเป็น **loopback traffic** และ Windows Firewall **ไม่กรอง loopback**
พอร์ตจะยังตอบ 200/404 ภายในเครื่องแม้ rule ทำงานถูกต้องแล้ว (ตรวจแล้วว่า rule ถูกสร้างครบ
5 ตัว, `RemoteAddress=100.64.0.0/255.192.0.0`, `Action=Block`, `Profile=Any`)

วิธีตรวจที่ถูกต้อง — ทดสอบจากเครื่องอื่นใน tailnet (มือถือที่ลง Tailscale / PC อีกเครื่อง):

```powershell
# ต้อง timeout / 000  (ถูกบล็อก)
curl http://100.99.80.84:3100/
curl http://100.99.80.84:8101/
curl http://100.99.80.84:9000/

# ต้องได้ 200 (ทางที่อนุญาต)
curl https://llm-server.tail923b9a.ts.net/index.html
curl https://llm-server.tail923b9a.ts.net:10000/login
curl https://llm-server.tail923b9a.ts.net:8443/AIEdgeGuard/health
```

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

| ทดสอบ                                                          | ผล                                                                                      |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| UI ปกติ: /, /login, /tasks/123, /projects/1/jobs, /favicon.ico | 200 ครบ (SPA fallback ทำงาน) ✓                                                          |
| /.env, /.git/config, /phpunit/..., /?id=1 OR 1=1               | **403** ✓                                                                               |
| /wp-login.php, /actuator/env                                   | 200 — probe เฉพาะแพลตฟอร์มที่ ruleset ไม่ครอบ (gap รู้ก่อน, เสริม rule ภายหลังได้)      |
| alert "Enabling body inspection"                               | informational — AppSec เตือนว่าต้อง forward body เพื่อตรวจ POST (plugin จัดการอยู่แล้ว) |

สถานะ route ทั้งหมดของ CVAT-family: cvat_server ✅ → cvat_ui ✅ → agents-office ⬜ → grafana ⬜ → aitradinghunter ⬜

## Route แรกที่ผูกจริง: cvat_server (2026-11-12) ✅

`cvat_server` เป็น route แรกที่อยู่หลัง `crowdsec@docker` — ผลทดสอบบน route จริง:

| ประเภท                                                                 | ผล                                                                                               |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| /api/server/about, /api/tasks?page=.., /api/users, /admin, /django-rq  | 200/401/301 ปกติ — **ไม่มี FP** ✓                                                                |
| /api/.env, /api/?id=1 OR 1=1, UNION SELECT, `<script>`                 | **403 + alert (anomaly scoring ระบุชนิด)** ✓                                                     |
| `/api/?file=..%2f..%2fetc%2fpasswd`, double-encoded                    | 403 + alert (lfi: 40) ✓                                                                          |
| `/static/` 403                                                         | ไม่ใช่ WAF — nginx ปฏิเสธ directory listing เอง (ไม่มี alert) ✓                                  |
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
- 127.0.0.1:8099 (edge-ai) : health ok ✓ (เปลี่ยนเป็น loopback — ดูหัวข้อ "บังคับเข้าผ่าน hostname")
- 100.99.80.84:8085 (LAPI) : alive ✓ (ตอบแล้ว — ตรวจ path ซ้ำหลัง reboot)
- 100.99.80.84:55000 (Wazuh API HTTPS) : 000 — boot ช้า/forwarding ตาย — retest หลัง reboot
- 9000 (host traefik native) : 200 ✓ (native process ไม่กระทบ)

**เช็คหลัง reboot (ลำดับ):**

1. curl http://100.99.80.84:8085/health → ตรวจ LAPI
2. curl -H Host llm-server http://localhost:8080/api/server/about → 200
3. curl http://127.0.0.1:8099/health → ok
4. Wazuh https://100.99.80.84:55000 (HTTPS) → 200
5. ถ้าครบ = ระบบกลับมาเต็ม 100% — ต่อด้วย Windows agent install (MSI พร้อมที่ wazuh/)

---

## รอบ Hardening + Mission Control 3 ชั้น (2026-11-12 เย็น) — จาก session เสริม

**สิ่งที่เพิ่ม (working tree — ดู docs/current-status.md + mission-control.md ฉบับเต็ม):**
- Policy hardening: target=source IP, human review บน prompt-injection, protected IPv6, clamp duration
- Approval concurrency: conditional UPDATE (claim ครั้งเดียว), executor failed/execution_unknown
- Durable outbox: queued_at IS NULL → watcher ส่งซ้ำได้; worker ไม่ ACK งาน fail + redis reconnect
- Campaign transaction fix (ไม่นับซ้ำ)
- Mission Control เชื่อมครบ 3 ชั้น: HTTP-WAF + Network-IDS (Suricata 7.0.3 WSL AF_PACKET, ET Open)
  + Host-EDR (Wazuh agents llm-server-wsl + llm-server-windows — Active ทั้งคู่)
- Telemetry pipeline: Suricata EVE + Wazuh alerts → PG durable outbox → Redis → Analysis → Policy
  (เฉพาะ incident-worthy: Suricata sev 1/2, Wazuh level >=5)
- Sensor bridge systemd + Startup shortcut (LACD Sensors.lnk)
- Dashboard/Mission: separate APIs, URL variants, XSS-safe, Lab UI event listeners
- Tests: 24 regression + policy + concurrency + queue recovery + mission browser + ruff + compose validation
- Deploy: edge-ai-api อัปเดต + rollback tag (rollback-20261112-124449) + smoke checks ผ่าน
- Port lockdown: firewall Block tailnet CGNAT → direct ports 3100/8101/9000/8085/8086

**ปิดแนวทาง Vercel Origin bypass** (allow-vercel.yaml เก็บเป็นประวัติ ไม่ mount — Origin spoofable)

## 🚨 CRITICAL ที่พบตรวจสด: /AIEdgeGuard write endpoints PUBLIC

ยืนยันของจริง (จากมุมมองคนนอก): /AIEdgeGuard/mission 200, /api/v1/decisions โชว์ข้อมูล,
/api/v1/incidents โชว์ข้อมูล, **POST /api/v1/attacks/run → 200 (run #7 ยิงจริง!)**
- ช่องโจมตี: approve ban / ยิง attack lab / อ่าน incidents — ใครก็ได้บนอินเทอร์เน็ตที่รู้ URL
- ข้อมูลปลอดภัยรอบข้าง: target เป็น Juice Shop lab (contained ✓), policy gate คุม pending ✓,
  CrowdSec WAF ครอบ route ✓ — แต่ยังเสี่ยงเกิน
- /aiedge alias มี Basic auth (401 ✓) — ใช้เส้นนี้แทนได้ทันที

**ข้อเสนอแก้ (รอยืนยันจากเจ้าของ):** ปิด public /AIEdgeGuard + ใช้ /aiedge (Basic auth)
หรือเพิ่ม auth เต็มรูปแบบ — คำสั่งอยู่ใน docs/public-preview.md

## งานค้างรวม (หลังรอบนี้)
- ปิด/ลดขนาด public exposure ของ write endpoints (ด้านบน)
- Remote tailnet e2e test (firewall rule ≠ ผลทดสอบจริง)
- Poller pagination/backpressure หากปริมาณสูง
- execution_unknown/executing ค้าง: ตรวจ CrowdSec active decisions + audit ก่อนดำเนินการ
- Campaign count ย้อนหลังยังไม่แก้ข้อมูล (รักษาประวัติ)
- mission.html ที่ราก repo เป็นไฟล์เก่า (แอปใช้ edge-ai/api/app/static/mission.html)

---

## Operation Key gate (2026-11-12 ลึก) — deployed, test blocked by port-forwarding

**สิ่งที่ implement แล้ว (ยืนยันในไฟล์):**
- config.py: `operation_key` setting (empty = gate OFF สำหรับ dev/tests)
- main.py: `require_operation_key` dependency (X-Operation-Key header,
  secrets.compare_digest) ผูกกับ 5 state-changing endpoints:
  events ingest / incidents requeue / decisions approve / reject / attacks/run
- compose: OPERATION_KEY ผ่านเข้า api container ✓
- .env: OPERATION_KEY ตั้งค่าแล้ว (gitignored) — gate ON ✓
- mission.js/dashboard.js: popup prompt + X-Operation-Key header
  (sessionStorage cache — ไม่ต้องใส่ซ้ำทุกคลิก)

**ทดสอบติดขัด:** loopback + TS-IP publish forwarding ตายเป็นระยะ (com.docker.backend
state เสียหลัง crash ×5) — **reboot เครื่องก่อนแล้วรัน test matrix ซ้ำ:**
```
curl -X POST http://127.0.0.1:8099/api/v1/attacks/run -d '{"target":"juicelab.lab.local"}'          → 403 (no key)
curl -X POST ... -H "X-Operation-Key: wrong"                                                        → 403
curl -X POST ... -H "X-Operation-Key: uC7QxyDNrzSTynmUTFeEXfRdnunvEaGM" -d '{"target":"juicelab.lab.local"}' → run จริง
```
**หมายเหตุ:** key นี้เก็บใน edge-ai/.env (gitignored) — ใช้ใน popup ของ dashboard ด้วย
