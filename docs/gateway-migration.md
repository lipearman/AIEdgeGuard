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
