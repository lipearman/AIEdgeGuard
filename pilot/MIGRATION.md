# Pilot Migration — ผูก project เข้ามาให้ CrowdSec ป้องกัน

> สถานะ gateway: รันอยู่แล้วที่ `C:\Docker\gateway\` (traefik + crowdsec + postgres)
> middleware ชื่อ **`crowdsec@docker`** พร้อมใช้ รอแค่ผูกเข้า router ทีละตัว
> ทุกขั้นย้อนกลับได้ — ลบ label/คอมเมนต์ middleware แล้ว `docker compose up -d` ก็จบ

## กรณี A — project ใหม่ (ยังไม่ผูกกับ Traefik เลย)

แก้ compose ของ project:

```yaml
services:
  myapp:
    # ports: ["3000:3000"]     ← ลบ/คอมเมนต์ (เลิก publish เอง)
    labels:
      - traefik.enable=true
      - traefik.http.routers.myapp.rule=Host(`myapp.lab.local`)
      - traefik.http.routers.myapp.entrypoints=pilot        # :80
      - traefik.http.routers.myapp.service=myapp
      - traefik.http.services.myapp.loadbalancer.server.port=3000
      - traefik.http.routers.myapp.middlewares=crowdsec@docker   # ← ประตูผ่าน CrowdSec
      - traefik.docker.network=edge_web                     # ← สำคัญ: บอก traefik ว่าเชื่อมทางไหน
    networks:
      - edge_web
networks:
  edge_web:
    external: true
```

ตั้ง hostname ให้เครื่องที่ใช้ทดสอบรู้จัก:
- Windows: `C:\Windows\System32\drivers\etc\hosts` (เปิด Notepad as admin) เพิ่ม `127.0.0.1  myapp.lab.local`
- เครื่องอื่นใน LAN: hosts ชี้มาที่ IP ของ llm-server (192.168.1.58)

ทดสอบ:

```bash
# ผ่านได้ปกติ
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: myapp.lab.local" http://localhost:80/
# โดนบล็อก (403) — payload ที่ rule จับแน่:
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: myapp.lab.local" http://localhost:80/.env
curl -s -o /dev/null -w "%{http_code}\n" -H "Host: myapp.lab.local" http://localhost:80/phpunit/src/Util/PHP/eval-stdin.php
# ดู alert ที่เกิดขึ้น
cd C:\Docker\gateway && docker compose exec crowdsec cscli alerts list
```

HTTPS ให้ project ใหม่: เปลี่ยน entrypoints เป็น `pilotsecure` (:8443, TLS self-signed ของ Traefik — ใช้ `curl -k` หรือเพิ่ม cert ภายหลัง)

## กรณี B — project เดิมที่มี traefik labels อยู่แล้ว (เช่น ai-call-center ฯลฯ)

เพิ่ม middleware เข้า router ที่มีอยู่:

```yaml
- traefik.http.routers.<ชื่อ router เดิม>.middlewares=crowdsec@docker
```

(ถ้า container อยู่หลาย network ให้เพิ่ม `traefik.docker.network=<network ที่ traefik เชื่อมถึง>` ด้วย)

## กรณี C — route ของ CVAT stack (cvat_server, cvat_ui, agents-office, grafana, aitradinghunter)

1. **route ที่นิยามด้วย label** (cvat_server/cvat_ui): เพิ่ม label `traefik.http.routers.cvat.middlewares=crowdsec@docker` ใน CVAT compose แล้ว `docker compose up -d cvat-server` (เฉพาะตัวนั้น)
2. **route ที่นิยามใน rule file** (agents-office/grafana ที่ `C:\Docker\cvat\components\analytics\`):

```yaml
routers:
  agentsoffice:
    middlewares:        # ← เพิ่ม 2 บรรทัดนี้
      - crowdsec@docker
    entryPoints: [web]
```

Traefik reload ไฟล์อัตโนมัติ (ไม่ต้อง restart)

**ลำดับที่แนะนำ:** cvat_server → ทดสอบ login/API ปกติ → cvat_ui → agents-office → grafana → aitradinghunter
**ทดสอบหลังแต่ละตัว:** ใช้งานจริง 1–2 ฟังก์ชัน + ดู FP ด้วย `docker compose exec crowdsec cscli alerts list`

ถ้า FP เยอะ → เริ่มด้วยตัวเบาก่อน: เพิ่ม label `crowdsecAppsecFailureBlock=false` เฉพาะ router นั้น (log อย่างเดียว ยังบล็อก IP ban อยู่)

## Rollback ทีละ route

ลบ `middlewares=crowdsec@docker` ออกจาก label/rule file → up/reload → เสร็จ

## เกณฑ์ผ่านของแต่ละ route

- [ ] ใช้งานปกติ (ฟังก์ชันหลัก) ไม่มี FP
- [ ] `/.env` probe → 403
- [ ] มี alert ใน `cscli alerts list` เมื่อยิง probe
- [ ] (ถ้าต้องการ) ban ทดสอบ → 403 ทั้ง route
