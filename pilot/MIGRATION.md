# Pilot Migration — ย้าย Docker project เข้า EdgeGuard

> เป้าหมาย: project 1–2 ตัวเข้าถึงผ่าน Traefik เท่านั้น (มี CrowdSec IP-ban + AppSec WAF ด่านหน้า)
> ทุกขั้นตอน **ย้อนกลับได้** (rollback) — ถ้าอะไรผิดพลาดให้เปิด port เดิมคืนได้ทันที

## ก่อนเริ่ม

- [ ] edge-guard stack รันอยู่ (`docker compose ps` ใน `edge-guard/` → traefik, crowdsec, postgres เป็น Up)
- [ ] สร้าง bouncer key และใส่ใน `.env` แล้ว (`cscli bouncers add traefik-bouncer -o raw`)
- [ ] รู้ port เดิมของ project (เช่น `3000:3000`) และจะใช้ hostname อะไร (เช่น `app1.lab.local`)

## ขั้นที่ 1 — แก้ compose ของ project

เดิม (publish port ตรง):

```yaml
services:
  myapp:
    image: myapp:latest
    ports:
      - "3000:3000"      # ← ตรงนี้ทำให้เข้าได้เลย ไม่ผ่านด่านใด
```

แก้เป็น:

```yaml
services:
  myapp:
    image: myapp:latest
    # ports: ["3000:3000"]   # ลบ/คอมเมนต์ทิ้ง — กลับมาเปิดคืนได้ถ้า rollback
    labels:
      - traefik.enable=true
      - traefik.http.routers.myapp.rule=Host(`app1.lab.local`)
      - traefik.http.services.myapp.loadbalancer.server.port=3000   # port ภายในของ container
      - traefik.http.routers.myapp.middlewares=crowdsec@docker      # ← ประตูผ่าน CrowdSec/AppSec
    networks:
      - edge_web
networks:
  edge_web:
    external: true
```

> **หมายเหตุ:** เอาแค่ `middlewares=crowdsec@docker` ก็ได้ทั้ง IP-ban และ AppSec WAF
> ในตัวเดียว (เพราะ plugin ตั้ง `appsecenabled=true` ไว้แล้ว)

## ขั้นที่ 2 — ตั้งชื่อ domain ให้เครื่องที่จะทดสอบรู้จัก

- **ทดสอบจาก Windows (เครื่องนี้):** เพิ่มในไฟล์ hosts:
  `C:\Windows\System32\drivers\etc\hosts` (เปิด Notepad แบบ Run as administrator):
  ```
  127.0.0.1  app1.lab.local
  ```
- **ทดสอบจากเครื่องอื่นใน LAN:** เพิ่ม hosts ที่เครื่องนั้นชี้มาที่ IP ของ llm-server
- **ทดสอบเร็วสุดไม่ต้องตั้ง hosts:** `curl -k -H "Host: app1.lab.local" https://localhost:8443/`
- TLS ช่วงแรกเป็น self-signed ของ Traefik → ใช้ `curl -k` / กด "Advanced → Continue" ใน browser ได้
- Port HTTPS คือ **:8443** (เพราะ :443 ถูก Tailscale ใช้อยู่บนเครื่องนี้)

## ขั้นที่ 3 — รีสตาร์ตและตรวจ

```bash
cd ~/path/to/myapp && docker compose up -d     # project ต้องรู้จัก network ใหม่
curl -kI https://localhost:8443/ -H "Host: app1.lab.local"    # ต้องตอบ 200/302 จาก app
docker compose -f edge-guard/docker-compose.yml exec crowdsec cscli metrics | grep -A2 parser
```

## ขั้นที่ 4 — ทดสอบว่าด่านป้องกันทำงานจริง (Acceptance Test)

**4.1 AppSec WAF — ต้องถูกบล็อก 403:**

```bash
# Path traversal
curl -k "https://localhost:8443/?file=../../etc/passwd" -H "Host: app1.lab.local" -I
# SQLi probe
curl -k "https://localhost:8443/?id=1%20OR%201=1" -H "Host: app1.lab.local" -I
```

คาดหวัง: `HTTP/1.1 403 Forbidden` (จาก AppSec)

**4.2 ดูว่า CrowdSec เห็นเหตุการณ์:**

```bash
docker compose -f edge-guard/docker-compose.yml exec crowdsec cscli alerts list
docker compose -f edge-guard/docker-compose.yml exec crowdsec cscli decisions list
```

**4.3 ทดสอบ ban ด้วยมือ (จำลองสิ่งที่ Defense Agent จะทำในอนาคต):**

```bash
docker compose -f edge-guard/docker-compose.yml exec crowdsec \
  cscli decisions add --ip <TEST_IP> --duration 4h --reason "manual-test"
# ลองเข้าเว็บจาก IP นั้น → ต้องโดน 403 จาก bouncer
docker compose -f edge-guard/docker-compose.yml exec crowdsec \
  cscli decisions remove --ip <TEST_IP>     # เคลียร์ทดสอบ
```

## ขั้นที่ 5 — ตรวจว่า project เดิมยังใช้งานได้ครบ

- ทดสอบฟังก์ชันหลักของ app (login, API call สำคัญ)
- ดู log ว่าไม่มี false positive จาก AppSec:
  `docker compose -f edge-guard/docker-compose.yml logs crowdsec | grep -i blocked`
  ถ้ามี FP → เริ่มด้วย `appsecfailureblock=false` (log อย่างเดียว) ก่อน แล้วค่อยบล็อกจริง

## Rollback

1. เปิด `ports: ["3000:3000"]` คืนใน compose ของ project → `docker compose up -d`
2. ปิด router: `traefik.enable=false` หรือ down container
3. เหตุฉุกเฉินทั้ง stack: `docker compose -f edge-guard/docker-compose.yml down`
   (port 80/443 ปล่อยว่าง ทันที แล้ว project เปิด port เดิมคืนได้)

## หลัง pilot ผ่าน

- ทำซ้ำกับ project ตัวที่ 2
- ต่อด้วย edge-ai (`edge-ai/docker-compose.yml`) → `curl 127.0.0.1:8080/health` ต้องได้ `"ollama":"ok"`
- จากนั้นค่อยวาง Wazuh + Suricata (เฟส 3)
