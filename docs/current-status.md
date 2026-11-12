# สถานะที่ตรวจจริง — 2026-11-12

> อัปเดตรอบ Mission Control: เชื่อมครบ HTTP-WAF + Network-IDS + Host-EDR แล้ว รวม Windows/Ubuntu Wazuh agents และ Suricata WSL ดู [mission-control.md](mission-control.md) สำหรับผลทดสอบล่าสุดและขอบเขตการมองเห็น ข้อความด้านล่างเป็นบันทึกของรอบก่อนหน้า

บันทึกนี้แยกผลตรวจรอบล่าสุดออกจากประวัติใน `gateway-migration.md` ซึ่งรวมเหตุการณ์ก่อนหน้าและปัญหาที่อาจหายแล้ว

## งานที่เก็บเสร็จ

- Policy ตรวจให้ target ตรงกับ source IP จริง ปฏิเสธข้อเสนอที่ชี้ IP อื่น
- บังคับ human review เมื่อ analysis ขอให้ตรวจหรือสงสัย prompt injection รวม protected IPv6 และ IPv4-mapped IPv6
- คงระยะเวลาบล็อกที่ผ่านการ clamp ไว้สำหรับข้อเสนอที่รออนุมัติ
- Cooldown นับเฉพาะบล็อกสำเร็จและใช้ `executed_at` แทนเวลาสร้างข้อเสนอ
- Approval/rejection ใช้ conditional UPDATE ใน PostgreSQL ป้องกันคำขอพร้อมกัน execute ซ้ำ
- Executor ที่คืน `ok=false` บันทึกเป็น `failed`; ข้อผิดพลาดระหว่างส่งคำสั่งบันทึกเป็น `execution_unknown` และห้ามอนุมัติซ้ำอัตโนมัติ
- Incident ที่บันทึกก่อน Redis ใช้งานได้จะอยู่ใน durable outbox (`queued_at IS NULL`) watcher ส่งใหม่ภายหลัง การส่งซ้ำปลอดภัยเพราะ worker ข้าม incident ที่วิเคราะห์แล้ว
- Worker ไม่ ACK งานที่ล้มเหลว ลอง pending ใหม่เป็นระยะ และลองเชื่อม Redis ใหม่หากยังไม่พร้อมตอนเริ่ม
- Campaign ใหม่ผูก incident ชุดแรกใน transaction เดียวกัน แก้การนำ incident เดิมมานับซ้ำในรอบถัดไป (ไม่เปลี่ยนประวัติข้อมูลเก่า)
- Mission ใช้ API แยกสำหรับ health, agents, incidents, decisions รองรับทั้ง URL ตรงและสอง gateway prefixes มีสถานะผิดพลาด/โหลดใหม่ และแสดงข้อมูลด้วย textContent
- ปุ่มทดสอบ Lab ใช้ event listener, ป้องกันกดซ้ำ และแสดงผลจริงตาม response; ปุ่ม Dashboard ไม่พึ่ง global `event`
- ปิดแนวทาง bypass WAF ด้วย Origin/Referer อย่างชัดเจน ตัวอย่าง `allow-vercel.yaml` เก็บเป็นประวัติที่ห้ามเปิดใช้และไม่ได้ mount
- README อัปเดตตามโค้ดปัจจุบัน

## ผลทดสอบ

| รายการ | ผล |
|---|---|
| Python regression tests | 24 ผ่าน รวม integration 4 กรณีบน PostgreSQL/pgvector แยกจากฐานใช้งานจริง |
| Policy | ตรวจ cooldown, target mismatch, confidence ผิดช่วง/NaN, review flags และ protected IPv4/IPv6 |
| Approval concurrency | ทดสอบทั้ง mock executor และ PostgreSQL จริง มีผู้ claim สำเร็จครั้งเดียว |
| Queue recovery | ทดสอบ publish ล้มเหลวแล้วส่งใหม่ และ pending ที่ล้มเหลวไม่ถูก ACK |
| Mission browser checks | Chrome headless, desktop 1440px/mobile 390px, URL 3 รูปแบบ, API errors/recovery และ XSS payload |
| Lab UI | ทดสอบกับ mocked API เท่านั้น ไม่มีการยิงโจมตีจากชุดทดสอบนี้ |
| Ruff | ไฟล์ Python ที่แก้ในรอบนี้และ tests ผ่าน |
| Docker compose | edge-ai และ gateway config ผ่าน validation โดยใช้ env ของแต่ละ stack |
| Gateway configuration | เทียบ YAML ใน repo กับ `C:\Docker\gateway\` แล้วตรงกันใน compose/static routes/dynamic routes/AppSec/whitelist |

สั่งทดสอบตาม README; integration tests จะล้างข้อมูลเฉพาะฐานทดสอบชื่อ `edgeguard_test` ที่กำหนดผ่าน `EDGEGUARD_TEST_DATABASE_URL`

## Deployment และ smoke checks

อัปเดตเฉพาะ `edge-ai-api` ด้วย compose เดิมและเก็บ image ก่อนหน้าไว้:

```text
edge-ai-api:rollback-20261112-124449
```

ตรวจหลังอัปเดต:

- `/health`: ollama/crowdsec/redis/postgres = `ok`
- `/mission`, `/dashboard`, `/static/mission.js`, incidents/campaigns/decisions API = HTTP 200
- `/api/v1/policy`: `dry_run (human approval)`
- เรียก `/AIEdgeGuard/health` ผ่าน Traefik โดยไม่ส่ง credentials = HTTP 401
- CVAT baseline `/api/server/about` ผ่าน gateway = HTTP 200
- Startup logs แสดง watcher, worker, detection, decision และ learning เริ่มทำงาน
- API port ยังคง bind `127.0.0.1:8099`
- Windows Firewall rules เดิมสำหรับ TCP 3100/8101/9000/8085/8086 เปิดใช้งานและ Action=Block

ไม่ได้ restart gateway เพราะ configuration ที่ใช้งานตรงกับ repo อยู่แล้ว ไม่ได้เปิด auto-execution หรือทำ live attack campaign ในรอบนี้

Rollback API (ใช้เฉพาะเมื่อจำเป็น):

```powershell
docker image tag edge-ai-api:rollback-20261112-124449 edge-ai-api:latest
docker compose -f edge-ai/docker-compose.yml up -d --no-deps --force-recreate api
```

Schema เพิ่มเฉพาะ `queued_at` แบบ additive จึงคงไว้ได้เมื่อ rollback image

## ข้อจำกัดและงานต่อยอด

- ยังไม่ได้ทดสอบ remote filtering จากอุปกรณ์ Tailnet เครื่องอื่น การมี firewall rule ไม่เท่ากับผลทดสอบ end-to-end
- Wazuh/Suricata automatic ingestion และ Windows agent เป็นงานถัดไป ไม่รวมในการ deploy รอบนี้
- Poller อ่าน CrowdSec ล่าสุด 100 alerts ทุก 30 วินาที ยังต้องออกแบบ pagination/backpressure หากปริมาณสูงกว่านั้น
- สถานะ `execution_unknown` หรือ `executing` ที่ค้างหลัง crash ต้องตรวจ active decisions ใน CrowdSec และ audit record ก่อนดำเนินการต่อ ไม่มีการ retry enforcement อัตโนมัติ
- Campaign count ที่ผิดจากบั๊กเดิมยังไม่ได้ปรับข้อมูลย้อนหลัง เพื่อรักษาประวัติการใช้งาน
- ไฟล์ `mission.html` ที่ราก repo เป็นไฟล์เดิมนอกเส้นทางเสิร์ฟของแอป เก็บไว้โดยไม่แก้; แอปใช้ `edge-ai/api/app/static/mission.html`
- การแก้ใน working tree รวมงานเดิมของผู้ใช้และงานรอบนี้ ยังไม่ได้ commit
