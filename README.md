# Local AI EdgeGuard

ระบบป้องกันไซเบอร์ที่รัน **local 100%** — Gateway (Traefik + CrowdSec) ตรวจจับ/บล็อกด่านหน้า,
Local LLM (Qwen3.5 9B บน Ollama) วิเคราะห์/เสนอการตอบสนอง ผ่าน Policy Engine ก่อน execute เสมอ

- รายงานศึกษาความเป็นไปได้: [docs/feasibility-study.md](docs/feasibility-study.md)
- บันทึกการย้าย gateway: [docs/gateway-migration.md](docs/gateway-migration.md) (**เสร็จแล้ว**)
- แผนสถาปัตยกรรมต้นฉบับ: [docs/reference-chatgpt-plan.md](docs/reference-chatgpt-plan.md)

## สถานะปัจจุบัน (2026-11-12): Gateway ใช้งานจริงแล้ว ✅

```
Internet → [traefik] :8080/:28080 (CVAT routes เดิม)  :80/:8443 (project ใหม่)
              ├─ middleware "crowdsec" (ผูกทีละ route)
              │     ├─ IP ban ตรวจทุก request (LAPI)
              │     └─ AppSec WAF (200+ vpatch rules) → 403
              ├─ access log (JSON) → gateway-crowdsec parser
              └─ networks: cvat_cvat + gateway_net + edge_web

[C:\Docker\gateway\]
  traefik + gateway-crowdsec + gateway-postgres(pgvector)

[edge-ai — ยังไม่ deploy]  FastAPI 6-agent orchestrator → Ollama (host :11434)
```

ผ่านการทดสอบแล้ว: routing ครบเท่า baseline ทุก route (CVAT/agents-office/grafana),
AppSec บล็อกจริง (403 + บันทึก alert), IP ban/unban ทำงาน

## โครงสร้าง repo

```
AIEdgeGuard/
├── edge-guard/          gateway stack (mirror ของ C:\Docker\gateway\ ที่ deploy จริงแล้ว)
├── edge-ai/             FastAPI orchestrator (skeleton พร้อม Analysis Agent)
├── pilot/MIGRATION.md   วิธีผูก project เข้ามาอยู่ใต้ CrowdSec (ทีละ route)
├── tools/               scripts ช่วยงานเอกสาร
└── docs/                รายงานศึกษา + migration record + แผนอ้างอิง
```

> **หมายเหตุ deployment:** config จริงที่รันอยู่คือ `C:\Docker\gateway\` บนเครื่อง llm-server (Windows + Docker Desktop) — ไฟล์ใน repo เป็น mirror ฉบับ canonical แก้ที่ repo แล้ว copy ไปที่ live เสมอ

## การเริ่มใช้งาน (หาก deploy ใหม่ที่เครื่องอื่น)

```bash
# 0. networks
docker network create edge_web   # gateway_net ถูกสร้างโดย gateway compose เอง

# 1. gateway
cd edge-guard && cp .env.example .env   # ใส่ POSTGRES_PASSWORD
docker compose up -d && sleep 20
docker compose exec crowdsec cscli bouncers add traefik-bouncer -o raw   # → ใส่ key ใน .env
docker compose up -d traefik

# 2. edge-ai (หลัง gateway พร้อม)
docker compose exec crowdsec cscli machines add edge-ai --password "<สุ่ม>" -o raw
docker compose exec crowdsec cscli bouncers add edge-ai-readonly -o raw
cd ../edge-ai && cp .env.example .env   # ใส่ credentials + OLLAMA_MODEL
docker compose up -d --build
curl http://127.0.0.1:8080/health       # ollama/crowdsec/redis = ok
```

## ผูก project เข้ามาให้ CrowdSec ป้องกัน

ดู [pilot/MIGRATION.md](pilot/MIGRATION.md) — สั้น ๆ คือ:

```yaml
# ใน compose ของ project: ลบ ports, เพิ่ม labels + network
labels:
  - traefik.enable=true
  - traefik.http.routers.myapp.rule=Host(`myapp.lab.local`)
  - traefik.http.routers.myapp.entrypoints=pilot        # :80 (ใหม่) หรือ web (:8080 เดิม)
  - traefik.http.routers.myapp.middlewares=crowdsec@docker
networks: [edge_web, gateway_net]   # edge_web = traffic, (แนะนำเพิ่ม traefik.docker.network=edge_web)
```

## Acceptance Tests (ทดสอบแล้ว ผ่านทุกข้อ ✅)

| Test | คำสั่ง | คาดหวัง | ผลจริง |
|---|---|---|---|
| Route เดิมครบ | `curl -H "Host: llm-server" http://localhost:8080/api/server/about` | 200 | ✅ |
| AppSec จับ .env | `curl -H "Host: <domain>" http://localhost:80/.env` (ต้องผูก middleware แล้ว) | **403** | ✅ |
| AppSec จับ CVE | `curl ... /phpunit/src/Util/PHP/eval-stdin.php` | **403** | ✅ |
| AppSec จับ .git | `curl ... /.git/config` | **403** | ✅ |
| Alert ถูกบันทึก | `cscli alerts list` | kind=waf + source IP | ✅ |
| Ban IP | `cscli decisions add --ip <IP> --duration 2m` แล้ว request จาก IP นั้น | **403** ทุก route | ✅ |
| Unban | `cscli decisions remove --ip <IP>` | กลับมา 200 | ✅ |
| Defense ปิดอยู่ | `POST /api/v1/defense/decision` (edge-ai) | **503** (safety gate) | ✅ |

> payload `?id=1 OR 1=1` แบบเก่า **ไม่** โดนบล็อก — CrowdSec AppSec เน้น virtual patching (CVE/pattern จริง) ไม่ใช่ regex SQLi หลวม ๆ — ใช้ payload ตามตารางข้างบนในการทดสอบ

## Roadmap ถัดไป

1. ✅ **เฟส 2:** Gateway migration + CrowdSec AppSec live + skeleton
2. ✅ **ผูก pilot project เข้า middleware** (ทีละ route — ดู pilot/MIGRATION.md)
3. **เฟส 3:** Wazuh (Docker Desktop) + Suricata ใน WSL2 Ubuntu (มีอยู่แล้วในเครื่อง)
4. **เฟส 4–5:** edge-ai up + event ingestion จริง (CrowdSec LAPI → Redis → PostgreSQL) + Detection Agent
5. **เฟส 6–7:** Decision Agent + Policy Engine (YAML) + Defense executor (human approval)
6. **เฟส 8–10:** Attack Lab (WSL2/VM) + Learning loop (pgvector) + Dashboard

## ข้อควรระวัง

- **ห้ามรัน** `docker compose up` ที่ C:\Docker\cvat จนกว่าจะ restore traefik block — port 8080 ชนกัน
- Image ทุกตัว pin เวอร์ชันหลวม ๆ — pin จริงก่อนขึ้น production
- `.env` ทั้งหมดถูก gitignore — ห้าม commit
- VRAM: ใช้ `typhoon2.5-qwen3-4b` ทดสอบ pipeline ก่อน (Windows desktop กิน VRAM ~8.4GB) สลับเป็น `qwen3.5:9b` ผ่าน `OLLAMA_MODEL` ใน edge-ai/.env เมื่อจัด VRAM ได้
