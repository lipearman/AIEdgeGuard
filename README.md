# Local AI EdgeGuard

ระบบป้องกันไซเบอร์ที่รัน **local 100%** — Security Engine (deterministic) ตรวจจับ/บล็อกด่านหน้า
Local LLM (Qwen3.5 9B บน Ollama) วิเคราะห์/เสนอการตอบสนอง ผ่าน Policy Engine ก่อน execute เสมอ

- รายงานศึกษาความเป็นไปได้: [docs/feasibility-study.md](docs/feasibility-study.md)
- แผนสถาปัตยกรรมต้นฉบับ: [docs/reference-chatgpt-plan.md](docs/reference-chatgpt-plan.md)
- เอกสาร Enterprise (ChatGPT export): `Local_AI_Cyber_Defense_Enterprise_Architecture.md`

## สถาปัตยกรรมเฟส Pilot (บน llm-server เครื่องเดียว)

```
Internet → [Traefik :80/:443]
              ├─ CrowdSec bouncer (IP ban)
              └─ CrowdSec AppSec (WAF: SQLi/XSS/path traversal)
                     ↓ ผ่านได้เท่านั้น
           [Docker projects ของคุณ (pilot 1–2 ตัว)]

สายข้อมูล (แยกจาก traffic):
  Traefik access log → CrowdSec → alerts/decisions
  FastAPI (edge-ai) → อ่าน alerts, วิเคราะห์ด้วย Ollama (host เดิม)
  Redis = event bus, PostgreSQL+pgvector = เก็บ incident/policy (เฟสถัดไป)
```

**เหตุผลที่แบ่งสอง compose:** เมื่อไหร่แยกเครื่องได้ ย้ายได้ทันที —
`edge-guard` (+Suricata+Wazuh ภายหลัง) ไป **Security Server**,
`edge-ai` ไป **AI Server** โดยไม่ต้องรื้ออะไร

## โครงสร้าง

```
AIEdgeGuard/
├── edge-guard/          ด่านหน้า: Traefik + CrowdSec(AppSec) + PostgreSQL/pgvector
│   ├── docker-compose.yml
│   ├── .env.example
│   ├── traefik/traefik.yml        static config (plugin, access log JSON)
│   ├── traefik/dynamic/           TLS certs / file-based config ภายหลัง
│   └── crowdsec/acquis.yml        log source + AppSec component
├── edge-ai/             สมอง: FastAPI 6-agent orchestrator (ใช้ Ollama เดิมของ host)
│   ├── docker-compose.yml
│   ├── .env.example
│   └── api/                       FastAPI app (Analysis Agent ใช้งานได้แล้ว)
├── pilot/MIGRATION.md   คู่มือย้าย project เดิมเข้า Traefik (มี rollback)
├── tools/               scripts ช่วยงานเอกสาร
└── docs/                รายงานศึกษา + แผนอ้างอิง
```

## ติดตั้งบน llm-server (Windows + Docker Desktop)

> **สภาพแวดล้อมจริง:** llm-server เป็น Windows ที่รัน Docker Desktop (WSL2 backend)
> Ollama เป็น Windows app/service ที่ port 11434, มี Tailscale (จึงใช้ :443 ไม่ได้ → Traefik ใช้ **:8443**)
> โมเดล qwen3.5:9b pull ไว้แล้วในเครื่อง

### ขั้นที่ 0 — เตรียมเครื่อง

```powershell
# สร้าง networks (ครั้งเดียว — คำสั่งเดียวกับ Linux)
docker network create edge_net
docker network create edge_web

# Ollama on Windows: ตั้ง env var แบบถาวร (รัน 1 ครั้ง แล้ว restart Ollama จาก system tray)
setx OLLAMA_MAX_LOADED_MODELS 1

# โมเดลมีอยู่แล้ว (ตรวจ: ollama list) — ถ้ายังไม่มีค่อย pull:
# ollama pull qwen3.5:9b
```

> **⚠️ VRAM:** เครื่องนี้ RTX 2060 12GB แต่ Windows desktop apps ใช้ไป ~8.4GB เหลือ ~3.5GB
> - **แผนสำรองสำหรับ pilot:** ใช้ `typhoon2.5-qwen3-4b` (2.5GB ทดสอบ pipeline ได้ทันที) โดยตั้ง `OLLAMA_MODEL=hf.co/typhoon-ai/typhoon2.5-qwen3-4b-gguf:Q4_K_M` ใน `edge-ai/.env`
> - เมื่อจะใช้ 9B จริง: ปิด Chrome/NVIDIA Overlay ลดการกิน VRAM, ปิดโมเดลที่โหลดค้าง (`ollama ps` ดู), หรือรอเครื่องแยก
> - `host.docker.internal` บน Docker Desktop ทำงานทันที ไม่ต้องตั้งเพิ่ม

### ขั้นที่ 1 — edge-guard (ด่านหน้า)

```bash
cd edge-guard
cp .env.example .env
# แก้ POSTGRES_PASSWORD ให้เป็นค่าสุ่มยาว ๆ
docker compose up -d
sleep 20   # รอ crowdsec ติดตั้ง collections

# สร้าง key สำหรับ Traefik plugin แล้วใส่ใน .env แล้ว restart traefik
docker compose exec crowdsec cscli bouncers add traefik-bouncer -o raw
# → copy key ไปใส่ CROWDSEC_BOUNCER_KEY ใน .env
docker compose up -d traefik
```

ตรวจ: `docker compose ps` ทุกตัว Up, `docker compose logs crowdsec | grep -i "appsec"` ทำงาน

### ขั้นที่ 2 — ย้าย project pilot

ทำตาม [pilot/MIGRATION.md](pilot/MIGRATION.md) — แก้ compose ของ project 1–2 ตัว
ให้ผ่าน Traefik + CrowdSec middleware พร้อมทดสอบว่า WAF บล็อกจริง

### ขั้นที่ 3 — edge-ai (สมอง)

```bash
cd edge-ai
cp .env.example .env
# สร้าง credentials สำหรับ edge-ai:
cd ../edge-guard
docker compose exec crowdsec cscli machines add edge-ai --password "สุ่มยาว" -o raw
docker compose exec crowdsec cscli bouncers add edge-ai-readonly -o raw
# → ใส่ค่าทั้งหมดใน edge-ai/.env
cd ../edge-ai
docker compose up -d --build
curl http://127.0.0.1:8080/health
# คาดหวัง: {"ollama":"ok","crowdsec":"ok","redis":"ok"}
```

### ขั้นที่ 4 — ทดสอบ Analysis Agent ครั้งแรก

```bash
curl -s http://127.0.0.1:8080/api/v1/analyze -H "Content-Type: application/json" -d '{
  "source": "manual",
  "event_type": "web_attack",
  "severity": "high",
  "source_ip": "192.0.2.10",
  "destination": "pilot-app",
  "evidence": {"signature": "SQL Injection Attempt", "count": 15, "time_window": "60 seconds"}
}'
```

คาดหวัง: JSON ที่มี `attack_type`, `severity`, `confidence`, `reasoning`,
`recommended_action` — วิเคราะห์ **จาก evidence เท่านั้น** (ห้ามเดา)

## Acceptance Tests (เฟส 2 ของ roadmap)

| Test | คำสั่ง | คาดหวัง |
|---|---|---|
| Traefik ขึ้นแล้ว | `curl -kI https://localhost:8443/` | 404 (ยังไม่มี router) |
| AppSec บล็อก SQLi | `curl -k "https://localhost:8443/?id=1 OR 1=1" -H "Host: <domain>" -I` | **403** |
| AppSec บล็อก traversal | `curl -k "https://localhost:8443/?f=../../etc/passwd" -H "Host: <domain>" -I` | **403** |
| CrowdSec เห็น event | `cscli alerts list` | มี alert เกิดขึ้น |
| Ban IP ทำงาน | `cscli decisions add --ip <IP> --duration 4h` แล้วเข้าจาก IP นั้น | **403** จาก bouncer |
| Health ครบ | `curl 127.0.0.1:8080/health` | ollama/crowdsec/redis = ok |
| Defense ปิดอยู่ | `POST /api/v1/defense/decision` | **503** (safety gate) |

## Roadmap ถัดไป

1. ✅ **เฟส 2 (ชุดนี้):** Traefik + CrowdSec/AppSec + pilot migration + FastAPI skeleton
2. **เฟส 3:** Wazuh all-in-one (Docker Desktop) + Suricata ใน **WSL2 Ubuntu** (มีอยู่แล้วในเครื่อง) — Suricata ไม่รัน native บน Windows
3. **เฟส 4–5:** event ingestion จริงจาก CrowdSec/Wazuh + Detection Agent (clustering)
4. **เฟส 6–7:** Decision Agent + Policy Engine (YAML, deterministic) + Defense executor (มี human approval)
5. **เฟส 8:** Attack Lab (atomic-operator บน WSL2 / VM แยก) วัด detection rate
6. **เฟส 9–10:** Learning loop (pgvector) + Dashboard (Next.js pipeline view)

## ข้อควรระวังก่อนใช้จริง

- ปลั๊กอิน CrowdSec Traefik เช็คเวอร์ชันล่าสุดก่อน pin: [Traefik plugin catalog](https://plugins.traefik.io/plugins/6335346ca4caa9ddeffda116/crowdsec-bouncer-traefik-plugin)
- Image ทุกตัวยังเป็น tag หลวม ๆ (latest/v3.3) — pin เวอร์ชันที่ทดสอบแล้วก่อนขึ้น production
- AppSec อาจ false positive กับ app ที่ input แปลก ๆ — เฟสแรกใช้ `appsecfailureblock=false` (log อย่างเดียว) ถ้าจำเป็น
- `.env` ห้าม commit — ใช้ `chmod 600 .env`
- อย่าลืมว่า port 80/443 ของเครื่องถูก Traefik กินไปแล้ว — project เก่าที่ publish 80 ต้องย้ายด้วย
