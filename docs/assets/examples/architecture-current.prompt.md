# Architecture image generation

Date: 2026-11-13 (Asia/Bangkok)
Tool: built-in imagegen (edit mode). No CLI/API fallback.
Original visual reference: user's `ChatGPT Image Nov 12, 2026, 12_56_00 PM.png`.
Published output: `architecture-current.png`.
Validated against source: telemetry.py, watcher.py, worker.py, traffic.py, triage.py, agents/decider.py and the current feature documentation.

The final image was generated and inspected, then corrected twice for engineering arrow direction. Full prompt set follows.

## Initial edit prompt

Edit the supplied architecture diagram into a CURRENT, technically accurate LACD architecture infographic as of 2026-11-13. Image 1 is the edit target and visual reference. Preserve its midnight navy, luminous cyan event arrows, amber enforcement arrows, thin white rounded containers, crisp readable white sans-serif lettering, simple line icons and polished technical presentation. Recompose substantially to fit the new complete flow without overlaps. Produce one very high resolution landscape 16:10 infographic, generous legible labels, no tiny paragraphs. This will replace the diagram on a GitHub README. English text for reliable readable technical labels.

Title exactly: "LACD" / "Local AI Cyber Defense" / "Current Architecture · 2026-11-13".
One outer environment heading: "Windows host · Docker Desktop · Ubuntu WSL". Ollama runs locally on the host, API/Redis/PostgreSQL in Docker, sensors have explicitly labeled scope.

Use FOUR spacious numbered horizontal sections. Draw only the following meaningful directed connections; do not invent direct security-engine access by the LLM.

1 "TRAFFIC & THREE-LAYER VISIBILITY"
Main traffic chain left to right: "Internet / Tailnet" → "Tailscale Funnel / Serve" → "Traefik Gateway" → "CrowdSec AppSec WAF" (subtitle "HTTP-WAF · OWASP CRS · virtual patching") → "Protected Applications".
Separate sensor strip below: "Suricata" (subtitle "Network-IDS · passive WSL eth0 · EVE alerts") and "Wazuh Agents → Manager" (subtitle "Host-EDR · Windows + WSL · alerts.json"). These are CONNECTED, not planned. Do NOT draw all application traffic through Suricata or Wazuh. State "Network visibility: configured WSL eth0 only".
Traefik has a clearly independent branch "Access log → Request Collector" with label "HTTP metadata + allowlisted headers" feeding PostgreSQL request history below. WAF has "LAPI alerts" feeding Watcher in section 2.

2 "PERSIST-FIRST EVENT & AI PIPELINE"
CrowdSec "LAPI alerts → Watcher"; "Suricata EVE + Wazuh alerts.json → Sensor Ingestion". Both ingestion paths converge into ONE "PostgreSQL + pgvector" storage box/cylinder, with subtitle "Incidents · request history · campaigns · decisions · audit". Mark "Persist first / durable outbox".
From persisted incident outbox draw cyan sequence: PostgreSQL → "Redis Streams" → "Worker / Analysis Agent" ↔ "Local Ollama" (subtitle "Qwen / Typhoon · local inference"). Worker analysis results are saved BACK to PostgreSQL. Depict Ollama as host service, not inside Docker boundary. If a Docker API boundary is shown, label only API/Redis/PostgreSQL appropriately; do not put host Ollama or Windows agents inside it.
Below/aside database: "Learning Agent" ↔ "pgvector memory", with "Embeddings + similar incidents (RAG)" and a cyan context arrow to Worker/Analysis. No claim of training or model fine tuning.
Keep one coherent storage box; use labeled routed connectors where needed.

3 "POLICY, APPROVAL & CONTROL"
From analyzed incidents in PostgreSQL branch to "Detection Agent" (subtitle "Correlate campaigns → PostgreSQL") and separately "Decision Agent / Policy Gate" (subtitle "Protected IPs · confidence · cooldown · TTL").
AMBER enforcement sequence: "Decision Agent / Policy Gate" → "Human Approval" (subtitle "Default: dry-run") → "Defense Executor" → "CrowdSec IP ban / TTL", routed up to the WAF box. No enforcement arrow originating at Analysis or Triage.
An AMBER dashed bypass from Policy Gate to Executor labeled "Optional L1 auto-execution · off by default".
"Dashboard / Mission Control" reads PostgreSQL and service/sensor status, offers "Paging · inspect evidence · approve · audit", with approval connector to Human Approval.
Compact "Attack Lab" card: "Kill switch + target allowlist · authorized lab only" → "Lab apps via gateway". Do not depict arbitrary public targets.
Include small factual limit "HTTP history stores metadata; alert payload/frame only when captured. No full PCAP / no general HTTPS body capture."

4 "ON-DEMAND AI TRIAGE COPILOT"
Clearly independent advisory branch, NOT connected to Defense Executor.
"PostgreSQL Wazuh incidents" → "Priority Queue" (subtitle "Rule level ≥ 7 · paginated") → "Cleaned Context" (subtitle "Bounded + secret-pattern redaction") → "Redis Cache" (subtitle "10-minute completed reports").
From Redis Cache draw cyan "Hit" → "SSE Report / Dashboard". Draw "Miss / Bypass" → "Local Ollama" → "SSE Report / Dashboard", and a return connector from completed report to Redis labeled "Cache completed report".
Use a repeated Ollama reference node for readability if necessary, labeled "Same local Ollama". UI feature text "Thai / English · installed model · hostname hint · inspect context · Stop".
Prominent note inside this lane: "ADVISORY ONLY · no enforcement · does not overwrite incident analysis".
Cache key footnote: "Evidence + language + model + hostname hint".
No unsupported labels: no "planned integrations", no "automatic ingestion pending", no "all traffic captured", no "AI directly blocks", no live health percentages, no authentication guarantees, no credentials or concrete private addresses. Do not invent token reduction statistics.
Footer: "Local inference · Persist-first ingestion · Deterministic policy · Human approval". Legend cyan "Events / context", amber "Approved response", amber dashed "Optional disabled path".
Quality: clean orthogonal arrows with unambiguous arrowheads, no ambiguous line crossings, enough space, polished readable infographics over decorative effects. Preserve the reference's identity while correcting all flow errors.

## Connector correction

Precisely correct the connectors in this current LACD infographic. Image 1 is the edit target. Preserve all current wording, title/date, palette, line icons, four horizontal sections, positions and overall finish. Only adjust connections/spacing as needed for these engineering corrections:
1. REMOVE the cyan arrow descending from the upper WAF "LAPI alerts" label directly into Worker/Analysis Agent. This is WRONG and bypasses persist-first ingestion. Remove that vertical elbow, its Worker arrowhead and its dangling "LAPI alerts" caption altogether. The already present far-left "CrowdSec LAPI alerts" source box feeding Watcher is the correct WAF source, so retain it. Do not add any direct WAF-to-Worker arrow.
2. In section03 REMOVE the horizontal cyan arrow from Detection Agent to Decision Agent / Policy Gate. These are independent consumers of analyzed PostgreSQL incidents, NOT a serial detection→decision chain.
3. Branch the cyan PostgreSQL downward line in section03 into THREE distinct arrowheads: one into the top of Detection Agent, one into the top of Decision Agent / Policy Gate, one into Dashboard / Mission Control. Clearly readable tiny label near the two agent branches: "Analyzed incidents". Keep Dashboard database read connector. Detection's subtitle "Correlate campaigns → PostgreSQL" already states its writeback so no extra campaign arrow needed.
4. Make the connector from Dashboard toward Human Approval a thin white arrow pointing INTO Human Approval, labeled "Approve / reject". It is a user action sent to the approval workflow, not an automatic policy result sent into Dashboard. Keep the main AMBER sequence Policy Gate → Human Approval → Defense Executor → CrowdSec ban / TTL, and the optional amber dashed path to Executor exactly correct.
5. Add one small cyan outgoing connector from the Attack Lab / Lab apps via gateway card, routed to the existing Traefik Gateway node and labeled "Controlled lab traffic". Do not connect Lab to arbitrary public targets.
Everything else must be retained, especially the active Wazuh+Suricata strip, collector→PostgreSQL branch, persist-first PostgreSQL→Redis Streams→Worker, Worker→PostgreSQL analysis result, Worker↔host Ollama, Learning→Worker context, and full independent on-demand cache-hit/cache-miss triage branch with no enforcement connection.
Use clean orthogonal connectors, no ambiguous junction dots on mere line crossings, precise arrowheads, small routing adjustments only. Maintain high resolution and readable labels. Do not restore planned integrations. No new functionality, text paragraphs or boxes.

## Final cleanup

Make TWO exact connector cleanup edits to Image 1, the current LACD architecture. Keep every word, box, icon, date, section and other connector unchanged.
A. Remove ONLY the cyan "Controlled lab traffic" connector, its entire long routed path and that caption. Specifically erase the cyan route leaving the Lab apps card at bottom-left, going up alongside/through the Sensor Ingestion and Suricata boxes and ending as an upward arrow into Traefik. It wrongly crosses sensor boxes. Keep the Attack Lab card and its existing "Lab apps via gateway" text, which sufficiently explains its target without a long connector. Leave sensor-to-ingestion, Watcher-to-PostgreSQL and other cyan lines intact.
B. Make the PostgreSQL analyzed-incidents fan-out unambiguous. Connect the cyan downward database line to a small horizontal cyan bus just ABOVE both Detection Agent and Decision Agent / Policy Gate. Put a separate downward arrowhead FROM THAT SAME BUS into Detection Agent, and another into Decision Agent / Policy Gate. These are parallel PostgreSQL consumers. Keep the separate database-to-Dashboard read arrow as well. There must not be a Detection→Decision arrow. The bus must physically join the existing PostgreSQL downward connector, not float unattached. Retain the two "Analyzed incidents" labels if they fit.
All remaining flows, especially persist-first, host Ollama, independent Triage/cache/SSE, policy/human/executor and the no-PCAP/advisory limitations must remain exactly the same. High-resolution image, no new text, no new boxes, no other rearrangement.
