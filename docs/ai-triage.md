# AI Alert Triage Copilot

Open Dashboard → **AI Triage**, or `/AIEdgeGuard/dashboard#triage`.

1. Select a Wazuh alert from the priority queue. Default minimum rule level is 7; select 5 to include all ingested host alerts. Level 10/12 filters are also available. Queue ordering is rule level descending, then newest record. Paging uses a stable maximum-ID snapshot; **Sync queue** starts a new snapshot.
2. Choose **ไทย + technical EN** or **English**. An optional hostname hint supplies unverified analyst context; it does not rename a Wazuh host.
3. **Inspect cleaned payload** shows the exact evidence context used for the next model request, including the current hostname hint. The stream's metadata also returns the actual context used.
4. **Stream analysis** generates an advisory report through local Ollama. **Stop** cancels the client stream and closes the upstream generation when the server receives disconnect. Partial/failed reports are visibly incomplete and are not cached by the server.
5. Redis caches completed reports for 10 minutes. **Bypass cache** requests fresh generation and refreshes that cache entry. Language, selected model, cleaned evidence, hostname hint and prompt version are part of the cache key.

**Ollama settings** lists installed non-embedding model names from the existing server. Model choice applies to this page session only; leaving the server-default option uses `OLLAMA_MODEL`. The feature does not modify global Ollama settings, download models or accept an arbitrary server URL.

## Evidence and execution boundaries

Only retained Wazuh incidents are accepted for SIEM triage. The queue uses actual `event.event.rule.level`; missing or malformed levels do not qualify as high-priority alerts. The existing ingestion scope remains unchanged, including its posture/SCA filtering and minimum rule level 5.

Context includes alert ID, timestamp, severity, rule, agent, bounded data/syscheck/full-log fields and optional analyst hint. Recursive depth/count/string bounds, common secret-key and inline-secret redaction, and a 12 KB UTF-8 evidence cap keep prompts bounded. Verbose fields can be omitted, so always inspect original incident evidence for a full investigation. Byte counts are measured context sizes, not invented token savings. Redaction is not guaranteed anonymization.

The system prompt treats log text and hostname hints as untrusted data, requires source-specific observations and uncertainty, and limits the report to recommendations. Model output renders as plain text, including any HTML-like content. No tools or enforcement API are attached to this copilot. Existing stored incident analysis, decision history, policy, approval and enforcement behavior are unchanged.

One uncached copilot generation runs per API process; another concurrent request receives a retry message. Generation has a 210-second deadline, 1,600 output-token cap and 8,192-token context option. Empty, interrupted or output-limited reports are not cached. Redis failure falls back to generation; the UI reports an unavailable cache if saving fails. Existing background AI tasks still share the same host Ollama and hardware.

## API

- `GET /api/v1/ai/queue?page=1&page_size=10&min_level=7[&snapshot=…]`
- `GET /api/v1/ai/config` → installed models, default model and cache TTL
- `GET /api/v1/ai/payload/{incident_id}?hostname=…` → cleaned evidence and byte counts
- `POST /api/v1/ai/triage` with `{incident_id, language: "th"|"en", model?: "installed-name", hostname?: "hint", bypass_cache?: false}` → SSE `meta`, `token`, `done` or `error` events, with keepalive comments while waiting

Existing proxy prefixes `/AIEdgeGuard`, `/aiedge` and local unprefixed routes work. The previously authorized temporary public-preview configuration is preserved.

## Verification

2026-11-12: 47 backend regressions passed, including isolated PostgreSQL priority filtering, pagination and non-Wazuh rejection; bounded/redacted context; cache isolation; completion-only caching; upstream cancellation and slot release; busy requests and validation. Existing Dashboard browser suite passed five widths. Triage browser suite passed 1440/768/390/320px: queue pagination, settings, language and hint, payload inspection, safe text rendering, cache/bypass, fragmented UTF-8 SSE, Stop, partial errors, queue recovery and returning to Traffic.

Live Thai analysis on a retained Wazuh level-9 alert completed in about 17.5 seconds, then returned from Redis immediately on repeat. A separate uncached English request through the public HTTPS Funnel delivered its first token at about 8 seconds and completed at about 14 seconds in that validation run. These are observations, not performance guarantees. Live UI checks at 1440/768/390px rendered real queue/report data without viewport overflow or JavaScript errors.

Implementation uses [Ollama streaming chat](https://docs.ollama.com/api/chat) and [FastAPI StreamingResponse](https://fastapi.tiangolo.com/advanced/custom-response/). Run `python edge-ai/api/tests/verify_triage.py` for the browser contract suite; it mocks copilot responses and executes no real AI generation or defensive action.
