# Defense workspace

The Dashboard extends Mission Control's midnight/cyan visual system and reuses its generated shield artwork, self-hosted fonts and a subdued static 3D page background. The standalone scene, its caption and animation button were removed from Dashboard at the user’s request; Mission retains its animation.

Open `/AIEdgeGuard/dashboard`. Traffic is the initial tab. Select **Inspect #…** to view a complete request target, transport/response metadata, captured headers and original JSON. **Download JSON** exports that record. The Incidents tab also exposes source events, network addresses/ports, captured payload and packet-frame hex/ASCII where the sensor recorded them. Previous/next in the inspector navigates records on the current page.

The **AI Triage** tab adds an on-demand Wazuh/Ollama copilot with Thai/English reports, streamed output, inspected cleaned context and Redis cache. See [AI Triage](ai-triage.md) for its workflow, limits and APIs.

## Paging and evidence

- Search, source/severity/status filters and paging run in PostgreSQL. Each response includes `total`, `page`, `page_size`, `pages` and a maximum-ID `snapshot`; subsequent pages keep that anchor so new records do not shift the result window. Updates/deletions of existing records can still change results. Refresh or a filter change starts a new snapshot.
- Desktop defaults to 10 rows; small screens default to 5 labeled records. Users can choose 5–100 rows, jump to a page, or use first/previous/next/last.
- New read APIs: `GET /api/v1/dashboard/summary`, `GET /api/v1/dashboard/data/{collection}`, `GET /api/v1/dashboard/data/{collection}/{id}`. Collections: requests, incidents, campaigns, decisions, approvals, attacks. Existing array APIs remain compatible.
- Approval filtering happens before database pagination. Existing confirmation, policy, compare-and-set execution checks, Attack Lab allowlist and kill switch remain in place.

## Collection and limits

`traffic.py` imports gateway JSON access logs into the additive `gateway_requests` table, deduplicating by content fingerprint. Redis saves the file position only after a database commit. On first start it reads the last 2 MB of the log, then follows new complete lines in batches of 500 every 3 seconds. This is retained gateway history, not a reconstruction of all earlier traffic.

Default retention is 7 days and 100,000 requests, pruned about every 3 minutes. Configure `REQUEST_HISTORY_ENABLED`, `REQUEST_MAX_ROWS`, `REQUEST_RETENTION_DAYS` in `edge-ai/.env` and recreate the API container. The log is mounted read-only. Retention affects only this new request table; existing security records are unchanged.

HTTP access logs contain metadata, not request bodies or complete PCAP. Traefik retains only allowlisted request headers: User-Agent, Content-Type, Accept, X-Request-ID and X-Forwarded-For. Authorization and Cookie headers are dropped. Older log records may have no headers. Source addresses are labeled **Gateway peer** because a proxy can supply the socket peer rather than the original internet client.

Suricata EVE alert logging now includes payload (4 KB buffer), printable payload and the captured packet frame. Capture applies to alert events on the existing passive WSL `eth0` sensor; it does not imply visibility into every machine or decryption of TLS. The inspector previews base64 evidence as bounded hex/ASCII and includes the original captured event in JSON. Payload is shown only when present. Existing HTTP-WAF/Host-EDR evidence remains source dependent.

Layer and service statuses come from live telemetry. Missing/stale data displays unavailable. The background map/attack paths are illustrative artwork, not geolocation of captured events. The previously authorized temporary public preview/auth configuration is unchanged by this feature; see [public-preview.md](public-preview.md).

## Verification and deployment

2026-11-12: 38 backend regression tests passed, including isolated PostgreSQL snapshot paging, literal search, filtering before pagination, deduplication, retention and detail lookup. Browser tests passed at 1440, 1024, 768, 390 and 320 pixels across canonical, alias and unprefixed routes. They cover all tabs, paging/search/filtering, safe rendering of raw evidence, JSON export, controlled mocked approval/lab actions, failure and recovery.

Live read-only checks passed at 1440, 768 and 390 pixels: rendered real records, no horizontal viewport overflow or JavaScript errors, advancing animation frames and functional inspector. Public HTTPS Dashboard and summary returned 200. A short-lived local HTTP server and the pre-existing controlled IDS validation rule confirmed payload, printable payload and packet frame in actual EVE events and persisted incident detail. No real external attack or automatic defensive action was triggered by this validation.

API was rebuilt and recreated using `docker compose build api` / `docker compose up -d --no-deps api` from `edge-ai`. The previous image is tagged `edge-ai-api:before-dashboard-20261112`. For rollback, retag it as `edge-ai-api:latest` and recreate API with `--no-build`; retain the additive table. Traefik's previous static config backup is in the local `.artifacts/dashboard-gateway-*.yml`. Suricata's previous config is `/etc/suricata/suricata.yaml.pre-dashboard`.

Configuration references: [Traefik access logs](https://doc.traefik.io/traefik/observability/access-logs/), [Suricata EVE output](https://docs.suricata.io/en/suricata-7.0.14/output/eve/eve-json-output.html).
