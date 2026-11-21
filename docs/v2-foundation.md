# Intelligence and investigation foundation

Implemented 2026-11-21. Open Dashboard → **Intelligence** (`/AIEdgeGuard/dashboard#intelligence`).

## Threat intelligence

The API imports [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) using the official [JSON schema](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json). Downloads use fixed CISA and official CISA GitHub mirror URLs, TLS verification, size/time bounds and no redirects. No logs are uploaded to these sources.

A validated snapshot atomically updates `known_vulnerabilities`; removed entries remain stored but inactive. Invalid downloads and older releases preserve the last good snapshot. `intelligence_feed` stores source, catalog version/release, attempt/success timestamps and errors. `INTELLIGENCE_ENABLED=true` enables daily background refresh; failures retry after 30 minutes. Manual **Sync catalog** uses the existing Operation Key. Turning automatic refresh off retains the catalog and authorized manual refresh.

`current` means a successful download within 48 hours and no later sync failure; it does not claim complete vulnerability coverage. Worker analysis receives at most three bounded KEV references for exact CVE mentions in source events, with freshness and applicability caveats. Enrichment failure does not stop analysis. This does not rewrite past analysis, deploy rules, establish local software applicability or prove exploitation.

## CPU traffic baseline

Compare the latest **completed** five-minute bucket with the preceding 12 buckets, using the 50 most active retained host/router groups in that 65-minute range. A volume signal requires ≥20 requests, ≥3 times baseline median and robust score ≥6. The score scales by max(3, square-root median, 1.4826 × MAD). Insufficient retained history shows **Warming up**. No GPU or new ML dependency is used.

This is a heuristic, not trained ML, causal attribution or an attack verdict. `stale` means no collected request within 10 minutes. Missing data is distinct from normal results. Collector gaps can resemble zero traffic even when the earliest retained record is old enough; continuity-aware baselines are future work. The result does not create a ban or change policy.

## Candidate timeline and evidence

From Traffic/Incidents select **Inspect → Investigate timeline & evidence**. Request inspection normalizes at most 16 KB / 100 query fields, performs at most two URL-decode passes, masks common secret query keys and lists syntax hints. Raw evidence remains separately available. Masking is not guaranteed anonymization and no body capture is added.

The timeline finds candidate incidents within ±15 minutes by default (API supports 1–60 minutes). Reasons include recorded source IP, Wazuh agent ID, endpoint IP appearing in telemetry, or recorded request ID. Private gateway peers do not establish requester identity. Incident-side private IP links remain candidates; shared NAT/proxy and ingestion timing can mislead. Manager agent `000`, loopback, unspecified, multicast and link-local addresses do not provide identity.

Only selected stable metadata keys are matched; no host/application mapping is inferred from URLs alone. Missing matches may reflect scope or missing identifiers, not safety. Pages contain 50 incidents and can change as late records arrive. The latest 20 linked decisions expose policy checks, rationale, status and response results; earlier records remain in Decisions.

Source CVE mentions and AI-only mentions are separated. KEV lookup uses source mentions and shows snapshot freshness, without claiming applicability. Incidents retain ingestion timestamps. Verified attack graphs, event-time normalization and asset inventory are later stages.

## API and deployment

- `GET /api/v1/intelligence/status`
- `GET /api/v1/intelligence/vulnerabilities?q=PHP&page=1&page_size=10`
- `POST /api/v1/intelligence/sync` with `X-Operation-Key`
- `GET /api/v1/investigation/behavior`
- `GET /api/v1/investigation/timeline/{requests|incidents}/{id}?minutes=15&page=1`

Additive tables initialize after existing schema on startup. Compose passes `INTELLIGENCE_ENABLED`; existing defense, lab, authentication and preview settings are preserved. Rebuild/recreate only API. Pre-release rollback image: `edge-ai-api:before-v2-20261121`; rollback requires no table deletion. See [Roadmap V2](roadmap-v2.md) for delivered versus planned work.

## Verification on 2026-11-21

58 backend regression tests passed against an isolated PostgreSQL/pgvector database, including the final Docker image's Python 3.12 dependency set. New browser checks passed four widths and three route prefixes; existing Dashboard checks passed five widths and Triage checks passed four. They cover feed paging/search, gated mock sync, missing/warmup baseline states, decoded hostile content, candidate/policy evidence and API failure/recovery. UI review disposition was `ship` for the declared foundation scope.

Live read-only checks retrieved 1,790 KEV records, 15 PHP search matches and a five-record Wazuh candidate timeline in that validation run. Manual sync without an operation key returned 403. Real UI data rendered at 1440/768/390px without viewport overflow or JavaScript errors; public HTTPS Dashboard/status/behavior endpoints returned 200. Traffic freshness was reported as observed, including stale or sparse windows. No live attack, ban or new automatic response was executed by this verification.
