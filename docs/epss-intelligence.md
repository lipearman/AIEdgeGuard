# FIRST EPSS lookup and score provenance (Release 2C.1)

Delivered 2026-11-21. Open `/AIEdgeGuard/dashboard#intelligence`, enter a CVE in **EPSS exploit likelihood**, or select **View EPSS** on a KEV entry.

## Read and fetch are separate

**View cached score** reads PostgreSQL only. **Fetch from FIRST** requires the existing Operation Key and requests one exact CVE from the fixed HTTPS FIRST endpoint. A successful lookup, including a no-score result, is cached for 24 hours. All API processes share a database-enforced budget of one outbound request per 30 seconds. HTTP 429 includes Retry-After. No incident payload, asset metadata, operator identity or key is sent to FIRST; only the requested CVE ID and result limit.

EPSS is on-demand in this release. CISA KEV still has its separate daily sync. EPSS is not refreshed merely by opening a public page, reading a cache entry or running the analysis worker. For eventual bulk/daily EPSS ingestion, use the publisher's CSV workflow rather than looping over its lookup API. [FIRST data access guidance](https://www.first.org/epss/data), [EPSS API](https://api.first.org/epss/).

The UI shows probability and percentile rank separately, score date, original snapshot fetch time, latest lookup attempt/success, cache state, FIRST API version, original source link and stored snapshot link. API version is not the EPSS model version. A score is shown as current only when its successful lookup is less than 24 hours old, its score date is at most two UTC calendar days old and the last lookup returned a score without errors. Otherwise an earlier score is explicitly stale. Reusing an unchanged snapshot retains its original fetched timestamp; latest-success time records the newer lookup.

Missing results mean **not scored**, never zero probability or a clean asset. Network errors, invalid/unexpected responses and publisher date rollback retain the last stored score with an error. A later empty result keeps any earlier snapshot separately as stale; it does not silently promote it to a current score.

## Meaning and source terms

[FIRST EPSS](https://www.first.org/epss/) estimates observed exploitation activity for a published CVE over the following 30 days. Percentile describes its ranking among scores. This is not impact/severity, proof a specific asset is affected, evidence a particular incident exploited that CVE, or a defense authorization. Use asset/version applicability and captured evidence separately. No threshold changes policy, bans an address, trains the local model or rewrites existing analysis in this release.

Attribution stays visible as **FIRST EPSS** with publisher links. Data access is free without registration; this integration is for preventative cybersecurity and incident-response use under the publisher's [Services Terms of Use](https://www.first.org/about/policies/terms). The local 30-second outbound budget is an application restriction, not a claim about the publisher's quota. See the publisher's [API rate-limit documentation](https://api.first.org/#rate-limit) for current upstream limits. NVD/CVE descriptions, product applicability, EPSS bulk sync, MITRE and IOC providers remain separate roadmap work.

## API and storage

| Endpoint | Behavior |
|---|---|
| `GET /api/v1/intelligence/epss/{cve}` | Public cached lookup only; never contacts FIRST or inserts a cache row |
| `POST /api/v1/intelligence/epss/{cve}` | Gated by `X-Operation-Key`; returns `action` (`cache_hit`, `fetched`, `failed`, `superseded`) and `result`, or HTTP 429 |
| `GET /api/v1/intelligence/epss/snapshots/{id}` | Immutable stored score, date, source, API version, fingerprint and original fetched timestamp |

`epss_snapshots` holds normalized validated score snapshots. Fingerprints use SHA-256 over the normalized score/CVE/date/API-version content; they are not hashes of the complete raw HTTP response. Ordinary UPDATE/DELETE is rejected by a database trigger. Identical snapshot content reuses its ID. `epss_cache` records the latest attempt/result and pointer to the retained score; `epss_request_budget` serializes outbound reservations across processes. An older lookup completing after a newer attempt cannot overwrite its result/error; it returns `superseded`. Migration adds tables without changing old evidence or asset/review records.

Only a bounded 64 KB response is accepted, without redirects, with a 15-second HTTP timeout. Validation requires the requested CVE, complete count/offset, API version, finite probability and percentile in 0–1, and a nonfuture score date. Unexpected records or partial responses reject the whole lookup. Errors shown publicly are bounded generic messages; keys and response bodies are not logged by the lookup code.

## Validation and rollback

Isolated PostgreSQL tests cover schema, score/date/type validation, cache hits, immutable snapshots, deduplication, stale/empty/failure preservation, concurrent global budget and publisher-date rollback. Mocked browser tests cover 1440/768/390/320px across three route prefixes, cache-only reads, catalog selection, gated fetch, probability/rank rendering, snapshot links, key rejection/re-prompt, rate-limit recovery and hostile literal text. Production verification uses official public CVE data only, without test asset declarations or analyst verdicts.

Rebuild/recreate the API only. Rollback image: `edge-ai-api:before-epss-20261121`; additive EPSS tables may remain. Existing reviewed-memory rules, asset mappings, preview routes, Operation Key gates and human approval policy are preserved. [Roadmap V2](roadmap-v2.md) distinguishes the delivered slice from remaining work.

2026-11-21 verification: the full 85-test backend suite passed with deployed Docker dependencies; the local baseline of84 and final8 EPSS tests passed against isolated PostgreSQL. EPSS browser checks passed four widths/three prefixes; existing Dashboard, Intelligence and Assets suites passed. Live read-only captures at1440/768/390px displayed an official cached FIRST score dated2026-11-20 with snapshot1, without overflow, JavaScript errors or browser writes. The public Internet443 cached API returned200; an ungated fetch returned403. A gated official lookup succeeded and the snapshot was readable; defense remained dry-run/human approval. Fresh UI review disposition: `ship` at this bounded EPSS scope.
