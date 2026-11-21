# Phase 2 source library, declared-product checks and provenance

Delivered 2026-11-21. This finishes the remaining Phase 2 implementation after Analyst Reviews, Asset Inventory and EPSS: NVD lookup, ATT&CK reference catalog, selected IP reputation, audited product/version checks and source/prompt/model provenance. It does not complete Phase 3 evaluation or Phase 4 operational release. Asset and analyst identities remain operator-attested behind the shared Operation Key; authenticated named actors and independently verified inventory are still future work.

Open `/AIEdgeGuard/dashboard#sources`.

## Source behavior

| Source | Retrieval | Local behavior |
|---|---|---|
| NVD CVE API 2.0 | One exact CVE, operator-triggered Fetch NVD | Positive/negative cache 24 hours; one outbound request per 30 seconds across processes; descriptions, supplied CVSS metrics and configurations retained |
| MITRE ATT&CK Enterprise STIX 2.1 | Official MITRE repository; check weekly | Retains active attack-pattern techniques, versions, tactics and bounded description excerpts; rejects duplicate technique IDs; supports local search/paging |
| Spamhaus DROP IPv4 / IPv6 | Fixed publisher JSONL endpoints; check daily | Separate family snapshots, metadata/copyright/date/count validation and local-only IP-to-range lookup |
| CISA KEV and FIRST EPSS | Existing integrations | KEV daily catalog and EPSS per-CVE on-demand lookup remain separate |

`INTELLIGENCE_ENABLED` controls automatic KEV/ATT&CK/DROP catalog checks. The source maintenance loop wakes hourly and uses each provider's cache interval; failed catalog attempts are retried at a later hourly pass. NVD and EPSS never become bulk crawlers or automatic network requests from incident processing. Manual source Fetch/Refresh requires `X-Operation-Key`. Source reservations persist in PostgreSQL across API processes; catalog providers cannot be fetched more often than hourly, including failures. Source URLs are fixed, redirects are rejected and response bodies are bounded (NVD 2 MB, ATT&CK 64 MB, each DROP 4 MB), with a 75-second total download ceiling. No secrets, analyst labels, asset facts, packet payloads or observed IPs are transmitted to these providers. NVD receives only the requested CVE ID.

Sources are validated before a complete atomic snapshot replacement. Invalid/failed responses, older publisher modification dates and late responses superseded by a newer attempt preserve the previous snapshot. Identical normalized content reuses its SHA-256 fingerprint and snapshot ID. Cache freshness uses last successful check; DROP also requires a publisher timestamp within 48 hours. NVD's `lastModified` is a record-modification timestamp, and ATT&CK's publisher timestamp is the latest retained technique modification, not the date the whole feed was downloaded. The UI shows check and publisher times separately. Missing data or a no-match is never presented as safety.

DROP entries are identified by `(CIDR, SBL ID)`: multiple SBL records for one range remain distinct, while exact duplicates are collapsed with counts in the stored payload. Feed metadata count is validated against the complete input before normalization. A match is range reputation, not evidence that an event was malicious or authorization to block it. IPv4-mapped IPv6 normalizes to IPv4; private/loopback addresses produce no reputation match. Coverage is these two netblock datasets, not a general domain/hash/URL IOC database.

Provider references and terms: [NVD developer documentation](https://nvd.nist.gov/developers/vulnerabilities), [NVD developer guidance](https://nvd.nist.gov/developers/start-here), [MITRE official STIX data](https://github.com/mitre-attack/attack-stix-data), [MITRE license](https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt), [DROP usage guidance](https://www.spamhaus.org/faqs/do-not-route-or-peer-drop/), [DROP terms](https://www.spamhaus.org/blocklists/drop-fair-use-policy/). The NVD non-endorsement notice is displayed with records. The MITRE license/copyright is reproduced under `static/licenses/mitre-attack.txt` and linked from the catalog. DROP publisher copyright and date are retained and displayed as operational attribution, not a commercial endorsement. Upstream terms and limits should be rechecked when changing provider/use scope.

## Product/version workflow

1. In **Assets**, declare actual installed software using `vendor | product | version | optional CPE 2.3 | optional version scheme`. Existing three-column declarations remain accepted. CPE must identify a specific vendor/product; it is not guessed from a display name. Scheme is `unknown` by default or explicitly `numeric_dot` for dot-separated nonnegative integer version components. These remain operator declarations, not automatically verified package inventory.
2. Use **Check CVE applicability** from a saved Asset, or select a registered asset in Sources. Load its current revision, enter a CVE and Fetch/view the retained NVD record.
3. Enter a self-reported author and reason/evidence, then **Save assessment**. The server checks the selected asset revision, pins the exact NVD snapshot and stores an immutable report. A changed asset revision returns 409; the draft remains until the operator reloads the selected asset. A lost response can safely retry the same request UUID. After a confirmed save, a new deliberate save can create a new assessment against updated source data.
4. Saved history is paginated. Opening a historical result displays its saved reason, author, time, asset revision, NVD snapshot and full product criteria/uncertainty, separately from an editable new-assessment draft. The historical report is not recalculated when declarations or catalogs change.

The checker is deliberately bounded, not a complete CPE/configuration engine:

- It checks literal declared CPE product identity and supported platform/edition fields, exact versions and explicit inclusive/exclusive bounds. Numeric ordering requires `numeric_dot`; arbitrary vendor strings, prerelease schemes and unsupported wildcard/escape patterns produce uncertainty. Numeric-dot components compare as integers with trailing zero components padded; this is an operator-selected convention, not a universal package version rule.
- Missing CPE/version/platform details, inconsistent CPE versus declared version, absent configurations or unsupported configuration depth/size return review/unknown states. Product applicability is not inferred from NVD descriptions, AI prose, KEV membership or EPSS.
- A simple supported vulnerable-criterion match is **Candidate match**, not a verified affected installation. AND, negation and environment prerequisites require review even when a product/version clause matches. Non-vulnerable environmental criteria are not discarded to claim success. Rejected/unanalysed records cannot yield an overall confirmed candidate state.
- A no-match describes only the declared products and supported criteria examined. Incomplete inventory, unsupported comparisons, deployment conditions, code-page settings, configuration and compensating controls still need investigation. It is not a clean-asset verdict or proof of exploitation.

## Analysis citations and model provenance

New incident analyses can receive bounded **local cached** references for exact CVE/ATT&CK identifiers mentioned in source event data and matches for observed public source/network IPs in retained DROP ranges. Literal identifiers may be attacker-controlled or misclassified. Catalog text and analyst declarations remain untrusted data, never instructions. A local-enrichment failure or five-second timeout does not stop durable ingestion or analysis.

Primary incident evidence has priority in the 6,000-character analysis input. Catalog references are included only when they fit in the remaining budget; the persisted `source_citations` contains only references actually provided, not all lookup hits or model-invented citations. Metadata records available/provided reference counts, prompt version, SHA-256 of system/input text, input length/truncation, requested and returned model names, execution type and timestamp. Truncated primary evidence forces human review. Deterministic fallback and timeout are explicitly labeled and do not pretend a model analysis succeeded. Existing analyses are not retrospectively assigned citations or metadata.

Where available, a local Ollama `/api/tags` check records the observed tag digest and observation time, cached for 60 seconds. This is a model-version observation, **not immutable runtime attestation**; the actual runtime digest remains unknown because this chat response does not supply one. A missing tag catalog does not block inference. No model is pulled or changed by this metadata check.

The Incident inspector exposes prompt/model metadata and immutable source snapshot links. AI Triage exposes a provenance disclosure after cleaned payload. Its prompt/input hashes, requested model and observed tag digest accompany SSE metadata and its existing 10-minute Redis report cache; this copilot does not rewrite incident evidence or introduce permanent report storage. An older cached report without provenance remains explicitly unrecorded.

## Interfaces and persistence

| Interface | Purpose |
|---|---|
| `GET /api/v1/knowledge/status` | Retained ATT&CK/DROP freshness/error/attribution |
| `GET /api/v1/knowledge/nvd/{cve}` | Cached NVD record, no outbound request |
| `POST /api/v1/knowledge/refresh/{nvd,mitre,drop4,drop6}/{key}` | Gated source lookup; exact CVE key for NVD, `catalog` for other providers |
| `GET /api/v1/knowledge/techniques?q=&page=1&page_size=10` | Local active-technique search/paging |
| `GET /api/v1/knowledge/ip?value=...` | Retained family-specific range lookup only |
| `GET /api/v1/knowledge/snapshots/{id}` | Complete immutable normalized source snapshot |
| `POST /api/v1/applicability` | Gated `{asset_id, asset_revision, cve, declared_by, rationale, request_id}` assessment |
| `GET /api/v1/applicability/{id}` | Immutable pinned report |
| `GET /api/v1/applicability/asset/{uuid}?page=1` | Saved report history, 10 per page |

`knowledge_snapshots`, `knowledge_cache` and `knowledge_budget` separate immutable source content from mutable freshness/pointers and outbound reservations. `applicability_assessments` references both asset revision and NVD snapshot, records the authorization method and checker version, and rejects ordinary UPDATE/DELETE. Existing software JSON without CPE fields stays valid; newly saved declarations add default values. Source/assessment snapshots have no automatic pruning in this release, preserving citation history; disk growth needs operational monitoring.

Migration is additive and initializes before background tasks. Roll back API only to `edge-ai-api:before-phase2-complete-20261121`; leave new tables for audit. That image retains reviewed-TP-only memory and EPSS/asset behavior. Older pre-reviewed-memory code needs the separate learning rollback precautions. Preview routes, Operation Key gates, target protections, dry-run and human approval remain unchanged. No production test assessments, invented software declarations, fake analyst labels or simulated attacks are required for verification.

## Acceptance and remaining work

Phase 2's implementation gate is satisfied for the declared operator workflow: correct alerts with revisioned review history, retrieve reviewed-TP-only memory, record explicit asset mappings, inspect dated KEV/EPSS/NVD/ATT&CK/selected IOC sources, save supported product/version checks with pinned evidence, and trace newly generated analysis context/model metadata. This does not certify inventory truth, named identity, detection accuracy or end-to-end attack causation.

Phase 3 still requires a labeled corpus, coverage/drift handling, held-out evaluations and qualified attack-graph evidence. Phase 4 retains authenticated roles/MFA, independent inventory verification, action-specific playbooks, deployment/CI hardening, monitoring and operator-authorized automation. Full ecosystem/CPE applicability and additional IOC providers need further supported matching rules and evidence; unsupported cases currently route to review. See [Roadmap V2](roadmap-v2.md).

Validation on2026-11-21:98 backend tests passed locally and in the deployed Docker dependency set against an isolated PostgreSQL database. Sources checks passed1440/768/390/320px and three route prefixes, including lost-response retry, concurrent revision conflict/reload, saved-reason/draft separation, source/assessment links, local IP lookup, paging and hostile literal text. Existing Dashboard, Intelligence, Assets, Reviews, EPSS and Triage browser suites passed. Fresh UI review identified two small fixes; the verdict pass scored both resolved (`ship` for those fixes). Live read-only captures at1440/768/390px had no overflow, JavaScript errors or browser writes. Official retained catalogs contained706 active ATT&CK techniques (release20.1),1751 DROP IPv4 records and90 IPv6 records; NVD CVE-2024-4577 was fetched successfully. Gated fetch/assessment requests without the key returned403, public443 source endpoints returned200, and defense remained dry-run/human approval. Two ordinary newly analyzed incidents already contained persisted prompt/model provenance and observed model digests at verification time. The production registry/assessment tables remained free of synthetic test declarations.
