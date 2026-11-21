# Phase3B — candidate evidence case graphs

Delivered 2026-11-22. Open Dashboard **Traffic or Incidents → Inspect → Candidate evidence graph**. This release supplies bounded, typed, reproducible associations. It does not establish a causal attack chain, independently validate evidence, or change defense policy.

## Investigation workflow

1. Inspect the retained anchor. Expand **Create case snapshot**, choose ±5/15/30/60 minutes, and supply a self-reported author and investigation purpose. Saving requires the existing Operation Key.
2. A UUID creates an immutable case. **Load saved cases** lists prior snapshots for this anchor,10/page. Later arrivals require a new UUID; original membership never changes.
3. The fan diagram expands **one hop**, showing the anchor and8 linked nodes/page on desktop or4 on mobile. The selectable text list is its complete paginated equivalent. Positions are not a time axis or causal sequence. The diagram consolidates multiple association types per pair; select a node to inspect every typed edge.
4. Inspect observed versus ingested/stored time, effective timeline basis, timestamp field/state, source hash and link reasons. Delay greater than5 minutes is labeled late with an explicit source-clock caveat. Missing event times remain unknown.
5. Inspect pinned bounds and current asset declarations, or export the exact case JSON. **Open stored record JSON** reads the current source record; it may be unavailable later. A hash/minimal fact snapshot cannot recover deleted raw evidence.

An ambiguous save retains its UUID/input in session storage. Reopen the same anchor after closing/reloading to restore **Retry same case snapshot**. Pending fields stay locked. Identical input returns the original record; conflicting UUID input returns409. Indexing-not-ready also returns409 and can be retried with the same UUID. Key/validation failures retain editable drafts. Do not clear session storage before resolving an ambiguous write. The shared key does not verify the declared name.

## Time indexing and late arrival

Incident ingestion adds derived `event_observed_at`, `event_time_field` and `event_time_state`. Raw JSON and original `created_at` ingestion time stay unchanged.

| Source | Observed field | Boundary |
|---|---|---|
| HTTP history | Existing `observed_at` from `StartUTC` | Existing collector normalization; `collected_at` is ingestion time |
| Wazuh | Raw `timestamp` | Sensor-reported, clock unverified |
| Suricata | EVE `timestamp` | Sensor-reported, clock unverified |
| CrowdSec | Alert `start_at` | Start of aggregated interval, not every contributing request |
| Unsupported | None | Ingestion fallback, not a guessed event time |

Incident source parsing requires a timezone-aware ISO timestamp of at most80 characters. Missing, invalid, timezone-missing, unsupported and over-five-minutes-future values receive explicit states and use ingestion fallback. Clocks up to5 minutes ahead can be recorded with a negative-delay warning; synchronization accuracy is not asserted. The existing HTTP collector's earlier timezone normalization is preserved, not newly certified.

A bounded worker backfills **only derived metadata**,500 incidents/transaction with row locks/`SKIP LOCKED`. A partial pending index avoids rescanning completed records. Normal new ingestion derives metadata at insert. Creation waits until no retained incidents remain `not_indexed`; missing/invalid time remains unknown even after indexing.

Membership uses `COALESCE(event_observed_at,created_at)` for incidents and observed time for HTTP. Thus an alert ingested hours late can join a **new** case around its reported event time. Repeatable-read PostgreSQL transactions pin consistent source/asset views and source high-water IDs. Concurrent same-UUID creation uses bounded retries and returns the same record. Later ingestion never changes an old case.

## Typed confidence

Confidence describes the **stated association/reference**, not attack probability, actor identity or independent validation. No value activates a response.

| Link | Confidence | Limit |
|---|---|---|
| Same recorded request ID | Low | Client supplied/reusable/spoofable; IDs over200 characters excluded rather than prefix-matched |
| Same Wazuh agent ID | Medium | Same sensor-reported ID, not independently verified endpoint identity |
| Same observed source IP | Low | Shared NAT/proxy does not identify an actor; private HTTP peers retain existing exclusion |
| Shared observed endpoint IP | Low | Shared/reassigned addresses remain ambiguous |
| Current operator asset binding | Low | Current route/parent or host declaration pinned by revision, not event-time identity |
| Incident→decision stored reference | High for linkage only | Exact `incident_alert_id`, not causal attack linkage or proof of execution |

Event associations are undirected; decision references are directed and marked `stored_reference_only`. Exact referenced decisions can occur outside the event window. Creating a graph never executes or modifies a decision.

Bare time proximity, a common route, AI-proposed CVE or model classification does not create an edge. Existing unique asset-binding rules apply, and ambiguous shared endpoint mappings do not establish identity. Pinned current declarations and revisions remain distinct from historical fact; raw evidence and AI analysis stay separate.

## Bounds and provenance

Maximum80 event nodes including anchor, plus20 directly referenced decisions. Each source query is capped at81 rows in effective-time order; combined event selection is capped and truncation is visible. This is bounded retrieval, not exhaustive discovery or relevance ranking. Weak candidates can be filtered after selection, so fewer displayed nodes do not imply full coverage. No candidates means no links under these rules, not no attack.

Immutable `evidence_cases` stores specification, purpose/author, shared-key authorization mode, source high-water IDs, algorithm version, implementation SHA-256, source hashes, node times, typed links, asset context, limits and content SHA-256. Triggers reject ordinary updates/deletes. No body/PCAP capture, external feeds or LLM calls are added. JSON contains operational identifiers and follows existing authorized public-preview read access.

## API

| Method/path | Purpose |
|---|---|
| GET `/api/v1/cases/index/status` | Counts by derived timestamp state |
| GET `/api/v1/cases?anchor_kind=requests&anchor_id=1&page=1` | Case history for one anchor,10/page |
| PUT `/api/v1/cases/{uuid}` | Gated immutable creation; same UUID/input is idempotent |
| GET `/api/v1/cases/{uuid}` | Original case/provenance/JSON export |

Example create body; replace the anchor with a real retained record and use a caller-generated UUID:

```json
{"anchor_kind":"incidents","anchor_id":1,"minutes":15,"declared_by":"Operator label","rationale":"Evidence-based investigation purpose"}
```

## Validation and deployment

The113-case backend suite passed locally and in Docker, including source timezone/future/unsupported handling, no AI time fallback, raw/ingestion preservation, late arrivals, concurrent same-UUID creation, content hashes, immutability, decision references, node bounds, asset revision pinning and HTTP→host candidate mapping. Browser checks use intercepted synthetic fixtures at4 widths/3 prefixes: pending retry across reload, accessible graph/list, paging, time facts, keyboard, export, empty/error recovery, XSS and no overflow. Existing Dashboard regression checks passed5 widths/3 prefixes; Intelligence/Investigation passed4 widths/3 prefixes. Fresh finish review returned `ship`; the documenter confirmed the extension fits the incumbent system without token changes. These are engineering fixtures, not production detection metrics.

Deploy only the API service. Additive indexes/columns/case tables initialize at startup. Rollback: `edge-ai-api:before-cases-20261122`, retaining additive schema/history. Authentication, preview configuration, policy and auto-execution remain unchanged. Phase3 independent maker/checker, drift controls, richer behavioral features and measured production detection remain open.

Live checks on2026-11-22: historical timestamp indexing completed with no pending rows, actual request drawers passed read-only desktop/mobile checks, and the case registry remained empty (no synthetic production case was created). Writes without an Operation Key returned403. The host Ollama service was found stopped and restarted using its existing executable; health then reported Ollama/CrowdSec/Redis/Postgres `ok`. This connectivity check is not a model-quality or latency benchmark.
