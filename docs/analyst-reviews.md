# Analyst feedback and reviewed AI memory

Release 2A, 2026-11-21. Open Dashboard → **Incidents → Inspect → Analyst review**.

## Reviewing an incident

Choose **True Positive**, **False Positive** or **Unknown**, enter a reviewer label and rationale, and optionally correct the attack classification or severity. Submit **Append review revision** with the existing Operation Key. Each save creates a new revision; original event data, AI analysis, decisions, pending approvals and IP bans remain unchanged.

The reviewer label is self-declared. The shared key authorizes the operation but does not authenticate a named person. Every revision records that authorization method, label, rationale, correction and server timestamp. Named-user identity, MFA and roles remain separate roadmap work. Operator labels are reviewed observations, not independently verified ground truth or measured detection accuracy.

History is newest first with paging. To correct a prior assessment, append another review rather than editing the old entry. Database triggers reject ordinary UPDATE/DELETE of review rows; database administrators can still alter schema or truncate tables. This is application/database append-only history, not a cryptographically tamper-proof ledger.

Saves require the expected latest revision. Concurrent changes return 409 and retain the draft until **Reload latest**. A client UUID makes retrying the same submission idempotent; a lost response can be retried without another revision. Reusing that UUID with different review content is rejected. Never enter secrets in reviewer labels or rationale; review history follows the existing public-preview read-access policy.

## What enters AI memory

Only an incident's **latest True Positive review**, with completed stored analysis, can enter reviewed RAG. The background learning agent embeds its effective classification/severity, original evidence summary and bounded analyst rationale. Optional corrected fields are separate review annotations; blank fields use the original stored classification/severity.

Vectors in `reviewed_memory` bind to the exact review ID/revision and embedding model, with a source-text hash. A changed review immediately disqualifies the old vector from subsequent queries. False Positive, Unknown and unreviewed incidents are excluded. A revised True Positive waits for a new embedding. Jobs finishing after a review changed cannot restore their stale vector. The default learning loop checks every 60 seconds; embedding service failures leave the eligible record pending for retry.

All pre-release `incidents.embedding` vectors remain stored as legacy data; they are not promoted to verified knowledge or silently relabeled. Mission now reports **Reviewed TP embedded**, and Intelligence reports eligible/ready/unreviewed counts. A newly upgraded system can correctly show zero reviewed memory even with many legacy vectors. Query embedding is skipped when no reviewed candidates exist.

The worker records the exact review IDs/revisions it retrieved in `analysis.reviewed_memory_sources`, and the inspector links those immutable revisions. Already-running or historical analyses are not rewritten when a later review changes; the recorded references explain which snapshot was used. Rationale is treated as untrusted model context, not instructions. This is retrieval augmentation, not model training; feedback never enables a firewall rule or authorizes a response.

## API and data

- `GET /api/v1/reviews/stats`: reviewed verdict counts, eligible/ready memory and identity scope.
- `GET /api/v1/reviews/{incident_id}?page=1&page_size=10`: latest revision, paginated history and current memory status.
- `GET /api/v1/reviews/history/{review_id}`: one immutable review revision, including after later corrections.
- `POST /api/v1/reviews/{incident_id}` with `X-Operation-Key` and `{verdict, reviewer_label, rationale, corrected_attack_type?, corrected_severity?, expected_revision, request_id}`.
- Existing `/api/v1/learning/stats` adds reviewed eligibility/pending and legacy counts; `/api/v1/learning/similar` now searches reviewed memory only.

`incident_reviews` and `reviewed_memory` initialize after existing schemas. Foreign keys preserve reviewed incident/history references; test fixtures truncate with CASCADE only in the explicitly isolated `edgeguard_test` database. No production rows are deleted or relabeled by migration.

## Deployment and rollback

Rebuild/recreate API only. Pre-release image: `edge-ai-api:before-reviews-20261121`. The new tables and legacy vectors can remain for rollback. **Before rolling back to code that retrieves legacy memory, set `LEARNING_ENABLED=false`** and keep it off until reviewed retrieval is restored; older code does not know about new False Positive/Unknown exclusions. No authentication or auto-execution flag is changed by this release.

Validation uses an isolated PostgreSQL/pgvector database and synthetic browser responses: append-only mutation guards, concurrent revision claims, idempotent retry, stale-embedding rejection, model/revision eligibility, history paging, raw-analysis preservation and source-reference persistence. Production checks are read-only; no real alerts are assigned test analyst verdicts. See [Roadmap V2](roadmap-v2.md) for the delivered operator-attested Asset Inventory (Release 2B), plus planned verified named identity and additional intelligence-source work.

On 2026-11-21, all 68 backend tests passed locally and with the deployed Docker dependency set against an isolated database. Review browser checks passed 1440/768/390/320px and three route prefixes, including a committed save with lost response, safe retry, conflict/draft retention, exclusion after correction, hostile literal text and error recovery. Existing Dashboard and Intelligence browser suites passed. Live reads at 1440/768/390px confirmed review/status UI without overflow or JavaScript errors; Mission handled zero eligible memory correctly. An unauthenticated save returned 403 and left the revision unchanged. UI review disposition: `ship` at this Release 2A scope.
