# Phase3C — retained-evidence checks and operator review

Delivered 2026-11-22. On a saved case, expand **Evidence consistency & analyst review** above the graph. This adds a deterministic check path and a separate human annotation workflow. It does **not** complete independent maker/checker validation: shared source data, unverified sensor clocks and shared-key reviewer names cannot establish independent ground truth or a second authenticated person.

## Workflow

1. Open Traffic/Incidents → Inspect → Candidate evidence graph and create or load a case.
2. Expand the new disclosure, then **Run retained-evidence check**. Supply a declared operator label and purpose. **Save consistency check** requires the existing Operation Key; it invokes no LLM or external service and performs no defense action.
3. Inspect the immutable report. Six node/edge/asset findings per page distinguish retained support, changed facts, missing evidence, unsupported data and contradicted rules. Inspect the full provenance disclosure or export check JSON. Matching hashes/facts do not certify source authenticity or attack causation.
4. Select a saved check and append an **Operator review**: `supported_association`, `needs_more_evidence` or `disputed`. The review pins that exact check, with a self-reported label and rationale. It never edits the graph, model analysis, RAG, policy or decision.
5. Read paginated check and review histories. A newer check can observe different source availability; it never rewrites an earlier report. Saved review text is separate from the editable draft. On a concurrent revision conflict, **Reload latest review** preserves the draft for inspection before resubmission.

Report switching is atomic: the selected check, displayed report and review target change together only after loading succeeds. A retained draft or failed read restores the original selection; review submission is disabled while a different report loads.

Ambiguous check/review saves retain their UUID, pinned case/check and original input in session storage. Reopen the same saved case after closing/reloading to restore the pending write. Retrying identical input returns its original result. Conflicting UUID content returns409. Key/validation failures preserve editable drafts; cancellation sends nothing. Do not clear session storage before resolving an ambiguous save.

## What the deterministic path checks

The checker is a separate module; it does not call the graph maker's association/node-building functions, model inference or an executor. Canonical hashing and a separate source parser/check rule set operate on retained database records. This is implementation separation, **not independent evidence acquisition or independently verified identity**.

* Recompute the saved graph content hash and validate bounded/unique node references.
* Read retained source rows in one repeatable-read PostgreSQL transaction. Session locking precedes the snapshot to serialize idempotent writes; the fresh per-operation connection releases the lock on exit.
* Rehash HTTP **raw JSON**, rather than trusting the stored fingerprint column. Rehash incident source envelopes. Missing raw records produce unavailable findings; hashes cannot recover pruned evidence.
* Compare observed/ingested/effective times, source and timestamp state, pinned event-window membership and source high-water boundaries. Incident timestamps are parsed separately, including missing/timezone/future-clock rules. HTTP uses the retained collector-normalized observed time and its original assumptions, not independent clock/normalization attestation.
* Compare request ID, Wazuh agent ID, observed source IP and endpoint IPs, retaining the same documented low/medium uncertainty. Matching identifiers only support the specific association predicate.
* Read exact historic asset revisions, compare pinned declaration payloads, and reproduce declared anchor route/host selectors and permitted host-binding membership. This does not independently validate real inventory, historical endpoint identity or global selector uniqueness at the original case time.
* Check permitted edge type, anchor/target, confidence, meaning and direction. An unsupported edge cannot be promoted to a causal claim. Missing/changed source nodes yield unverifiable edges.
* For incident→decision links, verify the actual stored incident reference. Decision lifecycle fields may legitimately change after case creation; these are reported as changed facts, not automatic tampering findings. A supported reference does not verify execution independently.

The checker does not re-expand the corpus or certify exhaustive membership. Existing80 event-node/20 decision bounds remain; reports support at most100 nodes and500 edges. Unsupported schema/bounds cannot produce a clean result. It does not check an external sensor signature, attest source clocks, confirm a causal attack, choose a model, measure detection accuracy or authorize an action.

## Report states

| State | Meaning |
|---|---|
| `consistent_with_retained_evidence` | Checked facts/predicates agree with retained records and declarations under this rule set; not a security verdict |
| `incomplete_or_changed` | At least one source/declaration is missing, changed or unsupported, or an edge cannot be established |
| `inconsistent` | Case checksum or a supported edge-rule constraint is contradicted |
| `unsupported_bounds` | Missing/duplicate anchor structure or case exceeds supported bounds; no clean result |

Node/declaration findings include `consistent`, `changed_since_snapshot`, `unavailable` and `unsupported`; edge findings include `supported_association`, `supported_reference`, `contradicted` and `unverifiable`. Report counts are fact-check counts, not detection metrics. `checked_at` records report completion; source reads use one transaction snapshot. All reports explicitly retain `independent_identity_verified=false`, `source_authenticity_verified=false` and `model_used=false`.

## Audit and API

`case_checks` and `case_operator_reviews` are append-only with ordinary update/delete rejection triggers and foreign keys to the original cases/checks. Each check pins case checksum, rule version, implementation file SHA-256, input/purpose, authorization method, findings and report checksum. Each review uses a case-wide revision, exact check reference, request UUID, rationale and authorization method. The API rejects a check belonging to another case. Compare-and-swap and idempotency prevent silent replacement or duplicate retry revisions. A self-reported review can disagree with the checker; it does not override the machine report or acquire enforcement privileges.

| Method/path | Purpose |
|---|---|
| PUT `/api/v1/case-checks/{uuid}` | Gated check creation; body `case_id`, `declared_by`, `rationale` |
| GET `/api/v1/case-checks?case_id={uuid}&page=1` | Check summaries,10/page |
| GET `/api/v1/case-checks/{uuid}` | Immutable report/export |
| POST `/api/v1/case-checks/reviews/{case_uuid}` | Gated annotation: `check_id`, `expected_revision`, verdict, `reviewer_label`, rationale, `request_id` |
| GET `/api/v1/case-checks/reviews/{case_uuid}?page=1` | Review history and latest revision,10/page |

Read/write authorization and existing public-preview configuration are unchanged. No credentials, source bodies or external-service calls are added by the checker. Reports/exports still contain operational identifiers and declared labels; handle them as operator data.

## Validation and deployment

Isolated PostgreSQL tests cover raw-source changes with an unchanged fingerprint, pruned sources, corrupted edge/window data, historical asset revisions, changed decision status, check concurrency/idempotency/hashes, cross-case review rejection, review revision conflicts, immutable history, write gates and forbidden forged independence fields. Browser fixtures cover4 widths/3 prefixes, missing versus consistent facts, immutable older reports, check/review retry across reload, draft preservation, paging, keyboard, export, literal hostile strings, API failure recovery and overflow. Fixtures are engineering tests, not production benchmarks.

The121-case backend suite passed locally and in Docker. Existing case-graph UI regression checks passed4 widths/3 prefixes, and Dashboard checks passed5 widths/3 prefixes. A dedicated delayed/failed/blocked report-switch test verifies that the selector stays pinned to the displayed report and review submission stays disabled until the switch succeeds.

Fresh UI review found one report-selection pinning issue; the follow-up verdict scored that fix resolved (`ship` for the scored fix). The documenter confirmed this ordinary extension fits the incumbent system without token changes.

Deploy only the API service; initialize additive tables after case schema. Rollback tag: `edge-ai-api:before-case-checks-20261122`, retaining audit tables/history. Automatic response, policy, model configuration and preview authentication are unchanged. Authenticated independent reviewers, external source attestation, causal verification and the wider Phase3–4 gates remain open.

Live checks on2026-11-22: public443 checker assets/history returned200; unauthenticated check creation returned403, and local check/review writes both returned403 without the key. Health reported Ollama/CrowdSec/Redis/Postgres `ok` and policy remained `dry_run (human approval)`. No synthetic check or operator review was seeded in production.
