# Phase3A — immutable HTTP corpus and CPU replay

Delivered 2026-11-21. Phase3A supplies the **API, operator CLI and Dashboard Evaluation tab**. Phase3 attack graphs, richer features, drift controls and independent maker/checker validation remain open.

## Dashboard workflow

Open `/AIEdgeGuard/dashboard#evaluation` (also supported on the root route and `/aiedge`). The existing Mission-derived visual system is preserved; the page stacks on narrow screens, with eight frozen windows per page on desktop and four on mobile.

1. Inspect collector status and first available continuity time. Unavailable/stale status is explicit; earlier history is not retroactively certified.
2. Select a dataset, or expand **Create snapshot**. Choose a retained observed host/router pair or enter exact values; specify UTC time boundaries, a self-reported author and scope/evidence. Observed pairs are not verified assets. Snapshot creation can succeed with gaps; those windows remain ineligible for scoring.
3. Select **Label #…**, inspect the saved revision separately from the blank draft, and append `normal`, `lab_attack` or `unknown` with evidence. No auto-label or bulk assumption of normal traffic is supplied. Label history is paginated. A revision conflict preserves the draft and requires **Reload latest revision** before another save.
4. **Run CPU comparison** uses saved label revisions. Inspect held-out test versus calibration confusion counts, excluded windows and rate-withholding states. Select older reports from the paginated list or export the pinned JSON. Dataset export includes current labels; a saved run continues to pin its original label revisions.

Writes use the existing Operation Key. An ambiguous network response keeps the original dataset/request/run UUID and input in this tab's session storage, locks the pending input and offers a same-request retry. Reloading the tab restores pending writes; switching datasets cannot move a pending label/run to another dataset. Operation-key cancellation sends nothing. Session storage is not long-term audit storage; do not clear it before resolving an ambiguous write. Browser exports may contain declared names and operational metadata; handle them as operator data.

The minimum five-hour dataset is not enough to publish test rates by itself: the fixed20% test split still needs at least25 eligible labeled windows including both classes. Collect a suitably longer period and evidence-based labels; additional windows alone do not establish valid generalization.

## What can be measured

One dataset freezes a single exact HTTP `host` and `router` from retained gateway request history into UTC five-minute windows. Choose 5 hours to 7 days, with timezone-aware aligned boundaries and an end at least ten minutes in the past. Each window stores counts, HTTP error count, collector coverage, a SHA-256 of sorted request fingerprints, maximum request ID and last collection timestamp. It stores no new request body, IP list or raw URL. Request history still has its existing row/day retention limits.

Dataset contents are immutable. Requests that arrive after creation do not change an old dataset. A new dataset UUID captures newer evidence. The membership hash is an audit commitment; it cannot recover deleted raw requests. Aggregate snapshots remain available for volume replay after request/tick retention expires.

Labels are separate append-only revisions: `normal`, `lab_attack` or `unknown`. They require a declared author, rationale, expected revision and request UUID. Missing labels remain unknown. `lab_attack` means an operator has evidence of an authorized attack in this window, not merely that traffic came from a lab. Alert TP/FP feedback is deliberately not imported as normal traffic ground truth: an alert-only sample has selection bias. Labels are operator attestations under the shared Operation Key, not verified named identities or independent ground truth.

## Prospective collector continuity

The request collector records successful polling intervals only when consecutive checkpoints belong to the same collector process, were caught up, clean and on the same file without reset, at most 15 seconds apart. A restart/warmup, rotation/truncation, backlog, partial line, malformed/unrecognized record or missing log breaks continuity. Failed writes do not advance the checkpoint; recovery may bridge at most 15 seconds if all retained lines are subsequently read successfully. Overlapping intervals are unioned, so multiple pollers cannot inflate coverage. Ticks retain eight days; their pruning follows existing request-history maintenance. A disabled collector records no ticks.

For evaluation eligibility a window needs **all 300 seconds** covered, plus a conservative retention floor: the oldest retained collection timestamp must precede the window. Missing history is not treated as a genuine zero. The current status endpoint reports whether the collector is caught up or stale/gapped.

This measures the collector's ability to read its mounted file; it does **not** prove Traefik emitted every request, detect every upstream logging failure, recover historic gaps, cover Windows/LAN traffic, or guarantee no late events. Quiet windows are eligible only with continuity and retained-history evidence. The ten-minute delay reduces late arrival exposure; it is not a completeness guarantee. The existing Intelligence-tab heuristic is unchanged and retains its previously documented limitations.

## Replay contract

Chronological 60% training / 20% calibration / 20% test windows, with end-exclusive split indices, no shuffle or parameter search. All training windows must be eligible and explicitly labeled normal, with a minimum of 12. Otherwise the persisted report says `needs_complete_normal_training` and has no metrics.

Both comparators use training statistics frozen before calibration/test:

* **Frozen median/MAD**: median and MAD scale `max(3, sqrt(median), 1.4826*MAD)`, minimum volume 20, ratio 3 and robust score 6. This borrows the current heuristic's thresholds, but uses frozen training statistics; it is not an exact replay of the production rolling 12-bucket heuristic.
* **One-sided EWMA control chart**: lambda 0.2, k 3, initial state equal to training mean, training sigma floor `max(3, sqrt(mean), population_stddev)`, finite-age upper limit and minimum current volume 20. State updates only from observed counts, never labels. Gaps emit no prediction and reset EWMA state/age. Calibration observations can influence subsequent EWMA state, as in sequential deployment; calibration labels cannot. There is no fitted ML model or automatic promotion.

Each run pins dataset hash, algorithm version, implementation file hash, parameters, split, training statistics, exact label revisions, predictions and confusion counts. Same run UUID returns the original report even after labels change. Use a new UUID to evaluate new revisions. The database rejects ordinary update/delete on datasets, labels and runs.

Unknown/gapped test windows are excluded, with counts reported. Recall and false-positive rate are withheld until that split has at least 5 eligible labeled attack and 20 normal windows. This is a reporting floor, **not statistical validation**. Even then the state is `descriptive_only`: adjacent windows are correlated, author labels may be wrong, volume detectors miss low-volume attacks, and one host/router sample does not establish general performance. No >=95% detection, <=1% FP, zero-day or SLA claim is produced. Error counts are retained for later evaluation but are not used as a detection feature yet.

Method references: [NIST EWMA control charts](https://www.itl.nist.gov/div898/handbook/pmc/section3/pmc324.htm), [scikit-learn time-series evaluation](https://scikit-learn.org/stable/modules/generated/sklearn.model_selection.TimeSeriesSplit.html). The implementation is standard-library CPU code; it does not add scikit-learn or send corpus data to an external model.

Each access-log poll reads up to a byte boundary captured on the opened file. A complete line appended beyond that boundary is read on the next poll. Partial lines, invalid records, backlog and file resets appear as distinct collector states. A completed read after a discontinuity is reported as `continuity_break`. Past collector ticks and saved datasets retain their original coverage.

## Operator usage

### Preparing the held-out evaluation

Use the actual host/router and UTC period evidenced by change, application or authorized lab records. Select a continuous training period with known normal traffic. The chronological split is fixed at 60/20/20. A five-hour snapshot contains only 12 held-out windows, so it cannot meet the reporting floor of 20 eligible normal and 5 eligible lab windows. With complete coverage, 121 five-minute windows (10 hours 5 minutes) are the shortest possible range that allocates 25 windows to the test split. Choose the range using source evidence and chronology before inspecting replay results.

Export the dataset and prepare a local JSON manifest. `dataset_sha256` is the exported `content_hash`. `labels` contains the same row objects as the single-label endpoint, each with its own window index, current expected revision, verdict, reporter, rationale referencing supporting evidence, and request UUID. Keep UUIDs on retry. A mismatch in checksum, ineligible non-unknown window, an out-of-range index, or a stale revision aborts the entire import. The manifest can contain up to 2,016 distinct windows. Use `unknown` where the source evidence cannot establish a class. Keep live operational evidence out of source control.

```powershell
python tools/evaluate_behavior.py readiness DATASET_UUID
python tools/evaluate_behavior.py manifest DATASET_UUID labels.json
python tools/evaluate_behavior.py readiness DATASET_UUID
python tools/evaluate_behavior.py replay DATASET_UUID RUN_UUID
```

`sample_floor_met` means the stored labels and coverage can produce the defined descriptive test metrics. If the most recent replay uses older label revisions, create a new replay UUID. For Phase 3 acceptance, record the held-out report ID and false positives/misses together with an independently corroborated incident review and its verifier and source. The shared Operation Key represents write authorization, so authenticated reviewer identity and separate corroboration must be established by the operator.

Run from the repository root. Reads are public under the existing preview configuration; writes require `X-Operation-Key` when configured. The CLI reads `EDGEGUARD_OPERATION_KEY` from the current environment; it never places the key in arguments or output. Do not commit keys or real corpus exports to GitHub.

```powershell
python tools/evaluate_behavior.py status
python tools/evaluate_behavior.py datasets --page 1
# With the existing authorized operation key in EDGEGUARD_OPERATION_KEY:
python tools/evaluate_behavior.py create DATASET_UUID dataset-input.json
python tools/evaluate_behavior.py show DATASET_UUID
python tools/evaluate_behavior.py label DATASET_UUID label-input.json
python tools/evaluate_behavior.py replay DATASET_UUID RUN_UUID
python tools/evaluate_behavior.py --output report.json run RUN_UUID
```

Replace UUID placeholders with real UUIDs. Retry the same dataset/request/run UUID after a lost response; do not create a new one until the previous outcome is known. IDs reused with conflicting inputs return HTTP409. A label submitted against a stale revision also returns409.

`dataset-input.json` (choose actual observed host/router and a suitable historical interval; dates below are syntax examples only):

```json
{
  "host": "app.example.test",
  "router": "app@file",
  "start": "2026-11-22T00:00:00Z",
  "end": "2026-11-22T05:00:00Z",
  "declared_by": "Operator label",
  "rationale": "Approved measurement interval and application scope"
}
```

`label-input.json` (use evidence for the selected window; do not bulk-assume normal):

```json
{
  "window_index": 0,
  "expected_revision": 0,
  "label": "unknown",
  "declared_by": "Operator label",
  "rationale": "Traffic classification has not yet been established",
  "request_id": "11111111-1111-4111-8111-111111111111"
}
```

Default base URL is `http://127.0.0.1:8099`. Use `--base-url https://llm-server.tail923b9a.ts.net/AIEdgeGuard` for the published route. API prefix: `/api/v1/evaluation`.

| Method/path | Purpose |
|---|---|
| GET `/status` | Prospective collector status and dataset count |
| GET `/segments?page=1&page_size=10` | Paginated retained host/router observations, maximum page size50 |
| GET `/datasets?page=1&page_size=20` | Paginated dataset listing, maximum page size50 |
| PUT `/datasets/{uuid}` | Gated immutable snapshot creation, idempotent by UUID/input |
| GET `/datasets/{uuid}` | Snapshot, latest label per window and latest50 run summaries |
| POST `/datasets/{uuid}/labels` | Gated append-only label with revision/idempotency checks |
| POST `/datasets/{uuid}/label-manifest` | Gated atomic import of explicit labels pinned to a snapshot checksum |
| GET `/datasets/{uuid}/readiness` | Coverage and labeled sample shortfalls, plus latest replay label currency |
| GET `/datasets/{uuid}/labels/{window_index}?page=1` | Paginated label history, 50 revisions/page |
| POST `/datasets/{uuid}/runs/{run_uuid}` | Gated deterministic replay and immutable report |
| GET `/datasets/{uuid}/runs?page=1&page_size=10` | Paginated saved run summaries, maximum page size50 |
| GET `/runs/{run_uuid}` | Original pinned report/export |

## Validation and deployment

Tests use only the isolated database `edgeguard_test`: coverage union, restart/gap/partial/malformed checkpoint behavior, future/test-label leakage, unknown/gapped exclusions, sample floors, write gates, input validation, CAS/idempotency, append-only history and late-arrival snapshot stability. Synthetic fixture results are engineering tests, not measured production performance. No production traffic labels or fabricated datasets are seeded by deployment.

Validation on 2026-11-21: the full 106-case backend suite passed locally; all8 evaluation-specific tests passed in Docker, including observed-segment and saved-run paging. The earlier104-case backend suite also passed in Docker. Dashboard regression checks passed at5 widths/3 prefixes; Evaluation passed at4 widths/3 prefixes with empty/error/recovery, snapshot/label/run retry across reload, CAS/draft handling, paging, keyboard focus, pinned exports, missing-data states, XSS and overflow checks. Ruff passed for changed implementation/tests. Fresh finish review returned `ship` for the scoped UI extension; the documenter confirmed the incumbent design system covers it without token changes. Live health reports Ollama/CrowdSec/Redis/Postgres `ok`; an unauthenticated replay returns403. The public443 canonical route serves evaluation status and the registry remains empty. No production benchmark has been run.

The additive schema initializes with the API. Deploy only the API container using the existing compose file. Rollback images: `edge-ai-api:before-phase3a-20261121` before the evaluation backend; `edge-ai-api:before-evaluation-ui-20261121` before its Dashboard extension. Retain additive tables/history. Authentication, policy, lab and auto-execution settings are unchanged.
