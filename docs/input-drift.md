# Phase3D — replay input drift and coverage

Delivered 2026-11-22. Open **Dashboard → Evaluation → saved replay → Input drift & data coverage**. New replay reports include descriptive input comparisons; existing immutable reports are not backfilled. This is not confirmed concept/model drift, a detection-quality score, attack confirmation or automatic threshold/retraining control.

## Frozen comparison contract

The existing chronological60/20/20 training/calibration/test split remains unchanged. The baseline uses only that dataset's training windows and requires at least12 windows, all eligible and explicitly labeled normal. Labels are operator attestations, not verified ground truth. Later labels never fit the baseline or change drift signals; their normal/lab/unknown counts are displayed as comparison context.

Each later split is compared separately with the frozen training sample from the **same exact HTTP host/router dataset**. No pooling across applications, alternate baseline selection or parameter tuning is added. Current host/router names do not independently verify application identity or unchanged routing. All eligible later traffic is compared, including lab/unknown windows; it is not silently assumed normal.

Comparison needs at least12 eligible windows and90% eligible coverage. Gaps are excluded, never converted to zero traffic. Missing/invalid volume fields block a clean comparison. Missing/invalid error fields do not become zero error rate. Coverage only reflects the existing prospective collector/retention eligibility contract; it does not attest upstream log completeness, source clocks or full Windows/LAN visibility.

## Descriptive rules

| Feature | Recorded comparison | Fixed candidate rule |
|---|---|---|
| Request volume | Two-sided empirical-CDF distance D, medians/means, median ratio and zero-window shares | D≥0.35 **and** absolute median change≥max(10 requests/window,50% of baseline median) |
| Observed error share | Sum of stored status≥400 counts / sum of stored requests; signed change in percentage points | Absolute share difference≥0.10, with≥100 requests in both periods |

These are versioned engineering heuristics, **not validated statistical/security thresholds**. Volume decreases can flag as well as increases. Median ratio is undefined when the baseline median is zero. Fewer than100 requests leaves error share unavailable even when volume can be described. Unknown status values in the denominator can bias the observed error share; it is not a complete application failure rate.

The ECDF distance is a descriptive implementation of the distance statistic described in [SciPy's two-sample KS documentation](https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.ks_2samp.html). The code uses the Python standard library and does not add SciPy. It computes **no p-value** and makes **no significance claim**: request counts are discrete, adjacent windows may be correlated, and eligible samples can be incomplete. The source reference supports the distance definition, not these candidate cutoffs or an accuracy claim.

Signals can reflect lab activity, seasonality, deployment/traffic mix, logging changes, attacks or collection limitations. The implementation does not identify the cause. No signal changes live anomaly thresholds, models, policy, assets, labels or defense execution.

## States and UI

| State | Meaning |
|---|---|
| `baseline_not_ready` | Training needs complete eligible normal-labeled windows |
| `invalid_baseline_features` | Training request counts missing/invalid |
| `insufficient_coverage` | Later sample too short or coverage below90%; no volume/error comparison |
| `invalid_volume_features` | Eligible later counts missing/invalid |
| `candidate_input_change` | At least one fixed descriptive rule fired; inspect per-feature availability |
| `partial_feature_coverage` | Volume describable, error share unavailable/too sparse; no complete comparison |
| `no_candidate_under_fixed_rules` | No candidate under this limited rule set, not proof of stable model quality or no attack |

The overall drift object is `descriptive_only` when the baseline is usable; each test/calibration comparison has its own state. Per-feature states remain visible when another feature flags. Coverage, exclusions and normal/lab/unknown context appear before expandable numeric details. Frozen parameters, split indices, method version and implementation-file SHA-256 remain inspectable in the saved replay/export.

Old replay reports without `input_drift` explicitly show **Not recorded for this saved replay**. A new replay UUID captures the current report format. Reusing the original UUID returns its saved result, including across version upgrades. Replay v2 introduced `input_drift`. Replay v3 adds the HTTP categories described below. The existing gated replay endpoint persists these fields.

## HTTP categories in replay v3

New dataset snapshots store aggregate histograms for HTTP method, response status class and path shape (root, one segment, multiple segments or unknown). These buckets use the stored request metadata and count the same host/router and time window as the existing request totals. They retain neither literal paths nor query values. Unrecognized methods are grouped as `other`; missing methods and out-of-range statuses have their own `unknown` bucket. Path shape describes the recorded target before the first `?`, with no decoding or route-template inference.

For eligible calibration and test windows, inspect `input_drift.comparisons.<split>.http_mix` in the pinned report disclosure or JSON export. Each available feature gives counts for both samples and total variation distance, half the sum of absolute differences in category proportions. It ranges from zero for identical proportions to one for disjoint categories. The minimum is 100 requests in each sample, plus the existing eligibility and coverage requirements. The distance is descriptive and does not affect the existing candidate flags or the replay detectors. Unknown categories remain visible in the counts.

Legacy datasets lack these histograms. A new replay on one reports `not_recorded` for the missing input. Creating a fresh dataset from retained traffic captures the new categories. A recorded zero-request window is distinct from a missing histogram. Counts that fail to reconcile with the frozen window total produce an unavailable feature.

Report selection is atomic: the selector retains the displayed replay until a requested report loads successfully. Mutable controls remain disabled during loading; failed reads restore the original selection, keeping exports and drift evidence tied to the displayed report.

## Validation and deployment

Tests cover known ECDF distances/ties, small versus sustained changes, error-only changes, zero traffic, gaps, short samples, invalid counts, missing error fields, no future-label fitting, immutable old replays and legacy/no-drift UI. The intercepted Evaluation workflow exercises4 widths/3 prefixes, actual backend replay calculation, UUID retry/CAS/history/export, readiness, candidate/error-share, gaps, legacy reports and delayed/failed selection. Synthetic fixtures are not production drift/detection metrics.

The129-case backend suite passed locally and in Docker; Dashboard regression checks passed5 widths/3 prefixes. Fresh UI review returned `ship` for the scoped drift extension, and the documenter confirmed no system-token changes were needed.

Deploy only the API service. Rollback tag: `edge-ai-api:before-drift-20261122`; retain existing immutable report history. Auth, labels, model configuration, policy and auto-execution are unchanged. Richer method/path/process features, cross-period validated drift monitoring, authenticated independent checking and measured production detection remain outside this release.

Live checks on2026-11-22: public443 assets/status returned200 with replay versionv2 and collector `collecting`. Local desktop/mobile Evaluation loaded without JS errors or write requests; unauthorized replay returned403 locally and publicly. All four health dependencies reported `ok`; policy stayed `dry_run (human approval)`. The production dataset registry remained empty; no synthetic labels/reports or production drift claim were introduced.
