# Dashboard: Defense workspace

Mode: Operate. Code-led extension of the approved Mission Control world.

User request: redesign `/AIEdgeGuard/dashboard` in responsive 3D Mission style, paginate records, and inspect incoming request/packet evidence.

Reuse Mission's midnight/cyan palette, self-hosted Barlow Condensed and IBM Plex Sans Thai, generated shield artwork as a static page background. The background supports context while the operational records remain primary. No new factual security claims or fabricated telemetry.

First viewport: product navigation, three actual defense-layer statuses, subdued 3D shield/world background behind the operational summary; records immediately below. Desktop uses a dense table, mobile uses labeled record rows and five records by default. Inspector shows full evidence without widening the page.

Signature interaction: select a request or incident, inspect the complete captured metadata, headers and available payload/frame hex, then navigate adjacent records or export JSON. Show capture limitations directly. Paging, search and filters run in PostgreSQL, with a snapshot anchor preventing new inserts from shifting subsequent pages.

Preserve approvals, campaigns, decisions, Attack Lab confirmation and kill switch, policy, existing API contracts and the previously authorized public preview configuration. Partial telemetry or API failures must show unavailable status, never fabricated health.

Evidence: `.impeccable/review/dashboard-*.png`, `edge-ai/api/tests/verify_dashboard.py`, backend paging regressions in `test_dashboard.py`.

AI Triage extension: user provided a two-pane Wazuh/Ollama copilot reference. Add an AI Triage tab inside the operational records panel, preserving the existing Mission-derived cyan world. Prioritized paginated Wazuh queue at left; selected alert, report/model provenance, language, optional unverified hostname hint, cleaned-context disclosure and streamed report at right. Stack panes below 900px with a bounded scrollable queue. Default minimum real Wazuh rule level 7; allow level 5/10/12. On-demand local Ollama, Thai/English, stop, Redis cache and bypass. Installed model choice is session-local, not a global runtime or URL change. Never overwrite existing incident analysis or perform enforcement. Show empty, partial/error, cached and unavailable states honestly. Required captures `.impeccable/review/triage-{1440,768,390}.png`.

2026-11-12 update: user asked to remove the standalone 3D scene, caption and Play/Pause control and use a 3D image background instead. Dashboard no longer loads Three.js or the scene script; Mission keeps its animation. Use a fixed, responsive decorative background with dark overlays and opaque record panels.
2026-11-21 V2 foundation: preserve the existing Operate world; add Intelligence tab with a paginated/searchable local CISA KEV catalog and real source freshness, gated manual sync, plus CPU volume baseline per host/router. Evidence drawer gains explicit Investigate action, bounded URL decode, masked secret query values, source-vs-AI CVE provenance, KEV snapshot freshness, candidate incident timeline with match reasons and policy evidence. No identity match is not evidence of safety; candidate links are not confirmed attack chains. Show warmup/stale/missing states, keep all recommendations outside enforcement. Required evidence: intelligence-{1440,768,390}.png and viewport-only investigation-{1440,390}.png.
2026-11-21 Reviewed knowledge extension (Release 2A): preserve Operate layout and cyan world. Add Analyst review in Incident inspector: self-declared reviewer label, TP/FP/Unknown, rationale, optional separate type/severity correction, append revision, conflict/reload and append-only paginated history. Stored raw evidence/AI output/decisions remain separate. Show immutable review links used by stored analysis, pending/excluded/ready reviewed memory states, and a summary on Intelligence. Shared Operation Key authorizes writes; it does not authenticate the named analyst. Strict RAG retrieves latest TP only with current review revision/model vector; unreviewed/FP/Unknown and stale vectors excluded. Legacy vectors retained. No feedback-generated rule, approval, unblock or action. Required captures reviews-{1440,768,390}.png, reviews-history-{1440,390}.png (viewport drawer), and reviewed-memory live summary.

2026-11-21 Release 2B: Assets tab extends the existing Operate world. Searchable/paginated registry beside revision editor, stacked below 900px. Host agent/IP and application/service exact route + parent bindings are operator-attested, with self-declared label and existing Operation Key; observed Wazuh evidence only prefills. Show current revision, history, validation, conflict/draft retention and retry states. Investigate adds current mapped asset/parent context, mapping revision/time and candidate-only cross-layer links. No automatic CVE applicability, discovery or authenticated actor claim. Evidence assets-{1440,768,390}.png and verify_assets.py.

2026-11-21 Release 2C.1: Intelligence adds a FIRST EPSS section above reviewed memory and KEV. Preserve Operate world. One exact CVE input, public cached read and explicitly gated Fetch from FIRST, 24-hour cache, on-demand scope (no EPSS daily sync), probability versus percentile rank, score-date/fetch/latest-attempt provenance, current/stale/missing/error states, immutable snapshot link and FIRST attribution. No asset applicability/severity/exploitation/enforcement inference. KEV entries expose View EPSS to select the CVE and read cache. Required captures epss-{1440,768,390}.png; verify_epss.py covers4widths/3prefixes.

2026-11-21 Phase2 completion: Sources tab extends the Operate world with two desktop columns (NVD/cache/fetch + revision-bound declared-product assessment/history; retained MITRE/DROP status, technique search/paging and local IP lookup), stacking below1000px. Native inputs/disclosures; control heights36px/44px mobile. Saved assessment rationale is read-only and separate from a retained draft. Unsupported CPE/version/environment conditions require review; candidate/no-match never proves affected/safe state. Assets accepts optional CPE2.3 and numeric_dot/unknown scheme; links saved revision to check. Incident drawer adds source links and prompt/model provenance; observed model digest is not runtime attestation. Triage provenance follows cleaned payload. Active tab stays horizontally visible on narrow screens. Required captures sources-{1440,768,390}.png, source-provenance-{1440,390}.png, triage-{1440,768,390}.png and current asset captures. No policy/auth/autoexecution changes.

## Evaluation extension contract

THESIS: extend the existing Operate surface with a traceable measurement workflow, never a decorative performance score or a claim of proven detection.

OWN-WORLD: inherit midnight panels, cyan actions, Barlow Condensed headings, IBM Plex Sans Thai body and the existing static shield background. Flat sections, native forms/disclosures, established button and table language.

STORY: inspect collector continuity; choose or create an immutable host/router snapshot; review individual windows; append audited labels; run or reopen a pinned CPU comparison. Unknown and gapped data stay explicit.

FIRST VIEWPORT: existing navigation/summary and Evaluation tab, collector status, two desktop columns for dataset list/create and selected windows. Stack below1000px; mobile shows four labeled windows/page, desktop eight. Replay/results follow; saved rationale is separate from draft.

FORM: local code-led extension, no new visual world or concept seed. Minimum36px controls,44px on mobile; keyboard focus; paged observations/datasets/labels/reports; pending write UUID recovery across reload. Evidence evaluation-{1440,768,390}.png, evaluation-empty-390.png, evaluation-label-{1440,390}.png and verify_evaluation.py. Synthetic captures are not production benchmarks.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
