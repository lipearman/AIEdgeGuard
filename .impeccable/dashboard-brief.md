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
