---
name: LACD Defense Console
description: Shared Mission Control and Dashboard visual system for local cyber defense.
colors:
  bg: "#030a12"
  panel: "#06121f"
  line: "#163145"
  text: "#e4effa"
  muted: "#8daabe"
  workspace-muted: "#a9c8dc"
  drawer-heading: "#071a29"
  drawer-surface: "#061421"
  cyan: "#22c9ff"
  cyan-soft: "#78d9fa"
  red: "#f64b68"
  amber: "#f5b845"
  green: "#26d6a0"
  severity-critical: "#f33257"
  severity-high: "#f27343"
  severity-medium: "#eeb74c"
  severity-low: "#21cba1"
  severity-unknown: "#547287"
typography:
  display:
    fontFamily: "Barlow Condensed, sans-serif"
    fontSize: "33px"
    fontWeight: 500
    lineHeight: 1.1
  headline:
    fontFamily: "Barlow Condensed, sans-serif"
    fontSize: "16px"
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: ".035em"
  body:
    fontFamily: "IBM Plex Sans Thai, sans-serif"
    fontSize: "13px"
    lineHeight: 1.5
  label:
    fontFamily: "IBM Plex Sans Thai, sans-serif"
    fontSize: "10px"
  workspace-body:
    fontFamily: "IBM Plex Sans Thai, sans-serif"
    fontSize: "14px"
    lineHeight: 1.5
  workspace-record:
    fontFamily: "IBM Plex Sans Thai, sans-serif"
    fontSize: "12px"
  workspace-control:
    fontFamily: "IBM Plex Sans Thai, sans-serif"
    fontSize: "11px"
rounded:
  badge: "3px"
  control: "4px"
  icon: "5px"
  navigation: "6px"
  visibility: "7px"
  panel: "8px"
spacing:
  tight: "8px"
  compact: "10px"
  mobile: "12px"
  gutter: "14px"
  panel-inset: "15px"
  workspace-inset: "18px"
components:
  button-primary:
    backgroundColor: "#0a2d43"
    textColor: "#c4eeff"
    rounded: "{rounded.control}"
    padding: "7px 10px"
  button-primary-hover:
    backgroundColor: "#124562"
  button-quiet:
    backgroundColor: "#071a29"
    textColor: "{colors.cyan-soft}"
    rounded: "{rounded.control}"
    padding: "5px 8px"
  icon-button:
    textColor: "{colors.cyan-soft}"
    rounded: "{rounded.icon}"
    size: "32px"
  panel:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
  navigation-active:
    backgroundColor: "#0a2940"
    textColor: "#e4f5ff"
    rounded: "{rounded.control}"
    padding: "9px 15px"
  select:
    backgroundColor: "#081e2d"
    textColor: "{colors.cyan-soft}"
    rounded: "{rounded.badge}"
    padding: "3px 5px"
  severity-badge:
    backgroundColor: "#183145"
    textColor: "#b8cbd9"
    rounded: "{rounded.badge}"
    padding: "2px 4px"
  search-field:
    backgroundColor: "#030e18"
    textColor: "{colors.text}"
    rounded: "{rounded.icon}"
    padding: "0 11px"
  record-open:
    backgroundColor: "#092539"
    textColor: "{colors.cyan-soft}"
    rounded: "{rounded.control}"
    padding: "6px 10px"
  evidence-drawer:
    backgroundColor: "{colors.drawer-surface}"
    textColor: "{colors.text}"
    rounded: "0"
    width: "min(650px, 100%)"
    height: "100dvh"
  triage-queue-alert:
    backgroundColor: "#04101b"
    textColor: "{colors.text}"
    rounded: "{rounded.visibility}"
    padding: "14px"
  triage-queue-alert-selected:
    backgroundColor: "#092335"
    textColor: "{colors.text}"
  review-field:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "10px"
  intelligence-entry:
    textColor: "{colors.text}"
    rounded: "{rounded.visibility}"
    padding: "16px"
  triage-report:
    backgroundColor: "{colors.bg}"
    textColor: "{colors.text}"
    rounded: "{rounded.visibility}"
    padding: "20px"
---

# Design System: LACD Defense Console

## Overview

**Creative North Star: "The Local Defense Console"**

Mission Control is a dense midnight-navy operations console with a cyan illuminated center. The supplied dashboard reference governs this built surface: compact incident evidence frames a large shield/world composition, while restrained neural imagery supports the AI status stack.

This system applies to Mission Control and the authorized Dashboard extension (Defense Workspace). Mission keeps its three-column overview; Dashboard reuses the palette, local fonts and shield artwork as a static decorative page background while giving operational records the primary reading space. AI Triage extends Dashboard with an advisory Wazuh priority queue and streamed local report, using the same visual language. Intelligence adds a local KEV catalog, explainable CPU traffic baseline and on-demand investigation evidence within that existing world. Analyst review adds declared assessments and revision history in the Incident drawer, with reviewed-memory scope visible on Intelligence and Mission. Small English condensed headings and numerals pair with readable Thai and English operational copy; measured borders and tonal panels keep the artwork from competing with evidence.

**Key Characteristics:**
- Dense operational hierarchy with a dominant central scene.
- Local bilingual fonts, thin cyan line icons and tabular metrics.
- Generated 3D raster art with restrained decorative Three.js overlays.
- Visible sample scope, sensor coverage and human approval state.

## Colors

The palette combines midnight structural neutrals with cyan navigation and instrumentation; warm incident colors punctuate the cool field.

### Primary

- **Instrument Cyan** (`cyan`): focus outlines, line icons, meters and active navigation cues.
- **Soft Cyan** (`cyan-soft`): links, quiet controls and secondary instrument text.

### Secondary

- **Online Mint** (`green`): healthy service or gateway states and low-priority supporting cues.
- **Review Amber** (`amber`): pending review and lab context.
- **Alert Rose** (`red`): blocked traffic and urgent attention.

Severity charts use the distinct `severity-critical`, `severity-high`, `severity-medium`, `severity-low` and `severity-unknown` palette from mission.js. High severity is orange in charts, while high/critical feed badges share the rose-tinted treatment. Preserve category text rather than implying these treatments are identical.

### Neutral

- **Midnight Canvas** (`bg`): page background.
- **Deep Instrument Panel** (`panel`): card fill.
- **Steel Divider** (`line`): panel edges and structural separators.
- **Ice Text** (`text`): primary information.
- **Muted Steel Blue** (`muted`): Mission supporting labels and source context.
- **Workspace Metric Blue** (`workspace-muted`): Dashboard metric-label literal; Dashboard supporting copy continues to inherit `muted`.
- **Drawer Header Navy** (`drawer-heading`) and **Drawer Surface Navy** (`drawer-surface`): sticky evidence heading and full-height evidence surface.

**The Evidence Rule.** Every health or severity color must have a readable status, count or category beside it.

## Typography

**Display Font:** locally served Barlow Condensed, sans-serif fallback.
**Body Font:** locally served IBM Plex Sans Thai, sans-serif fallback. Font loading lives in static/fonts/mission-fonts.css.

Condensed headings and numerals create a narrow instrument-panel voice. Thai and English explanatory copy use the body family. Numeric counts use tabular figures.

### Hierarchy

- **Display:** metric values use the frontmatter display role; overview values step down to 26px and ring totals to 29px.
- **Headline:** panel titles use the headline role; the scene title is 17px, compact metric headings 14px, dialog title 24px.
- **Body:** the body role supplies the base; the large-screen body becomes 14px.
- **Label:** Mission supporting labels commonly use 9–10px. Decorative scene annotations reach 7–9px; do not promote these micro-labels to task-critical instructions.
- **Dashboard hierarchy:** the workspace intentionally adds a 14px body, 12px record text and 11px compact controls/metadata alongside the existing smaller labels. Supporting source notes and service/layer statuses remain 9–10px where specified by dashboard.css; `muted` is inherited unchanged. Its condensed page heading is 48px on desktop (42px at 1199px, 36px at 800px, 38px when stacked at 600px); record-section titles are 27px desktop/25px mobile, summary values 36px desktop/30px mobile, and evidence headings 29px desktop/26px mobile.

## Layout

Mission Control: the workspace and header stop at 1920px and center in the viewport. The desktop workspace has 18px horizontal inset, 14px gutters and three tracks: minmax(235px, .95fr), minmax(420px, 2.05fr), minmax(270px, 1.06fr). The full-width defense-visibility strip comes first. Left and right stacks frame the center scene and its three equal metric cards. Panel heading insets are generally 15px; smaller metric panels use 12px.

- **At 1700px and wider:** increase heading/body scale, chart size and selected card minimum heights; the scene minimum height grows from 535px to 650px.
- **At 1199px and narrower:** wrap navigation under the brand; retain two workspace tracks and move the right stack into a full-width two-column grid.
- **At 700px and narrower:** use a vertical workspace with 12px insets/gaps. Visibility leads, followed by center scene/metrics, left incident panels, then the right stack. Navigation scrolls horizontally. The scene is 470px tall; center metrics remain three columns. Overview and severity remain a pair, while feed and right-hand cards span full width. Ancillary icons and tiny overview notes are suppressed.
- **At 380px and narrower:** hide the EdgeGuard brand suffix, reduce scene height to 420px and tighten selected headings and navigation padding.

These cutoffs are inclusive CSS media-query boundaries. Retain min-width:0, ellipsis for feed/vector titles, and wrapping for source details to contain dense data.

Dashboard adds a record-oriented layout with a 1680px content limit and 24px desktop insets (1720px header limit). Its intro is a single transparent block with operational copy and a 220px desktop minimum height; four summary metrics sit immediately above records. At 1199px content insets become 16px. At 800px metrics become two columns, and the desktop table can scroll inside its own viewport. At 600px the intro has no minimum height, insets become 12px, and the table becomes labeled two-column record rows. Request target, evidence and action cells span the row. Mobile defaults to five records; larger viewports default to ten. The drawer is right-aligned, at most 650px wide and full viewport height; on mobile it fills the width, with wrapping values, local code scrolling and a sticky heading.

AI Triage sits inside the Dashboard records panel as its own tab. The workspace has 22px padding and a 24px gutter between minmax(260px, .85fr) queue and minmax(0, 1.4fr) report tracks. A right-hand hairline and 24px inset separate the queue on desktop. At 900px and narrower the panes stack, the separator becomes a bottom rule, and the queue list maximum height drops from 560px to 320px so the report remains reachable. At 600px the workspace padding becomes 16px and tool/settings labels wrap. The report uses 14px plain text at 1.85 line height, a 280px minimum/650px maximum height and local scrolling; cleaned-context code has a 320px maximum height. Long hostnames, rule IDs, alert descriptions, status messages and report content wrap within their own pane.

Intelligence uses 24px workspace padding and a two-column equal-width catalog grid with 14px gaps. Catalog cards use 16px padding and the existing 7px corner radius. At 800px and narrower the catalog becomes one column and workspace padding becomes 18px; at 400px it becomes 14px and the search input fills its own row. Behavior rows use one flexible identity column plus three 100px measurement columns; at 800px they flow into a flexible column and an 80px column. Long router names, catalog titles, provenance, reasons and status text wrap. Investigation remains in the existing right-hand evidence drawer; section headings use 23px condensed type, result subheads 21px, body 12px/1.8 and metadata 11px. Its code blocks scroll locally at a 280px maximum height.

Analyst review stays inside the Incident evidence drawer. Its section has 20px vertical padding, 24px vertical margins and steel rules above/below. The native form uses a 14px vertical gap; paired reviewer/verdict and correction fields use two equal columns with 12px gaps, becoming one column at 500px and narrower. Labels are 12px with 6px label/control gaps; controls have 10px padding and 4px corners. The rationale textarea starts at 110px height and resizes vertically. Section headings use 24px/1.2 condensed type, explanatory text 12px/1.8 and history metadata 11px. History articles use 14px vertical padding and dividers; long labels, rationale, source links and status text wrap. The Intelligence reviewed-memory summary precedes the catalog with a 26px bottom margin, 24px bottom padding and separator.

Assets extends the Dashboard with a registry beside a revision editor: minmax(260px, .8fr) and minmax(0, 1.2fr), separated by 32px, inside 24px workspace padding. At 900px and narrower the panes stack with 36px gap and a registry list bounded to 420px scrolling height. Form fields use two columns with 16px gaps; at 520px they become one column and workspace padding becomes 18px 14px. Kind/status filters retain their pair while search spans both columns. Registry entries use 18px 12px padding and fine bottom rules; selection uses the incumbent cyan at 8% mixed with panel fill plus soft-cyan name text. Editor subheads are 22px/1.3 condensed type; registry names are 16px/500 and supporting copy 12px/1.6. Native fields use 13px text, 10px 12px padding and the existing 3px radius. Assets focus outlines retain 2px cyan with a local 3px offset.

Sources uses two equal desktop columns with a 36px gutter and 24px workspace padding: NVD and revision-bound assessment/history at left, retained catalogs and local reference lookups at right. At 1000px and narrower the columns stack. At 520px workspace padding becomes 18px 14px and button minimum height increases from 36px to 44px. Native form controls retain 13px text, 10px 12px padding and 4px corners; section/subhead condensed type is 25px/1.3 and 22px/1.3, prose 13px/1.7. Forms use 14px gaps; section separators use 32px top margin and 24px top padding. Local focus uses a 2px cyan outline with 3px offset. Preserve wrapping for criteria, saved reasons, dates, digests and snapshot links. Dashboard tab activation keeps the selected tab horizontally visible on narrow screens.

## Elevation & Depth

Mission Control animation and Dashboard imagery have distinct roles. Dashboard has no standalone scene, caption or Play/Pause control and loads neither Three.js nor mission-scene.js. Its existing generated shield/world image is a fixed, noninteractive decorative page background behind dark gradient overlays; record panels remain opaque. Desktop positions the image at right -100px with auto width and 650px height. At 600px and narrower it uses 65% -100px with auto width and 500px height. Horizontal overlays protect copy contrast; vertical overlays fade the art into the midnight page.

Structural UI is flat: dark tonal layers, one-pixel borders and fine separators establish grouping. The active navigation item has an inset lower cyan stroke (`inset 0 -2px #16bdf7`). There is no ambient card-shadow vocabulary. Generated world/shield and neural-brain raster art provide the volume; the brain uses screen blending. On Mission, a transparent Three.js canvas aligns to the contained static artwork and adds visibly rotating segmented shield-base rings, comet trails, pulsing illustrative map beacons, sparse particles and a cyan scan beam. The image itself stays static.

**The Quiet Frame Rule.** Keep panels flat and borders restrained; reserve luminous depth for the generated art and its decorative overlay.

On Mission, the raster remains visible if Three.js or WebGL is unavailable or the context is lost; the motion control stays visible, disabled and labeled “Animation unavailable.” Overlay rendering is limited to about 30fps with device pixel ratio capped at 1.5. An elapsed-time clock pauses and resumes without timeline jumps; hidden tabs and an offscreen scene suspend the frame loop. Per the user’s explicit autoplay preference, the scene plays on every fresh open/reload. Reduced-motion slows its elapsed-time clock to 35%, disables CSS scene/meter transitions, and removes smooth scrolling; Pause remains available. The scene image has no pointer parallax; meters use .8s ease-out.

Cached navigation suspends animation on persisted pagehide while retaining GPU resources, then resizes and restarts on persisted pageshow. Noncached navigation disconnects observers and disposes geometry, materials, texture and renderer. WebGL context loss enters static fallback; restoration re-enables the control and restarts according to the current pause state.

## Shapes

Panels and dialogs use gently rounded corners, controls smaller corners and badges tight corners, following frontmatter. Outline icons use thin rounded strokes. Dots and service rings are circular. Bars, hairline dividers and compact rectangular navigation retain a precise console character. The visibility strip has a slightly smaller radius than panels.

## Components

- **Panel:** deep fill, steel edge, clipped content, header divider and compact supporting source copy. On Mission, keep signature artwork concentrated in the scene and AI panel; on Dashboard, keep the decorative background subdued behind opaque records.
- **Primary button:** tinted cyan fill with outlined edge; hover lightens fill and border. Disabled controls lower opacity to .5 and use the disabled cursor. The controlled-test control keeps its existing confirmation and server authorization behavior.
- **Quiet and icon buttons:** compact, outlined, low-contrast fills; use for motion, dialog close and refresh rather than primary task hierarchy.
- **Navigation:** outlined segmented enclosure, muted default links, raised tonal hover and a cyan inset active marker. Preserve the horizontally scrollable mobile row.
- **Severity select:** small dark outlined native select with an accessible label. Mission has no free-text field; Dashboard adds a bordered search input and native status/source/severity/page-size filters.
- **Incident feed:** five recent incident buttons with severity badge, clipped title, source and UTC time; activation opens the evidence dialog. High and critical share rose badges, medium amber and low mint.
- **Defense visibility:** three labeled HTTP-WAF, Network-IDS and Host-EDR entries with evidence details and state text. Online/receiving dots are mint, stale/unknown amber, and disconnected rose. Current deployment evidence is CrowdSec AppSec HTTP gateway, Suricata on WSL eth0, and Wazuh Ubuntu/Windows agents; do not expand the network scope visually.
- **Service health:** four service rings show dependency checks. Gateway online is a gateway check, separate from all three defense layers and human approval policy.
- **Sample metrics:** incidents load up to 200, decisions up to 100 and gateway requests up to 80. Counts, severity distribution, vector shares and executed decisions describe their loaded samples. Mission memory now labels the value “Reviewed TP embedded” and shows reviewed-TP eligibility; the meter compares ready embeddings with eligible reviewed TPs. Legacy vectors do not inflate this reviewed count. Memory metrics carry their own source scope. Preserve unavailable states and em-dash placeholders.
- **Scene:** generated static image with decorative overlays; retain illustrative topology and attack-path labels, separate gateway status and response-policy copy, and motion control. The map conveys atmosphere, not geolocation or compliance.

Dashboard extends these components without changing the Mission composition:

- **Records workspace:** tabs for traffic, incidents, AI Triage, Intelligence, Sources, Assets, approvals, campaigns, decisions, Attack Lab and policy; selected tabs use a cyan lower rule and tonal fill. Search and source/severity/status filters operate on server records. Keep empty/error states and disabled page actions explicit.
- **Layer and service status:** defense layers retain readable state text on mobile; dependencies show the service name plus the actual status string and a dot. Missing health remains unavailable. Keep human approval mode next to these indicators.
- **Server paging:** search, filtering and page size are sent to the PostgreSQL-backed endpoint; the returned snapshot anchor keeps new inserts from shifting later pages. The pager displays record range, filtered total and current/total pages. Later pages pause auto-refresh; refresh/filter changes reset the snapshot as implemented. Dashboard totals describe retained server records and must not be confused with Mission loaded samples.
- **Evidence drawer:** selecting a record opens captured evidence with adjacent-record navigation, JSON export and collapsible raw JSON. HTTP traffic is retained access-log metadata with captured allowlisted headers when available; it is not a full PCAP/body capture. Incidents may expose sensor payload and a captured frame rendered as hex/ASCII (preview limited to 4096 bytes). Display missing capture/body limitations directly and retain the label “Gateway peer” rather than asserting an attacker identity. Wrap long targets and headers; preserve the mobile labeled-row view behind the modal.

AI Triage adds these evidence-first patterns within the same cyan world:

- **Priority queue:** paginated Wazuh alerts sorted by real rule level then newest record. Native minimum-level selection defaults to 7, with 5/10/12 options. Sync queue renews its stable snapshot. Full-width alert buttons use a steel outline, 7px corners and 14px padding; selection adds cyan border and a restrained blue fill, expressed with aria-pressed. The level badge, rule, reason, host and time stay readable independently of the accent.
- **Report controls:** native language select offers “ไทย + technical EN” and “English.” Ollama settings reveals installed-model selection with session-local scope; it does not change a global model or server URL. The optional hostname hint is unverified analyst context and does not rename a Wazuh host. Stream analysis, Stop and the native Bypass cache checkbox use incumbent controls and explicit disabled states.
- **Cleaned-context disclosure:** the details summary is “Cleaned model context”; Inspect cleaned payload previews the bounded/redacted evidence for the next request, including the current hint. This disclosure does not claim the preview was already sent. Stream metadata returns the actual context used. Show original-event and model-context byte counts as measured bytes, without invented token savings or a claim of guaranteed anonymization. Hint edits invalidate the displayed preview and prompt reinspection.
- **Provenance and streaming states:** new selection resets provenance to “Not generated · local Ollama”; language/model changes show “Not generated · settings changed.” Starting shows “Connecting · awaiting model metadata.” Only returned stream metadata supplies the model, language and Redis cached/live-generation provenance. Distinguish Ready, Streaming, Cache hit, Completed, Cached report, stopped partial report, errors and unavailable cache; do not let an old model label imply a new report exists. Preserve queue empty/error/retry states and incomplete report text.
- **Plain report surface:** render model output as plain text with preserved line breaks and wrapping, including HTML-like log content; no rich HTML report renderer. Advisory copy remains adjacent: analysis may be wrong, completed cache lasts ten minutes, and the report does not modify stored incident analysis or decisions or trigger enforcement. Partial/failed/stopped reports remain visibly incomplete rather than appearing cached or complete.

Intelligence and investigation reuse the same colors, fonts, controls and flat evidence surfaces:

- **Local KEV catalog:** CVE links, vendor/product/added date, and native disclosure for description and CISA required action. Search and ten-entry paging operate on the retained catalog. Keep source/version, last successful fetch, refresh mode and explicit current/stale/unavailable/error state visible. Current means a successful fetch within 48 hours without a later sync failure; it does not establish complete vulnerability coverage. Empty search results and catalog errors must remain distinct. Sync catalog retains the existing Operation Key gate; a failed sync preserves the last good snapshot.
- **CPU behavior rows:** pair each host/router with state text, reason, request count, baseline median and score. “Unusual volume,” “Warming up,” “Within baseline,” stale and missing/unavailable data are separate conditions. This is an explainable volume heuristic comparing a completed five-minute bucket with 12 preceding buckets, not trained ML or an attack verdict. Show the completed window and latest collected time; collector gaps can distort a baseline. No status implies enforcement.
- **On-demand investigation:** Traffic/Incident inspection offers “Investigate timeline & evidence.” Only activation loads linked evidence; show loading and unavailable/retry states. Bounded decoded target/query, common secret-query masking, syntax hints and truncation scope accompany separately retained raw evidence. This adds no body capture. Use the source label “Decoded target & query”; normalization or a syntax hint is not proof of exploitation.
- **CVE provenance:** label source-observed CVEs separately from “AI-only mentions (unverified).” KEV matches use source mentions and expose the snapshot state and last fetch. Membership does not establish local asset applicability or that this event exploited the CVE. Keep this caveat visible even when a KEV reference exists.
- **Candidate timeline:** the default ±15-minute window supplies candidate links with explicit match reasons, source/severity/time/record ID and available endpoint metadata. Preserve the “Candidate incident timeline” wording and direct incident JSON links. Recorded identifiers, shared NAT/proxy peers and ingestion timing do not prove common attacker identity or causation. No matches can reflect missing identity or capture scope, not safety. Timeline pages contain up to 50 incidents and can change with late arrivals; do not describe this as the record explorer’s stable snapshot.
- **Policy / response evidence:** native details show stored action/status, rationale and raw decision JSON including policy checks and response results. At most the latest 20 linked decisions appear, with an explicit earlier-history notice when truncated. Empty stored decisions remain explicit; request-side evidence may direct the operator to linked incidents. These are historical checks, not newly approved actions or a verified attack chain.

Analyst review and reviewed memory retain the incumbent cyan palette and native form language:

- **Declared review:** Incident inspection exposes “Analyst review” with a required self-declared reviewer label, native True Positive / False Positive / Unknown verdict, required rationale and optional corrected attack type/severity. Blank corrections retain original stored values. Keep “self-declared” and shared-key authorization copy visible; a reviewer label is not verified user identity or independently verified ground truth. Append review revision creates a separate annotation rather than editing raw event, AI analysis or stored decisions.
- **Revision states:** show verdict, latest revision and readable memory status together. Loading/unavailable state disables saving until a valid revision is known. Save uses the expected revision; a concurrent 409 conflict retains the draft, disables submission and directs the operator to Reload latest. Ambiguous network failures retain the draft and permit an idempotent retry of the same submission; “retry confirmed” identifies a replayed save. Do not imply an unsaved draft is persisted or a failed response means no revision exists.
- **Append-only history:** native disclosure reveals newest-first paginated revisions, each with verdict, declared label, authorization method, timestamp, rationale and corrections. A correction appends a revision; it does not replace past entries. This is application/database append-only history, not a cryptographically tamper-proof identity ledger.
- **Reviewed memory status:** preserve readable “ready,” “awaiting embedding,” “waiting for AI analysis” and “excluded from retrieval” labels. Intelligence shows ready/eligible reviewed TP, unreviewed count, verdict totals and identity scope, including unavailable/error states. Only the latest True Positive with completed stored analysis and a current revision/model vector is retrievable; revised TP waits for embedding, and FP/Unknown/unreviewed or stale vectors are excluded. Zero reviewed memory can be correct despite many retained legacy vectors.
- **Historical provenance:** stored analysis links exact immutable review IDs/revisions used by retrieval. Later corrections do not rewrite that historical report; show those links separately from the current review. Feedback is retrieval augmentation, not model training, evaluation accuracy or authorization to run a shell, policy action, ban or unblock.

Asset Inventory adds registry/editor behavior within the existing midnight/cyan system:

- **Registry and form:** searchable, kind/status-filtered, paginated current asset revisions; selected registry buttons use aria-pressed. Native fieldsets group identity/ownership, host or application/service bindings, declared software and the revision record. New asset moves focus to the editor. Keep loading, empty, unavailable, validation and disabled states readable; display unsaved draft/current revision separately from saved revision confirmation.
- **Attestation:** “Declared by · self-reported label” and a change rationale accompany Save new revision. Existing Operation Key authorizes the write; the label is not authenticated actor identity. Active/retired are registry states, not online/offline health. Observed Wazuh endpoint selection only prefills retained evidence with last-seen context and an inspect-before-saving reminder; it does not prove current online status or verified software facts.
- **Bindings and revisions:** host agent/IP bindings and application/service exact host/router plus bounded path-prefix routes are operator-attested, with parent-host context. Keep route syntax/examples beside the native textarea. Declared software versions do not establish CVE applicability. History uses native revision disclosures and paging; conflict retains the draft and requires Reload latest revision. Unsaved-draft discard confirmation and retry-recovered save messages distinguish current edits from persisted history.
- **Investigation mapping:** the existing drawer shows “Mapped asset context,” current mapped asset and parent metadata with owner, criticality, mapping revision and mapped time, plus native “Operator-declared asset metadata” disclosure. Preserve match reasons, warnings and no-unambiguous-active-mapping text. These are current declared mappings, not an event-time identity snapshot or a confirmed cross-layer attack chain. Missing mapping does not establish safety. Asset registration adds no automatic discovery, authenticated actor, CVE-applicability or enforcement claim.

FIRST EPSS sits above reviewed memory and KEV in Intelligence, reusing the wrapping search form, quiet cached-read button and primary fetch button. The section ends with 28px padding/margin and a steel divider. Result CVEs use 22px/1.3 condensed headings, prose 13px/1.7 and soft-cyan 16px tabular probability/rank text; long provenance and source strings wrap.

- **One-CVE lookup:** View cached score reads locally; Fetch from FIRST is an explicit shared-Operation-Key-gated request. KEV’s View EPSS selects the CVE and reads cache. Preserve input validation, busy/read-only state, cancellation and retry copy. The cache lasts 24 hours with a 30-second outbound lookup budget; EPSS is on demand, with no daily sync.
- **Meaning and provenance:** label probability separately from percentile rank. Show lookup state, last success/attempt, score date, fetched time and score current/stale state; a retained score can coexist with a newer failed or not-scored lookup. Missing/not-scored is not zero probability. Keep errors, retained-score caveat, immutable stored-snapshot link and FIRST attribution visible. “FIRST API” version is not the EPSS model version. This is exploitation likelihood, not severity, asset applicability, proof of exploitation or authorization for enforcement.

Sources and analysis provenance extend the existing Operate world:

- **NVD and catalog evidence:** View cached NVD performs a local read; Fetch NVD and source Refresh actions require the shared Operation Key. Keep cache/freshness/error, last successful check and publisher-modified times distinct, with immutable snapshot links and attribution/non-endorsement copy. NVD metrics/CVSS are not exploitation probability. Retained MITRE techniques support native search and paging with license/copyright links; DROP lookup checks retained IPv4/IPv6 ranges locally without sending the entered IP to a provider. No match or missing data is not safety, and a range match is not maliciousness or permission to block.
- **Declared-product assessment:** select an Asset revision, provide a self-reported author and rationale, and Save assessment against a pinned NVD snapshot. Render saved author/time/revision and “Saved reason / evidence” as read-only result text, separately from the editable new-assessment draft. Historical selections keep their original criteria, uncertainty and source links; never substitute the current draft for a saved reason. Preserve paginated history, retained drafts, revision-conflict/reload and idempotent retry messages. Candidate match requires verification; unsupported CPE/version, AND/negation/environment conditions route to review, and no-match is not a clean-asset verdict.
- **Asset declaration handoff:** software lines accept optional specific CPE 2.3 and version scheme (unknown or explicitly numeric_dot). These remain operator declarations, not verified installed-package facts. Check CVE applicability jumps from a saved Asset revision to Sources; unsaved edits must be saved or reloaded before checking that stored revision.
- **Analysis provenance:** Incident inspection uses an “Analysis provenance” section with native “Prompt/model execution metadata” disclosure and source/provider/identifier/freshness/scope plus immutable snapshot links. Historical metadata may be explicitly unrecorded; source references are not proof of technique use or exploitation. Prompt/input hashes, requested/returned model and observed tag digest describe the recorded context; observed model digest is not runtime attestation. Triage’s native “Prompt / model provenance” disclosure follows Cleaned model context and precedes report text. It begins Not generated, updates from stream metadata, and labels older cached provenance unrecorded rather than inventing it.

All interactive controls inherit a 2px cyan focus-visible outline with 4px offset. Preserve skip navigation, dialog semantics and actual text labels; color alone does not communicate state.

## Do's and Don'ts

### Do:

- Do keep sensor coverage and sample scope adjacent to their metrics.
- Do use the central raster artwork as the static visual foundation.
- Do preserve the mobile reading order: visibility, scene and metrics, incidents, then AI and health.
- Do keep keyboard focus visible and state labels readable without color.

### Don't:

- Don't let the static 3D background dominate Dashboard records or obscure capture limitations.
- Don't present decorative world paths as attacker geolocation.
- Don't turn a green gateway state into a claim of automatic enforcement or complete network coverage.
- Don't invent compliance badges, endpoint inventories or totals beyond the loaded sample.
