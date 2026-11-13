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

This system applies to Mission Control and the authorized Dashboard extension (Defense Workspace). Mission keeps its three-column overview; Dashboard reuses the palette, local fonts and shield artwork as a static decorative page background while giving operational records the primary reading space. AI Triage extends Dashboard with an advisory Wazuh priority queue and streamed local report, using the same visual language. Small English condensed headings and numerals pair with readable Thai and English operational copy; measured borders and tonal panels keep the artwork from competing with evidence.

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
- **Sample metrics:** incidents load up to 200, decisions up to 100 and gateway requests up to 80. Counts, severity distribution, vector shares and executed decisions describe their loaded samples. Memory metrics carry their own source scope. Preserve unavailable states and em-dash placeholders.
- **Scene:** generated static image with decorative overlays; retain illustrative topology and attack-path labels, separate gateway status and response-policy copy, and motion control. The map conveys atmosphere, not geolocation or compliance.

Dashboard extends these components without changing the Mission composition:

- **Records workspace:** tabs for traffic, incidents, AI Triage, approvals, campaigns, decisions, Attack Lab and policy; selected tabs use a cyan lower rule and tonal fill. Search and source/severity/status filters operate on server records. Keep empty/error states and disabled page actions explicit.
- **Layer and service status:** defense layers retain readable state text on mobile; dependencies show the service name plus the actual status string and a dot. Missing health remains unavailable. Keep human approval mode next to these indicators.
- **Server paging:** search, filtering and page size are sent to the PostgreSQL-backed endpoint; the returned snapshot anchor keeps new inserts from shifting later pages. The pager displays record range, filtered total and current/total pages. Later pages pause auto-refresh; refresh/filter changes reset the snapshot as implemented. Dashboard totals describe retained server records and must not be confused with Mission loaded samples.
- **Evidence drawer:** selecting a record opens captured evidence with adjacent-record navigation, JSON export and collapsible raw JSON. HTTP traffic is retained access-log metadata with captured allowlisted headers when available; it is not a full PCAP/body capture. Incidents may expose sensor payload and a captured frame rendered as hex/ASCII (preview limited to 4096 bytes). Display missing capture/body limitations directly and retain the label “Gateway peer” rather than asserting an attacker identity. Wrap long targets and headers; preserve the mobile labeled-row view behind the modal.

AI Triage adds these evidence-first patterns within the same cyan world:

- **Priority queue:** paginated Wazuh alerts sorted by real rule level then newest record. Native minimum-level selection defaults to 7, with 5/10/12 options. Sync queue renews its stable snapshot. Full-width alert buttons use a steel outline, 7px corners and 14px padding; selection adds cyan border and a restrained blue fill, expressed with aria-pressed. The level badge, rule, reason, host and time stay readable independently of the accent.
- **Report controls:** native language select offers “ไทย + technical EN” and “English.” Ollama settings reveals installed-model selection with session-local scope; it does not change a global model or server URL. The optional hostname hint is unverified analyst context and does not rename a Wazuh host. Stream analysis, Stop and the native Bypass cache checkbox use incumbent controls and explicit disabled states.
- **Cleaned-context disclosure:** the details summary is “Cleaned model context”; Inspect cleaned payload previews the bounded/redacted evidence for the next request, including the current hint. This disclosure does not claim the preview was already sent. Stream metadata returns the actual context used. Show original-event and model-context byte counts as measured bytes, without invented token savings or a claim of guaranteed anonymization. Hint edits invalidate the displayed preview and prompt reinspection.
- **Provenance and streaming states:** new selection resets provenance to “Not generated · local Ollama”; language/model changes show “Not generated · settings changed.” Starting shows “Connecting · awaiting model metadata.” Only returned stream metadata supplies the model, language and Redis cached/live-generation provenance. Distinguish Ready, Streaming, Cache hit, Completed, Cached report, stopped partial report, errors and unavailable cache; do not let an old model label imply a new report exists. Preserve queue empty/error/retry states and incomplete report text.
- **Plain report surface:** render model output as plain text with preserved line breaks and wrapping, including HTML-like log content; no rich HTML report renderer. Advisory copy remains adjacent: analysis may be wrong, completed cache lasts ten minutes, and the report does not modify stored incident analysis or decisions or trigger enforcement. Partial/failed/stopped reports remain visibly incomplete rather than appearing cached or complete.

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
