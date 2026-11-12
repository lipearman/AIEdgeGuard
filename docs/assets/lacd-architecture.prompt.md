# LACD architecture image — generation prompts

Tool: built-in image_gen. Output: lacd-architecture.png.

## Initial generation

Use case: infographic-diagram.
Create one polished, technically accurate landscape architecture infographic (wide 16:9, high-resolution, suitable for a project README and presentation). This is the real implemented architecture of the project LACD, Local AI Cyber Defense, implementation named EdgeGuard. Use excellent legible English typography, precise straight orthogonal connectors with arrowheads, generous spacing, a restrained midnight-navy background, crisp white text, cyan data arrows, amber approval/enforcement arrows, and subdued gray dashed future connectors. Flat professional technical illustration, subtle small infrastructure icons, no sci-fi decoration, no glowing brains, no code screenshots. Focus on clarity and correct relationships.

TITLE, large, verbatim: "LACD"
Subtitle verbatim: "Local AI Cyber Defense"
Small descriptor: "EdgeGuard Architecture"
Bottom principle line: "Local inference • Deterministic policy • Human approval"

Arrange three clearly separated horizontal bands, with a compact side panel for future integrations:

TOP BAND label "01  TRAFFIC & ENFORCEMENT" (the traffic path).
From left to right: "Internet / Tailnet" -> "Tailscale Funnel / Serve" -> "Traefik Gateway" -> "CrowdSec AppSec WAF" -> "Protected Applications".
Under WAF show small labels "Virtual Patching • OWASP CRS • IP Bans".
Protected applications small sublabels "CVAT • ERPNext • ForgeMind • Other Apps".
A single enclosing boundary around gateway, apps, and lower processing components labeled "LOCAL HOST · Windows + Docker Desktop" (external Internet is outside this boundary).
The WAF node connects down via cyan arrow labeled "Security alerts / LAPI" to Watcher in second band.
Indicate local Ollama runs on host within the local boundary, outside Docker portion if feasible, but do not sacrifice readability.

MIDDLE BAND label "02  EVENT & AI PIPELINE".
Main flow left to right: "Watcher / Ingestion" -> "Redis Streams" -> "Worker" -> "Analysis Agent".
Below Watcher a database node "PostgreSQL" with small text "Incidents • Campaigns • Decisions • Audit". Arrow Watcher to PostgreSQL labeled "Persist first"; Watcher to Redis labeled "Queue". Worker also connects to PostgreSQL labeled "Save analysis". No claim of atomic transactions across PostgreSQL and Redis.
Analysis Agent connects to a distinct "Ollama" node labeled "Local LLM · Qwen / Typhoon".
After Analysis branch into "Detection Agent" with text "Group incidents into campaigns", and "Decision Agent" with text "Deterministic YAML policy". Detection and Decision are separate deterministic roles; do not suggest all six roles are LLMs or that campaign grouping is mandatory before policy decisions.
Decision flows down into bottom band.

BOTTOM BAND label "03  CONTROL, RESPONSE & MEMORY".
Decision Agent -> "Policy Gate" -> "Human Approval" -> "Defense Executor".
Small badge at Human Approval: "Default: dry-run". A second thin amber dashed branch from Policy Gate to Defense Executor labeled "Optional L1 auto-execution". Defense Executor has an amber return arrow going up to CrowdSec WAF / IP Bans labeled "Temporary IP ban · TTL".
Safety text near Policy Gate, short readable lines: "Source IP validation", "Protected ranges", "Confidence + cooldown".
Place "Dashboard / Mission Control" linked to Human Approval and database with subtle lines, labeled "Monitor · Approve · Audit".
Place "Learning Agent" linked to PostgreSQL / pgvector, label "Embeddings + similar incidents (RAG)". Cyan feedback arrow returns from Learning to Analysis Agent labeled "Past incident context". Mention "pgvector" visibly as part of memory storage. Learning retrieves context, it does NOT train or fine-tune the LLM.
Small clearly separated bottom-left panel "Attack Simulator Agent", sublabel "Authorized Lab only", containing "Fixed Technique Catalog" -> "Juice Shop via Gateway". Arrow to the traffic inspection path labeled "Controlled tests". Small badge "Kill switch + target allowlist". Do not draw attack traffic directly to production apps.

RIGHT SIDE small muted dashed-outline panel label "PLANNED INTEGRATIONS": "Wazuh", "Suricata", sublabel "Automatic ingestion pending", gray dashed arrow toward Watcher. These must clearly be future connections, not active implemented ingestion.

Six role names must be present exactly once: Analysis Agent, Detection Agent, Decision Agent, Defense Executor (counts as Defense role), Learning Agent, Attack Simulator Agent.
Legend at bottom: cyan solid "Events / context"; amber solid "Approved response"; gray dashed "Planned".
Keep all text correctly spelled, no clipped text or overlapping connectors. Avoid duplicating blocks, invented services, Kubernetes, cloud AI, autonomous model-to-firewall control, or marking Wazuh/Suricata ingestion as complete. The diagram is an architecture illustration, not a dashboard mockup.

## Connector correction

Edit this existing LACD architecture infographic. Preserve its title, navy/cyan/amber style, typography, layout and all existing components. Make only these technical connector corrections, redrawing short clean routes with no intersections through text:
1. The cyan line "Security alerts / LAPI" must go FROM CrowdSec AppSec WAF TO Watcher / Ingestion. It currently points incorrectly to Redis Streams. Remove its existing arrow into Redis and reroute it to the top of Watcher. Watcher -> Redis queue arrow remains unchanged.
2. Add a clear cyan two-way connector between Analysis Agent and Ollama, labeled "Local inference". This is essential; Ollama must not remain disconnected. Route along upper edge of processing band if necessary.
3. Remove the amber connector going from Analysis Agent downward into Policy Gate. Instead draw amber arrow FROM Decision Agent TO Policy Gate. The Decision Agent must NOT connect directly to Human Approval. Existing correct path Policy Gate -> Human Approval -> Defense Executor remains.
4. Planned Integrations panel currently has no connection to the dashed arrow near Watcher. Replace the detached gray dashed line with a complete gray dashed arrow FROM the Planned Integrations panel (Wazuh / Suricata) TO Watcher / Ingestion, routing above or below processing nodes without crossing text. Dashed connection represents future ingestion, not active data.
Keep the Learning Agent feedback to Analysis Agent and Defense Executor return to WAF unchanged. Keep every text label spelled correctly. Preserve the 16:9 landscape image. Do not add any new services.

## Final cleanup

Make exactly two tiny connector edits to this diagram, preserving everything else pixel-for-pixel as much as possible: (1) Between "Policy Gate" and "Human Approval", change the amber connector to a clearly BIDIRECTIONAL horizontal arrow with arrowheads at BOTH ends. It represents proposal and approval interaction. (2) Remove the disconnected gray dashed L-shaped stub at the left of Watcher that goes downward behind the Attack Simulator panel. Keep the long gray dashed connection from Planned Integrations to the top of Watcher. Do not change any text, blocks, colors, layout or other connectors.

