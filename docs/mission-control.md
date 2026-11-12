# Mission Control — 3-layer visibility

Updated 2026-11-12. The requested dark SOC dashboard is implemented at `/AIEdgeGuard/mission`, with newly generated 3D world/shield and neural-brain assets, local Three.js animation, live metrics and responsive layouts.

## Verified layers

| Layer | Sensor and actual scope | Verification |
|---|---|---|
| HTTP-WAF | CrowdSec AppSec + OWASP CRS in the Traefik gateway | Controlled `/.env` request to the Juice Shop lab route returned HTTP 403 |
| Network-IDS | Suricata 7.0.3, passive AF_PACKET on Ubuntu WSL `eth0`; Emerging Threats Open rules | Controlled request from Windows to a temporary WSL HTTP server matched signature 1000001 and reached PostgreSQL as a Suricata incident |
| Host-EDR | Wazuh 4.14.5 agents `llm-server-wsl` and `llm-server-windows` connected to the existing Manager | Both agents Active; controlled Linux and Windows file-integrity events persisted as Wazuh incidents |

Network capture covers the configured WSL interface. It does **not** imply packet visibility over all Windows interfaces, Docker networks or the LAN. Extend capture with explicit traffic mirroring/routing when broader coverage is required. The world map is an illustration, not source-IP geolocation.

## Data path

```text
Traefik → CrowdSec alerts → existing watcher
Suricata EVE → WSL sensor bridge → sensor-data/suricata-alerts.jsonl
Wazuh agents → Manager → alerts/alerts.json (read-only volume)
                              ↓
                       telemetry reader
                              ↓
                  PostgreSQL durable outbox
                              ↓
                  Redis → Analysis → Policy
```

Only incident-worthy telemetry enters AI triage: Suricata severity 1/2, Wazuh level >=5, excluding bulk SCA posture scans. Original sensor logs retain the broader events. Host endpoint addresses are never invented as attacker IPs; file-integrity events without an evidenced attacker IP cannot become automatic IP bans.

Log offsets are checkpointed in Redis only after persistence. Incidents use stable content hashes to deduplicate retries. Wazuh manager-local events and duplicate Suricata events from Wazuh are excluded. The API has read-only access to telemetry and supplementary group999 for Wazuh log files; it receives no Docker socket.

## Liveness and display semantics

The WSL `edgeguard-sensor-bridge` systemd service writes a fresh `sensor-data/status.json` every 10 seconds. It checks the Suricata service, packet counters, and Manager's connected endpoint list. `/api/v1/visibility` rejects heartbeats older than 60 seconds or implausibly in the future.

The page refreshes every 30 seconds while visible. Dependency health, sensor states, incidents, decisions, request samples and embedding stats refresh independently. Failed sections clear their readings or show unavailable; old green sensor statuses are not retained. Source labels distinguish HTTP-WAF, NETWORK-IDS and HOST-EDR in the feed.

Counts identify their scope: latest 200 incidents, latest 100 decisions and latest 80 gateway requests. HTTP403 counts are response codes, not an assertion that every 403 is a WAF attack. Progress indicators reflect analyzed/embedded incidents, not invented processing progress.

## Interaction and assets

Animation starts playing automatically on every fresh open/reload, per the user’s preference. Reduced-motion uses slower pacing rather than stopping playback; the Pause button remains available.

- Severity filter updates the attack-vector distribution.
- Incident rows open source evidence in an accessible dialog; Escape closes it.
- Dashboard/approval links respect direct, `/AIEdgeGuard` and `/aiedge` routes.
- Lab testing retains confirmation, kill switch and target allowlist.
- Three.js renders genuine 3D rings, particles and curved paths above the generated artwork. Pause/resume, reduced-motion, hidden-tab throttling, WebGL failure fallback and resource disposal are implemented.
- Animation repair: visible comet trails, pulsing beacons, a scan beam and segmented shield-base rings replace the former tiny/slow overlays. Pixel comparison confirms visible change on desktop/mobile, no change while paused, and movement after Play. Cached-page lifecycle is covered with simulated persisted pagehide/pageshow events. GPU resources are preserved for cached navigation, and the scene resumes on return. An unavailable WebGL renderer disables the playback button with an explicit static-fallback label.
- Artwork, fonts and Three.js are self-hosted. Exact image prompts are embedded in the PNGs and recorded in `static/media/generation-prompts.md`. Font OFL licenses are in `static/fonts/`.

## Installed services and reproducibility

```powershell
# Sensor setup in Ubuntu (root is limited to that WSL distro)
wsl -d Ubuntu -u root -- bash /mnt/d/GitHub/AIEdgeGuard/tools/sensors/setup-wsl.sh

# Windows agent installer requires Administrator/UAC; verifies the MSI signature
powershell -File tools/sensors/install-windows-agent.ps1

# Observe current sensor evidence
Get-Content sensor-data/status.json
docker exec edgeguard-wazuh-manager /var/ossec/bin/agent_control -l -j
```

Suricata, Wazuh agent and the bridge are enabled systemd services. A current-user Startup shortcut, `LACD Sensors.lnk`, boots Ubuntu at Windows sign-in; Docker Desktop must also be running for Manager connectivity. The Windows Wazuh service starts automatically.

The bridge is installed as `/opt/edgeguard-export-sensors.py`, with configuration in `/etc/systemd/system/edgeguard-sensor-bridge.service`. Before changing sensor config, setup retains `.pre-edgeguard` backups. Windows agent config has an equivalent backup.

The installer uses version-matched Wazuh packages and the official [Windows deployment variables](https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html). The configured Windows service and enrollment workflow follow the [Wazuh installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html).

## Validation

28 Python regression/integration cases passed against an isolated PostgreSQL/pgvector instance. Playwright/Chrome checks passed at 1440, 1392, 768, 390 and 320px: all three URL prefixes, source escaping, filters, evidence dialogs, partial failures/recovery, controlled lab UI and reduced-motion. Actual WebGL frame counters advanced in live captures. No horizontal document overflow was observed.

Independent UI review accepted desktop/reference-width/mobile fidelity and verified the correction that removes stale successful telemetry after failed refreshes. This was browser emulation, not physical mobile-device testing.

The current API rollback image is `edge-ai-api:before-mission-20261112-131934`. It predates sensor ingestion; rolling back UI/API does not uninstall sensors. Sensor tests used only designated self-test paths and lab routes. Human approval remains the default; no automatic defense execution was enabled.

## Operational follow-up

- Extend network capture scope if all host/LAN packets must be inspected.
- Set a retention policy for the bridge's Suricata alert spool as event volume grows; sensor logs use their own retention mechanisms.
- Review classification quality on host/network events; existing model prompts were extended for the new sources, and policy continues to constrain responses.
- The project working tree includes previous user changes and this work; no commit was created.
