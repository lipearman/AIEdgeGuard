# Asset Inventory and explicit target mappings (Release 2B)

Delivered 2026-11-21. Open `/AIEdgeGuard/dashboard#assets`.

## Operator workflow

1. Register a **host** with its name, owner, criticality, OS/version and declared software. Bind Wazuh agent IDs as recorded (for example `001`, never manager `000`) and endpoint IPs. **Observed Wazuh endpoint** prefills retained evidence for inspection; it is not discovery of every device or confirmation that a device is online.
2. Register an **application/service** with exact observed HTTP host, Traefik router and literal path prefix. Optionally select its parent host. Route rows use `host | router | path prefix`; software rows use `vendor | product | version`. Maximum 20 entries in each list and 1,000 active assets.
3. Enter a self-reported operator label and reason/evidence, then **Save new revision** using the existing shared Operation Key. This authorizes the write; it does not authenticate the named person. Revisions preserve old declarations, actor label, authorization method, reason and server timestamp.
4. From Traffic or Incidents, open **Inspect → Investigate timeline & evidence**. **Mapped asset context** shows the selected asset and parent host, owner/criticality, mapping revision/time, reasons and full declared metadata. A mapped HTTP route can add parent-host Wazuh/IDS evidence to the candidate timeline.

The upgraded production registry starts empty. It does not turn observed endpoint names or sample software into verified production declarations. Operators must inspect and register their deployment's actual bindings.

## Matching boundaries

- HTTP peer/source IP is never used as the application's target identity. Hostnames are canonicalized for case, IDNA and trailing dots; observed port and router must match. The longest matching literal path prefix wins. `/app` matches `/app` and `/app/...`, not `/application`; identity matching does not URL-decode paths.
- Hosts bind to deployment-local Wazuh agent IDs or endpoint IP evidence from Wazuh/Suricata. WAF source IP does not identify the protected host. Missing target fields are not guessed. A Suricata event involving two separately mapped hosts has no single target selected.
- Agent IDs and exact route selectors must be unique across active assets. Shared endpoint IPs are permitted with warnings, but are excluded from unique asset matching and from mapping-based timeline expansion. Conflicting agent/IP mappings select no unique target. Existing source-IP candidate correlations remain explicitly labeled as candidates.
- An application/service may reference one parent host. Host events are not attributed to a particular child application without its route evidence. Retire/reassign active children before retiring their host. Retiring an asset removes its bindings from current matching; history remains.
- These are **current operator-attested mappings**, not independently verified identity or mappings as of historical event time. Historical investigations display the revision/time used now. IP reuse, NAT, agent re-enrollment and capture gaps still require operator judgment.
- Software declarations do not prove CVE applicability, exploitation or a causal attack chain. The [Phase2 checker](phase2-source-library.md) adds optional explicit CPE/version-scheme declarations and immutable candidate assessments; unsupported/environmental cases route to review. This release does not alter model prompts, old analyses, raw evidence, policy or enforcement.

## API and persistence

Gateway prefixes are stripped before these API paths:

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/assets?q=&kind=all&status=active&page=1&page_size=10` | Current revisions, search/filter and PostgreSQL paging |
| `GET /api/v1/assets/hosts` | Active parent-host options, bounded by registry capacity |
| `GET /api/v1/assets/observed` | Latest retained Wazuh evidence per non-manager agent, up to 50 |
| `GET /api/v1/assets/{uuid}?page=1&page_size=10` | Current declaration and append-only paginated revision history |
| `POST /api/v1/assets/{uuid}` | Append `{payload, declared_by, rationale, expected_revision, request_id}` with `X-Operation-Key` |

`payload` contains `name`, `kind` (`host/application/service`), `owner`, `criticality`, `status`, `os_name`, `os_version`, `software`, `agent_ids`, `ips`, `routes` and `parent_host_id`. Kind is immutable after creation. New identities use an operator-generated UUID and `expected_revision: 0`.

`asset_registry` stores identities; `asset_revisions` stores complete revision snapshots. Database triggers reject ordinary UPDATE/DELETE of revision history. A transaction/advisory lock serializes cross-asset uniqueness and parent lifecycle checks; optimistic revision checks reject stale writes with HTTP 409. Repeating the same request UUID/content returns its original revision. Reusing it for different content is rejected. The browser retries a lost response with the same UUID and retains a conflicting draft until explicit reload; backend selector/lifecycle conflicts can be corrected without discarding the draft. Asset editing never deletes or rewrites incidents.

`investigation/timeline` adds `asset_context` with metadata, selected revision/time, reasons, warnings and unambiguous host bindings. This is computed on demand, not silently persisted into historical analyses. Query limits/time windows and candidate-only semantics remain in force.

## Deployment and validation

Rebuild/recreate API only; schema initialization is additive. Rollback image: `edge-ai-api:before-assets-20261121`. It retains reviewed-TP-only memory behavior; older pre-2A images require disabling learning before rollback (see [Analyst reviews](analyst-reviews.md)). Preserve Operation Key gates and `DEFENSE_AUTO_EXECUTE=false`.

Validation uses isolated PostgreSQL/pgvector for writes and fully mocked browser responses: invalid bindings, API authorization, route boundaries, longest prefix, explicit parent linkage, ambiguous/conflicting addresses, concurrent selector claims, lifecycle constraints, search and cross-layer SQL timeline. Browser tests cover four widths/three prefixes, observed prefill, host/application forms, paging/history, lost-response retry, stale revision draft/reload, hostile text, errors/recovery and tab-switch draft retention. No test assets or analyst verdicts are added to production.

NVD/ATT&CK/selected IOC sources and bounded declared-product checks are now delivered in Phase2. Next: authenticated named identities, independently verified inventory and measured behavior/attack-graph evaluation. See [Roadmap V2](roadmap-v2.md).

On 2026-11-21, 77 backend tests passed locally and with the deployed Docker dependencies against an isolated database. Assets browser checks passed at 1440/768/390/320px across three route prefixes; Dashboard, Intelligence (including mapped-context hostile-text checks), Analyst Reviews, Triage and Mission regression suites passed. Live read-only checks at 1440/768/390px showed the truthful empty registry and two retained observed Wazuh endpoints, with no page overflow or JavaScript errors. Public Internet443 reads returned 200; a save without Operation Key returned403 and left the registry empty. Fresh UI review disposition: `ship` at the Release2B scope.
