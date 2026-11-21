# AIEdgeGuard V2 roadmap

Updated 2026-11-21 after comparing the repository with the user's [Centillex conversation](https://chatgpt.com/share/6b01200e-25bc-83ec-a185-5404e01e5b41). The earlier 10–13 week estimate preceded source inspection; the releases below use acceptance gates rather than an agreed schedule.

## Existing foundation

Already implemented: HTTP-WAF, passive WSL Network-IDS, Windows/WSL Host-EDR, durable ingestion, local analysis, campaigns, deterministic policy/approval, restricted IP-ban execution, controlled Attack Lab, pgvector memory, responsive Dashboard, request history and Wazuh AI Triage/SSE/cache. V2 extends these instead of rebuilding them. Existing Operation Key gates and preview/auth configuration are preserved.

## Release 1 Delivered evidence and intelligence foundation

| Capability | Delivered implementation | Boundary |
|---|---|---|
| Threat Intelligence Auto Update | Fixed CISA KEV feed, official mirror fallback, daily sync, validated atomic snapshots, source/version/freshness/error metadata | KEV is not a complete CVE/IOC knowledge engine. Failed/older feeds preserve the last good snapshot. |
| Local AI enrichment | Bounded KEV references for exact CVE IDs in source event evidence, with freshness and uncertainty | No inferred vulnerable asset or automatic rule deployment; existing analyses are not rewritten. |
| Behavioral Anomaly foundation | CPU median/MAD volume heuristic over 12 preceding five-minute buckets per host/router | Warmup/stale/missing states; not trained ML or a maliciousness verdict. |
| Attack Chain foundation | Candidate timeline using recorded IP, Wazuh agent/endpoint or request ID, bounded time window and explicit match reasons | Not a verified causal attack chain. Shared NAT/proxy and ingestion times remain limitations. |
| Evidence inspection | Bounded URL decode, common secret query masking, syntax hints, source-vs-AI CVE provenance, KEV freshness and stored policy evidence | No general body/PCAP capture, invented CVEs or guessed host/application mappings. |
| Dashboard | Intelligence tab, searchable/paginated local catalog and behavior results; Investigate action in request/incident drawer | Existing Mission, Triage, approvals and lab continue to work. |

Open `/AIEdgeGuard/dashboard#intelligence`; use **Inspect → Investigate timeline & evidence** from Traffic/Incidents. See [V2 foundation](v2-foundation.md) for interfaces and limits.

## Release 2 Reviewed knowledge and identity — implementation delivered

**Release 2A delivered 2026-11-21:** [Analyst feedback and reviewed AI memory](analyst-reviews.md) implements items 1–2 below with append-only revision history, concurrency/idempotency guards and latest-TP-only retrieval. Reviewer labels are self-declared behind the shared Operation Key, so verified named identity remains future work. Release 2B adds operator-attested inventory; Releases 2C/2D below complete the scoped source/check/provenance implementation. Independently verified identities remain an operational limitation and future identity work.

1. Delivered: True Positive/False Positive/Unknown feedback with append-only audit, declared reviewer label/authorization method, rationale and versioned corrections. Analyst annotations stay separate from raw evidence/model output. Authenticated actor identity and evaluation metrics remain planned.
2. Delivered for RAG: latest reviewed True Positives only; False Positive/Unknown/unreviewed and stale vectors are excluded without deleting audit history. Feedback does not activate a defense rule. Labeled evaluation/benchmarking remains planned.
3. **Release 2B delivered 2026-11-21:** [Asset Inventory](asset-inventory.md), owner/criticality, OS/software versions, revision history and explicit Wazuh agent/endpoint or HTTP host/router/path mappings. Mapped routes can link to parent-host candidate IDS/EDR evidence. Shared IPs do not establish unique identity. Current declarations are operator-attested, not independently verified or historical event-time identity; Supported declared-product checks are delivered in Release 2D below; unsupported CPE/environment cases route to human review.
4. **Release 2C.1 delivered 2026-11-21:** [FIRST EPSS](epss-intelligence.md) individual on-demand lookup, gated outbound fetch, 24-hour positive/negative cache, cross-process budget, immutable dated score snapshots and source links. This is not bulk/daily EPSS sync or verified asset applicability. **Release 2C.2 delivered:** NVD API2.0 exact-CVE lookup, official MITRE ATT&CK Enterprise STIX catalog and selected Spamhaus DROP IPv4/IPv6 reputation, with bounded retrieval, cache/budgets, validated atomic snapshots, source terms/attribution, freshness, rollback protection and deduplication. See [Phase2 source library](phase2-source-library.md).
5. **Release 2D delivered:** immutable declared-product/version assessments pin asset revisions and NVD snapshots; missing/unsupported/complex conditions route to review. Newly generated incident analyses persist only source references included in the actual prompt, prompt hashes/version, model tag/observed digest metadata and execution mode; old analyses remain unrecorded. Triage exposes equivalent metadata in its existing short-lived cache. Model-proposed CVEs remain distinct from source-mentioned identifiers; observed tag digest is not runtime attestation.

Gate met for the operator-attested workflow: an operator can correct an alert, inspect its declared author/authorization method and immutable revision history, trace reviewed context and source snapshots, and distinguish missing/unsupported coverage from a clean result. Named authenticated actors, independently verified inventory, universal CPE matching and measured detection claims are not supplied by this gate; see the explicit limits in [Phase2 delivery](phase2-source-library.md).

## Release 3 Measured behavior and attack chains

1. Collect a labeled normal/lab corpus and establish collector continuity, missing-window handling, application segmentation and drift controls.
2. Evaluate EWMA or Isolation Forest on CPU against the simple baseline. Add model complexity only when held-out results justify it.
3. Add error-share, method/path distribution, identity and endpoint process/network features only when evidence is captured and reliably mapped.
4. Build typed, confidence-qualified attack graphs with observed event time versus ingestion time, late-arrival handling and reproducible case membership. Same IP/time remains a candidate edge.
5. Add independent maker/checker evidence validation; another prompt on the same model does not establish independent verification.

Gate: replay held-out data, publish false positives/misses and distinguish real sequences from coincidental activity. Do not claim universal zero-day detection.

## Release 4 Controlled response and operational release

1. Add action-specific notification, rate-limit and containment playbooks only after identity, authorization, allowed targets, TTL, approval and rollback are tested for each action.
2. Add roles/MFA or an identity provider, read/write separation and redacted public-demo data. Preserve policy/executor separation and give the LLM no shell/firewall tools.
3. Pin dependencies/images, automate schema/rollback tests and CI, and verify private management endpoints from a second client.
4. Expand capture only through documented mirroring/routing or explicit host deployment. WSL `eth0` is not full Windows/LAN visibility.
5. Measure model latency, queue age, source uptime, audit coverage, response TTL/rollback and resource use; generate reports from measured data.

Gate: repeatable tests cover approval races, stale evidence, model/feed outages, collector gaps, failed enforcement and rollback. Automatic actions remain off until an operator explicitly enables an evaluated playbook.

## Evaluation targets are not current claims

The chat proposed detection ≥95%, false positives ≤1%, WAF added latency P95 ≤20 ms, AI Triage P95 ≤10 seconds, complete response auditing and sensor availability ≥99.9%. These are candidate objectives, not benchmark results. Define corpus, hardware, traffic, measurement method and reporting interval before accepting them as targets.

Phases1–2 implementation is delivered at the documented scope. Phases3–4 remain open; the complete V2 program and its evaluation/operational gates are not complete.
