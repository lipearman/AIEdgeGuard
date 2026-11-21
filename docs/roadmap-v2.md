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

## Release 2 Reviewed knowledge and identity

1. Add True Positive/False Positive/Unknown feedback with append-only audit, actor identity, rationale and versioned corrections. Keep analyst labels separate from raw evidence and model output.
2. Use reviewed labels in memory/evaluation. Never erase false-positive audit history or silently retrieve false positives as confirmed attacks. Feedback does not automatically activate a defense rule.
3. Add verified asset/application/service identity, versions, ownership and criticality. Use explicit mappings to link WAF, IDS and EDR instead of shared addresses.
4. Add NVD/CVE, EPSS, MITRE ATT&CK and selected IOC sources incrementally, checking schemas, licenses/quotas, provenance, freshness and deduplication for each.
5. Persist structured citations, prompt/model versions and product/version applicability checks, separate from model-proposed CVE mentions.

Gate: an operator can correct an alert, trace who changed it and how reviewed context enters RAG, and distinguish missing coverage from a clean result.

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

This delivered release supplies observable foundations for the three proposed priorities. The entire V2 program is not complete.
