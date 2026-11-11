"""Remaining five agents — role skeletons for upcoming phases.

Each agent is a distinct ROLE over the same single model (Qwen3.5 9B via
Ollama), with its own system prompt, tool permissions and context. Real
implementations land in later roadmap phases:

- detection.py  (Phase 5): alert dedup/clustering from Redis stream
- decision.py   (Phase 6): propose action + confidence -> Policy Engine gate
- defense.py    (Phase 7): restricted executor (CrowdSec LAPI, nftables)
- learning.py   (Phase 9): pgvector incident memory + RAG feedback
- attack.py     (Phase 8): atomic-operator test plans (LAB VLAN only)
"""


class AgentStub:
    """Placeholder documenting the role contract until implemented."""

    name = "stub"
    permission = "none"
    phase = "later"

    def __init__(self, reason: str):
        self.reason = reason

    async def run(self, *args, **kwargs):
        raise NotImplementedError(f"{self.name} is not implemented yet: {self.reason}")


detection_agent = AgentStub("Phase 5: alert clustering/dedup over Redis stream")
decision_agent = AgentStub("Phase 6: structured proposal -> deterministic Policy Engine gate")
defense_agent = AgentStub("Phase 7: restricted executor, DEFENSE_ENABLED=false for now")
learning_agent = AgentStub("Phase 9: pgvector incident memory + feedback loop")
attack_agent = AgentStub("Phase 8: atomic-operator test plans, isolated lab VLAN only")
