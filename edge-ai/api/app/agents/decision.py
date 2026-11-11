"""Decision Agent — deterministic policy evaluation of AI proposals.

Design (EdgeGuard principle): the Analysis Agent (LLM) PROPOSES an action;
this module DECIDES what is allowed. No LLM here on purpose — the gate must
be predictable, auditable and independent of model behaviour.

Verdicts:
  approve           — within allowlist, confidence/severity ok, clamped duration
  pending_approval  — policy wants a human (protected range, low confidence,
                      unknown attack type, unsupported action)
  deny              — action outside the allowlist entirely
"""

import ipaddress
from dataclasses import dataclass, field

import yaml

from app.config import settings

POLICY_PATH = "app/policy.yaml"


@dataclass
class Decision:
    verdict: str          # approve | pending_approval | deny
    reason: str
    action: str = "none"
    target: str = ""
    duration_seconds: int = 0
    checks: list = field(default_factory=list)


def load_policy() -> dict:
    with open(POLICY_PATH, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _ip_in_ranges(ip: str, ranges: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(r) for r in ranges)


def evaluate(proposal: dict, attack_type: str, confidence: float,
             severity: str, source_ip: str, recent_same_target: int = 0) -> Decision:
    """Evaluate one AI proposal against the policy. Pure and deterministic."""
    policy = load_policy()
    allow = policy.get("allowlist", {})
    defaults = policy.get("defaults", {})
    checks: list[str] = []

    action = (proposal.get("action_type") or "none").strip()
    proposal_target = (proposal.get("target") or "").strip()
    try:
        ipaddress.ip_address(proposal_target)
        target = proposal_target          # the LLM proposed a well-formed IP
    except ValueError:
        target = source_ip                # fall back to the event's source IP
    if action == "temporary_ip_block" and not target:
        target = source_ip
    proposed_duration = int(proposal.get("duration_seconds") or 0)

    # 1. action must be an allowed verb
    if action not in (allow.get("actions") or []):
        return Decision("deny", f"action '{action}' not in policy allowlist",
                        checks=checks + [f"action={action}"])

    # 2. target: for IP blocks it must be the attacker IP
    if not target:
        return Decision("pending_approval", "no target IP could be determined",
                        action=action, checks=checks + ["target=missing"])

    # 3. protected ranges are NEVER auto-approved
    if _ip_in_ranges(target, policy.get("protected_ranges") or []):
        checks.append(f"target={target} is protected (L2: human approval)")
        return Decision(
            "pending_approval",
            f"target {target} is in a protected range — requires human approval",
            action=action, target=target, checks=checks,
        )
    checks.append(f"target={target} is external")

    # 4. attack type must be in the allowlist
    if attack_type not in (allow.get("attack_types") or []):
        checks.append(f"attack_type={attack_type} unknown to policy")
        return Decision("pending_approval",
                        f"attack type '{attack_type}' not in allowlist — human review",
                        action=action, target=target, checks=checks)
    checks.append(f"attack_type={attack_type} allowed")

    # 5. confidence + severity floors
    min_conf = float((allow.get("min_confidence") or 0.6))
    if confidence < min_conf:
        checks.append(f"confidence {confidence} < {min_conf}")
        return Decision("pending_approval",
                        f"confidence {confidence} below {min_conf} — human review",
                        action=action, target=target, checks=checks)
    if severity not in (allow.get("min_severities") or ["high", "medium"]):
        checks.append(f"severity={severity} below policy")
        return Decision("pending_approval",
                        f"severity '{severity}' below policy — human review",
                        action=action, target=target, checks=checks)
    checks.append(f"confidence={confidence} severity={severity} ok")

    # 6. duration clamp
    duration = proposed_duration or int(defaults.get("default_duration_seconds") or 900)
    max_dur = int(defaults.get("max_duration_seconds") or 3600)
    if duration > max_dur:
        duration = max_dur
        checks.append(f"duration clamped to {max_dur}s")

    return Decision(
        "approve",
        "policy allows automated response (L1) for this proposal",
        action=action, target=target, duration_seconds=duration, checks=checks,
    )
