"""Decision Agent — deterministic policy evaluation of AI proposals.

Design (EdgeGuard principle): the Analysis Agent (LLM) PROPOSES an action;
this module DECIDES what is allowed. No LLM here on purpose — the gate must
be predictable, auditable and independent of model behaviour.

Verdicts:
  approve           — within allowlist, confidence/severity ok, clamped duration,
                      no recent enforced block for the same target (cooldown)
  pending_approval  — policy wants a human (protected range, low confidence,
                      unknown attack type, unsupported action, cooldown hit)
  deny              — action outside the allowlist entirely
"""

import ipaddress
import math
from dataclasses import dataclass, field
from pathlib import Path

import yaml

POLICY_PATH = Path(__file__).resolve().parents[1] / "policy.yaml"


@dataclass
class Decision:
    verdict: str  # approve | pending_approval | deny
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
    addr = getattr(addr, "ipv4_mapped", None) or addr
    return any(addr in ipaddress.ip_network(r) for r in ranges)


def resolve_target(proposal: dict, source_ip: str) -> str:
    """The IP a proposal would act on (well-formed IP, else the event source).

    Shared with the decider so the cooldown lookup and the policy verdict
    always agree on which target the action applies to.
    """
    # Enforcement must always refer to the observed source, never an IP
    # invented by a model or embedded in an attacker's log payload.
    candidate = str(source_ip or "").strip()
    try:
        ipaddress.ip_address(candidate)
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return ""


def evaluate(
    proposal: dict,
    attack_type: str,
    confidence: float,
    severity: str,
    source_ip: str,
    recent_same_target: int = 0,
    needs_human_review: bool = False,
    prompt_injection_suspected: bool = False,
) -> Decision:
    """Evaluate one AI proposal against the policy. Pure and deterministic."""
    policy = load_policy()
    allow = policy.get("allowlist", {})
    defaults = policy.get("defaults", {})
    checks: list[str] = []

    action = (proposal.get("action_type") or "none").strip()
    target = resolve_target(proposal, source_ip)
    proposed_duration = int(proposal.get("duration_seconds") or 0)

    # 1. action must be an allowed verb
    if action not in (allow.get("actions") or []):
        return Decision(
            "deny",
            f"action '{action}' not in policy allowlist",
            checks=checks + [f"action={action}"],
        )

    # 2. target: for IP blocks it must be the attacker IP
    if not target:
        return Decision(
            "pending_approval",
            "no target IP could be determined",
            action=action,
            checks=checks + ["target=missing"],
        )

    proposed_target = str(proposal.get("target") or "").strip()
    try:
        supplied_ip = ipaddress.ip_address(proposed_target)
    except ValueError:
        supplied_ip = None  # labels such as "source_ip" use the observed source
    if supplied_ip is not None and supplied_ip != ipaddress.ip_address(target):
        return Decision(
            "deny",
            "proposed target differs from the observed source IP",
            checks=checks + ["target mismatch"],
        )

    # 3. protected ranges are NEVER auto-approved (human approval required,
    #    but the proposed duration is still computed + clamped properly)
    duration = max(
        1, proposed_duration or int(defaults.get("default_duration_seconds") or 900)
    )
    max_dur = int(defaults.get("max_duration_seconds") or 3600)
    if duration > max_dur:
        duration = max_dur
        checks.append(f"duration clamped to {max_dur}s")
    if _ip_in_ranges(target, policy.get("protected_ranges") or []):
        checks.append(f"target={target} is protected (L2: human approval)")
        return Decision(
            "pending_approval",
            f"target {target} is in a protected range — requires human approval",
            action=action,
            target=target,
            duration_seconds=duration,
            checks=checks,
        )
    checks.append(f"target={target} is external")

    if needs_human_review or prompt_injection_suspected:
        return Decision(
            "pending_approval",
            "analysis requires human review or suspects prompt injection",
            action=action,
            target=target,
            duration_seconds=duration,
            checks=checks,
        )

    # 4. attack type must be in the allowlist
    if attack_type not in (allow.get("attack_types") or []):
        checks.append(f"attack_type={attack_type} unknown to policy")
        return Decision(
            "pending_approval",
            f"attack type '{attack_type}' not in allowlist — human review",
            action=action,
            target=target,
            duration_seconds=duration,
            checks=checks,
        )
    checks.append(f"attack_type={attack_type} allowed")

    # 5. confidence + severity floors
    min_conf = float(allow.get("min_confidence") or 0.6)
    if (
        not math.isfinite(confidence)
        or not 0 <= confidence <= 1
        or confidence < min_conf
    ):
        checks.append(f"confidence {confidence} < {min_conf}")
        return Decision(
            "pending_approval",
            f"confidence {confidence} below {min_conf} — human review",
            action=action,
            target=target,
            duration_seconds=duration,
            checks=checks,
        )
    if severity not in (allow.get("min_severities") or ["high", "medium"]):
        checks.append(f"severity={severity} below policy")
        return Decision(
            "pending_approval",
            f"severity '{severity}' below policy — human review",
            action=action,
            target=target,
            duration_seconds=duration,
            checks=checks,
        )
    checks.append(f"confidence={confidence} severity={severity} ok")

    # 7. cooldown: never auto-re-block a target that was enforced recently
    max_repeats = int(defaults.get("cooldown_max_repeats") or 1)
    if recent_same_target >= max_repeats:
        cooldown = int(defaults.get("cooldown_seconds") or 1800)
        checks.append(
            f"cooldown: {recent_same_target} enforced block(s) within {cooldown}s"
        )
        return Decision(
            "pending_approval",
            f"{target} was already blocked {recent_same_target} time(s) within "
            f"{cooldown}s — repeat block requires human review",
            action=action,
            target=target,
            duration_seconds=duration,
            checks=checks,
        )

    return Decision(
        "approve",
        "policy allows automated response (L1) for this proposal",
        action=action,
        target=target,
        duration_seconds=duration,
        checks=checks,
    )
