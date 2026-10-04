"""Explainable research-priority scoring engine.

Weights are loaded from ``rules/scoring.json`` and applied by rule id. Every
contribution is recorded as a :class:`ScoreReason` so the final score is fully
explainable. The engine surfaces *attack-surface* — it never concludes safety
or vulnerability. Caller-validation indicators *reduce* triage priority only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from models.finding import ScoreReason
from utils.rules import scoring_rules

# How much of a sink rule's weight a confidence level is worth. A label resting
# on a single framework link must not score like one backed by an entitlement
# plus two imports.
CONFIDENCE_FACTOR = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}

# Rule ids that are additive.
_ADDITIVE_RULES = [
    "privileged_service",
    "exposes_ipc",
    "private_entitlement",
    "auth_security_api",
    "account_credential",
    "filesystem_mutation",
    "installer_update",
    "network",
    "tcc_privacy",
]


@dataclass
class ScoreResult:
    score: int = 0
    reasons: List[ScoreReason] = field(default_factory=list)


class ScoringEngine:
    """Applies configurable scoring rules to a target's analyses."""

    def __init__(self, rules: dict | None = None) -> None:
        self._rules = rules or scoring_rules()
        self._by_id = {r["id"]: r for r in self._rules.get("rules", [])}
        self._cap = self._rules.get("caller_validation_cap", 4)

    def _weight(self, rule_id: str) -> int:
        return int(self._by_id.get(rule_id, {}).get("weight", 0))

    def _description(self, rule_id: str) -> str:
        return self._by_id.get(rule_id, {}).get("description", rule_id)

    def score(self, service, ipc_result, ent_result, signals_result) -> ScoreResult:
        result = ScoreResult()

        # privileged_service
        if service.is_privileged:
            result.reasons.append(ScoreReason(self._weight("privileged_service"), self._description("privileged_service")))

        # exposes_ipc
        exposes = service.exposes_ipc or (ipc_result.classification.endswith("provider")
                                          or ipc_result.classification == "xpc-mach-provider-and-client")
        if exposes:
            result.reasons.append(ScoreReason(self._weight("exposes_ipc"), self._description("exposes_ipc")))

        # private_entitlement
        if ent_result.high_value:
            result.reasons.append(
                ScoreReason(self._weight("private_entitlement"),
                            f"{self._description('private_entitlement')} ({', '.join(ent_result.high_value[:3])})")
            )

        by_sink = signals_result.by_sink()

        def contribution(rule_id: str, *sinks: str) -> None:
            """Add a sink rule's weight, scaled by the best supporting evidence."""
            present = [by_sink[s] for s in sinks if s in by_sink]
            if not present:
                return
            best = max(present, key=lambda a: a.score)
            factor = CONFIDENCE_FACTOR.get(best.confidence, 0.3)
            weight = int(round(self._weight(rule_id) * factor))
            if not weight:
                return
            detail = ", ".join(f"{a.label} {a.confidence}" for a in present)
            result.reasons.append(
                ScoreReason(weight, f"{self._description(rule_id)} [{detail}]")
            )

        contribution("auth_security_api", "credential", "security_policy")
        contribution("account_credential", "account", "credential")
        contribution("filesystem_mutation", "filesystem")
        contribution("installer_update", "install_update")
        contribution("network", "network")

        # tcc_privacy (evidence-weighted, or an entitlement category on its own)
        if "privacy" in by_sink:
            contribution("tcc_privacy", "privacy")
        elif any(cat == "tcc_privacy" for cat in ent_result.categorized.values()):
            result.reasons.append(
                ScoreReason(self._weight("tcc_privacy"),
                            f"{self._description('tcc_privacy')} [entitlement category]")
            )

        # disabled_service (negative): a job launchd will not load is not live
        # attack surface. It stays in the report because the state can change,
        # but it must not outrank a loadable service.
        if not getattr(service, "enabled", True):
            result.reasons.append(
                ScoreReason(self._weight("disabled_service"),
                            f"{self._description('disabled_service')}: {getattr(service, 'enabled_derivation', '')}")
            )

        # Caller validation is deliberately NOT scored. "Not observed" is a
        # statement about the scanner, not about the service, so rewarding its
        # absence with a higher rank made undetected validation look like missing
        # validation. It is reported as its own axis instead
        # (Target.validation: NONE_OBSERVED / WEAK / MEDIUM / STRONG).

        result.score = sum(r.weight for r in result.reasons)
        return result
