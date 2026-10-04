"""Entitlement categorization and sensitivity scoring (rule-driven).

Rules live in ``rules/entitlements.json`` so new entitlement categories can be
added without touching code. Each entitlement key is matched against ordered
prefix/contains/exact patterns and assigned a category + sensitivity weight.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from models.finding import FactLevel, Finding
from utils.rules import entitlements_rules


@dataclass
class EntitlementResult:
    categorized: Dict[str, str] = field(default_factory=dict)  # entitlement key -> category
    sensitivities: Dict[str, int] = field(default_factory=dict)  # entitlement key -> weight
    findings: List[Finding] = field(default_factory=list)

    @property
    def max_sensitivity(self) -> int:
        return max(self.sensitivities.values(), default=0)

    @property
    def high_value(self) -> List[str]:
        """Entitlement keys in high-value categories."""
        rules = entitlements_rules()
        high = set(rules["categories"].keys()) - {"security", "sandbox", "other"}
        return [k for k, c in self.categorized.items() if c in high]


def _match_rule(key: str, rule: dict) -> bool:
    mtype = rule.get("type", "prefix")
    match = rule.get("match", "")
    if mtype == "prefix":
        return key.startswith(match)
    if mtype == "contains":
        return match in key
    if mtype == "exact":
        return key == match
    return False


def categorize_key(key: str) -> tuple[str, int]:
    """Return (category, sensitivity) for a single entitlement key.

    When multiple rules match, the most specific (longest ``match`` string)
    wins, so e.g. ``com.apple.private.tcc.allow`` is classified as TCC privacy
    rather than the broader ``com.apple.private.*`` bucket.
    """
    rules = entitlements_rules()
    categories = rules.get("categories", {})
    best = None  # (match length, category, sensitivity)
    for rule in rules.get("rules", []):
        if _match_rule(key, rule):
            cat = rule.get("category", "other")
            sens = categories.get(cat, {}).get("sensitivity", 1)
            length = len(rule.get("match", ""))
            if best is None or length > best[0]:
                best = (length, cat, sens)
    if best is not None:
        return best[1], best[2]
    return "other", categories.get("other", {}).get("sensitivity", 1)


def analyze_entitlements(entitlements: Dict) -> EntitlementResult:
    """Categorize and score an entitlements dictionary."""
    result = EntitlementResult()
    if not entitlements:
        return result

    for key in entitlements:
        cat, sens = categorize_key(key)
        result.categorized[key] = cat
        result.sensitivities[key] = sens

    # Flag interesting entitlements explicitly.
    flagged = [k for k, c in result.categorized.items() if c not in ("other", "security", "sandbox")]
    for key in flagged:
        result.findings.append(
            Finding(
                category="entitlement",
                level=FactLevel.FACT,
                message=f"entitlement '{key}' -> category '{result.categorized[key]}'",
                evidence=f"value={entitlements[key]!r}",
            )
        )
    return result
