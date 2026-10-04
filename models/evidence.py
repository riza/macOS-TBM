"""Evidence-weighted sink assessment.

A sink label ("this daemon touches the filesystem") is only as good as what it
rests on. Auditing real scans showed the difference is large and systematic:

* an ``unlink`` **import** is the binary calling the syscall,
* ``com.apple.rootless.volume.Preboot`` is an **entitlement** Apple granted it,
* an ``NSURLSession`` **ObjC class reference** is a used class,
* ``com.apple.MobileSoftwareUpdate.UpdateBrainService`` is an **identifier string**
  — intent, not a call,
* linking ``CFNetwork`` is a **library link** and means almost nothing on its own
  (and nothing at all when the link is weak),
* the word "mount" inside ``"Failed to apply quarantine info to mount point"`` is
  a **loose token** and is not evidence.

Each class carries a weight; the sum decides the confidence label, and the
evidence list travels with it so a reader can always see why.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Evidence kinds, strongest first.
IMPORT = "import"          # imported symbol: the binary calls this API
ENTITLEMENT = "entitlement"  # granted capability: authoritative, but not usage
OBJC = "objc"              # referenced Objective-C class
STRING = "string"          # identifier-like string: a name it knows
LIBRARY = "library"        # linked framework/dylib
WEAK_LIBRARY = "weak-library"
TOKEN = "token"            # a word inside a sentence or path: not evidence
CORRELATED = "correlated-static"  # multiple required static markers observed together

WEIGHTS: Dict[str, int] = {
    IMPORT: 8,
    ENTITLEMENT: 6,
    OBJC: 5,
    STRING: 3,
    LIBRARY: 1,
    WEAK_LIBRARY: 0,
    TOKEN: 0,
    CORRELATED: 8,
}

# At most this many items of one kind count towards the score, so a binary with
# forty keychain imports does not dwarf one with an entitlement plus two calls.
PER_KIND_CAP = 2

HIGH_THRESHOLD = 10
MEDIUM_THRESHOLD = 5


@dataclass
class Evidence:
    """One observation that supports a sink label."""

    kind: str
    needle: str          # the rule needle that fired
    match: str           # what it matched in the binary
    aspect: str = ""     # what the primitive means, e.g. "mount", "path-resolution"
    aspect_weight: Optional[int] = None

    @property
    def weight(self) -> int:
        """The weaker of *how well we saw it* and *how much it means*.

        ``stat`` is a real import (8) but says little on its own, so the
        path-resolution aspect caps it at 2. ``mount`` is a real import and
        means a lot, so it keeps 8. A weak link or loose token stays at 0 no
        matter what it matched.
        """
        base = WEIGHTS.get(self.kind, 0)
        if self.aspect_weight is None:
            return base
        return min(base, self.aspect_weight)

    def describe(self) -> str:
        aspect = f" [{self.aspect}]" if self.aspect else ""
        if self.kind in (LIBRARY, WEAK_LIBRARY, ENTITLEMENT):
            return f"{self.kind}: {self.match}{aspect}"
        if self.needle.rstrip("*") == self.match or self.kind == IMPORT:
            return f"{self.kind}: {self.match}{aspect}"
        return f"{self.kind}: {self.match} (matched {self.needle}){aspect}"

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "needle": self.needle, "match": self.match,
                "aspect": self.aspect, "weight": self.weight}


@dataclass
class SinkAssessment:
    """A sink label with its confidence and the evidence behind it."""

    sink: str                                   # rule key, e.g. "filesystem"
    label: str                                  # display label, e.g. "FILESYSTEM"
    evidence: List[Evidence] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Weighted evidence score, capped per evidence kind."""
        seen: Dict[str, int] = {}
        total = 0
        for ev in sorted(self.evidence, key=lambda e: -e.weight):
            n = seen.get(ev.kind, 0)
            if n >= PER_KIND_CAP:
                continue
            seen[ev.kind] = n + 1
            total += ev.weight
        return total

    @property
    def confidence(self) -> str:
        score = self.score
        if score >= HIGH_THRESHOLD:
            return "HIGH"
        if score >= MEDIUM_THRESHOLD:
            return "MEDIUM"
        return "LOW"

    @property
    def counts(self) -> bool:
        """Whether this assessment carries any weight at all.

        A sink supported only by loose tokens is dropped: it is the class of
        match that produced ``mount`` from a log message.
        """
        return self.score > 0

    @property
    def aspects(self) -> List[str]:
        """Which facets of the sink were observed, strongest first."""
        order: Dict[str, int] = {}
        for ev in self.evidence:
            if ev.aspect and ev.weight:
                order[ev.aspect] = max(order.get(ev.aspect, 0), ev.weight)
        return [a for a, _ in sorted(order.items(), key=lambda kv: -kv[1])]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sink": self.sink,
            "label": self.label,
            "score": self.score,
            "confidence": self.confidence,
            "aspects": self.aspects,
            "evidence": [e.to_dict() for e in self.evidence],
            "evidence_text": [e.describe() for e in self.evidence],
        }


# --- caller-validation strength -------------------------------------------
#
# Kept deliberately separate from the priority score. "Not observed" is a
# statement about the scanner, not about the service, so it must never push a
# target up or down the ranking - it is a second axis the analyst reads.

NONE_OBSERVED = "NONE_OBSERVED"
WEAK = "WEAK"
MEDIUM = "MEDIUM"
STRONG = "STRONG"

VALIDATION_ORDER = [NONE_OBSERVED, WEAK, MEDIUM, STRONG]

# Grades for the summed weight of the validation classes observed. Calibrated so
# that the canonical correct pattern - read the caller's audit token AND check
# something about it - is the only cheap route to STRONG.
VALIDATION_STRONG = 12
VALIDATION_MEDIUM = 5


@dataclass
class ValidationAssessment:
    """Caller-validation evidence, graded like a sink and never scored.

    Deliberately kept out of the priority score: "not observed" is a statement
    about the scanner, not about the service, so it must not move a target up or
    down the ranking. It is a second axis the analyst reads.
    """

    evidence: List[Evidence] = field(default_factory=list)
    missing: List[Dict[str, Any]] = field(default_factory=list)  # classes not observed

    @property
    def by_class(self) -> Dict[str, List[Evidence]]:
        out: Dict[str, List[Evidence]] = {}
        for ev in self.evidence:
            out.setdefault(ev.aspect or "other", []).append(ev)
        return out

    @property
    def score(self) -> int:
        """Each validation class counts once, at its own weight."""
        best: Dict[str, int] = {}
        for ev in self.evidence:
            key = ev.aspect or "other"
            best[key] = max(best.get(key, 0), ev.weight)
        return sum(best.values())

    @property
    def confidence(self) -> str:
        score = self.score
        if score >= VALIDATION_STRONG:
            return STRONG
        if score >= VALIDATION_MEDIUM:
            return MEDIUM
        if score:
            return WEAK
        return NONE_OBSERVED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confidence": self.confidence,
            "score": self.score,
            "classes": sorted({e.aspect for e in self.evidence if e.aspect}),
            "evidence": [e.to_dict() for e in self.evidence],
            "evidence_text": [e.describe() for e in self.evidence],
            "not_observed": self.missing,
        }


def validation_strength(evidence: List[Evidence]) -> str:
    """Grade a list of validation evidence (thin wrapper for callers/tests)."""
    return ValidationAssessment(evidence=list(evidence)).confidence
