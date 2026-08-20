"""Static security-signal detection with weighted evidence.

Detects *static indicators* of caller validation (SecTask*, audit_token_*,
xpc_connection_get_audit_token, Authorization*) and of sensitive-subsystem
interaction (OpenDirectory, keychain, TCC, installer, networking, filesystem
mutation, process execution).

Every sink label is returned as a :class:`SinkAssessment`: the evidence that
produced it, weighted by *kind*, with a confidence label. An import is the
binary calling an API; an entitlement is a capability Apple granted it; a
library link is nearly nothing. Auditing real scans showed that 9% of sink
claims rested on a framework link alone, while 60% of entitlement-implied sinks
were never reported at all — the weighting fixes both directions.

Terminology discipline: we report "caller-validation signal detected" or "not
observed statically" — never "authorization is missing".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from models.evidence import (
    ENTITLEMENT,
    IMPORT,
    LIBRARY,
    OBJC,
    STRING,
    TOKEN,
    WEAK_LIBRARY,
    Evidence,
    SinkAssessment,
    ValidationAssessment,
)
from models.finding import FactLevel, Finding
from utils.rules import signals_rules

from ._match import library_names, match_details, string_match_quality
from .sinks import SINK_LABELS


@dataclass
class SignalsResult:
    caller_validation: List[str] = field(default_factory=list)
    validation_assessment: ValidationAssessment = field(default_factory=ValidationAssessment)
    assessments: List[SinkAssessment] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    checked_entitlements: List[str] = field(default_factory=list)

    @property
    def validation(self) -> str:
        return self.validation_assessment.confidence

    @property
    def validation_evidence(self) -> List[Evidence]:
        return self.validation_assessment.evidence

    @property
    def has_caller_validation(self) -> bool:
        return bool(self.caller_validation)

    @property
    def sensitive(self) -> Dict[str, List[str]]:
        """Backwards-compatible view: sink key -> matched needles."""
        return {a.sink: [e.needle for e in a.evidence] for a in self.assessments}

    @property
    def sensitive_categories(self) -> List[str]:
        return sorted(a.sink for a in self.assessments)

    def by_sink(self) -> Dict[str, SinkAssessment]:
        return {a.sink: a for a in self.assessments}


def _pools(macho, codesign):
    """Return the evidence pools, kept apart so each can be weighted correctly."""
    imports = list(macho.imported_symbols) if macho else []
    objc = list(macho.objc_classes) if macho else []
    strings = list(macho.interesting_strings) if macho else []
    libs = list(macho.linked_libs) if macho else []
    weak = set(macho.weak_linked_libs) if macho else set()
    ents = list((codesign.entitlements or {}).keys()) if codesign else []
    return imports, objc, strings, libs, weak, ents


def _entitlement_hits(entitlements: List[str], patterns: List[str]) -> List[Evidence]:
    """Entitlements are matched by prefix — the key namespace *is* the meaning."""
    out: List[Evidence] = []
    for pattern in patterns:
        for key in entitlements:
            if key == pattern or key.startswith(pattern):
                out.append(Evidence(ENTITLEMENT, pattern, key))
                break
    return out


def _needle_hits(needles, imports, objc, strings, aspect="", aspect_weight=None) -> List[Evidence]:
    """Match one needle set against the symbol/ObjC/string pools, in that order."""
    evidence: List[Evidence] = []
    needles = list(dict.fromkeys(needles))
    for needle, hit in match_details(imports, needles, anchored=True):
        evidence.append(Evidence(IMPORT, needle, hit, aspect, aspect_weight))
    seen = {e.match for e in evidence}
    for needle, hit in match_details(objc, needles, anchored=True):
        if hit not in seen:
            evidence.append(Evidence(OBJC, needle, hit, aspect, aspect_weight))
    matched = {e.needle for e in evidence}
    for needle, hit in match_details(strings, needles):
        if needle in matched:
            continue  # already established by a stronger pool
        quality = string_match_quality(needle, hit)
        kind = STRING if quality == "identifier" else TOKEN
        evidence.append(Evidence(kind, needle, hit, aspect, aspect_weight))
    return evidence


def _collect_evidence(cfg, imports, objc, strings, libs, weak, ents) -> List[Evidence]:
    """Gather every observation supporting one sink, tagged by kind and aspect."""
    evidence: List[Evidence] = []

    evidence += _entitlement_hits(ents, cfg.get("entitlements", []))

    names = library_names(libs)
    weak_names = set(library_names(weak))
    for needle, hit in match_details(names, cfg.get("libs", []), anchored=True):
        kind = WEAK_LIBRARY if hit in weak_names else LIBRARY
        evidence.append(Evidence(kind, needle, hit))

    # Aspects group primitives by what they mean: a 'mount' import is worth more
    # than a 'stat' import even though both are imports.
    for aspect, acfg in (cfg.get("aspects") or {}).items():
        evidence += _needle_hits(
            list(acfg.get("symbols", [])) + list(acfg.get("strings", [])),
            imports, objc, strings, aspect, acfg.get("weight"),
        )

    evidence += _needle_hits(
        list(cfg.get("symbols", [])) + list(cfg.get("strings", [])), imports, objc, strings)

    # One observation per (kind, match): two needles hitting the same symbol is
    # one piece of evidence, not two.
    seen_pairs = set()
    unique: List[Evidence] = []
    for ev in evidence:
        key = (ev.kind, ev.match)
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        unique.append(ev)
    return unique


def detect_checked_entitlements(macho, codesign) -> tuple[List[str], List[Evidence]]:
    """Entitlement keys a binary appears to CHECK on its clients (server-side).

    This is the held-vs-checked distinction: ``codesign.entitlements`` are the
    capabilities Apple granted *this* binary; ``checked_entitlements`` are the
    keys it queries on *other* processes. A binary that calls
    ``valueForEntitlement:`` / ``SecTaskCopyValueForEntitlement`` /
    ``xpc_connection_copy_entitlement_value`` on a connection is checking its
    clients, and the ``com.apple.*`` keys sitting in its string table that it
    does not itself hold are the candidate keys it checks — the
    ``com.apple.<name>.spi`` pattern Apple uses for server-side client gating.

    Returns ``(checked_keys, checker_evidence)``. Without a checker marker we
    return no keys: a ``com.apple.*`` string by itself is a name the binary
    knows, not an entitlement it checks.
    """
    rules = signals_rules()
    cfg = rules.get("server_entitlement_check", {})
    imports, objc, strings, _libs, _weak, ents = _pools(macho, codesign)

    checker_evidence = _needle_hits(
        list(cfg.get("symbols", [])) + list(cfg.get("strings", [])),
        imports, objc, strings,
    )
    if not checker_evidence:
        return [], []

    held = set(ents)
    keys: List[str] = []
    for s in strings:
        if s.startswith("com.apple.") and s not in held and s not in keys:
            keys.append(s)
    # Entitlement keys are lowercase, namespaced identifiers (>=3 dots:
    # com.apple.<name>.<key>). A bare service name (com.apple.fairplay), an
    # NSError domain (com.apple.MobileActivation.ErrorDomain) or a notification
    # name is not an entitlement; dropping those keeps the candidate set from
    # being mostly noise. These are candidates regardless — deputies() refines
    # them against what clients actually hold.
    keys = [k for k in keys if k.islower() and k.count(".") >= 3]
    return sorted(keys), checker_evidence


def detect_signals(service, macho, codesign) -> SignalsResult:
    """Detect security signals for a service/executable."""
    rules = signals_rules()
    result = SignalsResult()
    imports, objc, strings, libs, weak, ents = _pools(macho, codesign)

    # --- caller validation ------------------------------------------------
    # Graded exactly like a sink: which identity primitives were observed, what
    # each proves, and which ones were looked for and not found.
    cv = rules.get("caller_validation", {})
    cv_evidence: List[Evidence] = []
    missing: List[Dict[str, str]] = []
    for name, ccfg in (cv.get("classes") or {}).items():
        hits = [e for e in _needle_hits(
            list(ccfg.get("symbols", [])) + list(ccfg.get("strings", [])),
            imports, objc, strings, name, ccfg.get("weight"),
        ) if e.weight]
        if hits:
            cv_evidence += hits
        else:
            missing.append({"class": name, "weight": ccfg.get("weight", 0),
                            "description": ccfg.get("description", ""),
                            "looked_for": ", ".join(list(ccfg.get("symbols", []))[:4])})

    assessment = ValidationAssessment(evidence=cv_evidence, missing=missing)
    result.validation_assessment = assessment
    result.caller_validation = sorted({e.needle for e in cv_evidence})

    if cv_evidence:
        result.findings.append(
            Finding(
                category="caller_validation",
                level=FactLevel.FACT,
                message=(f"caller-validation evidence: {assessment.confidence} "
                         f"(score {assessment.score}; {', '.join(sorted(assessment.by_class))})"),
                evidence=", ".join(e.describe() for e in cv_evidence[:10]),
            )
        )
    else:
        result.findings.append(
            Finding(
                category="caller_validation",
                level=FactLevel.UNKNOWN,
                message="caller-validation signal not observed statically; manual review recommended",
                evidence="no matching symbols/strings found (may be hidden by helpers or dynamic dispatch)",
            )
        )

    # --- sensitive subsystems --------------------------------------------
    for sink, cfg in rules.get("sensitive", {}).items():
        evidence = _collect_evidence(cfg, imports, objc, strings, libs, weak, ents)
        if not evidence:
            continue
        assessment = SinkAssessment(sink=sink, label=SINK_LABELS.get(sink, sink.upper()), evidence=evidence)
        if not assessment.counts:
            # Only loose tokens / weak links: report the near-miss, do not label.
            result.findings.append(
                Finding(
                    category="sensitive_api",
                    level=FactLevel.UNKNOWN,
                    message=f"'{sink}' indicators too weak to label",
                    evidence=", ".join(e.describe() for e in evidence[:5]),
                )
            )
            continue
        result.assessments.append(assessment)
        result.findings.append(
            Finding(
                category="sensitive_api",
                level=FactLevel.HEURISTIC,
                message=(f"interacts with '{sink}' subsystem "
                         f"({assessment.confidence} confidence, score {assessment.score})"),
                evidence=", ".join(e.describe() for e in assessment.evidence[:10]),
            )
        )

    result.assessments.sort(key=lambda a: -a.score)

    # --- server-side entitlement checks -----------------------------------
    # Reported as a list of candidate checked keys, not scored. The crux is the
    # held-vs-checked distinction: keys the daemon queries on its clients are a
    # different set from the ones it itself holds.
    result.checked_entitlements, checker_evidence = detect_checked_entitlements(macho, codesign)
    if result.checked_entitlements:
        result.findings.append(
            Finding(
                category="server_entitlement_check",
                level=FactLevel.HEURISTIC,
                message=(f"appears to check client entitlement(s): "
                         f"{', '.join(result.checked_entitlements)}"),
                evidence=", ".join(e.describe() for e in checker_evidence[:8]),
            )
        )

    return result
