"""Opinionated reconciliation helpers for advisory lists.

This module is intentionally **not** re-exported at the top level —
that signals "opinion / one of many" rather than "core API."
Consumers who disagree with the reconciliation rules below should
write their own; the rules here are documented and stable, but they
are not the truth, just a sensible default.

The primary helper is :func:`summarize_fix_state`, which collapses a
list of :class:`Advisory` objects (typically returned by
``find_advisories`` for a single (CVE, package) pair across multiple
trivy-db sources) into a single ``FixSummary`` reflecting whether the
finding is fixed, will-not-fix, etc.

The rule order is **fix-found wins**:

1. Any source with an actionable fix (explicit ``Status=fixed`` OR
   non-empty ``FixedVersion``) → ``"fixed"``. Other sources reporting
   conflicting states (e.g. ``will_not_fix``) are surfaced in
   ``conflicting_sources`` so the consumer doesn't lose the
   disagreement signal.
2. Else if any source explicitly says ``will_not_fix`` → ``"wont-fix"``.
3. Else if any source has ``affected`` or ``fix_deferred`` → ``"not-fixed"``.
4. Else → ``"unknown"``.

State strings use hyphens to match Drape's existing
``InternalVulnerability.fix_state`` shape, so cross-validation
integrations don't need a mapping dict.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pytrivydb.models import Advisory


# Hyphenated string constants for typed use. Match Drape's
# InternalVulnerability.fix_state values.
class FixState:
    FIXED = "fixed"
    NOT_FIXED = "not-fixed"
    WONT_FIX = "wont-fix"
    UNKNOWN = "unknown"


_STATUS_FIXED = 3  # types.StatusFixed
_STATUS_AFFECTED = 2  # types.StatusAffected
_STATUS_WILL_NOT_FIX = 5  # types.StatusWillNotFix
_STATUS_FIX_DEFERRED = 6  # types.StatusFixDeferred


@dataclass
class FixSummary:
    """One opinionated verdict over a list of advisories.

    Attributes:
        fix_state: One of ``"fixed"``, ``"not-fixed"``, ``"wont-fix"``,
            ``"unknown"``. Hyphenated to match Drape's existing
            ``fix_state`` shape.
        fix_versions: Union of ``FixedVersion`` across all sources
            that reported a fix.
        sources_consulted: List of source bucket names that contributed
            advisories to this summary.
        conflicting_sources: Pairs of ``(source, reported_state)`` for
            sources whose state differs from the winning verdict.
            Empty when all consulted sources agree (or when nothing
            was consulted).
    """

    fix_state: str = FixState.UNKNOWN
    fix_versions: list[str] = field(default_factory=list)
    sources_consulted: list[str] = field(default_factory=list)
    conflicting_sources: list[tuple[str, str]] = field(default_factory=list)


def _advisory_signals_fix(adv: Advisory) -> bool:
    if adv.status_code == _STATUS_FIXED:
        return True
    return bool(adv.fixed_version)


def _advisory_state(adv: Advisory) -> str:
    """Return the per-source verdict in the same hyphenated namespace."""
    if _advisory_signals_fix(adv):
        return FixState.FIXED
    if adv.status_code == _STATUS_WILL_NOT_FIX:
        return FixState.WONT_FIX
    if adv.status_code in (_STATUS_AFFECTED, _STATUS_FIX_DEFERRED):
        return FixState.NOT_FIXED
    return FixState.UNKNOWN


def summarize_fix_state(advisories: list[Advisory]) -> FixSummary:
    """Collapse a list of per-source advisories into a single verdict.

    See the module docstring for the rule order. The returned summary
    always lists every source seen in :attr:`FixSummary.sources_consulted`
    and reports disagreements in :attr:`FixSummary.conflicting_sources`.
    """
    if not advisories:
        return FixSummary()

    sources_consulted = [a.source for a in advisories]
    per_source: list[tuple[str, str]] = [(a.source, _advisory_state(a)) for a in advisories]
    fix_versions: list[str] = []

    if any(state == FixState.FIXED for _, state in per_source):
        verdict = FixState.FIXED
        for adv in advisories:
            if (
                _advisory_signals_fix(adv)
                and adv.fixed_version
                and adv.fixed_version not in fix_versions
            ):
                fix_versions.append(adv.fixed_version)
    elif any(state == FixState.WONT_FIX for _, state in per_source):
        verdict = FixState.WONT_FIX
    elif any(state == FixState.NOT_FIXED for _, state in per_source):
        verdict = FixState.NOT_FIXED
    else:
        verdict = FixState.UNKNOWN

    conflicting = [
        (src, state) for src, state in per_source if state not in (verdict, FixState.UNKNOWN)
    ]
    return FixSummary(
        fix_state=verdict,
        fix_versions=fix_versions,
        sources_consulted=sources_consulted,
        conflicting_sources=conflicting,
    )
