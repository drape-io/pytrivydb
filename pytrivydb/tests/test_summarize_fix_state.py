"""summarize_fix_state — opinionated reconciliation helper.

Covers the rule order (fix-found wins) and the conflict-surfacing
field that powers cross-validation use cases.
"""

from __future__ import annotations

from pytrivydb.helpers import FixState, FixSummary, summarize_fix_state
from pytrivydb.models import Advisory


def _adv(source: str, fixed: str = "", status: int | None = None) -> Advisory:
    return Advisory(
        source=source,
        package_name="pkg",
        cve_id="CVE-X",
        fixed_version=fixed,
        status_code=status,
    )


def test_empty_advisories_is_unknown() -> None:
    s = summarize_fix_state([])
    assert s == FixSummary()
    assert s.fix_state == FixState.UNKNOWN
    assert s.fix_versions == []


def test_single_fixed_yields_fixed() -> None:
    s = summarize_fix_state([_adv("debian 12", fixed="1.2.3")])
    assert s.fix_state == FixState.FIXED
    assert s.fix_versions == ["1.2.3"]
    assert s.conflicting_sources == []


def test_single_will_not_fix_yields_wont_fix() -> None:
    s = summarize_fix_state([_adv("Red Hat", status=5)])
    assert s.fix_state == FixState.WONT_FIX


def test_single_affected_yields_not_fixed() -> None:
    s = summarize_fix_state([_adv("debian 12", status=2)])
    assert s.fix_state == FixState.NOT_FIXED


def test_fix_found_wins_over_wont_fix() -> None:
    """The headline rule: Debian fixed beats Red Hat wont-fix.
    The Red Hat dissent shows up in conflicting_sources.
    """
    s = summarize_fix_state(
        [
            _adv("debian 12", fixed="1.2.3"),
            _adv("Red Hat", status=5),
        ]
    )
    assert s.fix_state == FixState.FIXED
    assert s.fix_versions == ["1.2.3"]
    assert ("Red Hat", FixState.WONT_FIX) in s.conflicting_sources


def test_explicit_status_fixed_is_actionable_fix() -> None:
    """Even without FixedVersion, Status=Fixed (3) signals fix-found."""
    s = summarize_fix_state([_adv("debian 12", status=3)])
    assert s.fix_state == FixState.FIXED


def test_fix_versions_dedup_across_sources() -> None:
    s = summarize_fix_state(
        [
            _adv("debian 12", fixed="1.2.3"),
            _adv("ubuntu 22.04", fixed="1.2.3"),  # same version
            _adv("alpine 3.19", fixed="1.2.4"),
        ]
    )
    assert s.fix_state == FixState.FIXED
    assert sorted(s.fix_versions) == ["1.2.3", "1.2.4"]


def test_all_unknown_reduces_to_unknown() -> None:
    s = summarize_fix_state([_adv("X"), _adv("Y")])
    assert s.fix_state == FixState.UNKNOWN
    # Unknown sources aren't "conflicting" — they're just missing data.
    assert s.conflicting_sources == []


def test_sources_consulted_lists_all() -> None:
    s = summarize_fix_state([_adv("debian 12", fixed="1.0"), _adv("ubuntu 22.04", status=5)])
    assert s.sources_consulted == ["debian 12", "ubuntu 22.04"]


def test_fix_state_constants_are_hyphenated() -> None:
    """Critical for Drape: matches InternalVulnerability.fix_state values."""
    assert FixState.FIXED == "fixed"
    assert FixState.NOT_FIXED == "not-fixed"
    assert FixState.WONT_FIX == "wont-fix"
    assert FixState.UNKNOWN == "unknown"
