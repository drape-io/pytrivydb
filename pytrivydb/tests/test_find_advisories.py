"""find_advisories — all kwarg combos."""

from __future__ import annotations

from pathlib import Path

from pytrivydb import Advisory, Database, find_advisories
from pytrivydb.redhat import DEFAULT_CONTENT_SETS


def test_find_by_package_type_deb(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-2005-2541", "tar", package_type="deb")
    assert len(advs) == 1
    assert advs[0].source == "debian 12"
    assert advs[0].fixed_version == "1.34+dfsg-1"
    assert advs[0].vendor_ids == ["DLA-3399-1"]


def test_find_by_package_type_rpm_returns_redhat(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-2021-3600", "glibc", package_type="rpm")
    sources = [a.source for a in advs]
    assert "Red Hat" in sources


def test_find_explicit_sources_overrides_package_type(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2005-2541",
            "tar",
            package_type="rpm",  # would route to rpm sources
            sources=["debian 12"],  # but explicit sources wins
        )
    assert len(advs) == 1
    assert advs[0].source == "debian 12"


def test_find_with_no_filters_searches_all_sources(fixture_dir: Path) -> None:
    """No package_type, no sources -> searches every non-reserved bucket."""
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-2005-2541", "tar")
    assert len(advs) == 1


def test_find_unknown_cve_returns_empty(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-DOES-NOT-EXIST", "tar", package_type="deb")
    assert advs == []


def test_find_unknown_package_type_falls_through(fixture_dir: Path) -> None:
    """Unknown package_type falls through to "all sources" rather than failing."""
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-2005-2541", "tar", package_type="totally-made-up")
    # Falls through → searches all → finds the debian advisory.
    assert len(advs) == 1


def test_find_redhat_no_filter_returns_raw_entries(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-2021-3600", "glibc", sources=["Red Hat"])
    assert len(advs) == 1
    adv = advs[0]
    # Raw Red Hat shape preserved in `extra`.
    entries = adv.extra.get("Entries")
    assert isinstance(entries, list)
    assert len(entries) == 2  # unfiltered: RHEL-7 + RHEL-8 entries


def test_find_redhat_filter_by_default_content_sets_rhel8(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2021-3600",
            "glibc",
            sources=["Red Hat"],
            repositories=DEFAULT_CONTENT_SETS["8"],
        )
    assert len(advs) == 1
    entries = advs[0].extra.get("Entries")
    assert len(entries) == 1
    assert entries[0].get("FixedVersion") == "2.34-100.el8_10.2"


def test_find_redhat_filter_by_nvr(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2021-3600",
            "glibc",
            sources=["Red Hat"],
            nvrs=["glibc-2.34-100.el8_10.2-x86_64"],
        )
    assert len(advs) == 1
    entries = advs[0].extra.get("Entries")
    assert len(entries) == 1


def test_find_redhat_filter_drops_all_when_no_match(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2021-3600",
            "glibc",
            sources=["Red Hat"],
            repositories=["rhel-99-nonexistent-repo"],
        )
    assert advs == []


def test_free_function_find_advisories(fixture_dir: Path) -> None:
    """The free-function variant opens + closes a Database per call."""
    advs = find_advisories(fixture_dir, "CVE-2005-2541", "tar", package_type="deb")
    assert len(advs) == 1


def test_advisory_model_decodes_status_string(fixture_dir: Path) -> None:
    """Advisory.status mirrors STATUS_NAMES[status_code]."""
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-2024-XXXX", "linux", package_type="deb")
    assert len(advs) == 1
    adv: Advisory = advs[0]
    assert adv.status_code == 5
    assert adv.status == "will_not_fix"
