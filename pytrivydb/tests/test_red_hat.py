"""Red Hat CPE resolution coverage — the trickiest part of v0.1.

Verifies the resolution paths AND the anti-criterion that we do NOT
read the debug `cpe` sub-bucket.
"""

from __future__ import annotations

from pathlib import Path

from pytrivydb import Database
from pytrivydb.redhat import DEFAULT_CONTENT_SETS


def test_no_repos_no_nvrs_returns_unfiltered_entries(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories("CVE-2021-3600", "glibc", sources=["Red Hat"])
    assert len(advs) == 1
    assert len(advs[0].extra["Entries"]) == 2


def test_default_content_sets_rhel8(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2021-3600",
            "glibc",
            sources=["Red Hat"],
            repositories=DEFAULT_CONTENT_SETS["8"],
        )
    entries = advs[0].extra["Entries"]
    assert len(entries) == 1
    # RHEL-8 entry has the fix.
    assert entries[0]["FixedVersion"] == "2.34-100.el8_10.2"
    assert entries[0]["Status"] == 3  # types.StatusFixed


def test_default_content_sets_rhel7(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2021-3600",
            "glibc",
            sources=["Red Hat"],
            repositories=DEFAULT_CONTENT_SETS["7"],
        )
    entries = advs[0].extra["Entries"]
    assert len(entries) == 1
    # RHEL-7 entry is will_not_fix (Status=5).
    assert entries[0]["Status"] == 5


def test_nvr_filter_resolves_rhel8(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2021-3600",
            "glibc",
            sources=["Red Hat"],
            nvrs=["glibc-2.34-100.el8_10.2-x86_64"],
        )
    entries = advs[0].extra["Entries"]
    assert len(entries) == 1
    assert entries[0]["Status"] == 3


def test_combined_repos_and_nvrs_unions(fixture_dir: Path) -> None:
    """Passing both repositories and nvrs unions the CPE indices."""
    with Database(fixture_dir) as db:
        advs = db.find_advisories(
            "CVE-2021-3600",
            "glibc",
            sources=["Red Hat"],
            repositories=DEFAULT_CONTENT_SETS["7"],  # CPE 0
            nvrs=["glibc-2.34-100.el8_10.2-x86_64"],  # CPE 1
        )
    entries = advs[0].extra["Entries"]
    assert len(entries) == 2  # union: both entries kept
