"""iter_advisories — streaming iteration."""

from __future__ import annotations

from pathlib import Path

from pytrivydb import Database, iter_advisories


def test_iter_yields_all_rows(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        rows = list(db.iter_advisories(batch_size=2))
    keys = sorted((r.source, r.package_name, r.cve_id) for r in rows)
    assert keys == sorted(
        [
            ("Red Hat", "glibc", "CVE-2021-3600"),
            ("alpine 3.19", "openssl", "CVE-2023-YYYY"),
            ("debian 12", "linux", "CVE-2024-XXXX"),
            ("debian 12", "tar", "CVE-2005-2541"),
            ("ghsa::npm", "lodash", "CVE-2021-AAAA"),
            ("ubuntu 22.04", "bash", "CVE-2020-ZZZZ"),
        ]
    )


def test_iter_redhat_entries_preserved_in_extra(fixture_dir: Path) -> None:
    """Red Hat advisory rows surface the per-source `Entries[]` shape
    in `Advisory.extra` so consumers can inspect / reconcile.
    """
    with Database(fixture_dir) as db:
        for row in db.iter_advisories(batch_size=1000):
            if row.source == "Red Hat":
                entries = row.extra.get("Entries")
                assert isinstance(entries, list)
                assert len(entries) == 2
                return
    raise AssertionError("Red Hat row not found")


def test_iter_default_batch_size(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        rows = list(db.iter_advisories())  # default batch_size=1000
    assert len(rows) == 6


def test_iter_batch_size_one(fixture_dir: Path) -> None:
    """Smallest batch — exercises the per-call FFI boundary."""
    with Database(fixture_dir) as db:
        rows = list(db.iter_advisories(batch_size=1))
    assert len(rows) == 6


def test_free_function_iter_advisories(fixture_dir: Path) -> None:
    rows = list(iter_advisories(fixture_dir))
    assert len(rows) == 6
