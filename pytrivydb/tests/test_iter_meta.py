"""iter_vulnerability_meta — research submodule iterator."""

from __future__ import annotations

from pathlib import Path

from pytrivydb import Database
from pytrivydb.research import iter_vulnerability_meta


def test_iter_meta_yields_vulnerability_rows(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        rows = list(db.iter_vulnerability_meta(batch_size=10))
    assert len(rows) == 1
    v = rows[0]
    assert v.cve_id == "CVE-2021-3600"
    assert v.severity == "HIGH"
    assert "https://access.redhat.com/security/cve/CVE-2021-3600" in v.references


def test_iter_meta_vendor_severity_map_populated(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        rows = list(db.iter_vulnerability_meta())
    assert len(rows) == 1
    vs = rows[0].vendor_severity
    assert vs.get("nvd") == 3  # SeverityHigh
    assert vs.get("redhat") == 3


def test_iter_meta_cvss_map_populated(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        rows = list(db.iter_vulnerability_meta())
    nvd_cvss = rows[0].cvss.get("nvd")
    assert nvd_cvss is not None
    assert nvd_cvss.get("V3Score") == 7.8


def test_free_function_iter_meta(fixture_dir: Path) -> None:
    rows = list(iter_vulnerability_meta(fixture_dir))
    assert len(rows) == 1
