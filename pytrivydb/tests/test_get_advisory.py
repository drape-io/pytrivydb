"""get_advisory — exact-match lookup, keyword-only args."""

from __future__ import annotations

from pathlib import Path

import pytest

from pytrivydb import Database, get_advisory


def test_get_advisory_hit(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        adv = db.get_advisory(source="debian 12", package_name="tar", cve_id="CVE-2005-2541")
    assert adv is not None
    assert adv.source == "debian 12"
    assert adv.cve_id == "CVE-2005-2541"
    assert adv.fixed_version == "1.34+dfsg-1"


def test_get_advisory_miss(fixture_dir: Path) -> None:
    with Database(fixture_dir) as db:
        adv = db.get_advisory(source="debian 12", package_name="tar", cve_id="CVE-DOES-NOT-EXIST")
    assert adv is None


def test_get_advisory_keyword_only_args(fixture_dir: Path) -> None:
    """Positional args after `self`/`db` should raise TypeError."""
    with Database(fixture_dir) as db, pytest.raises(TypeError):
        db.get_advisory("debian 12", "tar", "CVE-2005-2541")  # type: ignore[misc]


def test_free_function_get_advisory(fixture_dir: Path) -> None:
    adv = get_advisory(fixture_dir, source="debian 12", package_name="tar", cve_id="CVE-2005-2541")
    assert adv is not None
    assert adv.fixed_version == "1.34+dfsg-1"
