"""Exception hierarchy + actionable error messages."""

from __future__ import annotations

from pathlib import Path

import pytest

from pytrivydb import (
    Database,
    DatabaseCorruptError,
    DatabaseNotFoundError,
    TrivyDbError,
    UnsupportedSchemaError,
)


def test_exception_hierarchy() -> None:
    assert issubclass(UnsupportedSchemaError, TrivyDbError)
    assert issubclass(DatabaseNotFoundError, TrivyDbError)
    assert issubclass(DatabaseCorruptError, TrivyDbError)


def test_missing_directory_raises_not_found(tmp_path: Path) -> None:
    bogus = tmp_path / "does-not-exist"
    with pytest.raises(DatabaseNotFoundError):
        Database(bogus)


def test_missing_trivy_db_but_metadata_present_raises_not_found(tmp_path: Path) -> None:
    (tmp_path / "metadata.json").write_text('{"Version": 2}')
    with pytest.raises(DatabaseNotFoundError) as exc:
        Database(tmp_path)
    assert "trivy.db" in str(exc.value)


def test_malformed_metadata_json_raises_corrupt(tmp_path: Path) -> None:
    """Truncated / malformed metadata.json → DatabaseCorruptError."""
    (tmp_path / "metadata.json").write_text("{this is not json")
    (tmp_path / "trivy.db").write_bytes(b"")
    with pytest.raises(DatabaseCorruptError):
        Database(tmp_path)


def test_corrupt_bbolt_raises_corrupt(tmp_path: Path) -> None:
    """Random bytes in trivy.db → bbolt open fails → DatabaseCorruptError."""
    (tmp_path / "metadata.json").write_text('{"Version": 2}')
    (tmp_path / "trivy.db").write_bytes(b"not a bbolt file" * 100)
    with pytest.raises(DatabaseCorruptError):
        Database(tmp_path)
