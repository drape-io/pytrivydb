"""Schema-version fail-fast on Database open."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from pytrivydb import Database, UnsupportedSchemaError, supported_schema_versions


def test_supported_versions_constant() -> None:
    assert supported_schema_versions == (2,)


def test_unsupported_schema_version_raises(tmp_path: Path) -> None:
    """A trivy-db with Version=99 in metadata.json is rejected."""
    # Use Go writer with a bogus version to produce a fixture.
    go_src = Path(__file__).parent.parent.parent / "go-src"
    subprocess.run(
        ["go", "run", "./cmd/build_synthetic", str(tmp_path)],
        cwd=go_src,
        check=True,
    )
    # Overwrite metadata.json with a non-supported version.
    md_path = tmp_path / "metadata.json"
    md = json.loads(md_path.read_text())
    md["Version"] = 99
    md_path.write_text(json.dumps(md))

    with pytest.raises(UnsupportedSchemaError) as exc:
        Database(tmp_path)
    assert "got 99" in str(exc.value)
    assert "pip install -U pytrivydb" in str(exc.value)
