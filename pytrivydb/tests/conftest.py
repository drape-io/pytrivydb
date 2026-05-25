"""Pytest config.

The session-scoped autouse fixture builds the synthetic test fixture
(``trivy.db`` + ``metadata.json``) on the first test run via
``go run ./pytrivydb/tests/build_synthetic <dir>`` invoked from the
``go-src/`` module root. Subsequent runs reuse the cache.
``just regen-fixture`` forces a rebuild.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_TESTS_DIR = Path(__file__).parent
_REPO_ROOT = _TESTS_DIR.parent.parent
_GO_SRC = _REPO_ROOT / "go-src"
_FIXTURE_DIR = _TESTS_DIR / "fixtures"
_DB_FILE = _FIXTURE_DIR / "trivy.db"
_METADATA_FILE = _FIXTURE_DIR / "metadata.json"


def _build_fixture(target_dir: Path) -> None:
    """Invoke the Go writer to populate `target_dir`."""
    target_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["go", "run", "./cmd/build_synthetic", str(target_dir)],
        cwd=_GO_SRC,
        check=True,
    )


@pytest.fixture(scope="session", autouse=True)
def _ensure_synthetic_fixture() -> Path:
    if not (_DB_FILE.exists() and _METADATA_FILE.exists()):
        _build_fixture(_FIXTURE_DIR)
    return _FIXTURE_DIR


@pytest.fixture()
def fixture_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Return a fresh copy of the synthetic fixture in a temp dir.

    Use this when the test mutates the on-disk fixture (e.g.
    schema-version downgrade); the cached session fixture stays
    intact.
    """
    out = tmp_path_factory.mktemp("trivydb")
    shutil.copy(_DB_FILE, out / "trivy.db")
    shutil.copy(_METADATA_FILE, out / "metadata.json")
    return out
