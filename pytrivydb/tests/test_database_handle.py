"""Database handle lifecycle + fd reuse + multi-DB + fork-safety."""

from __future__ import annotations

import gc
import multiprocessing
import os
import shutil
from pathlib import Path

import pytest

from pytrivydb import Database, TrivyDbError


def test_handle_reuse_across_many_calls(fixture_dir: Path) -> None:
    """One Database serves N calls — the JTBD for Drape's per-finding loop."""
    with Database(fixture_dir) as db:
        for _ in range(50):
            advs = db.find_advisories("CVE-2005-2541", "tar", package_type="deb")
            assert len(advs) == 1


def test_explicit_close_is_idempotent(fixture_dir: Path) -> None:
    db = Database(fixture_dir)
    db.close()
    db.close()  # double-close → no-op


def test_use_after_close_raises_clean_error(fixture_dir: Path) -> None:
    """Calling any query method after close() should raise a clear
    ``TrivyDbError("Database is closed")`` rather than a stale-handle
    error from the Go side.
    """
    db = Database(fixture_dir)
    db.close()

    with pytest.raises(TrivyDbError, match="Database is closed"):
        db.list_sources()
    with pytest.raises(TrivyDbError, match="Database is closed"):
        db.find_advisories("CVE-X", "tar", package_type="deb")
    with pytest.raises(TrivyDbError, match="Database is closed"):
        db.get_advisory(source="debian 12", package_name="tar", cve_id="CVE-X")
    with pytest.raises(TrivyDbError, match="Database is closed"):
        list(db.iter_advisories())


def test_context_manager_closes_on_exit(fixture_dir: Path) -> None:
    """After context exit, the handle is released."""
    with Database(fixture_dir) as db:
        sources = db.list_sources()
    assert len(sources) > 0


def test_weakref_finalize_closes_on_gc(fixture_dir: Path) -> None:
    """weakref.finalize backstops close() in case the consumer
    forgets to call it explicitly.
    """
    db = Database(fixture_dir)
    finalizer = db._finalizer
    assert finalizer.alive
    del db
    gc.collect()
    # After GC, finalizer should have fired (calls CloseDatabase).
    # We can't observe the Go side easily; assert the finalizer
    # is dead.
    assert not finalizer.alive


def test_multi_db_per_process(fixture_dir: Path, tmp_path_factory) -> None:
    """Open two Databases concurrently in one process — the
    architectural goal that motivated dropping trivy-db/pkg/db.
    """
    fixture2 = tmp_path_factory.mktemp("trivydb2")
    shutil.copy(fixture_dir / "trivy.db", fixture2 / "trivy.db")
    shutil.copy(fixture_dir / "metadata.json", fixture2 / "metadata.json")

    with Database(fixture_dir) as db1, Database(fixture2) as db2:
        srcs1 = sorted(db1.list_sources())
        srcs2 = sorted(db2.list_sources())
    assert srcs1 == srcs2
    assert len(srcs1) > 0


def _child_open(fixture_path: str) -> int:
    """Run inside a child process — open a fresh Database handle
    and count sources. Returns the count back to the parent.
    """
    with Database(Path(fixture_path)) as db:
        return len(db.list_sources())


def test_fork_safe_child_opens_own_handle(fixture_dir: Path) -> None:
    """Drape runs celery workers via fork on Linux. Each child should
    be able to open its own Database without inheriting state from
    the parent's bbolt mmap.
    """
    if os.name != "posix":
        return
    ctx = multiprocessing.get_context("fork")
    with ctx.Pool(1) as pool:
        count = pool.apply(_child_open, (str(fixture_dir),))
    assert count > 0
