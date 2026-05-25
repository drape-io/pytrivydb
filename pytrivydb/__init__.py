"""pytrivydb — Python reader for Aqua's trivy-db BoltDB schema.

This module exposes the core API. Opinionated / advanced helpers live
in submodules (intentionally NOT re-exported here):

- :mod:`pytrivydb.helpers` — :func:`~pytrivydb.helpers.summarize_fix_state`
- :mod:`pytrivydb.redhat` — :data:`~pytrivydb.redhat.DEFAULT_CONTENT_SETS`
- :mod:`pytrivydb.research` — :func:`~pytrivydb.research.iter_vulnerability_meta`,
  :func:`~pytrivydb.research.sources_for_package_type`

The submodule namespacing is a UX decision: top-level imports are
"core, opinion-free reader API"; submodules signal "opinion / advanced
/ one-of-many".
"""

from __future__ import annotations

import logging
import weakref
from collections.abc import Callable, Iterator
from pathlib import Path
from types import TracebackType

from pytrivydb._ffi import cstr, cstr_array, decode_response, last_error, lib
from pytrivydb.exceptions import (
    DatabaseCorruptError,
    DatabaseNotFoundError,
    TrivyDbError,
    UnsupportedSchemaError,
    from_go_error,
)
from pytrivydb.models import (
    SEVERITY_NAMES,
    STATUS_NAMES,
    Advisory,
    Vulnerability,
)

__version__ = "0.1.0.dev0"
supported_schema_versions: tuple[int, ...] = (2,)

__all__ = [
    "SEVERITY_NAMES",
    "STATUS_NAMES",
    "Advisory",
    "Database",
    "DatabaseCorruptError",
    "DatabaseNotFoundError",
    "TrivyDbError",
    "UnsupportedSchemaError",
    "Vulnerability",
    "__version__",
    "find_advisories",
    "get_advisory",
    "iter_advisories",
    "list_sources",
    "supported_schema_versions",
]

log = logging.getLogger("pytrivydb")


def _normalize_db_dir(p: Path | str) -> str:
    """Accept either a directory or a ``trivy.db`` file path and
    return the directory containing both ``trivy.db`` and
    ``metadata.json``.
    """
    pth = Path(p)
    if pth.is_file():
        return str(pth.parent)
    return str(pth)


def _drain_iter[Row](
    iter_handle: int,
    batch_size: int,
    from_row: Callable[[dict], Row],
) -> Iterator[Row]:
    """Generator wrapper for an iterator handle.

    Two cleanup paths are wired up by `_finalize_iter`:

    1. The ``try/finally`` here fires when the generator has *started*
       and is then GC'd, exhausted, exited via break/return, or
       interrupted by an exception. This is the common case.
    2. The caller registers ``weakref.finalize`` on the generator
       object so that even a generator that was *never started* (e.g.
       ``db.iter_advisories()`` whose return value is immediately
       dropped) still triggers ``IterClose`` when Python GCs it. The
       finally above never fires for an unstarted generator, so this
       backstop is load-bearing.

    Both paths can call ``IterClose`` on the same handle; the Go side
    is idempotent (`safeValue` recovers on already-deleted handles),
    so double-close is safe.
    """
    try:
        while True:
            batch = decode_response(lib.IterNext(iter_handle, batch_size))
            if not batch:
                return
            for row in batch:
                yield from_row(row)
    finally:
        lib.IterClose(iter_handle)


def _finalize_iter[Row](
    iter_handle: int,
    batch_size: int,
    from_row: Callable[[dict], Row],
) -> Iterator[Row]:
    """Return a `_drain_iter` generator with a `weakref.finalize`
    backstop attached so an unstarted-and-dropped generator still
    releases the underlying iterator handle. See `_drain_iter` for
    why this matters.
    """
    gen = _drain_iter(iter_handle, batch_size, from_row)
    weakref.finalize(gen, lib.IterClose, iter_handle)
    return gen


def _open_db_handle(db_dir: str) -> int:
    """Open a Go-side Database handle, raising the appropriate typed
    exception on failure.
    """
    handle = lib.OpenDatabase(cstr(db_dir))
    if handle == 0:
        msg = last_error()
        if msg is None:
            raise TrivyDbError("OpenDatabase failed with no error message")
        raise from_go_error(msg)
    log.debug("opened DB handle=%d dir=%s", handle, db_dir)
    return int(handle)


class Database:
    """Long-lived bbolt handle for high-frequency lookups.

    Use this for any code path that makes more than a handful of
    queries against the same trivy.db — particularly per-finding
    loops in vulnerability triage pipelines. Each :class:`Database`
    owns its own ``*bolt.DB``; you can open multiple ``Database``
    instances against different paths in the same process.

    Lifecycle: use as a context manager (``with Database(path) as db:``)
    or call :meth:`close` explicitly. A ``weakref.finalize`` backstop
    releases the handle on GC.
    """

    def __init__(self, db_path: Path | str) -> None:
        db_dir = _normalize_db_dir(db_path)
        self._handle = _open_db_handle(db_dir)
        self._finalizer = weakref.finalize(self, lib.CloseDatabase, self._handle)

    def __enter__(self) -> Database:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Release the bbolt handle. Idempotent."""
        if self._finalizer.alive:
            self._finalizer()
        # Zero the cached handle so a use-after-close surfaces as a
        # clean ``TrivyDbError("Database is closed")`` instead of a
        # "stale or invalid handle" error from the Go side.
        self._handle = 0

    def _require_open(self) -> int:
        if not self._handle:
            raise TrivyDbError("Database is closed")
        return self._handle

    # --- Queries ---

    def find_advisories(
        self,
        cve_id: str,
        package_name: str,
        *,
        package_type: str | None = None,
        sources: list[str] | None = None,
        repositories: list[str] | None = None,
        nvrs: list[str] | None = None,
    ) -> list[Advisory]:
        """Search relevant source buckets for matching advisories.

        Dispatch rules (priority order):

        1. If ``sources`` is given, use it as the search set.
        2. Else if ``package_type`` is given, expand via the internal
           mapping table against actually-present top-level buckets.
        3. Else, search every non-reserved top-level bucket (slower).

        Red Hat filtering: if ``repositories`` or ``nvrs`` is given,
        Red Hat advisories' ``Entries[]`` are filtered to those whose
        ``Affected`` CPE indices intersect the resolved set. If
        neither is given, raw ``Entries[]`` pass through.
        """
        # Hold both outer char*[] cdata AND inner char[] cdata across
        # the C call — see cstr_array() for the GC contract.
        srcs_cdata, n_srcs, _keep_srcs = cstr_array(sources or [])
        repos_cdata, n_repos, _keep_repos = cstr_array(repositories or [])
        nvrs_cdata, n_nvrs, _keep_nvrs = cstr_array(nvrs or [])
        resp = lib.FindAdvisories(
            self._require_open(),
            cstr(cve_id),
            cstr(package_name),
            cstr(package_type or ""),
            srcs_cdata,
            n_srcs,
            repos_cdata,
            n_repos,
            nvrs_cdata,
            n_nvrs,
        )
        rows = decode_response(resp) or []
        return [Advisory.from_row(r) for r in rows]

    def get_advisory(
        self,
        *,
        source: str,
        package_name: str,
        cve_id: str,
    ) -> Advisory | None:
        """Exact-match fetch for a known ``(source, package, cve)``.

        Keyword-only args after ``self`` to prevent argument-order
        bugs (4 positional strings is a footgun).
        """
        resp = lib.GetAdvisory(
            self._require_open(),
            cstr(source),
            cstr(package_name),
            cstr(cve_id),
        )
        row = decode_response(resp)
        if row is None:
            return None
        return Advisory.from_row(row)

    def iter_advisories(
        self,
        *,
        batch_size: int = 1000,
    ) -> Iterator[Advisory]:
        """Stream every ``(source, package, cve)`` advisory row.

        Holds a single read-only bbolt transaction for the iterator's
        lifetime. The dominant memory cost during iteration is the
        bbolt mmap of the trivy.db file itself; see the README's
        "Measured performance" section for empirical numbers.
        """
        iter_handle = lib.OpenAdvisoryIterator(self._require_open())
        if iter_handle == 0:
            raise TrivyDbError(last_error() or "OpenAdvisoryIterator failed")
        return _finalize_iter(iter_handle, batch_size, Advisory.from_row)

    def iter_vulnerability_meta(
        self,
        *,
        batch_size: int = 1000,
    ) -> Iterator[Vulnerability]:
        """Stream the aggregated ``vulnerability`` bucket."""
        iter_handle = lib.OpenMetaIterator(self._require_open())
        if iter_handle == 0:
            raise TrivyDbError(last_error() or "OpenMetaIterator failed")
        return _finalize_iter(iter_handle, batch_size, Vulnerability.from_row)

    def list_sources(self) -> list[str]:
        """Return non-reserved top-level bucket names."""
        resp = lib.ListSources(self._require_open())
        return list(decode_response(resp) or [])

    def sources_for_package_type(self, package_type: str) -> list[str]:
        """Expand a scanner ``package_type`` (e.g. ``"deb"``) to the
        list of source buckets that actually exist in this DB.

        Returns an empty list for unknown package types.
        """
        resp = lib.SourcesForPackageType(self._require_open(), cstr(package_type))
        return list(decode_response(resp) or [])


# --- Free-function entry points (open + close per call) ---


def find_advisories(
    db_path: Path | str | Database,
    cve_id: str,
    package_name: str,
    *,
    package_type: str | None = None,
    sources: list[str] | None = None,
    repositories: list[str] | None = None,
    nvrs: list[str] | None = None,
) -> list[Advisory]:
    """One-shot ``find_advisories``. Opens + closes a Database per call.

    For loops/services, use :class:`Database` directly to avoid
    fd churn (~500 calls/scan on macOS hits ``ulimit -n``).
    """
    if isinstance(db_path, Database):
        return db_path.find_advisories(
            cve_id,
            package_name,
            package_type=package_type,
            sources=sources,
            repositories=repositories,
            nvrs=nvrs,
        )
    with Database(db_path) as db:
        return db.find_advisories(
            cve_id,
            package_name,
            package_type=package_type,
            sources=sources,
            repositories=repositories,
            nvrs=nvrs,
        )


def get_advisory(
    db_path: Path | str | Database,
    *,
    source: str,
    package_name: str,
    cve_id: str,
) -> Advisory | None:
    """One-shot ``get_advisory``. See :func:`find_advisories` note."""
    if isinstance(db_path, Database):
        return db_path.get_advisory(source=source, package_name=package_name, cve_id=cve_id)
    with Database(db_path) as db:
        return db.get_advisory(source=source, package_name=package_name, cve_id=cve_id)


def iter_advisories(
    db_path: Path | str | Database,
    *,
    batch_size: int = 1000,
) -> Iterator[Advisory]:
    """One-shot streaming iterator. See :func:`find_advisories` note."""
    if isinstance(db_path, Database):
        yield from db_path.iter_advisories(batch_size=batch_size)
    else:
        with Database(db_path) as db:
            yield from db.iter_advisories(batch_size=batch_size)


def list_sources(db_path: Path | str | Database) -> list[str]:
    """One-shot list_sources."""
    if isinstance(db_path, Database):
        return db_path.list_sources()
    with Database(db_path) as db:
        return db.list_sources()
