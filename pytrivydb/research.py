"""Research / advanced helpers, intentionally off the top-level
namespace.

Most users want :func:`pytrivydb.iter_advisories` and
:func:`pytrivydb.find_advisories`. The helpers here exist for OSS
researchers and CVE-DB tools.

- :func:`iter_vulnerability_meta` streams the aggregated
  ``vulnerability`` bucket (~121K rows on the real trivy-db).
- :func:`sources_for_package_type` introspects the package-type →
  source-bucket mapping.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

# Re-exported from the main module to avoid a circular import at
# top-level. The actual generator / lookup function bodies live in
# pytrivydb/__init__.py to keep CFFI plumbing in one place.
from pytrivydb import (
    Database,
)
from pytrivydb.models import Vulnerability


def iter_vulnerability_meta(
    db: Path | str | Database,
    *,
    batch_size: int = 1000,
) -> Iterator[Vulnerability]:
    """Iterate every entry in the aggregated ``vulnerability`` bucket
    (one row per CVE).

    Yields :class:`Vulnerability` instances. See module docstring for
    when to use this vs. ``iter_advisories``.
    """
    if isinstance(db, Database):
        yield from db.iter_vulnerability_meta(batch_size=batch_size)
    else:
        with Database(db) as opened:
            yield from opened.iter_vulnerability_meta(batch_size=batch_size)


def sources_for_package_type(
    db: Path | str | Database,
    package_type: str,
) -> list[str]:
    """Return the bucket names that ``package_type`` resolves to in
    ``db``. Always round-trips through Go (single source of truth for
    the mapping table).
    """
    if isinstance(db, Database):
        return db.sources_for_package_type(package_type)
    with Database(db) as opened:
        return opened.sources_for_package_type(package_type)
