"""Exception hierarchy for pytrivydb.

The Go layer reports errors as ``<kind>: <message>`` (see
go-src/cmd/pytrivydb/main.go ``errKind``). Python routes each kind to
a specific exception class so callers can distinguish operational
modes (e.g., schema mismatch vs file missing vs corruption).
"""

from __future__ import annotations


class TrivyDbError(Exception):
    """Base class for all pytrivydb errors."""


class UnsupportedSchemaError(TrivyDbError):
    """Raised when ``metadata.json`` reports a schema version this
    build of pytrivydb does not support.

    The message includes "Upgrade pytrivydb / downgrade trivy-db" and
    a pointer to the README compatibility matrix.
    """


class DatabaseNotFoundError(TrivyDbError):
    """Raised when ``trivy.db`` or ``metadata.json`` is absent at the
    given path."""


class DatabaseCorruptError(TrivyDbError):
    """Raised when bbolt fails to open the file or ``metadata.json``
    cannot be parsed.
    """


def from_go_error(payload: str) -> TrivyDbError:
    """Translate a Go-side error string of the form ``<kind>: <msg>``
    into the appropriate Python exception. Falls back to
    :class:`TrivyDbError` if the kind is unknown.
    """
    kind, _, message = payload.partition(": ")
    if kind == "unsupported_schema":
        return UnsupportedSchemaError(
            f"{message}. Upgrade pytrivydb (`pip install -U pytrivydb`) or "
            "downgrade your trivy-db artifact. See pytrivydb compatibility "
            "matrix in the README."
        )
    if kind == "not_found":
        return DatabaseNotFoundError(message)
    if kind == "corrupt":
        return DatabaseCorruptError(message)
    return TrivyDbError(payload)
