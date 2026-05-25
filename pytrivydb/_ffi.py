"""CFFI loader + marshaling helpers for the Go-built shared library.

Loads the Go-compiled `.so`/`.dylib` adjacent to the package (named
``pytrivydb._pytrivydb<EXT_SUFFIX>``). Every Go-allocated buffer is
freed synchronously via ``lib.free`` after its contents have been
copied out — no ``ffi.gc`` finalizer chain, which is unreliable on
PyPy and adds no value when the buffer is read-and-dropped in the
same call frame.
"""

from __future__ import annotations

import json
import sysconfig
from pathlib import Path
from typing import Any

from pytrivydb._pytrivydb_cffi import ffi
from pytrivydb.exceptions import from_go_error

_LIB_PATH = Path(__file__).parent / f"_pytrivydb{sysconfig.get_config_var('EXT_SUFFIX')}"
lib = ffi.dlopen(str(_LIB_PATH))


def cstr(value: str) -> Any:
    """Encode a Python str as a CFFI char[]. Lifetime is the calling
    frame; the cdata must outlive the C call that uses it."""
    return ffi.new("char[]", value.encode("utf-8"))


def cstr_array(values: list[str]) -> tuple[Any, int, list[Any]]:
    """Encode a Python list[str] as ``(char**, int, keepalive_list)``.

    The C function being called needs every cdata in the returned
    structure to be alive for the duration of the call. The caller
    MUST hold a reference to the third tuple element (the per-string
    ``char[]`` cdata objects) — otherwise Python may GC them before
    the C call dereferences the pointers in the outer ``char*[]``
    array.
    """
    if not values:
        return ffi.NULL, 0, []
    cstrs = [cstr(v) for v in values]
    arr = ffi.new("char*[]", cstrs)
    return arr, len(values), cstrs


def decode_response(resp: Any) -> Any:
    """Decode a pytrivyResponse. Returns parsed JSON on success,
    raises a typed exception on error. Frees both pointers
    synchronously after extracting their contents.
    """
    if resp.err != ffi.NULL:
        err_bytes = ffi.string(resp.err)
        lib.free(resp.err)
        raise from_go_error(err_bytes.decode("utf-8"))
    if resp.json == ffi.NULL:
        return None
    json_bytes = ffi.string(resp.json)
    lib.free(resp.json)
    return json.loads(json_bytes)


def last_error() -> str | None:
    """Return the most recent Go-side error message, or None."""
    ptr = lib.LastError()
    if ptr == ffi.NULL:
        return None
    s = ffi.string(ptr).decode("utf-8")
    lib.free(ptr)
    return s
