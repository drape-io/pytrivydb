"""Iterator cleanup — proves the bolt.Tx is released across the
generator try/finally + GC paths (anti-criterion: must NOT hold tx
past generator lifetime).
"""

from __future__ import annotations

import gc
import threading
from pathlib import Path

from pytrivydb import Database


def test_iterator_close_on_natural_exhaustion(fixture_dir: Path) -> None:
    """Generator exhausted via list() — Close runs in finally."""
    with Database(fixture_dir) as db:
        rows = list(db.iter_advisories())
    assert len(rows) == 6


def test_iterator_close_on_break(fixture_dir: Path) -> None:
    """Generator interrupted by break — Close runs in finally."""
    with Database(fixture_dir) as db:
        for _ in db.iter_advisories():
            break  # try/finally fires on generator GC after for-loop scope


def test_iterator_close_on_gc_after_partial_consumption(fixture_dir: Path) -> None:
    """A partially-consumed generator that gets GC'd should fire its
    try/finally and close the underlying tx.

    Concrete check: after dropping a partially-consumed generator and
    GC-collecting, ``Database.close()`` must return promptly. If the
    iterator tx leaked, ``bolt.DB.Close`` would block waiting on it.
    """
    db = Database(fixture_dir)
    it = db.iter_advisories()
    next(it)  # start the generator so its frame exists
    del it
    gc.collect()

    # If the iterator tx leaked, db.close() blocks on it. Bound the
    # close call with a thread + join-timeout to assert prompt return.
    done = threading.Event()

    def closer() -> None:
        db.close()
        done.set()

    t = threading.Thread(target=closer, daemon=True)
    t.start()
    t.join(timeout=3.0)
    assert done.is_set(), "Database.close() blocked — iterator tx likely leaked"


def test_iterator_close_on_unstarted_generator_gc(fixture_dir: Path) -> None:
    """A generator that is created but never iterated should still
    release its handle when GC'd, via the weakref.finalize backstop.

    Without the backstop, the generator's try/finally never fires
    (Python's GeneratorExit only triggers for *started* generators),
    so the iter handle would leak until ``Database.close()``.
    """
    db = Database(fixture_dir)
    it = db.iter_advisories()
    del it  # never called next()
    gc.collect()

    # Database.close() must return promptly — if the unstarted
    # iterator's tx leaked, it would block on bolt.DB.Close.
    done = threading.Event()

    def closer() -> None:
        db.close()
        done.set()

    t = threading.Thread(target=closer, daemon=True)
    t.start()
    t.join(timeout=3.0)
    assert done.is_set(), "Database.close() blocked — unstarted iterator leaked"


def test_iterator_close_on_exception(fixture_dir: Path) -> None:
    """An exception in the consumer should still close the iterator."""

    class Sentinel(Exception):
        pass

    with Database(fixture_dir) as db:
        try:
            for adv in db.iter_advisories():
                if adv.source == "Red Hat":
                    raise Sentinel
        except Sentinel:
            pass
        # If tx leaked, the next call would block; assert it doesn't.
        sources = db.list_sources()
        assert len(sources) > 0
