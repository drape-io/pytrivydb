"""CI-enforced anti-criteria from the plan.

These are grep-style invariants that block regression of decisions
made in plan §Anti-criteria. They run on the source tree, not the
runtime behavior — so they only need pytest to be invoked from the
repo root (the default).
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PY_PKG = REPO_ROOT / "pytrivydb"
GO_SRC = REPO_ROOT / "go-src"


def _read_go_sources(root: Path, include_tests: bool = False) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for path in root.rglob("*.go"):
        if not include_tests and path.name.endswith("_test.go"):
            continue
        out.append((path, path.read_text()))
    return out


def _read_py_sources(root: Path) -> list[tuple[Path, str]]:
    out: list[tuple[Path, str]] = []
    for path in root.rglob("*.py"):
        # Skip auto-generated CFFI module.
        if path.name == "_pytrivydb_cffi.py":
            continue
        out.append((path, path.read_text()))
    return out


def test_no_trivy_db_pkg_db_import() -> None:
    """Must NOT import trivy-db/pkg/db (forces single DB per process)."""
    forbidden = "github.com/aquasecurity/trivy-db/pkg/db"
    offenders = [path for path, text in _read_go_sources(GO_SRC) if forbidden in text]
    assert offenders == [], f"trivy-db/pkg/db imported in Go production code: {offenders}"


def test_no_march_native_in_python_build() -> None:
    """Must NOT use -march=native; that bakes CI-runner CPU features
    into the wheel and SIGILLs on older user machines.

    Comments are allowed (they document the rule). Look for the
    literal flag string outside of a Python line comment.
    """

    def _has_bad_flag(text: str) -> bool:
        for line in text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if '"-march=native"' in line or "'-march=native'" in line:
                return True
        return False

    offenders = []
    # Exclude this test file itself — it references the flag string
    # in its detector code, which would self-trigger.
    self_path = Path(__file__).resolve()
    for path, text in _read_py_sources(REPO_ROOT):
        if path.resolve() == self_path:
            continue
        if _has_bad_flag(text):
            offenders.append(path)
    setup_py = (REPO_ROOT / "setup.py").read_text()
    if _has_bad_flag(setup_py):
        offenders.append(REPO_ROOT / "setup.py")
    assert offenders == [], f"-march=native found in: {offenders}"


def test_no_debug_cpe_bucket_read_in_reader() -> None:
    """Must NOT read the `Red Hat CPE / cpe` debug sub-bucket from
    pkg/reader.
    """
    reader_dir = GO_SRC / "pkg" / "reader"
    offenders = []
    for path, text in _read_go_sources(reader_dir):
        if '"cpe"' in text or "Red Hat CPE/cpe" in text:
            offenders.append(path)
    assert offenders == [], f"reader source references debug cpe bucket: {offenders}"


def test_no_runtime_setfinalizer_in_go() -> None:
    """cgo.Handle is the correct handle primitive; runtime.SetFinalizer
    has known issues with CGO callbacks.
    """
    offenders = []
    for path, text in _read_go_sources(GO_SRC):
        if "runtime.SetFinalizer" in text:
            offenders.append(path)
    assert offenders == [], f"runtime.SetFinalizer used in: {offenders}"


def test_no_dunder_del_on_database() -> None:
    """Must NOT define __del__ on Database — unreliable at interpreter
    shutdown in 3.12+.
    """
    init = (PY_PKG / "__init__.py").read_text()
    assert "def __del__" not in init, "__del__ defined on Database"


def test_no_comma_joined_string_abi() -> None:
    """Must NOT pass slice args as comma-joined strings across CGO.
    The plan locks the **C.char + int pattern (tfparse-compat).
    """
    main = (GO_SRC / "cmd" / "pytrivydb" / "main.go").read_text()
    assert "strings.Split(" not in main, "comma-split smell in main.go — use **C.char + int instead"
