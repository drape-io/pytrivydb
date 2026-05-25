# pytrivydb

`pytrivydb` is a Python library for reading
[Aqua's trivy-db](https://github.com/aquasecurity/trivy-db) BoltDB
vulnerability database. **It is not a CLI scanner — if you want to
scan images, use [trivy](https://github.com/aquasecurity/trivy).**

## Glossary

`trivy-db` has two distinct data shapes. This library reflects both:

- **Advisory** — one source's verdict about one package and one CVE
  (e.g. *"Debian 12 says tar's CVE-2005-2541 is fixed in 1.34+dfsg-1"*).
  ~3.94M rows in the production DB.
- **Vulnerability** — the CVE-level aggregated record shared across
  sources (description, CVSS scores, references, per-source severity).
  ~121K rows.

Most consumers want advisories. See the [advanced section](#advanced)
for the vulnerability metadata iterator.

## Install

```bash
pip install pytrivydb
# or:
uv add pytrivydb
```

Wheels are published for Python 3.12 / 3.13 / 3.14 on Linux x86_64,
Linux aarch64, and macOS arm64. There is no source-build fallback by
default — file an issue if you need one.

## Quick start

You need a trivy-db artifact on disk. Either run `trivy image ...`
once (trivy auto-downloads to `~/Library/Caches/trivy/db/` or similar),
or pull it explicitly with [`oras`](https://oras.land/):

```bash
oras pull ghcr.io/aquasecurity/trivy-db:2
tar -xzf db.tar.gz
# You should now have ./trivy.db and ./metadata.json
```

Then in Python:

```python
from pathlib import Path
from pytrivydb import Database

with Database(Path("./")) as db:
    advisories = db.find_advisories(
        cve_id="CVE-2005-2541",
        package_name="tar",
        package_type="deb",
    )
    for adv in advisories:
        print(adv.source, adv.cve_id, adv.fixed_version, adv.status)
    # → debian 12 CVE-2005-2541 1.34+dfsg-1 fixed
```

`Database` holds a long-lived bbolt handle. Use it whenever you make
more than a handful of queries against the same DB.

## Cross-validating a scanner finding

The primary use case `pytrivydb` was designed for: a triage tool has
already parsed a SARIF/CycloneDX report and wants to verify or
override the scanner's `fix_state`.

```python
from pytrivydb import Database
from pytrivydb.helpers import summarize_fix_state

with Database("/path/to/trivydb") as db:
    for finding in scanner_findings:
        advisories = db.find_advisories(
            cve_id=finding.cve_id,
            package_name=finding.package_name,
            package_type=finding.package_type,  # "deb" / "rpm" / "npm" / ...
        )
        summary = summarize_fix_state(advisories)
        # summary.fix_state == "fixed" | "not-fixed" | "wont-fix" | "unknown"
        # summary.fix_versions == ["1.2.3", ...]
        # summary.conflicting_sources surfaces disagreement, e.g.
        #   [("Red Hat", "wont-fix")] when Debian says fixed but RHEL says wont-fix.

        if summary.fix_state != finding.fix_state:
            log.warning(
                "trivy-db disagrees with scanner: %s vs %s for %s on %s",
                summary.fix_state, finding.fix_state,
                finding.cve_id, finding.package_name,
            )
```

`fix_state` values are **hyphenated** (`"not-fixed"`, `"wont-fix"`) to
match common scanner output. Constants live in
`pytrivydb.helpers.FixState`.

## For one-off scripts

If you're making 1–2 calls (a debug script, a one-shot lookup), the
free-function form is fine — it opens and closes a `Database` per
call:

```python
from pytrivydb import find_advisories
advs = find_advisories("/path/to/trivydb", "CVE-2005-2541", "tar", package_type="deb")
```

For loops or services, **always use `Database`** to avoid
file-descriptor churn (~500 lookups/scan can exhaust the default
macOS `ulimit -n` of 256).

## Decision tree for `find_advisories` kwargs

```
Have CVE + package name? Start here:
  - Just CVE/package?                 → find_advisories(db, cve, pkg)
  - Know package_type from scanner?   → +package_type="rpm"
  - Have Red Hat content sets (SBOM)? → +repositories=[...]
  - Have Red Hat NVRs (SBOM)?         → +nvrs=[...]
  - Know exact source bucket(s)?      → +sources=["debian 12"]
```

Priority order: `sources=` wins over `package_type=` wins over
"search all buckets" (slow).

## Red Hat specifics

Red Hat advisories store a nested `Entries[]` shape — one entry per
combination of (RHEL version, fix state, fixed-version). To narrow
to a specific RHEL version, pass either repositories or NVRs:

```python
from pytrivydb.redhat import DEFAULT_CONTENT_SETS
advs = db.find_advisories(
    "CVE-2021-3600", "glibc",
    repositories=DEFAULT_CONTENT_SETS["8"],  # RHEL 8 defaults
)
```

`DEFAULT_CONTENT_SETS` mirrors trivy's hardcoded fallback table for
RHEL 6 / 7 / 8 / 9. If neither `repositories=` nor `nvrs=` is
passed, the full `Entries[]` array passes through unfiltered in
`Advisory.extra`.

**Caveat on `DEFAULT_CONTENT_SETS`**: trivy-db's Red Hat advisories
are issued against specific content set / channel CPE indices (e.g.
`rhel-8-for-x86_64-appstream-eus-rpms` for EUS, various 3scale /
satellite / OpenShift channels, etc.). The two channels in
`DEFAULT_CONTENT_SETS["8"]` (`baseos` + `appstream`) match a small
fraction of advisories in practice — empirically, most real RHEL-8
glibc CVEs (e.g. CVE-2023-4806, CVE-2024-2961) reference per-channel
CPEs that are NOT in the default set, so the filter drops them.

If you have the actual content sets from the scanned image's
`/etc/yum.repos.d/`, pass them via `repositories=`. If you have RPM
NVR strings, pass via `nvrs=`. For triage tools that have neither
(SARIF / CycloneDX scanner output typically), call `find_advisories`
without `repositories=`/`nvrs=` and inspect `Advisory.extra["Entries"]`
yourself — the filter is more restrictive than it is informative.

## Compatibility matrix

| pytrivydb | trivy-db schema | Python      |
|-----------|-----------------|-------------|
| 0.1.x     | 2               | 3.12 – 3.14 |

When trivy-db ships schema v3, we publish a new pytrivydb minor
release that supports both v2 and v3 behind the same fail-fast
guard. Mismatched versions raise `UnsupportedSchemaError` with an
actionable message.

## Exceptions

```python
from pytrivydb import (
    TrivyDbError,            # base class
    UnsupportedSchemaError,  # metadata.json Version != supported
    DatabaseNotFoundError,   # trivy.db or metadata.json missing
    DatabaseCorruptError,    # bbolt open failed; malformed metadata.json
)
```

## Measured performance

Numbers below were measured against the real
`ghcr.io/aquasecurity/trivy-db:2` artifact (3,944,672 rows, 1.1 GB
trivy.db) on **Apple M-series Mac, Python 3.12, May 2026**:

| Operation | Result |
|---|---|
| `list_sources()` | 184 sources, <15 ms |
| Full `iter_advisories()` cold cache | ~34 s, ~115K rows/s |
| Full `iter_advisories()` warm cache | ~26 s, ~150K rows/s |
| Max RSS during full iteration | ~770 MB (dominated by bbolt mmap of the 1.1 GB file) |
| `find_advisories` P50 / P95 / P99 | 0.12 ms / 0.36 ms / 0.84 ms |
| `get_advisory` P50 / P95 | 0.01 ms / 0.05 ms |

These are empirical measurements, not SLOs. Per-call latency is
dominated by source-bucket iteration; expect higher P95 on
`package_type=None` (searches every bucket). Use `just bench
/path/to/trivydb` to measure on your hardware.

Memory: `iter_advisories` holds one read-only bbolt transaction
plus a batch of ≤1000 rows. The bulk of RSS during iteration is the
mmapped bbolt file itself, which is OS-page-cache-backed and
reclaimable under pressure.

## Advanced

### Vulnerability metadata

For OSS researchers and CVE-DB tools — `iter_vulnerability_meta`
streams the aggregated `vulnerability` bucket (~121K rows). Most
users want `iter_advisories` instead.

```python
from pytrivydb.research import iter_vulnerability_meta
for v in iter_vulnerability_meta("/path/to/trivydb"):
    if v.severity == "CRITICAL":
        print(v.cve_id, v.cvss, v.vendor_severity)
```

### Multi-DB

You can open multiple `Database` instances against different
trivy.db files in the same process (e.g. to cross-validate
yesterday's DB vs today's):

```python
with Database("/cache/trivy-2026-05-24") as old, \
     Database("/cache/trivy-2026-05-25") as new:
    ...
```

This is **not** possible with trivy-db's own Go package
(`pkg/db` uses a global singleton). pytrivydb implements its own
bbolt reader specifically to support this pattern.

### Inspection helpers

```python
from pytrivydb import list_sources
sources = list_sources("/path/to/trivydb")  # all non-reserved top-level buckets

from pytrivydb.research import sources_for_package_type
sources_for_package_type(db, "rpm")  # which buckets resolve from package_type="rpm"
```

### `Advisory.extra`

Per-source raw passthrough. **Unstable** — don't depend on key
shapes; they vary per source and per trivy-db release. Use it for
inspection / Red Hat `Entries[]`, never for typed access.

## Non-goals

`pytrivydb` is **not**:

- A CLI scanner. Use trivy.
- A database mirror or pull tool. Use `oras` directly.
- A writer. The library is read-only.
- A CVE enrichment service. The aggregated `vulnerability` bucket
  is exposed but pytrivydb doesn't crawl external feeds.

## Stability

pytrivydb is pre-1.0. Until 1.0, **patch and minor releases may
include breaking API changes** (model shape, function signatures,
exception types, helper behavior). Pin exactly in production
(`pytrivydb==0.1.0`). The trivy-db schema version we support is
part of the API; see the compatibility matrix.

## Development

```bash
git clone https://github.com/drape-io/pytrivydb
cd pytrivydb
just install     # uv sync + editable install
just test        # Go tests + Python tests
just regen-fixture  # rebuild the synthetic test fixture
just bench /path/to/trivydb  # measure per-call latency
```

Requires Go 1.24+, Python 3.12+, [uv](https://docs.astral.sh/uv/),
[just](https://just.systems/).

## License

Apache-2.0.
