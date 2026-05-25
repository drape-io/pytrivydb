"""Red Hat-specific helpers.

`DEFAULT_CONTENT_SETS` mirrors trivy's hardcoded fallback table at
`pkg/detector/ospkg/redhat/redhat.go:26-43`. Consumers who only know a
RHEL major version can use this to populate the `repositories=` kwarg
of `find_advisories` (or `Database.find_advisories`):

    from pytrivydb.redhat import DEFAULT_CONTENT_SETS
    advisories = db.find_advisories(
        cve, pkg, repositories=DEFAULT_CONTENT_SETS["8"],
    )

The table is pinned per-pytrivydb-release; it may lag upstream by one
release cycle. See the weekly real-DB CI cron which diffs against
trivy's live source.
"""

from __future__ import annotations

DEFAULT_CONTENT_SETS: dict[str, list[str]] = {
    "6": ["rhel-6-server-rpms", "rhel-6-server-extras-rpms"],
    "7": ["rhel-7-server-rpms", "rhel-7-server-extras-rpms"],
    "8": [
        "rhel-8-for-x86_64-baseos-rpms",
        "rhel-8-for-x86_64-appstream-rpms",
    ],
    "9": [
        "rhel-9-for-x86_64-baseos-rpms",
        "rhel-9-for-x86_64-appstream-rpms",
    ],
}
