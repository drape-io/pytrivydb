"""Pydantic models exposed by pytrivydb's public API.

These mirror the shapes from trivy-db's ``pkg/types``, with hyphenated
``status``/``severity`` string fields decoded alongside the raw enum
ints so consumers don't have to remember the mapping.

Per-source raw advisory shape (e.g. Red Hat's nested ``Entries[]``)
lives in :attr:`Advisory.extra` — explicitly documented as
**unstable** in the README; consumers should not depend on key
shapes there.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# Mirrors trivy-db/pkg/types/status.go (length-8 list).
STATUS_NAMES: dict[int, str] = {
    0: "unknown",
    1: "not_affected",
    2: "affected",
    3: "fixed",
    4: "under_investigation",
    5: "will_not_fix",
    6: "fix_deferred",
    7: "end_of_life",
}

# Mirrors trivy-db/pkg/types/types.go SeverityNames.
SEVERITY_NAMES: dict[int, str] = {
    0: "UNKNOWN",
    1: "LOW",
    2: "MEDIUM",
    3: "HIGH",
    4: "CRITICAL",
}


def _decode_enum(names: dict[int, str], code: int | None) -> str:
    """Resolve an enum int to its string label, or surface unrecognized
    codes as ``unknown_<N>`` so log scrapes can spot upstream additions
    instead of seeing a silent empty string.
    """
    if code is None:
        return ""
    name = names.get(code)
    if name is not None:
        return name
    return f"unknown_{code}"


class Advisory(BaseModel):
    """One advisory leaf: ``(source, package_name, cve_id)`` →
    per-source value.

    Known fields are best-effort extracted from the raw bbolt value.
    Per-source shape (e.g. Red Hat's ``Entries[]``) lands in
    :attr:`extra`.
    """

    model_config = ConfigDict(extra="ignore")

    source: str
    package_name: str
    cve_id: str
    fixed_version: str = ""
    status_code: int | None = None
    status: str = ""
    severity_code: int | None = None
    severity: str = ""
    vendor_ids: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Advisory:
        raw = row.get("raw") or {}
        known = {"FixedVersion", "Status", "Severity", "VendorIDs"}
        status_code: int | None = raw.get("Status")
        severity_code: int | None = raw.get("Severity")
        return cls(
            source=row["source"],
            package_name=row["package_name"],
            cve_id=row["cve_id"],
            fixed_version=raw.get("FixedVersion") or "",
            status_code=status_code,
            status=_decode_enum(STATUS_NAMES, status_code),
            severity_code=severity_code,
            severity=_decode_enum(SEVERITY_NAMES, severity_code),
            vendor_ids=list(raw.get("VendorIDs") or []),
            extra={k: v for k, v in raw.items() if k not in known},
        )


class Vulnerability(BaseModel):
    """One entry in trivy-db's aggregated ``vulnerability`` bucket
    (one row per CVE).
    """

    model_config = ConfigDict(extra="ignore")

    cve_id: str
    title: str = ""
    description: str = ""
    severity: str = ""
    cvss: dict[str, Any] = Field(default_factory=dict)
    vendor_severity: dict[str, int] = Field(default_factory=dict)
    references: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    published_date: datetime | None = None
    last_modified_date: datetime | None = None

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> Vulnerability:
        raw = row.get("raw") or {}
        return cls(
            cve_id=row["cve_id"],
            title=raw.get("Title") or "",
            description=raw.get("Description") or "",
            severity=raw.get("Severity") or "",
            cvss=dict(raw.get("CVSS") or {}),
            vendor_severity=dict(raw.get("VendorSeverity") or {}),
            references=list(raw.get("References") or []),
            cwe_ids=list(raw.get("CweIDs") or []),
            published_date=raw.get("PublishedDate"),
            last_modified_date=raw.get("LastModifiedDate"),
        )
