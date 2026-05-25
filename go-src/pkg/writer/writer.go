// Package writer builds a synthetic trivy-db fixture for testing.
//
// It writes both the bbolt file and the sibling metadata.json that
// pytrivydb's reader expects to find adjacent to it. Per-source value
// shapes import their canonical types from the upstream trivy-db
// package so that custom JSON marshaling (e.g. redhat-oval's Entry
// turning its Status enum into an integer key named "Status") is
// preserved byte-for-byte.
package writer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	redhat "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"

	"github.com/aquasecurity/trivy-db/pkg/types"
	bolt "go.etcd.io/bbolt"
)

// SupportedSchemaVersion is the trivy-db on-disk schema we mirror.
const SupportedSchemaVersion = 2

// Metadata mirrors trivy-db's pkg/metadata.Metadata so the file we
// emit is byte-shape-compatible. Verified against
// pkg/metadata/metadata.go:14-19.
type Metadata struct {
	Version      int `json:",omitempty"`
	NextUpdate   time.Time
	UpdatedAt    time.Time
	DownloadedAt time.Time
}

// Reserved top-level buckets the reader skips during iteration.
// Centralized here so the writer's anti-criterion test
// (write-something-into-a-non-reserved-bucket) stays in sync with
// the reader. The writer itself emits a subset; the reader's list is
// the full skip set.
var ReservedTopLevelBuckets = []string{
	"vulnerability",
	"vulnerability-detail",
	"vulnerability-id",
	"Red Hat CPE",
	"data-source",
	"trivy-db-metadata",
}

// WriteFixture builds a fresh trivy-db fixture under dbDir.
// dbDir is created if it does not exist. Both `trivy.db` and
// `metadata.json` end up inside dbDir.
func WriteFixture(dbDir string, version int) error {
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dbDir, err)
	}
	if err := writeMetadata(dbDir, version); err != nil {
		return fmt.Errorf("write metadata.json: %w", err)
	}
	if err := writeBolt(dbDir); err != nil {
		return fmt.Errorf("write trivy.db: %w", err)
	}
	return nil
}

func writeMetadata(dbDir string, version int) error {
	now := time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC)
	md := Metadata{
		Version:      version, // explicit non-zero so json:",omitempty" doesn't drop it
		NextUpdate:   now.Add(24 * time.Hour),
		UpdatedAt:    now,
		DownloadedAt: now,
	}
	data, err := json.MarshalIndent(md, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dbDir, "metadata.json"), data, 0o644)
}

func writeBolt(dbDir string) error {
	dbPath := filepath.Join(dbDir, "trivy.db")
	_ = os.Remove(dbPath)
	db, err := bolt.Open(dbPath, 0o644, nil)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		if err := writeDebian(tx); err != nil {
			return err
		}
		if err := writeAlpine(tx); err != nil {
			return err
		}
		if err := writeUbuntu(tx); err != nil {
			return err
		}
		if err := writeLanguagePackage(tx); err != nil {
			return err
		}
		if err := writeRedHat(tx); err != nil {
			return err
		}
		if err := writeRedHatCPE(tx); err != nil {
			return err
		}
		if err := writeVulnerabilityMeta(tx); err != nil {
			return err
		}
		return nil
	})
}

func putNested(tx *bolt.Tx, buckets []string, key string, value []byte) error {
	if len(buckets) == 0 {
		return fmt.Errorf("empty bucket path")
	}
	b, err := tx.CreateBucketIfNotExists([]byte(buckets[0]))
	if err != nil {
		return err
	}
	for _, name := range buckets[1:] {
		b, err = b.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return err
		}
	}
	return b.Put([]byte(key), value)
}

func putJSON(tx *bolt.Tx, buckets []string, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return putNested(tx, buckets, key, data)
}

// --- Per-source writers ---

func writeDebian(tx *bolt.Tx) error {
	// Debian advisory with FixedVersion + VendorIDs.
	adv1 := types.Advisory{
		FixedVersion: "1.34+dfsg-1",
		VendorIDs:    []string{"DLA-3399-1"},
	}
	if err := putJSON(tx, []string{"debian 12", "tar"}, "CVE-2005-2541", &adv1); err != nil {
		return err
	}
	// Debian advisory with Status only (will_not_fix).
	adv2 := types.Advisory{
		Status: types.StatusWillNotFix,
	}
	return putJSON(tx, []string{"debian 12", "linux"}, "CVE-2024-XXXX", &adv2)
}

func writeAlpine(tx *bolt.Tx) error {
	adv := types.Advisory{
		FixedVersion: "3.1.1-r1",
	}
	return putJSON(tx, []string{"alpine 3.19", "openssl"}, "CVE-2023-YYYY", &adv)
}

func writeUbuntu(tx *bolt.Tx) error {
	adv := types.Advisory{}
	return putJSON(tx, []string{"ubuntu 22.04", "bash"}, "CVE-2020-ZZZZ", &adv)
}

func writeLanguagePackage(tx *bolt.Tx) error {
	adv := types.Advisory{
		PatchedVersions:    []string{"4.17.21"},
		VulnerableVersions: []string{"<4.17.21"},
	}
	return putJSON(tx, []string{"ghsa::npm", "lodash"}, "CVE-2021-AAAA", &adv)
}

func writeRedHat(tx *bolt.Tx) error {
	// Red Hat uses its own Advisory/Entry types with a custom MarshalJSON
	// that serializes AffectedCPEIndices as JSON key "Affected" and the
	// Status enum as an integer key named "Status".
	adv := redhat.Advisory{
		Entries: []redhat.Entry{
			{
				FixedVersion: "2.34-100.el8_10.2",
				Cves: []redhat.CveEntry{
					{ID: "CVE-2021-3600", Severity: types.SeverityHigh},
				},
				Arches:             []string{"x86_64"},
				Status:             types.StatusFixed,
				AffectedCPEIndices: []int{1}, // RHEL-8 CPE index
			},
			{
				Cves: []redhat.CveEntry{
					{ID: "CVE-2021-3600", Severity: types.SeverityHigh},
				},
				Arches:             []string{"x86_64"},
				Status:             types.StatusWillNotFix,
				AffectedCPEIndices: []int{0}, // RHEL-7 CPE index
			},
		},
	}
	return putJSON(tx, []string{"Red Hat", "glibc"}, "CVE-2021-3600", &adv)
}

func writeRedHatCPE(tx *bolt.Tx) error {
	// Repository -> CPE indices.
	if err := putJSON(tx,
		[]string{"Red Hat CPE", "repository"},
		"rhel-7-server-rpms", []int{0},
	); err != nil {
		return err
	}
	if err := putJSON(tx,
		[]string{"Red Hat CPE", "repository"},
		"rhel-8-for-x86_64-baseos-rpms", []int{1},
	); err != nil {
		return err
	}
	if err := putJSON(tx,
		[]string{"Red Hat CPE", "repository"},
		"rhel-8-for-x86_64-appstream-rpms", []int{1},
	); err != nil {
		return err
	}
	// NVR -> CPE indices.
	if err := putJSON(tx,
		[]string{"Red Hat CPE", "nvr"},
		"glibc-2.34-100.el8_10.2-x86_64", []int{1},
	); err != nil {
		return err
	}
	// cpe sub-bucket is debug-only. We populate it to mirror the real
	// DB shape but the reader explicitly does NOT use it for resolution
	// (see plan anti-criteria + pkg/db/redhat_cpe.go:16-18).
	if err := putNested(tx,
		[]string{"Red Hat CPE", "cpe"}, "0",
		[]byte(`"cpe:/o:redhat:enterprise_linux:7"`),
	); err != nil {
		return err
	}
	return putNested(tx,
		[]string{"Red Hat CPE", "cpe"}, "1",
		[]byte(`"cpe:/o:redhat:enterprise_linux:8"`),
	)
}

func writeVulnerabilityMeta(tx *bolt.Tx) error {
	published := time.Date(2021, 6, 7, 0, 0, 0, 0, time.UTC)
	modified := time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	vuln := types.Vulnerability{
		Title:       "glibc: heap buffer overflow",
		Description: "A flaw was found in glibc.",
		Severity:    "HIGH",
		CweIDs:      []string{"CWE-787"},
		VendorSeverity: types.VendorSeverity{
			"nvd":    types.SeverityHigh,
			"redhat": types.SeverityHigh,
		},
		CVSS: types.VendorCVSS{
			"nvd": types.CVSS{V3Score: 7.8, V3Vector: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"},
		},
		References:       []string{"https://access.redhat.com/security/cve/CVE-2021-3600"},
		PublishedDate:    &published,
		LastModifiedDate: &modified,
	}
	return putJSON(tx, []string{"vulnerability"}, "CVE-2021-3600", &vuln)
}
