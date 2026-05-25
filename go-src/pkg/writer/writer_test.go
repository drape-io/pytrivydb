package writer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	redhat "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"

	bolt "go.etcd.io/bbolt"
)

func TestWriteFixtureProducesExpectedFiles(t *testing.T) {
	dir := t.TempDir()
	if err := WriteFixture(dir, SupportedSchemaVersion); err != nil {
		t.Fatalf("WriteFixture: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "trivy.db")); err != nil {
		t.Errorf("trivy.db missing: %v", err)
	}
	mdPath := filepath.Join(dir, "metadata.json")
	mdBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read metadata.json: %v", err)
	}

	var md Metadata
	if err := json.Unmarshal(mdBytes, &md); err != nil {
		t.Fatalf("unmarshal metadata.json: %v", err)
	}
	if md.Version != SupportedSchemaVersion {
		t.Errorf("Version = %d, want %d", md.Version, SupportedSchemaVersion)
	}

	// json:",omitempty" on Version: writing 0 would silently disappear.
	// Defensive assertion that the bytes-on-disk include the field literally.
	if !strings.Contains(string(mdBytes), `"Version"`) {
		t.Errorf("metadata.json bytes missing 'Version' key:\n%s", mdBytes)
	}
}

func TestRedHatEntryRoundTripsViaUpstreamMarshalJSON(t *testing.T) {
	// Verifies the Red Hat advisory JSON shape matches upstream's
	// custom marshaling: AffectedCPEIndices -> "Affected", Status as int.
	dir := t.TempDir()
	if err := WriteFixture(dir, SupportedSchemaVersion); err != nil {
		t.Fatalf("WriteFixture: %v", err)
	}

	db, err := bolt.Open(filepath.Join(dir, "trivy.db"), 0o600, &bolt.Options{ReadOnly: true})
	if err != nil {
		t.Fatalf("bolt.Open: %v", err)
	}
	defer db.Close()

	var raw []byte
	if err := db.View(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("Red Hat"))
		if root == nil {
			return nil
		}
		pkg := root.Bucket([]byte("glibc"))
		if pkg == nil {
			return nil
		}
		raw = pkg.Get([]byte("CVE-2021-3600"))
		return nil
	}); err != nil {
		t.Fatalf("View: %v", err)
	}
	if raw == nil {
		t.Fatal("Red Hat/glibc/CVE-2021-3600 not found")
	}

	// JSON contains the upstream custom-marshal key names.
	s := string(raw)
	for _, want := range []string{`"Affected":`, `"Status":`, `"Entries":`} {
		if !strings.Contains(s, want) {
			t.Errorf("Red Hat advisory JSON missing %q. Got:\n%s", want, s)
		}
	}

	// UnmarshalJSON round-trips through upstream's UnmarshalJSON.
	var adv redhat.Advisory
	if err := json.Unmarshal(raw, &adv); err != nil {
		t.Fatalf("unmarshal Red Hat advisory: %v", err)
	}
	if len(adv.Entries) != 2 {
		t.Fatalf("Entries len = %d, want 2", len(adv.Entries))
	}
	// First entry is the fixed RHEL-8 one (CPE index 1).
	if adv.Entries[0].FixedVersion == "" {
		t.Errorf("Entries[0].FixedVersion empty")
	}
	if len(adv.Entries[0].AffectedCPEIndices) != 1 || adv.Entries[0].AffectedCPEIndices[0] != 1 {
		t.Errorf("Entries[0].AffectedCPEIndices = %v, want [1]", adv.Entries[0].AffectedCPEIndices)
	}
}

func TestReservedBucketsAreExpected(t *testing.T) {
	want := map[string]bool{
		"vulnerability":        true,
		"vulnerability-detail": true,
		"vulnerability-id":     true,
		"Red Hat CPE":          true,
		"data-source":          true,
		"trivy-db-metadata":    true,
	}
	got := make(map[string]bool, len(ReservedTopLevelBuckets))
	for _, b := range ReservedTopLevelBuckets {
		got[b] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("ReservedTopLevelBuckets missing %q", name)
		}
	}
	for name := range got {
		if !want[name] {
			t.Errorf("ReservedTopLevelBuckets has unexpected %q", name)
		}
	}
}
