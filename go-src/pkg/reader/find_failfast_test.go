package reader

import (
	"errors"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// withCorruptedRedHatCPE rewrites a single Red Hat CPE bucket entry in
// the fixture DB with corruptedBytes, then returns an opened Database
// against it. The fixture is built via the writer first so the rest of
// the schema is sane.
func withCorruptedRedHatCPE(t *testing.T, key string, corruptedBytes []byte) *Database {
	t.Helper()
	dir := fixture(t)
	// Open in read-write mode just for this surgery, then re-open
	// through reader.Open which is read-only.
	rwDB, err := bolt.Open(dir+"/trivy.db", 0o600, nil)
	if err != nil {
		t.Fatalf("rw open: %v", err)
	}
	if err := rwDB.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("Red Hat CPE"))
		if root == nil {
			t.Fatal("Red Hat CPE bucket missing from fixture")
		}
		repo := root.Bucket([]byte("repository"))
		if repo == nil {
			t.Fatal("Red Hat CPE/repository bucket missing")
		}
		return repo.Put([]byte(key), corruptedBytes)
	}); err != nil {
		t.Fatalf("rw mutate: %v", err)
	}
	if err := rwDB.Close(); err != nil {
		t.Fatalf("rw close: %v", err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestFindAdvisoriesFailFastOnDeeplyNestedCPEEntry(t *testing.T) {
	// Build deeply-nested JSON exceeding MaxJSONDepth in the
	// CPE-indices slot. resolveRedHatCPEIndices should bubble
	// ErrCorrupt out through FindAdvisories.
	deep := strings.Repeat("[", MaxJSONDepth+5) + strings.Repeat("]", MaxJSONDepth+5)
	db := withCorruptedRedHatCPE(t, "rhel-8-for-x86_64-baseos-rpms", []byte(deep))

	_, err := db.FindAdvisories("CVE-2021-3600", "glibc", FindOpts{
		Sources:      []string{"Red Hat"},
		Repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
	})
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt for deeply-nested CPE entry, got %v", err)
	}
}

func TestFindAdvisoriesFailFastOnMalformedCPEJSON(t *testing.T) {
	db := withCorruptedRedHatCPE(t,
		"rhel-8-for-x86_64-baseos-rpms",
		[]byte(`{"not": "an int array"}`),
	)
	_, err := db.FindAdvisories("CVE-2021-3600", "glibc", FindOpts{
		Sources:      []string{"Red Hat"},
		Repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
	})
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt for malformed CPE JSON, got %v", err)
	}
}

func TestFindAdvisoriesFailFastOnOversizedCPEEntry(t *testing.T) {
	huge := make([]byte, MaxRawValueBytes+1)
	for i := range huge {
		huge[i] = 'a'
	}
	db := withCorruptedRedHatCPE(t, "rhel-8-for-x86_64-baseos-rpms", huge)

	_, err := db.FindAdvisories("CVE-2021-3600", "glibc", FindOpts{
		Sources:      []string{"Red Hat"},
		Repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
	})
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt for oversized CPE entry, got %v", err)
	}
}

func TestSafeUnmarshalDepthExceedanceMidStream(t *testing.T) {
	// VULN-105 follow-up: scanner should ErrCorrupt out before reaching
	// trailing garbage. Otherwise a hostile blob could blow stack via
	// deep nesting and bypass detection.
	deepThenGarbage := strings.Repeat("[", MaxJSONDepth+5) + "garbage"
	var v any
	err := safeUnmarshal([]byte(deepThenGarbage), &v)
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("expected ErrCorrupt for deep-then-garbage, got %v", err)
	}
}
