package reader

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/drape-io/pytrivydb/go-src/pkg/writer"
)

// fixture writes the synthetic fixture into a temp directory and
// returns the path. Reuses pkg/writer so we test against the
// canonical shape (upstream redhat-oval MarshalJSON etc.).
func fixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := writer.WriteFixture(dir, writer.SupportedSchemaVersion); err != nil {
		t.Fatalf("WriteFixture: %v", err)
	}
	return dir
}

func TestOpenAndListSources(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	sources, err := db.ListSources()
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	sort.Strings(sources)
	want := []string{"Red Hat", "alpine 3.19", "debian 12", "ghsa::npm", "ubuntu 22.04"}
	if !slices.Equal(sources, want) {
		t.Errorf("ListSources = %v, want %v", sources, want)
	}
}

func TestOpenUnsupportedSchema(t *testing.T) {
	dir := t.TempDir()
	if err := writer.WriteFixture(dir, 99); err != nil {
		t.Fatalf("WriteFixture: %v", err)
	}
	_, err := Open(dir)
	if !errors.Is(err, ErrUnsupportedSchema) {
		t.Errorf("Open with version 99: got %v, want ErrUnsupportedSchema", err)
	}
}

func TestOpenMissingMetadata(t *testing.T) {
	dir := t.TempDir()
	_, err := Open(dir)
	if !errors.Is(err, ErrMetadataNotFound) {
		t.Errorf("Open empty dir: got %v, want ErrMetadataNotFound", err)
	}
}

func TestOpenMalformedMetadata(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir)
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("Open malformed metadata: got %v, want ErrCorrupt", err)
	}
}

func TestOpenMissingTrivyDb(t *testing.T) {
	dir := t.TempDir()
	md := `{"Version": 2}`
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), []byte(md), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Open(dir)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Open missing trivy.db: got %v, want ErrNotFound", err)
	}
}

func TestIterAdvisoriesYieldsAllRows(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	it, err := db.OpenAdvisoryIterator()
	if err != nil {
		t.Fatalf("OpenAdvisoryIterator: %v", err)
	}
	defer it.Close()

	var all []AdvisoryRow
	for {
		batch, err := it.Next(2)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if batch == nil {
			break
		}
		all = append(all, batch...)
	}

	// Build a (source, pkg, cve) set to compare.
	type key struct{ src, pkg, cve string }
	got := make(map[key]bool, len(all))
	for _, r := range all {
		got[key{r.Source, r.PackageName, r.CveID}] = true
	}
	want := []key{
		{"Red Hat", "glibc", "CVE-2021-3600"},
		{"alpine 3.19", "openssl", "CVE-2023-YYYY"},
		{"debian 12", "linux", "CVE-2024-XXXX"},
		{"debian 12", "tar", "CVE-2005-2541"},
		{"ghsa::npm", "lodash", "CVE-2021-AAAA"},
		{"ubuntu 22.04", "bash", "CVE-2020-ZZZZ"},
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing row: %+v", w)
		}
	}
	if len(all) != len(want) {
		t.Errorf("got %d rows, want %d", len(all), len(want))
	}

	// Verify reserved buckets did NOT leak into iteration.
	for _, r := range all {
		if _, reserved := reservedTopLevelBuckets[r.Source]; reserved {
			t.Errorf("reserved bucket %q yielded row: %+v", r.Source, r)
		}
	}
}

func TestIterMetaYieldsVulnerabilities(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	it, err := db.OpenMetaIterator()
	if err != nil {
		t.Fatalf("OpenMetaIterator: %v", err)
	}
	defer it.Close()

	var rows []MetaRow
	for {
		batch, err := it.Next(10)
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if batch == nil {
			break
		}
		rows = append(rows, batch...)
	}
	if len(rows) != 1 {
		t.Fatalf("MetaIterator yielded %d rows, want 1", len(rows))
	}
	if rows[0].CveID != "CVE-2021-3600" {
		t.Errorf("got CveID %q", rows[0].CveID)
	}
	// Raw JSON should parse and contain Severity.
	var m map[string]any
	if err := json.Unmarshal(rows[0].Raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["Severity"] != "HIGH" {
		t.Errorf("Severity = %v, want HIGH", m["Severity"])
	}
}

func TestFindAdvisoriesByPackageType(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.FindAdvisories("CVE-2005-2541", "tar", FindOpts{PackageType: "deb"})
	if err != nil {
		t.Fatalf("FindAdvisories: %v", err)
	}
	if len(rows) != 1 || rows[0].Source != "debian 12" {
		t.Errorf("got %+v, want one row from debian 12", rows)
	}
}

func TestFindAdvisoriesUnknown(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.FindAdvisories("CVE-NONEXISTENT", "tar", FindOpts{PackageType: "deb"})
	if err != nil {
		t.Fatalf("FindAdvisories: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("got %d rows, want 0", len(rows))
	}
}

func TestFindAdvisoriesExplicitSources(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.FindAdvisories("CVE-2005-2541", "tar", FindOpts{Sources: []string{"debian 12"}})
	if err != nil {
		t.Fatalf("FindAdvisories: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("expected 1 row, got %d", len(rows))
	}
}

func TestFindAdvisoriesRedHatNoFilter(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.FindAdvisories("CVE-2021-3600", "glibc", FindOpts{Sources: []string{"Red Hat"}})
	if err != nil {
		t.Fatalf("FindAdvisories: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	var adv struct {
		Entries []json.RawMessage `json:"Entries"`
	}
	if err := json.Unmarshal(rows[0].Raw, &adv); err != nil {
		t.Fatalf("unmarshal advisory: %v", err)
	}
	if len(adv.Entries) != 2 {
		t.Errorf("Entries = %d, want 2 (unfiltered)", len(adv.Entries))
	}
}

func TestFindAdvisoriesRedHatFilterByRepository(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.FindAdvisories(
		"CVE-2021-3600", "glibc",
		FindOpts{
			Sources:      []string{"Red Hat"},
			Repositories: []string{"rhel-8-for-x86_64-baseos-rpms"},
		},
	)
	if err != nil {
		t.Fatalf("FindAdvisories: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	var adv struct {
		Entries []map[string]any `json:"Entries"`
	}
	if err := json.Unmarshal(rows[0].Raw, &adv); err != nil {
		t.Fatalf("unmarshal advisory: %v", err)
	}
	if len(adv.Entries) != 1 {
		t.Fatalf("filtered Entries = %d, want 1", len(adv.Entries))
	}
	// RHEL-8 entry has FixedVersion populated.
	if adv.Entries[0]["FixedVersion"] != "2.34-100.el8_10.2" {
		t.Errorf("FixedVersion = %v, want RHEL-8's", adv.Entries[0]["FixedVersion"])
	}
}

func TestFindAdvisoriesRedHatFilterByNVR(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.FindAdvisories(
		"CVE-2021-3600", "glibc",
		FindOpts{
			Sources: []string{"Red Hat"},
			NVRs:    []string{"glibc-2.34-100.el8_10.2-x86_64"},
		},
	)
	if err != nil {
		t.Fatalf("FindAdvisories: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
}

func TestFindAdvisoriesRedHatFilterDropsAll(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	rows, err := db.FindAdvisories(
		"CVE-2021-3600", "glibc",
		FindOpts{
			Sources:      []string{"Red Hat"},
			Repositories: []string{"rhel-9-server-rpms"}, // not in fixture
		},
	)
	if err != nil {
		t.Fatalf("FindAdvisories: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 rows after non-matching filter, got %d", len(rows))
	}
}

func TestGetAdvisory(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	row, ok, err := db.GetAdvisory("debian 12", "tar", "CVE-2005-2541")
	if err != nil {
		t.Fatalf("GetAdvisory: %v", err)
	}
	if !ok {
		t.Fatal("GetAdvisory returned false for known row")
	}
	if row.CveID != "CVE-2005-2541" {
		t.Errorf("CveID = %q", row.CveID)
	}

	_, ok, err = db.GetAdvisory("debian 12", "tar", "CVE-NONEXISTENT")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("GetAdvisory returned true for missing row")
	}
}

func TestSourcesForPackageType(t *testing.T) {
	dir := fixture(t)
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	debs, err := db.SourcesForPackageType("deb")
	if err != nil {
		t.Fatalf("SourcesForPackageType: %v", err)
	}
	sort.Strings(debs)
	if !slices.Equal(debs, []string{"debian 12", "ubuntu 22.04"}) {
		t.Errorf("deb sources = %v", debs)
	}

	rpms, err := db.SourcesForPackageType("rpm")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(rpms, "Red Hat") {
		t.Errorf("rpm sources missing Red Hat: %v", rpms)
	}

	unknown, err := db.SourcesForPackageType("totally-unknown")
	if err != nil {
		t.Fatal(err)
	}
	if len(unknown) != 0 {
		t.Errorf("unknown package_type should return nil/empty, got %v", unknown)
	}
}

// TestAntiCriterionNoDebugCpeBucketRead ensures the source code of
// pkg/reader never references the debug `cpe` sub-bucket name. This
// is the CI-enforced anti-criterion from plan §Anti-criteria.
func TestAntiCriterionNoDebugCpeBucketRead(t *testing.T) {
	matches := []string{}
	root := "."
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(b)
		// Look for the literal bucket name in non-test source.
		if strings.Contains(text, `"cpe"`) {
			matches = append(matches, path)
		}
		if strings.Contains(text, `Red Hat CPE/cpe`) {
			matches = append(matches, path)
		}
		return nil
	})
	if len(matches) > 0 {
		t.Errorf("anti-criterion violated: reader source references debug `cpe` bucket: %v", matches)
	}
}

func TestMultiDBPerProcess(t *testing.T) {
	dir1 := fixture(t)
	dir2 := fixture(t)
	db1, err := Open(dir1)
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()
	db2, err := Open(dir2)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()

	// Both DBs should iterate independently.
	it1, err := db1.OpenAdvisoryIterator()
	if err != nil {
		t.Fatal(err)
	}
	defer it1.Close()
	it2, err := db2.OpenAdvisoryIterator()
	if err != nil {
		t.Fatal(err)
	}
	defer it2.Close()

	b1, _ := it1.Next(1000)
	b2, _ := it2.Next(1000)
	if len(b1) == 0 || len(b2) == 0 {
		t.Errorf("expected non-empty batches from both iterators, got %d / %d", len(b1), len(b2))
	}
	if len(b1) != len(b2) {
		t.Errorf("identical fixtures should yield same row count: %d vs %d", len(b1), len(b2))
	}
}
