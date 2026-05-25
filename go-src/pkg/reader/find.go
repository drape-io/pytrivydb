package reader

import (
	"encoding/json"
	"fmt"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// PackageTypeSources maps scanner package_type strings to trivy-db
// source bucket name patterns. Patterns ending in `*` match any bucket
// name with that prefix (e.g. "debian *" matches "debian 11",
// "debian 12"). Authoritative; Python's sources_for_package_type
// always round-trips here.
//
// Mapping verified by inspecting the real `ghcr.io/aquasecurity/trivy-db:2`
// artifact. Language-ecosystem advisories live under the canonical
// ecosystem prefix (`npm::*`, `pip::*`, etc.); GHSA, ecosystem-native
// feeds, and the Seal Security Database all share that prefix
// (e.g. `npm::GitHub Security Advisory npm`,
// `npm::Node.js Ecosystem Security Working Group`,
// `seal npm::Seal Security Database`). There is no separate `ghsa::`
// top-level namespace.
//
// Seal Security Database feeds (`seal <distro>` / `seal <ecosystem>::*`)
// are included so consumers searching by package_type pick them up
// alongside the canonical advisories.
var PackageTypeSources = map[string][]string{
	// OS package types
	"deb": {
		"debian *", "ubuntu *",
		"root.io debian *", "root.io ubuntu *",
		"seal debian",
	},
	"rpm": {
		"Red Hat",
		"alma *", "rocky *",
		"amazon linux *",
		"Oracle Linux *",
		"Photon OS *",
		"CBL-Mariner *", "Azure Linux *",
		"openSUSE *", "SUSE *",
		"seal Red Hat *",
	},
	"apk": {
		"alpine *",
		"wolfi", "chainguard", "echo", "minimos",
		"root.io alpine *",
		"seal alpine",
	},
	// Language ecosystems
	"npm":          {"npm::*", "seal npm::*"},
	"java-archive": {"maven::*", "seal maven::*"},
	"pypi":         {"pip::*", "seal pip::*"},
	"gem":          {"rubygems::*", "seal rubygems::*"},
	"go":           {"go::*", "seal go::*"},
	"cargo":        {"cargo::*"},
	"nuget":        {"nuget::*"},
	"composer":     {"composer::*"},
	"conan":        {"conan::*"},
	"swift":        {"swift::*", "cocoapods::*"},
	"cocoapods":    {"cocoapods::*", "swift::*"},
	"pub":          {"pub::*"},
	"erlang":       {"erlang::*"},
	"julia":        {"julia::*"},
	"k8s":          {"k8s::*"},
}

// FindOpts are kwargs to FindAdvisories. Pointers distinguish "not
// given" from "empty list" — empty list is treated as no filter.
type FindOpts struct {
	PackageType  string
	Sources      []string
	Repositories []string
	NVRs         []string
}

// FindAdvisories searches relevant source buckets for (cve, pkg)
// matches. Dispatch rules:
//   1. If opts.Sources is non-empty, use it as-is.
//   2. Else if opts.PackageType is set, expand via PackageTypeSources
//      against actually-present top-level buckets.
//   3. Else, search every non-reserved top-level bucket.
//
// For Red Hat-family matches, if opts.Repositories OR opts.NVRs is
// non-empty, the advisory's Entries[] are filtered by resolved CPE
// index intersection. If neither is given, raw Entries[] pass through.
//
// Returns ErrCorrupt-wrapped errors on malformed Red Hat CPE / Entry
// JSON — these are fail-fast signals that the trivy.db is corrupt or
// has shipped a schema we don't understand.
func (d *Database) FindAdvisories(cveID, pkgName string, opts FindOpts) ([]AdvisoryRow, error) {
	var rows []AdvisoryRow
	err := d.bdb.View(func(tx *bolt.Tx) error {
		sources, err := resolveSources(tx, opts)
		if err != nil {
			return err
		}

		// Pre-resolve Red Hat CPE indices once per call if either
		// repositories or nvrs is provided. `redhatFilterActive`
		// distinguishes "no filter requested" (nil) from "filter
		// requested but resolved to zero indices" (non-nil empty).
		var cpeIndices []int
		redhatFilterActive := len(opts.Repositories) > 0 || len(opts.NVRs) > 0
		if redhatFilterActive {
			cpeIndices, err = resolveRedHatCPEIndices(tx, opts.Repositories, opts.NVRs)
			if err != nil {
				return err
			}
		}

		for _, src := range sources {
			row, ok := getOneAdvisory(tx, src, pkgName, cveID)
			if !ok {
				continue
			}
			if src == "Red Hat" && redhatFilterActive {
				filtered, kept, err := filterRedHatEntries(row.Raw, cpeIndices)
				if err != nil {
					return err
				}
				if !kept {
					continue
				}
				row.Raw = filtered
			}
			rows = append(rows, row)
		}
		return nil
	})
	return rows, err
}

// resolveSources implements the three-tier dispatch.
func resolveSources(tx *bolt.Tx, opts FindOpts) ([]string, error) {
	if len(opts.Sources) > 0 {
		return opts.Sources, nil
	}
	all := allNonReservedBuckets(tx)
	if opts.PackageType == "" {
		return all, nil
	}
	patterns, ok := PackageTypeSources[opts.PackageType]
	if !ok {
		// Unknown package_type — fall through to all sources rather
		// than returning nothing. Documented behavior.
		return all, nil
	}
	return expandSourcePatterns(patterns, all), nil
}

// allNonReservedBuckets returns top-level bucket names in tx, with
// reserved buckets filtered out.
func allNonReservedBuckets(tx *bolt.Tx) []string {
	var out []string
	_ = tx.ForEach(func(name []byte, _ *bolt.Bucket) error {
		s := string(name)
		if _, reserved := reservedTopLevelBuckets[s]; reserved {
			return nil
		}
		out = append(out, s)
		return nil
	})
	return out
}

// expandSourcePatterns expands `prefix *` patterns into actual bucket
// names. Exact-match patterns (no trailing `*`) are kept as-is only if
// the bucket exists in `available`. `*` after a `::` separator
// (e.g. "npm::*") is treated as a prefix-match too.
func expandSourcePatterns(patterns, available []string) []string {
	out := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, p := range patterns {
		if strings.HasSuffix(p, "*") {
			prefix := strings.TrimSuffix(p, "*")
			for _, a := range available {
				if strings.HasPrefix(a, prefix) {
					if _, dup := seen[a]; dup {
						continue
					}
					seen[a] = struct{}{}
					out = append(out, a)
				}
			}
			continue
		}
		// Exact match.
		for _, a := range available {
			if a == p {
				if _, dup := seen[a]; dup {
					continue
				}
				seen[a] = struct{}{}
				out = append(out, a)
				break
			}
		}
	}
	return out
}

// SourcesForPackageType returns the resolved bucket names for a
// package_type against the currently-open database.
func (d *Database) SourcesForPackageType(packageType string) ([]string, error) {
	patterns, ok := PackageTypeSources[packageType]
	if !ok {
		return nil, nil
	}
	var resolved []string
	err := d.bdb.View(func(tx *bolt.Tx) error {
		resolved = expandSourcePatterns(patterns, allNonReservedBuckets(tx))
		return nil
	})
	return resolved, err
}

// getOneAdvisory fetches a single (source, pkg, cve) leaf, returning
// (row, true) if present.
func getOneAdvisory(tx *bolt.Tx, source, pkgName, cveID string) (AdvisoryRow, bool) {
	src := tx.Bucket([]byte(source))
	if src == nil {
		return AdvisoryRow{}, false
	}
	pkg := src.Bucket([]byte(pkgName))
	if pkg == nil {
		return AdvisoryRow{}, false
	}
	v := pkg.Get([]byte(cveID))
	if v == nil {
		return AdvisoryRow{}, false
	}
	raw, okSize := copyRaw(v)
	if !okSize {
		return AdvisoryRow{}, false
	}
	return AdvisoryRow{
		Source:      source,
		PackageName: pkgName,
		CveID:       cveID,
		Raw:         raw,
	}, true
}

// --- Red Hat CPE resolution ---
//
// Only the "Red Hat" bucket participates in CPE-index Entry filtering.
// Other RPM-based sources (Alma, Rocky, etc.) store their own advisory
// shape and are not gated by Red Hat CPE indices.

// resolveRedHatCPEIndices returns the union of CPE indices that the
// given content sets (yum repository IDs) and NVRs resolve to via the
// `Red Hat CPE / repository` and `Red Hat CPE / nvr` buckets.
//
// Per the plan anti-criteria, this MUST NOT read the
// `Red Hat CPE / cpe` debug sub-bucket — that bucket is explicitly
// marked debug-only by upstream and not safe for resolution.
//
// Returns ErrCorrupt-wrapped errors when a stored CPE-index value
// fails to parse — that's a fail-fast signal of DB corruption, not
// a row to silently skip.
func resolveRedHatCPEIndices(tx *bolt.Tx, repos, nvrs []string) ([]int, error) {
	root := tx.Bucket([]byte("Red Hat CPE"))
	if root == nil {
		return nil, nil
	}
	seen := make(map[int]struct{})
	collect := func(b *bolt.Bucket, key string) error {
		if b == nil {
			return nil
		}
		v := b.Get([]byte(key))
		if v == nil {
			return nil
		}
		if len(v) > MaxRawValueBytes {
			return fmt.Errorf("%w: Red Hat CPE entry %q exceeds %d bytes",
				ErrCorrupt, key, MaxRawValueBytes)
		}
		var idxs []int
		if err := safeUnmarshal(v, &idxs); err != nil {
			return fmt.Errorf("%w: Red Hat CPE entry %q: %v", ErrCorrupt, key, err)
		}
		for _, i := range idxs {
			seen[i] = struct{}{}
		}
		return nil
	}
	repoBkt := root.Bucket([]byte("repository"))
	for _, r := range repos {
		if err := collect(repoBkt, r); err != nil {
			return nil, err
		}
	}
	nvrBkt := root.Bucket([]byte("nvr"))
	for _, n := range nvrs {
		if err := collect(nvrBkt, n); err != nil {
			return nil, err
		}
	}
	if len(seen) == 0 {
		return nil, nil
	}
	out := make([]int, 0, len(seen))
	for i := range seen {
		out = append(out, i)
	}
	return out, nil
}

// filterRedHatEntries trims an advisory's Entries[] array to only
// those whose `Affected` (a.k.a. AffectedCPEIndices) intersects the
// resolved CPE indices. Returns (filtered JSON, kept=true, nil) if
// at least one entry survives, (nil, false, nil) if all entries are
// filtered out, or (nil, false, ErrCorrupt-wrapped) on a malformed
// advisory value.
func filterRedHatEntries(raw json.RawMessage, cpeIndices []int) (json.RawMessage, bool, error) {
	var advisory struct {
		Entries []json.RawMessage `json:"Entries,omitempty"`
	}
	if err := safeUnmarshal(raw, &advisory); err != nil {
		return nil, false, fmt.Errorf("%w: Red Hat advisory parse: %v", ErrCorrupt, err)
	}
	wanted := make(map[int]struct{}, len(cpeIndices))
	for _, i := range cpeIndices {
		wanted[i] = struct{}{}
	}
	var kept []json.RawMessage
	for _, entryRaw := range advisory.Entries {
		var entry struct {
			Affected []int `json:"Affected"`
		}
		if err := safeUnmarshal(entryRaw, &entry); err != nil {
			return nil, false, fmt.Errorf("%w: Red Hat Entry parse: %v", ErrCorrupt, err)
		}
		for _, idx := range entry.Affected {
			if _, ok := wanted[idx]; ok {
				kept = append(kept, entryRaw)
				break
			}
		}
	}
	if len(kept) == 0 {
		return nil, false, nil
	}
	out, err := json.Marshal(struct {
		Entries []json.RawMessage `json:"Entries"`
	}{Entries: kept})
	if err != nil {
		return nil, false, fmt.Errorf("%w: Red Hat filtered re-encode: %v", ErrCorrupt, err)
	}
	return out, true, nil
}
