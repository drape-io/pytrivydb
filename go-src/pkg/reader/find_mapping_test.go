package reader

import (
	"slices"
	"testing"
)

// fakeBuckets is a curated snapshot of representative bucket names
// from the real ghcr.io/aquasecurity/trivy-db:2 artifact. The mapping
// table is verified by `expandSourcePatterns` against this snapshot
// so that an accidental edit (e.g. re-adding a non-existent `ghsa::*`
// pattern) is caught in unit tests, not at runtime against the real DB.
var fakeBuckets = []string{
	// OS
	"debian 12", "debian 13",
	"ubuntu 22.04", "ubuntu 24.04",
	"root.io debian 12", "root.io ubuntu 24.04",
	"seal debian",
	"Red Hat",
	"alma 9", "rocky 9",
	"amazon linux 2", "amazon linux 2023",
	"Oracle Linux 8", "Oracle Linux 9",
	"Photon OS 5.0",
	"CBL-Mariner 2.0", "Azure Linux 3.0",
	"openSUSE Leap 15.6", "SUSE Linux Enterprise 15",
	"seal Red Hat 8", "seal Red Hat 9",
	"alpine 3.20", "wolfi", "chainguard", "echo", "minimos",
	"root.io alpine 3.20", "seal alpine",
	// Language ecosystems
	"npm::GitHub Security Advisory npm",
	"npm::Node.js Ecosystem Security Working Group",
	"seal npm::Seal Security Database",
	"pip::GitHub Security Advisory pip",
	"pip::The Aqua Security Vulnerability Database",
	"seal pip::Seal Security Database",
	"maven::GitHub Security Advisory Maven",
	"seal maven::Seal Security Database",
	"rubygems::GitHub Security Advisory RubyGems",
	"rubygems::Ruby Advisory Database",
	"seal rubygems::Seal Security Database",
	"go::GitHub Security Advisory Go",
	"go::The Go Vulnerability Database",
	"seal go::Seal Security Database",
	"cargo::GitHub Security Advisory Rust",
	"nuget::GitHub Security Advisory NuGet",
	"composer::GitHub Security Advisory Composer",
	"composer::PHP Security Advisories Database",
	"conan::GitLab Advisory Database Community",
	"swift::GitHub Security Advisory Swift",
	"cocoapods::GitHub Security Advisory Swift",
	"pub::GitHub Security Advisory Pub",
	"erlang::GitHub Security Advisory Erlang",
	"julia::Julia Ecosystem Security Advisories",
	"k8s::Official Kubernetes CVE Feed",
}

// expectations[packageType] = set of bucket names that MUST be in the
// expanded set (subset check — extras are allowed but the listed ones
// must be present).
var expectations = map[string][]string{
	"deb": {
		"debian 12", "ubuntu 22.04",
		"root.io debian 12", "seal debian",
	},
	"rpm": {
		"Red Hat", "alma 9", "rocky 9",
		"amazon linux 2", "Oracle Linux 8",
		"Photon OS 5.0", "CBL-Mariner 2.0", "Azure Linux 3.0",
		"openSUSE Leap 15.6", "SUSE Linux Enterprise 15",
		"seal Red Hat 9",
	},
	"apk": {
		"alpine 3.20", "wolfi", "chainguard", "echo", "minimos",
		"root.io alpine 3.20", "seal alpine",
	},
	"npm": {
		"npm::GitHub Security Advisory npm",
		"npm::Node.js Ecosystem Security Working Group",
		"seal npm::Seal Security Database",
	},
	"java-archive": {
		"maven::GitHub Security Advisory Maven",
		"seal maven::Seal Security Database",
	},
	"pypi": {
		"pip::GitHub Security Advisory pip",
		"pip::The Aqua Security Vulnerability Database",
		"seal pip::Seal Security Database",
	},
	"gem": {
		"rubygems::GitHub Security Advisory RubyGems",
		"rubygems::Ruby Advisory Database",
		"seal rubygems::Seal Security Database",
	},
	"go": {
		"go::GitHub Security Advisory Go",
		"go::The Go Vulnerability Database",
		"seal go::Seal Security Database",
	},
	"cargo":     {"cargo::GitHub Security Advisory Rust"},
	"nuget":     {"nuget::GitHub Security Advisory NuGet"},
	"composer":  {"composer::GitHub Security Advisory Composer", "composer::PHP Security Advisories Database"},
	"conan":     {"conan::GitLab Advisory Database Community"},
	"swift":     {"swift::GitHub Security Advisory Swift", "cocoapods::GitHub Security Advisory Swift"},
	"cocoapods": {"cocoapods::GitHub Security Advisory Swift", "swift::GitHub Security Advisory Swift"},
	"pub":       {"pub::GitHub Security Advisory Pub"},
	"erlang":    {"erlang::GitHub Security Advisory Erlang"},
	"julia":     {"julia::Julia Ecosystem Security Advisories"},
	"k8s":       {"k8s::Official Kubernetes CVE Feed"},
}

func TestPackageTypeSourcesAgainstRealBuckets(t *testing.T) {
	for pt, wantSubset := range expectations {
		patterns, ok := PackageTypeSources[pt]
		if !ok {
			t.Errorf("PackageTypeSources missing entry for %q", pt)
			continue
		}
		got := expandSourcePatterns(patterns, fakeBuckets)
		for _, want := range wantSubset {
			if !slices.Contains(got, want) {
				t.Errorf("package_type=%q: expected bucket %q in expanded set, got %v",
					pt, want, got)
			}
		}
	}
}

// TestNoPhantomGHSANamespace guards against re-introducing the
// fictional `ghsa::*` namespace that an earlier version of this
// mapping incorrectly added. The real DB has no top-level buckets
// starting with `ghsa::`.
func TestNoPhantomGHSANamespace(t *testing.T) {
	for pt, patterns := range PackageTypeSources {
		for _, p := range patterns {
			if len(p) >= 6 && p[:6] == "ghsa::" {
				t.Errorf("package_type=%q: pattern %q references nonexistent "+
					"ghsa:: namespace (GHSA advisories live under the "+
					"ecosystem prefix, e.g. npm::GitHub Security Advisory npm)",
					pt, p)
			}
		}
	}
}
