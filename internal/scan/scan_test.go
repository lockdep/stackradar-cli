package scan

import (
	"reflect"
	"testing"

	"github.com/google/osv-scanner/v2/pkg/models"
	osvschema "github.com/ossf/osv-schema/bindings/go/osvschema"
)

func vuln(id, summary string, fixed ...string) *osvschema.Vulnerability {
	var events []*osvschema.Event
	for _, f := range fixed {
		events = append(events, &osvschema.Event{Fixed: f})
	}
	return &osvschema.Vulnerability{
		Id:       id,
		Summary:  summary,
		Affected: []*osvschema.Affected{{Ranges: []*osvschema.Range{{Events: events}}}},
	}
}

func pkgVulns(name, version, eco string, vulns []*osvschema.Vulnerability, groups ...models.GroupInfo) models.PackageVulns {
	return models.PackageVulns{
		Package:         models.PackageInfo{Name: name, Version: version, Ecosystem: eco},
		Vulnerabilities: vulns,
		Groups:          groups,
	}
}

func TestFlatten(t *testing.T) {
	res := models.VulnerabilityResults{Results: []models.PackageSource{
		{Packages: []models.PackageVulns{
			// Group with a GHSA id and a CVE alias: CVE wins as the display id,
			// summary and fix come from the first vuln in the group with one.
			pkgVulns("golang.org/x/net", "0.27.0", "Go",
				[]*osvschema.Vulnerability{
					vuln("GHSA-aaaa-bbbb-cccc", "", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"), // commit-hash fix, skipped
					vuln("GO-2025-0001", "HTTP/2 bad thing", "0.33.0"),
				},
				models.GroupInfo{IDs: []string{"GHSA-aaaa-bbbb-cccc", "GO-2025-0001"}, Aliases: []string{"CVE-2025-22870"}, MaxSeverity: "7.5"},
			),
			// "(devel)" Go main module: every advisory ever matches. Must be dropped.
			pkgVulns("github.com/acme/app", "(devel)", "Go",
				[]*osvschema.Vulnerability{vuln("GO-2020-0001", "noise", "1.0.0")},
				models.GroupInfo{IDs: []string{"GO-2020-0001"}, MaxSeverity: "9.9"},
			),
			// Empty version: also dropped.
			pkgVulns("libfoo", "", "Debian:12",
				[]*osvschema.Vulnerability{vuln("CVE-2020-1", "x")},
				models.GroupInfo{IDs: []string{"CVE-2020-1"}},
			),
			// Group with no ids is skipped; unparsable severity leaves CVSS at 0.
			pkgVulns("openssl", "3.0.13-1", "Debian:12",
				[]*osvschema.Vulnerability{vuln("CVE-2026-31789", "openssl thing", "3.0.14-1")},
				models.GroupInfo{},
				models.GroupInfo{IDs: []string{"CVE-2026-31789"}, MaxSeverity: "n/a"},
			),
		}},
		// Same package+version+id from a second source (another layer): deduped.
		{Packages: []models.PackageVulns{
			pkgVulns("openssl", "3.0.13-1", "Debian:12",
				[]*osvschema.Vulnerability{vuln("CVE-2026-31789", "openssl thing", "3.0.14-1")},
				models.GroupInfo{IDs: []string{"CVE-2026-31789"}, MaxSeverity: "9.8"},
			),
		}},
	}}

	got := flatten(res)
	want := []Finding{
		{ID: "CVE-2025-22870", Aliases: []string{"GHSA-aaaa-bbbb-cccc", "GO-2025-0001", "CVE-2025-22870"},
			Package: "golang.org/x/net", Version: "0.27.0", Ecosystem: "Go", Summary: "HTTP/2 bad thing", CVSS: 7.5, Fixed: "0.33.0"},
		{ID: "CVE-2026-31789", Aliases: []string{"CVE-2026-31789"},
			Package: "openssl", Version: "3.0.13-1", Ecosystem: "Debian:12", Summary: "openssl thing", CVSS: 0, Fixed: "3.0.14-1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("flatten mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestPickID(t *testing.T) {
	cases := []struct {
		ids, aliases []string
		want         string
	}{
		{[]string{"CVE-2024-1"}, nil, "CVE-2024-1"},
		{[]string{"GHSA-x", "CVE-2024-2"}, nil, "CVE-2024-2"},
		{[]string{"GHSA-x"}, []string{"CVE-2024-3"}, "CVE-2024-3"},
		{[]string{"GHSA-x", "GO-2024-1"}, []string{"PYSEC-1"}, "GHSA-x"},
	}
	for _, c := range cases {
		if got := pickID(c.ids, c.aliases); got != c.want {
			t.Errorf("pickID(%v,%v)=%q want %q", c.ids, c.aliases, got, c.want)
		}
	}
}

func TestFirstFixed(t *testing.T) {
	if got := firstFixed(vuln("x", "")); got != "" {
		t.Errorf("no events: got %q", got)
	}
	if got := firstFixed(vuln("x", "", "", "abcdefabcdefabcdefabcdefabcdefabcdefabcd", "1.2.3", "1.2.4")); got != "1.2.3" {
		t.Errorf("want first non-commit fixed, got %q", got)
	}
	// Ranges spread over multiple affected entries.
	v := &osvschema.Vulnerability{Affected: []*osvschema.Affected{
		{Ranges: []*osvschema.Range{{Events: []*osvschema.Event{{Introduced: "0"}}}}},
		{Ranges: []*osvschema.Range{{Events: []*osvschema.Event{{Fixed: "2.0.0"}}}}},
	}}
	if got := firstFixed(v); got != "2.0.0" {
		t.Errorf("got %q", got)
	}
}

func TestLooksLikeCommit(t *testing.T) {
	cases := map[string]bool{
		"1.2.3":  false,
		"abcdef": false,
		"abcdefabcdefabcdefabcdefabcdefabcdefabcd": true,
		"ABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD": false, // uppercase is not what OSV emits
		"abcdefabcdefabcdefabcdefabcdefabcdefabcg": false,
		"1.2.3-really-long-prerelease-string-here": false,
	}
	for in, want := range cases {
		if got := looksLikeCommit(in); got != want {
			t.Errorf("looksLikeCommit(%q)=%v want %v", in, got, want)
		}
	}
}

func TestDedupeFindings(t *testing.T) {
	a := Finding{ID: "CVE-1", Ecosystem: "Debian:12", Package: "openssl", Version: "1"}
	b := a
	b.Version = "2"
	c := a
	c.Ecosystem = "Debian:11"
	got := dedupeFindings([]Finding{a, a, b, c, a})
	if !reflect.DeepEqual(got, []Finding{a, b, c}) {
		t.Fatalf("got %+v", got)
	}
	if got := dedupeFindings(nil); got != nil {
		t.Fatalf("nil in, want nil out, got %+v", got)
	}
}

func TestFindingCVEs(t *testing.T) {
	f := Finding{ID: "GHSA-x", Aliases: []string{"CVE-2024-1", "GO-2024-1", "CVE-2024-2"}}
	if got := f.CVEs(); !reflect.DeepEqual(got, []string{"CVE-2024-1", "CVE-2024-2"}) {
		t.Fatalf("got %v", got)
	}
	if got := (Finding{ID: "CVE-1"}).CVEs(); !reflect.DeepEqual(got, []string{"CVE-1"}) {
		t.Fatalf("got %v", got)
	}
	if got := (Finding{ID: "GHSA-x"}).CVEs(); got != nil {
		t.Fatalf("got %v", got)
	}
	// Ubuntu USN records only carry the CVE as a distro-namespaced alias;
	// it must still resolve to the bare CVE (and not be duplicated when both
	// forms are present) so the KEV check can match it.
	usn := Finding{ID: "USN-8226-1", Aliases: []string{"USN-8226-1", "UBUNTU-CVE-2026-31431"}}
	if got := usn.CVEs(); !reflect.DeepEqual(got, []string{"CVE-2026-31431"}) {
		t.Fatalf("got %v", got)
	}
	both := Finding{ID: "CVE-2026-31431", Aliases: []string{"UBUNTU-CVE-2026-31431", "DEBIAN-CVE-2026-31431"}}
	if got := both.CVEs(); !reflect.DeepEqual(got, []string{"CVE-2026-31431"}) {
		t.Fatalf("got %v", got)
	}
}
