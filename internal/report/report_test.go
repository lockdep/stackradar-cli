package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/lockdep/stackradar-cli/internal/k8s"
	"github.com/lockdep/stackradar-cli/internal/kev"
	"github.com/lockdep/stackradar-cli/internal/scan"
)

func TestFromCVSS(t *testing.T) {
	cases := map[float64]Severity{
		0: Unknown, -1: Unknown,
		0.1: Low, 3.9: Low,
		4.0: Medium, 6.9: Medium,
		7.0: High, 8.9: High,
		9.0: Critical, 10: Critical,
	}
	for in, want := range cases {
		if got := FromCVSS(in); got != want {
			t.Errorf("FromCVSS(%v)=%s want %s", in, got, want)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"critical", "HIGH", "Medium", "low", "unknown"} {
		sev, ok := ParseSeverity(s)
		if !ok || sev.String() != strings.ToLower(s) {
			t.Errorf("ParseSeverity(%q) = %s,%v", s, sev, ok)
		}
	}
	if _, ok := ParseSeverity("severe"); ok {
		t.Error("accepted bogus severity")
	}
	if err := ValidateSeverity("nope"); err == nil || !strings.Contains(err.Error(), `"nope"`) {
		t.Errorf("ValidateSeverity error = %v", err)
	}
	if err := ValidateSeverity("high"); err != nil {
		t.Error(err)
	}
}

func img(ref string, pods ...string) k8s.Image {
	return k8s.Image{Ref: ref, Workloads: pods}
}

func finding(id string, cvss float64, aliases ...string) scan.Finding {
	return scan.Finding{ID: id, Package: "pkg-" + id, Version: "1", CVSS: cvss, Aliases: aliases}
}

func TestBuild(t *testing.T) {
	inv := &k8s.Inventory{Context: "ctx", Namespaces: []string{"a", "b"}, PodCount: 5}
	results := []ImageResult{
		// Lots of findings but nothing critical/KEV: should sort below the KEV image.
		{Image: img("many", "a/p1"), Findings: []scan.Finding{
			finding("CVE-1", 8.0), finding("CVE-2", 7.0), finding("CVE-3", 5.0), finding("CVE-4", 2.0), finding("CVE-5", 0),
		}},
		// One finding, but it is in KEV (via alias) -> worst image overall.
		{Image: img("kev", "b/p1", "b/p2"), Findings: []scan.Finding{
			finding("CVE-9", 3.0), finding("GHSA-x", 9.5, "CVE-KEV"),
		}},
		// A second image with the same KEV CVE: hit aggregates images + workloads.
		{Image: img("kev2", "b/p2", "b/p3"), Findings: []scan.Finding{finding("CVE-KEV", 9.5)}},
		{Image: img("unreach", "a/p2"), Err: errors.New("401"), Unreachable: true},
		{Image: img("broken"), Err: errors.New("boom")},
	}
	rep := Build(inv, results, kev.Set{"CVE-KEV": true})

	if rep.Context != "ctx" || rep.PodCount != 5 || !rep.KEVChecked {
		t.Fatalf("header: %+v", rep)
	}
	if rep.Unreachable != 1 || rep.Errored != 1 {
		t.Fatalf("unreachable=%d errored=%d", rep.Unreachable, rep.Errored)
	}
	if got := (Counts{Critical: 2, High: 2, Medium: 1, Low: 2, Unknown: 1, KEV: 2}); rep.Totals != got {
		t.Fatalf("totals %+v", rep.Totals)
	}

	var order []string
	for _, ir := range rep.Images {
		order = append(order, ir.Image.Ref)
	}
	// kev and kev2 tie on KEV=1, Critical=1, High=0; kev has more total findings.
	if want := "kev kev2 many unreach broken"; strings.Join(order, " ") != want {
		t.Fatalf("image order %v, want %s", order, want)
	}

	// Within an image: KEV first, then CVSS descending.
	kevImg := rep.Images[0]
	if kevImg.Findings[0].ID != "GHSA-x" || !kevImg.Findings[0].KEV || kevImg.Findings[0].Severity != "critical" {
		t.Fatalf("first finding %+v", kevImg.Findings[0])
	}
	many := rep.Images[2]
	if many.Findings[0].ID != "CVE-1" || many.Findings[4].ID != "CVE-5" || many.Findings[4].Severity != "unknown" {
		t.Fatalf("findings order %+v", many.Findings)
	}
	if many.Counts != (Counts{High: 2, Medium: 1, Low: 1, Unknown: 1}) {
		t.Fatalf("counts %+v", many.Counts)
	}

	if len(rep.KEV) != 1 {
		t.Fatalf("kev hits %+v", rep.KEV)
	}
	h := rep.KEV[0]
	if h.CVE != "CVE-KEV" || h.Package != "pkg-GHSA-x" {
		t.Fatalf("hit %+v", h)
	}
	if strings.Join(h.Images, ",") != "kev,kev2" || strings.Join(h.Workloads, ",") != "b/p1,b/p2,b/p3" {
		t.Fatalf("hit aggregation images=%v workloads=%v", h.Images, h.Workloads)
	}
	if rep.Images[3].Error != "401" || !rep.Images[3].Unreachable || rep.Images[4].Error != "boom" {
		t.Fatalf("errors not carried: %+v %+v", rep.Images[3], rep.Images[4])
	}
}

func TestBuildWithoutKEV(t *testing.T) {
	rep := Build(&k8s.Inventory{}, []ImageResult{{Image: img("x"), Findings: []scan.Finding{finding("CVE-KEV", 9.5)}}}, nil)
	if rep.KEVChecked || rep.Totals.KEV != 0 || len(rep.KEV) != 0 || rep.Images[0].Findings[0].KEV {
		t.Fatalf("nil KEV set must not flag anything: %+v", rep)
	}
}

func TestWriteJSON(t *testing.T) {
	rep := Build(&k8s.Inventory{Context: "c"}, []ImageResult{{Image: img("x"), Err: errors.New("boom")}}, nil)
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Context != "c" || len(back.Images) != 1 || back.Images[0].Error != "boom" {
		t.Fatalf("round trip: %+v", back)
	}
}

func tableFor(t *testing.T, rep *Report, minSev string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteTable(&buf, rep, minSev); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func TestWriteTable(t *testing.T) {
	inv := &k8s.Inventory{Context: "prod", Namespaces: []string{"a"}, PodCount: 3}
	results := []ImageResult{
		{Image: img("docker.io/library/nginx:1", "a/nginx"), Findings: []scan.Finding{
			{ID: "CVE-CRIT", Package: "openssl", Version: "1", CVSS: 9.8, Fixed: "2"},
			{ID: "CVE-MED", Package: "zlib", Version: "1", CVSS: 5.0},
			{ID: "CVE-LOW", Package: "curl", Version: "1", CVSS: 2.0},
			{ID: "CVE-NONE", Package: "bash", Version: "1"},
		}},
		{Image: img("reg/private:1", "a/priv"), Err: errors.New("401"), Unreachable: true},
		{Image: img("reg/broken:1", "a/broken"), Err: errors.New("boom")},
	}
	rep := Build(inv, results, kev.Set{"CVE-LOW": true})

	out := tableFor(t, rep, "high")
	for _, want := range []string{
		"3 images · 3 pods · 1 namespaces · context prod",
		"IMAGE", "not reachable from here", "scan failed",
		"1 critical · 0 high · 1 medium · 1 low · 1 unscored",
		"1 image(s) live in a registry", "1 image(s) failed to scan",
		"1 vulnerability in CISA", "CVE-LOW", "a/nginx",
		"Findings (≥ high):", "CVE-CRIT", "fix: 2", "CVE-LOW ★", // KEV shown even below the threshold
	} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"CVE-MED", "CVE-NONE", "\x1b["} {
		if strings.Contains(out, unwanted) {
			t.Errorf("table should not contain %q\n%s", unwanted, out)
		}
	}

	// Lower threshold pulls in medium; unscored stays hidden.
	out = tableFor(t, rep, "medium")
	if !strings.Contains(out, "CVE-MED") || strings.Contains(out, "CVE-NONE") {
		t.Errorf("min=medium wrong rows\n%s", out)
	}

	// Nothing above the bar and no KEV: no findings section at all.
	quiet := Build(inv, []ImageResult{{Image: img("x"), Findings: []scan.Finding{{ID: "CVE-LOW", CVSS: 2}}}}, kev.Set{})
	out = tableFor(t, quiet, "high")
	if strings.Contains(out, "Findings (") || !strings.Contains(out, "Nothing in CISA") {
		t.Errorf("quiet table\n%s", out)
	}
}

func TestWriteTableTruncatesLongLists(t *testing.T) {
	var fs []scan.Finding
	for i := 0; i < 20; i++ {
		fs = append(fs, scan.Finding{ID: "CVE-" + strings.Repeat("9", 2) + string(rune('a'+i)), CVSS: 9.0})
	}
	rep := Build(&k8s.Inventory{}, []ImageResult{{Image: img("x"), Findings: fs}}, nil)
	out := tableFor(t, rep, "high")
	if !strings.Contains(out, "… 5 more") {
		t.Errorf("expected truncation notice\n%s", out)
	}
}

func TestHelpers(t *testing.T) {
	if got := joinMax([]string{"a", "b", "c"}, 3); got != "a, b, c" {
		t.Error(got)
	}
	if got := joinMax([]string{"a", "b", "c", "d", "e"}, 2); got != "a, b, +3 more" {
		t.Error(got)
	}
	if got := joinMax(nil, 2); got != "" {
		t.Error(got)
	}
	if plural(1, "y", "ies") != "y" || plural(2, "y", "ies") != "ies" || plural(0, "y", "ies") != "ies" {
		t.Error("plural")
	}
	s := appendUnique(nil, "a")
	s = appendUnique(s, "a")
	s = appendUnique(s, "b")
	if strings.Join(s, "") != "ab" {
		t.Error(s)
	}
	if got := sevLabel("critical", 9.8, func(_, s string) string { return "<" + s + ">" }); got != "<CRITICAL 9.8>" {
		t.Error(got)
	}
	if got := sevLabel("low", 0, func(_, s string) string { return "<" + s + ">" }); got != "LOW" {
		t.Error(got)
	}
}
