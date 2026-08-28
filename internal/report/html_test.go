package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lockdep/stackradar-cli/internal/k8s"
	"github.com/lockdep/stackradar-cli/internal/kev"
	"github.com/lockdep/stackradar-cli/internal/scan"
)

func fixtureReport() *Report {
	// Same shape the scanner produces: Ref is repo@digest, Tags holds the bare tag from the pod spec.
	img := func(ref, digest string, pods ...string) k8s.Image {
		i := strings.LastIndex(ref, ":")
		repo, tag := ref[:i], ref[i+1:]
		return k8s.Image{Ref: repo + "@" + digest, Digest: digest, Workloads: pods, Tags: []string{tag}}
	}
	f := func(id, pkg, ver, eco string, cvss float64, fixed string, aliases ...string) scan.Finding {
		return scan.Finding{ID: id, Package: pkg, Version: ver, Ecosystem: eco, CVSS: cvss, Fixed: fixed, Aliases: aliases,
			Summary: "Summary with </script><!-- tricky --> characters & \"quotes\""}
	}
	inv := &k8s.Inventory{Context: "prod-eu", Namespaces: []string{"monitoring", "ingress", "payments", "auth"}, PodCount: 61}
	results := []ImageResult{
		{Image: img("docker.io/grafana/grafana:12.4.2", "sha256:83749231c383a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a", "monitoring/grafana-fbfc6595c-62kln"),
			Findings: []scan.Finding{
				f("CVE-2026-31789", "openssl", "3.0.13-1", "Debian:12", 9.8, "3.0.14-1"),
				f("GHSA-abcd-1234-efgh", "golang.org/x/net", "0.27.0", "Go", 7.5, "0.33.0", "CVE-2025-22870"),
				f("CVE-2025-1111", "libc6", "2.36-9", "Debian:12", 5.3, ""),
				f("CVE-2024-9999", "zlib1g", "1.2.13", "Debian:12", 0, ""),
				f("CVE-2023-4444", "curl", "7.88.1", "Debian:12", 3.1, "7.88.2"),
			}},
		{Image: img("ghcr.io/dexidp/dex:v2.43.0", "sha256:b08a58c9731c00000000000000000000000000000000000000000000000000000", "auth/dex-7c9d-x2ll1"),
			Findings: []scan.Finding{
				f("CVE-2026-31789", "openssl", "3.0.13-1", "Debian:12", 9.8, "3.0.14-1"),
				f("CVE-2025-2222", "github.com/go-jose/go-jose/v4", "4.0.1", "Go", 8.1, "4.0.5"),
			}},
		{Image: img("registry.internal/payments-api:9f1fd70", "sha256:957da44ee38f11111111111111111111111111111111111111111111111111111", "payments/api-1", "payments/api-2", "payments/api-3"),
			Err: os.ErrPermission, Unreachable: true},
		{Image: img("quay.io/broken/thing:1", "sha256:0000000000000000000000000000000000000000000000000000000000000000", "ingress/x"),
			Err: os.ErrClosed},
	}
	kevSet := kev.Set{"CVE-2026-31789": true}
	return Build(inv, results, kevSet)
}

func TestRenderHTML(t *testing.T) {
	page, err := RenderHTML(fixtureReport(), HTMLOptions{Version: "test", GeneratedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	s := string(page)
	if strings.Contains(s, "__DATA__") || strings.Contains(s, "__TITLE__") {
		t.Fatal("placeholders left in page")
	}
	// The JSON block must not be able to close the <script> element early.
	body := s[strings.Index(s, `<script id="report-data"`):]
	body = body[:strings.Index(body, "</script>")]
	if strings.Contains(body, "</script") || strings.Contains(body, "<!--") {
		t.Fatal("unescaped script terminator inside the report JSON")
	}
	if !strings.Contains(body, `\u003c/script\u003e`) {
		t.Fatal("expected </script> in the summary to be JSON-escaped")
	}
	for _, want := range []string{"stackradar.io", `"kev":true`, "CVE-2026-31789", "prod-eu", `"version":"test"`} {
		if !strings.Contains(s, want) {
			t.Fatalf("page missing %q", want)
		}
	}
	if out := os.Getenv("STACKRADAR_HTML_FIXTURE"); out != "" {
		if err := os.WriteFile(out, page, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
