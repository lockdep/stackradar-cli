// Package scan wraps osv-scanner's container scan.
package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scanner/v2/pkg/models"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	osvschema "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Finding is one vulnerability group (a CVE and its aliases) on one package.
type Finding struct {
	ID        string   `json:"id"`
	Aliases   []string `json:"aliases,omitempty"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	Ecosystem string   `json:"ecosystem"`
	Summary   string   `json:"summary,omitempty"`
	// CVSS is the max CVSS base score osv-scanner computed for the group, 0 if unknown.
	CVSS float64 `json:"cvss"`
	// Fixed is the first fixed version if OSV lists one.
	Fixed string `json:"fixed,omitempty"`
}

// CVEs returns every CVE identifier attached to the finding, deduplicated.
// Distro-namespaced aliases such as UBUNTU-CVE-2026-31431 (the only CVE
// reference OSV attaches to Ubuntu USN records) are normalised to the bare
// CVE ID so KEV lookups see them.
func (f Finding) CVEs() []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range append([]string{f.ID}, f.Aliases...) {
		if i := strings.Index(id, "CVE-"); i > 0 && strings.HasSuffix(id[:i], "-") {
			id = id[i:]
		}
		if strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

type Scanner struct {
	probe *osvProbe
}

// New returns a scanner. osv-scanner's log lines go through a handler that
// forwards everything at Error level to warn (a failure is never silent) and
// prints debug output to stderr when verbose. Requests to api.osv.dev are
// observed through http.DefaultTransport — osv-scanner discards the
// vulnerability matcher's own error status for container scans, so a failed
// lookup would otherwise come back as an empty, clean-looking result.
//
// New installs that probe on the process-wide http.DefaultTransport and
// osv-scanner's global logger, so call it once per process.
func New(verbose bool, warn func(msg string)) *Scanner {
	c := &capture{verbose: verbose, warn: warn}
	if verbose {
		c.debug = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	}
	osvscanner.SetLogger(c)
	p := &osvProbe{next: http.DefaultTransport}
	http.DefaultTransport = p
	return &Scanner{probe: p}
}

// ErrLookupFailed is returned when the OSV.dev query for an image failed;
// the findings would otherwise silently be empty.
var ErrLookupFailed = errors.New("vulnerability lookup failed")

// Tarball scans one image archive. Scans run concurrently; a failed OSV.dev
// request anywhere during this scan's window is attributed to it, which is
// the safe direction — an outage affects every in-flight lookup, and a clean
// image mislabelled "scan failed" during an outage costs a re-run, whereas
// a lookup failure mislabelled clean would pass a gate.
func (s *Scanner) Tarball(ctx context.Context, path string) ([]Finding, error) {
	started := time.Now()
	res, err := osvscanner.DoContainerScan(osvscanner.ScannerActions{
		Image:          path,
		IsImageArchive: true,
		ExperimentalScannerActions: osvscanner.ExperimentalScannerActions{
			RequestUserAgent:   "stackradar-cli",
			TransitiveScanning: osvscanner.TransitiveScanningActions{Disabled: true},
		},
	})
	switch {
	case err == nil, errors.Is(err, osvscanner.ErrVulnerabilitiesFound):
	case errors.Is(err, osvscanner.ErrNoPackagesFound):
		return nil, nil // scratch/distroless-without-metadata: genuinely nothing to report
	default:
		return nil, err
	}
	// Packages were found but nothing matched, and at least one OSV.dev
	// request failed on the way: that is a lookup failure, not a clean image.
	if rawVulnCount(res) == 0 {
		if msg := s.probe.failureSince(started); msg != "" {
			return nil, fmt.Errorf("%w: %s", ErrLookupFailed, msg)
		}
	}
	return flatten(res), nil
}

func rawVulnCount(res models.VulnerabilityResults) int {
	n := 0
	for _, src := range res.Results {
		for _, pkg := range src.Packages {
			n += len(pkg.Vulnerabilities)
		}
	}
	return n
}

// osvProbe wraps a RoundTripper and remembers failed requests to api.osv.dev.
type osvProbe struct {
	next http.RoundTripper

	mu       sync.Mutex
	failures []failure
}

type failure struct {
	at  time.Time
	msg string
}

const osvHost = "api.osv.dev"

// failureSince returns the most recent failure recorded at or after t, or "".
func (p *osvProbe) failureSince(t time.Time) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := len(p.failures) - 1; i >= 0; i-- {
		if !p.failures[i].at.Before(t) {
			return p.failures[i].msg
		}
	}
	return ""
}

func (p *osvProbe) record(msg string) {
	p.mu.Lock()
	p.failures = append(p.failures, failure{at: time.Now(), msg: msg})
	// Only the recent past matters; keep the slice from growing across a long run.
	if len(p.failures) > 256 {
		p.failures = p.failures[len(p.failures)-256:]
	}
	p.mu.Unlock()
}

func (p *osvProbe) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := p.next.RoundTrip(req)
	if req.URL.Hostname() != osvHost {
		return resp, err
	}
	switch {
	case err != nil:
		p.record(fmt.Sprintf("%s %s: %v", req.Method, req.URL.Path, err))
	case resp.StatusCode >= 400:
		p.record(fmt.Sprintf("%s %s: HTTP %d", req.Method, req.URL.Path, resp.StatusCode))
	}
	return resp, err
}

// capture is the slog.Handler osv-scanner logs through.
type capture struct {
	verbose bool
	warn    func(string)
	debug   slog.Handler
}

func (c *capture) Enabled(_ context.Context, l slog.Level) bool {
	return c.verbose || l >= slog.LevelError
}

func (c *capture) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError && c.warn != nil {
		c.warn(r.Message)
	}
	if c.debug != nil {
		return c.debug.Handle(ctx, r)
	}
	return nil
}

func (c *capture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *capture) WithGroup(string) slog.Handler      { return c }

func flatten(res models.VulnerabilityResults) []Finding {
	var out []Finding
	for _, src := range res.Results {
		for _, pkg := range src.Packages {
			byID := map[string]*osvschema.Vulnerability{}
			for _, v := range pkg.Vulnerabilities {
				byID[v.GetId()] = v
			}
			// A Go main module compiled without version info reports "(devel)";
			// osv-scanner then matches every advisory ever filed for it. Those
			// are noise, not findings.
			if pkg.Package.Version == "(devel)" || pkg.Package.Version == "" {
				continue
			}
			for _, g := range pkg.Groups {
				if len(g.IDs) == 0 {
					continue
				}
				f := Finding{
					ID:        pickID(g.IDs, g.Aliases),
					Aliases:   dedupe(append(g.IDs, g.Aliases...)),
					Package:   pkg.Package.Name,
					Version:   pkg.Package.Version,
					Ecosystem: pkg.Package.Ecosystem,
				}
				if s, err := strconv.ParseFloat(g.MaxSeverity, 64); err == nil {
					f.CVSS = s
				}
				for _, id := range g.IDs {
					if v := byID[id]; v != nil {
						if f.Summary == "" {
							f.Summary = v.GetSummary()
						}
						if f.Fixed == "" {
							f.Fixed = firstFixed(v, pkg.Package.Ecosystem, pkg.Package.Name)
						}
					}
				}
				out = append(out, f)
			}
		}
	}
	return dedupeFindings(out)
}

// dedupeFindings collapses the same vulnerability on the same package+version
// reported from several sources (e.g. an OS package DB present in two layers).
func dedupeFindings(in []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range in {
		k := f.ID + "|" + f.Ecosystem + "|" + f.Package + "|" + f.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, f)
	}
	return out
}

// pickID prefers the CVE over GHSA/vendor ids so the table speaks the language
// people search for.
func pickID(ids, aliases []string) string {
	for _, id := range append(append([]string{}, ids...), aliases...) {
		if strings.HasPrefix(id, "CVE-") {
			return id
		}
	}
	return ids[0]
}

// firstFixed returns the first non-commit fixed version for the package this
// finding is about. An advisory's affected list spans every ecosystem and
// package the advisory touches (a Debian CVE record lists each release, a
// DSA may cover several source packages), so only entries whose package
// matches are considered — otherwise nginx on Debian 12 would show the
// Debian 13 fix, or another package's fix, or a fix where there is none.
func firstFixed(v *osvschema.Vulnerability, ecosystem, name string) string {
	for _, a := range v.GetAffected() {
		if p := a.GetPackage(); p != nil && !samePackage(p, ecosystem, name) {
			continue
		}
		for _, r := range a.GetRanges() {
			for _, e := range r.GetEvents() {
				if fx := e.GetFixed(); fx != "" && !looksLikeCommit(fx) {
					return fx
				}
			}
		}
	}
	return ""
}

// samePackage compares an advisory's affected package with the scanned one.
// Ecosystem suffixes such as "Debian:12" vs "Debian" and case differences in
// names (Maven/NuGet/PyPI) are tolerated.
func samePackage(p *osvschema.Package, ecosystem, name string) bool {
	if !strings.EqualFold(p.GetName(), name) {
		return false
	}
	pe, e := p.GetEcosystem(), ecosystem
	if pe == "" || e == "" || strings.EqualFold(pe, e) {
		return true
	}
	// A release-qualified ecosystem on one side only ("Debian:12" vs "Debian")
	// still refers to the same distribution family.
	base := func(s string) string { return strings.SplitN(s, ":", 2)[0] }
	return (strings.Contains(pe, ":") != strings.Contains(e, ":")) && strings.EqualFold(base(pe), base(e))
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func looksLikeCommit(s string) bool {
	if len(s) < 20 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
