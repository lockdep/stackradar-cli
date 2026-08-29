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

// CVEs returns every CVE identifier attached to the finding.
func (f Finding) CVEs() []string {
	var out []string
	for _, id := range append([]string{f.ID}, f.Aliases...) {
		if strings.HasPrefix(id, "CVE-") {
			out = append(out, id)
		}
	}
	return out
}

type Scanner struct {
	// mu serialises DoContainerScan so the OSV.dev probe below can attribute
	// failed requests to one image. Pulls — the slow, network-bound part —
	// still run in parallel.
	mu    sync.Mutex
	probe *osvProbe
}

// New returns a scanner. osv-scanner's log lines go through a handler that
// forwards everything at Error level to warn (a failure is never silent) and
// prints debug output to stderr when verbose. Requests to api.osv.dev are
// observed through http.DefaultTransport — osv-scanner discards the
// vulnerability matcher's own error status for container scans, so a failed
// lookup would otherwise come back as an empty, clean-looking result.
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

func (s *Scanner) Tarball(ctx context.Context, path string) ([]Finding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.probe.reset()
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
		if msg := s.probe.failure(); msg != "" {
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
	failures []string
}

const osvHost = "api.osv.dev"

func (p *osvProbe) reset() {
	p.mu.Lock()
	p.failures = nil
	p.mu.Unlock()
}

// failure returns the last recorded failure, or "".
func (p *osvProbe) failure() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.failures) == 0 {
		return ""
	}
	return p.failures[len(p.failures)-1]
}

func (p *osvProbe) record(msg string) {
	p.mu.Lock()
	p.failures = append(p.failures, msg)
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
							f.Fixed = firstFixed(v)
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

func firstFixed(v *osvschema.Vulnerability) string {
	for _, a := range v.GetAffected() {
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
