// Package scan wraps osv-scanner's container scan.
package scan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"

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

type Scanner struct{}

// New returns a scanner. osv-scanner logs through its own slog handler; it is
// discarded unless verbose, in which case it goes to stderr.
func New(verbose bool) *Scanner {
	if verbose {
		osvscanner.SetLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	} else {
		osvscanner.SetLogger(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	return &Scanner{}
}

func (s *Scanner) Tarball(ctx context.Context, path string) ([]Finding, error) {
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
	return flatten(res), nil
}

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
