// Package report aggregates per-image findings and renders them.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/lockdep/stackradar-cli/internal/k8s"
	"github.com/lockdep/stackradar-cli/internal/kev"
	"github.com/lockdep/stackradar-cli/internal/scan"
)

type Severity int

const (
	Unknown Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"unknown", "low", "medium", "high", "critical"}[s]
}

func ParseSeverity(s string) (Severity, bool) {
	for i := Unknown; i <= Critical; i++ {
		if i.String() == strings.ToLower(s) {
			return i, true
		}
	}
	return Unknown, false
}

func ValidateSeverity(s string) error {
	if _, ok := ParseSeverity(s); !ok {
		return fmt.Errorf("unknown severity %q (want critical|high|medium|low)", s)
	}
	return nil
}

// FromCVSS maps a CVSS v3/v4 base score to a rating.
func FromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return Critical
	case score >= 7.0:
		return High
	case score >= 4.0:
		return Medium
	case score > 0:
		return Low
	default:
		return Unknown
	}
}

type ImageResult struct {
	Image       k8s.Image
	Findings    []scan.Finding
	Err         error
	Unreachable bool
}

type Counts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	KEV      int `json:"kev"`
}

func (c *Counts) add(s Severity) {
	switch s {
	case Critical:
		c.Critical++
	case High:
		c.High++
	case Medium:
		c.Medium++
	case Low:
		c.Low++
	default:
		c.Unknown++
	}
}

func (c Counts) total() int { return c.Critical + c.High + c.Medium + c.Low + c.Unknown }

type Finding struct {
	scan.Finding
	Severity string `json:"severity"`
	KEV      bool   `json:"kev"`
}

type ImageReport struct {
	Image       k8s.Image `json:"image"`
	Counts      Counts    `json:"counts"`
	Findings    []Finding `json:"findings,omitempty"`
	Error       string    `json:"error,omitempty"`
	Unreachable bool      `json:"unreachable,omitempty"`
}

type KEVHit struct {
	CVE       string   `json:"cve"`
	Package   string   `json:"package"`
	Images    []string `json:"images"`
	Workloads []string `json:"workloads"`
}

type Report struct {
	Context     string        `json:"context"`
	Namespaces  []string      `json:"namespaces"`
	PodCount    int           `json:"pod_count"`
	Images      []ImageReport `json:"images"`
	Totals      Counts        `json:"totals"`
	KEV         []KEVHit      `json:"kev,omitempty"`
	Unreachable int           `json:"unreachable_images"`
	Errored     int           `json:"errored_images"`
	KEVChecked  bool          `json:"kev_checked"`
	OnlyFixed   bool          `json:"only_fixed,omitempty"`
}

// ThresholdError is returned when --fail-on is met; main maps it to exit 2.
type ThresholdError struct {
	Threshold string
	Count     int
}

func (e *ThresholdError) Error() string {
	if e.Threshold == "kev" {
		return fmt.Sprintf("%d finding(s) in CISA KEV (--fail-on kev)", e.Count)
	}
	return fmt.Sprintf("%d finding(s) at or above %s severity (--fail-on %s)", e.Count, e.Threshold, e.Threshold)
}

// CheckThreshold returns a *ThresholdError if rep has findings at or above
// failOn ("" disables; "kev" means any KEV hit).
func CheckThreshold(rep *Report, failOn string) error {
	if failOn == "" {
		return nil
	}
	if failOn == "kev" {
		if rep.Totals.KEV > 0 {
			return &ThresholdError{Threshold: "kev", Count: rep.Totals.KEV}
		}
		return nil
	}
	min, ok := ParseSeverity(failOn)
	if !ok {
		return fmt.Errorf("unknown severity %q", failOn)
	}
	n := 0
	t := rep.Totals
	for s, c := range map[Severity]int{Critical: t.Critical, High: t.High, Medium: t.Medium, Low: t.Low} {
		if s >= min {
			n += c
		}
	}
	if n > 0 {
		return &ThresholdError{Threshold: min.String(), Count: n}
	}
	return nil
}

type BuildOptions struct {
	// OnlyFixed drops findings without a known fixed version.
	OnlyFixed bool
}

func Build(inv *k8s.Inventory, results []ImageResult, kevSet kev.Set, opts BuildOptions) *Report {
	rep := &Report{Context: inv.Context, Namespaces: inv.Namespaces, PodCount: inv.PodCount, KEVChecked: kevSet != nil, OnlyFixed: opts.OnlyFixed}
	kevHits := map[string]*KEVHit{}
	for _, r := range results {
		ir := ImageReport{Image: r.Image, Unreachable: r.Unreachable}
		if r.Err != nil {
			ir.Error = r.Err.Error()
			if r.Unreachable {
				rep.Unreachable++
			} else {
				rep.Errored++
			}
		}
		for _, f := range r.Findings {
			if opts.OnlyFixed && f.Fixed == "" {
				continue
			}
			sev := FromCVSS(f.CVSS)
			inKEV := false
			for _, cve := range f.CVEs() {
				if kevSet.Has(cve) {
					inKEV = true
					h, ok := kevHits[cve]
					if !ok {
						h = &KEVHit{CVE: cve, Package: f.Package}
						kevHits[cve] = h
					}
					h.Images = appendUnique(h.Images, r.Image.Display())
					for _, w := range r.Image.Workloads {
						h.Workloads = appendUnique(h.Workloads, w)
					}
				}
			}
			ir.Counts.add(sev)
			rep.Totals.add(sev)
			if inKEV {
				ir.Counts.KEV++
				rep.Totals.KEV++
			}
			ir.Findings = append(ir.Findings, Finding{Finding: f, Severity: sev.String(), KEV: inKEV})
		}
		sort.SliceStable(ir.Findings, func(a, b int) bool {
			fa, fb := ir.Findings[a], ir.Findings[b]
			if fa.KEV != fb.KEV {
				return fa.KEV
			}
			return fa.CVSS > fb.CVSS
		})
		rep.Images = append(rep.Images, ir)
	}
	// Worst images first.
	sort.SliceStable(rep.Images, func(a, b int) bool {
		ca, cb := rep.Images[a].Counts, rep.Images[b].Counts
		if ca.KEV != cb.KEV {
			return ca.KEV > cb.KEV
		}
		if ca.Critical != cb.Critical {
			return ca.Critical > cb.Critical
		}
		if ca.High != cb.High {
			return ca.High > cb.High
		}
		return ca.total() > cb.total()
	})
	for _, h := range kevHits {
		sort.Strings(h.Images)
		sort.Strings(h.Workloads)
		rep.KEV = append(rep.KEV, *h)
	}
	sort.Slice(rep.KEV, func(a, b int) bool { return rep.KEV[a].CVE < rep.KEV[b].CVE })
	return rep
}

func WriteJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
