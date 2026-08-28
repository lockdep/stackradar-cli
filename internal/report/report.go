// Package report aggregates per-image findings and renders them.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

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
}

func Build(inv *k8s.Inventory, results []ImageResult, kevSet kev.Set) *Report {
	rep := &Report{Context: inv.Context, Namespaces: inv.Namespaces, PodCount: inv.PodCount, KEVChecked: kevSet != nil}
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

const (
	cReset  = "\033[0m"
	cBold   = "\033[1m"
	cRed    = "\033[31m"
	cOrange = "\033[33m"
	cDim    = "\033[2m"
)

func WriteTable(w io.Writer, rep *Report, minSev string) error {
	min, _ := ParseSeverity(minSev)
	color := isTerminal(w)
	paint := func(c, s string) string {
		if !color {
			return s
		}
		return c + s + cReset
	}
	// cell wraps a painted string so tabwriter ignores the escape codes when measuring.
	cell := func(c, s string) string {
		if !color {
			return s
		}
		return "\xff" + c + s + cReset + "\xff"
	}

	fmt.Fprintf(w, "%s\n\n", paint(cBold, fmt.Sprintf("%d images · %d pods · %d namespaces · context %s",
		len(rep.Images), rep.PodCount, len(rep.Namespaces), rep.Context)))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.StripEscape)
	fmt.Fprintln(tw, "IMAGE\tCRIT\tHIGH\tMED\tLOW\tKEV\tPODS\t")
	for _, ir := range rep.Images {
		name := ir.Image.Display()
		pods := len(ir.Image.Workloads)
		switch {
		case ir.Unreachable:
			fmt.Fprintf(tw, "%s\t·\t·\t·\t·\t·\t%d\t%s\n", name, pods, cell(cDim, "not reachable from here"))
			continue
		case ir.Error != "":
			fmt.Fprintf(tw, "%s\t·\t·\t·\t·\t·\t%d\t%s\n", name, pods, cell(cDim, "scan failed"))
			continue
		}
		c := ir.Counts
		crit := fmt.Sprint(c.Critical)
		if c.Critical > 0 {
			crit = cell(cRed, crit)
		}
		high := fmt.Sprint(c.High)
		if c.High > 0 {
			high = cell(cOrange, high)
		}
		kevCol := "-"
		if c.KEV > 0 {
			kevCol = cell(cBold+cRed, fmt.Sprint(c.KEV))
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%d\t\n", name, crit, high, c.Medium, c.Low, kevCol, pods)
	}
	tw.Flush()

	t := rep.Totals
	fmt.Fprintf(w, "\n%s %d critical · %d high · %d medium · %d low",
		paint(cBold, "Total:"), t.Critical, t.High, t.Medium, t.Low)
	if t.Unknown > 0 {
		fmt.Fprintf(w, " · %d unscored", t.Unknown)
	}
	fmt.Fprintln(w)

	if rep.Unreachable > 0 {
		fmt.Fprintf(w, "%s\n", paint(cDim, fmt.Sprintf(
			"⚠  %d image(s) live in a registry this machine cannot pull from (no credentials, or private network).\n   An in-cluster agent scans those with the cluster's own pull secrets.", rep.Unreachable)))
	}
	if rep.Errored > 0 {
		fmt.Fprintf(w, "%s\n", paint(cDim, fmt.Sprintf("⚠  %d image(s) failed to scan — run with --json to see the errors.", rep.Errored)))
	}

	if rep.KEVChecked {
		if len(rep.KEV) > 0 {
			fmt.Fprintf(w, "\n%s\n", paint(cBold+cRed, fmt.Sprintf("★ %d vulnerabilit%s in CISA's Known Exploited catalogue — actively exploited in the wild:",
				len(rep.KEV), plural(len(rep.KEV), "y", "ies"))))
			for _, h := range rep.KEV {
				fmt.Fprintf(w, "   %s  %s  →  %s\n", paint(cBold, h.CVE), h.Package, joinMax(h.Workloads, 4))
			}
		} else {
			fmt.Fprintf(w, "%s\n", paint(cDim, "✓  Nothing in CISA's Known Exploited Vulnerabilities catalogue."))
		}
	}

	// Per-image detail, worst first, honouring --min-severity.
	shown := 0
	for _, ir := range rep.Images {
		var rows []Finding
		for _, f := range ir.Findings {
			s, _ := ParseSeverity(f.Severity)
			if f.KEV || s >= min && s != Unknown {
				rows = append(rows, f)
			}
		}
		if len(rows) == 0 {
			continue
		}
		if shown == 0 {
			fmt.Fprintf(w, "\n%s\n", paint(cBold, fmt.Sprintf("Findings (≥ %s):", min)))
		}
		shown++
		fmt.Fprintf(w, "\n%s  %s\n", paint(cBold, ir.Image.Display()), paint(cDim, joinMax(ir.Image.Workloads, 3)))
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', tabwriter.StripEscape)
		limit := 15
		for i, f := range rows {
			if i == limit {
				fmt.Fprintf(tw, "   %s\n", paint(cDim, fmt.Sprintf("… %d more (use --json for the full list)", len(rows)-limit)))
				break
			}
			fix := ""
			if f.Fixed != "" {
				fix = "fix: " + f.Fixed
			}
			id := f.ID
			if f.KEV {
				id = cell(cBold+cRed, id+" ★")
			}
			fmt.Fprintf(tw, "   %s\t%s\t%s %s\t%s\n", id, sevLabel(f.Severity, f.CVSS, cell), f.Package, f.Version, cell(cDim, fix))
		}
		tw.Flush()
	}

	fmt.Fprintf(w, "\n%s\n", paint(cDim, strings.Join([]string{
		"This is a point-in-time snapshot from your laptop. Nothing about your cluster was sent anywhere",
		"except your registries, api.osv.dev and cisa.gov.",
		"",
		"Want this continuously — every cluster, re-checked the moment a new advisory lands,",
		"with a history you can hand an auditor?  →  https://stackradar.io   (free tier, no card)",
	}, "\n")))
	return nil
}

func sevLabel(sev string, cvss float64, paint func(c, s string) string) string {
	s := strings.ToUpper(sev)
	if cvss > 0 {
		s = fmt.Sprintf("%-8s %.1f", s, cvss)
	}
	switch sev {
	case "critical":
		return paint(cRed, s)
	case "high":
		return paint(cOrange, s)
	default:
		return s
	}
}

func joinMax(s []string, n int) string {
	if len(s) <= n {
		return strings.Join(s, ", ")
	}
	return strings.Join(s[:n], ", ") + fmt.Sprintf(", +%d more", len(s)-n)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
