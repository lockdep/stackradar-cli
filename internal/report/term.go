package report

import (
	"slices"
	"sort"

	"fmt"
	"github.com/lockdep/stackradar-cli/internal/pull"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"golang.org/x/term"
)

// Palette mirrors grype's table presenter so the two tools read the same.
type styles struct {
	color bool

	title, hint, ok, warn        lipgloss.Style
	critical, high, medium, low  lipgloss.Style
	unknown, kev, kevBadge, link lipgloss.Style
}

func newStyles(w io.Writer) styles {
	color := isTerminal(w)
	st := styles{color: color}
	if !color {
		// Zero-value styles render plain text.
		return st
	}
	// Renderer bound to w so lipgloss picks the right colour profile for it
	// (stdout may be a pipe while stderr is a tty, or vice versa).
	r := lipgloss.NewRenderer(w)
	st.title = r.NewStyle().Bold(true)
	st.hint = r.NewStyle().Foreground(lipgloss.Color("240"))
	st.ok = r.NewStyle().Foreground(lipgloss.Color("34"))
	st.warn = r.NewStyle().Foreground(lipgloss.Color("178"))
	st.critical = r.NewStyle().Foreground(lipgloss.Color("198")).Bold(true)
	st.high = r.NewStyle().Foreground(lipgloss.Color("203"))
	st.medium = r.NewStyle().Foreground(lipgloss.Color("178"))
	st.low = r.NewStyle().Foreground(lipgloss.Color("36"))
	st.unknown = r.NewStyle().Foreground(lipgloss.Color("12"))
	st.kev = r.NewStyle().Foreground(lipgloss.Color("198")).Bold(true)
	st.kevBadge = r.NewStyle().Foreground(lipgloss.Color("198")).Reverse(true).Bold(true)
	st.link = r.NewStyle().Foreground(lipgloss.Color("69")).Underline(true)
	return st
}

func (s styles) sev(sev string) lipgloss.Style {
	switch sev {
	case "critical":
		return s.critical
	case "high":
		return s.high
	case "medium":
		return s.medium
	case "low":
		return s.low
	}
	return s.unknown
}

// count renders a severity count, dimmed when zero.
func (s styles) count(n int, st lipgloss.Style) string {
	if n == 0 {
		return s.hint.Render("0")
	}
	return st.Render(fmt.Sprint(n))
}

func isTerminal(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

func newTable(w io.Writer, columns []string) *tablewriter.Table {
	return tablewriter.NewTable(w,
		tablewriter.WithHeader(columns),
		tablewriter.WithHeaderAlignment(tw.AlignLeft),
		tablewriter.WithHeaderAutoWrap(tw.WrapNone),
		tablewriter.WithRowAutoWrap(tw.WrapNone),
		tablewriter.WithRenderer(renderer.NewBlueprint()),
		tablewriter.WithBehavior(tw.Behavior{TrimSpace: tw.On, AutoHide: tw.On}),
		tablewriter.WithPadding(tw.Padding{Right: "  "}),
		tablewriter.WithRendition(tw.Rendition{
			Symbols: tw.NewSymbols(tw.StyleNone),
			Settings: tw.Settings{Lines: tw.Lines{
				ShowTop: tw.Off, ShowBottom: tw.Off, ShowHeaderLine: tw.Off, ShowFooterLine: tw.Off,
			}},
		}),
	)
}

// WriteTable renders the human report: summary table (worst image first),
// totals, KEV callout, then per-image findings down to minSev.
func WriteTable(w io.Writer, rep *Report, minSev string) error {
	min, _ := ParseSeverity(minSev)
	st := newStyles(w)

	if rep.Context == "" {
		fmt.Fprintf(w, "%s\n\n", st.title.Render(fmt.Sprintf("%d image%s", len(rep.Images), plural(len(rep.Images), "", "s"))))
	} else {
		fmt.Fprintf(w, "%s\n\n", st.title.Render(fmt.Sprintf("%d images · %d pods · %d namespaces · context %s",
			len(rep.Images), rep.PodCount, len(rep.Namespaces), rep.Context)))
	}

	// --- summary table ------------------------------------------------------
	t := newTable(w, []string{"Image", "Critical", "High", "Medium", "Low", "KEV", "Pods", ""})
	for _, ir := range rep.Images {
		name := ir.Image.Name()
		pods := "" // empty when no cluster; the column then auto-hides
		if len(ir.Image.Workloads) > 0 {
			pods = fmt.Sprint(len(ir.Image.Workloads))
		}
		dot := st.hint.Render("·")
		switch {
		case ir.Unreachable:
			why := "not reachable from here"
			if ir.Reason != "" {
				why += ": " + ir.Reason
			}
			_ = t.Append(name, dot, dot, dot, dot, dot, pods, st.hint.Render(why))
			continue
		case ir.Error != "":
			_ = t.Append(name, dot, dot, dot, dot, dot, pods, st.warn.Render("scan failed"))
			continue
		}
		c := ir.Counts
		kevCol := st.hint.Render("-")
		if c.KEV > 0 {
			kevCol = st.kevBadge.Render(fmt.Sprintf(" %d ", c.KEV))
		}
		_ = t.Append(name,
			st.count(c.Critical, st.critical),
			st.count(c.High, st.high),
			st.count(c.Medium, st.medium),
			st.count(c.Low, st.low),
			kevCol, pods, "")
	}
	if err := t.Render(); err != nil {
		return err
	}

	// --- totals ---------------------------------------------------------------
	tt := rep.Totals
	fmt.Fprintf(w, "\n%s %s, %s, %s, %s",
		st.title.Render("Total:"),
		st.sev("critical").Render(fmt.Sprintf("%d critical", tt.Critical)),
		st.sev("high").Render(fmt.Sprintf("%d high", tt.High)),
		st.sev("medium").Render(fmt.Sprintf("%d medium", tt.Medium)),
		st.sev("low").Render(fmt.Sprintf("%d low", tt.Low)))
	if tt.Unknown > 0 {
		fmt.Fprintf(w, " %s", st.hint.Render(fmt.Sprintf("(%d unscored)", tt.Unknown)))
	}
	fmt.Fprintln(w)

	if rep.Unreachable > 0 {
		fmt.Fprintf(w, "%s %s\n", st.warn.Render("⚠"), st.hint.Render(unreachableHint(rep)))
	}
	if rep.Errored > 0 {
		fmt.Fprintf(w, "%s %s\n", st.warn.Render("⚠"), st.hint.Render(fmt.Sprintf(
			"%d image(s) failed to scan — run with -o json to see the errors.", rep.Errored)))
	}

	// --- KEV callout ----------------------------------------------------------
	if rep.KEVChecked {
		if len(rep.KEV) > 0 {
			fmt.Fprintf(w, "\n%s %s\n", st.kevBadge.Render(" KEV "), st.kev.Render(fmt.Sprintf(
				"%d vulnerabilit%s in CISA's Known Exploited Vulnerabilities catalogue — actively exploited in the wild",
				len(rep.KEV), plural(len(rep.KEV), "y", "ies"))))
			kt := newTable(w, []string{"", "Vulnerability", "Package", "Image", "Workloads"})
			for _, h := range rep.KEV {
				_ = kt.Append("", st.kev.Render(h.CVE), h.Package, joinMax(h.Images, 2), joinMax(h.Workloads, 4))
			}
			if err := kt.Render(); err != nil {
				return err
			}
		} else {
			fmt.Fprintf(w, "%s %s\n", st.ok.Render("✔"), st.hint.Render("Nothing in CISA's Known Exploited Vulnerabilities catalogue."))
		}
	}

	// --- per-image findings, worst first, honouring --min-severity ------------
	shown := 0
	for _, ir := range rep.Images {
		if minSev == "none" {
			break
		}
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
			fmt.Fprintf(w, "\n%s %s\n", st.title.Render("Findings"), st.hint.Render(fmt.Sprintf("(≥ %s; --min-severity to change)", min)))
		}
		shown++
		fmt.Fprintf(w, "\n%s  %s\n", st.title.Render(ir.Image.Display()), st.hint.Render(joinMax(ir.Image.Workloads, 3)))
		ft := newTable(w, []string{"", "Name", "Installed", "Fixed In", "Type", "Vulnerability", "Severity", "CVSS", ""})
		const limit = 15
		for i, f := range rows {
			if i == limit {
				_ = ft.Append("", st.hint.Render(fmt.Sprintf("… %d more (-o json for the full list)", len(rows)-limit)), "", "", "", "", "", "", "")
				break
			}
			cvss := st.hint.Render("N/A")
			if f.CVSS > 0 {
				cvss = fmt.Sprintf("%.1f", f.CVSS)
			}
			badge := ""
			if f.KEV {
				badge = st.kevBadge.Render(" KEV ")
			}
			_ = ft.Append("", f.Package, f.Version, f.Fixed, f.Ecosystem, f.ID,
				st.sev(f.Severity).Render(displaySeverity(f.Severity)), cvss, badge)
		}
		if err := ft.Render(); err != nil {
			return err
		}
	}

	fmt.Fprintln(w)
	footer := []string{
		"This is a point-in-time snapshot from your laptop. Nothing about your cluster was sent anywhere",
		"except your registries, api.osv.dev and cisa.gov.",
	}
	if n := len(rep.PullSecretsUsed); n > 0 {
		footer = append(footer, fmt.Sprintf("Registry credentials were read from %d cluster imagePullSecret%s (%s) and used in memory only.",
			n, plural(n, "", "s"), joinMax(rep.PullSecretsUsed, 3)))
	}
	footer = append(footer, "")
	for _, line := range append(footer, []string{
		"Want this continuously — every cluster, re-checked the moment a new advisory lands,",
		"with a history you can hand an auditor?  →  " + st.link.Render("https://stackradar.io") + st.hint.Render("   (free tier, no card)"),
	}...) {
		fmt.Fprintln(w, st.hint.Render(line))
	}
	return nil
}

// unreachableHint explains why images could not be pulled, grouped by the
// dominant cause, with the command that fixes it where there is one.
func unreachableHint(rep *Report) string {
	byReason := map[string][]string{} // reason -> registries
	for _, ir := range rep.Images {
		if !ir.Unreachable {
			continue
		}
		reg := pull.Registry(ir.Image.Ref)
		r := ir.Reason
		if r == "" {
			r = "unknown"
		}
		if !slices.Contains(byReason[r], reg) {
			byReason[r] = append(byReason[r], reg)
		}
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("%d image(s) could not be pulled from this machine.", rep.Unreachable))
	reasons := make([]string, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		regs := strings.Join(byReason[r], ", ")
		switch {
		case strings.HasPrefix(r, "credentials rejected"):
			lines = append(lines, fmt.Sprintf("  %s — no credentials for this registry, or the stored login expired. Run `docker login %s`", regs, byReason[r][0]))
			if strings.HasSuffix(byReason[r][0], "digitalocean.com") {
				lines[len(lines)-1] += " (or `doctl registry login`)"
			}
			lines[len(lines)-1] += "."
		case strings.HasPrefix(r, "access denied"), strings.HasPrefix(r, "not found"):
			lines = append(lines, fmt.Sprintf("  %s — %s: no credentials found for this registry, or the account cannot read the repo. Run `docker login %s`.", regs, r, byReason[r][0]))
		case r == "cannot resolve host":
			lines = append(lines, fmt.Sprintf("  %s — not resolvable from here (private network?).", regs))
		default:
			lines = append(lines, fmt.Sprintf("  %s — %s.", regs, r))
		}
	}
	if rep.PullSecretsOffered {
		lines = append(lines, "  The cluster has imagePullSecrets for these pods. Re-run with --use-pull-secrets to pull with them",
			"  (read via your kubeconfig, used in memory only, never written).")
	} else if len(rep.PullSecretsUsed) > 0 {
		lines = append(lines, "  The cluster's imagePullSecrets were used too and did not cover these.")
	}
	return strings.Join(lines, "\n")
}

func displaySeverity(s string) string {
	if s == "unknown" {
		return "Unscored"
	}
	return strings.ToUpper(s[:1]) + s[1:]
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
