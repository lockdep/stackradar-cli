// Package ui renders scan progress on stderr. On a terminal it is a live
// bubbletea task list in the style of grype/syft (spinner → ✔, tree of
// sub-stats); elsewhere it degrades to one plain line per event.
package ui

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"
)

// Phase of one image's life inside the scan.
type Phase int

const (
	Queued Phase = iota
	Pulling
	Scanning
	Done
)

// Outcome summarises a finished image for the progress view.
type Outcome struct {
	Findings    int
	Critical    int
	High        int
	Medium      int
	Low         int
	Unknown     int
	Err         error
	Unreachable bool
}

// Progress is what the scan loop reports into.
type Progress interface {
	// ImagesListed announces the inventory (task 1 done, task 3 sized).
	ImagesListed(images, pods, namespaces int, context string)
	// KEVLoaded finishes the KEV task; n is the catalogue size, err a soft failure.
	KEVLoaded(n int, err error)
	// KEVSkipped marks the KEV task as deliberately not run.
	KEVSkipped()
	// Image moves one image to a phase; Outcome is read only when phase == Done.
	Image(ref string, phase Phase, out Outcome)
	// Note prints a free-form line (warnings that must survive the live view).
	Note(format string, a ...any)
	// Close stops the live view and leaves the final task list on screen.
	Close()
	// OnInterrupt registers what to do when the user presses Ctrl-C / Esc in the live view.
	OnInterrupt(fn func())
}

// New picks the live view when w is a terminal, otherwise the plain one.
// quiet suppresses all progress output (used for --json).
func New(w io.Writer, quiet bool) Progress {
	if quiet {
		return nopProgress{}
	}
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) && os.Getenv("TERM") != "dumb" {
		return newLive(f)
	}
	return &plain{w: w}
}

// ---------------------------------------------------------------------------
// shared state

type imageState struct {
	ref     string
	phase   Phase
	started time.Time
	out     Outcome
}

type state struct {
	mu sync.Mutex

	listed    bool
	images    int
	pods      int
	nss       int
	context   string
	listStart time.Time

	kevStart   time.Time
	kevDone    bool
	kevSkipped bool
	kevN       int
	kevErr     error

	scanStart time.Time
	scanEnd   time.Time
	byRef     map[string]*imageState
	order     []string
	done      int
	tot       Outcome

	notes []string
}

func newState() *state {
	now := time.Now()
	return &state{byRef: map[string]*imageState{}, listStart: now, kevStart: now, scanStart: now}
}

func (s *state) imagesListed(images, pods, nss int, ctx string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listed, s.images, s.pods, s.nss, s.context = true, images, pods, nss, ctx
	s.scanStart = time.Now()
}

func (s *state) image(ref string, phase Phase, out Outcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.byRef[ref]
	if !ok {
		st = &imageState{ref: ref}
		s.byRef[ref] = st
		s.order = append(s.order, ref)
	}
	if st.phase == Queued && phase != Queued {
		st.started = time.Now()
	}
	st.phase = phase
	if phase == Done {
		st.out = out
		s.done++
		s.tot.Findings += out.Findings
		s.tot.Critical += out.Critical
		s.tot.High += out.High
		s.tot.Medium += out.Medium
		s.tot.Low += out.Low
		s.tot.Unknown += out.Unknown
		if out.Unreachable {
			s.tot.Unreachable = true
		}
		if s.done == s.images {
			s.scanEnd = time.Now()
		}
	}
}

// inFlight returns images currently pulling/scanning, oldest first.
func (s *state) inFlight() []*imageState {
	var out []*imageState
	for _, ref := range s.order {
		st := s.byRef[ref]
		if st.phase == Pulling || st.phase == Scanning {
			out = append(out, st)
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].started.Before(out[b].started) })
	return out
}

func (s *state) unreachable() (n int) {
	for _, st := range s.byRef {
		if st.phase == Done && st.out.Unreachable {
			n++
		}
	}
	return n
}

func (s *state) errored() (n int) {
	for _, st := range s.byRef {
		if st.phase == Done && st.out.Err != nil && !st.out.Unreachable {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// styles (palette mirrors grype's table presenter so both tools feel alike)

var (
	styleTitle    = lipgloss.NewStyle().Bold(true)
	styleHint     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleOK       = lipgloss.NewStyle().Foreground(lipgloss.Color("34"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("178"))
	styleFail     = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleSkip     = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	styleCritical = lipgloss.NewStyle().Foreground(lipgloss.Color("198")).Bold(true)
	styleHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("178"))
	styleLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("36"))
	styleSpinner  = lipgloss.NewStyle().Foreground(lipgloss.Color("69"))
)

const (
	branch           = "├──"
	end              = "└──"
	titleWidth       = 26
	maxInFlightShown = 6
)

// ---------------------------------------------------------------------------
// live (bubbletea) view

type live struct {
	*state
	prog    *tea.Program
	wg      sync.WaitGroup
	onInt   func()
	closed  bool
	closeMu sync.Mutex
}

type tickMsg time.Time
type quitMsg struct{}

type model struct {
	s     *state
	sp    spinner.Model
	bar   progress.Model
	width int
	onInt func()
	quit  bool
}

func newLive(f *os.File) *live {
	l := &live{state: newState()}
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(styleSpinner))
	bar := progress.New(progress.WithSolidFill("69"), progress.WithoutPercentage())
	bar.Width = 30
	bar.Empty = '━'
	bar.Full = '━'
	bar.EmptyColor = "238"
	m := &model{s: l.state, sp: sp, bar: bar, width: 100}
	m.onInt = func() {
		if l.onInt != nil {
			l.onInt()
		}
	}
	l.prog = tea.NewProgram(m, tea.WithOutput(f), tea.WithInput(os.Stdin))
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		_, _ = l.prog.Run()
	}()
	return l
}

func (l *live) OnInterrupt(fn func())                   { l.onInt = fn }
func (l *live) ImagesListed(i, p, n int, ctx string)    { l.state.imagesListed(i, p, n, ctx) }
func (l *live) Image(ref string, ph Phase, out Outcome) { l.state.image(ref, ph, out) }

func (l *live) KEVLoaded(n int, err error) {
	l.mu.Lock()
	l.kevDone, l.kevN, l.kevErr = true, n, err
	l.mu.Unlock()
}

func (l *live) KEVSkipped() {
	l.mu.Lock()
	l.kevDone, l.kevSkipped = true, true
	l.mu.Unlock()
}

func (l *live) Note(format string, a ...any) {
	l.mu.Lock()
	l.notes = append(l.notes, fmt.Sprintf(format, a...))
	l.mu.Unlock()
}

func (l *live) Close() {
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	l.prog.Send(quitMsg{})
	l.wg.Wait()
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(m.sp.Tick, tick())
}

func tick() tea.Cmd {
	return tea.Tick(80*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		if msg.Width > 0 {
			m.width = msg.Width
			m.bar.Width = clamp(msg.Width-titleWidth-24, 10, 40)
		}
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc", "q":
			if m.onInt != nil {
				m.onInt()
			}
		}
		return m, nil
	case tickMsg:
		return m, tick()
	case quitMsg:
		m.quit = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.sp, cmd = m.sp.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m *model) View() string {
	s := m.s
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	row := func(icon, title, hint string) {
		fmt.Fprintf(&b, " %s %-*s %s\n", icon, titleWidth, title, hint)
	}
	ok := styleOK.Render("✔")
	spin := m.sp.View()

	// 1. inventory
	if s.listed {
		if s.context == "" {
			row(ok, "Resolved images", styleHint.Render(fmt.Sprintf("[%d from --image]", s.images)))
		} else {
			row(ok, "Listed running images", styleHint.Render(fmt.Sprintf("[%d images · %d pods · %d namespaces · %s]",
				s.images, s.pods, s.nss, s.context)))
		}
	} else {
		row(spin, "Listing running images", styleHint.Render(elapsed(s.listStart)))
	}

	// 2. KEV
	switch {
	case s.kevSkipped:
		row(styleSkip.Render("-"), "CISA KEV catalogue", styleHint.Render("[skipped]"))
	case s.kevDone && s.kevErr != nil:
		row(styleWarn.Render("⚠"), "CISA KEV catalogue", styleWarn.Render("[unavailable: "+short(s.kevErr.Error(), 60)+"]"))
	case s.kevDone:
		row(ok, "Loaded CISA KEV catalogue", styleHint.Render(fmt.Sprintf("[%d exploited CVEs]", s.kevN)))
	default:
		row(spin, "Loading CISA KEV catalogue", styleHint.Render(elapsed(s.kevStart)))
	}

	// 3. scan
	if !s.listed {
		return b.String()
	}
	finished := s.done == s.images
	if finished {
		row(ok, "Scanned images", styleHint.Render(fmt.Sprintf("[%d images in %s]", s.images, s.scanEnd.Sub(s.scanStart).Round(time.Second))))
	} else {
		pct := float64(s.done) / float64(max(1, s.images))
		hint := fmt.Sprintf("%s %s", m.bar.ViewAs(pct), styleHint.Render(fmt.Sprintf("[%d/%d]  %s", s.done, s.images, elapsed(s.scanStart))))
		row(spin, "Scanning images", hint)
	}

	// tree: severities + problems + in-flight
	var lines []string
	lines = append(lines, "by severity: "+sevSummary(s.tot))
	if u, e := s.unreachable(), s.errored(); u > 0 || e > 0 {
		var parts []string
		if u > 0 {
			parts = append(parts, fmt.Sprintf("%d not reachable from here", u))
		}
		if e > 0 {
			parts = append(parts, fmt.Sprintf("%d failed", e))
		}
		lines = append(lines, "skipped:     "+styleWarn.Render(strings.Join(parts, ", ")))
	}
	if !finished {
		inflight := s.inFlight()
		for i, st := range inflight {
			if i == maxInFlightShown {
				lines = append(lines, styleHint.Render(fmt.Sprintf("… %d more in flight", len(inflight)-i)))
				break
			}
			verb := "pulling "
			if st.phase == Scanning {
				verb = "scanning"
			}
			lines = append(lines, fmt.Sprintf("%s %s %s", styleHint.Render(verb), short(st.ref, clamp(m.width-28, 24, 110)), styleHint.Render(elapsed(st.started))))
		}
	}
	for i, ln := range lines {
		conn := branch
		if i == len(lines)-1 {
			conn = end
		}
		fmt.Fprintf(&b, "   %s %s\n", styleHint.Render(conn), ln)
	}
	for _, n := range s.notes {
		fmt.Fprintf(&b, " %s %s\n", styleWarn.Render("⚠"), n)
	}
	return b.String()
}

func sevSummary(t Outcome) string {
	paint := func(n int, st lipgloss.Style, label string) string {
		txt := fmt.Sprintf("%d %s", n, label)
		if n == 0 {
			return styleHint.Render(txt)
		}
		return st.Render(txt)
	}
	out := strings.Join([]string{
		paint(t.Critical, styleCritical, "critical"),
		paint(t.High, styleHigh, "high"),
		paint(t.Medium, styleMedium, "medium"),
		paint(t.Low, styleLow, "low"),
	}, ", ")
	if t.Unknown > 0 {
		out += styleHint.Render(fmt.Sprintf(" (%d unscored)", t.Unknown))
	}
	return out
}

func elapsed(t time.Time) string {
	d := time.Since(t)
	if d < 10*time.Second {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return d.Round(time.Second).String()
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 4 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---------------------------------------------------------------------------
// plain (non-tty) view: one line per event, no escape codes.

type plain struct {
	*state
	w  io.Writer
	mu sync.Mutex
}

func (p *plain) OnInterrupt(func()) {}

func (p *plain) ImagesListed(images, pods, nss int, ctx string) {
	if p.state == nil {
		p.state = newState()
	}
	p.state.imagesListed(images, pods, nss, ctx)
	if ctx == "" {
		p.printf("Scanning %d image(s)", images)
		return
	}
	p.printf("Found %d unique images across %d pods in %d namespaces (context %s)", images, pods, nss, ctx)
}

func (p *plain) KEVLoaded(n int, err error) {
	if err != nil {
		p.printf("warning: could not load CISA KEV catalogue (%v); continuing without it", err)
		return
	}
	p.printf("Loaded CISA KEV catalogue (%d exploited CVEs)", n)
}

func (p *plain) KEVSkipped() {}

func (p *plain) Image(ref string, ph Phase, out Outcome) {
	if p.state == nil {
		p.state = newState()
	}
	p.state.image(ref, ph, out)
	if ph != Done {
		return
	}
	p.state.mu.Lock()
	done, total := p.state.done, p.state.images
	p.state.mu.Unlock()
	suffix := fmt.Sprintf("%d findings", out.Findings)
	switch {
	case out.Unreachable:
		suffix = "not reachable from this machine"
	case out.Err != nil:
		suffix = "error: " + out.Err.Error()
	}
	p.printf("  [%d/%d] %s  %s", done, total, ref, suffix)
}

func (p *plain) Note(format string, a ...any) { p.printf(format, a...) }
func (p *plain) Close()                       {}

func (p *plain) printf(format string, a ...any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, format+"\n", a...)
}

// ---------------------------------------------------------------------------

type nopProgress struct{}

func (nopProgress) ImagesListed(int, int, int, string) {}
func (nopProgress) KEVLoaded(int, error)               {}
func (nopProgress) KEVSkipped()                        {}
func (nopProgress) Image(string, Phase, Outcome)       {}
func (nopProgress) Note(string, ...any)                {}
func (nopProgress) Close()                             {}
func (nopProgress) OnInterrupt(func())                 {}
