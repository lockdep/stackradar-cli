package ui

import (
	"errors"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"
)

// ErrCancelled is returned by PickContext when the user backs out.
var ErrCancelled = errors.New("cancelled")

// CanPrompt reports whether an interactive picker can be shown: both stdin
// and w must be terminals.
func CanPrompt(w *os.File) bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(w.Fd())) && os.Getenv("TERM") != "dumb"
}

// PickContext shows a single-select list of kubeconfig contexts on w with the
// cursor on current, so Enter picks the current context. Returns the chosen
// name, or ErrCancelled on Esc / Ctrl-C / q.
func PickContext(w *os.File, contexts []string, current string) (string, error) {
	m := &pickModel{items: contexts, current: current}
	for i, c := range contexts {
		if c == current {
			m.cursor = i
		}
	}
	res, err := tea.NewProgram(m, tea.WithOutput(w), tea.WithInput(os.Stdin)).Run()
	if err != nil {
		return "", err
	}
	pm := res.(*pickModel)
	if pm.cancelled {
		return "", ErrCancelled
	}
	return pm.items[pm.cursor], nil
}

type pickModel struct {
	items     []string
	current   string
	cursor    int
	cancelled bool
	chosen    bool
}

func (m *pickModel) Init() tea.Cmd { return nil }

func (m *pickModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch key.String() {
	case "ctrl+c", "esc", "q":
		m.cancelled = true
		return m, tea.Quit
	case "enter", " ":
		m.chosen = true
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = len(m.items) - 1
	}
	return m, nil
}

func (m *pickModel) View() string {
	if m.chosen || m.cancelled {
		return "" // leave the screen clean; the caller reports the choice
	}
	var b strings.Builder
	b.WriteString(styleTitle.Render("Which cluster do you want to scan?"))
	b.WriteString(styleHint.Render("  (↑/↓ move · enter select · esc cancel)") + "\n")
	for i, c := range m.items {
		line := c
		if c == m.current {
			line += styleHint.Render("  (current)")
		}
		if i == m.cursor {
			fmt.Fprintf(&b, " %s %s\n", styleSpinner.Render("›"), styleTitle.Render(c)+strings.TrimPrefix(line, c))
		} else {
			fmt.Fprintf(&b, "   %s\n", line)
		}
	}
	return b.String()
}
