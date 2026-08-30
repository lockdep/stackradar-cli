package report

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"time"
)

//go:embed ui/index.html
var htmlTemplate string

// HTMLOptions carries the metadata the page shows next to the report.
type HTMLOptions struct {
	Version     string
	GeneratedAt time.Time
}

// htmlPayload is what the page's script reads. The report is wrapped rather
// than extended so the --json output stays exactly the report.
type htmlPayload struct {
	Report      *Report   `json:"report"`
	GeneratedAt time.Time `json:"generated_at"`
	Version     string    `json:"version"`
}

// RenderHTML returns the report as a single self-contained page: no external
// scripts, styles or fonts, so it works offline and can be shared as a file.
func RenderHTML(rep *Report, opts HTMLOptions) ([]byte, error) {
	if opts.GeneratedAt.IsZero() {
		opts.GeneratedAt = time.Now()
	}
	data, err := json.Marshal(htmlPayload{Report: rep, GeneratedAt: opts.GeneratedAt, Version: opts.Version})
	if err != nil {
		return nil, fmt.Errorf("encoding report: %w", err)
	}
	// Inside <script type="application/json"> only "</script" can end the block;
	// escaping every "</" is the conservative version of that rule. "<!--" is
	// escaped for the same reason (HTML spec: script data double escaped state).
	safe := bytes.ReplaceAll(data, []byte("</"), []byte(`<\/`))
	safe = bytes.ReplaceAll(safe, []byte("<!--"), []byte(`<\!--`))

	page := strings.Replace(htmlTemplate, "__DATA__", string(safe), 1)
	page = strings.Replace(page, "__TITLE__", html.EscapeString(rep.Context), 1)
	return []byte(page), nil
}

func WriteHTML(w io.Writer, rep *Report, opts HTMLOptions) error {
	page, err := RenderHTML(rep, opts)
	if err != nil {
		return err
	}
	_, err = w.Write(page)
	return err
}
