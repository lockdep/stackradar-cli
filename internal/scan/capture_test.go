package scan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCaptureSurfacesErrorLevelOnly(t *testing.T) {
	var warned []string
	c := &capture{warn: func(m string) { warned = append(warned, m) }}
	log := slog.New(c)
	log.Debug("noise")
	log.Info("noise")
	log.Error("Error during extraction: (extracting as os/dpkg) etc/foo: bad line")
	if len(warned) != 1 || !strings.Contains(warned[0], "os/dpkg") {
		t.Fatalf("expected the error to be surfaced once, got %v", warned)
	}
	if !c.Enabled(context.Background(), slog.LevelError) || c.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatalf("non-verbose handler should enable Error only")
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOSVProbeRecordsOnlyOSVFailures(t *testing.T) {
	var next rtFunc
	p := &osvProbe{next: rtFunc(func(r *http.Request) (*http.Response, error) { return next(r) })}
	do := func(host, path string) {
		req := &http.Request{Method: "POST", URL: &url.URL{Scheme: "https", Host: host, Path: path}}
		resp, _ := p.RoundTrip(req)
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}
	ok := func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	next = ok
	do("api.osv.dev", "/v1/querybatch")
	if p.failure() != "" {
		t.Fatalf("2xx must not be a failure")
	}
	next = func(*http.Request) (*http.Response, error) { return nil, errors.New("dial tcp: connection refused") }
	do("registry-1.docker.io", "/v2/")
	if p.failure() != "" {
		t.Fatalf("other hosts are ignored, got %q", p.failure())
	}
	do("api.osv.dev", "/v1/querybatch")
	if got := p.failure(); !strings.Contains(got, "connection refused") {
		t.Fatalf("transport error not recorded: %q", got)
	}
	next = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
	}
	do("api.osv.dev", "/v1/vulns/CVE-1")
	if got := p.failure(); !strings.Contains(got, "HTTP 503") {
		t.Fatalf("5xx not recorded: %q", got)
	}
	p.reset()
	if p.failure() != "" {
		t.Fatalf("reset should clear failures")
	}
}
