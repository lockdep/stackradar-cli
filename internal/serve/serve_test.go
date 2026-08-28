package serve

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRunServesPageOnLoopback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	page := []byte("<!doctype html><title>x</title>hello")
	urlc := make(chan string, 1)
	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, page, 0, func(u string) { urlc <- u }) }()

	u := <-urlc
	if !strings.HasPrefix(u, "http://127.0.0.1:") {
		t.Fatalf("expected loopback URL, got %s", u)
	}
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != string(page) {
		t.Fatalf("unexpected body %q", body)
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("missing CSP header")
	}
	if r, _ := http.Get(u + "nope"); r.StatusCode != 404 {
		t.Fatalf("expected 404 for other paths, got %d", r.StatusCode)
	}
	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}
