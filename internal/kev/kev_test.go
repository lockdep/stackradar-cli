package kev

import "testing"

func TestParse(t *testing.T) {
	b := []byte(`{"title":"CISA KEV","count":2,"vulnerabilities":[
		{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j"},
		{"cveID":"CVE-2026-31789"}]}`)
	s, err := parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 2 || !s.Has("CVE-2021-44228") || !s.Has("CVE-2026-31789") {
		t.Fatalf("got %v", s)
	}
	if s.Has("CVE-2000-0001") {
		t.Fatal("unexpected hit")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := parse([]byte(`<html>maintenance</html>`)); err == nil {
		t.Fatal("expected error for non-JSON feed")
	}
	// A valid JSON document with no vulnerabilities is an empty, non-nil set:
	// the report should say "checked, nothing found", not "not checked".
	s, err := parse([]byte(`{}`))
	if err != nil || s == nil || len(s) != 0 {
		t.Fatalf("got %v, %v", s, err)
	}
}

func TestSetHasNil(t *testing.T) {
	var s Set
	if s.Has("CVE-2021-44228") {
		t.Fatal("nil set must not report hits")
	}
}
