package pull

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

func TestIsAuthOrNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"401", &transport.Error{StatusCode: http.StatusUnauthorized}, true},
		{"403", &transport.Error{StatusCode: http.StatusForbidden}, true},
		{"404", &transport.Error{StatusCode: http.StatusNotFound}, true},
		{"500", &transport.Error{StatusCode: http.StatusInternalServerError}, false},
		{"429", &transport.Error{StatusCode: http.StatusTooManyRequests}, false},
		{"wrapped 401", fmt.Errorf("pull: %w", &transport.Error{StatusCode: http.StatusUnauthorized}), true},
		{"UNAUTHORIZED text", errors.New("GET https://x/v2/: UNAUTHORIZED: authentication required"), true},
		{"DENIED text", errors.New("DENIED: requested access to the resource is denied"), true},
		{"MANIFEST_UNKNOWN text", errors.New("MANIFEST_UNKNOWN: manifest unknown"), true},
		{"dns", errors.New("dial tcp: lookup registry.internal: no such host"), true},
		{"timeout", errors.New("dial tcp 10.0.0.1:443: i/o timeout"), false},
		{"tls", errors.New("tls: failed to verify certificate"), false},
	}
	for _, c := range cases {
		if got := IsAuthOrNotFound(c.err); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("dial tcp: i/o timeout"), ""},
		{&transport.Error{StatusCode: http.StatusInternalServerError}, ""},
		{&transport.Error{StatusCode: http.StatusUnauthorized}, "credentials rejected (401)"},
		{&transport.Error{StatusCode: http.StatusForbidden}, "access denied (403)"},
		{&transport.Error{StatusCode: http.StatusNotFound}, "not found (404)"},
		// DigitalOcean's token endpoint 401s as a plain error, not a transport.Error.
		{errors.New("GET https://api.digitalocean.com/v2/registry/auth?scope=x: unexpected status code 401 Unauthorized: {}"), "credentials rejected (401)"},
		{errors.New("lookup reg.internal: no such host"), "cannot resolve host"},
		{errors.New("DENIED: requested access to the resource is denied"), "access denied (403)"},
		{errors.New("MANIFEST_UNKNOWN: manifest unknown"), "not found (404)"},
	}
	for _, c := range cases {
		if got := Reason(c.err); got != c.want {
			t.Errorf("Reason(%v) = %q, want %q", c.err, got, c.want)
		}
		if IsAuthOrNotFound(c.err) != (c.want != "") {
			t.Errorf("IsAuthOrNotFound(%v) disagrees with Reason", c.err)
		}
	}
}

func TestRegistry(t *testing.T) {
	if got := Registry("registry.digitalocean.com/a/b:1"); got != "registry.digitalocean.com" {
		t.Fatal(got)
	}
	if got := Registry("nginx:1"); got != "index.docker.io" {
		t.Fatal(got)
	}
}
