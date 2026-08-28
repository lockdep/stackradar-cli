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
