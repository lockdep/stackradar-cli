// Package pull fetches an image from its registry into a docker-save style
// tarball, using the same credentials docker/crane would (~/.docker/config.json,
// credential helpers, cloud keychains).
package pull

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// ToTarball pulls ref and writes it to a temp file. Caller removes it.
func ToTarball(ctx context.Context, ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", ref, err)
	}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
		remote.WithPlatform(v1.Platform{OS: "linux", Architecture: "amd64"}),
		remote.WithUserAgent("stackradar-cli"),
	)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "stackradar-*.tar")
	if err != nil {
		return "", err
	}
	f.Close()
	tagRef, ok := r.(name.Tag)
	if !ok {
		// Digest refs have no tag; give the tarball manifest a synthetic one.
		tagRef = r.Context().Tag("stackradar-scan")
	}
	if err := tarball.WriteToFile(f.Name(), tagRef, img); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// IsAuthOrNotFound reports whether the error means "this machine cannot reach
// or is not allowed to read that image" — as opposed to a transient failure.
func IsAuthOrNotFound(err error) bool {
	var te *transport.Error
	if errors.As(err, &te) {
		switch te.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
			return true
		}
	}
	msg := err.Error()
	return strings.Contains(msg, "UNAUTHORIZED") ||
		strings.Contains(msg, "DENIED") ||
		strings.Contains(msg, "MANIFEST_UNKNOWN") ||
		strings.Contains(msg, "no such host")
}
