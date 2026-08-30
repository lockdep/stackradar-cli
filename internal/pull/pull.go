// Package pull fetches an image from its registry into a docker-save style
// tarball, using the same credentials docker/crane would (~/.docker/config.json,
// credential helpers, cloud keychains) plus any extra keychain the caller
// supplies (e.g. the cluster's own imagePullSecrets).
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

// Keychain builds the credential lookup chain: the local Docker keychain
// first, then any extras in order (a later keychain is only consulted when
// an earlier one has nothing for that registry).
func Keychain(extra ...authn.Keychain) authn.Keychain {
	chain := []authn.Keychain{authn.DefaultKeychain}
	for _, k := range extra {
		if k != nil {
			chain = append(chain, k)
		}
	}
	return authn.NewMultiKeychain(chain...)
}

// ToTarball pulls ref and writes it to a temp file. Caller removes it.
// A nil keychain means the local Docker credentials only.
func ToTarball(ctx context.Context, ref string, kc authn.Keychain) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", ref, err)
	}
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(kc),
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
	return Reason(err) != ""
}

// Reason turns an unreachable-image error into a short, actionable phrase
// ("credentials rejected (401)", "no credentials (401)", "not found (404)",
// "cannot resolve host"). Empty when err is not an unreachability error.
func Reason(err error) string {
	if err == nil {
		return ""
	}
	var te *transport.Error
	if errors.As(err, &te) {
		switch te.StatusCode {
		case http.StatusUnauthorized:
			return "credentials rejected (401)"
		case http.StatusForbidden:
			return "access denied (403)"
		case http.StatusNotFound:
			return "not found (404)"
		}
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no such host"):
		return "cannot resolve host"
	case strings.Contains(msg, "401 Unauthorized"), strings.Contains(msg, "UNAUTHORIZED"):
		// Cloud registries (e.g. DigitalOcean) 401 from their own token endpoint
		// when a stored login has expired; that surfaces as a plain error.
		return "credentials rejected (401)"
	case strings.Contains(msg, "DENIED"):
		return "access denied (403)"
	case strings.Contains(msg, "MANIFEST_UNKNOWN"):
		return "not found (404)"
	}
	return ""
}

// Registry returns the registry host of an image reference ("" if unparsable).
func Registry(ref string) string {
	r, err := name.ParseReference(ref)
	if err != nil {
		return ""
	}
	return r.Context().RegistryStr()
}
