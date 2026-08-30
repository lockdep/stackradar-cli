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
	"github.com/google/go-containerregistry/pkg/v1/cache"
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

// Options control one pull.
type Options struct {
	// Platform selects the variant of a multi-arch image: "linux/arm64",
	// "linux/arm/v7". Empty means linux/amd64.
	Platform string
	// Keychain resolves registry credentials; nil means the local Docker
	// credentials only.
	Keychain authn.Keychain
	// Cache, when non-nil, stores layers by digest so a re-run does not
	// download what it already has.
	Cache cache.Cache
}

// ParsePlatform validates an "os/arch[/variant]" string. Empty is allowed and
// means the default.
func ParsePlatform(s string) (v1.Platform, error) {
	if s == "" {
		return v1.Platform{OS: "linux", Architecture: "amd64"}, nil
	}
	p, err := v1.ParsePlatform(s)
	if err != nil || p.OS == "" || p.Architecture == "" {
		return v1.Platform{}, fmt.Errorf("invalid platform %q (want os/arch, e.g. linux/arm64)", s)
	}
	return *p, nil
}

// ToTarball pulls ref and writes it to a temp file. Caller removes it.
func ToTarball(ctx context.Context, ref string, o Options) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", fmt.Errorf("parse %q: %w", ref, err)
	}
	platform, err := ParsePlatform(o.Platform)
	if err != nil {
		return "", err
	}
	kc := o.Keychain
	if kc == nil {
		kc = authn.DefaultKeychain
	}
	img, err := remote.Image(r,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(kc),
		remote.WithPlatform(platform),
		remote.WithUserAgent("stackradar-cli"),
	)
	if err != nil {
		return "", err
	}
	if o.Cache != nil {
		img = cache.Image(img, o.Cache)
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
