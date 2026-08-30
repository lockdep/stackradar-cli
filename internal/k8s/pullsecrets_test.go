package k8s

import (
	"encoding/base64"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
)

func TestPullSecretsKeychain(t *testing.T) {
	auth := base64.StdEncoding.EncodeToString([]byte("me:s3cret"))
	ps := &PullSecrets{auths: map[string]authn.AuthConfig{}}
	n, err := ps.add(&corev1.Secret{
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{corev1.DockerConfigJsonKey: []byte(`{"auths":{
			"https://registry.digitalocean.com":{"auth":"` + auth + `"},
			"https://index.docker.io/v1/":{"username":"u","password":"p"},
			"empty.example.com":{}
		}}`)},
	})
	if err != nil || n != 2 {
		t.Fatalf("add: n=%d err=%v", n, err)
	}
	if _, err := ps.add(&corev1.Secret{Type: corev1.SecretTypeOpaque}); err == nil {
		t.Fatal("opaque secret must be rejected")
	}
	check := func(ref, user, pass string) {
		t.Helper()
		r, _ := name.ParseReference(ref)
		a, err := ps.Resolve(r.Context().Registry)
		if err != nil {
			t.Fatal(err)
		}
		cfg, _ := a.Authorization()
		if cfg.Username != user || cfg.Password != pass {
			t.Errorf("%s: got %s/%s want %s/%s", ref, cfg.Username, cfg.Password, user, pass)
		}
	}
	check("registry.digitalocean.com/x/y:1", "me", "s3cret")
	check("nginx:1", "u", "p")
	check("ghcr.io/x/y:1", "", "") // anonymous
	if ps.Len() != 4 {             // DO + 3 docker hub aliases
		t.Fatalf("Len = %d", ps.Len())
	}
}

func TestHostKeys(t *testing.T) {
	if got := hostKeys("https://reg.example.com:5000/v2/"); len(got) != 1 || got[0] != "reg.example.com:5000" {
		t.Fatal(got)
	}
	if got := hostKeys("docker.io"); len(got) != 3 {
		t.Fatal(got)
	}
}
