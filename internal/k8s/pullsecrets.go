package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// PullSecrets is the outcome of loading the imagePullSecrets referenced by the
// scanned pods. It doubles as an authn.Keychain.
type PullSecrets struct {
	// Loaded is "namespace/name" for every secret whose credentials were read.
	Loaded []string
	// Skipped is "namespace/name: why" for referenced secrets that could not be
	// used (RBAC denied, missing, not a docker-config secret).
	Skipped []string

	mu    sync.RWMutex
	auths map[string]authn.AuthConfig // registry host -> creds
}

// SecretRef names one imagePullSecret referenced by a running pod.
type SecretRef struct{ Namespace, Name string }

// LoadPullSecrets reads the docker-config secrets in refs and returns a
// keychain that resolves registries to those credentials. Individual secrets
// that cannot be read are reported in Skipped, not returned as an error, so a
// scan can proceed with whatever credentials were available.
func LoadPullSecrets(ctx context.Context, o Options, refs []SecretRef) (*PullSecrets, error) {
	ps := &PullSecrets{auths: map[string]authn.AuthConfig{}}
	if len(refs) == 0 {
		return ps, nil
	}
	cs, _, err := newClient(o)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		key := ref.Namespace + "/" + ref.Name
		sec, err := cs.CoreV1().Secrets(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			ps.Skipped = append(ps.Skipped, key+": "+shortErr(err))
			continue
		}
		n, err := ps.add(sec)
		if err != nil {
			ps.Skipped = append(ps.Skipped, key+": "+err.Error())
			continue
		}
		if n > 0 {
			ps.Loaded = append(ps.Loaded, key)
		}
	}
	sort.Strings(ps.Loaded)
	sort.Strings(ps.Skipped)
	return ps, nil
}

// add parses a kubernetes.io/dockerconfigjson or kubernetes.io/dockercfg
// secret and records its registry credentials. Returns how many were added.
func (ps *PullSecrets) add(sec *corev1.Secret) (int, error) {
	var auths map[string]dockerAuth
	switch sec.Type {
	case corev1.SecretTypeDockerConfigJson:
		var cfg struct {
			Auths map[string]dockerAuth `json:"auths"`
		}
		if err := json.Unmarshal(sec.Data[corev1.DockerConfigJsonKey], &cfg); err != nil {
			return 0, fmt.Errorf("bad .dockerconfigjson: %w", err)
		}
		auths = cfg.Auths
	case corev1.SecretTypeDockercfg:
		if err := json.Unmarshal(sec.Data[corev1.DockerConfigKey], &auths); err != nil {
			return 0, fmt.Errorf("bad .dockercfg: %w", err)
		}
	default:
		return 0, fmt.Errorf("not a docker-config secret (type %s)", sec.Type)
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	n := 0
	for host, a := range auths {
		ac := authn.AuthConfig{Username: a.Username, Password: a.Password, IdentityToken: a.IdentityToken, RegistryToken: a.RegistryToken}
		if a.Auth != "" && ac.Username == "" {
			if raw, err := base64.StdEncoding.DecodeString(a.Auth); err == nil {
				if u, p, ok := strings.Cut(string(raw), ":"); ok {
					ac.Username, ac.Password = u, p
				}
			}
		}
		if ac == (authn.AuthConfig{}) {
			continue
		}
		for _, h := range hostKeys(host) {
			if _, dup := ps.auths[h]; !dup {
				ps.auths[h] = ac
			}
		}
		n++
	}
	return n, nil
}

type dockerAuth struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	Auth          string `json:"auth"`
	IdentityToken string `json:"identitytoken"`
	RegistryToken string `json:"registrytoken"`
}

// hostKeys normalises a docker-config auth key ("https://index.docker.io/v1/",
// "registry.example.com:5000/path") to the registry host names ggcr will ask
// for.
func hostKeys(key string) []string {
	h := key
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if i := strings.Index(h, "/"); i >= 0 {
		h = h[:i]
	}
	if h == "" {
		return nil
	}
	if h == "index.docker.io" || h == "docker.io" || h == "registry-1.docker.io" {
		return []string{"index.docker.io", "docker.io", "registry-1.docker.io"}
	}
	return []string{h}
}

// Resolve implements authn.Keychain.
func (ps *PullSecrets) Resolve(target authn.Resource) (authn.Authenticator, error) {
	if ps == nil {
		return authn.Anonymous, nil
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	if ac, ok := ps.auths[target.RegistryStr()]; ok {
		return authn.FromConfig(ac), nil
	}
	return authn.Anonymous, nil
}

// Len is the number of registries with credentials.
func (ps *PullSecrets) Len() int {
	if ps == nil {
		return 0
	}
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.auths)
}

func shortErr(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "forbidden") {
		return "forbidden (no RBAC permission to read secrets)"
	}
	if strings.Contains(msg, "not found") {
		return "not found"
	}
	return msg
}

// collectPullSecretRefs returns the imagePullSecrets a pod would use: its own
// plus those of its service account (which the kubelet merges in).
func collectPullSecretRefs(ctx context.Context, cs kubernetes.Interface, pod *corev1.Pod, saCache map[string][]string) []SecretRef {
	var out []SecretRef
	for _, s := range pod.Spec.ImagePullSecrets {
		out = append(out, SecretRef{pod.Namespace, s.Name})
	}
	sa := pod.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	key := pod.Namespace + "/" + sa
	names, ok := saCache[key]
	if !ok {
		if acct, err := cs.CoreV1().ServiceAccounts(pod.Namespace).Get(ctx, sa, metav1.GetOptions{}); err == nil {
			for _, s := range acct.ImagePullSecrets {
				names = append(names, s.Name)
			}
		}
		saCache[key] = names // cache misses too; one failed lookup per SA is enough
	}
	for _, n := range names {
		out = append(out, SecretRef{pod.Namespace, n})
	}
	return out
}
