// Package k8s lists the images actually running in a cluster.
package k8s

import (
	"context"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Options struct {
	Kubeconfig string
	Context    string
	// Namespaces to scan; empty means all.
	Namespaces []string
	// ExcludeNamespaces are skipped even if they appear in Namespaces.
	ExcludeNamespaces []string
}

// Image is one unique running image, keyed by the digest the kubelet reports.
type Image struct {
	// Ref is what we pull: repo@sha256:... when the kubelet reported a digest,
	// otherwise the tag from the pod spec.
	Ref string `json:"ref"`
	// Tags seen in pod specs for this digest (informational).
	Tags []string `json:"tags,omitempty"`
	// Workloads is "namespace/pod" for every pod running this image.
	Workloads []string `json:"workloads"`
	// Digest is the raw sha256 when known.
	Digest string `json:"digest,omitempty"`
}

// Display returns a short human-readable name: repo:tag@sha256:abcd1234.
func (i Image) Display() string {
	name := i.Ref
	if i.Digest != "" {
		repo := strings.SplitN(i.Ref, "@", 2)[0]
		short := strings.TrimPrefix(i.Digest, "sha256:")
		if len(short) > 12 {
			short = short[:12]
		}
		name = repo
		if len(i.Tags) > 0 {
			name += ":" + i.Tags[0]
		}
		name += "@" + short
	}
	return name
}

type Inventory struct {
	Context    string   `json:"context"`
	Namespaces []string `json:"namespaces"`
	PodCount   int      `json:"pod_count"`
	Images     []Image  `json:"images"`
}

// InventoryFromRefs builds an inventory from explicit image references
// (the --image path): no cluster, no workloads, Context left empty.
func InventoryFromRefs(refs []string) *Inventory {
	inv := &Inventory{}
	seen := map[string]bool{}
	for _, r := range refs {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		img := Image{Ref: r}
		if i := strings.Index(r, "@sha256:"); i >= 0 {
			img.Digest = r[i+1:]
			if j := strings.LastIndex(r[:i], ":"); j > strings.LastIndex(r[:i], "/") {
				img.Tags = []string{r[j+1 : i]}
				img.Ref = r[:j] + r[i:]
			}
		}
		inv.Images = append(inv.Images, img)
	}
	return inv
}

func ListRunningImages(ctx context.Context, o Options) (*Inventory, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if o.Kubeconfig != "" {
		rules.ExplicitPath = o.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: o.Context}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	raw, err := cc.RawConfig()
	if err != nil {
		return nil, err
	}
	ctxName := o.Context
	if ctxName == "" {
		ctxName = raw.CurrentContext
	}
	if ctxName == "" {
		return nil, fmt.Errorf("no current kubeconfig context; pass --context")
	}

	rest, err := cc.ClientConfig()
	if err != nil {
		return nil, err
	}
	rest.UserAgent = "stackradar-cli"
	cs, err := kubernetes.NewForConfig(rest)
	if err != nil {
		return nil, err
	}

	namespaces := o.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{metav1.NamespaceAll}
	}

	byKey := map[string]*Image{}
	nsSeen := map[string]bool{}
	pods := 0
	for _, ns := range namespaces {
		if contains(o.ExcludeNamespaces, ns) {
			continue
		}
		list, err := cs.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing pods in %q: %w", nsOrAll(ns), err)
		}
		for _, pod := range list.Items {
			if pod.Status.Phase != corev1.PodRunning || contains(o.ExcludeNamespaces, pod.Namespace) {
				continue
			}
			pods++
			nsSeen[pod.Namespace] = true
			specImages := map[string]string{}
			for _, c := range pod.Spec.InitContainers {
				specImages[c.Name] = c.Image
			}
			for _, c := range pod.Spec.Containers {
				specImages[c.Name] = c.Image
			}
			for _, c := range pod.Spec.EphemeralContainers {
				specImages[c.Name] = c.Image
			}
			statuses := append(append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...), pod.Status.EphemeralContainerStatuses...)
			for _, st := range statuses {
				ref, digest, tag := resolve(specImages[st.Name], st.Image, st.ImageID)
				if ref == "" {
					continue
				}
				key := ref
				img, ok := byKey[key]
				if !ok {
					img = &Image{Ref: ref, Digest: digest}
					byKey[key] = img
				}
				if tag != "" && !contains(img.Tags, tag) {
					img.Tags = append(img.Tags, tag)
				}
				wl := pod.Namespace + "/" + pod.Name
				if !contains(img.Workloads, wl) {
					img.Workloads = append(img.Workloads, wl)
				}
			}
		}
	}

	inv := &Inventory{Context: ctxName, PodCount: pods}
	for ns := range nsSeen {
		inv.Namespaces = append(inv.Namespaces, ns)
	}
	sort.Strings(inv.Namespaces)
	for _, img := range byKey {
		sort.Strings(img.Workloads)
		inv.Images = append(inv.Images, *img)
	}
	sort.Slice(inv.Images, func(a, b int) bool { return inv.Images[a].Ref < inv.Images[b].Ref })
	return inv, nil
}

// resolve turns the kubelet's (image, imageID) pair into a pullable reference.
//
// imageID is usually "docker-pullable://repo@sha256:..." or "repo@sha256:...";
// on some runtimes it is a bare "sha256:..." (image loaded locally, no
// registry digest) in which case we fall back to the spec tag.
func resolve(specImage, statusImage, imageID string) (ref, digest, tag string) {
	id := imageID
	for _, p := range []string{"docker-pullable://", "docker://", "containerd://", "cri-o://"} {
		id = strings.TrimPrefix(id, p)
	}
	spec := specImage
	if spec == "" {
		spec = statusImage
	}
	tag = tagOf(spec)

	if at := strings.Index(id, "@sha256:"); at > 0 {
		return id, id[at+1:], tag
	}
	if strings.HasPrefix(id, "sha256:") && spec != "" {
		// Local-only image: pull by tag, remember what the digest was.
		if strings.Contains(spec, "@sha256:") {
			return spec, spec[strings.Index(spec, "@")+1:], ""
		}
		return spec, "", tag
	}
	if spec != "" {
		return spec, "", tag
	}
	return "", "", ""
}

func tagOf(ref string) string {
	if strings.Contains(ref, "@") {
		ref = ref[:strings.Index(ref, "@")]
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[colon+1:]
	}
	return ""
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func nsOrAll(ns string) string {
	if ns == "" {
		return "all namespaces"
	}
	return ns
}

// ListContexts returns every context name in the kubeconfig (sorted) and the
// current-context, which may be empty.
func ListContexts(kubeconfig string) (names []string, current string, err error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	raw, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).RawConfig()
	if err != nil {
		return nil, "", err
	}
	for name := range raw.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, raw.CurrentContext, nil
}
