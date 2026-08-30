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
	// Platform, when set ("linux/arm64"), is used for every image instead of
	// the architecture of the node each pod runs on.
	Platform string
}

// DefaultPlatform is assumed when neither the node nor the caller says.
const DefaultPlatform = "linux/amd64"

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
	// Platform is the os/arch the image runs on (from the node), so the
	// variant we pull is the one the kubelet actually ran. Empty means
	// DefaultPlatform. The same digest on two architectures is two Images.
	Platform string `json:"platform,omitempty"`
	// Owners groups Workloads by the controller that created them
	// (Deployment, DaemonSet, StatefulSet, CronJob, ...). Bare pods are kind "Pod".
	Owners []Owner `json:"owners,omitempty"`
}

// Owner is the top-level controller behind one or more pods, resolved through
// intermediate ReplicaSets and Jobs so that a Deployment's pods collapse to it.
type Owner struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Pods is "namespace/pod" for each of this owner's pods running the image.
	Pods []string `json:"pods"`
}

func (o Owner) key() string { return o.Namespace + "/" + o.Kind + "/" + o.Name }

// Name returns repo:tag without the digest, for the summary table where the
// column width matters more than pinning; Display carries the digest.
func (i Image) Name() string {
	if i.Digest == "" {
		return i.Ref + i.platformSuffix()
	}
	name := strings.SplitN(i.Ref, "@", 2)[0]
	if len(i.Tags) > 0 {
		name += ":" + i.Tags[0]
	}
	return name + i.platformSuffix()
}

// platformSuffix marks images pulled for anything other than the default
// platform, e.g. " (arm64)", so a mixed cluster's two rows can be told apart.
func (i Image) platformSuffix() string {
	if i.Platform == "" || i.Platform == DefaultPlatform {
		return ""
	}
	return " (" + strings.TrimPrefix(i.Platform, "linux/") + ")"
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
	return name + i.platformSuffix()
}

type Inventory struct {
	Context    string   `json:"context"`
	Namespaces []string `json:"namespaces"`
	PodCount   int      `json:"pod_count"`
	Images     []Image  `json:"images"`
	// PullSecretRefs are the imagePullSecrets (pod- and service-account-level)
	// referenced by the running pods, deduplicated. Not serialised.
	PullSecretRefs []SecretRef `json:"-"`
	// Warnings are non-fatal things the caller should surface (e.g. node
	// architectures could not be read). Not serialised.
	Warnings []string `json:"-"`
}

// InventoryFromRefs builds an inventory from explicit image references
// (the --image path): no cluster, no workloads, Context left empty.
func InventoryFromRefs(refs []string, platform string) *Inventory {
	inv := &Inventory{}
	seen := map[string]bool{}
	for _, r := range refs {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		img := Image{Ref: r, Platform: platform}
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

// newClient builds a clientset for o and returns the resolved context name.
func newClient(o Options) (*kubernetes.Clientset, string, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if o.Kubeconfig != "" {
		rules.ExplicitPath = o.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: o.Context}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	raw, err := cc.RawConfig()
	if err != nil {
		return nil, "", err
	}
	ctxName := o.Context
	if ctxName == "" {
		ctxName = raw.CurrentContext
	}
	if ctxName == "" {
		return nil, "", fmt.Errorf("no current kubeconfig context; pass --context")
	}

	rest, err := cc.ClientConfig()
	if err != nil {
		return nil, "", err
	}
	rest.UserAgent = "stackradar-cli"
	cs, err := kubernetes.NewForConfig(rest)
	if err != nil {
		return nil, "", err
	}
	return cs, ctxName, nil
}

func ListRunningImages(ctx context.Context, o Options) (*Inventory, error) {
	cs, ctxName, err := newClient(o)
	if err != nil {
		return nil, err
	}

	namespaces := o.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{metav1.NamespaceAll}
	}

	nodeArch, warn := nodePlatforms(ctx, cs, o.Platform)
	byKey := map[string]*Image{}
	nsSeen := map[string]bool{}
	secretSeen := map[SecretRef]bool{}
	saCache := map[string][]string{}
	owners := &ownerResolver{cs: cs, cache: map[string]metav1.OwnerReference{}}
	var secretRefs []SecretRef
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
			for _, ref := range collectPullSecretRefs(ctx, cs, &pod, saCache) {
				if !secretSeen[ref] {
					secretSeen[ref] = true
					secretRefs = append(secretRefs, ref)
				}
			}
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
			platform := o.Platform
			if platform == "" {
				platform = nodeArch[pod.Spec.NodeName]
			}
			statuses := append(append(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses...), pod.Status.EphemeralContainerStatuses...)
			for _, st := range statuses {
				ref, digest, tag := resolve(specImages[st.Name], st.Image, st.ImageID)
				if ref == "" {
					continue
				}
				key := ref + "|" + platform
				img, ok := byKey[key]
				if !ok {
					img = &Image{Ref: ref, Digest: digest, Platform: platform}
					byKey[key] = img
				}
				if tag != "" && !contains(img.Tags, tag) {
					img.Tags = append(img.Tags, tag)
				}
				wl := pod.Namespace + "/" + pod.Name
				if !contains(img.Workloads, wl) {
					img.Workloads = append(img.Workloads, wl)
					img.addOwner(owners.resolve(ctx, &pod), wl)
				}
			}
		}
	}

	inv := &Inventory{Context: ctxName, PodCount: pods, PullSecretRefs: secretRefs}
	if warn != "" {
		inv.Warnings = append(inv.Warnings, warn)
	}
	for ns := range nsSeen {
		inv.Namespaces = append(inv.Namespaces, ns)
	}
	sort.Strings(inv.Namespaces)
	for _, img := range byKey {
		sort.Strings(img.Workloads)
		for i := range img.Owners {
			sort.Strings(img.Owners[i].Pods)
		}
		sort.Slice(img.Owners, func(a, b int) bool { return img.Owners[a].key() < img.Owners[b].key() })
		inv.Images = append(inv.Images, *img)
	}
	sort.Slice(inv.Images, func(a, b int) bool {
		if inv.Images[a].Ref != inv.Images[b].Ref {
			return inv.Images[a].Ref < inv.Images[b].Ref
		}
		return inv.Images[a].Platform < inv.Images[b].Platform
	})
	return inv, nil
}

// nodePlatforms maps node name -> "os/arch" from each node's nodeInfo, so
// that an image is pulled for the architecture it actually runs on. When
// the caller fixed a platform there is nothing to look up. If nodes cannot
// be listed (a namespace-scoped user, typically) every pod falls back to
// DefaultPlatform and the returned warning says so.
func nodePlatforms(ctx context.Context, cs kubernetes.Interface, override string) (map[string]string, string) {
	if override != "" {
		return nil, ""
	}
	list, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		reason := err.Error()
		if strings.Contains(reason, "forbidden") {
			reason = "forbidden"
		}
		return nil, fmt.Sprintf("cannot list nodes (%s); assuming every image is %s — pass --platform to override", reason, DefaultPlatform)
	}
	m := make(map[string]string, len(list.Items))
	for _, n := range list.Items {
		os, arch := n.Status.NodeInfo.OperatingSystem, n.Status.NodeInfo.Architecture
		if os == "" || arch == "" {
			continue
		}
		m[n.Name] = os + "/" + arch
	}
	return m, ""
}

func (i *Image) addOwner(o Owner, pod string) {
	for k := range i.Owners {
		if i.Owners[k].key() == o.key() {
			if !contains(i.Owners[k].Pods, pod) {
				i.Owners[k].Pods = append(i.Owners[k].Pods, pod)
			}
			return
		}
	}
	o.Pods = []string{pod}
	i.Owners = append(i.Owners, o)
}

// ownerResolver walks controller owner references up to the object a user
// would recognise: ReplicaSet -> Deployment, Job -> CronJob. Lookups are
// cached per object; if one fails (RBAC, object already gone) the
// intermediate object is reported as the owner rather than failing the scan.
type ownerResolver struct {
	cs    kubernetes.Interface
	cache map[string]metav1.OwnerReference // "ns/Kind/name" -> its controller ref (empty Kind = none)
}

func controllerRef(refs []metav1.OwnerReference) (metav1.OwnerReference, bool) {
	for _, r := range refs {
		if r.Controller != nil && *r.Controller {
			return r, true
		}
	}
	if len(refs) > 0 {
		return refs[0], true
	}
	return metav1.OwnerReference{}, false
}

func (r *ownerResolver) resolve(ctx context.Context, pod *corev1.Pod) Owner {
	ref, ok := controllerRef(pod.OwnerReferences)
	if !ok {
		return Owner{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name}
	}
	ns := pod.Namespace
	switch ref.Kind {
	case "ReplicaSet":
		if parent, ok := r.parentOf(ctx, ns, ref); ok {
			return Owner{Kind: parent.Kind, Namespace: ns, Name: parent.Name}
		}
	case "Job":
		if parent, ok := r.parentOf(ctx, ns, ref); ok {
			return Owner{Kind: parent.Kind, Namespace: ns, Name: parent.Name}
		}
	}
	return Owner{Kind: ref.Kind, Namespace: ns, Name: ref.Name}
}

// parentOf returns the controller of a ReplicaSet or Job, fetching it once.
func (r *ownerResolver) parentOf(ctx context.Context, ns string, ref metav1.OwnerReference) (metav1.OwnerReference, bool) {
	key := ns + "/" + ref.Kind + "/" + ref.Name
	if p, ok := r.cache[key]; ok {
		return p, p.Kind != ""
	}
	var refs []metav1.OwnerReference
	switch ref.Kind {
	case "ReplicaSet":
		rs, err := r.cs.AppsV1().ReplicaSets(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			r.cache[key] = metav1.OwnerReference{}
			return metav1.OwnerReference{}, false
		}
		refs = rs.OwnerReferences
	case "Job":
		job, err := r.cs.BatchV1().Jobs(ns).Get(ctx, ref.Name, metav1.GetOptions{})
		if err != nil {
			r.cache[key] = metav1.OwnerReference{}
			return metav1.OwnerReference{}, false
		}
		refs = job.OwnerReferences
	}
	p, ok := controllerRef(refs)
	if !ok {
		p = metav1.OwnerReference{}
	}
	r.cache[key] = p
	return p, ok
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
