package k8s

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func ownedBy(kind, name string) []metav1.OwnerReference {
	t := true
	return []metav1.OwnerReference{{Kind: kind, Name: name, Controller: &t}}
}

func TestOwnerResolver(t *testing.T) {
	cs := fake.NewSimpleClientset(
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "web-abc123", OwnerReferences: ownedBy("Deployment", "web")}},
		&appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "orphan-rs"}},
		&batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "backup-1700000000", OwnerReferences: ownedBy("CronJob", "backup")}},
	)
	r := &ownerResolver{cs: cs, cache: map[string]metav1.OwnerReference{}}
	pod := func(name string, owners []metav1.OwnerReference) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: name, OwnerReferences: owners}}
	}
	cases := []struct {
		pod  *corev1.Pod
		want Owner
	}{
		{pod("web-abc123-x1", ownedBy("ReplicaSet", "web-abc123")), Owner{Kind: "Deployment", Namespace: "ns", Name: "web"}},
		{pod("web-abc123-x2", ownedBy("ReplicaSet", "web-abc123")), Owner{Kind: "Deployment", Namespace: "ns", Name: "web"}},
		{pod("orphan-rs-x1", ownedBy("ReplicaSet", "orphan-rs")), Owner{Kind: "ReplicaSet", Namespace: "ns", Name: "orphan-rs"}},
		{pod("gone-rs-x1", ownedBy("ReplicaSet", "gone-rs")), Owner{Kind: "ReplicaSet", Namespace: "ns", Name: "gone-rs"}},
		{pod("backup-1700000000-q", ownedBy("Job", "backup-1700000000")), Owner{Kind: "CronJob", Namespace: "ns", Name: "backup"}},
		{pod("agent-k2j", ownedBy("DaemonSet", "agent")), Owner{Kind: "DaemonSet", Namespace: "ns", Name: "agent"}},
		{pod("db-0", ownedBy("StatefulSet", "db")), Owner{Kind: "StatefulSet", Namespace: "ns", Name: "db"}},
		{pod("debug", nil), Owner{Kind: "Pod", Namespace: "ns", Name: "debug"}},
	}
	for _, c := range cases {
		got := r.resolve(context.Background(), c.pod)
		if got.Kind != c.want.Kind || got.Namespace != c.want.Namespace || got.Name != c.want.Name {
			t.Errorf("%s: got %+v, want %+v", c.pod.Name, got, c.want)
		}
	}
	// The Deployment lookup happened once for two pods.
	gets := 0
	for _, a := range cs.Actions() {
		if a.GetVerb() == "get" && a.GetResource().Resource == "replicasets" && a.(interface{ GetName() string }).GetName() == "web-abc123" {
			gets++
		}
	}
	if gets != 1 {
		t.Errorf("replicaset web-abc123 fetched %d times, want 1", gets)
	}
}

func TestImageAddOwner(t *testing.T) {
	var img Image
	dep := Owner{Kind: "Deployment", Namespace: "ns", Name: "web"}
	img.addOwner(dep, "ns/web-1")
	img.addOwner(dep, "ns/web-2")
	img.addOwner(dep, "ns/web-2")
	img.addOwner(Owner{Kind: "DaemonSet", Namespace: "ns", Name: "agent"}, "ns/agent-x")
	if len(img.Owners) != 2 || len(img.Owners[0].Pods) != 2 || img.Owners[1].Pods[0] != "ns/agent-x" {
		t.Fatalf("unexpected owners: %+v", img.Owners)
	}
}
