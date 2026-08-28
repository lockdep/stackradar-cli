package k8s

import "testing"

func TestResolve(t *testing.T) {
	cases := []struct {
		spec, status, id             string
		wantRef, wantDigest, wantTag string
	}{
		{"nginx:1.29", "nginx:1.29", "docker-pullable://docker.io/library/nginx@sha256:abc", "docker.io/library/nginx@sha256:abc", "sha256:abc", "1.29"},
		{"ghcr.io/x/y:v1", "ghcr.io/x/y:v1", "ghcr.io/x/y@sha256:def", "ghcr.io/x/y@sha256:def", "sha256:def", "v1"},
		{"local/img:dev", "local/img:dev", "sha256:0123", "local/img:dev", "", "dev"},
		{"reg/img@sha256:999", "reg/img@sha256:999", "sha256:0123", "reg/img@sha256:999", "sha256:999", ""},
		{"", "", "", "", "", ""},
	}
	for _, c := range cases {
		ref, digest, tag := resolve(c.spec, c.status, c.id)
		if ref != c.wantRef || digest != c.wantDigest || tag != c.wantTag {
			t.Errorf("resolve(%q,%q,%q) = %q,%q,%q; want %q,%q,%q", c.spec, c.status, c.id, ref, digest, tag, c.wantRef, c.wantDigest, c.wantTag)
		}
	}
}

func TestDisplay(t *testing.T) {
	got := Image{Ref: "ghcr.io/x/y@sha256:0123456789abcdefff", Digest: "sha256:0123456789abcdefff", Tags: []string{"v1"}}.Display()
	if got != "ghcr.io/x/y:v1@0123456789ab" {
		t.Fatal(got)
	}
}

func TestInventoryFromRefs(t *testing.T) {
	inv := InventoryFromRefs([]string{
		"nginx:1.25",
		"nginx:1.25",
		"ghcr.io/foo/bar:v1@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"",
	})
	if len(inv.Images) != 2 {
		t.Fatalf("want 2 unique images, got %d", len(inv.Images))
	}
	if inv.Images[0].Ref != "nginx:1.25" || inv.Images[0].Digest != "" {
		t.Errorf("plain tag mangled: %+v", inv.Images[0])
	}
	d := inv.Images[1]
	if d.Ref != "ghcr.io/foo/bar@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ||
		d.Tags[0] != "v1" || d.Digest[:7] != "sha256:" {
		t.Errorf("digest ref not split: %+v", d)
	}
	if inv.Context != "" {
		t.Error("context must stay empty for --image inventories")
	}
}
