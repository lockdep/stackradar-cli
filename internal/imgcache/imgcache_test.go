package imgcache

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func randomLayer(t *testing.T) v1.Layer {
	t.Helper()
	l, err := random.Layer(4096, "application/vnd.docker.image.rootfs.diff.tar.gzip")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func drain(t *testing.T, l v1.Layer) []byte {
	t.Helper()
	rc, err := l.Compressed()
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Close(); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPutThenGet(t *testing.T) {
	c, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	l := randomLayer(t)
	h, _ := l.Digest()
	if _, err := c.Get(h); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("empty cache Get = %v, want ErrNotFound", err)
	}
	wrapped, err := c.Put(l)
	if err != nil {
		t.Fatal(err)
	}
	want := drain(t, wrapped)
	got, err := c.Get(h)
	if err != nil {
		t.Fatalf("Get after full read: %v", err)
	}
	if !bytes.Equal(drain(t, got), want) {
		t.Fatal("cached bytes differ from download")
	}
	if entries, _ := os.ReadDir(c.Dir()); len(entries) != 1 {
		t.Fatalf("want exactly one file, got %d", len(entries))
	}
}

func TestPartialReadIsNotCached(t *testing.T) {
	c, _ := Open(t.TempDir())
	l := randomLayer(t)
	h, _ := l.Digest()
	wrapped, _ := c.Put(l)
	rc, _ := wrapped.Compressed()
	if _, err := io.ReadFull(rc, make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if _, err := c.Get(h); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("partial read must not be cached, Get = %v", err)
	}
	entries, _ := os.ReadDir(c.Dir())
	if len(entries) != 0 {
		t.Fatalf("temp file left behind: %v", entries[0].Name())
	}
}

func TestConcurrentWritersSameLayer(t *testing.T) {
	c, _ := Open(t.TempDir())
	l := randomLayer(t)
	h, _ := l.Digest()
	want := drain(t, l)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, _ := c.Put(l)
			drain(t, w)
		}()
	}
	wg.Wait()
	got, err := c.Get(h)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(drain(t, got), want) {
		t.Fatal("concurrent writers corrupted the entry")
	}
}

func TestCorruptEntryIsEvicted(t *testing.T) {
	c, _ := Open(t.TempDir())
	h := v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("a", 64)}
	if err := os.WriteFile(c.path(h), []byte("not a gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(h); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("Get = %v", err)
	}
	if _, err := os.Stat(c.path(h)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt entry should have been deleted")
	}
}

func TestPruneKeepsRecentlyUsed(t *testing.T) {
	c, _ := Open(t.TempDir())
	var hashes []v1.Hash
	for range 3 {
		l := randomLayer(t)
		h, _ := l.Digest()
		hashes = append(hashes, h)
		w, _ := c.Put(l)
		drain(t, w)
	}
	// Age everything, then touch the first one via a cache hit.
	old := time.Now().Add(-time.Hour)
	for _, h := range hashes {
		os.Chtimes(c.path(h), old, old)
	}
	if _, err := c.Get(hashes[0]); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(c.Dir(), ".partial-leftover"), []byte("x"), 0o600)

	keep, _ := os.Stat(c.path(hashes[0]))
	removed, err := c.Prune(keep.Size())
	if err != nil {
		t.Fatal(err)
	}
	if removed.Layers != 2 {
		t.Fatalf("pruned %d layers, want 2", removed.Layers)
	}
	if _, err := c.Get(hashes[0]); err != nil {
		t.Fatal("recently used layer was pruned")
	}
	if _, err := os.Stat(filepath.Join(c.Dir(), ".partial-leftover")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial file should have been cleaned up")
	}
	if st, _ := c.Clear(); st.Layers != 1 {
		t.Fatalf("Clear removed %d, want 1", st.Layers)
	}
}
