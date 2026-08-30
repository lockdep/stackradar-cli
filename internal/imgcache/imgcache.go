// Package imgcache is an on-disk layer cache for image pulls. Layers are
// stored by compressed digest, so base layers shared between images are
// downloaded once and a second scan of an unchanged cluster fetches nothing
// but manifests.
//
// go-containerregistry ships a filesystem cache, but it writes the final
// file in place while streaming, so two images sharing a layer and pulled
// concurrently interleave their writes, and an interrupted pull leaves a
// truncated file that later reads as a valid-but-short layer. This one
// streams into a temp file and renames it only after the full layer was
// read, which makes concurrent writers and Ctrl-C safe.
package imgcache

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/cache"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// DefaultMaxBytes is the size the cache is pruned back to after a scan.
const DefaultMaxBytes = 4 << 30

// DefaultDir is $XDG_CACHE_HOME/stackradar/layers (~/Library/Caches on macOS).
func DefaultDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "stackradar", "layers"), nil
}

type Cache struct {
	dir string
}

// Open makes dir usable as a cache.
func Open(dir string) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cache dir %s: %w", dir, err)
	}
	return &Cache{dir: dir}, nil
}

func (c *Cache) Dir() string { return c.dir }

var _ cache.Cache = (*Cache)(nil)

func (c *Cache) path(h v1.Hash) string {
	return filepath.Join(c.dir, h.Algorithm+"-"+h.Hex)
}

// Put wraps l so that reading it also stores it.
func (c *Cache) Put(l v1.Layer) (v1.Layer, error) {
	digest, err := l.Digest()
	if err != nil {
		return nil, err
	}
	return &layer{Layer: l, c: c, digest: digest}, nil
}

// Get returns a stored layer or cache.ErrNotFound. The file is re-hashed
// before it is trusted: a corrupt or truncated entry is evicted rather than
// scanned, and hashing local disk is still far cheaper than a download.
func (c *Cache) Get(h v1.Hash) (v1.Layer, error) {
	f, err := os.Open(c.path(h))
	if errors.Is(err, os.ErrNotExist) {
		return nil, cache.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	got, _, err := v1.SHA256(f)
	f.Close()
	if err != nil || got != h {
		_ = c.Delete(h)
		return nil, cache.ErrNotFound
	}
	l, err := tarball.LayerFromFile(c.path(h))
	if err != nil {
		_ = c.Delete(h)
		return nil, cache.ErrNotFound
	}
	c.Touch(h)
	return l, nil
}

func (c *Cache) Delete(h v1.Hash) error {
	err := os.Remove(c.path(h))
	if errors.Is(err, os.ErrNotExist) {
		return cache.ErrNotFound
	}
	return err
}

type layer struct {
	v1.Layer
	c      *Cache
	digest v1.Hash
}

// Compressed tees the download into a temp file that becomes the cache
// entry once the reader hits EOF. Closing early discards it.
func (l *layer) Compressed() (io.ReadCloser, error) {
	rc, err := l.Layer.Compressed()
	if err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(l.c.dir, ".partial-*")
	if err != nil {
		rc.Close()
		return nil, err
	}
	return &writer{rc: rc, tmp: tmp, final: l.c.path(l.digest)}, nil
}

// Uncompressed is not cached: the tarball writer only ever asks for the
// compressed stream, and storing both would double the disk use.
func (l *layer) Uncompressed() (io.ReadCloser, error) {
	return l.Layer.Uncompressed()
}

type writer struct {
	rc       io.ReadCloser
	tmp      *os.File
	final    string
	complete bool
	failed   bool
}

func (w *writer) Read(p []byte) (int, error) {
	n, err := w.rc.Read(p)
	if n > 0 && !w.failed {
		if _, werr := w.tmp.Write(p[:n]); werr != nil {
			w.failed = true // keep serving the download; just don't cache it
		}
	}
	if errors.Is(err, io.EOF) {
		w.complete = true
	}
	return n, err
}

func (w *writer) Close() error {
	rerr := w.rc.Close()
	cerr := w.tmp.Close()
	if w.complete && !w.failed && cerr == nil {
		if err := os.Rename(w.tmp.Name(), w.final); err == nil {
			return rerr
		}
	}
	os.Remove(w.tmp.Name())
	return rerr
}

// Stats describes what is on disk.
type Stats struct {
	Layers int
	Bytes  int64
}

func (c *Cache) Stats() (Stats, error) {
	entries, err := c.entries()
	if err != nil {
		return Stats{}, err
	}
	var st Stats
	for _, e := range entries {
		st.Layers++
		st.Bytes += e.size
	}
	return st, nil
}

// Prune deletes least-recently-used layers until the cache is at most
// maxBytes, and removes any partial files an interrupted run left behind.
func (c *Cache) Prune(maxBytes int64) (Stats, error) {
	entries, err := c.entries()
	if err != nil {
		return Stats{}, err
	}
	var total int64
	for _, e := range entries {
		total += e.size
	}
	var removed Stats
	// Oldest first.
	sort.Slice(entries, func(i, j int) bool { return entries[i].used < entries[j].used })
	for _, e := range entries {
		if total <= maxBytes {
			break
		}
		if err := os.Remove(e.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		total -= e.size
		removed.Layers++
		removed.Bytes += e.size
	}
	return removed, nil
}

// Clear removes every entry.
func (c *Cache) Clear() (Stats, error) {
	return c.Prune(0)
}

type entry struct {
	path string
	size int64
	used int64 // unix nanos, last use
}

func (c *Cache) entries() ([]entry, error) {
	dirents, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []entry
	for _, d := range dirents {
		if d.IsDir() {
			continue
		}
		p := filepath.Join(c.dir, d.Name())
		if strings.HasPrefix(d.Name(), ".partial-") {
			os.Remove(p) // leftover from an interrupted run
			continue
		}
		info, err := d.Info()
		if err != nil {
			continue
		}
		out = append(out, entry{path: p, size: info.Size(), used: lastUsed(info)})
	}
	return out, nil
}

// Touch marks a cache hit so Prune keeps hot layers. Renames do not update
// mtime on read, so Get callers bump it explicitly.
func (c *Cache) Touch(h v1.Hash) {
	now := nowFunc()
	_ = os.Chtimes(c.path(h), now, now)
}
