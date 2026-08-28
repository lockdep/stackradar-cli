// Package kev loads CISA's Known Exploited Vulnerabilities catalogue.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const feedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type Set map[string]bool

func (s Set) Has(cve string) bool { return s != nil && s[cve] }

type feed struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// Load fetches the catalogue, caching it for 24h in the user cache dir.
func Load(ctx context.Context) (Set, error) {
	cache := cachePath()
	if cache != "" {
		if st, err := os.Stat(cache); err == nil && time.Since(st.ModTime()) < 24*time.Hour {
			if b, err := os.ReadFile(cache); err == nil {
				if s, err := parse(b); err == nil {
					return s, nil
				}
			}
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "stackradar-cli")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cisa.gov returned %s", resp.Status)
	}
	var buf []byte
	buf, err = readAll(resp)
	if err != nil {
		return nil, err
	}
	s, err := parse(buf)
	if err != nil {
		return nil, err
	}
	if cache != "" {
		_ = os.MkdirAll(filepath.Dir(cache), 0o755)
		_ = os.WriteFile(cache, buf, 0o644)
	}
	return s, nil
}

func readAll(resp *http.Response) ([]byte, error) {
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		out = append(out, buf[:n]...)
		if err != nil {
			if err.Error() == "EOF" {
				return out, nil
			}
			return out, err
		}
	}
}

func parse(b []byte) (Set, error) {
	var f feed
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	s := Set{}
	for _, v := range f.Vulnerabilities {
		s[v.CVEID] = true
	}
	return s, nil
}

func cachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "stackradar", "kev.json")
}
