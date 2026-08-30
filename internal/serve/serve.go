// Package serve hosts a rendered report on localhost.
package serve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"time"
)

// Run serves page at http://127.0.0.1:port/ until ctx is cancelled. port 0
// picks a free one. It returns the URL through ready before blocking.
// Loopback only: the report contains pod names and image digests, and a
// shared file (--output) is the intended way to hand it to someone else.
func Run(ctx context.Context, page []byte, port int, ready func(url string)) error {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("listening on port %d: %w", port, err)
	}
	url := "http://" + ln.Addr().String() + "/"

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'")
		_, _ = w.Write(page)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	if ready != nil {
		ready(url)
	}
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// OpenBrowser tries the platform's default opener; failure is not an error
// worth stopping for, the URL is printed anyway.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}
