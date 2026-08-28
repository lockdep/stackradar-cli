package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/lockdep/stackradar-cli/internal/k8s"
	"github.com/lockdep/stackradar-cli/internal/kev"
	"github.com/lockdep/stackradar-cli/internal/pull"
	"github.com/lockdep/stackradar-cli/internal/report"
	"github.com/lockdep/stackradar-cli/internal/scan"
	"github.com/lockdep/stackradar-cli/internal/serve"
	"github.com/lockdep/stackradar-cli/internal/ui"
)

var scanOpts struct {
	kubeconfig  string
	kubeContext string
	namespaces  []string
	excludeNS   []string
	allNS       bool
	concurrency int
	jsonOut     bool
	noKEV       bool
	timeout     time.Duration
	minSeverity string
	output      string
	serve       bool
	port        int
	noOpen      bool
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan every image running in the current cluster for known vulnerabilities",
	Long: `Lists the images behind every running container (by digest, so you scan what is
actually running, not what the tag points at today), pulls each unique image
with your local registry credentials, and matches its packages against OSV.

Nothing about your cluster is sent to StackRadar. The only network calls are
to your container registries, api.osv.dev and (unless --no-kev) cisa.gov.`,
	RunE: runScan,
}

func init() {
	f := scanCmd.Flags()
	f.StringVar(&scanOpts.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVar(&scanOpts.kubeContext, "context", "", "kubeconfig context to use (default: interactive picker on a terminal, else current-context)")
	f.StringSliceVarP(&scanOpts.namespaces, "namespace", "n", nil, "namespace(s) to scan (repeatable; default: all)")
	f.StringSliceVarP(&scanOpts.excludeNS, "exclude-namespace", "N", nil, "namespace(s) to skip (repeatable; e.g. -N kube-system)")
	f.IntVar(&scanOpts.concurrency, "concurrency", runtime.NumCPU(), "images to pull+scan in parallel")
	f.BoolVar(&scanOpts.jsonOut, "json", false, "emit machine-readable JSON instead of the table")
	f.BoolVar(&scanOpts.noKEV, "no-kev", false, "skip the CISA Known Exploited Vulnerabilities lookup")
	f.DurationVar(&scanOpts.timeout, "timeout", 15*time.Minute, "overall time limit")
	f.StringVar(&scanOpts.minSeverity, "min-severity", "low", "lowest severity to show per image: critical|high|medium|low")
	f.StringVarP(&scanOpts.output, "output", "o", "", "also write a self-contained HTML report to this file")
	f.BoolVar(&scanOpts.serve, "serve", false, "open the report in your browser (served from localhost, nothing leaves the machine)")
	f.IntVar(&scanOpts.port, "port", 8000, "port for --serve (0 picks a free one)")
	f.BoolVar(&scanOpts.noOpen, "no-open", false, "with --serve: print the URL instead of launching a browser")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), scanOpts.timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	stderr := cmd.ErrOrStderr()
	if err := report.ValidateSeverity(scanOpts.minSeverity); err != nil {
		return err
	}

	// No --context: let the user pick one when we can ask, preselecting the
	// kubeconfig's current-context so Enter is the fast path.
	if scanOpts.kubeContext == "" && !scanOpts.jsonOut {
		if f, ok := stderr.(*os.File); ok && ui.CanPrompt(f) {
			names, current, err := k8s.ListContexts(scanOpts.kubeconfig)
			if err != nil {
				return fmt.Errorf("reading kubeconfig: %w", err)
			}
			switch {
			case len(names) == 0:
				return fmt.Errorf("no contexts in kubeconfig; pass --kubeconfig")
			case len(names) == 1:
				scanOpts.kubeContext = names[0]
			default:
				chosen, err := ui.PickContext(f, names, current)
				if err != nil {
					return err
				}
				scanOpts.kubeContext = chosen
			}
		}
	}

	prog := ui.New(stderr, scanOpts.jsonOut)
	prog.OnInterrupt(stop)
	defer prog.Close()

	// 1. What is running?
	inv, err := k8s.ListRunningImages(ctx, k8s.Options{
		Kubeconfig:        scanOpts.kubeconfig,
		Context:           scanOpts.kubeContext,
		Namespaces:        scanOpts.namespaces,
		ExcludeNamespaces: scanOpts.excludeNS,
	})
	if err != nil {
		prog.Close()
		return fmt.Errorf("listing running images: %w", err)
	}
	if len(inv.Images) == 0 {
		prog.Close()
		return fmt.Errorf("no running containers found in context %q", inv.Context)
	}
	prog.ImagesListed(len(inv.Images), inv.PodCount, len(inv.Namespaces), inv.Context)

	// 2. KEV catalogue, fetched concurrently with the pulls.
	var kevSet kev.Set
	var kevWG sync.WaitGroup
	if scanOpts.noKEV {
		prog.KEVSkipped()
	} else {
		kevWG.Add(1)
		go func() {
			defer kevWG.Done()
			var kevErr error
			kevSet, kevErr = kev.Load(ctx)
			prog.KEVLoaded(len(kevSet), kevErr)
		}()
	}

	// 3. Pull + scan each image.
	scanner := scan.New()
	results := make([]report.ImageResult, len(inv.Images))
	sem := make(chan struct{}, max(1, scanOpts.concurrency))
	var wg sync.WaitGroup
	for i, img := range inv.Images {
		prog.Image(img.Display(), ui.Queued, ui.Outcome{})
		wg.Add(1)
		go func(i int, img k8s.Image) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := report.ImageResult{Image: img}
			prog.Image(img.Display(), ui.Pulling, ui.Outcome{})
			tar, err := pull.ToTarball(ctx, img.Ref)
			if err != nil {
				res.Err = err
				res.Unreachable = pull.IsAuthOrNotFound(err)
			} else {
				defer os.Remove(tar)
				prog.Image(img.Display(), ui.Scanning, ui.Outcome{})
				res.Findings, res.Err = scanner.Tarball(ctx, tar)
			}
			results[i] = res
			prog.Image(img.Display(), ui.Done, outcome(res))
		}(i, img)
	}
	wg.Wait()
	kevWG.Wait()
	if ctx.Err() != nil {
		prog.Close()
		return ctx.Err()
	}

	rep := report.Build(inv, results, kevSet)

	var page []byte
	if scanOpts.output != "" || scanOpts.serve {
		page, err = report.RenderHTML(rep, report.HTMLOptions{Version: version})
		if err != nil {
			return err
		}
	}
	if scanOpts.output != "" {
		if err := os.WriteFile(scanOpts.output, page, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", scanOpts.output, err)
		}
		prog.Note("Wrote %s", scanOpts.output)
	}

	// Freeze the task list before the report goes to stdout.
	prog.Close()

	if scanOpts.jsonOut {
		if err := report.WriteJSON(cmd.OutOrStdout(), rep); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(stderr)
		if err := report.WriteTable(cmd.OutOrStdout(), rep, scanOpts.minSeverity); err != nil {
			return err
		}
	}

	if !scanOpts.serve {
		return nil
	}
	// The scan is done; the overall --timeout should not tear the page down.
	stop()
	cancel()
	serveCtx, serveStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer serveStop()
	return serve.Run(serveCtx, page, scanOpts.port, func(url string) {
		fmt.Fprintf(stderr, "\nReport at %s  (Ctrl-C to stop)\n", url)
		if !scanOpts.noOpen {
			if err := serve.OpenBrowser(url); err != nil {
				fmt.Fprintf(stderr, "could not open a browser (%v) — open the URL yourself\n", err)
			}
		}
	})
}

func outcome(r report.ImageResult) ui.Outcome {
	o := ui.Outcome{Findings: len(r.Findings), Err: r.Err, Unreachable: r.Unreachable}
	for _, f := range r.Findings {
		switch report.FromCVSS(f.CVSS) {
		case report.Critical:
			o.Critical++
		case report.High:
			o.High++
		case report.Medium:
			o.Medium++
		case report.Low:
			o.Low++
		default:
			o.Unknown++
		}
	}
	return o
}
