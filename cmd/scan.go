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
)

var scanOpts struct {
	kubeconfig  string
	kubeContext string
	namespaces  []string
	allNS       bool
	concurrency int
	jsonOut     bool
	noKEV       bool
	timeout     time.Duration
	minSeverity string
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
	f.StringVar(&scanOpts.kubeContext, "context", "", "kubeconfig context to use (default: current-context)")
	f.StringSliceVarP(&scanOpts.namespaces, "namespace", "n", nil, "namespace(s) to scan (repeatable; default: all)")
	f.IntVar(&scanOpts.concurrency, "concurrency", runtime.NumCPU(), "images to pull+scan in parallel")
	f.BoolVar(&scanOpts.jsonOut, "json", false, "emit machine-readable JSON instead of the table")
	f.BoolVar(&scanOpts.noKEV, "no-kev", false, "skip the CISA Known Exploited Vulnerabilities lookup")
	f.DurationVar(&scanOpts.timeout, "timeout", 15*time.Minute, "overall time limit")
	f.StringVar(&scanOpts.minSeverity, "min-severity", "low", "lowest severity to show per image: critical|high|medium|low")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), scanOpts.timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	stderr := cmd.ErrOrStderr()
	progress := func(format string, a ...any) {
		if !scanOpts.jsonOut {
			fmt.Fprintf(stderr, format+"\n", a...)
		}
	}

	if err := report.ValidateSeverity(scanOpts.minSeverity); err != nil {
		return err
	}

	// 1. What is running?
	inv, err := k8s.ListRunningImages(ctx, k8s.Options{
		Kubeconfig: scanOpts.kubeconfig,
		Context:    scanOpts.kubeContext,
		Namespaces: scanOpts.namespaces,
	})
	if err != nil {
		return fmt.Errorf("listing running images: %w", err)
	}
	if len(inv.Images) == 0 {
		return fmt.Errorf("no running containers found in context %q", inv.Context)
	}
	progress("Found %d unique images across %d pods in %d namespaces (context %s)",
		len(inv.Images), inv.PodCount, len(inv.Namespaces), inv.Context)

	// 2. KEV catalogue, fetched concurrently with the pulls.
	var kevSet kev.Set
	var kevErr error
	var kevWG sync.WaitGroup
	if !scanOpts.noKEV {
		kevWG.Add(1)
		go func() {
			defer kevWG.Done()
			kevSet, kevErr = kev.Load(ctx)
		}()
	}

	// 3. Pull + scan each image.
	scanner := scan.New()
	results := make([]report.ImageResult, len(inv.Images))
	sem := make(chan struct{}, max(1, scanOpts.concurrency))
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, img := range inv.Images {
		wg.Add(1)
		go func(i int, img k8s.Image) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res := report.ImageResult{Image: img}
			tar, err := pull.ToTarball(ctx, img.Ref)
			if err != nil {
				res.Err = err
				res.Unreachable = pull.IsAuthOrNotFound(err)
			} else {
				defer os.Remove(tar)
				res.Findings, res.Err = scanner.Tarball(ctx, tar)
			}
			mu.Lock()
			results[i] = res
			done++
			progress("  [%d/%d] %s%s", done, len(inv.Images), img.Display(), statusSuffix(res))
			mu.Unlock()
		}(i, img)
	}
	wg.Wait()
	kevWG.Wait()
	if kevErr != nil {
		progress("warning: could not load CISA KEV catalogue (%v); continuing without it", kevErr)
	}

	rep := report.Build(inv, results, kevSet)
	if scanOpts.jsonOut {
		return report.WriteJSON(cmd.OutOrStdout(), rep)
	}
	fmt.Fprintln(stderr)
	return report.WriteTable(cmd.OutOrStdout(), rep, scanOpts.minSeverity)
}

func statusSuffix(r report.ImageResult) string {
	switch {
	case r.Unreachable:
		return "  (not reachable from this machine)"
	case r.Err != nil:
		return "  (error: " + r.Err.Error() + ")"
	default:
		return fmt.Sprintf("  %d findings", len(r.Findings))
	}
}
