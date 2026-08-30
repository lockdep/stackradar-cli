package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/lockdep/stackradar-cli/internal/k8s"
	"github.com/lockdep/stackradar-cli/internal/kev"
	"github.com/lockdep/stackradar-cli/internal/pull"
	"github.com/lockdep/stackradar-cli/internal/report"
	"github.com/lockdep/stackradar-cli/internal/scan"
	"github.com/lockdep/stackradar-cli/internal/serve"
	"github.com/lockdep/stackradar-cli/internal/ui"
)

var scanOpts struct {
	kubeconfig     string
	kubeContext    string
	images         []string
	namespaces     []string
	excludeNS      []string
	allNS          bool
	concurrency    int
	noKEV          bool
	timeout        time.Duration
	minSeverity    string
	format         string
	file           string
	failOn         string
	onlyFixed      bool
	serve          bool
	port           int
	noOpen         bool
	usePullSecrets bool
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan every image running in the current cluster for known vulnerabilities",
	Long: `Lists the images behind every running container (by digest, so you scan what is
actually running, not what the tag points at today), pulls each unique image
with your local registry credentials, and matches its packages against OSV.

Nothing about your cluster is sent to StackRadar. The only network calls are
to your container registries, api.osv.dev and (unless --no-kev) cisa.gov.

Cluster secrets are never read unless you pass --use-pull-secrets; then the
imagePullSecrets referenced by the scanned pods are read through your
kubeconfig, used in memory for the pull, and never written anywhere.`,
	RunE: runScan,
}

func init() {
	f := scanCmd.Flags()
	f.StringVar(&scanOpts.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: $KUBECONFIG or ~/.kube/config)")
	f.StringVar(&scanOpts.kubeContext, "context", "", "kubeconfig context to use (default: interactive picker on a terminal, else current-context)")
	f.StringSliceVar(&scanOpts.images, "image", nil, "scan these image references instead of a cluster (repeatable; no kubeconfig needed)")
	f.StringSliceVarP(&scanOpts.namespaces, "namespace", "n", nil, "namespace(s) to scan (repeatable; default: all)")
	f.StringSliceVarP(&scanOpts.excludeNS, "exclude-namespace", "N", nil, "namespace(s) to skip (repeatable; e.g. -N kube-system)")
	f.IntVar(&scanOpts.concurrency, "concurrency", runtime.NumCPU(), "images to pull+scan in parallel")
	f.BoolVar(&scanOpts.noKEV, "no-kev", false, "skip the CISA Known Exploited Vulnerabilities lookup")
	f.DurationVar(&scanOpts.timeout, "timeout", 15*time.Minute, "overall time limit")
	f.StringVar(&scanOpts.minSeverity, "min-severity", "low", "lowest severity to show per image: critical|high|medium|low, or none for the summary only")
	f.StringVarP(&scanOpts.format, "output", "o", "table", "report format: table|json|html")
	f.StringVar(&scanOpts.file, "file", "", "write the report here instead of stdout (e.g. --file report.html)")
	f.StringVarP(&scanOpts.failOn, "fail-on", "f", "", "exit 2 if any finding is at or above this severity: critical|high|medium|low, or kev")
	f.BoolVar(&scanOpts.onlyFixed, "only-fixed", false, "only report vulnerabilities that have a fixed version")
	f.BoolVar(&scanOpts.serve, "serve", false, "open the report in your browser (served from localhost, nothing leaves the machine)")
	f.IntVar(&scanOpts.port, "port", 8000, "port for --serve (0 picks a free one)")
	f.BoolVar(&scanOpts.noOpen, "no-open", false, "with --serve: print the URL instead of launching a browser")
	f.BoolVar(&scanOpts.usePullSecrets, "use-pull-secrets", false, "also pull with the cluster's imagePullSecrets (read via your kubeconfig, used in memory only)")
	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), scanOpts.timeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	stderr := cmd.ErrOrStderr()
	stdout := cmd.OutOrStdout()
	if err := report.ValidateSeverity(scanOpts.minSeverity); err != nil {
		return err
	}
	if scanOpts.failOn != "" && scanOpts.failOn != "kev" {
		if err := report.ValidateSeverity(scanOpts.failOn); err != nil {
			return fmt.Errorf("--fail-on: %w (or kev)", err)
		}
	}
	switch scanOpts.format {
	case "table", "json", "html":
	default:
		return fmt.Errorf("unknown output format %q (want table|json|html)", scanOpts.format)
	}

	// No --context: let the user pick one when we can ask, preselecting the
	// kubeconfig's current-context so Enter is the fast path. Never prompt
	// when the report is being piped somewhere — that is a script.
	if scanOpts.kubeContext == "" && len(scanOpts.images) == 0 && !rootOpts.quiet {
		if f, ok := stderr.(*os.File); ok && ui.CanPrompt(f) && isTTY(stdout) {
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

	var err error
	prog := ui.New(stderr, rootOpts.quiet)
	prog.OnInterrupt(stop)
	defer prog.Close()

	// 1. What is running? (or, with --image, what was asked for)
	var inv *k8s.Inventory
	if len(scanOpts.images) > 0 {
		inv = k8s.InventoryFromRefs(scanOpts.images)
	} else {
		inv, err = k8s.ListRunningImages(ctx, k8s.Options{
			Kubeconfig:        scanOpts.kubeconfig,
			Context:           scanOpts.kubeContext,
			Namespaces:        scanOpts.namespaces,
			ExcludeNamespaces: scanOpts.excludeNS,
		})
		if err != nil {
			prog.Close()
			return fmt.Errorf("listing running images: %w", err)
		}
	}
	if len(inv.Images) == 0 {
		prog.Close()
		return fmt.Errorf("no running containers found in context %q", inv.Context)
	}
	prog.ImagesListed(len(inv.Images), inv.PodCount, len(inv.Namespaces), inv.Context)

	// 1b. Registry credentials: local docker login, plus — only when asked —
	// the imagePullSecrets the scanned pods use (if RBAC lets us read them).
	var secrets *k8s.PullSecrets
	if scanOpts.usePullSecrets && len(inv.PullSecretRefs) > 0 {
		secrets, err = k8s.LoadPullSecrets(ctx, k8s.Options{Kubeconfig: scanOpts.kubeconfig, Context: scanOpts.kubeContext}, inv.PullSecretRefs)
		if err != nil {
			prog.Note("could not read imagePullSecrets (%v); using local docker credentials only", err)
			secrets = nil
		} else {
			prog.PullSecretsLoaded(secrets.Loaded, secrets.Skipped)
		}
	}
	keychain := pull.Keychain()
	if secrets != nil && secrets.Len() > 0 {
		keychain = pull.Keychain(secrets)
	}

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
	scanner := scan.New(rootOpts.verbose, func(msg string) { prog.Note("%s", msg) })
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
			tar, err := pull.ToTarball(ctx, img.Ref, keychain)
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

	buildOpts := report.BuildOptions{OnlyFixed: scanOpts.onlyFixed, PullSecretsOffered: !scanOpts.usePullSecrets && len(inv.PullSecretRefs) > 0}
	if secrets != nil {
		buildOpts.PullSecretsUsed = secrets.Loaded
	}
	rep := report.Build(inv, results, kevSet, buildOpts)

	var page []byte
	if scanOpts.format == "html" || scanOpts.serve {
		page, err = report.RenderHTML(rep, report.HTMLOptions{Version: version})
		if err != nil {
			return err
		}
	}

	// Freeze the task list before the report goes out.
	prog.Close()

	out := stdout
	if scanOpts.file != "" {
		f, err := os.Create(scanOpts.file)
		if err != nil {
			return fmt.Errorf("writing %s: %w", scanOpts.file, err)
		}
		defer f.Close()
		out = f
	}
	switch scanOpts.format {
	case "json":
		err = report.WriteJSON(out, rep)
	case "html":
		_, err = out.Write(page)
	default:
		if scanOpts.file == "" && !rootOpts.quiet {
			fmt.Fprintln(stderr)
		}
		err = report.WriteTable(out, rep, scanOpts.minSeverity)
	}
	if err != nil {
		return err
	}
	if scanOpts.file != "" && !rootOpts.quiet {
		fmt.Fprintf(stderr, "Wrote %s\n", scanOpts.file)
	}

	explicit := len(scanOpts.images) > 0
	if !scanOpts.serve {
		return exitStatus(rep, scanOpts.failOn, explicit)
	}
	// The scan is done; the overall --timeout should not tear the page down.
	stop()
	cancel()
	serveCtx, serveStop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer serveStop()
	if err := serve.Run(serveCtx, page, scanOpts.port, func(url string) {
		fmt.Fprintf(stderr, "\nReport at %s  (Ctrl-C to stop)\n", url)
		if !scanOpts.noOpen {
			if err := serve.OpenBrowser(url); err != nil {
				fmt.Fprintf(stderr, "could not open a browser (%v) — open the URL yourself\n", err)
			}
		}
	}); err != nil {
		return err
	}
	return exitStatus(rep, scanOpts.failOn, explicit)
}

// exitStatus decides the process outcome once the report is out. A met
// --fail-on threshold wins (exit 2). Otherwise an image that failed to scan —
// or, when images were named with --image, one this machine could not pull —
// is an error (exit 1): a gate must never pass because the scan did not
// happen. Unreachable images in a cluster scan are expected (private
// registries) and stay exit 0.
func exitStatus(rep *report.Report, failOn string, explicitImages bool) error {
	if err := report.CheckThreshold(rep, failOn); err != nil {
		return err
	}
	var problems []string
	if rep.Errored > 0 {
		problems = append(problems, fmt.Sprintf("%d image(s) failed to scan", rep.Errored))
	}
	if explicitImages && rep.Unreachable > 0 {
		problems = append(problems, fmt.Sprintf("%d image(s) could not be pulled", rep.Unreachable))
	}
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; ") + " (see the report for details)")
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
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
