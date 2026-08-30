package cmd

import (
	"github.com/spf13/cobra"
)

// Set by GoReleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
)

var rootOpts struct {
	quiet   bool
	verbose bool
}

var rootCmd = &cobra.Command{
	Use:           "stackradar",
	Short:         "See which running pods contain known vulnerabilities — from your laptop, in about a minute",
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       version + " (" + commit + ")",
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.BoolVarP(&rootOpts.quiet, "quiet", "q", false, "no progress or notices on stderr; only the report on stdout")
	pf.BoolVarP(&rootOpts.verbose, "verbose", "v", false, "debug logging on stderr (registry, scanner internals)")
}

func Execute() error {
	return rootCmd.Execute()
}
