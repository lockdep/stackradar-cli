package cmd

import (
	"github.com/spf13/cobra"
)

// Set by GoReleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
)

var rootCmd = &cobra.Command{
	Use:           "stackradar",
	Short:         "See which running pods contain known vulnerabilities — from your laptop, in about a minute",
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       version + " (" + commit + ")",
}

func Execute() error {
	return rootCmd.Execute()
}
