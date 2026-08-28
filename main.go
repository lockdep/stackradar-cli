// stackradar is a read-only CLI that lists the container images running in
// your Kubernetes cluster and checks them against the OSV vulnerability
// database — locally, with nothing sent to StackRadar.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/lockdep/stackradar-cli/cmd"
	"github.com/lockdep/stackradar-cli/internal/report"
)

// Exit codes follow grype: 0 clean, 1 error, 2 --fail-on threshold reached.
func main() {
	err := cmd.Execute()
	if err == nil {
		return
	}
	var thr *report.ThresholdError
	if errors.As(err, &thr) {
		fmt.Fprintln(os.Stderr, thr.Error())
		os.Exit(2)
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
