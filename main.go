// stackradar is a read-only CLI that lists the container images running in
// your Kubernetes cluster and checks them against the OSV vulnerability
// database — locally, with nothing sent to StackRadar.
package main

import (
	"fmt"
	"os"

	"github.com/lockdep/stackradar-cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
