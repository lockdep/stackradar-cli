<h1>
  <img src=".github/logo-heading.svg" alt="" width="32" height="40" align="top"> StackRadar CLI
</h1>

**See which of your running Kubernetes pods contain known vulnerabilities — from your laptop, in about a minute, without installing anything in the cluster.**

<p>
    <a href="https://github.com/lockdep/stackradar-cli/releases/latest"><img src="https://img.shields.io/github/release/lockdep/stackradar-cli.svg" alt="GitHub release"></a>
    <a href="https://github.com/lockdep/stackradar-cli"><img src="https://img.shields.io/github/go-mod/go-version/lockdep/stackradar-cli.svg" alt="Go version"></a>
    <a href="https://github.com/lockdep/stackradar-cli/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache-2.0"></a>
</p>

![stackradar scan demo](.github/demo.gif)

When a CVE lands and someone asks **"are we affected?"**, this answers it from what is
*actually running* — the container digests reported by the kubelet — not from what a manifest says.

## Features

- Scans **every running image** in a cluster through your kubeconfig, deduplicated by digest — or a single image with `--image`, no cluster needed
- Matches OS and language packages against [OSV](https://osv.dev) using the embedded [osv-scanner](https://github.com/google/osv-scanner) library
- Flags CVEs in [CISA's Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue, so you fix what is being exploited first
- Pulls images with your existing registry credentials (`~/.docker/config.json`, credential helpers, cloud keychains)
- **Table**, **JSON**, or a self-contained **HTML report** you can share — or open live in your browser with `--serve`
- CI gate with `--fail-on` (exit codes follow grype: `0` clean, `1` error, `2` threshold met)
- Single static binary. No Docker daemon, no cluster-side agent, no account, no telemetry

> [!NOTE]
> Nothing is sent to StackRadar. Image pulls go to **your** registries, package names + versions go to **api.osv.dev**,
> and one GET goes to **cisa.gov** for the KEV catalogue. That is the full list.

## Installation

```bash
curl -fsSL https://raw.githubusercontent.com/lockdep/stackradar-cli/main/install.sh | sh
```

Or with Homebrew / Go:

```bash
brew install lockdep/tap/stackradar
go install github.com/lockdep/stackradar-cli@latest
```

## The basics

Scan a cluster (needs `list pods` — the same permission as `kubectl get pods`):

```bash
# every running image in the current kubeconfig context
stackradar scan

# specific context and namespaces
stackradar scan --context prod -n payments -n checkout

# everything except system namespaces
stackradar scan -N kube-system -N monitoring
```

Scan a single image, no kubeconfig needed:

```bash
stackradar scan --image nginx:1.25
```

Get the report in a different shape:

```bash
stackradar scan -o json > report.json          # every finding, machine-readable
stackradar scan -o html --file report.html     # self-contained HTML to share internally
stackradar scan --serve                        # interactive dashboard on 127.0.0.1, nothing leaves the machine
stackradar scan --min-severity high            # quieter per-image detail (none = summary only)
```

Use it as a gate in CI:

```bash
stackradar scan --fail-on high                 # exit 2 if anything ≥ high is running
stackradar scan --fail-on kev --only-fixed     # exit 2 only on exploited CVEs that have a fix
stackradar scan -q -o json                     # no progress on stderr, just the report
```

Progress goes to stderr and the report to stdout. `-q` silences progress, `-v` turns on debug
logging, `NO_COLOR` is honoured. Run `stackradar scan --help` for every flag.

## Good to know

- **Images it cannot reach.** If an image lives in a registry your laptop has no credentials for,
  the row says `not reachable from here` instead of guessing. An in-cluster agent that uses the
  cluster's own pull secrets solves that — which is what [StackRadar](https://stackradar.io) is.
- **Point in time.** Run it again tomorrow and yesterday's clean image may have a new CVE — nothing
  here watches for that.
- **Severity** is the CVSS base score OSV publishes; advisories without one are reported as
  unscored, not silently dropped into "low".
- **Go binaries** built without module version info (`(devel)`) are skipped rather than reported
  against every advisory ever filed for them.
- **Multi-arch images** are scanned as `linux/amd64`; the digest shown is the manifest-list digest.
- Results will differ slightly from syft/grype or Trivy. Different inventories, different matchers — this is normal.

## Why this exists

[StackRadar](https://stackradar.io) keeps a continuous SBOM of every workload across your clusters
and re-checks it the moment a new advisory lands, with a dated history you can hand to an auditor.
This CLI is the sixty-second, zero-signup version of the same question. Use it, keep it, never
sign up — that's fine.

## Contributing

Bug reports with a redacted `-o json` output are the most useful thing you can send.

```bash
git clone https://github.com/lockdep/stackradar-cli && cd stackradar-cli
GOTOOLCHAIN=auto go build -o stackradar . && ./stackradar scan -n kube-system
go vet ./... && go test ./...
```

stackradar is developed by [lockdep](https://stackradar.io) and released under the [Apache-2.0 License](LICENSE).
