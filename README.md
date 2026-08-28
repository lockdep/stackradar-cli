# stackradar

**See which of your running Kubernetes pods contain known vulnerabilities — from your laptop, in about a minute, without installing anything in the cluster.**

```
$ stackradar scan

 ✔ Listed running images      [39 images · 61 pods · 8 namespaces · prod-eu]
 ✔ Loaded CISA KEV catalogue  [1412 exploited CVEs]
 ✔ Scanned images             [39 images in 1m12s]
   ├── by severity: 167 critical, 446 high, 546 medium, 66 low
   └── skipped:     1 not reachable from here

39 images · 61 pods · 8 namespaces · context prod-eu

IMAGE                                                CRITICAL  HIGH  MEDIUM  LOW  KEV    PODS
docker.io/grafana/grafana:12.4.2@83749231c383        14        51    66      5     1     1
ghcr.io/dexidp/dex:v2.43.0@b08a58c9731c              19        28    30      5    -      1
quay.io/argoproj/argocd:v3.2.3@9ab6baab65a6          17        23    37      4    -      7
registry.internal/payments-api:9f1fd70@957da44ee38f  ·         ·     ·       ·    ·      3     not reachable from here
...

Total: 167 critical, 446 high, 546 medium, 66 low

 KEV  1 vulnerability in CISA's Known Exploited Vulnerabilities catalogue — actively exploited in the wild
      VULNERABILITY   PACKAGE  WORKLOADS
      CVE-2026-31789  openssl  monitoring/grafana-fbfc6595c-62kln
```

While it runs you get a live task list (spinner, progress bar, which images are
being pulled/scanned right now); the same output degrades to plain lines when
stderr is not a terminal, and `NO_COLOR` is honoured.

```

It answers the question every platform team gets asked at 09:00 when a CVE lands:
**"are we affected?"** — using what is *actually running* (container digests reported by
the kubelet), not what a manifest says.

## Install

```sh
brew install lockdep/tap/stackradar
# or
curl -fsSL https://raw.githubusercontent.com/lockdep/stackradar-cli/main/install.sh | sh
# or
go install github.com/lockdep/stackradar-cli@latest
```

Single static binary. No Docker daemon, no `osv-scanner` install, no cluster-side agent.

## Usage

```sh
stackradar scan                          # pick a kubeconfig context (current one preselected), all namespaces
stackradar scan --context prod -n payments -n checkout
stackradar scan -N kube-system -N monitoring    # everything except those namespaces
stackradar scan --min-severity high      # quieter per-image detail
stackradar scan -o json > report.json    # everything, machine-readable
stackradar scan -o html --file report.html   # self-contained HTML you can share internally
stackradar scan --serve                  # open the report in your browser (localhost only)
stackradar scan --fail-on high           # CI gate: exit 2 if anything ≥ high is running
stackradar scan --fail-on kev --only-fixed   # exit 2 only on exploited CVEs that have a fix
stackradar scan -q -o json               # no progress on stderr, just the report
stackradar scan --no-kev                 # skip the cisa.gov lookup
```

Exit codes follow grype: `0` clean, `1` error, `2` the `--fail-on` threshold was met.
`-q` silences progress and notices on stderr; `-v` turns on debug logging.

`--serve` renders the same data as a small dashboard — filter by namespace, severity, fixable,
KEV; click an image for its findings — served from `127.0.0.1` by the binary itself. Everything
is embedded, so the page makes no network requests. `--no-open` prints the URL instead of
launching a browser; `--port 0` picks a free port.

It needs `list pods` on the namespaces you scan — the same permission as `kubectl get pods`.

## What it does, exactly

1. Lists running pods through your kubeconfig (via client-go — `kubectl` itself is not required).
2. Takes the **image digest** from each container status (`imageID`), so a `:latest` tag on
   your laptop can never disagree with what the node is running. Deduplicates by digest.
3. Pulls each unique image with the same credentials `docker` / `crane` would use
   (`~/.docker/config.json`, credential helpers, cloud keychains).
4. Generates the package inventory and matches it against [OSV](https://osv.dev) using the
   embedded [osv-scanner](https://github.com/google/osv-scanner) library.
5. Cross-references every CVE with [CISA's Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalogue (cached locally for 24 h).
6. Prints a table, worst image first — or, with `--serve` / `--output`, a self-contained HTML report.

### What leaves your machine

- Image pulls go to **your** registries.
- Package lists (name + version, nothing else) are queried against **api.osv.dev**.
- One GET to **cisa.gov** for the KEV catalogue.

Nothing is sent to StackRadar. There is no telemetry. The code is short — read it.

### Images it cannot reach

If an image lives in a registry your laptop has no credentials for (or that is only reachable
from inside the cluster), the row says `not reachable from here` instead of guessing. An
in-cluster agent that uses the cluster's own pull secrets is what solves that — which is
what [StackRadar](https://stackradar.io) is.

## Limitations (honest ones)

- Point in time. Run it again tomorrow and yesterday's clean image may have a new CVE — nothing
  here watches for that.
- Go binaries built without module version info (`(devel)`) are skipped rather than
  reported against every advisory ever filed for them.
- Severity is the CVSS base score OSV publishes; advisories without one are counted as
  "unscored", not silently dropped into "low".
- Pulls the `linux/amd64` variant of multi-arch images. Package contents are the same
  across architectures in practice, but the digest you see is the manifest-list digest.
- Results will differ slightly from what a syft/grype or Trivy run reports. Different
  inventories, different matchers — this is normal.

## Why this exists

[StackRadar](https://stackradar.io) keeps a continuous SBOM of every workload across your
clusters and re-checks it the moment a new advisory lands, with a dated history you can hand
to an auditor (the EU CRA's 24-hour reporting obligation applies from 11 September 2026).
This CLI is the sixty-second, zero-trust-required version of the same question. Use it,
keep it, never sign up — that's fine.

## Developing

```sh
git clone https://github.com/lockdep/stackradar-cli && cd stackradar-cli
GOTOOLCHAIN=auto go build -o stackradar . && ./stackradar scan -n kube-system
go test ./...
```

`GOTOOLCHAIN=auto` lets Go fetch the version pinned in `go.mod` if your local one is older.
Progress goes to stderr and the report to stdout, so `2>/dev/null` leaves just the report;
`-o json` shows every finding, the table truncates at 15 per image.

## Contributing

Bug reports with a redacted `-o json` output are the most useful thing you can send.
`go vet ./...`, `go test ./...` and `go build ./...` are the whole CI.

## License

Apache-2.0.
