# Changelog

Notable changes to the `stackradar` CLI, written from the perspective of
someone who runs `brew upgrade stackradar` and wants to know whether their
scans, flags or exit codes change.

The version is the `v*` git tag, cut by the Cut release workflow — see
[RELEASING.md](RELEASING.md). The release workflow reads the section matching
the tag it is building and uses it as the GitHub Release notes, so what is
written here is what users read; word it for them rather than for us. A release
with no section here falls back to commit subjects, and warns.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The `###`
headings are `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` and
`Security`. Entries go under `## [Unreleased]` in the pull request that makes
the change; cutting a release moves them under a version.

## [Unreleased]

### Added

- `stackradar scan` — scan the images running in a Kubernetes cluster (via
  the current kubeconfig context; `-n`/`-N` to include or skip namespaces) or
  images named with `--image`, and list the pods affected by known
  vulnerabilities. Matching uses [OSV](https://osv.dev), with CISA KEV
  flagged (`--no-kev` to skip). No account, agent or Docker daemon is needed;
  layers are pulled straight from the registry, using the cluster's
  `imagePullSecrets` with `--use-pull-secrets`.
- Output as a table, JSON (`-o json`) or a self-contained HTML report
  (`-o html`, `--file report.html`); `--serve` opens the report in a browser
  from a localhost-only server.
- `--fail-on <severity>` and `--fail-on kev` exit 2 when a finding meets the
  threshold, for use in CI; `--min-severity` and `--only-fixed` trim the
  report.
- `--platform` to pick the os/arch to scan; by default each image is pulled
  for the architecture of the node its pod runs on.
- A layer cache (`--cache-dir`, `--no-cache`), `--concurrency`, `--timeout`
  (default 30m), `-q`/`-v`, and `--version`.
- Linux, macOS and Windows binaries for amd64 and arm64, a Homebrew tap
  (`brew install lockdep/tap/stackradar`) and cosign-signed checksums.

[Unreleased]: https://github.com/lockdep/stackradar-cli/compare/HEAD...HEAD
