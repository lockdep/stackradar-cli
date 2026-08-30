# Security policy

## Reporting a vulnerability

Please report security issues in the StackRadar CLI privately to **security@stackradar.io**
rather than opening a public issue. Include the version (`stackradar --version`), your OS/arch,
and steps to reproduce. You will get an acknowledgement within 3 business days.

## Scope

This tool runs on your machine with your kubeconfig and registry credentials. Things we treat
as security issues:

- credentials (docker config, cluster `imagePullSecrets`) being written to disk, logged, or sent anywhere
- any network call other than your registries, `api.osv.dev` and `cisa.gov`
- the `--serve` report listening on anything but loopback, or serving anything but the report
- a scan reporting clean when the vulnerability lookup actually failed

Vulnerabilities in the embedded [osv-scanner](https://github.com/google/osv-scanner) or other
dependencies are best reported upstream; we pick up fixes through Dependabot and `govulncheck` in CI.

## Supported versions

Only the latest release receives fixes.
