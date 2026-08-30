# Releasing

The git tag is the single source of truth for the version. There is no version
file to bump: `stackradar --version` reports whatever goreleaser stamped in
from the tag, and a `go build` from source reports `dev`.

Tagging `v1.2.3` publishes:

| Artifact | Where |
| --- | --- |
| Binaries | `stackradar_1.2.3_<os>_<arch>.tar.gz` (`.zip` on Windows) for linux, darwin and windows on amd64 and arm64, on the GitHub Release |
| Checksums | `checksums.txt`, cosign-signed (keyless) as `checksums.txt.sig` + `.pem` |
| Homebrew | `Casks/stackradar.rb` in [lockdep/homebrew-tap](https://github.com/lockdep/homebrew-tap), so `brew install lockdep/tap/stackradar` |
| Go | `go install github.com/lockdep/stackradar-cli@v1.2.3` — nothing to publish; the module proxy picks the tag up on first request |

with the release notes taken from `CHANGELOG.md`.

## Cutting a release

Run the **Cut release** workflow from the Actions tab and choose `patch`,
`minor` or `major`. From a terminal that is:

```bash
gh workflow run cut-release.yaml -f bump=minor
```

Choosing which of the three it is (see below) is the whole of the decision. The
workflow does the rest:

1. works out the number from the tags that already exist — `v0.1.1` plus a
   `minor` is `0.2.0` — and refuses a version that has been released;
2. moves the `## [Unreleased]` entries in `CHANGELOG.md` under
   `## [0.2.0] - <today>`, updates the compare links at the foot of the file,
   and commits that to `main`;
3. tags that commit `v0.2.0` and starts the release workflow on it.

Nothing needs preparing first. The changelog is written in the pull requests
that change things, under `## [Unreleased]`; cutting a release is what gives
those entries a version. A release whose Unreleased section is empty fails
instead of shipping notes nobody wrote.

To see the version and the changelog diff without publishing anything:

```bash
gh workflow run cut-release.yaml -f bump=minor -f dry_run=true
```

Then watch the release itself:

```bash
gh run watch "$(gh run list --workflow=release.yaml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

### What the release workflow needs

- `HOMEBREW_TAP_TOKEN` — a repository secret holding a token that can write
  to `lockdep/homebrew-tap` (fine-grained PAT, that one repository, Contents:
  read and write). The built-in `GITHUB_TOKEN` cannot push to another
  repository. Without it the release fails at the Homebrew step, after the
  GitHub Release exists; re-run the workflow once the secret is set.
- Nothing else: cosign signs with the job's own OIDC identity, so there is no
  key to keep.

### Tagging by hand

The tag is still the only thing that matters, so releasing without the workflow
is releasing normally — write the `## [1.2.3]` section yourself, land it on
`main`, then:

```bash
git checkout main && git pull
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

A tag pushed from a laptop starts the release workflow through its `push`
trigger. A tag with no matching changelog section still releases — the notes
fall back to the commit subjects since the previous tag — but the run carries a
warning, because commit subjects are written for us, not for the people running
the CLI.

### Choosing the number

Semver, judged from the *user's* perspective — someone with `stackradar` in a
script or CI job:

- **major** — a breaking change to the CLI's contract: a removed or renamed
  flag or subcommand, a changed exit code, a changed default that alters what
  a scan reports, or a change to the JSON output's shape.
- **minor** — new capability existing users can take or leave: a new flag, a
  new output format, a new column.
- **patch** — bug fixes and dependency bumps that change nothing a user
  invokes.

While on `0.x`, breaking changes go in the *minor* position (`0.1.0` → `0.2.0`);
semver explicitly allows this pre-1.0.

### Prereleases

A tag with a prerelease suffix (`v1.2.3-rc.1`) publishes the binaries and a
GitHub Release marked as a prerelease, and skips the Homebrew formula, so
`brew` users are never moved onto a candidate. Same workflow, with an
identifier — the counter continues from whatever candidate exists, so running
this twice gives `rc.1` then `rc.2`:

```bash
gh workflow run cut-release.yaml -f bump=minor -f prerelease=rc
```

A candidate does not consume the version and does not touch `CHANGELOG.md`. The
number is always computed from the last *stable* tag, so the `minor` release cut
after `v1.2.0-rc.2` is `1.2.0` itself, and its notes are the entries that were
under `## [Unreleased]` all along.

## Released versions are immutable

The release workflow refuses to run if a GitHub Release for the tag already
exists. A published version is a promise about specific bytes: republishing
over it would invalidate every checksum and signature a user has recorded, and
the Homebrew formula's `sha256` would no longer match.

If a release is wrong, cut the next patch version. Do not delete and re-push a
tag that has already been released.

If a release run fails *before* it published anything — a flaky runner, a
missing secret — the tag is fine and only the run needs repeating:

```bash
gh workflow run release.yaml --ref v1.2.3
```

If the tag itself is wrong (cut from the wrong commit, wrong number), delete it
and cut again. The changelog commit it came with stays on `main`, and cutting
the same number a second time reuses the section already written.

```bash
git push --delete origin v1.2.3
git tag -d v1.2.3
```
