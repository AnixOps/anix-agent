# Specification: repository files

## Scope

Deleted before implementation, to be written new:
`.github/workflows/release.yml`, `.github/workflows/codeql-analysis.yml`,
`.github/dependabot.yml`, `.github/ISSUE_TEMPLATE/bug-report.md`,
`.gitignore`. Deleted and not replaced: `.github/build/friendly-filenames.json`
(nothing reads it). `go.mod` / `go.sum` are regenerated (below).
`LICENSE` and the README's attribution are not in scope: the owner decides
them after the code is replaced.

## `release.yml` ("Build and Release")

Triggers: manual dispatch; push to `main` and tags `v*`; pull requests to
`main`. Default permissions `contents: read`. Concurrency: per workflow,
pull requests grouped by ref with cancel-in-progress, every other run in
its own group (`github.run_id`). Workflow env
`ANIXOPS_OFFICIAL_PUBLIC_KEY: 'jW26nr2tbthASoeq6RmIpx8Ah+uhPNIv9V1ewRVb1VE='`
(the official release key, base64 raw Ed25519).

Jobs (names matter: branch protection and other workflows refer to
`validate release tag`, `release prerequisite tests`, `build (linux-64)`,
`build (linux-arm64-v8a)`):

1. `tag-gate` named `validate release tag`: output `is_release_tag` is
   true only for a push or dispatch on a tag matching
   `^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$`; when true run
   `python3 scripts/check_release_version.py --tag "$GITHUB_REF_NAME"`.
2. `test` named `release prerequisite tests`: always run
   `python3 scripts/check_release_version.py --self-test`,
   `python3 scripts/check_release_assets.py --self-test` and
   `python3 scripts/check_release_assets.py workflow --file .github/workflows/release.yml`.
   On tags only: Go 1.26.11, protoc 29.2 (`arduino/setup-protoc@v3`),
   `protoc-gen-go@v1.36.11` and `protoc-gen-go-grpc@v1.6.1`, regenerate
   `api/anxmgmt` with `bash api/anxmgmt/gen.sh` and fail on any diff or
   untracked file there, `go mod download`, fail on gofmt differences of
   tracked Go files, then `GOEXPERIMENT=jsonv2 GOWORK=off go test ./... -count=1`.
3. `build` named `build (<asset>)`, needs `test`, matrix linux/amd64 →
   `linux-64` and linux/arm64 → `linux-arm64-v8a`, `CGO_ENABLED=0`, not
   fail-fast: run `bash scripts/check_release_build_policy.sh`; Go 1.26.11;
   `go mod download`; version = tag name on tags, else the commit SHA;
   build `build_assets/anix-agent` with `GOEXPERIMENT=jsonv2`, tags
   `anixcore`, `-trimpath -buildvcs=false`, ldflags
   `-X 'github.com/AnixOps/anix-agent/v5/cmd.version=<version>' -s -w -buildid=`;
   copy `README.md`, `LICENSE` and `example/*.json` into `build_assets`;
   zip the directory (all files with a fixed mtime of 1 January of the
   current year) as `anix-agent-<asset>.zip`; write
   `anix-agent-<asset>.zip.dgst` with one line per algorithm md5, sha1,
   sha256, sha512 in the form `<ALGO>= <hex>` (Control's installer reads
   the `SHA256=`/`SHA2-256=` line); run
   `python3 scripts/check_release_assets.py zip --zip <zip>`; upload zip
   and dgst as artifact `package-<asset>` kept 3 days.
4. `release`: only when `is_release_tag` is true, needs `build` and
   `tag-gate`, `contents: write`. Download `package-*` into `dist`. With
   secrets `ANIXOPS_PLUGIN_SIGNING_PRIVATE_KEY` and
   `ANIXOPS_PLUGIN_OFFICIAL_PUBLIC_KEY`: fail when the private key is
   empty (message pointing to docs/INSTALL.md "Release Signing") or the
   public key secret differs from `ANIXOPS_OFFICIAL_PUBLIC_KEY`; write
   `SHA256SUMS` of both zips; for each zip and `SHA256SUMS` write
   `<file>.sig` = base64 (one line) of the raw Ed25519 signature
   (`openssl pkeyutl -sign -rawin`) and verify it against the official
   key (DER SubjectPublicKeyInfo built from the raw key); the key file is
   private (0600) and removed on exit. List `dist`, then publish with
   `softprops/action-gh-release@v2`: tag name, generated notes,
   prerelease when the tag contains `-alpha`, `-beta` or `-rc`, files:
   both zips with `.dgst` and `.sig`, `SHA256SUMS`, `SHA256SUMS.sig`.

`scripts/check_release_assets.py workflow` must accept the file.

## `codeql-analysis.yml` ("CodeQL")

Go analysis on pushes and pull requests to `main` and weekly (Wednesday
22:43 UTC); permissions `actions: read`, `contents: read`,
`security-events: write` (uploading needs it); same concurrency rule as
above; job `Analyze` on ubuntu-24.04: checkout, Go from `go.mod`, CodeQL
v3 init (go), autobuild, analyze with category `/language:go`.

## `dependabot.yml`

Daily `gomod` updates for `/`, and weekly `github-actions` updates.

## `bug-report.md`

A short issue template (front matter: name, about, labels `bug`) asking
for Agent version (`anix-agent version`), Control version, OS and
architecture, the node's protocol, what happened, what was expected,
steps, and relevant `journalctl -u anix-agent` lines with secrets
removed. Chinese and English.

## `.gitignore`

Ignore: built binaries (`/anix-agent`, `/build/`, `/build_assets/`,
`/dist/`), `*.log`, `logs/`, local configs (`config.json`,
`config.local*.json`, `config.debug.json`), local secrets (`*.enc`,
`node/*.key`, `node/*.pem`, `node/cert/`), editor and agent metadata
(`.vscode/`, `.idea/`, `.claude/`). Make sure no tracked file becomes
ignored (`git ls-files -ci --exclude-standard` must stay empty).

## `go.mod` / `go.sum`

Keep `module github.com/AnixOps/anix-agent/v5`, the `go` and `toolchain`
lines, and the versions of the direct dependencies; run `go mod tidy`.
Direct requirements that no code imports any more are dropped by tidy.
