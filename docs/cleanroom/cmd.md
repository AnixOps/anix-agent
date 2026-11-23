# Specification: command line (`cmd`, `main.go`)

## Scope

Deleted before implementation, to be written new: `main.go`,
`cmd/cmd.go`, `cmd/common.go`, `cmd/server.go`, `cmd/version.go`,
`cmd/x25519.go`, `cmd/service_linux.go`, `cmd/server_test.go`, and in
`cmd/uninstall_linux.go` the `uninstall` command registration (`init`,
`purgeConfig`) and `uninstallHandle`. The `uninstaller` type, its
methods, `ensureRoot`, `uninstallRoot` and `uninstallSystemctl` stay.

Stays and is context: the other files in `cmd` (`join.go` with
`exitError`/`ExitCode`, `identity.go`, `forward.go`, `migrate_paths.go`,
`upgrade.go`, `validate_config.go`, `uninstall_linux.go`), their tests,
`common/layout`, `common/hosttune`, and the packages the server starts.

## Program

`main.go`: run `cmd.Run()`; on error exit with `cmd.ExitCode(err)`.

`cmd.Run() error`: set `panel.Version` to the build version, execute the
root command; when the error is not an `*exitError` (which has printed
itself) log it with logrus at error level; return it.

Constants: command name `anix-agent`, product name `AnixOps Agent`;
`serviceName = layout.Service + ".service"`, `defaultConfigPath =
layout.ConfigDir + "/config.json"`. The package variable `version`
(default `"v5.0.10"`) is set by release builds with
`-ldflags "-X github.com/AnixOps/anix-agent/v5/cmd.version=<tag>"`;
keep that exact symbol. The root command imports
`github.com/AnixOps/anix-agent/v5/core/imports` for its side effects.

Terminal helpers used by other files: `Err`, `Ok`, `Warn(msg ...any)
string` return the message wrapped in ANSI red, green, yellow and reset.

## Logging

On start the process sets a logrus text formatter with full timestamps in
local time (`time.DateTime` layout) that rewrites every node tag of the
form `[<host>]-<protocol>:<id>` (host without `]` or spaces, protocol
`[a-z0-9]+`) to `node-<id>`, so the journal names no protocol or Control
host. `cmd/logformat_test.go` (stays) tests it through a type named
`logFormatter` embedding `log.TextFormatter`; make it pass.

## Commands

- Root `anix-agent`: runs the server (same handler as `server`). Persistent
  flags: `-c/--config` (default `defaultConfigPath`), `-w/--watch`
  (default true). Long help lists `server`, `-c`, `join`, `version`.
- `server`: no arguments; runs the server (below). The installed unit
  runs `anix-agent server -c /etc/anixops/agent/config.json`
  (`cmd/installer_test.go` checks the flag parses).
- `version`: prints `AnixOps Agent <version>` to the command's output.
- `x25519`: prints a new random X25519 key pair, base64 raw URL encoding,
  as `Private key: <k>` and `Public key: <k>` lines (use `crypto/ecdh`).
  No prompts.
- `start`, `stop`, `restart`: run `systemctl <action> <serviceName>`; on
  failure return an error with systemctl's output; on success print a
  green confirmation pointing to `anix-agent log`.
- `log`: run `journalctl -u <serviceName> -e --no-pager -f` attached to
  the terminal.
- `update [--version vX.Y.Z]`: the version must match
  `^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+(\.dev\.[0-9]+)?)?)?$`;
  download `https://raw.githubusercontent.com/AnixOps/anix-agent/main/scripts/install.sh`
  to a temporary file (removed afterwards) and run it with bash, passing
  the version as its argument when given, attached to the terminal.
- `uninstall [--purge]`: requires root (`ensureRoot`); asks
  `确定要卸载 AnixOps Agent 吗?(y/N)` (yellow) on the command's output and
  reads one word from its input; anything but `y`/`Y` prints `已取消卸载`
  and returns nil. Otherwise run `(&uninstaller{root: uninstallRoot,
  purge: <flag>, systemctl: uninstallSystemctl}).uninstall()`, call its
  `report(out)`, and on error return `卸载未完成: <err>`, else print
  `卸载成功` in green. The long help and the `--purge` help describe what is
  removed and kept (read the uninstaller); `SilenceUsage` is set.
  `cmd/uninstall_linux_test.go` (stays) drives it through a package
  variable `purgeConfig`.

Dropped on purpose: a `synctime` command (hosts run their own NTP
client) and deriving an X25519 key from node id, type and token.

## The server

1. Log the version line. Load the configuration with `conf.New()` +
   `LoadFromPath(config)`; failure is returned (wrapped with the path).
2. Apply the log config: `Level` through `logrus.ParseLevel` (unknown or
   empty leaves the level); a non-empty `Output` is opened for append
   (0644) and becomes the log output; if it cannot be opened, log an
   error and keep stdout.
3. Run, in this order (these functions exist and stay):
   `migrateLegacyPaths(c)` (keep the existing function and its messages;
   it lives in `server.go` today, so write it again: for each report of
   `c.MigrateLegacyDefaults(conf.MigrateOptions{})` log a warning with
   `what/from/to` and the error, telling the operator to run
   `anix-agent migrate-paths` as root, or an info line that the earlier
   directory was copied and is no longer used),
   `tuneHostTCP()` (on Linux unless `ANIXOPS_TCP_TUNE=0`: apply
   `hosttune.ApplyTCP("/proc/sys")`, log what changed at info and an
   error at warning), `upgrade.Shared(panel.Version).LogLastResult()`.
4. Forwarding, when `c.Forward.Enabled()`:
   `node.NewForwardComponent(c.Forward, c.NodeConfig)` (closed at exit).
   When `c.Forward.ForwardNodeOnly()`: `node.StartForward(c.Forward,
   component)` (closed at exit); if there are no cores and no nodes,
   wait for SIGINT/SIGTERM and return nil.
5. (Removed 2026-11-23: the top-level `AnxLine` section.)
6. When `c.AnxKeyRotation.Enabled()`: `node.KeyRotator(...)`; non-nil →
   `Start`, closed at exit; nil → warn that there is no anx-server.
7. The data plane: `node.New()`; when forwarding is on and the Agent is
   not forward-only, `SetForward(component, proxyNodeID)`. Build the core
   with `vCore.NewForConfig(c.CoresConfig, len(c.NodeConfig))`, `Start`
   it, then `nodes.Start(c.NodeConfig, core)`; errors returned wrapped.
   The current core is closed at exit.
8. With `--watch`: `c.Watch(config, reload)`; a reload (under a lock, so
   it never races the exit) runs `migrateLegacyPaths`, closes the nodes,
   closes the core (on error: log and stop the reload), builds and starts
   a new core and starts the nodes on it (errors logged), then
   `runtime.GC()`.
9. Wait for SIGINT or SIGTERM; return nil.

Each step's failure is returned as an error naming the step (the root
command logs it). Every startup failure returns a non-nil error
(`cmd/server_test.go` must check a missing config file).

## Tests

Write `cmd/server_test.go` (missing config → error; `Run` with test args
does not panic). All of `GOEXPERIMENT=jsonv2 GOWORK=off go test ./cmd/...`
must pass, and `go vet -tags anixcore ./...`.
