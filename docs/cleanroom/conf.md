# Specification: configuration loading (`conf`)

## Scope

Deleted before implementation, to be written new:

- `conf/conf.go`, `conf/node.go`, `conf/core.go`, `conf/cert.go`,
  `conf/limit.go`, `conf/log.go`, `conf/watch.go`, `conf/conf_test.go`
- `common/json5/` (the whole package)
- `example/config.json`

Files in `conf` that stay and that the new code must work with:
`anixcore.go` (`AnixcoreConfig`, `NewAnixcoreConfig`, `InstalledAnxNodePath`),
`wireguard.go` (`WireGuardConfig`, `NewWireGuardConfig`), `forward.go`
(`ForwardConfig`, `(*Conf).normalizeAgentNodes`), `identity.go`
(`AgentIdentityConfig`, `(*Conf).validateAgentIdentities`), `credential.go`
(`(*Conf).validateNodeCredentials`), `stream.go` (`AgentStreamConfig`),
`paths.go`, `production.go` (`(*Conf).ValidateForProduction`) and their
tests. Read them: they use fields of the types below.

## The file

`config.json` is one JSON object. It may contain `//` line comments,
`/* */` block comments and a trailing comma before `]` or `}`; these are
removed before decoding. Text inside strings (including escaped quotes) is
never changed. Write this pre-processor yourself (a few dozen lines); do
not add a dependency.

Top-level members (exact JSON names; Go names in brackets are the ones the
rest of the code uses):

| JSON | Go field | Type |
|---|---|---|
| `Environment` | `Environment` | string, default `"development"` |
| `Log` | `LogConfig` | `LogConfig{Level, Output string}`, default level `"info"` |
| `Cores` | `CoresConfig` | `[]CoreConfig` |
| `Nodes` | `NodeConfig` | `[]NodeConfig` |
| `Forward` | `Forward` | `*ForwardConfig` |
| `AnxLine` | `AnxLine` | `*anxline.Config` |
| `AnxKeyRotation` | `AnxKeyRotation` | `*anxserver.RotationConfig` |

Top-level decoding uses `encoding/json/v2` (member names are matched
exactly, as today). Member decoding inside `CoreConfig`, `NodeConfig` and
`Options` uses `encoding/json` (v1 semantics: case-insensitive names,
unknown members ignored); configs in the field depend on that.

`New() *Conf` returns the defaults above.

`(*Conf).LoadFromPath(path string) error`: read the file, strip
comments, decode into the receiver, then run, in this order, stopping at
the first error: `normalizeAgentNodes`, `validateAgentIdentities`,
`validateNodeCredentials`, `Forward.Validate`, `AnxLine.Validate`,
`AnxKeyRotation.Validate`, `ValidateForProduction` (the `Validate` methods
accept a nil receiver). Errors name the file.

## `CoreConfig`

JSON members `Type` and `Name` (Go: `Type`, `Name`), plus
`WireGuardConfig *WireGuardConfig` and `AnixcoreConfig *AnixcoreConfig`
which are not JSON members themselves. When decoding:

- `Type` `anixcore`: `AnixcoreConfig = NewAnixcoreConfig()` and the same
  object is also decoded into it.
- `Type` `wireguard`: likewise with `NewWireGuardConfig()`.
- `Type` `xray`, `sing` or `hysteria2` (retired cores): `Type` becomes
  `anixcore` with `NewAnixcoreConfig()`; when the regular file
  `InstalledAnxNodePath` exists, `BinaryPath` is set to it and `AnxLine`
  to true. The check is a package variable `installedAnxNode func() bool`
  so tests can replace it.
- Any other type: left as is.

## `NodeConfig`

One entry of `Nodes` is a single flat JSON object. It is decoded twice:
into `ApiConfig` and into `Options` (both Go fields, not JSON members).
Defaults before decoding: `ApiConfig.APIHost = "http://127.0.0.1"`,
`ApiConfig.GRPCKeepalive = 30`, `Options.ListenIP = "0.0.0.0"`,
`Options.CertConfig = NewCertConfig()`. Nested `ApiConfig`/`Options`
objects and an `Include` member are not supported.

`ApiConfig` members (JSON = Go unless noted): `ApiHost` (Go `APIHost`),
`GRPCHost`, `GRPCUseTLS`, `GRPCServerName`, `GRPCKeepalive` (seconds),
`AgentControlAllowInsecure`, `AgentIdentity` (`AgentIdentityConfig`),
`AgentStream` (`AgentStreamConfig`), `MaintenanceEnvironment`,
`PluginSupervisorEnabled`, `PluginRoot`, `PluginSocketDir`,
`PluginOfficialPublicKey`, `AgentNode`, `NodeID` (int), `NodeType`.
Keep the explanatory comments short; `go doc` users rely on knowing that
`APIHost` names the node's tag and defaults the stream host, that
`AgentControlAllowInsecure` must be explicit for plaintext to a
non-loopback host, and that `AgentNode` is `proxy-<id>` / `forward-<id>`.

`Options` members: `Name`, `Core`, `CoreName`, `ListenIP`,
`DeviceOnlineMinTraffic` (int64, KB), `ReportMinTraffic` (int64),
`LimitConfig`, `CertConfig` (`*CertConfig`), and the Go-only field
`RawOptions json.RawMessage` which holds a copy of the whole object the
options were decoded from (the core selector decodes it again per core).
`Options` has its own `UnmarshalJSON`: decode, keep `RawOptions`, then
normalise `Core`: `anixcore` and `wireguard` stay; `xray`, `sing`,
`hysteria2` become `anixcore`; anything else becomes empty.

`LimitConfig`: `SpeedLimit` (int, Mbps, 0 none), `EnableDynamicSpeedLimit`
(bool), `DynamicSpeedLimitConfig` (`*DynamicSpeedLimitConfig` with
`Periodic` int seconds, `Traffic` int64 bytes, `SpeedLimit` int Mbps,
`ExpireTime` int minutes).

`CertConfig`: `CertMode` (`none`, `file`, `self`, `http`, `dns`),
`CertDomain`, `CertFile`, `KeyFile`, `Provider`, `Email`, `DNSEnv`
(map). `NewCertConfig()` returns mode `none`.

Members that are no longer modelled and must simply be ignored when
present: `SendIP`, `RuleListPath`, `RejectUnknownSni`, and in
`LimitConfig`: `EnableRealtime`, `DeviceLimit`, `ConnLimit`,
`EnableIpRecorder`, `IpRecorderConfig`.

## Watching the file

`(*Conf).Watch(path string, reload func()) error` watches the file with
`github.com/fsnotify/fsnotify` (already a dependency). Errors creating the
watcher or adding the path are returned. On a change other than a pure
permission change: wait 5 seconds (changes during the wait are folded into
the same reload), load the file into a new `Conf` with `New` +
`LoadFromPath`; if that fails, log the error and keep the running config;
else copy it into the receiver and call `reload`. Reloads never run
concurrently. Logging uses `github.com/sirupsen/logrus`.

## `example/config.json`

A minimal working Agent configuration as the installers write it: `Log`
info, empty `Cores`, one node with `ApiHost`
`https://control.example.com`, `GRPCHost` `control.example.com:50051`,
`GRPCUseTLS` true, plugin supervisor on (`PluginRoot`
`/var/lib/anixops-agent/plugins`, `PluginSocketDir`
`/run/anixops-agent/plugins`, `PluginOfficialPublicKey`
`IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M=`), `AgentNode` `proxy-33`,
`NodeID` 33, `AgentIdentity` (`Enroll` auto, `CertDir`
`/var/lib/anixops-agent/pki`, `EnrollCredentialFile`
`/var/lib/anixops-agent/enroll.credential`), `AgentStream.StateDir`
`/var/lib/anixops-agent/stream`, `DeviceOnlineMinTraffic` 200,
`CertConfig.CertMode` `self`. It must pass `LoadFromPath` and
`ValidateForProduction`'s expectations used by `conf/production_test.go`
(read that test).

## Tests to write

`conf/conf_test.go`: the example loads (node 33); `example/config.wireguard.json`
keeps `Core` `wireguard` and `NodeType` `wireguard`; `ApiConfig` defaults
are safe (no plugin supervisor, no insecure stream unless set);
`Watch` on a missing file errors; the comment stripper (comments, trailing
commas, strings containing `//`, `/*`, `\"` and `]` untouched); unknown
members are ignored. All existing tests of the package must pass:
`GOEXPERIMENT=jsonv2 GOWORK=off go test ./conf/ ./core/... ./node/ ./cmd/...`.
