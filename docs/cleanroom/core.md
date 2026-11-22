# Specification: core registry, interface and selector (`core`)

## Scope

Deleted before implementation, to be written new: `core/core.go`,
`core/interface.go`, `core/selector.go`, `core/imports/imports.go`.

Stays: `core/core_test.go` (adapt it to the names below), `core/anixcore`,
`core/wireguard`, `core/imports/anixcore.go`, `core/imports/wireguard.go`.

## Registry

- `type Factory func(*conf.CoreConfig) (Core, error)`;
  `func Register(t string, f Factory)` (called from each core's `init`;
  update `core/anixcore` and `core/wireguard`). Keep the registry in a
  package variable `factories map[string]Factory` (the tests swap it).
- `package imports` (file `imports.go`): only the package clause and a
  doc comment; the build-tagged siblings import the cores.

## `NewForConfig(configs []conf.CoreConfig, nodes int) (Core, error)`

- No configured core and `nodes > 0`: build a `Selector` from
  `DefaultCoreConfigs()`; an empty default list is an error.
- No configured core and no nodes (a forward-only Agent): error.
- One configured core: build it directly with its factory (unknown
  `Type` is an error naming it).
- Several: a `Selector` over them.

`DefaultCoreConfigs() ([]conf.CoreConfig, error)`: every registered core,
ordered by the preference list `defaultCorePreference = {"anixcore",
"wireguard"}` then by name; `anixcore` is left out unless its binary is
found by the replaceable package variable
`anixcoreBinary func() (path string, anxLine bool, ok bool)`, which
answers the installed anx-node (`conf.InstalledAnxNodePath`, regular file,
`anxLine` true) or else the default anixcore binary found on `PATH`
(`anxLine` false). Each config is produced by decoding a JSON object
`{"Type": name}` (plus `BinaryPath` and `AnxLine` for anixcore) with
`encoding/json`, so the core's own defaults apply.

## The interface

```go
type Core interface {
	Start() error
	Close() error
	Type() string
	Protocols() []string
	AddNode(tag string, info *panel.NodeInfo, options *conf.Options) error
	DelNode(tag string) error
	AddUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) (added int, err error)
	DelUsers(tag string, info *panel.NodeInfo, users []panel.UserInfo) error
	UserTraffic(tag string, reset bool) ([]panel.UserTraffic, error)
}
```

Optional interfaces (same method signatures as the cores already
implement, except the renamed rollback): `OnlineDeviceProvider`
(`GetOnlineDevice`), `RuntimeHealthProvider` (`RuntimeHealth`),
`RateLimitUpdater` (`UpdateUserRateLimit(tag, uuid string, bytesPerSecond
int) error`), `TrafficRollbacker` (`RollbackUserTraffic(tag string, traffic
[]panel.UserTraffic) error`), `DestinationProvider`
(`GetDestinationTraffic`), `EgressApplier`, `QoSApplier`,
`ExitPolicyApplier`, `MainlandCounter`, `NetworkApplier`. Read the
implementations in `core/anixcore` and `core/wireguard` and the callers in
`node` for the exact signatures; rename the cores' methods and every
caller (`node`, tests) to the new names and argument order.

`var ErrNodeNotFound = errors.New("the node is not have")` is answered
for an unknown tag (the text is matched by existing logs and tests).

## Selector

Runs several cores as one `Core`:

- Built from configs in order; two configs with the same name (`Name`,
  else `Type`) count once (several retired core types all become
  anixcore). Unknown type: error.
- `Start` starts each in order (first error returned); `Close` closes all
  and joins the errors. `Type()` names the cores, e.g.
  `Selector[anixcore wireguard]`. `Protocols()` concatenates.
- `AddNode(tag, info, options)`: when `options.CoreName` is set, the core
  with that name; else when `options.Core` is set, the first core whose
  `Type()` equals it; when such a core is not configured, log a warning,
  clear both and continue as for a node that names none. A node naming no
  core runs on the first core, in configuration order, whose `Protocols()`
  contains `info.Type`; before each attempt `options` is re-decoded from
  `options.RawOptions` (`options.UnmarshalJSON(raw)`), then `options.Core`
  is set to that core's type and `RawOptions` cleared. A core that refuses
  (error) hands the node to the next such core (log a warning); when all
  refuse, return the joined errors; when none serves the protocol, an
  error naming it. The tag remembers its core.
- The per-node calls (`DelNode`, `AddUsers`, `DelUsers`, `UserTraffic`,
  `GetOnlineDevice`, `GetDestinationTraffic`, `UpdateUserRateLimit`,
  `RollbackUserTraffic`) go to the tag's core; unknown tag →
  `ErrNodeNotFound`; an optional interface the core lacks → zero result,
  nil error. `DelNode` forgets the tag on success. The tag map is safe for
  concurrent use.
- Device-wide calls go to the first core in configuration order that
  implements the interface: `ApplyEgress` (none: nil when
  `config.Empty()`, else `ErrEgressUnsupported`), `ApplyQoS` and
  `ApplyExitPolicy` (none: nil), `MainlandBlocked` (none: 0, nil),
  `NetworkKinds` / `ApplyNetwork` / `NetworkStatus` (the first whose
  `NetworkKinds()` is non-empty; none: nil kinds, `ErrNetworkUnsupported`).
  The two error variables are exported, messages:
  `no core of this Agent runs egress routes (they need the anixcore core)`
  and `no core of this Agent runs the network model (it needs the anixcore core)`.

## Tests

`core/core_test.go` must pass after renaming (`newSelector` may be the
unexported constructor), plus
`GOEXPERIMENT=jsonv2 GOWORK=off go test ./core/... ./node/ ./cmd/...` and
`go vet -tags anixcore ./...`.
