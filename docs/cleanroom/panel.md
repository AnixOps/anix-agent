# Specification: node configuration parsing (`api/panel`)

## Scope

Deleted before implementation, to be written new:

- `api/panel/node.go` except the protocol types that were always ours,
  which a preparatory commit moved to `api/panel/protocols.go`
  (`WireGuardNode`, `WireGuardRelay`, `WireGuardNetworkPolicy`,
  `WireGuardNetworkPath`, `WireGuardHealthCheck`, `IwanNode`, `SnellNode`,
  `AnxNode`): those stay and embed `CommonNode`.
- `api/panel/user.go`, `api/panel/node_test.go`.

Stays: the other files of the package (`egress.go`, `exit_policy.go`,
`log.go`, `qos.go`, `version.go`, `protocols.go` and their tests).

## Where the input comes from

Control's configuration snapshot carries, per node, a JSON "runtime
answer". `ParseNodeInfo(body []byte, nodeID int) (*NodeInfo, nodeCategory
string, error)` turns one answer into a `NodeInfo`. Control's side of the
contract is in `github.com/AnixOps/anix-control` (snake_case members only).
`nodeCategory` is the answer's `node_type`.

### Type and category

- `type` names the protocol, `node_type` the category; both
  case-insensitive (lower-cased). When one is empty it takes the other's
  value. `v2ray` in either means `vmess`.
- Both empty: error `node type not found in the node configuration (<n>
  bytes)`. The body holds secrets: no error may quote it.
- Supported protocols: `vless`, `vmess`, `shadowsocks`, `trojan`, `tuic`,
  `anytls`, `hysteria2`, `wireguard`, `iwan`, `anx`, `snell`. Others:
  error `unsupported node type: <type>`.

### `NodeInfo`

| Field | Meaning |
|---|---|
| `Id int` | the `nodeID` argument |
| `Type string` | the protocol |
| `Security int` | `None` (0), `Tls` (1) or `Reality` (2): vless/vmess take the answer's `tls` member; trojan, tuic, anytls and hysteria2 are `Tls`; the rest `None` |
| `PushInterval`, `PullInterval time.Duration` | `base_config.push_interval` / `pull_interval` in seconds, given as JSON number or numeric string; missing, null or unparsable is 0 |
| `Rules Rules` | block rules, below |
| `Common *CommonNode` | the common members, with `routes` and `base_config` cleared after use |
| one protocol pointer | `VLessVMess *VLessVMessNode` (vless and vmess), `Shadowsocks`, `Trojan`, `Tuic`, `AnyTls`, `Hysteria2`, `WireGuard`, `Iwan`, `Anx`, `Snell`; exactly the one of the protocol is set |

`CommonNode` (JSON): `host`, `server_port` (int), `server_name`, `routes`
(list of `{id int, match, action string}`), `base_config`
(`{push_interval, pull_interval}` of any JSON type). Every protocol type
embeds it so that its members decode from the same object.

Protocol members (JSON → Go):

- `VLessVMessNode`: `tls` → `Tls int`, `tls_settings` → `TlsSettings`
  (`server_name` ServerName, `dest` Dest, `server_port` ServerPort
  (string), `short_id` ShortId, `private_key` PrivateKey), `network`,
  `network_settings` (raw JSON) → `NetworkSettings json.RawMessage`,
  `flow` → `Flow`.
- `ShadowsocksNode`: `cipher` Cipher, `server_key` ServerKey.
- `TrojanNode`: `network` Network, `network_settings` NetworkSettings (raw).
- `TuicNode`: `congestion_control` CongestionControl.
- `AnyTlsNode`: `padding_scheme` PaddingScheme (`[]string`, omitempty).
- `Hysteria2Node`: `obfs` ObfsType, `obfs-password` ObfsPassword.

No other members are read (Control sends none that the Agent uses).

### Block rules

`Rules{Regexp []string; Protocol []string}`. Each route's `match` is a
comma-separated string or a JSON list of strings; any other type, or a
list holding a non-string, is an error naming the route id (`route <id>:
...`), whatever the action. Routes with action `block` contribute: an
entry `protocol:<name>` adds `<name>` to `Protocol`; any other entry adds
itself to `Regexp`, without a leading `regexp:`. Other actions are
ignored.

## Users and reports (`user.go`)

- `UserInfo`: `id` Id int, `uuid` Uuid, `speed_limit` SpeedLimit int
  (Mbps), `device_limit` DeviceLimit int, `wireguard_peer_ip`
  WireGuardPeerIP, `wireguard_public_key` WireGuardPublicKey,
  `wireguard_preshared_key` WireGuardPresharedKey, `extra` Extra
  `map[string]string`.
- `UserTraffic{UID int; Upload, Download int64}`.
- `OnlineUser{UID int; IP string}`.

## Renames the rest of the code must follow

The old vless/vmess type and field had other names; update every use in
the repository (`core/anixcore`, `node`, tests, `cmd/agent-control-fixture`)
to `VLessVMessNode` / `NodeInfo.VLessVMess`. Fields that no longer exist
(`TlsSettingsBack`, `NetworkSettingsBack`, `RealityConfig`, `RawDNS`) must
be removed from their users: anixcore reads `TlsSettings` and
`NetworkSettings` only, and sets no `max_time_difference_secs`.

## Tests to write

`api/panel/node_test.go`: a WireGuard exit answer without key material
(relay members read, `server_port` 0 kept); type/category fallback and
`v2ray`; security per protocol; block rules from string and list matches,
non-string match errors; intervals from number, string, missing; unknown
type error; no error message contains the body. Example file paths in
fixtures live under `/etc/anixops/agent/`. Then
`GOEXPERIMENT=jsonv2 GOWORK=off go test ./api/... ./core/... ./node/ ./cmd/...`.
