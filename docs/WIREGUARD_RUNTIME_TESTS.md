# WireGuard Runtime Test Notes

## Covered By Unit Tests

- `core/wireguard`: validates Linux WireGuard config rendering, peer field validation, peer credential refresh, runtime-health defaults, transfer delta parsing, peer online-state parsing from recent `wg show <iface> dump` handshakes, per-peer Linux `tc` shaping/policing, and that a node still carrying the removed relay settings is refused.
- `node`: validates online-device merge and deduplication before reporting to the panel `/alive` path.
- `api/grpc`: fingerprints deterministic node-config responses so unchanged WireGuard settings do not trigger a full runtime reload; credential changes produce a new fingerprint.

## Removed: The Dual-Node Relay

The entry/exit relay (WireGuard into a domestic entry, carried to an overseas
exit over a gost `relay+quic` or `relay+wss` tunnel, with entry policy routing,
exit NAT and a network-policy failover) ran on gost and was removed with it,
together with its privileged namespace acceptance job. Cross-border paths run
on the network model (ANX-A); a WireGuard node with relay settings is refused.

## CI Check

GitHub Actions runs the full Go suite and the focused `WireGuard relay and peer
limit contract` job (`go test ./core/wireguard ./node -count=1`) before both
normal and `-rc.N` release artifacts are built. Only strict `vX.Y.Z` and
`vX.Y.Z-rc.N` tags publish GitHub releases. Local checkout builds and test runs
are intentionally not part of the release procedure.

## Remaining Evidence Gaps

- No privileged two-machine WireGuard peer speed-limit evidence yet.
- Runtime health is reported through REST `/api/v2/node/runtime-health` or the gRPC node-log channel.
