# Changelog

## Unreleased

### Added

- Agent control stream, A2 negotiation (AG-1). The client reads
  `HelloAck.server_capabilities`, logs them with the negotiated set at each
  connection, and exposes them (`Client.ServerCapabilities`,
  `Client.Negotiated`, `Client.TransportStatus`). `Negotiated` is false while
  the stream is down, when the legacy transports carry the data.
  - The Agent advertises only what it implements. It implements no
    data-plane capability yet (`config.v1`, `users.v1`, `reports.v1`,
    `package-reports.v1`, `diag.v1`), so configuration, users and reports
    stay on REST, gRPC and WebSocket until AG-3 to AG-5. `NewClient` refuses
    a Hello that lists one of them.
  - A data-plane payload Control sends without negotiation is dropped and
    counted; the stream stays up.
  - Control's deprecation signal for the node API key
    (`x-anix-auth-deprecated`, with its link and sunset; Control 4.1.0,
    `agent_control.mtls: preferred`) is logged once and reported in the
    heartbeat metric `agent_control_legacy_auth_deprecated`.
  - A refusal with `agent_mtls_required` (Control 4.2 default,
    `agent_control.mtls: required`) is reported as `ErrMTLSRequired` with an
    explanation, logged at most every 10 minutes, and counted in
    `agent_control_mtls_required_refusals_total`.

- `machine-telemetry` accepts the `systemd_services` configuration key that
  Control's `machine-telemetry` 4.1 package pushes (per-node `enabled`,
  `include`, `exclude`). Before, the plugin refused the key as unknown and
  failed to configure. Every other unknown key is still refused, and the
  configuration file limit rises from 64 KiB to 1 MiB to fit 4096 nodes.
- `machine-telemetry` collects the systemd services table for its node when
  that node is enabled: every 30 s it lists `.service` units over D-Bus and
  reads their cgroup v2 CPU and memory, keeps a 10-minute window, and serves
  the latest `systemd.services` report (unit name, ActiveState, SubState,
  average and peak CPU in percent of one CPU, current and peak memory) on the
  new `Telemetry/SystemdServices` RPC. Nodes without systemd or cgroup v2
  report `supported: false` with a reason. The node comes from the
  `ANIXOPS_NODE_ID` environment variable. The Supervisor does not poll the
  RPC or send the report yet. See `docs/PLUGIN_SUPERVISOR.md`.
- `github.com/godbus/dbus/v5` (BSD-2-Clause) is now a direct dependency,
  at the version already in the module graph.

### Changed

- The Control SDK requirement moves to go_dev `46718e54fe35`
  (`v0.0.0-20261003185058-46718e54fe35`). `anix.agent.v1` and
  `agentcontrol` are unchanged since `3f23349fceda`.

- The Control SDK requirement moves to go_dev `3f23349fceda`, which has
  `sdk/telemetry/systemdreport` (the report schema and sanitizer). The
  configuration parser is a local copy of the SDK's
  `systemdreport.ParseConfig` until anix-control #163 is merged.

- The Agent contract now comes from Control's SDK module,
  `github.com/AnixOps/anix-control/sdk` (`api/agent/v1`, `agentcontrol`,
  `plugincontrol`), at the commit that moved it there. The wire protocol is
  unchanged: the descriptors are identical to `sdk/v1.1.0` apart from
  `go_package`.
  - The nested `sdk/` module is deprecated and frozen at v1.1.0.
  - The Control SDK's requirements raise `google.golang.org/grpc` to v1.83.2
    and `google.golang.org/protobuf` to v1.36.11, with matching
    `golang.org/x` updates.

## 3.1.0-alpha.2 - 2026-07-18

### Added

- Started the formal 3.1--4.0 staged release line. This prerelease publishes
  only the `machine-telemetry` 1.1.0 official signed package contract shared
  by Control, Agent, and the signed Control WebUI.

### Changed

- Product release metadata now uses `3.1.0-alpha.2`. The Go module path stays
  `github.com/AnixOps/anix-agent/v4` as an ABI namespace; it is not a claim
  that AnixOps 4.0 has been released.

### Known Gaps

- `nftables-forward`, `gost-mesh`, `nat-egress`, WireGuard, and protocol
  runtime work are outside this package-release scope. They remain historical
  v4 preview work and must not be promoted to production traffic from this tag.

## 4.0.0-alpha.7 - 2026-07-18

### Changed

- Release metadata now pairs this Agent build with the Control security-gate
  fixes required before the next canary candidate. No Agent runtime behavior
  changed from `4.0.0-alpha.6`.

## 4.0.0-alpha.6 - 2026-07-18

### Added

- Added `nftables-forward` 1.2.0 live-kernel evidence. Every signed DNAT rule
  receives an nftables counter; semantic `nft -j` verification publishes a
  stable ruleset SHA-256 that excludes mutable counters and handles, plus
  per-rule packet/byte totals.
- Added an atomic private `StatePath + .observed.json` contract. It contains
  only fixed identity, health, timestamp, fingerprint, and counter fields;
  drift, cleanup, and process exit invalidate it to `unhealthy`.
- Added Supervisor collection of observation files from enabled official
  packages that explicitly declare `kernel.observed-state`. Every heartbeat
  checks the runtime Unix health socket before accepting a file; a non-serving
  runtime sends bounded `unhealthy` evidence rather than reusing a prior
  fingerprint. The Supervisor supplies the authoritative plugin version,
  config hash, and revisions.

### Fixed

- The heartbeat validator now retains a bounded unhealthy observation without
  a ruleset fingerprint, while refusing non-healthy observations with counters.

### Known Gaps

- This runtime remains opt-in and canary-only. Stable promotion still depends
  on Control-side staging restore/fallback evidence and the required 72-hour
  canary; it does not authorize production traffic takeover by itself.

## 4.0.0-alpha.5 - 2026-07-17

### Added

- Added `nftables-forward` 1.1.0 runtime-state and signed cleanup support. The
  plugin accepts the canonical Control package contract, starts safely with
  `apply=false` and an empty rule set, and rejects active plans without rules
  or with rollback disabled.
- Added a durable private ownership journal containing the exact pre-apply
  nftables table snapshot and managed identity. Journal publication is atomic
  and fsynced before applying rules, while successful rollback removes it only
  after the original state is restored.
- Added `--anixops-state`, `--anixops-cleanup`, and `--anixops-validate` entry
  modes for Supervisor-owned recovery and preflight validation.

### Fixed

- Restored interrupted nftables ownership before every new apply, including
  hard process death and Agent restart. Rollback now checks whether the current
  table exists before deleting it, so missing or externally removed state does
  not turn cleanup into an invalid nftables transaction.
- Extended privileged namespace acceptance with `SIGKILL`, persisted-journal,
  restart recovery, TCP/UDP traffic, created-table deletion, and exact
  pre-existing table restoration evidence.

### Known Gaps

- This runtime remains opt-in and canary-only. Control must keep topology
  execution disabled until signed package import, staging restore, fallback,
  rollout, live kernel-observed health, and 72-hour canary evidence are
  recorded. Stable 4.0 remains unauthorized.

## 4.0.0-alpha.4 - 2026-07-17

### Added

- Added the signed `machine-telemetry` 1.1.0 Agent package runtime with a
  versioned local Unix gRPC snapshot RPC and bounded gopsutil-backed metrics.
- Added Supervisor telemetry aggregation and heartbeat namespacing, including
  plugin health, sample age, partial-failure handling, and deterministic metric
  ordering.

### Fixed

- Added context-aware Supervisor lifecycle admission and retryable close/cleanup
  fencing so concurrent operations cannot race shutdown or lose ownership state.
- Propagated operation deadline and cancellation decisions through queueing,
  handler execution, and plugin locks; timeout observations now use one stable
  wire message for Control reconciliation.
- Added a release-tag gate that requires CLI, registration, Docker, README,
  install/migration guides, and Changelog versions to match before publishing.

### Known Gaps

- This is an opt-in alpha. It does not imply production forwarding cutover;
  topology apply, Secret-ID materialization, and sustained canary evidence
  remain required before stable 4.0 authorization.

## 4.0.0-alpha.3 - 2026-07-17

### Changed

- Isolated every enabled official-plugin Supervisor by the final registered
  node ID. Fresh installations now keep plugin artifacts, operation journals,
  runtime state, and Unix sockets below a node-specific `nodes/<node_id>`
  namespace, so two nodes in one Agent process cannot share plugin state.
- Bound each node-scoped Supervisor and Agent Control stream to the same
  Control endpoint, TLS identity, and API-key fingerprint. Configurations that
  reuse a numeric node ID across different Controls now fail closed instead of
  mixing credentials or routing operations to another node's Supervisor.
- Preserved an existing non-namespaced Supervisor layout for a true
  single-node upgrade when legacy plugin state or sockets are present. A fresh
  single-node installation uses the namespaced layout; multi-node startup
  rejects ambiguous legacy state and requires an explicit migration.

### Fixed

- Made controller startup and teardown track acquired limiter and core-node
  resources independently, preventing cleanup of resources that were never
  created after a partial failure and preserving deterministic retry behavior.
- Serialized Agent lifecycle and file-watcher reload transactions. A failed
  configuration load leaves the active configuration unchanged, while staged
  controller cleanup prevents leaked or double-removed resources during
  restart and reload failures.
- Bounded Supervisor shutdown per node and changed aggregate close failures
  from process panics to explicit error logs, so a stuck plugin cannot block a
  configuration reload indefinitely or crash the Agent teardown path.

### Known Gaps

- This remains an opt-in alpha Supervisor release. Declarative topology apply,
  Secret-ID materialization, composed GOST-to-NAT deployment, and sustained
  production canary evidence are not complete; production traffic cutover is
  not implied by this release.

## 4.0.0-alpha.2 - 2026-07-17

### Fixed

- Fixed the `nftables-forward` runtime and `--version` output to report the
  official signed package manifest version `1.0.0`.

## 4.0.0-alpha.1 - 2026-07-17

### Added

- Added authenticated, same-origin `plugin.install` delivery for official
  signed manifests and artifacts, with exact size/SHA-256/signature/key-ID
  checks, redirect rejection, 32 MiB bounds, immutable staging publication,
  and replay without a second download.

### Fixed

- Fixed update configuration ownership and same-revision interrupted-operation
  repair. Agent restart now defers automatic plugin restore while a mutating
  operation needs exact replay, joins terminal persistence failures with the
  operation error, and uses Linux parent-death signaling to avoid leaving the
  supervised plugin process running after an Agent crash.

## 3.1.0-alpha.1 - 2026-07-17

### Added

- Added the opt-in official plugin Supervisor with signed ZIP/tar/tar.gz Agent
  entrypoint extraction, immutable manifest/artifact verification, persisted
  lifecycle journal replay, Unix gRPC health checks, and the executable
  `machine-telemetry` reference package.
- Added `operation.cancel:v1` handling for running, queued, repeated, unknown,
  and session-teardown cases, plus unexpected plugin-process exit observation.
- Added the real `nat-egress` official plugin runtime with nftables IPv4/IPv6
  masquerade, fwmark policy routing, interface-bound marked health probes,
  strict conflict/configuration validation, and a crash-safe ownership journal.
- Added privileged `nat-egress` namespace acceptance proving marked forwarded
  traffic follows the plugin policy table and is masqueraded, wrong-mark
  traffic remains isolated, counters increment, normal exit removes the
  ownership journal, and rollback removes or restores owned host state.
- Added Supervisor `plugin.runtime-state` and `plugin.cleanup` capability
  enforcement with stable state paths, signed cleanup after crashes and
  lifecycle transitions, persisted `cleanup_pending`/cleanup-version recovery,
  and per-plugin serialization. A failed update-target cleanup leaves the old
  version disabled; automatic rollback starts it only after cleanup succeeds.
- Added signed auxiliary runtime entrypoints such as
  `runtime-gost-<goos>-<goarch>`, materialized into the immutable plugin
  version directory and reverified byte-for-byte before every start.
- Added the independent `gost-mesh` official plugin runtime. One signed plugin
  process manages aggregate entry/exit tunnels, starts pinned GOST v3.2.6
  children, owns TUN/source-policy state through a crash-safe journal, exposes
  gRPC health, and performs bounded restart with fail-closed cleanup.
- Added mandatory QUIC/WSS mutual TLS, source-bound remote health probes, IPv4
  forwarding and reverse-path-filter preflight, and privileged namespace
  acceptance proving wrong-SNI and unauthorized-client rejection, TCP/UDP
  traffic, transport-family counters, rollback, and preservation of unrelated
  policy state.
- Added a side-effect-free `gost-mesh --anixops-validate` release gate, strict
  canonical config parsing, bounded CIDR arrays, and entry-only policy table and
  priority ownership.

- Added a tag-pinned release installation guide and legacy migration runbook for fresh installs, same-fork updates, upstream config mapping, WireGuard canaries, rollback, and operator evidence.
- Hardened the Linux release installer with ZIP SHA-256 verification, exact-tag management script retrieval, previous-binary backups, and automatic binary restoration when restart fails; it continues to install from GitHub Release assets without cloning or local builds.
- Added initial P0 WireGuard runtime support: REST/gRPC config parsing, runtime peer fields, Linux `ip`/`wg` interface application, peer validation, and `wg show <iface> transfer` traffic delta parsing.
- Added initial WireGuard peer online-state reporting by parsing recent `wg show <iface> dump` handshakes and merging them into the existing node `/alive` report path.
- Added a tested WireGuard GOST TUN relay runtime slice: entry nodes can start GOST TUN over `relay+quic`/`relay+wss` and install source-based policy routing for the WireGuard CIDR, while exit nodes can start the matching GOST TUN listener and apply iptables NAT for the WireGuard CIDR.
- Added per-peer and node-level Linux `tc` shaping with dynamic-limit convergence, traffic-cursor rollback after rejected panel reports, and IPv4-only relay validation.
- Added GOST process supervision with cleanup/restart backoff and panel-visible WireGuard runtime health reporting over REST and gRPC.
- Added a release-gated, privileged GitHub Actions acceptance path that drives a real client WireGuard interface through V2bX entry routing, GOST `relay+quic` and certificate-verified `relay+wss`, V2bX exit NAT, and an isolated HTTP target.
- Made the WireGuard exit role relay-only: it no longer creates a local WireGuard interface, receives peer credentials, or reports user-peer counters.
- Prevented unchanged gRPC node-config responses from repeatedly rebuilding the WireGuard runtime.
- Added secure WSS relay configuration: entry nodes require SNI/certificate verification, exit nodes require certificate/private-key paths, and the RC/tag namespace acceptance matrix verifies both QUIC and WSS routes.

### Fixed

- Made enabled plugin configuration restart and health-check the real process,
  restore the previous config/process on failure, and fail closed when recovery
  cannot be completed.
- Treated a process that exits after forced kill as successfully stopped instead
  of returning the already-expired graceful-shutdown context error.

### Known Gaps

- Control production release-signing wiring for `nat-egress` is present, but
  production activation still requires a signed release, topology prerequisites,
  staged canary evidence, and operator approval. `gost-mesh` now has real QUIC
  and WSS runtime evidence; TUIC is intentionally outside GOST Mesh v1 because
  pinned GOST v3.2.6 does not implement it. Control status execution is now
  version-bound; Secret-ID materialization, GOST-to-NAT composition, and
  sustained canary evidence are still pending.
- `v2.5.0-rc.6` passed the release-gated QUIC and WSS namespace acceptance jobs. Real geographically separated dual-node evidence and real-client import evidence are still not complete. Runtime health reporting and GOST process supervision do not replace those production observations.
