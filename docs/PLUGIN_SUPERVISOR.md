# Official Plugin Supervisor

The Supervisor is opt-in and does not replace the existing proxy cores or
forwarding paths. When disabled, the Agent advertises and behaves exactly as a
legacy Agent Control client.

## Configuration

Add the following fields to the node `ApiConfig` that owns the physical Agent:

```json
{
  "AgentControlEnabled": true,
  "PluginSupervisorEnabled": true,
  "MaintenanceEnvironment": "staging",
  "PluginRoot": "/var/lib/anixops/plugins",
  "PluginSocketDir": "/run/anixops/plugins",
  "PluginOfficialPublicKey": "BASE64_ED25519_PUBLIC_KEY"
}
```

`PluginRoot` and `PluginSocketDir` are base directories. On a fresh install,
each final registered node ID receives a separate Supervisor namespace:

```text
PluginRoot/nodes/<node_id>
PluginSocketDir/nodes/<node_id>
```

When `PluginSocketDir` is omitted, sockets use
`PluginRoot/nodes/<node_id>/sockets`. The namespace owns that node's installed
artifacts, operation journal, runtime state, and sockets. A repeated config
entry for the same node may reuse its Supervisor only when the root, socket
directory, trust root, and Control identity match exactly. The Control identity
includes the API and gRPC endpoints, TLS settings, server name, and an API-key
fingerprint; the raw API key is not stored in the identity. Reusing one numeric
node ID across different Controls fails closed.

An upgrade of a true single-node Agent preserves the old non-namespaced root
and socket directory when existing plugin state or sockets are detected. A
fresh single-node Agent uses the namespaced layout. Multi-node startup refuses
ambiguous legacy state instead of silently treating it as empty; operators must
migrate that state into the intended `nodes/<node_id>` directory before
enabling multiple Supervisors.

A plugin artifact must be an Agent-targeted manifest published by `AnixOps`,
signed with that key, and match its SHA-256 digest.
An omitted `architectures` list remains compatible with early manifests;
otherwise entries use `arch`, `os/arch`, or `os-arch` (with `any` for a
portable artifact) and must include the current Agent platform. Dependencies
and conflicts are plugin IDs; self references, duplicates, and overlap are
rejected. Entrypoints must be canonical relative paths.

## Runtime Contract

Each installed version is retained under the selected node namespace at
`<node-root>/<plugin>/<version>` (the legacy single-node layout keeps
`PluginRoot/<plugin>/<version>`).
`plugin.install` accepts the strict `anixops.io/plugin-install/v1alpha1`
descriptor from the Agent Control stream. Its manifest and artifact URLs must
be exact same-origin `/api/v3/agent/plugin-releases/<plugin>/<version>/...`
paths with matching `sha256` and `size` query values. The Agent authenticates
both raw-body GETs with its existing `X-API-Key`, refuses redirects and encoded
or traversal paths, enforces a 1 MiB manifest limit and 32 MiB artifact limit,
then verifies exact size, SHA-256, publisher, API version, trust-root key ID,
and Ed25519 signature before installation.

New versions are assembled under a private staging directory and published by
one atomic rename. Exact retries verify and reuse a complete immutable version;
stale pre-rename staging directories are removed. A restart converts an
in-flight journal record to `interrupted`, allowing only the exact same
operation/revision/config hash to repair it while still rejecting stale or
rebound operations. An interrupted configure, enable, disable, update, or
rollback blocks automatic process restore until that exact operation converges;
Linux plugin children also receive a parent-death signal so an Agent crash
cannot leave the old supervised process serving traffic.

Disabling stops the process but preserves its binary, configuration references,
state, and rollback version. The Supervisor writes `state.json` atomically and
journals operation ID, revision, and configuration hash before changing a
process. A package may be zip, tar, or tar.gz and uses a signed platform
entrypoint (`agent-<goos>-<goarch>`, `agent-any`, or `agent`). The original
package and materialized executable are both re-hashed before every start.

A packaged Agent entrypoint may declare signed auxiliary executables through
the same `entrypoints` map:

```json
{
  "runtime-gost-linux-amd64": "runtime/linux-amd64/gost",
  "runtime-helper-any": "runtime/portable/helper"
}
```

`runtime-<name>-<goos>-<goarch>` is preferred for the current platform. A
single explicit `runtime-<name>-any` or `runtime-<name>` fallback may be used
when no platform entry exists; declaring both fallback forms is rejected.
Runtime names are lowercase path-safe identifiers. Runtime declarations must
use canonical package paths distinct from every other declared entrypoint and
regular non-empty files, with at most 32 declarations, 128 MiB per file, and
256 MiB for the selected platform.
Declarations for other platforms remain in the signed package but are not
materialized on this Agent.

Selected files are installed as
`<node-root>/<plugin>/<version>/runtime/<name>` with mode `0750` (or the
equivalent legacy single-node path). Plugins locate them relative to their own
materialized executable. Before every process
start, the Supervisor re-verifies the package digest and compares every
selected runtime byte-for-byte with its signed package member. Missing,
non-regular, non-executable, oversized, or modified runtime files fail closed
before the plugin runner is invoked. Raw legacy artifacts cannot declare
auxiliary runtimes; they must use a packaged Agent entrypoint.

The signed executable receives:

```text
--anixops-socket /run/anixops/plugins/nodes/<node_id>/<plugin>.sock
--anixops-config /var/lib/anixops/plugins/nodes/<node_id>/<plugin>/<version>/config.json
```

A manifest that declares `plugin.runtime-state` also receives:

```text
--anixops-state /var/lib/anixops/plugins/nodes/<node_id>/<plugin>/runtime-state/ownership.json
```

The state path is stable across plugin-version and Agent-process changes. A
manifest may declare `plugin.cleanup` only together with
`plugin.runtime-state`; unsupported declared capabilities fail closed rather
than falling back to the stateless runner. Cleanup runs the verified executable
for the owning version with `--anixops-cleanup` plus the same socket, config,
and state paths.

It must expose the standard gRPC health service on the Unix socket. Business
traffic must not pass through the Supervisor. A protocol plugin owns its data
plane; nftables plugins program the kernel and then return control.

The first implementation supports install, inspect, configure, enable, disable,
update, rollback, health, and out-of-band `operation.cancel`. Update writes the
target version's supplied configuration before starting it and records the
matching `config_hash`; start, health, or state-persistence failure restores the
old target file and previous running version. Enabled configuration
changes restart and health-check the process; failed recovery disables it and
records an unhealthy state. Unexpected CommandRunner exits are observed and
also fail closed.

For cleanup-capable plugins, the Supervisor persists `cleanup_pending` and
`cleanup_version` whenever stop or signed cleanup cannot be confirmed. Startup
and later lifecycle operations recover that exact version before starting a
process. Disable, configure, update, rollback, failed start/health, unexpected
exit, and Supervisor close all use the same serialized per-plugin cleanup path.
During update, target-version cleanup failure blocks automatic restart of the
old version; the old version is started only after target cleanup succeeds.
This intentionally prefers no stale nftables or policy-routing ownership over
automatic availability.

The `nftables-forward` 1.2.0, `nat-egress`, and `gost-mesh` runtimes use this
contract for private crash-safe ownership journals. `nftables-forward` writes
the original table snapshot before applying rules, restores an interrupted
journal before a new start, and exposes signed cleanup and config-validation
modes. Its privileged namespace test includes process `SIGKILL` and same-state
Agent restart recovery. `gost-mesh` also consumes a signed pinned GOST
runtime from `runtime/gost`; QUIC and WSS require mutual TLS, and its privileged
namespace matrix proves TCP/UDP data flow, TLS rejection, policy routing, child
cleanup, and unrelated-state preservation. TUIC is not a GOST Mesh v1
capability. Signed artifact transport from Control now has an Agent-side
contract and implementation; Control endpoint integration, Secret-ID
materialization, topology apply, GOST-to-NAT composition, and sustained canary
evidence remain release gates, so this phase must not be described as production
forwarding cutover.

The signed `gost-mesh` executable also supports
`--anixops-validate --anixops-config <absolute-path>` for release-gate contract
checks. This mode only loads and validates the strict v1 JSON contract; it does
not require a socket or state path and does not start GOST or mutate networking.
Signed field values are never silently trimmed or lowercased; non-canonical
role, transport, endpoint, CIDR, and health values are rejected.
Only entry tunnels declare source-policy `routing.table` and `priority`; exit
tunnels must omit them or set both to zero.

## Maintenance reporting

Enabling the Supervisor starts node-scoped maintenance monitoring and a durable outbox. The first delivery uses the authenticated HTTP/WebSocket sync connection; HTTP/REST nodes reuse sync and gRPC nodes start a maintenance-only WebSocket bridge using the HTTP(S) ApiHost and existing registered node credentials alongside GRPCHost. WebSocket must remain enabled. Health failures and process exits follow the 3 failures / 2 minutes gate. Only machine-telemetry may restart automatically, at most twice per instance per rolling 30 minutes, persisted across Agent restarts. Credentials, permissions, signatures and invalid configuration always require manual handling. See [the maintenance runbook](MAINTENANCE_P0.md) for configuration, storage, acknowledgment, recovery and acceptance boundaries.
