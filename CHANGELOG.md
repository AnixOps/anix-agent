# Changelog

## Unreleased

### Fixed

- **The alive list from the control stream is no longer lost or raced while
  a node starts.** The data plane applies `AliveList` (alive.v1) on its own
  goroutine, also while the node's configuration is being applied.
  `go test -race ./node` reported a data race in
  `TestEnrolledAgentUnderRequiredNeedsNoLegacyPath` (`startWith` wrote the
  controller's alive map without the reconcile lock), and the same window
  lost the list: a list that arrived after the limiter was added but before
  the node counted as started never reached the limiter, and a list that
  arrived before the start was overwritten by the one the start had read
  earlier, so device limits counted a stale list until Control's next one.
  - The user list, alive map and limiter are now set under the reconcile
    lock; the limiter takes a list from the stream as soon as it exists; a
    start keeps a list the stream delivered before it.
  - CI runs the whole `./node` package under the race detector, not only
    the maintenance tests (about 50 s on 4 CPUs; 12 runs in a row passed).

- **`anix-agent uninstall` matches the installed layout.** It knew only the
  root install (`scripts/install.sh`): on a node installed by Control's
  `/install.sh` (the O1 layout, which the O2/O3 work noted) it left
  `/usr/lib/anixops-agent` (the Agent, `gost`, the `anix-agent.prev`
  rollback copy), `anixops-agent-updater.path` and `.service` (the path unit
  stayed enabled and would start an updater whose binary was gone),
  `anixops-gost.service` and the polkit rule behind, and `--purge` kept
  `/var/lib/anixops-agent` (the identity) and `/var/lib/anixops-gost`.
  - It removes what either installer wrote, and only that: the four units
    (stopped in the installer's order: updater, Agent, gost), the
    `V2bX.service` link, the polkit rule, `/usr/lib/anixops-agent`,
    `/usr/local/anixops-agent`, the commands linked to them, and the manager
    script when it is this repository's. A link is removed only when it
    points where the installer pointed it; a file or link of the same name
    that is anything else is kept and listed (the old command removed
    `/usr/bin/anix-agent` and `/usr/local/bin/anix-agent` whatever they were).
  - Without `--purge` the configuration, identity and state stay, as with
    `install.sh uninstall`; `--purge` also removes `/etc/anixops/agent`
    (and `/etc/anixops` when empty), `/var/lib/anixops-agent`,
    `/var/lib/anixops-gost` and `/etc/sysctl.d/90-anixops-forward.conf`.
    The users, the forward drivers' nftables table and tc qdiscs, and the
    directories of earlier releases are not the installer's files: they are
    kept and listed (Control's `install.sh uninstall --purge` removes the
    users and the forwarding objects).
  - It refuses to run without root (it used to ignore every removal error),
    prints what it removed and what it kept, goes on past an error and exits
    non-zero when something could not be removed, and the prompt now reads
    `(y/N)`, which is its default.
    docs/INSTALL.md lists the paths per installer.

## 4.2.0-rc.1 - 2026-10-04

### Added

- **Control-pushed staged upgrades: `upgrade.v1` and `agent.upgrade`**
  (anix-control O4, PROTOCOL.md "Agent upgrades", forward-sdk.md section 9;
  owner decision H19: Control decides the batches, an Agent never upgrades
  on its own, artifacts are verified with the official Ed25519 key).
  - **Negotiation.** Proxy and forward nodes list `upgrade.v1`
    (`DataPlaneConfig.Upgrade`) only when `anixops-agent-updater.path` is
    active. The official release key is compiled in
    (`upgrade.OfficialPublicKey`, the key of anix-control's `install.sh`).
    One handler serves every node identity of the process, so a host that
    runs `proxy-<id>` and `forward-<id>` upgrades once.
  - **The Agent** (package `upgrade`, `Agent`):
    - It refuses the operation before acknowledging it when it does not
      parse (`upgrade_invalid_request`) or another upgrade is in progress
      (`upgrade_in_progress`, also while a hand-off waits for the updater).
      The same upgrade offered through the host's other node identity is
      admitted: it waits for the running one and answers `handed_off` once
      that hand-off is with the updater (one download, one request).
    - On the target already: `SUCCEEDED` `current`, which also answers
      Control's replay after the restart.
    - Otherwise: the artifact of its `GOARCH` (`upgrade_no_artifact`),
      `APPLYING` `downloading` into `/var/lib/anixops-agent/upgrade` (at
      most `size` bytes), `APPLYING` `verifying` (size, SHA-256, Ed25519
      signature: `upgrade_digest_mismatch`, `upgrade_signature_invalid`; the
      download is removed).
    - The hand-off: `request.json` is written to a temporary file,
      `SUCCEEDED` `handed_off` is sent, and only then is the request renamed
      into place (the updater restarts the Agent). If the terminal state is
      not a success (the deadline passed), the request is dropped.
    - A rollback needs `anix-agent.prev.json` naming the target
      (`upgrade_no_previous_release`); no updater:
      `upgrade_updater_unavailable`.
  - **The updater**: `anix-agent upgrade apply --request <file>`, the
    `ExecStart` of the root oneshot `anixops-agent-updater.service`
    (`upgrade.Applier`). It trusts nothing in the request:
    - It consumes the request and reads it and the staged release without
      following links.
    - It copies the release into `/usr/lib/anixops-agent` and verifies it
      again with its own key.
    - It refuses a downgrade other than a rollback to the kept release
      (`upgrade_downgrade_refused`).
    - It unpacks only the regular files `anix-agent` and `gost`, and checks
      that the new binary's `version` prints the target.
    - It keeps the installed binary as `anix-agent.prev` with
      `anix-agent.prev.json` (version, SHA-256), swaps by rename and
      restarts `anix-agent.service`.
    - When the new Agent does not stay active with one main process for 30
      s, it reinstates the kept binary and restarts again
      (`upgrade_start_failed`).
    - It writes `result.json`, which the next Agent logs once.
    - It never restarts `anixops-gost.service`. A release `gost` whose
      SHA-256 is the pinned one (`upgrade.PinnedGostSHA256`, kept equal to
      `release.yml` by a test) is installed for gost's next start.
  - **Client hooks** (`api/agent`): `Config.Admit` refuses an operation
    before its acknowledgement; `ReportProgress` sends `APPLYING` with
    `state_json`; `AfterTerminal` runs after the terminal state was recorded
    and sent, with the phase actually sent.
  - anix-control SDK `49a3d9bc` (`agentcontrol.CapabilityUpgrade`,
    `UpgradeRequest`).

- **`agent.diagnostic` and the forward diagnostic checks** (anix-control
  F3c, PROTOCOL.md "Diagnostic operation"; Control's route diagnosis,
  forward-sdk.md section 7.6).
  - A forward node, and a proxy node that forwards, list `agent.diagnostic`
    and `diag.v1` (`DataPlaneConfig.Diagnostics`). They run Control's
    diagnostic tasks on the stream (package `diagnostic`).
  - **Generic actions** for the service `gost` (unit
    `anixops-gost.service`): `service_status` and `log_tail` (at most 1000
    lines). `service_restart` is refused, because the forward component
    manages gost.
  - **Forward checks** (`forward.Component.Diagnose`):
    - `forward.listen`: the hop's nftables rules are running, or gost's
      socket is bound to the port.
    - `forward.port_conflict`: foreign listeners from `ss -p`, and other
      tables' dnat, redirect and tproxy rules on the port, nat table
      included, from `nft -j list ruleset`.
    - `forward.connect`: a TCP connect to each upstream, all at once.
    - `forward.udp_probe`: one datagram per upstream. No reply is
      `inconclusive`.
  - A check probes only the hop the component holds, never an address
    Control names. Every address a target resolves to passes
    `validate.CheckTargetAddress`, under the stricter of the hop's policy and
    Control's `target_policy`. A check changes nothing on the node.
  - As the sandboxed `anixops-agent` user, `ss -p` may not name other
    users' processes. A socket it cannot attribute on a gost hop is taken
    as gost's.

- O1 installer layout (anix-control #177; owner decisions H13, H20, H25).
  The Agent runs from the configuration Control's `/install.sh` writes, as
  the user `anixops-agent` in a systemd sandbox.
  - **Credential-only nodes.** A proxy node (`AgentNode` `proxy-<id>`)
    without `ApiKey` and with `"Cores": []` loads, passes `validate-config`
    and `ValidateForProduction`, enrolls with
    `AgentIdentity.EnrollCredentialFile` (or uses its enrolled identity) and
    runs Control's configuration and users from the stream's data plane. It
    never falls back to the legacy transports: while the stream is not up
    (enrollment pending, Control unreachable) the node waits for it in the
    background instead of failing the start, and the legacy gRPC client
    connects lazily. A node without `ApiKey` that speaks to Control must
    have the stream data plane, TLS, and an enrollment credential or an
    enrolled identity. Configurations with an `ApiKey` are unchanged.
    Production validation of a forward node no longer requires
    `GRPCServerName` (GRPCHost's host is the TLS name).
  - **Cores from the stream.** Without configured cores, every compiled-in
    core runs behind the selector (xray, sing, hysteria2, wireguard), and a
    node that names no core runs on the first core that serves its
    protocol. The selector now picks in configuration order (it picked at
    random among several matching cores).
  - **Paths.** Defaults move to `/var/lib/anixops-agent` (`pki`, `stream`,
    `forward`, `plugins`) and `/run/anixops-agent/plugins` (the unit's
    `RuntimeDirectory`); `PluginRoot`/`PluginSocketDir` default to them when
    both are left out. The earlier defaults (`/var/lib/anix-agent/pki`,
    `/var/lib/anix-agent/stream`, `/var/lib/anixops/plugins`) are copied
    once, at start, when the new directory does not exist; the old one is
    kept, and a failed copy leaves the Agent on it. Configured paths are
    used as they are. `anix-agent migrate-paths [--chown USER]` does the
    same for installers running as root.
  - **Commands.** `anix-agent forward sysctl-dropin` (alias of `forward
    sysctl`) prints `/etc/sysctl.d/90-anixops-forward.conf`; the start-time
    warning about disabled forwarding names it. `server -c <config>` is the
    unit's command (unchanged, now tested).
  - **Release.** Each linux package carries the pinned gost 3.2.6 as `gost`
    (archive and binary checked by SHA-256, anix-control's pin). The
    release publishes `SHA256SUMS` and `<asset>.sig` for both packages and
    `SHA256SUMS` (base64 raw Ed25519 by the official AnixOps release key,
    the format of `agent-install.sh.sig`), signed with the secrets
    `ANIXOPS_PLUGIN_SIGNING_PRIVATE_KEY` and
    `ANIXOPS_PLUGIN_OFFICIAL_PUBLIC_KEY`, which this repository needs before
    the next tag (docs/INSTALL.md). `scripts/check_release_assets.py`
    checks the packages in every build and the workflow in the release
    prerequisite tests.
  - **scripts/install.sh** stays the root install and upgrade path: it
    refuses a node Control's installer set up, installs the bundled gost,
    runs `migrate-paths`, uses the new plugin defaults and gives the root
    unit `RuntimeDirectory=anixops-agent`.

- Agent control stream, maintenance outbox, alive list, plugin artifacts by
  client certificate and error codes (AG-5b; anix-control #172 and #174, SDK
  go_dev aa1c36f1). An enrolled Agent whose Control serves `config.v1`,
  `users.v1`, `reports.v1`, `alive.v1` and, with the plugin supervisor,
  `maintenance.v1` and `artifacts.v1` makes no request to a legacy channel
  under `agent_control.mtls: required`.
  - **`maintenance.v1`.** The supervisor's durable maintenance outbox
    drains as `MaintenanceEvents` (at most 50 events and 256 KiB per batch,
    oldest first, one batch in flight). Per event: `persisted` removes it, a
    refusal (an `error`, or any code but `maintenance_unavailable`, also an
    unknown one) drops it and logs its `error_code`, otherwise it stays and
    goes again not before `retry_after_ms` (30 s without one);
    `maintenance_batch_too_large` halves the batch. The maintenance-only
    WebSocket is not opened while the stream carries the outbox, and one
    started before stops.
  - **`alive.v1`.** `AliveList` pages are buffered per session and revision
    and, on `last_page`, replace every controller's alive map (users not
    listed: 0) in place of UniProxy `alivelist`; a node starting on the
    stream takes the latest list. A list cut by a reconnect is dropped.
  - **`artifacts.v1`.** Listed in `Hello` only on a session that presents
    the client certificate. `plugin.install` downloads the manifest and the
    artifact from `AgentArtifacts` by the content address of the install
    configuration, writes chunks in offset order up to the artifact's size,
    keeps every check of the HTTP download (sizes, SHA-256 of both documents,
    the ed25519 manifest signature, the artifact digest in the manifest) and
    cross-checks the `PluginRelease` (digests, sizes, signature, algorithm,
    publisher, key id, plugin API version). `plugin_release_download_busy`
    and `Unavailable` are retried with backoff; `agent_cert_*` discards the
    certificate and enrolls again; the API key is never sent then. Without
    `artifacts.v1` on the session (an Agent not enrolled yet, or a Control
    4.1.x before AgentArtifacts: the v4.2 upgrade runs the new Agent first)
    the HTTP download with `X-API-Key` is used, as before; a refusal there
    with `agent_mtls_required` is named in the install error.
  - **Enrollment credential.** While the Agent waits for a one-time
    credential it looks for the file every 5 s (was 1 minute), so a
    credential written after a refusal is used promptly.
  - **Codes.** `ConfigStatus.error_code` on every refusal
    (`config_format_unsupported`, `config_hash_mismatch`, `config_invalid`
    for a document the node cannot read, `config_apply_failed`).
    `reports.v1` is listed with `transient_ack: "v1"`; a batch answered
    `report_unavailable` stays in the spool and goes again not before
    `retry_after_ms`, and a `ReportAck` with only an unknown code is a
    refusal. Certificate refusals are decided on their code (status message
    prefix, then the `x-anix-error-code` trailer; the old messages for older
    Controls): `agent_cert_revoked`, `expired`, `invalid` and
    `wrong_cluster` discard the certificate and enroll again;
    `agent_cert_wrong_node` keeps it, logs a configuration error at most
    every 10 minutes and reconnects no faster than every 5 minutes;
    `agent_enrollment_rejected` stops using that bootstrap.
  - **Status.** A runtime health change sends a `NodeStatus` at once, with
    the current system usage (the last sample if reading it fails).
  - **Metrics.** New heartbeat metrics
    `agent_dataplane_maintenance_{pending,persisted_total,refused_total,deferred_total}`,
    `agent_dataplane_alive_{revision,users}`,
    `agent_dataplane_artifact_{downloads,failures}_total`,
    `agent_dataplane_reports_deferred_total` and
    `agent_identity_wrong_node_refusals_total`.
  - `agent.diagnostic` is not advertised: the Agent has no diagnostic task
    executor yet.
  - `agenttest` serves the offer rule as an intersection, maintenance
    batches and acknowledgements, paged alive lists, `AgentArtifacts`, error
    codes and transient report acknowledgements, and sends operations.

- Agent control stream, reports and package reports on the stream, with
  the spool (AG-5). The Agent advertises `reports.v1` and
  `package-reports.v1`; when Control serves them (A2-5, systemd panel 1/7)
  traffic, online IPs, logs and status go on the stream instead of UniProxy
  `push` / `alive`, v2board `ReportTraffic` / `ReportOnline` /
  `NodeLogService` / `ReportStatus` and the node `runtime-health` route.
  - **Batches.** A traffic window (per-user bytes and the node's online IPs,
    merged across the node's controllers since Control replaces the whole
    alive set) and the node's logs (one `LogBatch` per node at most every
    30 s) carry a batch id `node:proxy-<id>:<boot id>:<sequence>`. A window
    with no traffic and nobody online is not sent, except once to clear the
    online set. Large windows are split at 5000 users per batch, each with
    the full online set.
  - **Spool.** Each batch is written durably to
    `AgentStream.StateDir/proxy-<NodeID>/spool/{traffic,logs}/` (one file per
    batch, written through a synced temporary file and a rename; directories
    0700, files 0600) before it counts as reported, then sent in order with
    at most 16 awaiting their `ReportAck`. Every `ReportAck` drops the batch
    (applied, recorded before, or refused for good, which is logged and
    counted); a batch without one is resent after 30 s on the stream, never
    over a legacy transport, so a byte is counted once. Bounds:
    `SpoolMaxMB` (traffic, default 64), `LogSpoolMaxMB` (default 16; logs
    never push traffic out), `SpoolMaxAgeHours` (default 72, at most 144,
    below Control's 7-day batch memory); the oldest batches are dropped first
    and every drop is counted. Spooled batches survive restarts.
  - **Outages.** While the stream is down for less than 5 minutes new
    windows and logs go to the spool; after that, new data goes to the
    legacy transports as before (spooled batches stay for the stream).
  - **Status.** `NodeStatus` (CPU, memory and disk usage, the Agent's
    uptime, and the runtime health of every core of the node) is sent at
    each session start and every minute; the legacy status and
    runtime-health reports stop while the stream carries `reports.v1`.
  - **Package reports, systemd panel 4/7.** The Supervisor hands every
    plugin process `ANIXOPS_NODE_ID` (an inherited value is never passed
    on), so `machine-telemetry` collects the systemd services table of its
    node when enabled. While `package-reports.v1` is negotiated the Agent
    polls `Telemetry/SystemdServices` of each enabled, healthy plugin running
    its assigned release whose verified manifest declares
    `telemetry.systemd.read`, and sends `PackageReport{plugin_id,
    kind: systemd.services, version, payload_json, observed_at_unix_ms}`
    every 5 minutes and at each session start, latest value only (never
    spooled or resent; an unchanged observation is sent once per session).
    `version` is the release the node is assigned (the plugin operation's
    target version), not the plugin's own version constant. Nothing is sent
    when collection is off (`FailedPrecondition`), nothing was collected yet
    or the plugin predates the collector.
  - With configuration, users and reports on the stream, an Agent whose
    Control requires mTLS (4.2, `agent_control.mtls: required`) makes no
    request to the legacy REST, gRPC or WebSocket channels, except the
    plugin maintenance outbox (no stream payload yet) and plugin artifact
    downloads.
  - The spool is kept when the state of another Control (a different gRPC
    target) is discarded: batch ids are per node and Control dedupes them,
    so a batch made for the old target is delivered to the new one.
    `ANIXOPS_NODE_ID` is given to every plugin process (only
    `machine-telemetry` reads it today).
  - `TransportStatus.data_plane.reports` reports the spool (batches, bytes,
    drops), acknowledgements and refusals.
  - `agent-control-fixture` gains `-reports`, `-traffic` and
    `-package-report-file`.

- Agent control stream, users from the stream (AG-4). The Agent advertises
  `users.v1` and, when Control serves it (A2-4), takes the node's users from
  Control's `UserDelta` instead of UniProxy `user`, v2board `GetUsers` and
  the WebSocket `user_update` / `user_ban`.
  - **Deltas and resyncs.** The pages of a delta are applied together when
    its `last_page` arrives; a session that ends before it leaves the set
    and the cursor as they were. A `full` delta replaces the set; other
    deltas apply each changed user's current state (`upserts`) and
    removals in order. Deltas that arrive together are applied as one set.
  - **No restart.** The node adds and removes only the users that changed
    (`DelUsers` / `AddUsers` and the limiter), as for a legacy user change;
    the core is not restarted. A set the node cannot apply is retried every
    30 s with the newest set.
  - **Cursor.** The set and its cursor are stored in
    `AgentStream.StateDir/proxy-<NodeID>/users.pb` (0600; written at most
    every 2 s and on shutdown) and the cursor is sent as
    `Hello.users_cursor`, so a reconnect or a restart resumes from it.
    Control resynchronizes (a `full` set in pages) when the Agent has no
    cursor, when its change log no longer covers the cursor, or when the
    cursor is ahead of it (another database). A user set of another Control
    is discarded.
  - **Startup.** With a stored configuration and user set the node starts
    from them at once. Otherwise, when the session negotiates `users.v1`,
    the node waits up to 60 s for the whole set and starts with it (no
    legacy user or alive-list pull).
  - **Legacy fallback.** The periodic pull, `users.reload` and the
    WebSocket take users from the legacy transport only while the stream
    does not carry them (as for the configuration, with the same 5-minute
    grace). While the stream carries both the configuration and the users,
    the legacy WebSocket is not started, and one already running is
    stopped; a plugin maintenance outbox keeps its maintenance-only
    WebSocket (Control has no stream payload for it).
  - The UniProxy alive list (`alivelist`, other nodes' online IPs per user)
    has no stream counterpart: while the stream carries users, device limits
    count this node's own connections only.
  - `TransportStatus.data_plane` reports the users cursor, the set size and
    the last apply error; the heartbeat reports `agent_dataplane_users` and
    `agent_dataplane_users_apply_failures_total`.

- Agent control stream, configuration from the stream (AG-3). With
  `AgentControlEnabled`, the Agent advertises `config.v1` and, when Control
  serves it (A2-3), runs the node's configuration from Control's
  `ConfigSnapshot` instead of UniProxy `config`, v2board `GetConfig`, the
  WebSocket `config_update` and the `node.reload` re-pull.
  - **What runs.** A snapshot is applied only when its format is
    `anixops.nodeconfig/v1` and `config_hash` is the SHA-256 of its exact
    bytes. Each controller of the node runs its entry of `legacy_pull`
    (`types[<NodeType>]`, or `default` without a `NodeType`), parsed by the
    same code as the UniProxy answer, so a snapshot runs exactly what the
    legacy pull would. A new revision goes through the existing restart
    path of each core (xray, sing-box, hysteria2); the same revision and
    hash is answered without a restart. Snapshots that arrive while one
    applies are skipped for the newest.
  - **`ConfigStatus`.** Every snapshot is answered: applied, or not with the
    error (an unknown format, a hash mismatch, a node type the node does not
    serve, a core that refuses the inbound). A status that cannot be sent
    when it is ready goes out after the next `HelloAck`.
  - **Hello reconcile and restarts.** The applied snapshot is stored in
    `AgentStream.StateDir/proxy-<NodeID>/config.pb` (default
    `/var/lib/anix-agent/stream`; directories 0700, files 0600, owned by the
    Agent's user; a file with wider permissions, another owner or a hash
    that does not verify is discarded). A restarted Agent runs it at once,
    without waiting for Control, and reports its revision in
    `Hello.config_revision`, so Control sends a snapshot only when the
    desired configuration moved. A stored snapshot the node can no longer
    run is discarded and Hello reports 0. State of another Control (a
    different gRPC target) is discarded.
  - **Startup without a stored snapshot.** The Agent waits up to 20 s for
    the stream. When the session negotiates `config.v1` it waits up to 60 s
    for the snapshot and fails the start without one (systemd restarts it);
    it does not fall back to the legacy pull. When the stream is down or
    Control does not serve `config.v1`, the node starts on the legacy pull
    as before.
  - **Legacy fallback.** The periodic pull, `node.reload`, `users.reload`
    and the WebSocket's `config_update` take the configuration from the
    legacy transport only while the stream does not carry it: never while a
    session negotiated `config.v1`, nor for 5 minutes after such a session
    ended (or after a restart whose last session negotiated it). After
    that, the next legacy pull is taken in full.
  - **Rollback.** `AgentStream.DataPlane: "off"` keeps every node on the
    legacy transports (the stream carries operations only).
  - Users, traffic, online IPs, logs and status stay on the legacy
    transports until AG-4 and AG-5.
  - `TransportStatus` gains `data_plane` (state directory, transport per
    capability, running revision and the last apply error); the heartbeat
    reports `agent_dataplane_config_revision` and
    `agent_dataplane_config_apply_failures_total`.
  - `agent-control-fixture` gains `-data-plane-dir` and `-config-record` for
    Control's cross-repository E2E (A2-7).
  - The UniProxy configuration parser no longer panics on a missing
    `base_config` or a malformed route `match`, and no longer echoes the
    configuration (which holds the node's secrets) in its error.

- Agent control stream, mTLS identity (AG-2). With `AgentControlEnabled`
  and TLS, the Agent enrolls with Control's `AgentEnrollment`, stores its
  identity, renews it, and presents its client certificate instead of the
  node API key.
  - **Enrollment** (`AgentIdentity.Enroll`, default `auto`). The bootstrap
    is a one-time `anixagt_` credential from
    `AgentIdentity.EnrollCredentialFile` (mode 0600, removed after use) when
    present, else the node API key, once. Control 4.2
    (`agent_control.mtls: required`) accepts only the credential. The key is
    generated on the node (ECDSA P-256); the issued certificate is checked
    against the key, the node (`proxy-<NodeID>`), the cluster when
    `AgentIdentity.Cluster` pins it, client-auth usage and the CA bundle.
  - **Storage.** `AgentIdentity.CertDir` (default `/var/lib/anix-agent/pki`)
    holds `proxy-<id>/identity.pem` (key and certificate, replaced in one
    rename), `ca.pem` and `identity.json`; directories 0700, files 0600,
    owned by the Agent's user. Files with wider permissions or another owner
    are refused, and the Agent enrolls again. The key is not "encrypted"
    with a derived key.
  - **Renewal** at Control's `renew_after` (two thirds of the 7-day
    lifetime) plus a small jitter, with a new key; failures retry with
    backoff while the current certificate stays in use.
  - **Refusals.** A certificate Control refuses (revoked, expired, not of
    this cluster), on the stream or at renewal, is discarded, and the Agent
    enrolls again. Against a Control without `AgentEnrollment` (v4.0:
    `Unimplemented`) or without its CA (`FailedPrecondition`), the Agent
    keeps the API key and retries every 30 minutes.
  - **No API key once enrolled.** The stream sends `x-node-id` and the
    certificate only. It falls back to the API key only when Control does
    not request a client certificate (`agent_control.mtls: off`, or no agent
    PKI). Enrollment is tried before the first connection and then in the
    background; a session opened with the API key reconnects with the
    certificate as soon as one is installed. A session that Control serves
    with the API key clears an earlier `agent_mtls_required` refusal, so an
    Agent re-enrolls with the key after Control is moved back from
    `required` to `preferred`.
  - `anix-agent identity [--json] [--pki-dir DIR]` shows each node's SPIFFE
    ID, serial, expiry and renewal time from the local files. The heartbeat
    reports `agent_identity_enrolled` and `agent_identity_expires_in_seconds`,
    and `-r/--re-register` also removes the stored identity.
  - The identity needs TLS: a plaintext stream keeps the API key, with a
    warning.

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

- The Control SDK requirement moves to go_dev `e6ced8bb79ee`
  (`v0.0.0-20261003210818-e6ced8bb79ee`). `agentcontrol` gains
  `CapabilityForward` (`forward.v1`), which this Agent neither implements
  nor advertises; `anix.agent.v1` is unchanged.
- `machine-telemetry` parses `systemd_services` with the SDK's
  `systemdreport.ParseConfig` (anix-control #163), the parser Control
  validates the configuration with, instead of a local copy.

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

### Fixed

- **A failed node reload no longer leaves the node without an inbound.**
  When the new configuration could not be added (seen: `bind: address
  already in use` a few seconds after the previous reload), the node stayed
  deleted and every later snapshot failed with `delete node ...: the node is
  not have` until the Agent restarted.
  - Adding a node retries a busy address (EADDRINUSE) three times within
    3.5 s. If the new configuration still fails, the previous one (tag,
    limiter, rules, inbound, users) is restored and the error is reported to
    Control.
  - The controller tracks whether the core runs the node: a reconciliation
    after a failed restore adds the node without deleting the absent one,
    and a delete answered `ErrNodeNotFound` (`core.ErrNodeNotFound`, now
    returned by the Selector and WireGuard) counts as done.
  - Xray drops an inbound handler whose start failed (and the inbound of a
    node whose outbound failed), so the tag is free for the next add.
  - The legacy WebSocket's full configuration push (`reloadNode`) takes the
    same path, under the reconciliation lock.
- **A configuration revision that leaves the proxy node's configuration
  unchanged no longer reloads its inbound.** A forwarding plan change
  (`forward.v1`) moves the node's revision; the Agent restarted the
  VLESS/VMess/... inbound on every one, dropping the users' connections. A
  snapshot, legacy pull or node.reload whose parsed configuration equals the
  running one (compared in full, Reality settings included) now only applies
  the users and the alive list.

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
