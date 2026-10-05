# AnixOps Agent Release Installation

This guide installs AnixOps Agent from GitHub Release assets. The installer
does not clone the repository or compile Go code on the node host.

Supported installer targets are Linux `amd64` and Linux `arm64`. Pin an exact
tag in production so the installer, archive, management script, and checksum
all come from the same release.

## One-Command Install From Control (Recommended)

New nodes are installed with the command on the node's page in AnixOps
Control ("复制安装命令"), Control's `/install.sh` (anix-control
`internal/agentinstall/install.sh`, docs/guide/agent-onboarding.md there):

```bash
curl -fsSL https://<control>/install.sh | sudo bash -s -- \
  --control https://<control> --node proxy-12 --token anixagt_...
```

It installs this repository's release package for the node's architecture
(checked by SHA-256 and by its `.sig`, see "Release Signing"), and runs the
Agent as the unprivileged user `anixops-agent` (owner decision H13): ambient
`CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` only, `NoNewPrivileges`,
`ProtectSystem=strict` with `ReadWritePaths=/var/lib/anixops-agent
/var/lib/anixops-gost`; root is used by the installer only. The unit runs
`/usr/lib/anixops-agent/anix-agent server -c /etc/anixops/agent/config.json`.

The configuration it writes holds credentials only (no `ApiKey`, no `Cores`):

```json
{
  "Cores": [],
  "Nodes": [{
    "ApiHost": "https://<control>", "Transport": "grpc",
    "GRPCHost": "<grpc host:port>", "GRPCUseTLS": true,
    "AgentControlEnabled": true, "AgentControlAllowInsecure": false,
    "AgentNode": "proxy-12", "NodeID": 12,
    "AgentIdentity": {"Enroll": "auto", "CertDir": "/var/lib/anixops-agent/pki",
                      "EnrollCredentialFile": "/var/lib/anixops-agent/enroll.credential"},
    "AgentStream": {"StateDir": "/var/lib/anixops-agent/stream"}
  }]
}
```

- A **proxy node** (`proxy-<id>`) without `ApiKey` enrolls with the one-time
  credential (the file is removed after use), then authenticates with its
  client certificate only. Its configuration, users and reports go over the
  control stream's data plane; it never falls back to the legacy transports.
  Until the stream is up (enrollment may wait for the credential, or Control
  may be unreachable) the node waits instead of failing. With `"Cores": []`
  every compiled-in core runs behind the selector (xray, sing, hysteria2,
  wireguard, in that order of preference) and each node of the stream's
  configuration runs on the first core that serves its protocol.
- A **forward node** (`forward-<id>`) runs the forward component only.
- A node without `ApiKey` that speaks to Control (`AgentNode` set or
  `AgentControlEnabled`) must have the stream data plane (`AgentStream.DataPlane`
  `auto`), TLS, and an enrollment credential or an enrolled identity
  (`CertDir/proxy-<id>/identity.pem`); `validate-config` refuses it
  otherwise. Configurations with an `ApiKey` work as before.

### Forwarding and sysctl

nftables forwarding needs the kernel to forward. The Agent checks
`net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding` at start and logs a
warning when they are off; it never changes them itself. The drop-in:

```bash
anix-agent forward sysctl-dropin | sudo tee /etc/sysctl.d/90-anixops-forward.conf
sudo sysctl --system
```

`anix-agent forward gost-unit` prints `anixops-gost.service`.

## File System Layout

| Path | Purpose |
|---|---|
| `/etc/anixops/agent/config.json` | Configuration (read only for the Agent) |
| `/var/lib/anixops-agent/pki` | Agent identity (`AgentIdentity.CertDir` default) |
| `/var/lib/anixops-agent/stream` | Stream state and report spool (`AgentStream.StateDir` default) |
| `/var/lib/anixops-agent/forward` | Forwarding state (`Forward.StateDir` default) |
| `/var/lib/anixops-agent/plugins` | Official plugin data (`PluginRoot` default) |
| `/run/anixops-agent/plugins` | Plugin sockets (`PluginSocketDir` default; the unit's `RuntimeDirectory=anixops-agent`) |
| `/var/lib/anixops-gost` | gost configuration and link certificates |
| `/usr/lib/anixops-agent/gost` | The pinned gost of the release |
| `/var/lib/anixops-agent/upgrade` | Control-pushed upgrades: the staged release, `request.json`, the updater's `result.json` |
| `/usr/lib/anixops-agent/anix-agent.prev` | The binary kept for a rollback, with `anix-agent.prev.json` (version, SHA-256) |

`PluginRoot` and `PluginSocketDir` now default as above when both are left
out; a configured `PluginRoot` without `PluginSocketDir` keeps its sockets in
`PluginRoot/sockets` as before.

### Migration of earlier defaults

Earlier releases kept the identity in `/var/lib/anix-agent/pki`, the stream
state in `/var/lib/anix-agent/stream` and plugin data in
`/var/lib/anixops/plugins`. They move once:

- Only defaults move. A path the configuration names is used as it is.
- A directory is copied when the old one exists and the new one does not;
  an existing new directory is never touched.
- The copy is made next to the new directory and renamed into place (all or
  nothing), with file modes and symbolic links kept (a link into the old
  tree points into the copy); sockets, pipes and devices are skipped.
- The old directory is never removed: identity material always keeps a copy,
  and an earlier release still starts. Remove it by hand once the node runs.
- The Agent does this at start as its own user. If the copy fails (the old
  directory is not readable or the new place not writable, as in the
  sandbox), it logs a warning and keeps using the old directory for that
  run.
- An installer running as root copies for the sandboxed Agent:
  `anix-agent migrate-paths --chown anixops-agent` (the copies then belong
  to that user; `pki` refuses files owned by another user). `scripts/install.sh`
  runs `anix-agent migrate-paths` on every root install and upgrade.

## Control-Pushed Upgrades (upgrade.v1)

Control upgrades Agents in canary batches (5%, 25%, 100%, at least 30
minutes each) and rolls a batch back when more than 5% of it fails (owner
decision H19; anix-control `sdk/api/agent/v1/PROTOCOL.md`, "Agent
upgrades"). An Agent never upgrades on its own.

- **Who can.** The Agent lists `upgrade.v1` only when
  `anixops-agent-updater.path` is active (`systemctl is-active`, which the
  `anixops-agent` user may ask). Control's installer writes that path unit
  and the root oneshot `anixops-agent-updater.service`; an Agent installed
  before them is upgraded by re-running the installer.
- **The Agent** (`agent.upgrade`, package `upgrade`) refuses the operation
  before acknowledging it when it does not parse (`upgrade_invalid_request`)
  or another upgrade is in progress (`upgrade_in_progress`); the same
  upgrade offered through the host's other node identity joins the running
  one and answers `handed_off` with it. On the target
  release already it answers `SUCCEEDED` `current`, which is also the
  answer to Control's replay after the restart. Otherwise it picks the
  artifact of its architecture, reports `downloading`, fetches it into
  `/var/lib/anixops-agent/upgrade` (at most its size), reports `verifying`
  and checks the size, the SHA-256 and the Ed25519 signature with the
  official release key compiled in (never a key Control sends); a mismatch
  removes the download. It then writes `request.json` to a temporary file,
  reports `SUCCEEDED` `handed_off`, and only then renames the request into
  place, because the updater restarts it. A rollback needs
  `anix-agent.prev.json` to name the target (`upgrade_no_previous_release`).
- **The updater** runs `anix-agent upgrade apply --request
  /var/lib/anixops-agent/upgrade/request.json` as root. It consumes the
  request, copies the staged release into `/usr/lib/anixops-agent` and
  verifies it again with the key of the installed binary, refuses a target
  older than the installed release unless it is a rollback to the kept one
  (`upgrade_downgrade_refused`), checks that the new binary's `version`
  prints the target, keeps the installed binary as `anix-agent.prev`, swaps
  the new one in with a rename and restarts `anix-agent.service`. The new
  Agent must stay active with one main process for 30 seconds, or the kept
  binary is reinstated and the Agent restarted again. The outcome goes to
  `result.json`, which the next Agent logs once at start.
- **gost keeps running.** The updater never restarts
  `anixops-gost.service`. A `gost` in the release replaces
  `/usr/lib/anixops-agent/gost` only when its SHA-256 is the pinned one
  (`upgrade.PinnedGostSHA256`, the release workflow's pin), so gost starts it
  next time.

## Release Signing

Every release publishes, next to `anix-agent-linux-64.zip` and
`anix-agent-linux-arm64-v8a.zip` (each with its `.dgst`):

- the pinned gost v3 release (H20; 3.2.6, archive and binary checked by
  SHA-256, the pin anix-control's CI uses) as `gost` inside each zip;
- `SHA256SUMS` of both packages;
- `<asset>.sig` for each package and for `SHA256SUMS`: base64 of the raw
  Ed25519 signature by the official AnixOps release key over the file's
  exact bytes (the format of anix-control's `agent-install.sh.sig`).

Verify a package:

```bash
printf '%s' 'MCowBQYDK2VwAyEAjW26nr2tbthASoeq6RmIpx8Ah+uhPNIv9V1ewRVb1VE=' | base64 -d >official.der
base64 -d anix-agent-linux-64.zip.sig >anix-agent-linux-64.zip.sig.bin
openssl pkeyutl -verify -pubin -keyform DER -inkey official.der -rawin \
  -in anix-agent-linux-64.zip -sigfile anix-agent-linux-64.zip.sig.bin
```

The release job signs with the repository secrets anix-control uses for the
same key; they must be added to this repository (Settings, Secrets and
variables, Actions) before the first signed tag:

| Secret | Value |
|---|---|
| `ANIXOPS_PLUGIN_SIGNING_PRIVATE_KEY` | The official release key, PEM (`openssl pkeyutl -sign -inkey` reads it) |
| `ANIXOPS_PLUGIN_OFFICIAL_PUBLIC_KEY` | `jW26nr2tbthASoeq6RmIpx8Ah+uhPNIv9V1ewRVb1VE=` |

Without them, or with another public key, the release job fails before
publishing; pull requests and branch builds need no secret (they build and
check the packages but do not sign).

## Root Install With scripts/install.sh

`scripts/install.sh` keeps the earlier root layout for existing root installs
(including V2bX migrations) and their upgrades. It refuses a node that
Control's installer set up (`User=anixops-agent` in `anix-agent.service`):
upgrade such a node by running its install command from Control again.

## Fresh Install

Run as root on Debian/Ubuntu, RHEL-compatible Linux, Alpine, or Arch:

```bash
export VERSION=v4.2.0-rc.1
curl -fsSL \
  "https://raw.githubusercontent.com/AnixOps/anix-agent/${VERSION}/scripts/install.sh" \
  -o /tmp/anix-agent-install.sh
sudo bash /tmp/anix-agent-install.sh "${VERSION}"
rm -f /tmp/anix-agent-install.sh
```

The installer downloads `anix-agent-linux-64.zip` or
`anix-agent-linux-arm64-v8a.zip`, verifies SHA-256 from the matching `.dgst`,
and installs these paths:

| Path | Purpose |
|---|---|
| `/usr/local/anixops-agent/anix-agent` | GitHub Actions-built Agent binary |
| `/etc/anixops/agent/config.json` | Persistent node configuration |
| `/etc/anixops/agent/credential.json*` | Auto-register credentials when used (new templates: `/var/lib/anixops-agent/credential.json.enc`) |
| `/usr/lib/anixops-agent/gost` | The pinned gost the release ships |
| `/var/lib/anixops-agent` | Identity, stream state, forwarding state, plugin data |
| `/usr/local/anixops-agent/backups/` | Previous binaries retained during update |
| `/usr/local/anixops-agent/.release-version` | Installed release tag |
| `anix-agent.service` | systemd service (`anix-agent` on OpenRC) |
| `anix-agent` | CLI and service/configuration manager |

On a fresh install the release archive's `config.production.json` is installed
as `/etc/anixops/agent/config.json` with mode `0600`. It intentionally contains
placeholders and the service is not started. Fill those values or run the
interactive wizard, then validate before starting:

```bash
sudo anix-agent initconfig
sudo anix-agent config
sudo /usr/local/anixops-agent/anix-agent validate-config \
  -c /etc/anixops/agent/config.json
sudo anix-agent start
sudo anix-agent status
sudo anix-agent log
```

The wizard asks for the HTTPS panel URL, node ID, API key, core type, and the existing
data-plane transport. It then asks separately whether to enable the Agent
Control stream. When enabled, configure its gRPC target, TLS preference, SNI,
and keepalive settings. The installed binary validates the generated file before
the wizard reports success. Never paste API keys into public logs or support tickets.

## Update And Rollback

Install an exact stable or prerelease tag with the same command:

```bash
sudo anix-agent update v4.2.0-rc.1
sudo anix-agent status
```

Accepted tag forms are `vX.Y.Z`, `vX.Y.Z-alpha[.N]`,
`vX.Y.Z-beta[.N]`, and `vX.Y.Z-rc[.N]`.

The installer preserves `/etc/anixops/agent`, backs up the current executable,
and restores it if the new service cannot start. To roll back, install the
previous verified tag and check service health.

## Uninstall

`sudo anix-agent uninstall [--purge]` asks for confirmation and removes what
the installer wrote, for either installer, and nothing else. Every path is
removed only when it is the installer's: units, directories and the polkit
rule by name, links only when they point where the installer pointed them
(`/usr/local/bin/anix-agent` to `/usr/lib/anixops-agent/anix-agent`, or to
the manager script), the manager script `/usr/bin/anix-agent` only when it is
this repository's `scripts/anix-agent.sh`. Anything else of those names is
left and listed as kept.

This is the Agent binary's command. On a node Control's installer set up,
`anix-agent` is the binary (`/usr/local/bin/anix-agent`). On a root install
`anix-agent` is the manager script, which has its own `uninstall [--purge]`
(see "The manager script on a root install" below); run
`/usr/local/anixops-agent/anix-agent uninstall` for the command described in
the tables here.

| Removed by `uninstall` | Installer |
|---|---|
| `anixops-agent-updater.path`, `anixops-agent-updater.service`, `anix-agent.service`, `anixops-gost.service` (disabled and stopped in that order), and the `V2bX.service` link to `anix-agent.service` | both |
| `/etc/polkit-1/rules.d/50-anixops-agent.rules` | Control |
| `/usr/lib/anixops-agent` (the Agent, `gost`, `anix-agent.prev`, `anix-agent.prev.json`) and the `/usr/local/bin/anix-agent` link | Control (`gost` also: root) |
| `/usr/local/anixops-agent` (binary, backups; `data/` only with `--purge`), `/usr/bin/anix-agent` and the `V2bX` / `v2bx-anixops` links | root |

Without `--purge` the configuration and the node's identity and state stay,
with gost's directory and the sysctl drop-in, so that installing again finds
the node enrolled:

| Kept, removed by `--purge` |
|---|
| `/etc/anixops/agent` (and `/etc/anixops`, when empty) |
| `/var/lib/anixops-agent` (identity, stream state, forwarding state, plugins, staged upgrades) |
| `/var/lib/anixops-gost` |
| `/etc/sysctl.d/90-anixops-forward.conf` (forwarding stays on until the next boot) |

Not removed even with `--purge`, because the installer did not write them:
the users `anixops-agent` and `anixops-gost`, the kernel objects the forward
drivers create (the nftables table `inet anixops_fwd` and the tc root qdiscs
`af00:`), and the directories of earlier releases (`/var/lib/anix-agent`,
`/var/lib/anixops/plugins`). The command lists what it kept. AnixOps Control's
`install.sh uninstall --purge` also removes the users and the forwarding
objects (only when they carry the drivers' marks). The command does not
reach Control: revoke the node's credentials there.

### The manager script on a root install

On a root install `sudo anix-agent uninstall [--purge]` runs
`scripts/anix-agent.sh`. It asks no question (the menu entries 12 and 13 ask
first), accepts only `--purge` (any other argument is ignored with a warning
and the keep-everything behaviour applies), prints what it removed and what it
kept, goes on past a path it cannot remove and exits non-zero in that case.
Like the binary's command above, it keeps `data/` (the credentials, a migrated
V2bX one included) without `--purge`.

| Removed in both modes |
|---|
| `anix-agent.service` (stopped and disabled) and the `V2bX.service` link (a V2bX unit backed up by the installer is put back, not started) |
| `anixops-gost.service`, when the node was installed with `ANIXOPS_FORWARD=1` (stopped and disabled after the Agent, so the Agent cannot start it again) |
| `/usr/local/anixops-agent` (binary, `.release-version`, `backups/`; `data/` stays unless `--purge`) |
| `/usr/bin/anix-agent` (the manager script itself), `/usr/local/bin/anix-agent` and the `V2bX` / `v2bx-anixops` links that point to it |
| `/usr/lib/anixops-agent/gost` (the release's pinned gost), and that directory when it is empty |

| Kept, removed by `--purge` |
|---|
| `/usr/local/anixops-agent/data` (the node's credentials, `credential.json` and `credential.json.enc`, including the ones migrated from V2bX) |
| `/etc/anixops/agent` (and `/etc/anixops`, when empty) |
| `/var/lib/anixops-agent` (identity, stream state, forwarding state, plugins) |
| `/var/lib/anixops-gost` (gost's state directory) |
| `/etc/sysctl.d/90-anixops-forward.conf` (forwarding stays on until the next boot) |

Never removed: the user `anixops-gost`, the nftables table `inet anixops_fwd`
and the tc qdiscs the forward drivers create, and `/usr/local/V2bX` and
`/etc/V2bX`. The root installer writes no polkit rule (only Control's
installer does), so the manager script touches none.

## Legacy V2bX_AnixOps Upgrade

The installer automatically detects `/etc/V2bX`, `/usr/local/V2bX`, and
`V2bX.service`. It copies only files missing from the new configuration
directory, backs up the old binary and service definition, then switches to
`anix-agent.service`.

The old directories are not deleted. These compatibility entries remain:

| Legacy entry | Compatibility target |
|---|---|
| `V2bX` | `anix-agent` manager/CLI |
| `v2bx-anixops` | `anix-agent` manager/CLI |
| `V2bX.service` | `anix-agent.service` |
| Legacy `V2bX-*` release ZIP | Installer fallback when a migration-period tag has no new-named asset |

New releases publish only `anix-agent-*`. The new installer can consume an
older `V2bX-*` asset and its `V2bX` executable name as a verified fallback.
The v4 release line does not promise old asset filenames; its new archive only
keeps a `V2bX -> anix-agent` executable symlink for command compatibility. See
[ANIX_AGENT_MIGRATION.md](ANIX_AGENT_MIGRATION.md) before upgrading a
production node.

## Panel Pairing

Use the matching panel release. Create or rotate the node API key in the panel,
then set it in `/etc/anixops/agent/config.json`. Verify after startup:

1. Node configuration pull succeeds.
2. User synchronization succeeds.
3. Traffic and online reports arrive at the panel.
4. The data-plane transport and optional Agent Control TLS settings match the
   Control endpoint.
5. `validate-config` passes and the authenticated maintenance WebSocket remains
   connected through a forced reconnect and Agent restart.

## WireGuard Relay Nodes

WireGuard entry/exit nodes additionally require `iproute2`, `wireguard-tools`,
`iptables`, `tc`, `/dev/net/tun`, and a checksum-verified GOST v3 binary.

```bash
sudo apt-get update
sudo apt-get install -y iproute2 iptables wireguard-tools
sudo modprobe wireguard || true
test -c /dev/net/tun
```

Validate one canary entry/exit pair before moving production users. See
[WIREGUARD_RUNTIME_TESTS.md](WIREGUARD_RUNTIME_TESTS.md) and
[MIGRATION.md](MIGRATION.md).

## Operational Rules

- Build release artifacts in GitHub Actions, not on the node.
- Pin production deployments to a tag and retain checksum evidence.
- Back up `/etc/anixops/agent` before overwriting configuration.
- Upgrade one node at a time and observe panel reports before continuing.
- Use `anix-agent uninstall` to preserve configuration, identity and state;
  add `--purge` only when the configuration, the state and migration backups
  should also be removed (see "Uninstall").
