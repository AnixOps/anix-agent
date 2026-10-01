# AnixOps Agent Release Installation

This guide installs AnixOps Agent from GitHub Release assets. The installer
does not clone the repository or compile Go code on the node host.

Supported installer targets are Linux `amd64` and Linux `arm64`. Pin an exact
tag in production so the installer, archive, management script, and checksum
all come from the same release.

## Fresh Install

Run as root on Debian/Ubuntu, RHEL-compatible Linux, Alpine, or Arch:

```bash
export VERSION=v3.1.0-alpha.2
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
| `/etc/anixops/agent/credential.json*` | Auto-register credentials when used |
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
sudo anix-agent update v3.1.0-alpha.2
sudo anix-agent status
```

Accepted tag forms are `vX.Y.Z`, `vX.Y.Z-alpha[.N]`,
`vX.Y.Z-beta[.N]`, and `vX.Y.Z-rc[.N]`.

The installer preserves `/etc/anixops/agent`, backs up the current executable,
and restores it if the new service cannot start. To roll back, install the
previous verified tag and check service health.

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
- Use `anix-agent uninstall` to preserve configuration; add `--purge` only when
  the new configuration and migration backups should also be removed.
