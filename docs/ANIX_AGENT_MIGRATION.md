# Migrating V2bX_AnixOps To AnixOps Agent

This guide covers the branding and filesystem migration from legacy
V2bX_AnixOps installations to AnixOps Agent. It does not change the panel API,
credential encryption format, or node identity.

## Path Mapping

| Legacy location | New location | Installer behavior |
|---|---|---|
| `/usr/local/V2bX/V2bX` | `/usr/local/anixops-agent/anix-agent` | Back up legacy binary, then install release binary |
| `/etc/V2bX` | `/etc/anixops/agent` | Copy only files missing from the new directory |
| `V2bX.service` | `anix-agent.service` | Record state, back up definition, stop old service, install new service |
| `/etc/init.d/V2bX` | `/etc/init.d/anix-agent` | Same behavior on OpenRC |
| `V2bX` | `anix-agent` | Install compatibility symlink |
| `v2bx-anixops` | `anix-agent` | Install compatibility symlink |

The installer never deletes `/etc/V2bX` or `/usr/local/V2bX`. Existing files in
`/etc/anixops/agent` take precedence and are not overwritten by legacy files.

## What Is Backed Up

- Existing new or legacy binary:
  `/usr/local/anixops-agent/backups/anix-agent.<timestamp>`
- Legacy service definition:
  `/etc/anixops/agent/migration/V2bX.service.<timestamp>.bak`
  or `V2bX.openrc.<timestamp>.bak`
- Existing command entries replaced by compatibility symlinks:
  `/etc/anixops/agent/migration/commands/`

Backups can contain configuration paths and operational metadata. Keep the
migration directory readable only by trusted administrators.

## Before Migration

Record the legacy service state and create an independent backup:

```bash
sudo systemctl status V2bX.service --no-pager || true
sudo install -d -m 0700 /root/anix-agent-migration
sudo tar -C /etc -czf /root/anix-agent-migration/V2bX-config.tgz V2bX
sudo cp -a /usr/local/V2bX/V2bX \
  /root/anix-agent-migration/V2bX.binary
sudo sha256sum /root/anix-agent-migration/* \
  | sudo tee /root/anix-agent-migration/SHA256SUMS
```

Do not upload these files to an Issue or public repository. Configuration and
credential files may contain API keys, certificates, or registration secrets.

## Run The Migration

Use an exact release tag:

```bash
export VERSION=v4.2.0-rc.1
curl -fsSL \
  "https://raw.githubusercontent.com/AnixOps/anix-agent/${VERSION}/scripts/install.sh" \
  -o /tmp/anix-agent-install.sh
sudo bash /tmp/anix-agent-install.sh "${VERSION}"
rm -f /tmp/anix-agent-install.sh
```

All release downloads and checksum checks complete before the installer stops
the legacy service. If a valid legacy configuration was copied, the installer
starts `anix-agent.service`. If the new service fails, it first restores the
backed-up binary and then attempts to restore the previously active legacy
service.

## Verify The New Agent

```bash
sudo systemctl status anix-agent.service --no-pager
sudo anix-agent status
sudo anix-agent log
sudo anix-agent version
```

Then verify at the panel:

1. The same node ID is connected.
2. Configuration and users synchronize successfully.
3. Traffic and online reports continue to increase.
4. Existing client traffic reaches the expected egress.
5. Certificate and custom rule paths remain readable.

Legacy configuration may contain absolute `/etc/V2bX/...` paths. The installer
does not rewrite JSON values automatically because path replacement can corrupt
custom certificate, rule, or credential references. Those references continue
to work because the old directory is preserved. Move them to
`/etc/anixops/agent` later during a controlled configuration change.

## Compatibility Window

After migration, these commands address the new Agent:

```bash
anix-agent status
v2bx-anixops status
V2bX status
systemctl status V2bX.service
```

New automation should use `anix-agent` and `anix-agent.service`. Compatibility
aliases are intended only for staged migration and may be removed in a future
major release after operators have updated their automation.

## Roll Back

The installer performs an automatic rollback when startup fails. For a manual
rollback after a later functional problem:

```bash
sudo anix-agent stop
sudo anix-agent uninstall
sudo systemctl enable --now V2bX.service
sudo systemctl status V2bX.service --no-pager
```

Default uninstall preserves `/etc/anixops/agent`, the node credentials in
`/usr/local/anixops-agent/data` (including the ones migrated from V2bX) and the
node's state in `/var/lib/anixops-agent`, and restores a backed-up legacy
service definition when available. It never deletes `/etc/V2bX` or
`/usr/local/V2bX`. Use the independently backed-up binary and configuration if
the legacy service had a nonstandard layout.

Do not use `anix-agent uninstall --purge` until the migration is accepted. The
`--purge` option removes the new configuration directory, including migration
metadata, the migrated credentials in `/usr/local/anixops-agent/data` and the
state in `/var/lib/anixops-agent`, but still does not remove the two legacy
directories.
