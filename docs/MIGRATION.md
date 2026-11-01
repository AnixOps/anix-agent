# AnixOps Agent Runtime Migration And Rollback

For the automatic V2bX_AnixOps brand, service, and filesystem migration, read
[ANIX_AGENT_MIGRATION.md](ANIX_AGENT_MIGRATION.md) first. This document covers
configuration and runtime changes that still require operator validation.

## Supported Paths

| Source | Support level | Migration method |
|---|---|---|
| Legacy V2bX_AnixOps release | Automatic base migration | Run the release installer, then verify configuration and traffic |
| Upstream V2bX configuration | Operator-guided | Map fields and validate with a canary node |
| WireGuard node without relay runtime | Operator-guided | Add Linux/GOST prerequisites and test one entry/exit pair |
| Unrelated node agent | Not automatic | Build a field mapping and register a new node credential |

## Preparation

1. Record the installed version, service state, node ID, transport, core, and
   listening ports.
2. Back up configuration and auto-register credentials with restrictive file
   permissions.
3. Capture recent service logs and panel traffic/online counters.
4. Confirm that the target panel exposes the required node transport.
5. Prepare a maintenance window and a tested rollback command.

```bash
sudo systemctl status anix-agent.service --no-pager || \
  sudo systemctl status V2bX.service --no-pager
sudo install -d -m 0700 /root/anix-agent-runtime-backup
sudo tar -C /etc/anixops -czf \
  /root/anix-agent-runtime-backup/agent-config.tgz agent
```

Never publish the backup. It may contain API keys, certificate paths, and
encrypted registration credentials.

## Foreign Or Heavily Customized Configurations

Do not overwrite the current configuration with the wizard until field mapping
is complete. Compare a separate copy with `../example/config.json` and check:

- `ApiHost`, `GRPCHost`, `NodeID` (or `AgentNode`), `NodeType`, and
  `AgentIdentity` (the node enrolls; there is no `ApiKey`)
- Core type and core-specific settings
- Agent Control TLS settings (`GRPCUseTLS`, `GRPCServerName`)
- Certificates, DNS provider environment, and file ownership
- Traffic thresholds, device/online settings, and send/listen IPs
- Custom inbound/outbound, DNS, route, and geo data paths

Start only a canary node. Rotate the API key when configuration came from an
unknown or previously shared environment.

## WireGuard Entry/Exit Migration

WireGuard migration must prove the complete path:

```text
client WireGuard -> entry -> GOST relay+QUIC -> exit NAT -> target
```

WSS is a compatibility transport, not the default. Before cutover:

1. Install `iproute2`, `wireguard-tools`, `iptables`, and expose `/dev/net/tun`
   on both entry and exit nodes.
2. Install a checksum-verified GOST v3 binary at the configured `GostPath`.
3. Create a matching panel protocol and generate new node/WireGuard keys.
4. Start one canary entry/exit pair with a non-production peer CIDR.
5. Verify configuration pull, interface creation, peer handshake, client
   traffic, panel reports, exit NAT, and cleanup.
6. Test WSS certificate/SNI behavior only when that fallback is required.
7. Move users in batches and preserve the old route during observation.

If the canary fails, stop the new Agent, restore the previous service and
binary, and revert the panel assignment. Do not roll back a panel database for
a node runtime failure unless a panel migration was part of the same change.

## Evidence To Retain

- Exact panel and Agent tags, release checksums, and GitHub Actions run URLs
- Configuration backup checksum and storage location
- Pre/post counters and a canary user ID with secrets removed
- WireGuard entry/exit evidence when relevant
- Operator, maintenance window, and rollback decision record
