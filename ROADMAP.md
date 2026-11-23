# Roadmap

The roadmap for Control and Agent is kept in one place, the
[AnixOps Control roadmap](https://github.com/AnixOps/anix-control/blob/main/ROADMAP.md).
This file only lists Agent-side notes.

## WireGuard

- The `wireguard` core applies a Linux WireGuard interface through `ip` and
  `wg`, reads peer traffic from `wg show <iface> transfer` and online peers
  from recent handshakes in `wg show <iface> dump`.
- Per-peer and node-level speed limits converge through Linux `tc`,
  dynamic speed limits included.
- Validation is IPv4-only.
- The dual-node relay (entry/exit tunnel, policy routing, exit NAT) was
  removed; inter-node paths run on the network model.
