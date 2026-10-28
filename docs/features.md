# Feature Status

## Product Feature Matrix

| Area | Feature | Status | Evidence | Notes |
|------|---------|--------|----------|-------|
| Core | VMess/VLESS/Trojan/Shadowsocks runtime | Implemented | Xray and Sing-box cores | Keep panel compatibility tests current. |
| Core | Hysteria2 runtime | Implemented | Hysteria2 core | Keep auth and traffic paths covered. |
| Platform | Official plugin Supervisor and `nftables-forward` 1.2.0 | Preview/Partial | Signed artifact verification, node-isolated lifecycle journals, authenticated v2 Secret material validation, private-file rotation/cleanup, metadata-only replay binding, runtime-state/cleanup capabilities, canonical config validation, durable nftables ownership snapshot, live semantic ruleset SHA-256 plus per-rule counters, TCP/UDP namespace traffic, exact rollback, and `SIGKILL` plus Agent-restart recovery | Keep `PluginSupervisorEnabled` opt-in; production requires matching Control topology admission, staged fallback, rollout records, and a sustained canary. |
| Core | WireGuard user access | Partial/P0 | `core/wireguard`, REST/gRPC parsing, peer field sync, focused unit tests, Linux `tc` shaping, dynamic-limit sync | Single-node WireGuard interface, peer traffic/online reporting and per-peer/node shaping. The dual-node gost relay was removed; a node with relay settings is refused. |
| WireGuard | WireGuard subscription runtime contract | Partial/P0 | `api/panel.NodeInfo`, `api/panel.UserInfo`, gRPC `extra` mapping | Requires matching `v2board_AnixOps` panel runtime peer fields. |
| WireGuard | GOST relay+QUIC tunnel backend | Removed | — | Removed with gost; cross-border paths run on the network model (ANX-A). |
| WireGuard | WSS compatibility tunnel mode | Partial | `tunnel_type=wss` and relay `wss_compat` select `relay+wss`; entry validates SNI/CA and exit validates certificate/key paths; RC/tag workflow exercises the verified route in a namespace | WSS is compatibility mode, not default; production certificate rotation and real cross-region compatibility evidence are still required. |

## Not Implemented Or Not Complete

| Feature | Status | Why It Is Not Complete |
|---------|--------|------------------------|
| P0 WireGuard dual-node relay | Removed | Removed with gost (entry/exit gost tunnel, policy routing, exit NAT); cross-border paths run on the network model. |
| Release builds | Policy | Release builds must run in GitHub Actions; do not produce local release artifacts. |
