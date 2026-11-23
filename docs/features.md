# Feature Status

## Product Feature Matrix

| Area | Feature | Status | Evidence | Notes |
|------|---------|--------|----------|-------|
| Core | VMess/VLESS/Trojan/Shadowsocks/Hysteria2/TUIC/AnyTLS/Snell/ANX runtime | Implemented | anixcore core (`core/anixcore`) driving the separate anx-node process over its management API | Xray, sing-box and Hysteria 2 cores were removed in 5.0.0-rc.22; no third-party engine or GPL module may be linked (CI `scripts/check_forbidden_deps.sh` + go-licenses). Snell needs an anx-node with the snell inbound, which no anx-node release has yet. |
| Platform | Official plugin Supervisor | Preview/Partial | Signed artifact verification, node-isolated lifecycle journals, authenticated v2 Secret material validation, private-file rotation/cleanup, metadata-only replay binding, runtime-state/cleanup capabilities, canonical config validation, durable nftables ownership snapshot, live semantic ruleset SHA-256 plus per-rule counters, TCP/UDP namespace traffic, exact rollback, and `SIGKILL` plus Agent-restart recovery | Keep `PluginSupervisorEnabled` opt-in; production requires matching Control topology admission, staged fallback, rollout records, and a sustained canary. |
| Core | WireGuard user access | Partial/P0 | `core/wireguard`, REST/gRPC parsing, peer field sync, focused unit tests, Linux `tc` shaping, dynamic-limit sync | Single-node WireGuard interface, peer traffic/online reporting and per-peer/node shaping. The dual-node gost relay was removed; a node with relay settings is refused. |
| WireGuard | WireGuard subscription runtime contract | Partial/P0 | `api/panel.NodeInfo`, `api/panel.UserInfo`, gRPC `extra` mapping | Requires the matching AnixOps Control peer fields. |
| WireGuard | GOST relay+QUIC tunnel backend | Removed | — | Removed with gost; inter-node paths run on the network model (ANX-A). |
| WireGuard | WSS compatibility tunnel mode | Removed | — | Removed with the dual-node relay. |

## Not Implemented Or Not Complete

| Feature | Status | Why It Is Not Complete |
|---------|--------|------------------------|
| P0 WireGuard dual-node relay | Removed | Removed with gost (entry/exit gost tunnel, policy routing, exit NAT); inter-node paths run on the network model. |
| Release builds | Policy | Release builds must run in GitHub Actions; do not produce local release artifacts. |
