# Feature Status

## Product Feature Matrix

| Area | Feature | Status | Evidence | Notes |
|------|---------|--------|----------|-------|
| Core | VMess/VLESS/Trojan/Shadowsocks runtime | Implemented | Xray and Sing-box cores | Keep panel compatibility tests current. |
| Core | Hysteria2 runtime | Implemented | Hysteria2 core | Keep auth and traffic paths covered. |
| Platform | Official plugin Supervisor and `nftables-forward` 1.2.0 | Preview/Partial | Signed artifact verification, node-isolated lifecycle journals, authenticated v2 Secret material validation, private-file rotation/cleanup, metadata-only replay binding, runtime-state/cleanup capabilities, canonical config validation, durable nftables ownership snapshot, live semantic ruleset SHA-256 plus per-rule counters, TCP/UDP namespace traffic, exact rollback, and `SIGKILL` plus Agent-restart recovery | Keep `PluginSupervisorEnabled` opt-in; production requires matching Control topology admission, staged fallback, rollout records, and a sustained canary. |
| Core | WireGuard user access over dual-node relay | Partial/P0 | `core/wireguard`, REST/gRPC parsing, peer field sync, focused unit tests, Linux `tc` shaping, dynamic-limit sync, IPv4-only relay guard, and release-gated GitHub Actions checks | Domestic-entry WireGuard interface, peer traffic/online reporting, GOST TUN relay command planning, stateful entry/exit forwarding, optional exit NAT, per-peer/node shaping, and privileged QUIC/WSS network-namespace route acceptance jobs exist. `v2.5.0-rc.6` passed both acceptance jobs; real cross-region evidence remains required. |
| WireGuard | WireGuard subscription runtime contract | Partial/P0 | `api/panel.NodeInfo`, `api/panel.UserInfo`, gRPC `extra` mapping | Requires matching `v2board_AnixOps` panel runtime peer fields. |
| WireGuard | GOST relay+QUIC tunnel backend | Partial/P0 | GOST TUN relay entry/exit command planning, unit tests, and release-gated namespace route acceptance | Default mode is `relay+quic`; `v2.5.0-rc.6` passed the namespace route and real two-machine relay-path evidence is still required. |
| WireGuard | WSS compatibility tunnel mode | Partial | `tunnel_type=wss` and relay `wss_compat` select `relay+wss`; entry validates SNI/CA and exit validates certificate/key paths; RC/tag workflow exercises the verified route in a namespace | WSS is compatibility mode, not default; production certificate rotation and real cross-region compatibility evidence are still required. |

## Not Implemented Or Not Complete

| Feature | Status | Why It Is Not Complete |
|---------|--------|------------------------|
| P0 WireGuard dual-node relay | Partial/P0 | Entry WireGuard runtime, traffic delta parsing, online-state reporting, GOST TUN relay command planning, IPv4-only entry policy routing, exit NAT, tc speed limits, dynamic-limit convergence, HTTP exit-config parsing, and release-gated GitHub Actions QUIC/WSS namespace route acceptance jobs exist. `v2.5.0-rc.6` accepted both transports; privileged two-machine runtime evidence remains. |
| Release builds | Policy | Release builds must run in GitHub Actions; do not produce local release artifacts. |
