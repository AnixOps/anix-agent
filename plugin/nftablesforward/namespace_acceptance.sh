#!/usr/bin/env bash
# Run a privileged network-namespace acceptance test for the nftables-forward
# Agent plugin. The script is intentionally outside the normal unit-test path:
# it requires root, iproute2, nftables, conntrack/NAT kernel support, and Python.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AGENT_BINARY=""
GO_BIN="${GO_BIN:-go}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

fail() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: plugin/nftablesforward/namespace_acceptance.sh [--agent-binary PATH]

Builds or uses an nftables-forward Agent plugin binary, then proves in
temporary Linux network namespaces that:

1. IPv4 and IPv6 TCP DNAT forward client traffic to the target namespace.
2. IPv4 and IPv6 UDP DNAT forward client traffic to the target namespace.
3. SIGKILL leaves a durable journal and restart recovers it before re-apply.
4. rollback_on_exit deletes a plugin-created nftables table.
5. rollback_on_exit restores a pre-existing nftables table snapshot.

This script modifies only temporary network namespaces named with the current
process ID and deletes them on exit.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

counter_observation_ready() {
  "${PYTHON_BIN}" - "$1" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    observed = json.load(handle)
if observed.get("health") != "healthy":
    raise SystemExit(1)
counters = {entry.get("rule_id"): entry for entry in observed.get("rule_counters", [])}
for rule_id in ("tcp4-namespace", "udp4-namespace", "tcp6-namespace", "udp6-namespace"):
    counter = counters.get(rule_id)
    if not isinstance(counter, dict) or counter.get("packets", 0) <= 0 or counter.get("bytes", 0) <= 0:
        raise SystemExit(1)
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --agent-binary)
      [[ $# -ge 2 ]] || fail "--agent-binary requires a path"
      AGENT_BINARY="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

[[ "$(id -u)" == "0" ]] || fail "root is required to create network namespaces and nftables NAT rules"
for command in ip nft sysctl timeout "${PYTHON_BIN}"; do
  require_command "${command}"
done

WORK_DIR="$(mktemp -d)"
CLIENT_NS="anix-c-${$}"
ROUTER_NS="anix-r-${$}"
TARGET_NS="anix-t-${$}"
CLIENT_LINK="axc${$}"
ROUTER_CLIENT_LINK="axr0${$}"
ROUTER_TARGET_LINK="axr1${$}"
TARGET_LINK="axt${$}"
PLUGIN_PID=""
TCP_PID=""
UDP_PID=""
TCP6_PID=""
UDP6_PID=""

cleanup() {
  set +e
  if [[ -n "${PLUGIN_PID}" ]]; then
    kill "${PLUGIN_PID}" >/dev/null 2>&1
    wait "${PLUGIN_PID}" >/dev/null 2>&1
  fi
  if [[ -n "${TCP_PID}" ]]; then
    kill "${TCP_PID}" >/dev/null 2>&1
    wait "${TCP_PID}" >/dev/null 2>&1
  fi
  if [[ -n "${UDP_PID}" ]]; then
    kill "${UDP_PID}" >/dev/null 2>&1
    wait "${UDP_PID}" >/dev/null 2>&1
  fi
  if [[ -n "${TCP6_PID}" ]]; then
    kill "${TCP6_PID}" >/dev/null 2>&1
    wait "${TCP6_PID}" >/dev/null 2>&1
  fi
  if [[ -n "${UDP6_PID}" ]]; then
    kill "${UDP6_PID}" >/dev/null 2>&1
    wait "${UDP6_PID}" >/dev/null 2>&1
  fi
  ip netns del "${CLIENT_NS}" >/dev/null 2>&1
  ip netns del "${ROUTER_NS}" >/dev/null 2>&1
  ip netns del "${TARGET_NS}" >/dev/null 2>&1
  if [[ -n "${WORK_DIR}" && -d "${WORK_DIR}" ]]; then
    find "${WORK_DIR}" -type f -delete >/dev/null 2>&1
    rmdir "${WORK_DIR}" >/dev/null 2>&1
  fi
}
trap cleanup EXIT

if [[ -z "${AGENT_BINARY}" ]]; then
  AGENT_BINARY="${WORK_DIR}/nftables-forward-agent"
  GOEXPERIMENT="${GOEXPERIMENT:-jsonv2}" GOWORK=off "${GO_BIN}" -C "${ROOT_DIR}" build -o "${AGENT_BINARY}" ./cmd/nftables-forward
fi
[[ -x "${AGENT_BINARY}" ]] || fail "agent binary is not executable: ${AGENT_BINARY}"

TCP_SERVER="${WORK_DIR}/tcp_server.py"
UDP_SERVER="${WORK_DIR}/udp_server.py"
TCP6_SERVER="${WORK_DIR}/tcp6_server.py"
UDP6_SERVER="${WORK_DIR}/udp6_server.py"
CLIENT_CHECK="${WORK_DIR}/client_check.py"
cat >"${TCP_SERVER}" <<'PY'
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("10.32.1.2", 18081))
server.listen(1)
conn, _ = server.accept()
with conn:
    conn.sendall(b"tcp-ok")
PY
cat >"${UDP_SERVER}" <<'PY'
import socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("10.32.1.2", 18082))
data, addr = server.recvfrom(1024)
if data != b"udp-ping":
    raise SystemExit("unexpected UDP payload")
server.sendto(b"udp-ok", addr)
PY
cat >"${TCP6_SERVER}" <<'PY'
import socket
server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("fd32:1::2", 18081))
server.listen(1)
conn, _ = server.accept()
with conn:
    conn.sendall(b"tcp6-ok")
PY
cat >"${UDP6_SERVER}" <<'PY'
import socket
server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
server.bind(("fd32:1::2", 18082))
data, addr = server.recvfrom(1024)
if data != b"udp6-ping":
    raise SystemExit("unexpected IPv6 UDP payload")
server.sendto(b"udp6-ok", addr)
PY
cat >"${CLIENT_CHECK}" <<'PY'
import socket

tcp = socket.create_connection(("10.32.2.100", 18080), timeout=3)
with tcp:
    data = tcp.recv(32)
if data != b"tcp-ok":
    raise SystemExit(f"unexpected TCP response: {data!r}")

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.settimeout(3)
udp.sendto(b"udp-ping", ("10.32.2.100", 18080))
data, _ = udp.recvfrom(32)
if data != b"udp-ok":
    raise SystemExit(f"unexpected UDP response: {data!r}")

tcp6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
tcp6.settimeout(3)
tcp6.connect(("fd32:2::100", 18080))
with tcp6:
    data = tcp6.recv(32)
if data != b"tcp6-ok":
    raise SystemExit(f"unexpected IPv6 TCP response: {data!r}")

udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
udp6.settimeout(3)
udp6.sendto(b"udp6-ping", ("fd32:2::100", 18080))
data, _ = udp6.recvfrom(32)
if data != b"udp6-ok":
    raise SystemExit(f"unexpected IPv6 UDP response: {data!r}")
PY

ip netns add "${CLIENT_NS}"
ip netns add "${ROUTER_NS}"
ip netns add "${TARGET_NS}"
ip link add "${CLIENT_LINK}" type veth peer name "${ROUTER_CLIENT_LINK}"
ip link add "${ROUTER_TARGET_LINK}" type veth peer name "${TARGET_LINK}"
ip link set "${CLIENT_LINK}" netns "${CLIENT_NS}"
ip link set "${ROUTER_CLIENT_LINK}" netns "${ROUTER_NS}"
ip link set "${ROUTER_TARGET_LINK}" netns "${ROUTER_NS}"
ip link set "${TARGET_LINK}" netns "${TARGET_NS}"

ip -n "${CLIENT_NS}" addr add 10.32.0.2/24 dev "${CLIENT_LINK}"
ip -n "${ROUTER_NS}" addr add 10.32.0.1/24 dev "${ROUTER_CLIENT_LINK}"
ip -n "${ROUTER_NS}" addr add 10.32.1.1/24 dev "${ROUTER_TARGET_LINK}"
ip -n "${TARGET_NS}" addr add 10.32.1.2/24 dev "${TARGET_LINK}"
ip -n "${CLIENT_NS}" -6 addr add fd32:0::2/64 dev "${CLIENT_LINK}" nodad
ip -n "${ROUTER_NS}" -6 addr add fd32:0::1/64 dev "${ROUTER_CLIENT_LINK}" nodad
ip -n "${ROUTER_NS}" -6 addr add fd32:1::1/64 dev "${ROUTER_TARGET_LINK}" nodad
ip -n "${TARGET_NS}" -6 addr add fd32:1::2/64 dev "${TARGET_LINK}" nodad
for ns in "${CLIENT_NS}" "${ROUTER_NS}" "${TARGET_NS}"; do
  ip -n "${ns}" link set lo up
done
ip -n "${CLIENT_NS}" link set "${CLIENT_LINK}" up
ip -n "${ROUTER_NS}" link set "${ROUTER_CLIENT_LINK}" up
ip -n "${ROUTER_NS}" link set "${ROUTER_TARGET_LINK}" up
ip -n "${TARGET_NS}" link set "${TARGET_LINK}" up
ip -n "${CLIENT_NS}" route add 10.32.2.100/32 via 10.32.0.1
ip -n "${TARGET_NS}" route add default via 10.32.1.1
ip -n "${CLIENT_NS}" -6 route add fd32:2::100/128 via fd32:0::1
ip -n "${TARGET_NS}" -6 route add default via fd32:1::1
ip netns exec "${ROUTER_NS}" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "${ROUTER_NS}" sysctl -q -w net.ipv6.conf.all.forwarding=1

CONFIG="${WORK_DIR}/plugin.json"
SOCKET="${WORK_DIR}/plugin.sock"
STATE="${WORK_DIR}/ownership.json"
cat >"${CONFIG}" <<EOF
{
  "apply": true,
  "rollback_on_exit": true,
  "family": "inet",
  "table": "anixops_forward",
  "chain": "prerouting",
  "priority": -100,
  "rules": [
    {
      "id": "tcp4-namespace",
      "protocol": "tcp",
      "listen_address": "10.32.2.100",
      "listen_port": 18080,
      "target_address": "10.32.1.2",
      "target_port": 18081,
      "comment": "namespace"
    },
    {
      "id": "udp4-namespace",
      "protocol": "udp",
      "listen_address": "10.32.2.100",
      "listen_port": 18080,
      "target_address": "10.32.1.2",
      "target_port": 18082,
      "comment": "namespace"
    },
    {
      "id": "tcp6-namespace",
      "protocol": "tcp",
      "listen_address": "fd32:2::100",
      "listen_port": 18080,
      "target_address": "fd32:1::2",
      "target_port": 18081,
      "comment": "namespace-v6"
    },
    {
      "id": "udp6-namespace",
      "protocol": "udp",
      "listen_address": "fd32:2::100",
      "listen_port": 18080,
      "target_address": "fd32:1::2",
      "target_port": 18082,
      "comment": "namespace-v6"
    }
  ]
}
EOF
chmod 0600 "${CONFIG}"
chmod 0700 "${WORK_DIR}"

ip netns exec "${TARGET_NS}" "${PYTHON_BIN}" "${TCP_SERVER}" &
TCP_PID="$!"
ip netns exec "${TARGET_NS}" "${PYTHON_BIN}" "${UDP_SERVER}" &
UDP_PID="$!"
ip netns exec "${TARGET_NS}" "${PYTHON_BIN}" "${TCP6_SERVER}" &
TCP6_PID="$!"
ip netns exec "${TARGET_NS}" "${PYTHON_BIN}" "${UDP6_SERVER}" &
UDP6_PID="$!"
ip netns exec "${ROUTER_NS}" "${AGENT_BINARY}" --anixops-config "${CONFIG}" --anixops-socket "${SOCKET}" --anixops-state "${STATE}" &
PLUGIN_PID="$!"

for _ in {1..50}; do
  [[ -S "${SOCKET}" ]] && break
  sleep 0.1
done
[[ -S "${SOCKET}" ]] || fail "plugin socket did not become ready"
RULESET="$(ip netns exec "${ROUTER_NS}" nft list table inet anixops_forward 2>&1)" || fail "nftables table was not installed: ${RULESET}"
for rule_id in tcp4-namespace udp4-namespace tcp6-namespace udp6-namespace; do
  grep -q "${rule_id}" <<<"${RULESET}" || fail "nftables rule ${rule_id} was not installed: ${RULESET}"
done
[[ "$(grep -c "counter packets" <<<"${RULESET}")" -eq 4 ]] || fail "per-rule nftables counters were not installed: ${RULESET}"
timeout 10 ip netns exec "${CLIENT_NS}" "${PYTHON_BIN}" "${CLIENT_CHECK}"
OBSERVATION="${STATE}.observed.json"
for _ in {1..70}; do
  if [[ -f "${OBSERVATION}" ]] && counter_observation_ready "${OBSERVATION}"; then
    break
  fi
  sleep 0.1
done
counter_observation_ready "${OBSERVATION}" || fail "runtime observation did not report incremented IPv4/IPv6 TCP/UDP counters"

kill -KILL "${PLUGIN_PID}"
if wait "${PLUGIN_PID}"; then
  fail "plugin unexpectedly exited cleanly after SIGKILL"
fi
PLUGIN_PID=""
[[ -f "${STATE}" ]] || fail "ownership journal was not durable after SIGKILL"
ip netns exec "${ROUTER_NS}" nft list table inet anixops_forward >/dev/null 2>&1 || fail "nftables table disappeared before restart recovery"
rm -f "${SOCKET}"

# A fresh process must recover the durable journal before applying its new
# generation. This is the crash/restart path that the Supervisor uses after an
# Agent restart, not a direct best-effort table delete.
ip netns exec "${ROUTER_NS}" "${AGENT_BINARY}" --anixops-config "${CONFIG}" --anixops-socket "${SOCKET}" --anixops-state "${STATE}" &
PLUGIN_PID="$!"
for _ in {1..50}; do
  [[ -S "${SOCKET}" ]] && break
  sleep 0.1
done
[[ -S "${SOCKET}" ]] || fail "plugin socket did not become ready after restart recovery"
ip netns exec "${ROUTER_NS}" nft list table inet anixops_forward >/dev/null 2>&1 || fail "nftables table was not re-installed after restart recovery"
kill "${PLUGIN_PID}"
wait "${PLUGIN_PID}"
PLUGIN_PID=""
if ip netns exec "${ROUTER_NS}" nft list table inet anixops_forward >/dev/null 2>&1; then
  fail "plugin-created nftables table still exists after graceful rollback"
fi
[[ ! -e "${STATE}" ]] || fail "ownership journal survived successful rollback"

SNAPSHOT_TABLE="${WORK_DIR}/snapshot.nft"
cat >"${SNAPSHOT_TABLE}" <<'EOF'
table inet anixops_forward {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 10.32.2.200 tcp dport 19090 dnat ip to 10.32.1.2:19091 comment "pre-existing-marker"
	}
}
EOF
ip netns exec "${ROUTER_NS}" nft -f "${SNAPSHOT_TABLE}"
ip netns exec "${ROUTER_NS}" "${AGENT_BINARY}" --anixops-config "${CONFIG}" --anixops-socket "${SOCKET}" --anixops-state "${STATE}" &
PLUGIN_PID="$!"
for _ in {1..50}; do
  [[ -S "${SOCKET}" ]] && break
  sleep 0.1
done
[[ -S "${SOCKET}" ]] || fail "plugin socket did not become ready for snapshot test"
RULESET="$(ip netns exec "${ROUTER_NS}" nft list table inet anixops_forward 2>&1)" || fail "replacement nftables table was not installed: ${RULESET}"
grep -q "tcp4-namespace" <<<"${RULESET}" || fail "replacement nftables rule was not installed: ${RULESET}"
kill "${PLUGIN_PID}"
wait "${PLUGIN_PID}"
PLUGIN_PID=""
ip netns exec "${ROUTER_NS}" nft list table inet anixops_forward | grep -q "pre-existing-marker" || fail "pre-existing nftables snapshot was not restored"
if ip netns exec "${ROUTER_NS}" nft list table inet anixops_forward | grep -q "tcp4-namespace"; then
  fail "replacement nftables rule survived snapshot rollback"
fi

printf 'status=PASS\n'
printf 'plugin_id=nftables-forward\n'
printf 'ipv4_tcp_dnat=true\n'
printf 'ipv4_udp_dnat=true\n'
printf 'ipv6_tcp_dnat=true\n'
printf 'ipv6_udp_dnat=true\n'
printf 'rollback_created_table=deleted\n'
printf 'rollback_existing_table=snapshot_restored\n'
printf 'crash_restart_recovery=true\n'
