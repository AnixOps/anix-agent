#!/usr/bin/env bash
# Fails when go.mod or go.sum pulls in a retired third-party proxy engine or
# a GPL / AGPL module. The Agent drives anixcore (anx-node) and anx-server as
# separate processes over gRPC, HTTP, config files and the command line; it
# must never link those engines again (sing-box is GPL-3.0, which would put
# the whole Agent binary under the GPL).
#
#   scripts/check_forbidden_deps.sh             check go.mod and go.sum
#   scripts/check_forbidden_deps.sh --self-test check the matcher itself
set -euo pipefail

# Module path prefixes that must not appear. Keep in sync with AGENTS.md.
FORBIDDEN=(
  "github.com/sagernet/"        # sing-box and its sing-* modules (GPL-3.0)
  "github.com/metacubex/"       # mihomo / Clash.Meta forks of sing-*
  "github.com/xtls/"            # Xray-core, REALITY
  "github.com/v2fly/"           # v2ray-core
  "github.com/apernet/"         # Hysteria
  "github.com/enfein/mieru"     # Mieru (GPL-3.0)
  "github.com/easytier/"        # EasyTier
  "github.com/go-gost/"         # gost
  "github.com/ginuerzh/gost"    # gost v2
)

# matches FILE: prints every forbidden module line found in FILE.
matches() {
  local file="$1" prefix
  for prefix in "${FORBIDDEN[@]}"; do
    grep -inF -- "${prefix}" "${file}" || true
  done
}

check() {
  local found="" file
  for file in "$@"; do
    [[ -f "${file}" ]] || continue
    local hit
    hit="$(matches "${file}")"
    if [[ -n "${hit}" ]]; then
      found+="${file}:"$'\n'"${hit}"$'\n'
    fi
  done
  if [[ -n "${found}" ]]; then
    echo "::error::forbidden third-party engine / GPL module in the Agent's dependencies"
    printf '%s' "${found}"
    echo "Drive anixcore (anx-node) over its management API instead of linking an engine."
    return 1
  fi
}

self_test() {
  local dir
  dir="$(mktemp -d)"
  trap 'rm -rf "${dir}"' RETURN
  printf 'module x\n\nrequire github.com/spf13/cobra v1.9.1\n' >"${dir}/clean.mod"
  printf 'module x\n\nrequire github.com/SagerNet/sing-box v1.12.0\n' >"${dir}/dirty.mod"
  printf 'github.com/xtls/xray-core v1.8.0 h1:abc=\n' >"${dir}/dirty.sum"
  check "${dir}/clean.mod" >/dev/null || { echo "self-test: clean go.mod rejected"; return 1; }
  if check "${dir}/dirty.mod" >/dev/null; then echo "self-test: sing-box not caught"; return 1; fi
  if check "${dir}/dirty.sum" >/dev/null; then echo "self-test: xray-core in go.sum not caught"; return 1; fi
  echo "check_forbidden_deps self-test OK"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  exit
fi

cd "$(dirname "$0")/.."
check go.mod go.sum
echo "No forbidden engine or GPL modules in go.mod / go.sum"
