#!/usr/bin/env bash
# Fails when a tracked file describes ANX internals or uses a sensitive word.
# This repository and its pkg.go.dev page are public: ANX may be named and
# driven only through the fields, flags and names in contracts/anx/BOUNDARY.md,
# never explained (spec references, carrier mechanics, key sizes, rationale).
#
#   scripts/check_public_wording.sh             check every tracked file
#   scripts/check_public_wording.sh --self-test check the matcher itself
set -euo pipefail

# Extended regular expressions, matched case-insensitively.
PATTERNS=(
  'ANX-LINE-(SPEC|REVERSE|ONBOARDING)' # private spec documents
  'TBD-L[0-9]'                      # private spec decisions
  'anx (spec )?§'                   # private spec sections
  'hybrid public key|混合公钥'
  'RM_ADDR|MP_PRIO'
  'cover[- ]site|looks unlike'
  'camouflage|伪装'
  'cross-border|跨境'
  'GFW|翻墙|被墙|墙内|墙外|机场|审查|封锁|censor'
)

# Files that may hold these words: the licence text, checksums and this script.
EXCLUDE=':!LICENSE :!go.sum :!scripts/check_public_wording.sh'

matcher() {
  local IFS='|'
  printf '%s' "${PATTERNS[*]}"
}

if [[ "${1:-}" == "--self-test" ]]; then
  bad=$'see anx ANX-LINE-REVERSE §6.4\nthe hybrid public key\ncamouflage target\nTBD-L14'
  good=$'anx-server --reverse-a2-listen\nnftables firewall rules\nmainland-China address blocks'
  [[ "$(grep -icE "$(matcher)" <<<"${bad}")" == 4 ]] || { echo "self-test: missed a bad line" >&2; exit 1; }
  ! grep -iqE "$(matcher)" <<<"${good}" || { echo "self-test: flagged a good line" >&2; exit 1; }
  echo "self-test ok"
  exit 0
fi

# shellcheck disable=SC2086
if git grep -nIiE "$(matcher)" -- . ${EXCLUDE}; then
  echo "public wording check failed: describe ANX only through contracts/anx/BOUNDARY.md names, and use neutral words" >&2
  exit 1
fi
echo "public wording ok"
