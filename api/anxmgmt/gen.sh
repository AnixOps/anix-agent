#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULE_PATH="github.com/AnixOps/anix-agent/v5"

cd "${REPO_ROOT}"

for command_name in protoc protoc-gen-go protoc-gen-go-grpc; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "error: ${command_name} not found" >&2
    exit 1
  fi
done

# The anx management API is a copy of the closed anx repository's boundary
# (contracts/anx): it has no go_package, so the import path is given here.
ANX_MGMT="anx/mgmt/v1/mgmt.proto"
ANX_MGMT_PACKAGE="${MODULE_PATH}/api/anxmgmt/v1;anxmgmtpb"
protoc \
  -I contracts/anx/proto \
  --go_out=. \
  --go_opt="module=${MODULE_PATH}" \
  --go_opt="M${ANX_MGMT}=${ANX_MGMT_PACKAGE}" \
  --go-grpc_out=. \
  --go-grpc_opt="module=${MODULE_PATH}" \
  --go-grpc_opt="M${ANX_MGMT}=${ANX_MGMT_PACKAGE}" \
  "contracts/anx/proto/${ANX_MGMT}"

echo "Generated the anx management client."
