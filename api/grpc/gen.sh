#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MODULE_PATH="github.com/AnixOps/anix-agent/v5"
PROTO_FILES=(
  "api/grpc/v2board.proto"
)

cd "${REPO_ROOT}"

for command_name in protoc protoc-gen-go protoc-gen-go-grpc; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    echo "error: ${command_name} not found" >&2
    exit 1
  fi
done

protoc \
  --go_out=. \
  --go_opt="module=${MODULE_PATH}" \
  --go-grpc_out=. \
  --go-grpc_opt="module=${MODULE_PATH}" \
  "${PROTO_FILES[@]}"

echo "Generated legacy gRPC bindings."
