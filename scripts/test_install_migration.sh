#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${repo_root}/scripts/install.sh"

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT

LEGACY_CONFIG_DIR="${test_root}/etc/V2bX"
CONFIG_DIR="${test_root}/etc/anixops/agent"
MIGRATION_DIR="${CONFIG_DIR}/migration"
LEGACY_INSTALL_DIR="${test_root}/usr/local/V2bX"
INSTALL_DIR="${test_root}/usr/local/anixops-agent"
LEGACY_DATA_DIR="${LEGACY_INSTALL_DIR}/data"
DATA_DIR="${INSTALL_DIR}/data"
BIN_PATH="${INSTALL_DIR}/anix-agent"
LEGACY_BIN_PATH="${LEGACY_INSTALL_DIR}/V2bX"
VERSION_FILE="${INSTALL_DIR}/.release-version"
PLUGIN_ROOT="${test_root}/var/lib/anixops/plugins"
PLUGIN_SOCKET_DIR="${test_root}/run/anixops/plugins"
SYSTEMD_UNIT_DIR="${test_root}/etc/systemd/system"
OPENRC_INIT_DIR="${test_root}/etc/init.d"

mkdir -p "${LEGACY_CONFIG_DIR}/certs" "${CONFIG_DIR}" "${LEGACY_DATA_DIR}" "${DATA_DIR}"
printf '%s\n' legacy-config >"${LEGACY_CONFIG_DIR}/config.json"
printf '%s\n' legacy-cert >"${LEGACY_CONFIG_DIR}/certs/node.pem"
printf '%s\n' new-config >"${CONFIG_DIR}/config.json"
printf '%s\n' legacy-plain-credential >"${LEGACY_DATA_DIR}/credential.json"
printf '%s\n' legacy-encrypted-credential >"${LEGACY_DATA_DIR}/credential.json.enc"
printf '%s\n' current-plain-credential >"${DATA_DIR}/credential.json"
chmod 0640 "${LEGACY_DATA_DIR}/credential.json.enc"

copy_legacy_config
copy_legacy_credentials

[[ "$(cat "${CONFIG_DIR}/config.json")" == "new-config" ]]
[[ "$(cat "${CONFIG_DIR}/certs/node.pem")" == "legacy-cert" ]]
[[ "$(cat "${LEGACY_CONFIG_DIR}/config.json")" == "legacy-config" ]]
[[ "$(cat "${DATA_DIR}/credential.json")" == "current-plain-credential" ]]
[[ "$(cat "${DATA_DIR}/credential.json.enc")" == "legacy-encrypted-credential" ]]
[[ "$(stat -c '%a' "${DATA_DIR}/credential.json.enc")" == "640" ]]

tmp_dir="${test_root}/command-snapshot"
mkdir -p "${tmp_dir}" "${test_root}/commands"
COMMAND_PATHS=(
    "${test_root}/commands/anix-agent"
    "${test_root}/commands/v2bx-anixops"
    "${test_root}/commands/V2bX"
)
printf '%s\n' old-manager >"${COMMAND_PATHS[0]}"
chmod 0750 "${COMMAND_PATHS[0]}"
ln -s "${COMMAND_PATHS[0]}" "${COMMAND_PATHS[1]}"
capture_command_entries
printf '%s\n' new-manager >"${COMMAND_PATHS[0]}"
rm -f "${COMMAND_PATHS[1]}"
ln -s /does/not/exist "${COMMAND_PATHS[1]}"
ln -s "${COMMAND_PATHS[0]}" "${COMMAND_PATHS[2]}"
restore_command_entries
[[ "$(cat "${COMMAND_PATHS[0]}")" == "old-manager" ]]
[[ "$(stat -c '%a' "${COMMAND_PATHS[0]}")" == "750" ]]
[[ "$(readlink "${COMMAND_PATHS[1]}")" == "${COMMAND_PATHS[0]}" ]]
[[ ! -e "${COMMAND_PATHS[2]}" && ! -L "${COMMAND_PATHS[2]}" ]]

release="debian"
legacy_service_backup=""
legacy_service_was_active="false"
legacy_service_was_enabled="false"
legacy_service_captured="false"
mkdir -p "${SYSTEMD_UNIT_DIR}"
legacy_unit="${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service"
printf '%s\n' legacy-service-definition >"${legacy_unit}"
systemctl_log="${test_root}/systemctl.log"
systemctl() {
    printf '%s\n' "$*" >>"${systemctl_log}"
    case "$*" in
        "show -p FragmentPath --value ${LEGACY_SERVICE_NAME}.service")
            printf '%s\n' "${legacy_unit}"
            ;;
        "is-active --quiet ${LEGACY_SERVICE_NAME}.service"|"is-enabled --quiet ${LEGACY_SERVICE_NAME}.service")
            return 0
            ;;
    esac
    return 0
}
capture_legacy_service
printf '%s\n' new-service-definition >"${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"
rm -f "${legacy_unit}"
ln -s "${SERVICE_NAME}.service" "${legacy_unit}"
restore_legacy_service
[[ ! -e "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" ]]
[[ "$(cat "${legacy_unit}")" == "legacy-service-definition" ]]
grep -Fq "enable ${LEGACY_SERVICE_NAME}.service" "${systemctl_log}"
grep -Fq "start ${LEGACY_SERVICE_NAME}.service" "${systemctl_log}"

for version in v3.0.0 v3.0.0-alpha v3.0.0-alpha.1 v3.0.0-beta.2 v3.0.0-rc.3; do
    (validate_version "${version}")
done
for version in 3.0.0 v3.0 v3.0.0-preview.1 v3.0.0-rc.x; do
    if (validate_version "${version}" >/dev/null 2>&1); then
        echo "invalid version accepted: ${version}" >&2
        exit 1
    fi
done

tmp_dir="${test_root}/downloads"
mkdir -p "${tmp_dir}"
RELEASE_BASE="https://example.invalid/releases/download"

curl() {
    local output_path=""
    local url=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o)
                output_path="$2"
                shift 2
                ;;
            http*)
                url="$1"
                shift
                ;;
            *)
                shift
                ;;
        esac
    done

    if [[ "${url}" == *"/anix-agent-linux-64.zip" ]]; then
        return 22
    fi
    printf '%s\n' legacy-asset >"${output_path}"
}

selected_asset="$(download_release_zip v2.5.0 linux-64)"
[[ "$(basename "${selected_asset}")" == "V2bX-linux-64.zip" ]]

grep -Fq 'ln -s anix-agent build_assets/V2bX' "${repo_root}/.github/workflows/release.yml"
grep -Fq 'zip -9vyr ../anix-agent-' "${repo_root}/.github/workflows/release.yml"
grep -Fq "\"V2bX-\${asset_suffix}.zip\"" "${repo_root}/scripts/install.sh"
grep -Fq 'credential.json.enc' "${repo_root}/scripts/install.sh"
grep -Fq 'ANIX_AGENT_CONFIG:-/etc/anixops/agent/config.json' "${repo_root}/Dockerfile"
grep -Fq '[ -e /etc/V2bX/config.json ]' "${repo_root}/Dockerfile"

ensure_plugin_layout
[[ "$(stat -c '%a' "${PLUGIN_ROOT}")" == "750" ]]
[[ "$(stat -c '%a' "${PLUGIN_SOCKET_DIR}")" == "750" ]]

install_fixture="${test_root}/release-fixture"
tmp_dir="${test_root}/fresh-install-tmp"
INSTALL_DIR="${test_root}/fresh-install/usr/local/anixops-agent"
CONFIG_DIR="${test_root}/fresh-install/etc/anixops/agent"
BIN_PATH="${INSTALL_DIR}/anix-agent"
VERSION_FILE="${INSTALL_DIR}/.release-version"
mkdir -p "${install_fixture}" "${tmp_dir}"
printf '#!/bin/sh\nexit 0\n' >"${install_fixture}/anix-agent"
chmod 0755 "${install_fixture}/anix-agent"
printf '%s\n' production-template >"${install_fixture}/config.production.json"
printf '%s\n' development-template >"${install_fixture}/config.json"
touch "${test_root}/release-fixture.zip"
unzip() {
    local destination=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d)
                destination="$2"
                shift 2
                ;;
            *) shift ;;
        esac
    done
    cp -a "${install_fixture}/." "${destination}/"
}
install_files "${test_root}/release-fixture.zip" "v9.9.9"
[[ "$(cat "${CONFIG_DIR}/config.json")" == "production-template" ]]
[[ "$(stat -c '%a' "${CONFIG_DIR}/config.json")" == "600" ]]
[[ "$(cat "${VERSION_FILE}")" == "v9.9.9" ]]

for example in \
    config.json config.grpc.json config.production.json config_auto_register.json config_realtime_sync.json \
    config_test_local.json config.wireguard.json; do
    example_path="${repo_root}/example/${example}"
    grep -Fq '"PluginSupervisorEnabled": true' "${example_path}"
    grep -Fq '"PluginRoot": "/var/lib/anixops/plugins"' "${example_path}"
    grep -Fq '"PluginSocketDir": "/run/anixops/plugins"' "${example_path}"
    grep -Fq '"PluginOfficialPublicKey": "IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M="' "${example_path}"
done

(
    source "${repo_root}/scripts/anix-agent.sh"
    CONFIG_DIR="${test_root}/wizard/etc/anixops/agent"
    BIN_PATH="${test_root}/wizard/usr/local/anixops-agent/anix-agent"

    prompt_text() {
        case "$1" in
            "选择内核类型"*) printf '%s' sing ;;
            "节点类型"*) printf '%s' vless ;;
            "监听 IP"*) printf '%s' 0.0.0.0 ;;
            "发送 IP"*) printf '%s' 0.0.0.0 ;;
            "证书模式"*) printf '%s' self ;;
            "传输方式"*) printf '%s' http ;;
            "Agent Control / gRPC 目标"*) printf '%s' control.company.net:443 ;;
            "GRPCServerName"*) printf '%s' control.company.net ;;
            *) printf '%s' "${2:-}" ;;
        esac
    }
    prompt_required_text() {
        case "$1" in
            "面板地址"*) printf '%s' https://control.company.net ;;
            *) printf '%s' 0123456789abcdef0123456789abcdef ;;
        esac
    }
    prompt_int() { printf '%s' "${2:-1}"; }
    confirm() {
        case "$1" in
            "是否启用 Agent Control gRPC 长连接？"*|"是否启用 AnixOps 官方插件 Supervisor？"*|"是否启用 Agent Control / gRPC TLS？"*) return 0 ;;
            *) return 1 ;;
        esac
    }

    init_config_wizard
    wizard_config="${CONFIG_DIR}/config.json"
    grep -Fq '"Transport": "http"' "${wizard_config}"
    grep -Fq '"AgentControlEnabled": true' "${wizard_config}"
    grep -Fq '"GRPCUseTLS": true' "${wizard_config}"
    grep -Fq '"AgentControlAllowInsecure": false' "${wizard_config}"
    grep -Fq '"Environment": "production"' "${wizard_config}"
    grep -Fq '"MaintenanceEnvironment": "production"' "${wizard_config}"
    grep -Fq '"WSEndpoint": "/api/v2/agent/ws"' "${wizard_config}"
    grep -Fq '"PluginSupervisorEnabled": true' "${wizard_config}"
    grep -Fq '"PluginRoot": "/var/lib/anixops/plugins"' "${wizard_config}"
    grep -Fq '"PluginSocketDir": "/run/anixops/plugins"' "${wizard_config}"
    grep -Fq '"PluginOfficialPublicKey": "IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M="' "${wizard_config}"
    grep -Fq '"Transport": "http"' "${wizard_config}"
    agent_control_host_is_loopback "[::1]:50051" "http://example.com"
    ! agent_control_host_is_loopback "control.example.com:50051" "http://127.0.0.1"
)

GOEXPERIMENT=jsonv2 GOWORK=off go run . validate-config \
    -c "${test_root}/wizard/etc/anixops/agent/config.json" >/dev/null

echo "installer migration compatibility test passed"
