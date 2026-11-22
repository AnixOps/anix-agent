#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${repo_root}/scripts/install.sh"

test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT

CONFIG_DIR="${test_root}/etc/anixops/agent"
INSTALL_DIR="${test_root}/usr/local/anixops-agent"
BIN_PATH="${INSTALL_DIR}/anix-agent"
VERSION_FILE="${INSTALL_DIR}/.release-version"
STATE_ROOT="${test_root}/var/lib/anixops-agent"
GOST_BINARY="${test_root}/usr/lib/anixops-agent/gost"
RELAY_BINARY="${test_root}/usr/lib/anixops-agent/anixops-relay"
PLUGIN_ROOT="${test_root}/var/lib/anixops-agent/plugins"
PLUGIN_SOCKET_DIR="${test_root}/run/anixops-agent/plugins"
SYSTEMD_UNIT_DIR="${test_root}/etc/systemd/system"
OPENRC_INIT_DIR="${test_root}/etc/init.d"

tmp_dir="${test_root}/command-snapshot"
mkdir -p "${tmp_dir}" "${test_root}/commands"
COMMAND_PATHS=(
    "${test_root}/commands/anix-agent"
    "${test_root}/commands/local-anix-agent"
    "${test_root}/commands/absent"
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

    printf '%s\n' "${url}" >"${output_path}"
}

selected_asset="$(download_release_zip v5.0.0 linux-64)"
[[ "$(basename "${selected_asset}")" == "anix-agent-linux-64.zip" ]]
[[ "$(cat "${selected_asset}")" == "${RELEASE_BASE}/v5.0.0/anix-agent-linux-64.zip" ]]
grep -Fq 'zip -9vyr ../anix-agent-' "${repo_root}/.github/workflows/release.yml"

ensure_plugin_layout
[[ "$(stat -c '%a' "${STATE_ROOT}")" == "700" ]]
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
printf '%s\n' stale-gost >"${install_fixture}/gost"
printf '%s\n' stale-relay >"${install_fixture}/anixops-relay"
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
# gost and the anixops relay were removed: an older package's are not installed.
[[ ! -e "${GOST_BINARY}" && ! -e "${RELAY_BINARY}" ]]

# retire_gost removes what an earlier install set up for gost.
GOST_DIR="${test_root}/var/lib/anixops-gost"
mkdir -p "${SYSTEMD_UNIT_DIR}" "${GOST_DIR}/tls" "$(dirname "${GOST_BINARY}")"
printf '[Service]\n' >"${SYSTEMD_UNIT_DIR}/anixops-gost.service"
printf '{}\n' >"${GOST_DIR}/gost.json"
printf '%s\n' old-gost >"${GOST_BINARY}"
systemctl() { :; }
userdel() { :; }
groupdel() { :; }
retire_gost >/dev/null
[[ ! -e "${SYSTEMD_UNIT_DIR}/anixops-gost.service" && ! -e "${GOST_DIR}" && ! -e "${GOST_BINARY}" ]]
unset -f systemctl userdel groupdel

# retire_relay removes what an earlier ANIXOPS_RELAY=1 install set up.
RELAY_DIR="${test_root}/var/lib/anixops-relay"
mkdir -p "${SYSTEMD_UNIT_DIR}" "${RELAY_DIR}/tls" "$(dirname "${RELAY_BINARY}")"
printf '[Service]\n' >"${SYSTEMD_UNIT_DIR}/anixops-relay.service"
printf '{}\n' >"${RELAY_DIR}/relay.json"
printf '%s\n' old-relay >"${RELAY_BINARY}"
systemctl() { :; }
userdel() { :; }
groupdel() { :; }
retire_relay >/dev/null
[[ ! -e "${SYSTEMD_UNIT_DIR}/anixops-relay.service" && ! -e "${RELAY_DIR}" && ! -e "${RELAY_BINARY}" ]]
unset -f systemctl userdel groupdel

# A node installed by Control's O1 installer (user anixops-agent, sandboxed)
# is never switched back to the root layout.
o1_units="${test_root}/o1-units"
mkdir -p "${o1_units}"
printf '[Service]\nUser=anixops-agent\n' >"${o1_units}/${SERVICE_NAME}.service"
if (SYSTEMD_UNIT_DIR="${o1_units}" refuse_o1_install >/dev/null 2>&1); then
    echo "an O1 install was not refused" >&2
    exit 1
fi
printf '[Service]\nUser=root\n' >"${o1_units}/${SERVICE_NAME}.service"
(SYSTEMD_UNIT_DIR="${o1_units}" refuse_o1_install)
grep -Fq 'RuntimeDirectory=anixops-agent' "${repo_root}/scripts/install.sh"

for example in config.json config.production.json config.wireguard.json; do
    example_path="${repo_root}/example/${example}"
    grep -Fq '"PluginSupervisorEnabled": true' "${example_path}"
    grep -Fq '"PluginRoot": "/var/lib/anixops-agent/plugins"' "${example_path}"
    grep -Fq '"PluginSocketDir": "/run/anixops-agent/plugins"' "${example_path}"
    grep -Fq '"PluginOfficialPublicKey": "IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M="' "${example_path}"
done

(
    source "${repo_root}/scripts/anix-agent.sh"
    CONFIG_DIR="${test_root}/wizard/etc/anixops/agent"
    BIN_PATH="${test_root}/wizard/usr/local/anixops-agent/anix-agent"

    prompt_text() { printf '%s' "${2:-}"; }
    prompt_required_text() {
        case "$1" in
            "Control 地址"*) printf '%s' https://control.company.net ;;
            "Agent 控制流"*) printf '%s' control.company.net:443 ;;
            *) printf '%s' unexpected ;;
        esac
    }
    prompt_int() { printf '%s' "${2:-1}"; }
    confirm() {
        case "$1" in
            "是否启用 AnixOps 官方插件 Supervisor？"*) return 0 ;;
            *) return 1 ;;
        esac
    }

    init_config_wizard
    wizard_config="${CONFIG_DIR}/config.json"
    grep -Fq '"GRPCUseTLS": true' "${wizard_config}"
    grep -Fq '"GRPCHost": "control.company.net:443"' "${wizard_config}"
    grep -Fq '"AgentNode": "proxy-1"' "${wizard_config}"
    grep -Fq '"Environment": "production"' "${wizard_config}"
    grep -Fq '"MaintenanceEnvironment": "production"' "${wizard_config}"
    grep -Fq '"PluginSupervisorEnabled": true' "${wizard_config}"
    grep -Fq '"PluginRoot": "/var/lib/anixops-agent/plugins"' "${wizard_config}"
    grep -Fq '"PluginSocketDir": "/run/anixops-agent/plugins"' "${wizard_config}"
    grep -Fq '"PluginOfficialPublicKey": "IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M="' "${wizard_config}"
    ! grep -Fq 'ApiKey' "${wizard_config}"
)

GOEXPERIMENT=jsonv2 GOWORK=off go run . validate-config \
    -c "${test_root}/wizard/etc/anixops/agent/config.json" >/dev/null

echo "installer test passed"
