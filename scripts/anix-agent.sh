#!/usr/bin/env bash

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

REPO_OWNER="${REPO_OWNER:-AnixOps}"
REPO_NAME="${REPO_NAME:-anix-agent}"
INSTALL_SCRIPT_REF="${INSTALL_SCRIPT_REF:-${REPO_BRANCH:-dev_new}}"

PRODUCT_NAME="AnixOps Agent"
SERVICE_NAME="anix-agent"
INSTALL_DIR="/usr/local/anixops-agent"
BIN_PATH="${INSTALL_DIR}/anix-agent"
CONFIG_DIR="/etc/anixops/agent"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}"
CMD_NAME="anix-agent"
DEFAULT_PLUGIN_ROOT="/var/lib/anixops-agent/plugins"
DEFAULT_PLUGIN_SOCKET_DIR="/run/anixops-agent/plugins"
OFFICIAL_PLUGIN_PUBLIC_KEY="IaqXgif/OGydNv/mQHoyFmqOvzeplICaMZndrhqMG0M="

LEGACY_SERVICE_NAME="V2bX"
LEGACY_INSTALL_DIR="/usr/local/V2bX"
LEGACY_CONFIG_DIR="/etc/V2bX"
LEGACY_CMD_NAME="v2bx-anixops"
MIGRATION_DIR="${CONFIG_DIR}/migration"

# Where the root installer (scripts/install.sh) puts the rest of what uninstall
# removes. They are plain assignments, never read from the environment, so the
# command always works on the real host; scripts/test_manager_uninstall.sh
# sources this file and points them at a temporary directory.
SYSTEMD_UNIT_DIR="/etc/systemd/system"
OPENRC_INIT_DIR="/etc/init.d"
SYSCTL_DROPIN="/etc/sysctl.d/90-anixops-forward.conf"
USR_BIN_DIR="/usr/bin"
USR_LOCAL_BIN_DIR="/usr/local/bin"
STATE_ROOT="/var/lib/anixops-agent"
GOST_SERVICE_NAME="anixops-gost"
GOST_USER="anixops-gost"
GOST_DIR="/var/lib/anixops-gost"
GOST_BINARY="/usr/lib/anixops-agent/gost"
RELAY_SERVICE_NAME="anixops-relay"
RELAY_USER="anixops-relay"
RELAY_DIR="/var/lib/anixops-relay"
RELAY_BINARY="/usr/lib/anixops-agent/anixops-relay"

info() {
    echo -e "${green}$*${plain}"
}

warn() {
    echo -e "${yellow}$*${plain}"
}

error() {
    echo -e "${red}$*${plain}"
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "错误：请使用 root 用户运行 ${PRODUCT_NAME} 管理脚本"
        exit 1
    fi
}

is_alpine() {
    [[ -f /etc/alpine-release ]]
}

is_installed() {
    [[ -x "${BIN_PATH}" ]]
}

run_state() {
    if ! is_installed; then
        echo "not_installed"
        return
    fi

    if is_alpine; then
        local status_text
        status_text="$(rc-service "${SERVICE_NAME}" status 2>/dev/null || true)"
        if echo "${status_text}" | grep -qi "started"; then
            echo "running"
        else
            echo "stopped"
        fi
        return
    fi

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "running"
    else
        echo "stopped"
    fi
}

enable_state() {
    if ! is_installed; then
        echo "not_installed"
        return
    fi

    if is_alpine; then
        if rc-update show 2>/dev/null | grep -Eq "^${SERVICE_NAME}[[:space:]]"; then
            echo "enabled"
        else
            echo "disabled"
        fi
        return
    fi

    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo "enabled"
    else
        echo "disabled"
    fi
}

state_label() {
    case "$1" in
        running) echo -e "${green}运行中${plain}" ;;
        stopped) echo -e "${yellow}未运行${plain}" ;;
        enabled) echo -e "${green}已启用${plain}" ;;
        disabled) echo -e "${yellow}未启用${plain}" ;;
        not_installed) echo -e "${red}未安装${plain}" ;;
        *) echo -e "${yellow}未知${plain}" ;;
    esac
}

install_state_label() {
    if [[ "$1" == "not_installed" ]]; then
        echo -e "${red}未安装${plain}"
    else
        echo -e "${green}已安装${plain}"
    fi
}

svc_start() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" start
    else
        systemctl start "${SERVICE_NAME}"
    fi
}

svc_stop() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" stop
    else
        systemctl stop "${SERVICE_NAME}"
    fi
}

svc_restart() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" restart
    else
        systemctl restart "${SERVICE_NAME}"
    fi
}

svc_status() {
    if is_alpine; then
        rc-service "${SERVICE_NAME}" status
    else
        systemctl --no-pager --full status "${SERVICE_NAME}"
    fi
}

svc_enable() {
    if is_alpine; then
        rc-update add "${SERVICE_NAME}" default >/dev/null 2>&1 || true
    else
        systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
}

svc_disable() {
    if is_alpine; then
        rc-update del "${SERVICE_NAME}" default >/dev/null 2>&1 || true
    else
        systemctl disable "${SERVICE_NAME}" >/dev/null 2>&1 || true
    fi
}

show_log() {
    if command -v journalctl >/dev/null 2>&1; then
        journalctl -u "${SERVICE_NAME}" -n 200 --no-pager -e
        return
    fi

    if command -v logread >/dev/null 2>&1; then
        logread | grep -i "${SERVICE_NAME}" | tail -n 200
        return
    fi

    warn "当前系统无法自动读取日志，请手动查看系统日志"
}

run_install_script() {
    local version="${1:-}"
    local script_ref="${INSTALL_SCRIPT_REF}"
    local tmp_file
    local rc=0

    if [[ -n "${version}" ]]; then
        script_ref="${version}"
    fi
    tmp_file="$(mktemp)"

    curl -fsSL "${RAW_BASE}/${script_ref}/scripts/install.sh" -o "${tmp_file}"
    chmod +x "${tmp_file}"
    if [[ -n "${version}" ]]; then
        "${tmp_file}" "${version}" || rc=$?
    else
        "${tmp_file}" || rc=$?
    fi

    rm -f "${tmp_file}"
    return "${rc}"
}

run_bin_subcommand() {
    local sub_cmd="$1"
    shift || true

    if ! is_installed; then
        error "未检测到可执行文件：${BIN_PATH}"
        return 1
    fi

    "${BIN_PATH}" "${sub_cmd}" "$@"
}

edit_config() {
    local cfg="${CONFIG_DIR}/config.json"
    local editor="${EDITOR:-}"

    if [[ ! -f "${cfg}" ]]; then
        error "配置文件不存在：${cfg}"
        return 1
    fi

    if [[ -z "${editor}" ]]; then
        for e in nano vim vi; do
            if command -v "${e}" >/dev/null 2>&1; then
                editor="${e}"
                break
            fi
        done
    fi

    if [[ -z "${editor}" ]]; then
        error "未找到可用编辑器（nano/vim/vi）"
        return 1
    fi

    "${editor}" "${cfg}"
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    printf '%s' "${s}"
}

prompt_text() {
    local prompt="$1"
    local default="${2:-}"
    local value=""
    if [[ -n "${default}" ]]; then
        read -r -p "${prompt} [默认: ${default}]: " value
        value="${value:-${default}}"
    else
        read -r -p "${prompt}: " value
    fi
    printf '%s' "${value}"
}

prompt_required_text() {
    local prompt="$1"
    local value=""
    while true; do
        read -r -p "${prompt}: " value
        if [[ -n "${value}" ]]; then
            printf '%s' "${value}"
            return
        fi
        warn "该项不能为空，请重新输入"
    done
}

prompt_int() {
    local prompt="$1"
    local default="${2:-}"
    local value=""
    while true; do
        if [[ -n "${default}" ]]; then
            read -r -p "${prompt} [默认: ${default}]: " value
            value="${value:-${default}}"
        else
            read -r -p "${prompt}: " value
        fi

        if [[ "${value}" =~ ^[0-9]+$ ]]; then
            printf '%s' "${value}"
            return
        fi
        warn "请输入有效的整数"
    done
}

agent_control_host_is_loopback() {
    local grpc_host="$1"
    local api_host="$2"
    local endpoint="${grpc_host:-${api_host}}"
    local host=""

    endpoint="${endpoint#*://}"
    endpoint="${endpoint%%/*}"
    if [[ "${endpoint}" =~ ^\[([^]]+)\](:[0-9]+)?$ ]]; then
        host="${BASH_REMATCH[1]}"
    elif [[ "${endpoint}" == *:* ]]; then
        host="${endpoint%%:*}"
    else
        host="${endpoint}"
    fi

    [[ "${host,,}" == "localhost" || "${host}" == "::1" || "${host}" == 127.* ]]
}

init_config_wizard() {
    local cfg="${CONFIG_DIR}/config.json"
    local backup=""
    local core_type api_host api_key node_id node_type timeout listen_ip send_ip cert_mode
    local transport grpc_host grpc_use_tls grpc_server_name grpc_keepalive
    local agent_control_enabled agent_control_allow_insecure grpc_tls_default
    local plugin_supervisor_enabled plugin_supervisor_default
    local core_json

    info "进入初始化配置向导（将写入 ${cfg}）"
    mkdir -p "${CONFIG_DIR}"

    if [[ -f "${cfg}" ]]; then
        if ! confirm "检测到已有配置，是否覆盖？" "n"; then
            warn "已取消初始化配置"
            return 0
        fi
        backup="${cfg}.bak.$(date +%Y%m%d%H%M%S)"
        cp -f "${cfg}" "${backup}"
        info "已备份旧配置到 ${backup}"
    fi

    while true; do
        core_type="$(prompt_text "选择内核类型(sing/xray/hysteria2)" "sing")"
        core_type="$(echo "${core_type}" | tr '[:upper:]' '[:lower:]')"
        if [[ "${core_type}" == "sing" || "${core_type}" == "xray" || "${core_type}" == "hysteria2" ]]; then
            break
        fi
        warn "仅支持 sing / xray / hysteria2"
    done

    api_host="$(prompt_required_text "面板地址 ApiHost（生产环境必须使用 HTTPS）")"
    api_key="$(prompt_required_text "面板 API Key")"
    node_id="$(prompt_int "节点 ID NodeID" "1")"
    node_type="$(prompt_text "节点类型 NodeType(面板分类)" "v2ray")"
    timeout="$(prompt_int "接口超时(秒)" "30")"
    listen_ip="$(prompt_text "监听 IP ListenIP" "0.0.0.0")"
    send_ip="$(prompt_text "发送 IP SendIP" "0.0.0.0")"
    cert_mode="$(prompt_text "证书模式 CertMode(self/file/dns)" "self")"
    while true; do
        transport="$(prompt_text "传输方式 Transport(http/grpc)" "http")"
        transport="$(echo "${transport}" | tr '[:upper:]' '[:lower:]')"
        if [[ "${transport}" == "http" || "${transport}" == "grpc" ]]; then
            break
        fi
        warn "仅支持 http / grpc"
    done

    if confirm "是否启用 Agent Control gRPC 长连接？" "y"; then
        agent_control_enabled=true
        plugin_supervisor_default="y"
    else
        agent_control_enabled=false
        plugin_supervisor_default="n"
    fi

    if confirm "是否启用 AnixOps 官方插件 Supervisor？" "${plugin_supervisor_default}"; then
        plugin_supervisor_enabled=true
    else
        plugin_supervisor_enabled=false
    fi
    if [[ "${plugin_supervisor_enabled}" == "true" && "${agent_control_enabled}" != "true" ]]; then
        warn "插件 Supervisor 已启用，但远程生命周期操作需要 Agent Control 长连接"
    fi

    grpc_host=""
    grpc_use_tls=false
    grpc_server_name=""
    grpc_keepalive=30
    agent_control_allow_insecure=false
    if [[ "${transport}" == "grpc" || "${agent_control_enabled}" == "true" ]]; then
        grpc_host="$(prompt_text "Agent Control / gRPC 目标 GRPCHost(host:port，留空从 ApiHost 推导)" "")"
        grpc_tls_default="n"
        if [[ "${api_host,,}" == https://* ]]; then
            grpc_tls_default="y"
        fi
        while true; do
            if confirm "是否启用 Agent Control / gRPC TLS？" "${grpc_tls_default}"; then
                grpc_use_tls=true
            else
                grpc_use_tls=false
            fi
            if [[ "${agent_control_enabled}" != "true" || "${grpc_use_tls}" == "true" ]] || \
                agent_control_host_is_loopback "${grpc_host}" "${api_host}"; then
                break
            fi
            if confirm "远程明文会暴露节点凭证，是否显式设置 AgentControlAllowInsecure=true？" "n"; then
                agent_control_allow_insecure=true
                break
            fi
            warn "非本地 Agent Control 必须启用 TLS，或显式允许不安全明文连接"
        done
        grpc_server_name="$(prompt_text "GRPCServerName(可为空，默认取主机名)" "")"
        grpc_keepalive="$(prompt_int "GRPCKeepalive(秒)" "30")"
    fi

    case "${core_type}" in
        sing)
            core_json='{
      "Type": "sing",
      "Log": {
        "Level": "info",
        "Timestamp": true
      },
      "NTP": {
        "Enable": false,
        "Server": "time.apple.com",
        "ServerPort": 0
      }
    }'
            ;;
        xray)
            core_json='{
      "Type": "xray"
    }'
            ;;
        hysteria2)
            core_json='{
      "Type": "hysteria2"
    }'
            ;;
    esac

    cat >"${cfg}" <<EOF
{
  "Environment": "production",
  "Log": {
    "Level": "info",
    "Output": ""
  },
  "Cores": [
    ${core_json}
  ],
  "Nodes": [
    {
      "Core": "$(json_escape "${core_type}")",
      "ApiHost": "$(json_escape "${api_host}")",
      "Transport": "$(json_escape "${transport}")",
      "GRPCHost": "$(json_escape "${grpc_host}")",
      "GRPCUseTLS": ${grpc_use_tls},
      "GRPCServerName": "$(json_escape "${grpc_server_name}")",
      "GRPCKeepalive": ${grpc_keepalive},
      "AgentControlEnabled": ${agent_control_enabled},
      "AgentControlAllowInsecure": ${agent_control_allow_insecure},
      "MaintenanceEnvironment": "production",
      "PluginSupervisorEnabled": ${plugin_supervisor_enabled},
      "PluginRoot": "${DEFAULT_PLUGIN_ROOT}",
      "PluginSocketDir": "${DEFAULT_PLUGIN_SOCKET_DIR}",
      "PluginOfficialPublicKey": "${OFFICIAL_PLUGIN_PUBLIC_KEY}",
      "ApiKey": "$(json_escape "${api_key}")",
      "NodeID": ${node_id},
      "NodeType": "$(json_escape "${node_type}")",
      "Timeout": ${timeout},
      "EnableSign": true,
      "EncryptCredential": true,
      "CredentialFile": "/var/lib/anixops-agent/credential.json.enc",
      "SyncConfig": {
        "EnableWebSocket": true,
        "WSEndpoint": "/api/v2/agent/ws",
        "WSEndpointFallbacks": ["/api/v2/node/ws"],
        "ReconnectInterval": 5,
        "MaxReconnectTries": 0,
        "PingInterval": 30,
        "PongTimeout": 10,
        "AckTimeout": 5,
        "AckRetries": 2,
        "BufferSize": 100,
        "EnableFallback": true,
        "FallbackInterval": 60
      },
      "ListenIP": "$(json_escape "${listen_ip}")",
      "SendIP": "$(json_escape "${send_ip}")",
      "DeviceOnlineMinTraffic": 200,
      "MinReportTraffic": 0,
      "CertConfig": {
        "CertMode": "$(json_escape "${cert_mode}")"
      }
    }
  ]
}
EOF

    chmod 600 "${cfg}" || true
    if is_installed && ! "${BIN_PATH}" validate-config -c "${cfg}"; then
        error "配置校验失败；请修正 ${cfg} 后再次运行 validate-config，服务不会自动启动"
        return 1
    fi
    info "配置初始化完成: ${cfg}"
    info "启动前运行: ${BIN_PATH} validate-config -c ${cfg}"
    info "默认仍使用: ${BIN_PATH} server -c ${cfg}"
}

restore_legacy_service_definition() {
    local backup=""

    if is_alpine; then
        if [[ -L "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}" && "$(readlink -f "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}")" == "${OPENRC_INIT_DIR}/${SERVICE_NAME}" ]]; then
            uninstall_remove "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}"
        fi
        if [[ -d "${MIGRATION_DIR}" ]]; then
            backup="$(find "${MIGRATION_DIR}" -maxdepth 1 -type f -name "${LEGACY_SERVICE_NAME}.openrc.*.bak" -print 2>/dev/null | sort | tail -n 1 || true)"
        fi
        if [[ -n "${backup}" && ! -e "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}" ]]; then
            install -m 0755 "${backup}" "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}"
            info "已恢复旧 OpenRC 服务定义（未启动）：${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}"
        fi
        return
    fi

    if [[ -L "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service" && "$(readlink -f "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service")" == "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" ]]; then
        uninstall_remove "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service"
    fi
    if [[ -d "${MIGRATION_DIR}" ]]; then
        backup="$(find "${MIGRATION_DIR}" -maxdepth 1 -type f -name "${LEGACY_SERVICE_NAME}.service.*.bak" -print 2>/dev/null | sort | tail -n 1 || true)"
    fi
    if [[ -n "${backup}" && ! -e "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service" ]]; then
        install -m 0644 "${backup}" "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service"
        info "已恢复旧 systemd 服务定义（未启动）：${LEGACY_SERVICE_NAME}.service"
    fi
    systemctl daemon-reload || true
}

# What uninstall removed and what it left, for the report at its end.
UNINSTALL_REMOVED=()
UNINSTALL_KEPT=()
UNINSTALL_FAILED="false"

uninstall_remove() {
    local target="$1"

    if [[ -z "${target}" || "${target}" == "/" ]]; then
        return 0
    fi
    if [[ ! -e "${target}" && ! -L "${target}" ]]; then
        return 0
    fi
    if rm -rf -- "${target}"; then
        UNINSTALL_REMOVED+=("${target}")
    else
        UNINSTALL_FAILED="true"
        error "无法删除：${target}"
    fi
}

# uninstall_remove_empty_dir removes a directory only when nothing is in it.
uninstall_remove_empty_dir() {
    local target="$1"

    if [[ -d "${target}" && ! -L "${target}" ]] && rmdir -- "${target}" 2>/dev/null; then
        UNINSTALL_REMOVED+=("${target}")
    fi
}

uninstall_keep() {
    UNINSTALL_KEPT+=("$1")
}

account_exists() {
    id "$1" >/dev/null 2>&1
}

# uninstall_install_dir removes the program directory. data/ holds the node's
# credentials (credential.json[.enc], including the ones migrated from V2bX),
# so without --purge everything else in the directory goes and data/ stays.
uninstall_install_dir() {
    local purge="$1"
    local data_dir="${INSTALL_DIR}/data"
    local entry

    if [[ "${purge}" == "true" || ! -d "${INSTALL_DIR}" || -L "${INSTALL_DIR}" ]]; then
        uninstall_remove "${INSTALL_DIR}"
        return 0
    fi

    while IFS= read -r -d '' entry; do
        uninstall_remove "${entry}"
    done < <(find "${INSTALL_DIR}" -mindepth 1 -maxdepth 1 ! -name data -print0)
    uninstall_remove_empty_dir "${INSTALL_DIR}"
    if [[ -e "${data_dir}" || -L "${data_dir}" ]]; then
        uninstall_keep "${data_dir}：节点凭证（credential.json / credential.json.enc，含从 V2bX 迁移的凭证），--purge 才会删除"
    fi
}

# uninstall_agent removes what scripts/install.sh wrote. It keeps the
# configuration, data/ (credentials), the node's identity and state, and
# gost's state directory unless --purge; it never removes the users or the
# kernel objects the forward drivers create. It writes no polkit rule (only
# AnixOps Control's installer does), so it touches none.
uninstall_agent() {
    local purge_config="false"
    local forwarding="false"
    local gost_unit="${SYSTEMD_UNIT_DIR}/${GOST_SERVICE_NAME}.service"
    local gost_unit_present="false"
    local relay_unit="${SYSTEMD_UNIT_DIR}/${RELAY_SERVICE_NAME}.service"
    local relay_unit_present="false"
    local reset_units=("${SERVICE_NAME}.service")
    local alias_path item

    UNINSTALL_REMOVED=()
    UNINSTALL_KEPT=()
    UNINSTALL_FAILED="false"

    if [[ "${1:-}" == "--purge" ]]; then
        purge_config="true"
    elif [[ -n "${1:-}" ]]; then
        warn "忽略未知参数：$1（仅支持 --purge；未指定 --purge，将保留配置和数据）"
    fi

    if ! is_alpine && [[ -e "${gost_unit}" || -L "${gost_unit}" ]]; then
        gost_unit_present="true"
        reset_units+=("${GOST_SERVICE_NAME}.service")
    fi
    if ! is_alpine && [[ -e "${relay_unit}" || -L "${relay_unit}" ]]; then
        relay_unit_present="true"
        reset_units+=("${RELAY_SERVICE_NAME}.service")
    fi
    if [[ "${gost_unit_present}" == "true" || "${relay_unit_present}" == "true" || -e "${SYSCTL_DROPIN}" || -d "${GOST_DIR}" || -d "${RELAY_DIR}" || -d "${STATE_ROOT}/forward" ]]; then
        forwarding="true"
    fi

    warn "开始卸载 ${PRODUCT_NAME}..."
    svc_stop >/dev/null 2>&1 || true
    svc_disable
    if [[ "${gost_unit_present}" == "true" ]]; then
        # The Agent is stopped first, so that it cannot start gost again.
        systemctl disable --now "${GOST_SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi
    if [[ "${relay_unit_present}" == "true" ]]; then
        systemctl disable --now "${RELAY_SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi
    restore_legacy_service_definition

    if is_alpine; then
        uninstall_remove "${OPENRC_INIT_DIR}/${SERVICE_NAME}"
    else
        uninstall_remove "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service"
        uninstall_remove "${gost_unit}"
        uninstall_remove "${relay_unit}"
        systemctl daemon-reload || true
        systemctl reset-failed "${reset_units[@]}" >/dev/null 2>&1 || true
    fi

    uninstall_install_dir "${purge_config}"
    for alias_path in \
        "${USR_BIN_DIR}/${LEGACY_CMD_NAME}" "${USR_LOCAL_BIN_DIR}/${LEGACY_CMD_NAME}" \
        "${USR_BIN_DIR}/${LEGACY_SERVICE_NAME}" "${USR_LOCAL_BIN_DIR}/${LEGACY_SERVICE_NAME}"; do
        if [[ -L "${alias_path}" && "$(readlink -f "${alias_path}" 2>/dev/null || true)" == "${USR_BIN_DIR}/${CMD_NAME}" ]]; then
            uninstall_remove "${alias_path}"
        fi
    done
    uninstall_remove "${USR_LOCAL_BIN_DIR}/${CMD_NAME}"
    uninstall_remove "${USR_BIN_DIR}/${CMD_NAME}"

    # The pinned gost the release ships (install_files); its directory goes
    # only when nothing else is in it.
    uninstall_remove "${GOST_BINARY}"
    uninstall_remove "${GOST_BINARY}.new"
    # The anixops relay (experimental) goes the same way, and the directory
    # last.
    uninstall_remove "${RELAY_BINARY}"
    uninstall_remove "${RELAY_BINARY}.new"
    uninstall_remove_empty_dir "$(dirname "${GOST_BINARY}")"

    if [[ "${purge_config}" == "true" ]]; then
        uninstall_remove "${CONFIG_DIR}"
        # /etc/anixops goes only when nothing else is in it.
        if [[ "$(basename "$(dirname "${CONFIG_DIR}")")" == "anixops" ]]; then
            uninstall_remove_empty_dir "$(dirname "${CONFIG_DIR}")"
        fi
        uninstall_remove "${STATE_ROOT}"
        uninstall_remove "${GOST_DIR}"
        uninstall_remove "${RELAY_DIR}"
        uninstall_remove "${SYSCTL_DROPIN}"
    else
        if [[ -e "${CONFIG_DIR}" ]]; then
            uninstall_keep "${CONFIG_DIR}：配置，--purge 才会删除"
        fi
        if [[ -e "${STATE_ROOT}" ]]; then
            uninstall_keep "${STATE_ROOT}：节点身份和状态（身份证书、stream、转发状态、插件），--purge 才会删除"
        fi
        if [[ -e "${GOST_DIR}" ]]; then
            uninstall_keep "${GOST_DIR}：gost 状态目录，--purge 才会删除"
        fi
        if [[ -e "${RELAY_DIR}" ]]; then
            uninstall_keep "${RELAY_DIR}：anixops 中继状态目录，--purge 才会删除"
        fi
        if [[ -e "${SYSCTL_DROPIN}" ]]; then
            uninstall_keep "${SYSCTL_DROPIN}：转发 sysctl 配置（到下次重启前转发仍然开启），--purge 才会删除"
        fi
    fi

    # Neither files nor units of the installer: they stay.
    if account_exists "${GOST_USER}"; then
        uninstall_keep "用户 ${GOST_USER}：不再需要时请用 userdel（和 groupdel）手动删除"
    fi
    if account_exists "${RELAY_USER}"; then
        uninstall_keep "用户 ${RELAY_USER}：不再需要时请用 userdel（和 groupdel）手动删除"
    fi
    if [[ "${forwarding}" == "true" ]]; then
        uninstall_keep "nftables 表 inet anixops_fwd 和 tc 根 qdisc af00: 中转发驱动创建的规则：留在内核中，直到重启或手动删除"
    fi
    for item in "${LEGACY_INSTALL_DIR}" "${LEGACY_CONFIG_DIR}"; do
        if [[ -e "${item}" ]]; then
            uninstall_keep "${item}：旧 V2bX 目录，本脚本从不删除"
        fi
    done

    if [[ "${#UNINSTALL_REMOVED[@]}" -eq 0 ]]; then
        echo "已移除: 无 (未发现已安装的 ${PRODUCT_NAME})"
    else
        echo "已移除:"
        for item in "${UNINSTALL_REMOVED[@]}"; do
            echo "  - ${item}"
        done
    fi
    if [[ "${#UNINSTALL_KEPT[@]}" -gt 0 ]]; then
        echo "已保留:"
        for item in "${UNINSTALL_KEPT[@]}"; do
            echo "  - ${item}"
        done
    fi

    if [[ "${UNINSTALL_FAILED}" == "true" ]]; then
        error "卸载未完全完成：上面列出的路径未能删除"
        return 1
    fi
    if [[ "${purge_config}" == "true" ]]; then
        info "已卸载 ${PRODUCT_NAME}，并删除配置、数据和状态（--purge）"
    else
        info "已卸载 ${PRODUCT_NAME}，保留配置、数据和状态；用 --purge 一并删除"
    fi
}

confirm() {
    local prompt="$1"
    local default="${2:-n}"
    local answer

    read -r -p "${prompt} [${default}]: " answer
    answer="${answer:-${default}}"
    [[ "${answer}" == "y" || "${answer}" == "Y" ]]
}

pause_return() {
    echo
    read -r -p "按回车返回主菜单..." _
}

print_service_summary() {
    local rstate estate
    rstate="$(run_state)"
    estate="$(enable_state)"

    echo -e "安装状态: $(install_state_label "${rstate}")"
    echo -e "运行状态: $(state_label "${rstate}")"
    echo -e "开机自启: $(state_label "${estate}")"
}

show_help() {
    cat <<EOF
${PRODUCT_NAME} 管理脚本

无参数运行时进入可视化菜单。

Usage:
  ${CMD_NAME}                     # 进入菜单
  ${CMD_NAME} menu                # 进入菜单
  ${CMD_NAME} initconfig
  ${CMD_NAME} start
  ${CMD_NAME} stop
  ${CMD_NAME} restart
  ${CMD_NAME} status
  ${CMD_NAME} enable
  ${CMD_NAME} disable
  ${CMD_NAME} log
  ${CMD_NAME} config
  ${CMD_NAME} update [version]
  ${CMD_NAME} install [version]
  ${CMD_NAME} uninstall [--purge]
  ${CMD_NAME} version
  ${CMD_NAME} x25519
  ${CMD_NAME} generate

兼容命令: ${LEGACY_SERVICE_NAME}, ${LEGACY_CMD_NAME}
旧目录 ${LEGACY_INSTALL_DIR} 和 ${LEGACY_CONFIG_DIR} 不会被本脚本删除。

uninstall 删除安装器写入的程序目录、服务单元（含 ${GOST_SERVICE_NAME}.service）、
命令入口和 gost 二进制；默认保留配置 ${CONFIG_DIR}、凭证 ${INSTALL_DIR}/data、
节点身份和状态 ${STATE_ROOT}、gost 状态目录 ${GOST_DIR} 和转发 sysctl 配置，
--purge 才会一并删除。用户和转发驱动创建的内核规则不会被删除。
EOF
}

menu_header() {
    clear || true
    echo -e "${cyan}========================================${plain}"
    echo -e "${cyan}          ${PRODUCT_NAME} 管理菜单${plain}"
    echo -e "${cyan}========================================${plain}"
    print_service_summary
    echo
    echo " 1. 启动 ${PRODUCT_NAME}"
    echo " 2. 停止 ${PRODUCT_NAME}"
    echo " 3. 重启 ${PRODUCT_NAME}"
    echo " 4. 查看状态"
    echo " 5. 查看日志"
    echo " 6. 启用开机自启"
    echo " 7. 关闭开机自启"
    echo " 8. 编辑配置文件"
    echo " 9. 更新到最新版本"
    echo "10. 更新到指定版本"
    echo "11. 安装/重装 ${PRODUCT_NAME}"
    echo "12. 卸载 ${PRODUCT_NAME}（保留配置和数据）"
    echo "13. 卸载 ${PRODUCT_NAME}（删除配置、数据和状态）"
    echo "14. 初始化配置向导"
    echo "15. 生成 x25519 密钥"
    echo "16. 生成配置模板"
    echo "17. 查看版本"
    echo " 0. 退出"
    echo
}

run_menu() {
    local choice version
    while true; do
        menu_header
        read -r -p "请输入选项 [0-17]: " choice
        case "${choice}" in
            1) execute_command "start" || true ;;
            2) execute_command "stop" || true ;;
            3) execute_command "restart" || true ;;
            4) execute_command "status" || true ;;
            5) execute_command "log" || true ;;
            6) execute_command "enable" || true ;;
            7) execute_command "disable" || true ;;
            8) execute_command "config" || true ;;
            9) execute_command "update" || true ;;
            10)
                read -r -p "请输入版本号（如 v0.0.1）: " version
                if [[ -z "${version}" ]]; then
                    warn "未输入版本号，已取消"
                else
                    execute_command "update" "${version}" || true
                fi
                ;;
            11) execute_command "install" || true ;;
            12)
                if confirm "确认卸载（保留配置和数据）？" "n"; then
                    execute_command "uninstall" || true
                fi
                ;;
            13)
                if confirm "确认彻底卸载（删除配置、数据和状态）？" "n"; then
                    execute_command "uninstall" "--purge" || true
                fi
                ;;
            14) execute_command "initconfig" || true ;;
            15) execute_command "x25519" || true ;;
            16) execute_command "generate" || true ;;
            17) execute_command "version" || true ;;
            0) exit 0 ;;
            *)
                warn "无效选项：${choice}"
                ;;
        esac
        pause_return
    done
}

execute_command() {
    local cmd="$1"
    shift || true

    case "${cmd}" in
        start)
            if ! is_installed; then
                error "${PRODUCT_NAME} 未安装"
                return 1
            fi
            svc_start
            info "已执行启动"
            ;;
        stop)
            if ! is_installed; then
                error "${PRODUCT_NAME} 未安装"
                return 1
            fi
            svc_stop
            info "已执行停止"
            ;;
        restart)
            if ! is_installed; then
                error "${PRODUCT_NAME} 未安装"
                return 1
            fi
            svc_restart
            info "已执行重启"
            ;;
        status)
            svc_status
            ;;
        enable)
            svc_enable
            info "已启用开机自启"
            ;;
        disable)
            svc_disable
            info "已关闭开机自启"
            ;;
        log)
            show_log
            ;;
        config)
            edit_config
            ;;
        initconfig)
            init_config_wizard
            ;;
        install)
            run_install_script "${1:-}"
            ;;
        update)
            run_install_script "${1:-}"
            ;;
        uninstall)
            uninstall_agent "${1:-}"
            ;;
        version)
            run_bin_subcommand "version" "$@" || run_bin_subcommand "--version" "$@"
            ;;
        x25519|generate)
            run_bin_subcommand "${cmd}" "$@"
            ;;
        menu)
            run_menu
            ;;
        *)
            if ! is_installed; then
                error "${PRODUCT_NAME} 未安装，无法执行原生命令: ${cmd}"
                return 1
            fi
            exec "${BIN_PATH}" "${cmd}" "$@"
            ;;
    esac
}

requires_root() {
    case "$1" in
        menu|start|stop|restart|status|enable|disable|log|config|initconfig|install|update|uninstall)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

main() {
    local cmd="${1:-menu}"
    shift || true

    if [[ "${cmd}" == "help" || "${cmd}" == "-h" || "${cmd}" == "--help" ]]; then
        show_help
        exit 0
    fi

    if requires_root "${cmd}"; then
        need_root
    fi

    if [[ "${cmd}" == "menu" ]]; then
        run_menu
        exit 0
    fi

    execute_command "${cmd}" "$@"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
