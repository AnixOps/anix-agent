#!/usr/bin/env bash

set -euo pipefail

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

REPO_OWNER="${REPO_OWNER:-AnixOps}"
REPO_NAME="${REPO_NAME:-anix-agent}"
REPO_BRANCH="${REPO_BRANCH:-dev_new}"

PRODUCT_NAME="AnixOps Agent"
APP_NAME="anix-agent"
SERVICE_NAME="anix-agent"
INSTALL_DIR="/usr/local/anixops-agent"
CONFIG_DIR="/etc/anixops/agent"
DATA_DIR="${INSTALL_DIR}/data"
BIN_PATH="${INSTALL_DIR}/anix-agent"
MANAGE_CMD_NAME="anix-agent"

LEGACY_SERVICE_NAME="V2bX"
LEGACY_INSTALL_DIR="/usr/local/V2bX"
LEGACY_CONFIG_DIR="/etc/V2bX"
LEGACY_DATA_DIR="${LEGACY_INSTALL_DIR}/data"
LEGACY_BIN_PATH="${LEGACY_INSTALL_DIR}/V2bX"
LEGACY_MANAGE_CMD_NAME="v2bx-anixops"
MIGRATION_DIR="${CONFIG_DIR}/migration"
PLUGIN_ROOT="${PLUGIN_ROOT:-/var/lib/anixops/plugins}"
PLUGIN_SOCKET_DIR="${PLUGIN_SOCKET_DIR:-/run/anixops/plugins}"

SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"
OPENRC_INIT_DIR="${OPENRC_INIT_DIR:-/etc/init.d}"

API_BASE="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}"
RELEASE_BASE="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download"
RAW_BASE="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}"
VERSION_FILE="${INSTALL_DIR}/.release-version"

release=""
tmp_dir=""
backup_path=""
legacy_service_backup=""
legacy_service_was_active="false"
legacy_service_was_enabled="false"
legacy_service_captured="false"
migration_detected="false"
command_backup_dir=""
command_backup_manifest=""
rollback_armed="false"
rollback_completed="false"
COMMAND_PATHS=(
    "/usr/bin/${MANAGE_CMD_NAME}"
    "/usr/local/bin/${MANAGE_CMD_NAME}"
    "/usr/bin/${LEGACY_MANAGE_CMD_NAME}"
    "/usr/local/bin/${LEGACY_MANAGE_CMD_NAME}"
    "/usr/bin/${LEGACY_SERVICE_NAME}"
    "/usr/local/bin/${LEGACY_SERVICE_NAME}"
)

cleanup() {
    local exit_code=$?
    trap - EXIT
    if [[ "${rollback_armed}" == "true" && "${rollback_completed}" != "true" ]]; then
        rollback_install_state || true
    fi
    if [[ -n "${tmp_dir}" && -d "${tmp_dir}" ]]; then
        rm -rf "${tmp_dir}"
    fi
    exit "${exit_code}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    trap cleanup EXIT
fi

info() {
    echo -e "${green}$*${plain}" >&2
}

warn() {
    echo -e "${yellow}$*${plain}" >&2
}

error() {
    echo -e "${red}$*${plain}" >&2
}

need_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "错误：必须使用 root 用户运行此脚本"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/alpine-release ]]; then
        release="alpine"
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        release="debian"
        return
    fi

    if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        release="centos"
        return
    fi

    if command -v pacman >/dev/null 2>&1; then
        release="arch"
        return
    fi

    error "未检测到受支持的系统（支持 Debian/Ubuntu/CentOS/Alpine/Arch）"
    exit 1
}

install_base() {
    info "安装基础依赖..."
    case "${release}" in
        centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            else
                yum install -y coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            fi
            ;;
        debian)
            apt-get update -y >/dev/null 2>&1
            apt-get install -y coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
        alpine)
            apk add --no-cache coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
        arch)
            pacman -Sy --noconfirm --needed coreutils curl wget unzip tar ca-certificates >/dev/null 2>&1
            ;;
    esac
}

detect_asset_suffix() {
    local arch
    arch="$(uname -m)"

    case "${arch}" in
        x86_64|amd64)
            echo "linux-64"
            ;;
        aarch64|arm64)
            echo "linux-arm64-v8a"
            ;;
        *)
            return 1
            ;;
    esac
}

fetch_latest_release() {
    local tag
    tag="$(
        curl -fsSL \
            -H "Accept: application/vnd.github+json" \
            -H "User-Agent: ${APP_NAME}-installer" \
            "${API_BASE}/releases/latest" \
            | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' \
            | head -n 1
    )"

    if [[ -z "${tag}" ]]; then
        error "获取 latest release 失败，请先在 ${REPO_OWNER}/${REPO_NAME} 创建 Release，或手动指定版本"
        exit 1
    fi

    echo "${tag}"
}

validate_version() {
    local version="$1"
    if [[ ! "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)(\.[0-9]+)?)?$ ]]; then
        error "版本号格式无效：${version}"
        exit 1
    fi
}

download_release_zip() {
    local version="$1"
    local asset_suffix="$2"
    local asset_name download_url zip_path

    for asset_name in "anix-agent-${asset_suffix}.zip" "V2bX-${asset_suffix}.zip"; do
        download_url="${RELEASE_BASE}/${version}/${asset_name}"
        zip_path="${tmp_dir}/${asset_name}"
        info "下载 ${asset_name} (${version})..."
        if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 600 \
            "${download_url}" -o "${zip_path}"; then
            if [[ "${asset_name}" == V2bX-* ]]; then
                warn "未找到新命名资产，已回退使用兼容资产：${asset_name}"
            fi
            echo "${zip_path}"
            return
        fi
        rm -f "${zip_path}"
    done

    error "下载失败：${version} 未提供 anix-agent 或 V2bX 兼容资产"
    exit 1
}

download_release_digest() {
    local release_version="$1"
    local zip_path="$2"
    local asset_name
    asset_name="$(basename "${zip_path}")"
    local digest_name="${asset_name}.dgst"
    local download_url="${RELEASE_BASE}/${release_version}/${digest_name}"
    local digest_path="${tmp_dir}/${digest_name}"

    info "下载 ${digest_name} (${release_version})..."
    curl -fL --retry 3 --retry-delay 2 --connect-timeout 15 --max-time 120 \
        "${download_url}" -o "${digest_path}"
    echo "${digest_path}"
}

verify_release_zip() {
    local zip_path="$1"
    local digest_path="$2"
    local expected actual

    expected="$(awk -F'= ' '/SHA(2-)?256/ { print $2; exit }' "${digest_path}" | tr -d '\r')"
    if [[ ! "${expected}" =~ ^[A-Fa-f0-9]{64}$ ]]; then
        error "校验文件中缺少 SHA-256：${digest_path}"
        exit 1
    fi
    actual="$(sha256sum "${zip_path}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
        error "发行包 SHA-256 校验失败：${zip_path}"
        exit 1
    fi
    info "SHA-256 校验通过：$(basename "${zip_path}")"
}

backup_existing_binary() {
    local source_path="${BIN_PATH}"
    if [[ ! -x "${source_path}" && -x "${LEGACY_BIN_PATH}" ]]; then
        source_path="${LEGACY_BIN_PATH}"
        migration_detected="true"
    fi
    if [[ ! -x "${source_path}" ]]; then
        return
    fi

    backup_path="${INSTALL_DIR}/backups/anix-agent.$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$(dirname "${backup_path}")"
    cp -a "${source_path}" "${backup_path}"
    chmod 0700 "$(dirname "${backup_path}")" || true
    info "已备份现有二进制：${source_path} -> ${backup_path}"
}

restore_existing_binary() {
    if [[ -z "${backup_path}" || ! -f "${backup_path}" ]]; then
        return
    fi

    warn "启动失败，恢复旧二进制：${backup_path}"
    install -m 0755 "${backup_path}" "${BIN_PATH}"
}

copy_legacy_config() {
    if [[ ! -d "${LEGACY_CONFIG_DIR}" ]]; then
        return
    fi

    migration_detected="true"
    mkdir -p "${CONFIG_DIR}"
    while IFS= read -r -d '' source_path; do
        local relative_path target_path
        relative_path="${source_path#"${LEGACY_CONFIG_DIR}"/}"
        target_path="${CONFIG_DIR}/${relative_path}"

        if [[ -d "${source_path}" && ! -L "${source_path}" ]]; then
            mkdir -p "${target_path}"
        elif [[ ! -e "${target_path}" && ! -L "${target_path}" ]]; then
            mkdir -p "$(dirname "${target_path}")"
            cp -a "${source_path}" "${target_path}"
        fi
    done < <(find "${LEGACY_CONFIG_DIR}" -mindepth 1 -print0)

    info "已迁移旧配置中的缺失文件：${LEGACY_CONFIG_DIR} -> ${CONFIG_DIR}"
    info "旧配置目录保持不变，可用于回滚"
}

copy_legacy_credentials() {
    if [[ ! -d "${LEGACY_DATA_DIR}" ]]; then
        return
    fi

    local credential_name source_path target_path
    for credential_name in credential.json credential.json.enc; do
        source_path="${LEGACY_DATA_DIR}/${credential_name}"
        target_path="${DATA_DIR}/${credential_name}"
        if [[ ! -e "${source_path}" && ! -L "${source_path}" ]]; then
            continue
        fi
        migration_detected="true"
        if [[ -e "${target_path}" || -L "${target_path}" ]]; then
            info "保留现有 Agent 凭证，未覆盖：${target_path}"
            continue
        fi
        mkdir -p "${DATA_DIR}"
        cp -a "${source_path}" "${target_path}"
        info "已迁移旧节点凭证：${source_path} -> ${target_path}"
    done
}

capture_command_entries() {
    command_backup_dir="${tmp_dir}/command-backup"
    command_backup_manifest="${command_backup_dir}/manifest"
    mkdir -p "${command_backup_dir}"
    : >"${command_backup_manifest}"

    local command_path backup_name
    for command_path in "${COMMAND_PATHS[@]}"; do
        backup_name="${command_path#/}"
        backup_name="${backup_name//\//_}"
        if [[ -e "${command_path}" || -L "${command_path}" ]]; then
            cp -a "${command_path}" "${command_backup_dir}/${backup_name}"
            printf 'present|%s|%s\n' "${command_path}" "${backup_name}" >>"${command_backup_manifest}"
        else
            printf 'missing|%s|\n' "${command_path}" >>"${command_backup_manifest}"
        fi
    done
}

restore_command_entries() {
    if [[ -z "${command_backup_manifest}" || ! -f "${command_backup_manifest}" ]]; then
        return
    fi

    local state command_path backup_name
    while IFS='|' read -r state command_path backup_name; do
        rm -f "${command_path}"
        if [[ "${state}" == "present" ]]; then
            mkdir -p "$(dirname "${command_path}")"
            cp -a "${command_backup_dir}/${backup_name}" "${command_path}"
        fi
    done <"${command_backup_manifest}"
    warn "已恢复安装前的命令入口和兼容别名"
}

rollback_install_state() {
    if [[ "${rollback_completed}" == "true" ]]; then
        return
    fi
    rollback_completed="true"

    warn "安装未完成，正在恢复安装前状态"
    restore_existing_binary || true
    restore_command_entries || true
    if [[ "${legacy_service_captured}" == "true" ]]; then
        restore_legacy_service || true
    else
        restart_service || true
    fi
}

capture_legacy_service() {
    mkdir -p "${MIGRATION_DIR}"

    if [[ "${release}" == "alpine" ]]; then
        if [[ ! -e "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}" ]]; then
            return
        fi
        if [[ "$(readlink -f "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}" 2>/dev/null || true)" == "${OPENRC_INIT_DIR}/${SERVICE_NAME}" ]]; then
            return
        fi

        migration_detected="true"
        legacy_service_backup="${MIGRATION_DIR}/${LEGACY_SERVICE_NAME}.openrc.$(date -u +%Y%m%dT%H%M%SZ).bak"
        cp -a "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}" "${legacy_service_backup}"
        legacy_service_captured="true"
        if rc-service "${LEGACY_SERVICE_NAME}" status >/dev/null 2>&1; then
            legacy_service_was_active="true"
        fi
        if rc-update show 2>/dev/null | grep -Eq "^${LEGACY_SERVICE_NAME}[[:space:]]"; then
            legacy_service_was_enabled="true"
        fi
        rc-service "${LEGACY_SERVICE_NAME}" stop >/dev/null 2>&1 || true
        rc-update del "${LEGACY_SERVICE_NAME}" default >/dev/null 2>&1 || true
        return
    fi

    local fragment_path resolved_fragment
    fragment_path="$(systemctl show -p FragmentPath --value "${LEGACY_SERVICE_NAME}.service" 2>/dev/null || true)"
    if [[ -z "${fragment_path}" ]]; then
        for candidate in \
            "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service" \
            "/usr/lib/systemd/system/${LEGACY_SERVICE_NAME}.service" \
            "/lib/systemd/system/${LEGACY_SERVICE_NAME}.service"; do
            if [[ -e "${candidate}" || -L "${candidate}" ]]; then
                fragment_path="${candidate}"
                break
            fi
        done
    fi
    resolved_fragment="$(readlink -f "${fragment_path}" 2>/dev/null || true)"
    if [[ -z "${fragment_path}" || "${resolved_fragment}" == "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" ]]; then
        return
    fi

    migration_detected="true"
    legacy_service_backup="${MIGRATION_DIR}/${LEGACY_SERVICE_NAME}.service.$(date -u +%Y%m%dT%H%M%SZ).bak"
    if [[ -f "${resolved_fragment}" ]]; then
        cp -a "${resolved_fragment}" "${legacy_service_backup}"
        legacy_service_captured="true"
    fi
    if systemctl is-active --quiet "${LEGACY_SERVICE_NAME}.service"; then
        legacy_service_was_active="true"
    fi
    if systemctl is-enabled --quiet "${LEGACY_SERVICE_NAME}.service"; then
        legacy_service_was_enabled="true"
    fi
    systemctl stop "${LEGACY_SERVICE_NAME}.service" >/dev/null 2>&1 || true
    systemctl disable "${LEGACY_SERVICE_NAME}.service" >/dev/null 2>&1 || true
}

restore_legacy_service() {
    if [[ "${legacy_service_captured}" != "true" || ! -f "${legacy_service_backup}" ]]; then
        return 1
    fi

    warn "新服务启动失败，恢复旧 ${LEGACY_SERVICE_NAME} 服务定义和状态"
    if [[ "${release}" == "alpine" ]]; then
        rc-service "${SERVICE_NAME}" stop >/dev/null 2>&1 || true
        rc-update del "${SERVICE_NAME}" default >/dev/null 2>&1 || true
        rm -f "${OPENRC_INIT_DIR}/${SERVICE_NAME}" "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}"
        install -m 0755 "${legacy_service_backup}" "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}"
        if [[ "${legacy_service_was_enabled}" == "true" ]]; then
            rc-update add "${LEGACY_SERVICE_NAME}" default >/dev/null 2>&1 || true
        else
            rc-update del "${LEGACY_SERVICE_NAME}" default >/dev/null 2>&1 || true
        fi
        if [[ "${legacy_service_was_active}" == "true" ]]; then
            rc-service "${LEGACY_SERVICE_NAME}" start
        else
            rc-service "${LEGACY_SERVICE_NAME}" stop >/dev/null 2>&1 || true
        fi
        return
    fi

    systemctl stop "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    systemctl disable "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    rm -f "${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service"
    install -m 0644 "${legacy_service_backup}" "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service"
    systemctl daemon-reload
    if [[ "${legacy_service_was_enabled}" == "true" ]]; then
        systemctl enable "${LEGACY_SERVICE_NAME}.service" >/dev/null 2>&1 || true
    else
        systemctl disable "${LEGACY_SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi
    if [[ "${legacy_service_was_active}" == "true" ]]; then
        systemctl start "${LEGACY_SERVICE_NAME}.service"
    else
        systemctl stop "${LEGACY_SERVICE_NAME}.service" >/dev/null 2>&1 || true
    fi
}

install_compat_link() {
    local target_path="$1"
    local link_path="$2"
    local resolved_target=""
    local backup_name=""

    if [[ -L "${link_path}" ]]; then
        resolved_target="$(readlink -f "${link_path}" 2>/dev/null || true)"
        if [[ "${resolved_target}" == "$(readlink -f "${target_path}" 2>/dev/null || printf '%s' "${target_path}")" ]]; then
            return
        fi
    fi

    if [[ -d "${link_path}" && ! -L "${link_path}" ]]; then
        error "兼容命令路径是目录，无法迁移：${link_path}"
        exit 1
    fi
    if [[ -e "${link_path}" || -L "${link_path}" ]]; then
        mkdir -p "${MIGRATION_DIR}/commands"
        backup_name="${link_path#/}"
        backup_name="${backup_name//\//_}.$(date -u +%Y%m%dT%H%M%SZ).bak"
        cp -a "${link_path}" "${MIGRATION_DIR}/commands/${backup_name}"
        info "已备份旧命令入口：${link_path}"
    fi

    rm -f "${link_path}"
    ln -s "${target_path}" "${link_path}"
}

install_files() {
    local zip_path="$1"
    local install_version="$2"
    local extract_dir="${tmp_dir}/extract"

    mkdir -p "${extract_dir}"
    unzip -oq "${zip_path}" -d "${extract_dir}"

    local extracted_binary="${extract_dir}/anix-agent"
    if [[ ! -f "${extracted_binary}" && -f "${extract_dir}/V2bX" ]]; then
        extracted_binary="${extract_dir}/V2bX"
        warn "压缩包使用旧二进制名 V2bX，将按新路径安装"
    fi
    if [[ ! -f "${extracted_binary}" ]]; then
        error "压缩包中未找到 anix-agent 或 V2bX 可执行文件"
        exit 1
    fi

    mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"

    install -m 0755 "${extracted_binary}" "${BIN_PATH}"

    if [[ -f "${extract_dir}/config.production.json" && ! -f "${CONFIG_DIR}/config.json" ]]; then
        install -m 0600 "${extract_dir}/config.production.json" "${CONFIG_DIR}/config.json"
    fi

    for f in geoip.dat geosite.dat; do
        if [[ -f "${extract_dir}/${f}" ]]; then
            install -m 0644 "${extract_dir}/${f}" "${CONFIG_DIR}/${f}"
        fi
    done

    for f in config.json dns.json route.json custom_outbound.json custom_inbound.json; do
        if [[ -f "${extract_dir}/${f}" && ! -f "${CONFIG_DIR}/${f}" ]]; then
            install -m 0644 "${extract_dir}/${f}" "${CONFIG_DIR}/${f}"
        fi
    done

    printf '%s\n' "${install_version}" > "${VERSION_FILE}"
    chmod 0644 "${VERSION_FILE}"
}

ensure_plugin_layout() {
    install -d -m 0750 "${PLUGIN_ROOT}" "${PLUGIN_SOCKET_DIR}"
}

install_service() {
    if [[ "${release}" == "alpine" ]]; then
        mkdir -p "${OPENRC_INIT_DIR}"
        cat >"${OPENRC_INIT_DIR}/${SERVICE_NAME}" <<EOF
#!/sbin/openrc-run

name="${PRODUCT_NAME}"
description="${PRODUCT_NAME} Service"
command="${BIN_PATH}"
command_args="server -c ${CONFIG_DIR}/config.json"
command_user="root"
pidfile="/run/${SERVICE_NAME}.pid"
command_background="yes"

depend() {
    need net
}
EOF
        chmod +x "${OPENRC_INIT_DIR}/${SERVICE_NAME}"
        rc-update add ${SERVICE_NAME} default >/dev/null 2>&1 || true
        rm -f "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}"
        ln -s "${OPENRC_INIT_DIR}/${SERVICE_NAME}" "${OPENRC_INIT_DIR}/${LEGACY_SERVICE_NAME}"
    else
        mkdir -p "${SYSTEMD_UNIT_DIR}"
        cat >"${SYSTEMD_UNIT_DIR}/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=${PRODUCT_NAME}
After=network.target nss-lookup.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${INSTALL_DIR}/
ExecStart=${BIN_PATH} server -c ${CONFIG_DIR}/config.json
Restart=always
RestartSec=10
LimitNOFILE=512000

[Install]
WantedBy=multi-user.target
EOF
        rm -f "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service"
        ln -s "${SERVICE_NAME}.service" "${SYSTEMD_UNIT_DIR}/${LEGACY_SERVICE_NAME}.service"
        systemctl daemon-reload
        systemctl enable ${SERVICE_NAME} >/dev/null 2>&1 || true
    fi
}

download_manage_script() {
    local install_version="$1"
    local raw_script_url="${RAW_BASE}/${install_version}/scripts/anix-agent.sh"
    local manager_path="${tmp_dir}/anix-agent-manager"

    info "下载管理脚本 (${install_version}) ..."
    curl -fsSL "${raw_script_url}" -o "${manager_path}"
    bash -n "${manager_path}"
    echo "${manager_path}"
}

install_manage_script() {
    local manager_path="$1"

    info "安装管理脚本 /usr/bin/${MANAGE_CMD_NAME} ..."
    install -m 0755 "${manager_path}" "/usr/bin/${MANAGE_CMD_NAME}"

    install_compat_link "/usr/bin/${MANAGE_CMD_NAME}" "/usr/local/bin/${MANAGE_CMD_NAME}"
    install_compat_link "/usr/bin/${MANAGE_CMD_NAME}" "/usr/bin/${LEGACY_MANAGE_CMD_NAME}"
    install_compat_link "/usr/bin/${MANAGE_CMD_NAME}" "/usr/local/bin/${LEGACY_MANAGE_CMD_NAME}"
    install_compat_link "/usr/bin/${MANAGE_CMD_NAME}" "/usr/bin/${LEGACY_SERVICE_NAME}"
    install_compat_link "/usr/bin/${MANAGE_CMD_NAME}" "/usr/local/bin/${LEGACY_SERVICE_NAME}"
}

restart_service() {
    if [[ "${release}" == "alpine" ]]; then
        if ! rc-service ${SERVICE_NAME} restart >/dev/null 2>&1; then
            rc-service ${SERVICE_NAME} start >/dev/null 2>&1 || return 1
        fi
        rc-service ${SERVICE_NAME} status || true
        rc-service ${SERVICE_NAME} status >/dev/null 2>&1
    else
        if ! systemctl restart ${SERVICE_NAME}; then
            systemctl --no-pager --full status ${SERVICE_NAME} || true
            return 1
        fi
        systemctl --no-pager --full status ${SERVICE_NAME} || true
        systemctl is-active --quiet ${SERVICE_NAME}
    fi
}

print_help() {
    cat <<EOF
Usage:
  bash install.sh                # 安装最新版本
  bash install.sh v0.1.0         # 安装指定版本

安装器只下载 GitHub Release 资产，不会克隆仓库或在节点机执行本地构建。
安装时会校验发布包 SHA-256，并保留旧二进制到
${INSTALL_DIR}/backups/ 以便服务启动失败时自动恢复。

默认路径:
  程序目录: ${INSTALL_DIR}
  配置目录: ${CONFIG_DIR}
  插件目录: ${PLUGIN_ROOT}
  插件 Socket: ${PLUGIN_SOCKET_DIR}
  服务名称: ${SERVICE_NAME}.service

检测到 ${LEGACY_CONFIG_DIR}、${LEGACY_INSTALL_DIR} 或 ${LEGACY_SERVICE_NAME}.service
时会自动迁移。旧目录不会删除，${LEGACY_SERVICE_NAME} 和
${LEGACY_MANAGE_CMD_NAME} 命令继续作为兼容别名。

环境变量（可选）:
  REPO_OWNER   默认: AnixOps
  REPO_NAME    默认: anix-agent
  REPO_BRANCH  默认: dev_new
EOF
}

main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        print_help
        exit 0
    fi

    if [[ $# -gt 1 ]]; then
        print_help
        exit 1
    fi

    need_root
    detect_os
    install_base
    command -v sha256sum >/dev/null 2>&1 || {
        error "未找到 sha256sum，无法验证 GitHub Release 资产"
        exit 1
    }

    copy_legacy_config
    copy_legacy_credentials
    if [[ -d "${LEGACY_INSTALL_DIR}" ]]; then
        migration_detected="true"
    fi

    local first_install=false
    if [[ ! -f "${CONFIG_DIR}/config.json" ]]; then
        first_install=true
    fi

    local version="${1:-}"
    if [[ -z "${version}" ]]; then
        version="$(fetch_latest_release)"
    fi
    validate_version "${version}"

    local asset_suffix
    if ! asset_suffix="$(detect_asset_suffix)"; then
        error "不支持的系统架构：$(uname -m)"
        exit 1
    fi

    info "系统: ${release}, 架构资产: ${asset_suffix}, 版本: ${version}"

    tmp_dir="$(mktemp -d)"
    local zip_path digest_path manager_path
    zip_path="$(download_release_zip "${version}" "${asset_suffix}")"
    digest_path="$(download_release_digest "${version}" "${zip_path}")"
    verify_release_zip "${zip_path}" "${digest_path}"
    manager_path="$(download_manage_script "${version}")"

    capture_command_entries
    rollback_armed="true"
    capture_legacy_service
    backup_existing_binary
    install_files "${zip_path}" "${version}"
    ensure_plugin_layout
    install_manage_script "${manager_path}"
    install_service

    if [[ "${migration_detected}" == "true" ]]; then
        info "已完成旧版安装迁移；${LEGACY_CONFIG_DIR} 和 ${LEGACY_INSTALL_DIR} 均未删除"
    fi

    if [[ "${first_install}" == "true" ]]; then
        warn "检测到首次安装，已写入默认配置：${CONFIG_DIR}/config.json"
        warn "请先修改配置后再启动：${MANAGE_CMD_NAME} start"
    else
        info "检测到已有配置，尝试重启服务..."
        if ! restart_service; then
            rollback_install_state
            rollback_armed="false"
            error "新版本启动失败，已恢复安装前的二进制、命令入口和可用服务状态"
            exit 1
        fi
    fi

    rollback_armed="false"

    echo
    info "安装完成。常用命令："
    echo "  ${MANAGE_CMD_NAME} start|stop|restart|status|log"
    echo "  ${MANAGE_CMD_NAME} initconfig"
    echo "  ${MANAGE_CMD_NAME} update [version]"
    echo "  ${MANAGE_CMD_NAME} uninstall [--purge]"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
