#!/usr/bin/env bash
# Tests the uninstall of the root-layout manager script (scripts/anix-agent.sh)
# against a temporary root with a fake systemctl: nothing outside the
# temporary directory is read as an install, changed or removed.
#
# The manager script keeps its install paths in plain variables; the test
# sources it, points every one of them at the temporary root and refuses (and
# records) any write outside it, any user removal and any kernel-object tool.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manager="${repo_root}/scripts/anix-agent.sh"

test_root="$(cd "$(mktemp -d)" && pwd -P)"
trap 'command rm -rf "${test_root}"' EXIT
violations="${test_root}/violations"
systemctl_log="${test_root}/systemctl.log"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

# --- helpers shared by the cases (they run in subshells that source the manager)

# The variables of the manager script that hold an install path.
path_variables=(
    INSTALL_DIR BIN_PATH CONFIG_DIR MIGRATION_DIR
    LEGACY_INSTALL_DIR LEGACY_CONFIG_DIR
    SYSTEMD_UNIT_DIR OPENRC_INIT_DIR SYSCTL_DROPIN USR_BIN_DIR USR_LOCAL_BIN_DIR
    STATE_ROOT GOST_DIR GOST_BINARY RELAY_DIR RELAY_BINARY
)

# The variables are the manager script's, which the cases source.
# shellcheck disable=SC2034
use_root() {
    local root="$1"
    INSTALL_DIR="${root}/usr/local/anixops-agent"
    BIN_PATH="${INSTALL_DIR}/anix-agent"
    CONFIG_DIR="${root}/etc/anixops/agent"
    MIGRATION_DIR="${CONFIG_DIR}/migration"
    LEGACY_INSTALL_DIR="${root}/usr/local/V2bX"
    LEGACY_CONFIG_DIR="${root}/etc/V2bX"
    SYSTEMD_UNIT_DIR="${root}/etc/systemd/system"
    OPENRC_INIT_DIR="${root}/etc/init.d"
    SYSCTL_DROPIN="${root}/etc/sysctl.d/90-anixops-forward.conf"
    USR_BIN_DIR="${root}/usr/bin"
    USR_LOCAL_BIN_DIR="${root}/usr/local/bin"
    STATE_ROOT="${root}/var/lib/anixops-agent"
    GOST_DIR="${root}/var/lib/anixops-gost"
    GOST_BINARY="${root}/usr/lib/anixops-agent/gost"
    RELAY_DIR="${root}/var/lib/anixops-relay"
    RELAY_BINARY="${root}/usr/lib/anixops-agent/anixops-relay"
    case_root="${root}"
    : >"${systemctl_log}"
    rm -f "${violations}"
    # The manager script defines its own is_alpine; the case chooses.
    # shellcheck disable=SC2317
    is_alpine() { [[ "${alpine}" == "true" ]]; }
    assert_confined
}

# assert_confined stops the case when a path variable points outside the
# temporary root (or the manager script gained one this test does not know).
assert_confined() {
    local name value
    for name in "${path_variables[@]}"; do
        value="${!name}"
        case "${value}" in
            "${test_root}"/*) ;;
            *) fail "${name}=${value} is outside the test root; refusing to run uninstall" ;;
        esac
    done
    # Every path variable of the manager must be confined too, except the
    # plugin defaults only the configuration wizard writes into a file.
    while IFS= read -r name; do
        case " ${path_variables[*]} DEFAULT_PLUGIN_ROOT DEFAULT_PLUGIN_SOCKET_DIR " in
            *" ${name} "*) ;;
            *) fail "the manager script defines ${name}, which this test does not confine" ;;
        esac
    done < <(grep -Eo '^[A-Z_]+_(DIR|ROOT|PATH|BINARY|DROPIN)=' "${manager}" | tr -d '=' | sort -u)
    # And the code of uninstall names no absolute host path of its own.
    if sed -n '/^restore_legacy_service_definition() {/,/^confirm() {/p' "${manager}" |
        grep -v '^[[:space:]]*#' |
        grep -Eq '(^|[^A-Za-z0-9_$}])/(etc|usr|var|opt|run|root|home|lib|bin|sbin)/'; then
        fail "uninstall in the manager script uses a literal host path; use a path variable"
    fi
}

# Writes outside the temporary root are refused and recorded; the removal of
# users and the kernel-object tools must never be called.
under_root() {
    local arg
    for arg in "$@"; do
        case "${arg}" in
            "${test_root}"/*) ;;
            /*)
                echo "outside the test root: $*" >>"${violations}"
                return 1
                ;;
        esac
    done
}
rm() { under_root "$@" && command rm "$@"; }
rmdir() { under_root "$@" && command rmdir "$@"; }
install() { under_root "$@" && command install "$@"; }
mv() { under_root "$@" && command mv "$@"; }
cp() { under_root "$@" && command cp "$@"; }
ln() { under_root "$@" && command ln "$@"; }
userdel() { echo "userdel $*" >>"${violations}"; }
groupdel() { echo "groupdel $*" >>"${violations}"; }
nft() { echo "nft $*" >>"${violations}"; }
tc() { echo "tc $*" >>"${violations}"; }
sysctl() { echo "sysctl $*" >>"${violations}"; }
systemctl() { printf '%s\n' "$*" >>"${systemctl_log}"; }
rc_log="${test_root}/rc.log"
rc-service() { printf 'rc-service %s\n' "$*" >>"${rc_log}"; }
rc-update() { printf 'rc-update %s\n' "$*" >>"${rc_log}"; }
alpine=false
is_alpine() { [[ "${alpine}" == "true" ]]; }
gost_account=true
relay_account=false
id() { [[ "$1" == "anixops-gost" && "${gost_account}" == "true" ]] || [[ "$1" == "anixops-relay" && "${relay_account}" == "true" ]]; }

put() { # put <path> [content]: a file with its parents
    command mkdir -p "$(dirname "$1")"
    printf '%s\n' "${2:-$(basename "$1")}" >"$1"
}
link() { # link <path> <target>
    command mkdir -p "$(dirname "$1")"
    command ln -s "$2" "$1"
}

present() {
    local path
    for path in "$@"; do
        [[ -e "${path}" || -L "${path}" ]] || fail "missing, but must stay: ${path#"${test_root}"}"
    done
}
absent() {
    local path
    for path in "$@"; do
        [[ ! -e "${path}" && ! -L "${path}" ]] || fail "still present, but must be removed: ${path#"${test_root}"}"
    done
}
no_violations() {
    [[ ! -e "${violations}" ]] || fail "forbidden action: $(cat "${violations}")"
}

# populate lays out what scripts/install.sh writes for a root install, with
# ANIXOPS_FORWARD=1 (gost's unit, sysctl drop-in and directories), and a
# V2bX migration; $1 is "plain" to leave the forwarding parts out.
populate() {
    local mode="${1:-forward}"
    put "${SYSTEMD_UNIT_DIR}/anix-agent.service" "[Service]"
    link "${SYSTEMD_UNIT_DIR}/V2bX.service" "anix-agent.service"
    for f in anix-agent .release-version backups/anix-agent.20260101T000000Z data/credential.json.enc data/credential.json; do
        put "${INSTALL_DIR}/${f}"
    done
    for f in config.json geoip.dat migration/commands/note; do
        put "${CONFIG_DIR}/${f}"
    done
    put "${STATE_ROOT}/pki/proxy-1/identity.pem"
    put "${STATE_ROOT}/stream/state.json"
    put "${GOST_BINARY}"
    put "${USR_BIN_DIR}/anix-agent" "$(cat "${manager}")"
    command chmod 0755 "${USR_BIN_DIR}/anix-agent"
    for l in "${USR_LOCAL_BIN_DIR}/anix-agent" "${USR_BIN_DIR}/v2bx-anixops" "${USR_LOCAL_BIN_DIR}/v2bx-anixops" \
        "${USR_BIN_DIR}/V2bX" "${USR_LOCAL_BIN_DIR}/V2bX"; do
        link "${l}" "${USR_BIN_DIR}/anix-agent"
    done
    # Left by the V2bX era: never removed.
    put "${LEGACY_INSTALL_DIR}/V2bX"
    put "${LEGACY_INSTALL_DIR}/data/credential.json"
    put "${LEGACY_CONFIG_DIR}/config.json"
    if [[ "${mode}" == "forward" ]]; then
        put "${SYSTEMD_UNIT_DIR}/anixops-gost.service" "[Service]"
        put "${SYSCTL_DROPIN}" "net.ipv4.ip_forward = 1"
        put "${GOST_DIR}/gost.json"
        put "${GOST_DIR}/tls/link.pem"
        put "${STATE_ROOT}/forward/state.json"
    fi
}

# populate_relay adds what ANIXOPS_RELAY=1 writes (the experimental anixops
# engine): the relay's unit, binary, and its state directory with the link files.
populate_relay() {
    put "${SYSTEMD_UNIT_DIR}/anixops-relay.service" "[Service]"
    put "${RELAY_BINARY}"
    put "${RELAY_DIR}/relay.json"
    put "${RELAY_DIR}/tls/link.pem"
}

# bystanders are files the installer did not write and uninstall must leave.
bystanders() {
    put "${case_root}/etc/anixops/other-product/config"
    put "${case_root}/usr/local/bin/other-tool"
    put "${case_root}/usr/bin/other-tool"
    put "${case_root}/etc/systemd/system/other.service"
    put "${case_root}/etc/systemd/system/anixops-other.service"
    put "${case_root}/usr/lib/anixops-agent/other-file"
    put "${case_root}/var/lib/anixops-other/state"
    put "${case_root}/etc/polkit-1/rules.d/50-anixops-agent.rules" "written by Control's installer"
}
bystander_paths() {
    printf '%s\n' \
        "${case_root}/etc/anixops/other-product/config" "${case_root}/usr/local/bin/other-tool" "${case_root}/usr/bin/other-tool" \
        "${case_root}/etc/systemd/system/other.service" "${case_root}/etc/systemd/system/anixops-other.service" \
        "${case_root}/usr/lib/anixops-agent/other-file" "${case_root}/var/lib/anixops-other/state" \
        "${case_root}/etc/polkit-1/rules.d/50-anixops-agent.rules"
}
assert_bystanders() {
    local path
    while IFS= read -r path; do
        present "${path}"
    done < <(bystander_paths)
}
assert_legacy_dirs() {
    present "${LEGACY_INSTALL_DIR}/V2bX" "${LEGACY_INSTALL_DIR}/data/credential.json" "${LEGACY_CONFIG_DIR}/config.json"
}

# The part of uninstall every case shares: the agent, the program directory,
# the commands and the gost binary go; the V2bX directories stay.
assert_program_removed() {
    absent "${SYSTEMD_UNIT_DIR}/anix-agent.service" "${SYSTEMD_UNIT_DIR}/V2bX.service" \
        "${INSTALL_DIR}/anix-agent" "${INSTALL_DIR}/.release-version" "${INSTALL_DIR}/backups" \
        "${USR_BIN_DIR}/anix-agent" "${USR_LOCAL_BIN_DIR}/anix-agent" \
        "${USR_BIN_DIR}/v2bx-anixops" "${USR_LOCAL_BIN_DIR}/v2bx-anixops" "${USR_BIN_DIR}/V2bX" "${USR_LOCAL_BIN_DIR}/V2bX" \
        "${GOST_BINARY}" "${SYSTEMD_UNIT_DIR}/anixops-gost.service"
    assert_legacy_dirs
}

systemctl_calls() { cat "${systemctl_log}"; }

# --- the cases

# A: `uninstall` without --purge, through the dispatcher the CLI and the menu use.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/a"
    populate forward
    bystanders
    out="$(execute_command uninstall 2>&1)"

    assert_program_removed
    # Kept: the credentials of data/ (the bug was removing them), the
    # configuration with its migration backups, the identity and state, gost's
    # state directory and the sysctl drop-in.
    present "${INSTALL_DIR}/data/credential.json.enc" "${INSTALL_DIR}/data/credential.json"
    present "${CONFIG_DIR}/config.json" "${CONFIG_DIR}/geoip.dat" "${CONFIG_DIR}/migration/commands/note"
    present "${STATE_ROOT}/pki/proxy-1/identity.pem" "${STATE_ROOT}/stream/state.json" "${STATE_ROOT}/forward/state.json"
    present "${GOST_DIR}/gost.json" "${GOST_DIR}/tls/link.pem" "${SYSCTL_DROPIN}"
    [[ "$(cat "${INSTALL_DIR}/data/credential.json.enc")" == "credential.json.enc" ]] || fail "credential changed"
    assert_bystanders
    no_violations
    # The program directory holds only data/ now, and /usr/lib/anixops-agent
    # (not empty) stays.
    [[ "$(find "${INSTALL_DIR}" -mindepth 1 -maxdepth 1 | wc -l)" == "1" ]] || fail "INSTALL_DIR holds more than data/"
    # The Agent stops first, then gost; the units are gone before the reload.
    expected=$'stop anix-agent\ndisable anix-agent\ndisable --now anixops-gost.service\ndaemon-reload\ndaemon-reload\nreset-failed anix-agent.service anixops-gost.service'
    [[ "$(systemctl_calls)" == "${expected}" ]] || fail "systemctl calls: $(systemctl_calls)"
    # The report lists what was removed and what stays.
    for line in "已移除:" "${SYSTEMD_UNIT_DIR}/V2bX.service" "${SYSTEMD_UNIT_DIR}/anixops-gost.service" "${GOST_BINARY}" "已保留:" \
        "${INSTALL_DIR}/data：" "${CONFIG_DIR}：" "${STATE_ROOT}：" "${GOST_DIR}：" "${SYSCTL_DROPIN}：" \
        "用户 anixops-gost" "inet anixops_fwd" "${LEGACY_INSTALL_DIR}：" "${LEGACY_CONFIG_DIR}：" "保留配置、数据和状态"; do
        grep -Fq -- "${line}" <<<"${out}" || fail "report lacks: ${line}"$'\n'"${out}"
    done
    ! grep -Fq "polkit" <<<"${out}" || fail "the manager has no polkit rule to report"
)

# B: --purge removes the configuration, data/, identity and state, gost's state
# directory and the sysctl drop-in, and only those.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/b"
    populate forward
    bystanders
    out="$(execute_command uninstall --purge 2>&1)"

    assert_program_removed
    absent "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_ROOT}" "${GOST_DIR}" "${SYSCTL_DROPIN}"
    # /etc/anixops holds another product, so it stays; so does the directory
    # of the gost binary, which holds another file.
    present "${case_root}/etc/anixops" "${case_root}/usr/lib/anixops-agent"
    assert_bystanders
    no_violations
    for line in "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_ROOT}" "${GOST_DIR}" "${SYSCTL_DROPIN}" "并删除配置、数据和状态"; do
        grep -Fq -- "${line}" <<<"${out}" || fail "report lacks: ${line}"$'\n'"${out}"
    done
    ! grep -Fq "${INSTALL_DIR}/data：" <<<"${out}" || fail "data/ reported as kept after --purge"
)

# C: --purge with nothing else in /etc/anixops and /usr/lib/anixops-agent
# removes those empty directories too.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/c"
    populate forward
    uninstall_agent --purge >/dev/null 2>&1
    absent "${case_root}/etc/anixops" "${case_root}/usr/lib/anixops-agent" "${INSTALL_DIR}" "${STATE_ROOT}" "${GOST_DIR}"
    present "${case_root}/etc" "${case_root}/usr/local" "${LEGACY_CONFIG_DIR}/config.json"
    no_violations
)

# D: a node without forwarding: no gost unit, drop-in or directory. Nothing
# about gost is stopped, kept or reported, and the pinned gost binary the
# installer always writes is still removed.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/d"
    gost_account=false
    populate plain
    out="$(uninstall_agent 2>&1)"
    assert_program_removed
    present "${INSTALL_DIR}/data/credential.json.enc" "${CONFIG_DIR}/config.json" "${STATE_ROOT}/pki/proxy-1/identity.pem"
    ! grep -Fq "anixops-gost" "${systemctl_log}" || fail "gost touched on a node without forwarding: $(cat "${systemctl_log}")"
    ! grep -Fq "inet anixops_fwd" <<<"${out}" || fail "forwarding note on a node without forwarding"
    ! grep -Fq "anixops-gost" <<<"${out}" || fail "gost mentioned on a node without forwarding: ${out}"
    no_violations
)

# E: nothing installed: succeeds, removes nothing, is repeatable.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/e"
    gost_account=false
    command mkdir -p "${case_root}/etc"
    for args in "" "--purge"; do
        # shellcheck disable=SC2086
        out="$(uninstall_agent ${args} 2>&1)" || fail "uninstall of nothing failed: ${out}"
        grep -Fq "已移除: 无" <<<"${out}" || fail "nothing-installed report: ${out}"
        ! grep -Fq "已保留:" <<<"${out}" || fail "kept something on an empty host: ${out}"
    done
    no_violations
)

# F: a second run after a purge, and an argument that is not --purge keeps
# data (an unknown argument is ignored with a warning, as before).
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/f"
    populate forward
    out="$(uninstall_agent --pruge 2>&1)"
    grep -Fq "忽略未知参数" <<<"${out}" || fail "no warning for an unknown argument: ${out}"
    present "${INSTALL_DIR}/data/credential.json.enc" "${CONFIG_DIR}/config.json" "${STATE_ROOT}/pki/proxy-1/identity.pem" "${GOST_DIR}/gost.json"
    assert_program_removed
    # Running the same command again, and then --purge, finishes the job.
    uninstall_agent >/dev/null 2>&1
    present "${INSTALL_DIR}/data/credential.json.enc"
    uninstall_agent --purge >/dev/null 2>&1
    absent "${INSTALL_DIR}" "${CONFIG_DIR}" "${STATE_ROOT}" "${GOST_DIR}" "${SYSCTL_DROPIN}"
    assert_legacy_dirs
    no_violations
)

# G: entries that carry the installer's names but are not its own stay: a
# V2bX / v2bx-anixops command that is not a link to the manager script.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/g"
    populate forward
    command rm -f "${USR_LOCAL_BIN_DIR}/V2bX" "${USR_BIN_DIR}/v2bx-anixops"
    link "${USR_LOCAL_BIN_DIR}/V2bX" "${case_root}/opt/other/V2bX"
    put "${USR_BIN_DIR}/v2bx-anixops" "the old binary"
    uninstall_agent >/dev/null 2>&1
    present "${USR_BIN_DIR}/v2bx-anixops" "${USR_LOCAL_BIN_DIR}/V2bX"
    [[ "$(cat "${USR_BIN_DIR}/v2bx-anixops")" == "the old binary" ]] || fail "a foreign v2bx-anixops was changed"
    absent "${USR_BIN_DIR}/anix-agent" "${USR_LOCAL_BIN_DIR}/anix-agent" "${USR_LOCAL_BIN_DIR}/v2bx-anixops" "${USR_BIN_DIR}/V2bX"
    no_violations
)

# H: the V2bX service definition backed up by the installer is restored, as before.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/h"
    populate plain
    put "${MIGRATION_DIR}/V2bX.service.20260101T000000Z.bak" "legacy-service-definition"
    uninstall_agent >/dev/null 2>&1
    absent "${SYSTEMD_UNIT_DIR}/anix-agent.service"
    [[ -f "${SYSTEMD_UNIT_DIR}/V2bX.service" && ! -L "${SYSTEMD_UNIT_DIR}/V2bX.service" ]] || fail "V2bX.service not restored"
    [[ "$(cat "${SYSTEMD_UNIT_DIR}/V2bX.service")" == "legacy-service-definition" ]] || fail "V2bX.service has other content"
    no_violations
)

# I: OpenRC (Alpine): no systemd unit is touched, the init script and the V2bX
# link are removed, data/ stays.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/i"
    alpine=true
    gost_account=false
    populate plain
    command rm -f "${SYSTEMD_UNIT_DIR}/anix-agent.service" "${SYSTEMD_UNIT_DIR}/V2bX.service"
    put "${OPENRC_INIT_DIR}/anix-agent" "#!/sbin/openrc-run"
    link "${OPENRC_INIT_DIR}/V2bX" "${OPENRC_INIT_DIR}/anix-agent"
    : >"${rc_log}"
    uninstall_agent >/dev/null 2>&1
    absent "${OPENRC_INIT_DIR}/anix-agent" "${OPENRC_INIT_DIR}/V2bX" "${INSTALL_DIR}/anix-agent" "${GOST_BINARY}"
    present "${INSTALL_DIR}/data/credential.json.enc" "${CONFIG_DIR}/config.json"
    [[ ! -s "${systemctl_log}" ]] || fail "systemctl ran on OpenRC: $(cat "${systemctl_log}")"
    grep -Fq "rc-service anix-agent stop" "${rc_log}" || fail "the OpenRC service was not stopped"
    grep -Fq "rc-update del anix-agent default" "${rc_log}" || fail "the OpenRC service was not disabled"
    no_violations
)

# J: a removal that fails does not stop the others, and the command reports
# failure (non-zero) with the path.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/j"
    populate forward
    stuck="${USR_BIN_DIR}/anix-agent"
    rm() {
        if [[ " $* " == *" ${stuck} "* ]]; then
            return 1
        fi
        under_root "$@" && command rm "$@"
    }
    if out="$(uninstall_agent 2>&1)"; then
        fail "uninstall reported success although a removal failed"
    fi
    grep -Fq "无法删除：${stuck}" <<<"${out}" || fail "the failed path is not reported: ${out}"
    present "${stuck}"
    absent "${SYSTEMD_UNIT_DIR}/anix-agent.service" "${SYSTEMD_UNIT_DIR}/anixops-gost.service" "${GOST_BINARY}" "${INSTALL_DIR}/anix-agent"
    present "${INSTALL_DIR}/data/credential.json.enc"
    no_violations
)

# K: the experimental anixops relay (ANIXOPS_RELAY=1): its unit is stopped after
# gost's and removed with its binary, its state directory stays unless --purge,
# and its account is reported, never removed.
(
    # shellcheck source=scripts/anix-agent.sh
    source "${manager}"
    use_root "${test_root}/k"
    relay_account=true
    populate forward
    populate_relay
    bystanders
    out="$(uninstall_agent 2>&1)"
    assert_program_removed
    absent "${SYSTEMD_UNIT_DIR}/anixops-relay.service" "${RELAY_BINARY}"
    present "${RELAY_DIR}/relay.json" "${RELAY_DIR}/tls/link.pem" "${GOST_DIR}/gost.json"
    assert_bystanders
    expected=$'stop anix-agent\ndisable anix-agent\ndisable --now anixops-gost.service\ndisable --now anixops-relay.service\ndaemon-reload\ndaemon-reload\nreset-failed anix-agent.service anixops-gost.service anixops-relay.service'
    [[ "$(systemctl_calls)" == "${expected}" ]] || fail "systemctl calls: $(systemctl_calls)"
    for line in "${SYSTEMD_UNIT_DIR}/anixops-relay.service" "${RELAY_BINARY}" "${RELAY_DIR}：" "用户 anixops-relay"; do
        grep -Fq -- "${line}" <<<"${out}" || fail "report lacks: ${line}"$'\n'"${out}"
    done
    : >"${systemctl_log}"
    uninstall_agent --purge >/dev/null 2>&1
    absent "${RELAY_DIR}" "${GOST_DIR}" "${SYSCTL_DROPIN}"
    no_violations
)

# The manager script still tells itself apart from other programs (the Go
# uninstall reads these markers) and its help documents the command.
head -c 4096 "${manager}" >"${test_root}/manager-head"
grep -Fq 'PRODUCT_NAME="AnixOps Agent"' "${test_root}/manager-head" || fail "manager marker PRODUCT_NAME is not in the first 4096 bytes"
grep -Fq 'CMD_NAME="anix-agent"' "${test_root}/manager-head" || fail "manager marker CMD_NAME is not in the first 4096 bytes"
help_text="$(bash "${manager}" --help)"
grep -Fq 'uninstall [--purge]' <<<"${help_text}" || fail "help does not list uninstall [--purge]"

echo "manager script uninstall test passed"
