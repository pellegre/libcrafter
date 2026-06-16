#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

DRIVER_IP="${DRIVER_IP:-192.0.2.10}"
RIP_BIND_IFACE="${RIP_BIND_IFACE:-}"
RIP_NETWORK="${RIP_NETWORK:-192.0.2.0/24}"
RIP_ORIGINATE_PREFIX="${RIP_ORIGINATE_PREFIX:-198.51.100.0/24}"
RIP_AUTH_MODE="${RIP_AUTH_MODE:-none}"
RIP_AUTH_KEY="${RIP_AUTH_KEY:-}"

FRR_CONF="${FRR_CONF:-/etc/frr/frr.conf}"
FRR_DAEMONS="${FRR_DAEMONS:-/etc/frr/daemons}"
FRR_TEMPLATE="${FRR_TEMPLATE:-${SCRIPT_DIR}/ripd.conf.template}"

die() {
    printf 'provision-daemon: %s\n' "$*" >&2
    exit 1
}

require_value() {
    local name="$1"
    local value="$2"

    [[ -n "$value" ]] || die "$name must not be empty"
    [[ "$value" != *$'\n'* ]] || die "$name must not contain newlines"
}

require_value DRIVER_IP "$DRIVER_IP"
require_value RIP_NETWORK "$RIP_NETWORK"
require_value RIP_ORIGINATE_PREFIX "$RIP_ORIGINATE_PREFIX"

case "$RIP_AUTH_MODE" in
none | simple | md5) ;;
*) die "RIP_AUTH_MODE must be one of: none, simple, md5" ;;
esac

if [[ "$RIP_AUTH_MODE" != "none" ]]; then
    require_value RIP_AUTH_KEY "$RIP_AUTH_KEY"
fi

[[ -f "$FRR_TEMPLATE" ]] || die "template not found: $FRR_TEMPLATE"

SUDO=()
if [[ "${EUID}" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "run as root or install sudo"
    SUDO=(sudo)
fi

as_root() {
    "${SUDO[@]}" "$@"
}

install_frr() {
    if command -v vtysh >/dev/null 2>&1; then
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        as_root env DEBIAN_FRONTEND=noninteractive apt-get update
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y frr
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y frr
    elif command -v yum >/dev/null 2>&1; then
        as_root yum install -y frr
    elif command -v zypper >/dev/null 2>&1; then
        as_root zypper --non-interactive install frr
    elif command -v pacman >/dev/null 2>&1; then
        as_root pacman -Sy --noconfirm frr
    elif command -v apk >/dev/null 2>&1; then
        as_root apk add --no-cache frr
    else
        die "no supported package manager found for installing FRR"
    fi
}

enable_daemon_flag() {
    local name="$1"
    local tmp

    tmp="$(mktemp)"
    if [[ -f "$FRR_DAEMONS" ]]; then
        cp "$FRR_DAEMONS" "$tmp"
    fi

    if grep -Eq "^${name}=" "$tmp"; then
        sed -i -E "s/^${name}=.*/${name}=yes/" "$tmp"
    else
        printf '%s=yes\n' "$name" >>"$tmp"
    fi

    as_root install -d -m 0755 "$(dirname -- "$FRR_DAEMONS")"
    as_root install -m 0644 "$tmp" "$FRR_DAEMONS"
    rm -f "$tmp"
}

configure_daemons() {
    enable_daemon_flag zebra
    enable_daemon_flag ripd

    if [[ -f "$FRR_DAEMONS" ]] && ! grep -Eq '^vtysh_enable=' "$FRR_DAEMONS"; then
        printf 'vtysh_enable=yes\n' | as_root tee -a "$FRR_DAEMONS" >/dev/null
    elif [[ -f "$FRR_DAEMONS" ]]; then
        as_root sed -i -E 's/^vtysh_enable=.*/vtysh_enable=yes/' "$FRR_DAEMONS"
    fi
}

sed_escape() {
    printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

render_config() {
    local rip_network rip_origin_prefix interface_line auth_block

    rip_network="$(sed_escape "$RIP_NETWORK")"
    rip_origin_prefix="$(sed_escape "$RIP_ORIGINATE_PREFIX")"

    interface_line=""
    if [[ -n "$RIP_BIND_IFACE" ]]; then
        interface_line=" network $(sed_escape "$RIP_BIND_IFACE")"
    fi

    auth_block=""
    case "$RIP_AUTH_MODE" in
    simple)
        auth_block=" ip rip authentication mode text"$'\n'" ip rip authentication string $(sed_escape "$RIP_AUTH_KEY")"
        ;;
    md5)
        auth_block=" ip rip authentication mode md5"$'\n'" ip rip authentication string $(sed_escape "$RIP_AUTH_KEY")"
        ;;
    esac

    sed \
        -e "s|{{RIP_NETWORK}}|${rip_network}|g" \
        -e "s|{{RIP_ORIGINATE_PREFIX}}|${rip_origin_prefix}|g" \
        -e "s|{{RIP_INTERFACE_LINE}}|${interface_line}|g" \
        -e "s|{{RIP_AUTH_BLOCK}}|${auth_block}|g" \
        "$FRR_TEMPLATE"
}

write_config() {
    local tmp

    tmp="$(mktemp)"
    render_config >"$tmp"
    as_root install -d -m 0755 "$(dirname -- "$FRR_CONF")"
    as_root install -m 0640 "$tmp" "$FRR_CONF"
    rm -f "$tmp"

    if id frr >/dev/null 2>&1 && getent group frr >/dev/null 2>&1; then
        as_root chown frr:frr "$FRR_CONF" "$FRR_DAEMONS"
    fi
}

restart_frr() {
    if command -v systemctl >/dev/null 2>&1 &&
        systemctl list-unit-files frr.service >/dev/null 2>&1; then
        if as_root systemctl enable frr && as_root systemctl restart frr; then
            return
        fi
    fi

    if command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1; then
        if as_root rc-update add frr default && as_root rc-service frr restart; then
            return
        fi
    fi

    if command -v service >/dev/null 2>&1; then
        if as_root service frr restart; then
            return
        fi
    fi

    die "FRR installed and configured, but no supported service manager was found"
}

install_frr
configure_daemons
write_config
restart_frr

cat <<EOF
Configured FRR RIP peer:
  rip network: ${RIP_NETWORK}
  driver source: ${DRIVER_IP}
  advertised IPv4 prefix: ${RIP_ORIGINATE_PREFIX}
  authentication: ${RIP_AUTH_MODE}
  config: ${FRR_CONF}
EOF
