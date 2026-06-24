#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

MQTT_BIND_IPV4="${MQTT_BIND_IPV4:-192.0.2.20}"
MQTT_PORT="${MQTT_PORT:-1883}"
MOSQUITTO_CONF="${MOSQUITTO_CONF:-/etc/mosquitto/mosquitto.conf}"
MOSQUITTO_TEMPLATE="${MOSQUITTO_TEMPLATE:-${SCRIPT_DIR}/mosquitto.conf.template}"

die() {
    printf 'provision-broker: %s\n' "$*" >&2
    exit 1
}

require_value() {
    local name="$1"
    local value="$2"

    [[ -n "$value" ]] || die "$name must not be empty"
    [[ "$value" != *$'\n'* ]] || die "$name must not contain newlines"
}

require_integer() {
    local name="$1"
    local value="$2"

    [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an integer"
}

require_value MQTT_BIND_IPV4 "$MQTT_BIND_IPV4"
require_value MQTT_PORT "$MQTT_PORT"
require_value MOSQUITTO_CONF "$MOSQUITTO_CONF"
require_value MOSQUITTO_TEMPLATE "$MOSQUITTO_TEMPLATE"
require_integer MQTT_PORT "$MQTT_PORT"
[[ -f "$MOSQUITTO_TEMPLATE" ]] || die "template not found: $MOSQUITTO_TEMPLATE"

SUDO=()
if [[ "${EUID}" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "run as root or install sudo"
    SUDO=(sudo)
fi

as_root() {
    "${SUDO[@]}" "$@"
}

install_mosquitto() {
    if command -v mosquitto >/dev/null 2>&1; then
        return
    fi

    if command -v apt-get >/dev/null 2>&1; then
        as_root env DEBIAN_FRONTEND=noninteractive apt-get update
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y mosquitto
    elif command -v dnf >/dev/null 2>&1; then
        as_root dnf install -y mosquitto
    elif command -v yum >/dev/null 2>&1; then
        as_root yum install -y mosquitto
    elif command -v zypper >/dev/null 2>&1; then
        as_root zypper --non-interactive install mosquitto
    elif command -v pacman >/dev/null 2>&1; then
        as_root pacman -Sy --noconfirm mosquitto
    elif command -v apk >/dev/null 2>&1; then
        as_root apk add --no-cache mosquitto
    else
        die "no supported package manager found for installing mosquitto"
    fi
}

sed_escape() {
    printf '%s' "$1" | sed 's/[&|\\]/\\&/g'
}

render_config() {
    local bind_ipv4 port

    bind_ipv4="$(sed_escape "$MQTT_BIND_IPV4")"
    port="$(sed_escape "$MQTT_PORT")"

    sed \
        -e "s|{{MQTT_BIND_IPV4}}|${bind_ipv4}|g" \
        -e "s|{{MQTT_PORT}}|${port}|g" \
        "$MOSQUITTO_TEMPLATE"
}

write_config() {
    local tmp

    tmp="$(mktemp)"
    render_config >"$tmp"
    as_root install -d -m 0755 "$(dirname -- "$MOSQUITTO_CONF")"
    as_root install -m 0644 "$tmp" "$MOSQUITTO_CONF"
    rm -f "$tmp"
}

restart_mosquitto() {
    if command -v systemctl >/dev/null 2>&1 &&
        systemctl list-unit-files mosquitto.service >/dev/null 2>&1; then
        if as_root systemctl enable mosquitto && as_root systemctl restart mosquitto; then
            return
        fi
    fi

    if command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1; then
        if as_root rc-update add mosquitto default && as_root rc-service mosquitto restart; then
            return
        fi
    fi

    if command -v service >/dev/null 2>&1; then
        if as_root service mosquitto restart; then
            return
        fi
    fi

    die "mosquitto installed and configured, but no supported service manager was found"
}

mosquitto_version() {
    { mosquitto -h 2>&1 || true; } | sed -n '1p'
}

listener_summary() {
    if command -v ss >/dev/null 2>&1; then
        ss -ltn | grep -F "${MQTT_BIND_IPV4}:${MQTT_PORT}" || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -ltn | grep -F "${MQTT_BIND_IPV4}:${MQTT_PORT}" || true
    fi
    return 0
}

install_mosquitto
write_config
restart_mosquitto

version="$(mosquitto_version)"
listener="$(listener_summary)"

cat <<EOF
Configured Mosquitto MQTT broker:
  listen: ${MQTT_BIND_IPV4}:${MQTT_PORT}
  anonymous access: enabled
  version: ${version:-unknown}
  config: ${MOSQUITTO_CONF}
  listener: ${listener:-not inspected}
EOF
