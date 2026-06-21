#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_ROOT="${IGMP_ARTIFACT_ROOT:-target/probe/target-services/igmp}"
GROUP="${IGMP_GROUP:-233.252.0.42}"
PORT="${IGMP_PORT:-5000}"
BIND_IPV4="${IGMP_BIND_IPV4:-0.0.0.0}"
BIND_IFACE="${IGMP_BIND_IFACE:-}"
DRY_RUN="${IGMP_DRY_RUN:-0}"

case "${1:-}" in
--dry-run)
    DRY_RUN=1
    shift
    ;;
--help)
    cat <<'EOF'
Usage: provision-listener.sh [--dry-run]

Provision a controlled IPv4 multicast listener on a disposable probe target.
Live mode requires LIBCRAFTER_PROBE_LAB_TARGET=1.
EOF
    exit 0
    ;;
"") ;;
*) printf 'provision-listener: unknown argument: %s\n' "$1" >&2; exit 2 ;;
esac

die() {
    printf 'provision-listener: %s\n' "$*" >&2
    exit 1
}

require_value() {
    local name="$1"
    local value="$2"

    [[ -n "$value" ]] || die "$name must not be empty"
    [[ "$value" != *$'\n'* ]] || die "$name must not contain newlines"
    [[ "$value" != *'"'* ]] || die "$name must not contain double quotes"
}

require_integer() {
    local name="$1"
    local value="$2"

    [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an integer"
}

validate_ipv4_multicast() {
    command -v python3 >/dev/null 2>&1 || die "python3 is required"
    python3 - "$GROUP" <<'PY'
import ipaddress
import sys

addr = ipaddress.IPv4Address(sys.argv[1])
if not addr.is_multicast:
    raise SystemExit(f"{addr} is not an IPv4 multicast address")
PY
}

write_plan() {
    local dry_run_json="$1"
    local state="$2"

    install -d -m 0755 "$ARTIFACT_ROOT"
    cat >"$ARTIFACT_ROOT/listener-plan.json" <<EOF
{
  "role": "igmp-listener",
  "lab_only": true,
  "dry_run": ${dry_run_json},
  "state": "${state}",
  "group": "${GROUP}",
  "port": ${PORT},
  "bind_ipv4": "${BIND_IPV4}",
  "bind_iface": "${BIND_IFACE}",
  "artifacts": [
    "${ARTIFACT_ROOT}/listener.stdout.txt",
    "${ARTIFACT_ROOT}/listener.stderr.txt",
    "${ARTIFACT_ROOT}/listener.pid"
  ]
}
EOF
}

require_value IGMP_ARTIFACT_ROOT "$ARTIFACT_ROOT"
require_value IGMP_GROUP "$GROUP"
require_value IGMP_PORT "$PORT"
require_value IGMP_BIND_IPV4 "$BIND_IPV4"
require_integer IGMP_PORT "$PORT"
validate_ipv4_multicast

if [[ "$DRY_RUN" == "1" ]]; then
    write_plan true planned
    printf 'igmp_listener=dry-run\n'
    exit 0
fi

[[ "${LIBCRAFTER_PROBE_LAB_TARGET:-}" == "1" ]] ||
    die "live listener provisioning requires LIBCRAFTER_PROBE_LAB_TARGET=1; use --dry-run locally"

write_plan false starting

listener_py="$ARTIFACT_ROOT/igmp-listener.py"
cat >"$listener_py" <<'PY'
import ipaddress
import socket
import struct
import sys

group = sys.argv[1]
port = int(sys.argv[2])
bind_ipv4 = sys.argv[3]

group_addr = ipaddress.IPv4Address(group)
if not group_addr.is_multicast:
    raise SystemExit(f"{group} is not an IPv4 multicast address")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bind_host = "" if bind_ipv4 == "0.0.0.0" else bind_ipv4
sock.bind((bind_host, port))
mreq = struct.pack("=4s4s", socket.inet_aton(group), socket.inet_aton(bind_ipv4))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

print(f"igmp_listener=ready group={group} port={port} bind_ipv4={bind_ipv4}", flush=True)
while True:
    data, peer = sock.recvfrom(65535)
    print(f"datagram peer={peer[0]}:{peer[1]} length={len(data)}", flush=True)
PY

nohup python3 "$listener_py" "$GROUP" "$PORT" "$BIND_IPV4" \
    >"$ARTIFACT_ROOT/listener.stdout.txt" \
    2>"$ARTIFACT_ROOT/listener.stderr.txt" &
printf '%s\n' "$!" >"$ARTIFACT_ROOT/listener.pid"

cat >"$ARTIFACT_ROOT/cleanup.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [ -f "${ARTIFACT_ROOT}/listener.pid" ]; then
    pid="\$(cat "${ARTIFACT_ROOT}/listener.pid")"
    if kill -0 "\$pid" >/dev/null 2>&1; then
        kill "\$pid" || true
    fi
    rm -f "${ARTIFACT_ROOT}/listener.pid"
fi
EOF
chmod +x "$ARTIFACT_ROOT/cleanup.sh"

printf 'igmp_listener=running\n'

