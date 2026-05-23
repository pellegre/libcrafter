#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"
init_suite "loopback-udp-tcp"
require_tool cargo
require_tool python3
require_live_lab

if is_dry_run; then
  run_logged rust-udp-traceroute-dry-run \
    cargo run --quiet --example udp_traceroute -- --iface dry-run0 --src 127.0.0.1 --host 127.0.0.1 --max-hops 1
  run_logged rust-tcp-traceroute-dry-run \
    cargo run --quiet --example tcp_traceroute -- --iface dry-run0 --src 127.0.0.1 --host 127.0.0.1 --port 18080 --max-hops 1
  run_oracle_legacy_scapy_logged scapy-udp-tcp-bytes --case loopback-udp-tcp-bytes
  write_suite_json ok "dry-run generated Rust and Scapy UDP/TCP artifacts"
  exit 0
fi

pcap_file="$suite_dir/udp-tcp-loopback.pcap"
capture_log="$suite_dir/libpcap-capture.log"
server_log="$suite_dir/python-servers.log"
capture_pid=""
server_pid=""

cleanup() {
  stop_background "$capture_pid"
  stop_background "$server_pid"
}
trap cleanup EXIT

python3 -u - <<'PY' >"$server_log" 2>&1 &
import socket
import threading
import time

deadline = time.time() + 20

def udp_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 18182))
    sock.settimeout(0.5)
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        print(f"udp_received={len(data)} from={addr}", flush=True)
        sock.sendto(b"libcrafter-live-udp-reply", addr)
    sock.close()

def tcp_server() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 18080))
    sock.listen(8)
    sock.settimeout(0.5)
    while time.time() < deadline:
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        print(f"tcp_accept={addr}", flush=True)
        conn.close()
    sock.close()

threads = [threading.Thread(target=udp_server), threading.Thread(target=tcp_server)]
for thread in threads:
    thread.daemon = True
    thread.start()
while time.time() < deadline:
    time.sleep(0.25)
PY
server_pid="$!"
sleep 1

capture_pid="$(start_libpcap_capture lo "tcp or udp or icmp" "$pcap_file" "$capture_log")"

run_logged rust-tcp-traceroute-live \
  cargo run --quiet --example tcp_traceroute -- --live --iface lo --src 127.0.0.1 --host 127.0.0.1 --port 18080 --max-hops 1
run_logged rust-udp-traceroute-live \
  cargo run --quiet --example udp_traceroute -- --live --iface lo --src 127.0.0.1 --host 127.0.0.1 --base-port 18181 --max-hops 1

run_oracle_legacy_scapy_logged scapy-udp-tcp-live --case loopback-udp-tcp-live

wait_for_capture "$capture_pid" "$capture_log"
capture_pid=""
pcap_has_packets "$pcap_file"
write_suite_json ok "loopback UDP/TCP validated with Rust, Scapy, and libpcap"
