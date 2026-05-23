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
  run_scapy_logged scapy-udp-tcp-bytes <<PY
import json
from pathlib import Path
from scapy.all import IP, Raw, TCP, UDP, raw
packets = {
    'udp': IP(src='127.0.0.1', dst='127.0.0.1') / UDP(sport=40100, dport=18181) / Raw(b'libcrafter-live-udp'),
    'tcp': IP(src='127.0.0.1', dst='127.0.0.1') / TCP(sport=40101, dport=18080, flags='S', seq=0x10203040),
}
Path('$suite_dir/scapy-udp-tcp.json').write_text(
    json.dumps({name: {'summary': packet.summary(), 'hex': raw(packet).hex()} for name, packet in packets.items()}, indent=2, sort_keys=True) + '\\n',
    encoding='utf-8',
)
print('scapy_udp_tcp_bytes=ok')
PY
  write_suite_json ok "dry-run generated Rust and Scapy UDP/TCP artifacts"
  exit 0
fi

pcap_file="$suite_dir/udp-tcp-loopback.pcap"
tcpdump_log="$suite_dir/tcpdump.log"
server_log="$suite_dir/python-servers.log"
tcpdump_pid=""
server_pid=""

cleanup() {
  stop_background "$tcpdump_pid"
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

tcpdump_pid="$(start_tcpdump lo "tcp or udp or icmp" "$pcap_file" "$tcpdump_log")"

run_logged rust-tcp-traceroute-live \
  cargo run --quiet --example tcp_traceroute -- --live --iface lo --src 127.0.0.1 --host 127.0.0.1 --port 18080 --max-hops 1
run_logged rust-udp-traceroute-live \
  cargo run --quiet --example udp_traceroute -- --live --iface lo --src 127.0.0.1 --host 127.0.0.1 --base-port 18181 --max-hops 1

run_scapy_logged scapy-udp-tcp-live <<PY
import json
from pathlib import Path
from scapy.all import IP, Raw, TCP, UDP, conf, send, sr1

conf.verb = 0
tcp_probe = IP(dst='127.0.0.1') / TCP(sport=40101, dport=18080, flags='S', seq=0x10203040)
tcp_reply = sr1(tcp_probe, timeout=2)
udp_probe = IP(dst='127.0.0.1') / UDP(sport=40102, dport=18182) / Raw(b'libcrafter-live-udp')
send(udp_probe, verbose=False)
Path('$suite_dir/scapy-udp-tcp.json').write_text(
    json.dumps(
        {
            'tcp_probe': tcp_probe.summary(),
            'tcp_reply': tcp_reply.summary() if tcp_reply is not None else None,
            'udp_probe': udp_probe.summary(),
        },
        indent=2,
        sort_keys=True,
    ) + '\\n',
    encoding='utf-8',
)
if tcp_reply is None:
    raise SystemExit('no TCP loopback response captured by Scapy')
print('scapy_udp_tcp=ok')
PY

stop_background "$tcpdump_pid"
tcpdump_pid=""
pcap_has_packets "$pcap_file"
write_suite_json ok "loopback UDP/TCP validated with Rust, Scapy, and tcpdump"
