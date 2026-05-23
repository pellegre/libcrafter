#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"
init_suite "dns-local"
require_tool cargo
require_tool python3
require_live_lab

if is_dry_run; then
  run_logged rust-dns-query-dry-run \
    cargo run --quiet --example dns_query -- --iface dry-run0 --src 127.0.0.1 --server 127.0.0.1 --sport 53010 --name example.test
  run_scapy_logged scapy-dns-bytes <<PY
import json
from pathlib import Path
from scapy.all import DNS, DNSQR, IP, UDP, raw
packet = IP(src='127.0.0.1', dst='127.0.0.1') / UDP(sport=53010, dport=53) / DNS(id=0x1234, rd=1, qd=DNSQR(qname='example.test.', qtype='A'))
Path('$suite_dir/scapy-dns.json').write_text(
    json.dumps({'summary': packet.summary(), 'hex': raw(packet).hex()}, indent=2, sort_keys=True) + '\\n',
    encoding='utf-8',
)
print('scapy_dns_bytes=ok')
PY
  write_suite_json ok "dry-run generated Rust and Scapy DNS artifacts"
  exit 0
fi

pcap_file="$suite_dir/dns-loopback.pcap"
capture_log="$suite_dir/libpcap-capture.log"
server_log="$suite_dir/dns-server.log"
capture_pid=""
server_pid=""

cleanup() {
  stop_background "$capture_pid"
  stop_background "$server_pid"
}
trap cleanup EXIT

python3 -u - <<'PY' >"$server_log" 2>&1 &
import socket
import struct
import time

def build_response(query: bytes) -> bytes:
    transaction_id = query[:2]
    flags = b"\x81\x80"
    qdcount = query[4:6]
    ancount = qdcount
    header = transaction_id + flags + qdcount + ancount + b"\x00\x00\x00\x00"
    question = query[12:]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + bytes([127, 0, 0, 42])
    return header + question + answer

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("127.0.0.1", 53))
sock.settimeout(0.5)
deadline = time.time() + 20
while time.time() < deadline:
    try:
        data, addr = sock.recvfrom(4096)
    except socket.timeout:
        continue
    print(f"dns_query={len(data)} from={addr}", flush=True)
    sock.sendto(build_response(data), addr)
sock.close()
PY
server_pid="$!"
sleep 1

capture_pid="$(start_libpcap_capture lo "udp port 53" "$pcap_file" "$capture_log")"

run_logged rust-dns-query-live \
  cargo run --quiet --example dns_query -- --live --iface lo --src 127.0.0.1 --server 127.0.0.1 --sport 53010 --name example.test

run_scapy_logged scapy-dns-live <<PY
import json
from pathlib import Path
from scapy.all import DNS, DNSQR, IP, UDP, conf, sr1

conf.verb = 0
query = IP(dst='127.0.0.1') / UDP(sport=53011, dport=53) / DNS(id=0x5150, rd=1, qd=DNSQR(qname='example.test.', qtype='A'))
reply = sr1(query, timeout=2)
if reply is None:
    raise SystemExit('no DNS reply captured by Scapy')
Path('$suite_dir/scapy-dns.json').write_text(
    json.dumps({'query': query.summary(), 'reply': reply.summary()}, indent=2, sort_keys=True) + '\\n',
    encoding='utf-8',
)
print('scapy_dns=ok')
PY

wait_for_capture "$capture_pid" "$capture_log"
capture_pid=""
pcap_has_packets "$pcap_file"
write_suite_json ok "local DNS server validated with Rust, Scapy, and libpcap"
