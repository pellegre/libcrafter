#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"
init_suite "loopback-icmp"
require_tool cargo
require_tool python3
require_live_lab

if is_dry_run; then
  run_logged rust-network-ping-dry-run \
    cargo run --quiet --example network_ping -- --iface dry-run0 --src 127.0.0.1 --dst 127.0.0.1
  run_scapy_logged scapy-icmp-bytes <<PY
from pathlib import Path
from scapy.all import ICMP, IP, Raw, raw
out = Path('$suite_dir/scapy-icmp.hex')
packet = IP(src='127.0.0.1', dst='127.0.0.1') / ICMP(id=0x4321, seq=7) / Raw(b'libcrafter-live-icmp')
out.write_text(raw(packet).hex() + '\\n', encoding='utf-8')
print(f'wrote={out}')
PY
  write_suite_json ok "dry-run generated Rust and Scapy ICMP artifacts"
  exit 0
fi

pcap_file="$suite_dir/icmp-loopback.pcap"
tcpdump_log="$suite_dir/tcpdump.log"
tcpdump_pid="$(start_tcpdump lo "icmp" "$pcap_file" "$tcpdump_log")"
trap 'stop_background "$tcpdump_pid"' EXIT

run_logged rust-network-ping-live \
  cargo run --quiet --example network_ping -- --live --iface lo --src 127.0.0.1 --dst 127.0.0.1

run_scapy_logged scapy-icmp-live <<PY
import json
from pathlib import Path
from scapy.all import ICMP, IP, Raw, conf, sr1, wrpcap

conf.verb = 0
packet = IP(src='127.0.0.1', dst='127.0.0.1') / ICMP(id=0x4321, seq=7) / Raw(b'libcrafter-live-icmp')
reply = sr1(packet, timeout=2)
if reply is None:
    raise SystemExit('no ICMP reply captured by Scapy')
wrpcap('$suite_dir/scapy-icmp.pcap', [packet, reply])
Path('$suite_dir/scapy-icmp.json').write_text(
    json.dumps({'sent': packet.summary(), 'reply': reply.summary()}, indent=2, sort_keys=True) + '\\n',
    encoding='utf-8',
)
print('scapy_icmp=ok')
PY

stop_background "$tcpdump_pid"
trap - EXIT
pcap_has_packets "$pcap_file"
write_suite_json ok "loopback ICMP validated with Rust, Scapy, and tcpdump"
