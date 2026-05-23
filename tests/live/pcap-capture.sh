#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"
init_suite "pcap-capture"
require_tool cargo
require_tool python3
require_live_lab

offline_pcap="$suite_dir/rust-dump.pcap"
run_logged rust-dump-pcap \
  cargo run --quiet --example dump_pcap -- --out "$offline_pcap" --count 3
run_logged rust-read-pcap \
  cargo run --quiet --example read_pcap -- --in "$offline_pcap"
run_logged rust-simple-sniffer \
  cargo run --quiet --example simple_sniffer -- --pcap "$offline_pcap" --filter tcp --count 2

if is_dry_run; then
  write_suite_json ok "dry-run validated pcap read/write/sniffer examples"
  exit 0
fi

pcap_file="$suite_dir/live-icmp.pcap"
tcpdump_log="$suite_dir/tcpdump.log"
tcpdump_pid="$(start_tcpdump lo "icmp" "$pcap_file" "$tcpdump_log")"
trap 'stop_background "$tcpdump_pid"' EXIT

run_scapy_logged scapy-generate-live-pcap <<PY
from scapy.all import ICMP, IP, Raw, conf, send

conf.verb = 0
packet = IP(dst='127.0.0.1') / ICMP(id=0x5151, seq=9) / Raw(b'libcrafter-live-pcap')
send(packet, verbose=False)
print('sent=icmp-loopback')
PY

stop_background "$tcpdump_pid"
trap - EXIT
pcap_has_packets "$pcap_file"
run_logged rust-read-live-pcap \
  cargo run --quiet --example read_pcap -- --in "$pcap_file"
write_suite_json ok "live tcpdump capture decoded by Rust pcap helpers"
