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
  run_oracle_legacy_scapy_logged scapy-icmp-bytes --case loopback-icmp-bytes
  write_suite_json ok "dry-run generated Rust and Scapy ICMP artifacts"
  exit 0
fi

pcap_file="$suite_dir/icmp-loopback.pcap"
capture_log="$suite_dir/libpcap-capture.log"
capture_pid="$(start_libpcap_capture lo "icmp" "$pcap_file" "$capture_log")"
trap 'stop_background "$capture_pid"' EXIT

run_logged rust-network-ping-live \
  cargo run --quiet --example network_ping -- --live --iface lo --src 127.0.0.1 --dst 127.0.0.1

run_oracle_legacy_scapy_logged scapy-icmp-live --case loopback-icmp-live

wait_for_capture "$capture_pid" "$capture_log"
capture_pid=""
trap - EXIT
pcap_has_packets "$pcap_file"
write_suite_json ok "loopback ICMP validated with Rust, Scapy, and libpcap"
