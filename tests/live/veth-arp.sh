#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$script_dir/common.sh"

parse_live_args "$@"
init_suite "veth-arp"
require_tool cargo
require_tool python3
require_live_lab

if is_dry_run; then
  run_logged rust-arp-ping-dry-run \
    cargo run --quiet --example arp_ping -- --iface dry-run0 --src 10.200.32.1 --target 10.200.32.2
  run_oracle_legacy_scapy_logged scapy-arp-bytes --case veth-arp-bytes
  write_suite_json ok "dry-run generated Rust and Scapy ARP artifacts"
  exit 0
fi

require_tool ip
pcap_file="$suite_dir/veth-arp.pcap"
capture_log="$suite_dir/libpcap-capture.log"
ns_name="lcrafter-arp-$$"
host_if="lcarp$$h"
peer_if="lcarp$$p"
capture_pid=""

cleanup() {
  stop_background "$capture_pid"
  ip netns delete "$ns_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ip netns add "$ns_name"
ip link add "$host_if" type veth peer name "$peer_if"
ip link set "$peer_if" netns "$ns_name"
ip addr add 10.200.32.1/24 dev "$host_if"
ip link set "$host_if" up
ip netns exec "$ns_name" ip addr add 10.200.32.2/24 dev "$peer_if"
ip netns exec "$ns_name" ip link set "$peer_if" up
ip netns exec "$ns_name" ip link set lo up
host_mac="$(cat "/sys/class/net/$host_if/address")"

capture_pid="$(start_libpcap_capture "$host_if" "arp" "$pcap_file" "$capture_log")"

run_logged rust-arp-ping-live \
  cargo run --quiet --example arp_ping -- --live --iface "$host_if" --src 10.200.32.1 --target 10.200.32.2 --src-mac "$host_mac"

run_oracle_legacy_scapy_logged scapy-arp-live \
  --case veth-arp-live \
  --host-if "$host_if" \
  --host-mac "$host_mac"

wait_for_capture "$capture_pid" "$capture_log"
capture_pid=""
pcap_has_packets "$pcap_file"
write_suite_json ok "veth ARP validated with Rust, Scapy, and libpcap"
