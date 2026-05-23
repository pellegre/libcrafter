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
  run_scapy_logged scapy-arp-bytes <<PY
import json
from pathlib import Path
from scapy.all import ARP, Ether, raw
packet = Ether(src='02:00:5e:00:53:01', dst='ff:ff:ff:ff:ff:ff') / ARP(
    op=1,
    hwsrc='02:00:5e:00:53:01',
    psrc='10.200.32.1',
    hwdst='00:00:00:00:00:00',
    pdst='10.200.32.2',
)
Path('$suite_dir/scapy-arp.json').write_text(
    json.dumps({'summary': packet.summary(), 'hex': raw(packet).hex()}, indent=2, sort_keys=True) + '\\n',
    encoding='utf-8',
)
print('scapy_arp_bytes=ok')
PY
  write_suite_json ok "dry-run generated Rust and Scapy ARP artifacts"
  exit 0
fi

require_tool ip
pcap_file="$suite_dir/veth-arp.pcap"
tcpdump_log="$suite_dir/tcpdump.log"
ns_name="lcrafter-arp-$$"
host_if="lcarp$$h"
peer_if="lcarp$$p"
tcpdump_pid=""

cleanup() {
  stop_background "$tcpdump_pid"
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

tcpdump_pid="$(start_tcpdump "$host_if" "arp" "$pcap_file" "$tcpdump_log")"

run_logged rust-arp-ping-live \
  cargo run --quiet --example arp_ping -- --live --iface "$host_if" --src 10.200.32.1 --target 10.200.32.2 --src-mac "$host_mac"

run_scapy_logged scapy-arp-live <<PY
import json
from pathlib import Path
from scapy.all import ARP, Ether, conf, srp1

conf.verb = 0
request = Ether(src='$host_mac', dst='ff:ff:ff:ff:ff:ff') / ARP(
    op=1,
    hwsrc='$host_mac',
    psrc='10.200.32.1',
    hwdst='00:00:00:00:00:00',
    pdst='10.200.32.2',
)
reply = srp1(request, iface='$host_if', timeout=2)
if reply is None:
    raise SystemExit('no ARP reply captured by Scapy')
Path('$suite_dir/scapy-arp.json').write_text(
    json.dumps({'request': request.summary(), 'reply': reply.summary()}, indent=2, sort_keys=True) + '\\n',
    encoding='utf-8',
)
print('scapy_arp=ok')
PY

stop_background "$tcpdump_pid"
tcpdump_pid=""
pcap_has_packets "$pcap_file"
write_suite_json ok "veth ARP validated with Rust, Scapy, and tcpdump"
