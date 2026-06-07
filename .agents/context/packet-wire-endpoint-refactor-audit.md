# Packet Wire Endpoint Refactor Audit

This audit records the final shape of the packet wire refactor and endpoint
rename work completed on `feature/packet-wire-abstraction`.

## Public API

The packet capture and transmit abstraction now lives under `crafter::wire`.
The public surface centers on:

- `PacketWire` for opening one packet-capable interface, file, or future
  backend.
- `PacketSource` and `PacketWriter` for receive and transmit halves.
- `PacketRecord` for a `Packet` plus backend/interface metadata.
- `PacketTransform` for stateful stream transforms.
- `Sniffer` for consuming a source and applying transform chains.
- `Transmitter` for applying transmit-side behavior over a writer.

The `pcap` module is now documented as the low-level backend and file-format
module. High-level applications should open a `PacketWire`, pass `wire.source()`
to `Sniffer::new`, and pass `wire.writer()` to `Transmitter::new`.

WPA decryption is still future work. The intended home is a stateful
`PacketTransform` that consumes Dot11 `PacketRecord` values, captures the
required handshake state, and emits decrypted Ethernet/IP records with network
metadata.

## Endpoint Rename

Provider lifecycle management is now owned by `tools/endpoint`. The old
provider-lifecycle wording and legacy environment prefix were removed from
project references. Endpoint-facing documentation, tests, and smokes use the
endpoint naming consistently.

## Validation Summary

The following validation gates passed during the refactor:

- Rust wire suite and focused `wire`, `pcap`, and `net` library tests.
- Endpoint provider dry-runs for Hetzner, QEMU, VirtualBox, and Docker.
- Hetzner, QEMU, VirtualBox, and Docker endpoint provider tests.
- Lab provider matrix, registry, dry-run, create/destroy, and cleanup tests.
- Oracle and probe provider dry-runs.
- Docker live private packet exchange, LAN ICMP, WAN DNS, and live probe smoke.
- Full workspace `cargo test --workspace`.
- Full tool pytest suite for endpoint, lab, oracle, and probe tools.
- Workspace documentation build with `cargo doc --workspace --no-deps`.
- Static release gate with `.agents/scripts/check-crafter-release --static`.

## Live Provider Results

QEMU live WAN coverage ran successfully. Endpoint
`qemu-wan-libcrafter-20260606225455-bb4891` was created, exercised with a
remote command, destroyed, and verified absent from remaining QEMU processes.

Docker live smokes ran successfully for private packet exchange, LAN ICMP, WAN
DNS, and probe cases. Cleanup verified no provider-owned containers or networks
remained.

Hetzner live coverage was skipped because the host did not have usable `hcloud`
credentials. VirtualBox live coverage was skipped because `VBoxManage` or
`LAN_ROUTER` was unavailable.

The cleanup pass found all endpoint manifests destroyed, removed disposable
private keys for destroyed endpoint state, and found no provider containers or
networks left behind. One unrelated running VirtualBox VM named `farm` was left
untouched.
