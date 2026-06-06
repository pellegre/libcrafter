# Packet Wire API Inventory

This inventory records the public packet wire abstraction for generated tools
and future backend work. The guide in [wire.md](wire.md) explains usage; this
document fixes the API boundary and backend responsibilities.

## Boundary

`crafter::wire` is the high-level packet stream API. Every stream item is a
`PacketRecord`, which always contains a `Packet`. Opaque or undecoded bytes stay
inside that packet as `Raw` layers instead of becoming a separate non-packet
event type.

`crafter::pcap` remains the low-level pcap file format, record, timestamp, link
type, reader, writer, and libpcap support module. Application code that wants a
packet stream should usually enter through `PacketWire`, `Sniffer`, or
`Transmitter`; backend implementations can still use `crafter::pcap` directly.

## Public Types

| API | Contract |
| --- | --- |
| `PacketWire` | Opened capability handle for exactly one backend target. It is not a multi-interface manager. |
| `PacketWireBuilder` | Builder for pcap file, pcap recorder, and pcap interface targets. |
| `RawSocketWireBuilder` | Builder for write-only raw socket targets, defaulting to dry-run sends. |
| `PacketWireTarget` | Inspectable target enum for pcap file, pcap recorder, pcap interface, or raw socket interface. |
| `PacketSource` | Object-safe trait with `next_record() -> Result<Option<PacketRecord>>`. |
| `PacketWriter` | Object-safe trait with `write_record(&PacketRecord) -> Result<WriteReport>`. |
| `PacketRecord` | Packet plus `PacketMetadata`; this is the stream item passed between all layers. |
| `PacketMetadata` | Origin, backend, interface/file, pcap lengths/timestamp/bytes, link type, transforms, and medium metadata. |
| `PacketTransform` | Stateful transform from one `PacketRecord` to zero, one, or many `PacketRecord` outputs. |
| `TransformOutput` | Small collection helper for one transform invocation. |
| `Sniffer` | Owns one `PacketSource`, applies inbound transforms, and yields transformed records. |
| `Transmitter` | Owns one `PacketWriter`, applies outbound transforms, and returns `WriteReport` values. |
| `WireError` | Error type for unsupported capabilities, backend failures, packet errors, pcap errors, net errors, I/O, and transform errors. |

## Constructors

`PacketWire` constructors:

| Constructor | Backend target | Capability |
| --- | --- | --- |
| `PacketWire::pcap_file(path)` | Offline pcap input file | source only |
| `PacketWire::pcap_recorder(path, link_type)` | Offline pcap output file | writer only |
| `PacketWire::pcap_interface(interface)` | Live libpcap interface | source, and writer when supported by the backend |
| `PacketWire::raw_socket_interface(interface)` | Raw socket send path | writer only |

`PacketWireBuilder` options apply to pcap targets:

| Method | Responsibility |
| --- | --- |
| `filter`, `clear_filter`, `pcap_filter` | Configure or inspect the libpcap BPF filter used by pcap sources. |
| `timeout`, `no_timeout`, `pcap_timeout` | Configure live pcap read timeout. |
| `snaplen`, `pcap_snaplen` | Configure live pcap snapshot length. |
| `promisc`, `pcap_promisc` | Configure live pcap promiscuous mode. |
| `immediate_mode`, `pcap_immediate_mode` | Configure live pcap immediate mode. |
| `nonblocking`, `nonblock`, `pcap_nonblocking` | Configure live pcap nonblocking reads. |
| `open` | Open one backend target and attach the available source/writer capabilities. |

`RawSocketWireBuilder` options apply to raw socket writer targets:

| Method | Responsibility |
| --- | --- |
| `mode`, `link_layer`, `network_layer` | Select the raw send mode used by `SocketSender`. |
| `dry_run` | Keep output as send planning only. This is the default. |
| `live` | Explicitly opt in to live raw socket transmission. |
| `write_timeout`, `no_write_timeout` | Configure the raw socket write timeout hint. |
| `write_buffer_size` | Configure the raw socket write buffer hint. |
| `open` | Validate the interface and return a write-only `PacketWire`. |

Opened `PacketWire` methods:

| Method | Responsibility |
| --- | --- |
| `target` | Inspect the single backend target. |
| `has_source` | Report whether a source capability is present. |
| `has_writer` | Report whether a writer capability is present. |
| `source` | Consume the wire and return one `PacketSource`. |
| `writer` | Consume the wire and return one `PacketWriter`. |
| `split` | Consume the wire and return both capabilities when the backend has both. |

## Capability Errors

Unsupported directions return `WireError::UnsupportedCapability` with a stable
`capability`, optional backend identifier, and diagnostic `reason`.

Expected capability failures:

| Target | Unsupported request | Reason shape |
| --- | --- | --- |
| `pcap_file` | `writer` or `split` requiring writer | Pcap file inputs are read-only; use `pcap_recorder` for output. |
| `pcap_recorder` | `source` or `split` requiring source | Pcap recorder targets are write-only; use `pcap_file` for input. |
| `raw_socket_interface` | `source` or `split` requiring source | Raw socket targets are write-only; use `pcap_interface` for capture. |
| `pcap_interface` | `source`, `writer`, or `split` after backend open omits that capability | No matching packet source or writer was opened for this wire. |

Other `WireError` variants keep failures inspectable:

| Variant | Use |
| --- | --- |
| `Backend` | Backend-specific setup or operation failures before another error domain applies. |
| `Packet` | Packet compile or decode errors. |
| `Pcap` | Pcap read, write, filter, or capture errors. |
| `Net` | Network interface, routing, raw send, or send/receive errors. |
| `Io` | File, stream, socket, or thread I/O errors. |
| `Transform` | Packet transform failures with transform name and reason. |

## Backend Responsibilities

| Backend | Responsibility |
| --- | --- |
| Offline pcap source | Read pcap records, apply optional BPF filtering, decode records into `PacketRecord`, and preserve pcap timestamp, lengths, captured bytes, and link metadata. |
| Pcap recorder | Compile packet records, validate compatible link metadata when present, write pcap records, and return `WriteReport`. |
| Live pcap source | Capture from one authorized interface through libpcap, apply configured timeout/snaplen/promisc/immediate/nonblocking/filter options, and attach interface metadata. |
| Live pcap writer | Write packet records through the libpcap interface path when supported, with explicit link type validation. |
| Raw socket writer | Wrap `SocketSender`, preserve dry-run-by-default behavior, enforce send-mode validation, and surface live-send failures through `WireError::Net`. |
| Memory source/writer | Provide deterministic packet stream fixtures for tests and generated examples. |

Future Bluetooth, SDR, or provider-backed interfaces should implement
`PacketSource`, `PacketWriter`, or both, attach backend-specific metadata to
`PacketRecord`, and use `WireError::UnsupportedCapability` for unsupported
directions.

## Transform Pipeline

`PacketTransform` is the state-machine extension point. It receives one
`PacketRecord` and emits zero, one, or many `PacketRecord` values. `Sniffer`
uses this contract inbound; `Transmitter` uses it outbound. Transforms may
buffer state across calls, drop records that are not ready, duplicate records,
annotate metadata, decrypt payloads, reassemble fragments, or decode higher
layers while preserving packet-shaped output.

Current helper transforms include pass-through, drop-all, duplicate, trace
append, and Dot11 metadata annotation. WPA decryption is not implemented. It
belongs as a future inbound `PacketTransform` that accepts SSID/passphrase
configuration, observes beacons and EAPOL handshakes, keeps per-network key
state, and emits decrypted Ethernet/IP packet records with metadata identifying
the source network.

## Concurrency Model

Open one `PacketWire` per interface or backend. The crate does not provide a
multi-wire builder. Applications that need Wi-Fi plus Bluetooth, multiple Wi-Fi
adapters, or simultaneous capture and transmit should run separate `Sniffer`
and `Transmitter` instances in their own threads, tasks, or channels.
