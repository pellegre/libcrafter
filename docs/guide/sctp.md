# SCTP Wire Coverage

This page describes SCTP packet-layer support in the `crafter` crate: native
IPv4/IPv6 SCTP, guarded RFC 6951 UDP encapsulation, the common header,
CRC32c checksum handling, chunks, parameters, error causes, fixtures, and the
safe validation boundary.

`crafter` treats SCTP as a packet primitive. It can build, compile, decode,
round-trip, and inspect SCTP bytes through the existing `Packet` abstraction,
`/` composition, `compile()`, `Packet::decode_from_l3`, `summary()`, and
`show()`. It is not an SCTP association stack, socket API, endpoint service,
scanner, fuzzer, retransmission engine, congestion controller, stream
reassembler, or application payload dispatcher.

Wire facts come from RFC 9260, current IANA SCTP registries, IANA protocol
number `132`, RFC 6951 UDP encapsulation, RFC 9653 zero-checksum context, and
selected extension RFCs recorded in the SCTP source notes under
`.agents/docs/`.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Native SCTP over IPv4/IPv6 | Supported | `compile()` fills IPv4 protocol / IPv6 next-header `132` when unset. |
| RFC 6951 UDP encapsulation | Supported | UDP port `9899` with conservative payload shape checks; unrelated UDP payloads remain `Raw`. |
| Common header | Supported | Source port, destination port, verification tag, CRC32c checksum. |
| Checksum fill | Supported | Unset SCTP checksum is filled over the SCTP packet; explicit checksum values are preserved. |
| Checksum status | Supported | Decode reports valid, invalid, zero-checksum, or not-checked status without dropping the packet. |
| DATA, INIT, INIT ACK, SACK, HEARTBEAT, SHUTDOWN and control chunks | Supported | Typed chunks where implemented, with byte-preserving raw forms for future or unknown codepoints. |
| Parameters and error causes | Supported | TLV envelopes, padding, typed selected parameters/causes, unknown preservation. |
| Padding | Supported | Chunk, parameter, and cause padding is preserved for byte-for-byte round trips. |
| Pcap fixtures | Supported | Synthetic Raw IP fixtures cover native IPv4, native IPv6, and UDP-encapsulated SCTP. |
| Association behavior | Out of scope | No lifecycle, retransmission, congestion, path, stream, socket, AUTH cryptography, or application dispatch state. |

## Offline DATA Construction

The common path is the same as every other `crafter` packet: compose typed
layers, compile, and decode from an explicit entry point.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn main() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 44))
        .dst(Ipv4Addr::new(198, 51, 100, 44))
        / Sctp::data(
            0x0102_0304,
            1,
            1,
            SCTP_PPID_WEBRTC_STRING,
            b"hello-sctp".to_vec(),
        )
        .sport(5_000)
        .dport(5_001)
        .vtag(0x1122_3344);

    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Valid);
    assert_eq!(sctp.chunk_count(), 1);
    println!("{}", decoded.summary());
    Ok(())
}
```

`compile()` fills only fields left unset. The IP protocol value, IPv6
next-header value, SCTP checksum, chunk lengths, and padding are filled when
needed. If a caller sets a field explicitly, the value survives unchanged,
including values that are reserved, unknown, or intentionally malformed.

## INIT Parameters And Chunk Storage

SCTP chunks live inside the `Sctp` layer. Parameter-bearing chunks use the
source-backed TLV envelope and can be built from typed parameters or preserved
raw bytes.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn init_with_parameters() -> crafter::Result<Packet> {
    let parameters = [
        SctpParameter::from(SctpIpv4AddressParameter::from_address(Ipv4Addr::new(192, 0, 2, 45))),
        SctpParameter::from(SctpSupportedExtensionsParameter::from_chunk_type_values([
            SCTP_CHUNK_TYPE_AUTH,
            SCTP_CHUNK_TYPE_ASCONF,
            SCTP_CHUNK_TYPE_FORWARD_TSN,
        ])),
        SctpParameter::from(SctpUnknownParameter::new(0x9234, [0xde, 0xad, 0xbe, 0xef])),
    ];
    let mut parameter_bytes = Vec::new();
    encode_parameters(&parameters, &mut parameter_bytes)?;

    let init = SctpInitChunk::from_init_with_parameters(
        0x5566_7745,
        65_535,
        10,
        10,
        0x0102_0345,
        parameter_bytes,
    );

    Ok(Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 45))
        .dst(Ipv4Addr::new(198, 51, 100, 45))
        / Sctp::new().sport(5_010).dport(5_011).vtag(0).chunk(init))
}
```

Unknown, unassigned, reserved, temporary, private, or future chunk and
parameter codepoints are packet data. When the envelope is structurally valid,
decode preserves the numeric codepoint, flags, declared value bytes, and
padding rather than discarding the data or forcing it through a lossy enum.

## Selective ACKs And Control Chunks

`Sctp::sack` constructs a SACK chunk with gap acknowledgement blocks and
duplicate TSNs:

```rust
use crafter::prelude::*;

fn sack_layer() -> crafter::Result<Sctp> {
    Ok(Sctp::sack(
        0x1122_3300,
        0x0003_0000,
        [
            SctpSackGapAckBlock::new(1, 3),
            SctpSackGapAckBlock::new(7, 9),
        ],
        [0x0102_0300, 0x0506_0700],
    )?
    .sport(5_020)
    .dport(5_021)
    .vtag(0x1122_3300))
}
```

Control chunk helpers also cover HEARTBEAT, HEARTBEAT ACK, ABORT, ERROR,
COOKIE ECHO, COOKIE ACK, AUTH packet fields, ASCONF, ASCONF ACK, RE-CONFIG,
FORWARD TSN, I-FORWARD TSN, PAD, SHUTDOWN, SHUTDOWN ACK, and SHUTDOWN
COMPLETE. These are packet fields only. AUTH chunks are represented and
preserved, but the crate does not compute or verify association HMACs.

## Decode And UDP Encapsulation

Native SCTP decode is selected by IP protocol / next-header `132`. UDP
encapsulation follows RFC 6951 on UDP port `9899`, but the registry uses a
shape check before claiming a UDP payload as SCTP.

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn udp_encapsulated_sctp() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 46))
        .dst(Ipv4Addr::new(198, 51, 100, 46))
        / Udp::new().sport(49_152).dport(SCTP_UDP_ENCAPSULATION_PORT)
        / Sctp::data(0x1111_2222, 1, 2, SCTP_PPID_WEBRTC_STRING, b"udp-sctp".to_vec())
            .sport(5_030)
            .dport(5_031)
            .vtag(0x1020_3040);

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;

    assert!(decoded.layer::<Udp>().is_some());
    assert!(decoded.layer::<Sctp>().is_some());
    Ok(())
}
```

If a UDP/9899 payload does not look like a structurally valid SCTP packet, it
stays as `Raw` behind the UDP layer. Turning application decoding off in a
custom `ProtocolRegistry` also keeps the SCTP payload as `Raw`.

## Checksum Behavior

SCTP uses CRC32c over the complete SCTP packet. `compile()` serializes the SCTP
common header with the checksum field set to zero, serializes all chunks and
their padding, computes CRC32c, and writes the checksum when the caller did not
set one.

Explicit checksum overrides are preserved for negative tests:

```rust
use crafter::prelude::*;
use std::net::Ipv4Addr;

fn explicit_bad_checksum() -> crafter::Result<()> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 47))
        .dst(Ipv4Addr::new(198, 51, 100, 47))
        / Sctp::data(0x0102_0347, 1, 1, SCTP_PPID_WEBRTC_STRING, b"bad-crc".to_vec())
            .sport(5_040)
            .dport(5_041)
            .vtag(0x1122_3347)
            .checksum(0x0102_0304);

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
    let sctp = decoded.layer::<Sctp>().expect("SCTP layer");

    assert_eq!(sctp.checksum_value(), Some(0x0102_0304));
    assert_eq!(sctp.checksum_status(), SctpChecksumStatus::Invalid);
    Ok(())
}
```

A zero checksum is reported distinctly. Zero-checksum acceptable parameters
from RFC 9653 are representable as packet data, but they do not turn
`crafter` into an SCTP-over-DTLS endpoint or alternate error-detection engine.

## Malformed Data And Unknown Codepoints

Malformed SCTP buffers return structured errors instead of panicking:

- common headers shorter than 12 octets;
- chunk, parameter, or cause length fields shorter than their fixed headers;
- declared lengths that overrun the enclosing byte sequence;
- truncated alignment padding.

Valid but unsupported data remains inspectable. Use `SctpChunk::unknown`,
`SctpParameter::unknown` / `SctpUnknownParameter`, and
`SctpErrorCause::unknown` when a generated tool needs future, private,
reserved, or deliberately odd codepoints.

## Fixtures And Pcap

The test corpus includes synthetic byte fixtures for INIT, INIT ACK, DATA,
SACK, mixed control chunks, malformed inputs, checksum vectors, padding
round-trips, and unknown codepoints. Pcap fixtures use documentation addresses
and Raw IP link types for:

- native IPv4 SCTP DATA;
- native IPv6 SCTP DATA;
- IPv4 UDP-encapsulated SCTP DATA on port `9899`.

These fixtures are deterministic and offline. They are suitable for generated
tools, CI, and oracle/probe dry-run comparisons without raw socket privileges
or external runner credentials.

## External Execution Boundary

Use the tracked deterministic validation surfaces first:

```sh
tools/oracle/run offline --profile smoke --seed 1 --count 10
tools/oracle/run pcap --profile smoke --seed 1 --count 10
tools/probe/run --profile smoke --seed 1 --count 10 --out target/probe/plan
```

These commands do not select infrastructure or send packets. Any authorized use
of concrete interfaces, peers, radios, or targets is owned by external operator
tooling, which supplies runtime inputs and collects artifacts. libcrafter does
not provision machines, configure responders, manage credentials, or perform
remote cleanup.
