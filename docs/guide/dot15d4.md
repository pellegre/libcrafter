# IEEE 802.15.4 And Zigbee Wire Coverage

This page describes the IEEE 802.15.4 and Zigbee support in the `crafter` crate:
what `Dot15d4Radio`, `Dot15d4`, `ZigbeeNwk`, and `ZigbeeAps` build and decode
today, which fields are auto-filled, how the layers map to pcap link types, and
where live dongle work sits outside the offline default path.

`crafter` treats 802.15.4 and Zigbee as packet data. It builds, compiles,
decodes, summarizes, and shows these layers through the same `Packet` surface as
every other protocol: `/` composition, `compile()`, `Packet::decode_from_link`,
`summary()`, `show()`, and `hexdump()`. It is not a Zigbee stack, a router, a key
manager, a commissioning state machine, or a ZCL implementation.

Protocol facts here are source-backed; the
[Standards and registries implemented](#standards-and-registries-implemented)
section below lists the source set, and the evidence manifests under
`.agents/docs/` (`dot15d4-manifest.md`, `dot15d4-codepoints.md`,
`zigbee-manifest.md`, `zigbee-scope.md`, `whad-dot15d4-manifest.md`) record the
specific clauses, tables, and codepoints each value traces to.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| 802.15.4 radio descriptor | Supported | `Dot15d4Radio` models the IEEE 802.15.4 TAP pseudo-header: channel, RSSI, LQI, FCS type, and FCS-valid metadata. |
| 802.15.4 MAC frames | Supported | `Dot15d4` builds and decodes the MAC header: frame type, security/pending/ack-request/PAN-ID-compression flags, sequence number, short or extended destination and source addressing, payload, and the trailing FCS. |
| Zigbee NWK frames | Supported | `ZigbeeNwk` builds and decodes the Network-layer header that rides on the MAC payload: frame control, destination and source 16-bit addresses, radius, sequence number, and payload. |
| Zigbee APS frames | Supported | `ZigbeeAps` builds and decodes the Application Support frame: frame control, delivery mode, destination endpoint, cluster id, profile id, source endpoint, APS counter, and payload. |
| Classic pcap | Supported | `LinkType::Ieee802154` maps to DLT 195 (with FCS) and DLT 230 (no FCS); `LinkType::Ieee802154Tap` maps to DLT 283 (TAP pseudo-header) for read/write through the pcap backend. |
| Live WHAD dongle path | Explicit live surface | The crate keeps examples offline by default. Hardware-backed WHAD sniff and inject are covered by the operations live manual. |
| Out of scope | Deferred | Full Zigbee routing, network/link key management, NWK/APS security and decryption, association and commissioning state machines, the complete ZCL command/attribute set, Touchlink, jamming, and MITM. |

## 802.15.4 / Zigbee Stack

A full Zigbee stack starts with `Dot15d4Radio` (the radio descriptor), then a
`Dot15d4` MAC frame, then the Zigbee `ZigbeeNwk` and `ZigbeeAps` layers riding on
the MAC payload, all composed with `/`:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Dot15d4Radio::on_channel(20)
        / Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001)
        / ZigbeeNwk::data()
            .dest(0x0000)
            .src(0x1234)
            .radius(30)
            .seq(42)
        / ZigbeeAps::data()
            .dest_endpoint(1)
            .cluster(0x0006)
            .profile(0x0104)
            .src_endpoint(1)
            .counter(0xaa)
            .payload(&[0x01, 0x02]);

    let compiled = packet.compile()?;
    println!("{} bytes", compiled.as_bytes().len());
    println!("{}", packet.summary());
    println!("{}", packet.show());

    Ok(())
}
```

`Dot15d4Radio::on_channel(20)` selects an 802.15.4 2.4 GHz channel (valid
channels are 11 through 26). `Dot15d4::data()` selects the Data frame type, and
the `dest_short` / `src_short` builders set the addressing mode, PAN id, and
short (16-bit) address together. `compile()` fills the FCF addressing-mode bits
implied by the addresses present, the PAN-ID-compression bit when both addresses
share a PAN, and the trailing 2-octet FCS computed over the whole MAC frame
(header plus following layers) unless the caller explicitly set an override.

The example uses lab-safe values: PAN `0x1234`, short addresses `0x0001` and
`0x0002`, channel 20, and synthetic payload bytes. Do not copy real device PAN
ids, addresses, captures, or payloads from networks or devices you are not
authorized to inspect into tracked docs or fixtures.

## Radio Descriptor

`Dot15d4Radio` is the link root for 802.15.4 records carried with the TAP
pseudo-header. It carries capture or transmit metadata for the MAC frame that
follows it:

```rust
use crafter::prelude::*;

fn main() {
    let radio = Dot15d4Radio::on_channel(15)
        .rssi(-55)
        .lqi(200)
        .fcs_valid(true);

    let packet = radio / Dot15d4::data();
    println!("{}", packet.summary());
}
```

The radio descriptor is intentionally explicit. `compile()` does not invent RSSI
or LQI when the caller did not set them, and it defaults the FCS-valid flag to
true only when nothing was set. When a caller sets a malformed channel, FCS type,
or FCS-valid state on purpose, the value is preserved for the emitted bytes.

`Dot15d4Radio` serializes only as the TAP (DLT 283) pseudo-header. A bare MAC
frame without a radio descriptor serializes as `LinkType::Ieee802154` (DLT
195/230).

## MAC Frame And Addressing

`Dot15d4` models the 802.15.4 MAC header plus the payload and trailing FCS.
Common constructors are `data`, `beacon`, `ack`, and `command`. Addressing
builders set the address, the PAN id, and the matching addressing mode together:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    // Short (16-bit) addressing.
    let short = Dot15d4::data()
        .seq(7)
        .dest_short(0x1234, 0x0002)
        .src_short(0x1234, 0x0001)
        .payload(&[0xde, 0xad, 0xbe, 0xef]);

    // Extended (64-bit) addressing with PAN ID compression set explicitly.
    let extended = Dot15d4::data()
        .seq(8)
        .pan_id_compression(true)
        .dest_extended(0x1234, 0x0000_0000_0000_0002)
        .src_extended(0x1234, 0x0000_0000_0000_0001);

    println!("{}", short.compile()?.as_bytes().len());
    println!("{}", extended.compile()?.as_bytes().len());
    Ok(())
}
```

`dest_short` / `src_short` use 16-bit addresses; `dest_extended` / `src_extended`
use 64-bit addresses. `compile()` derives the destination and source addressing
mode bits from whichever builder was used and the PAN-ID-compression bit from the
PAN ids present, unless the caller set those flags explicitly. Flags such as
`security`, `frame_pending`, `ack_request`, `pan_id_compression`, and
`frame_version` are honored verbatim, including reserved or inconsistent values
set on purpose.

## Zigbee NWK And APS

`ZigbeeNwk` and `ZigbeeAps` build the Zigbee Network and Application Support
frames that ride on the MAC payload. They stack on `Dot15d4` through the same `/`
composition:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let nwk = ZigbeeNwk::data()
        .dest(0x0000)
        .src(0x1234)
        .radius(30)
        .seq(42)
        .payload(&[0xaa, 0xbb]);

    let aps = ZigbeeAps::data()
        .delivery_mode(0)
        .dest_endpoint(1)
        .cluster(0x0006)
        .profile(0x0104)
        .src_endpoint(1)
        .counter(0xaa)
        .payload(&[0x01, 0x02]);

    let packet = Dot15d4::data()
        .dest_short(0x1234, 0x0000)
        .src_short(0x1234, 0x1234)
        / nwk
        / aps;

    println!("{}", packet.summary());
    Ok(())
}
```

`ZigbeeNwk::data()` selects the NWK Data frame type and auto-fills the NWK
protocol version. `ZigbeeAps::data()` selects the APS Data frame type; APS field
presence (destination endpoint, cluster, profile, source endpoint) follows the
delivery mode and frame type. Only header framing plus the basic
cluster/profile/endpoint fields are modeled; full routing, security, and the ZCL
command set are out of scope.

## Compile, Summary, And Show

`compile()` returns the exact bytes for the whole packet stack. `summary()` is
the compact single-line view, and `show()` is the multi-line packet tree used by
examples and generated tools:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Dot15d4Radio::on_channel(20)
        / Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001);

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", packet.show());
    println!("{}", packet.hexdump()?);
    assert!(!bytes.as_bytes().is_empty());

    Ok(())
}
```

The summary for the MAC layer has the same shape as other link roots:

```text
Dot15d4(Data, seq=7, dst=0x0002, src=0x0001)
```

A `ZigbeeNwk` layer summarizes as `ZigbeeNwk(Data, dst=0x0000, src=0x1234,
r=30)`, and a `ZigbeeAps` layer as `ZigbeeAps(Data, cluster=0x0006,
profile=0x0104, dst_ep=1)`. The exact fields shown depend on which builders the
caller used.

## Decoding Sniffed Frames

Decode 802.15.4 frames with the 802.15.4 link types. Use
`LinkType::Ieee802154Tap` for records carried with the TAP radio pseudo-header,
and `LinkType::Ieee802154` for a bare MAC frame (with or without FCS):

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Dot15d4Radio::on_channel(20)
        / Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001);

    let sniffed = packet.compile()?;

    let decoded = Packet::decode_from_link(LinkType::Ieee802154Tap, sniffed.as_bytes())?;
    let mac = decoded
        .layer::<Dot15d4>()
        .expect("decoded 802.15.4 MAC layer");

    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    println!("decoded MAC layer: {mac:#?}");

    Ok(())
}
```

For a bare MAC frame without the radio descriptor, decode through
`LinkType::Ieee802154`:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let mac = Dot15d4::data()
        .seq(7)
        .dest_short(0x1234, 0x0002)
        .src_short(0x1234, 0x0001);

    let bytes = mac.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ieee802154, bytes.as_bytes())?;

    println!("{}", decoded.summary());
    Ok(())
}
```

When the MAC payload looks like a Zigbee frame, decode dispatches the
`ZigbeeNwk` and `ZigbeeAps` layers automatically; an unknown or non-Zigbee
payload is preserved as a trailing `Raw` layer rather than failing. Header fields
are exposed through `inspection_fields()`. Malformed or truncated input returns
structured `CrafterError` values with context, required byte count, and available
byte count; decode does not panic on short 802.15.4 buffers. A frame whose FCS is
invalid or absent (the no-FCS link type) still yields the MAC header and reports
FCS validity through the radio descriptor rather than being rejected.

## Pcap Usage

Classic pcap support maps 802.15.4 records to the standard link types:

- `LinkType::Ieee802154` is the crate link root for a bare `Dot15d4` MAC frame.
  `PcapLinkType::Ieee802154WithFcs` maps to DLT 195, and
  `PcapLinkType::Ieee802154NoFcs` maps to DLT 230.
- `LinkType::Ieee802154Tap` is the crate link root for `Dot15d4Radio / Dot15d4`.
  `PcapLinkType::Ieee802154Tap` maps to DLT 283.

When the packet root is `Dot15d4Radio`, the pcap recorder infers the TAP link
type; when the root is a bare `Dot15d4`, it infers the with-FCS link type. You
can also pass the link type explicitly:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Dot15d4Radio::on_channel(20)
        / Dot15d4::data()
            .seq(7)
            .dest_short(0x1234, 0x0002)
            .src_short(0x1234, 0x0001);

    let writer = PacketWire::pcap_recorder("target/dot15d4-tap.pcap", LinkType::Ieee802154Tap)
        .open()?
        .writer()?;
    Transmitter::new(writer).send(packet.clone())?;

    let source = PacketWire::pcap_file("target/dot15d4-tap.pcap")
        .open()?
        .source()?;
    let records = Sniffer::new(source).collect_records()?;
    assert_eq!(records[0].packet().summary(), packet.summary());

    Ok(())
}
```

Keep tracked pcap fixtures synthetic and deterministic. Do not add captures from
real devices, public PAN ids or addresses, live host identifiers, credentials, or
sensitive traffic.

## Live Testing Boundary

Offline construction, decode, fixtures, pcap round trips, and oracle validation
are the normal path. 802.15.4 live work has a stricter boundary because RF
injection and sniffing can affect or observe devices outside the developer
machine.

The WHAD-compatible dongle backend is a live wire backend, not a default example
path. Its default-safe behavior is dry-run planning; real serial transmit or
sniff work requires the optional `whad` feature and explicit live opt-in. The
live dongle checklist is covered by
[`docs/operations/dot15d4-whad-live-manual.md`](../operations/dot15d4-whad-live-manual.md).

Examples, docs, fixtures, and tests should use lab-safe 802.15.4 channels (11
through 26), lab-safe PAN ids and short/extended addresses, documentation IP
address space where IP appears, and synthetic payload bytes. Real PAN ids,
device addresses, captures, credentials, provider account data, public IPs, and
live host identifiers do not belong in tracked documentation or fixtures.

## Validation

Focused automated coverage stays offline:

```sh
cargo test -p crafter dot15d4_
cargo test -p crafter --test fixture_suite dot15d4
tools/oracle/run offline --family dot15d4 --profile smoke
tools/oracle/run pcap --family dot15d4 --profile smoke
```

Provider-backed or hardware-backed 802.15.4 work must start with dry-run planning
and remain behind explicit live confirmation. Automated validation must not
require an 802.15.4 dongle, root privileges, provider credentials, or real device
identifiers.

## Standards And Registries Implemented

The 802.15.4 and Zigbee wire facts above trace to reviewed standards and
link-type registries, captured in the evidence manifests under `.agents/docs/`.
The source set that `crafter` implements for this phase:

- **IEEE Std 802.15.4-2020, Clause 7** - MAC frame format, the Frame Control
  field, addressing modes, PAN-ID compression rules, sequence number, and the
  Frame Check Sequence. See `.agents/docs/dot15d4-manifest.md` and
  `.agents/docs/dot15d4-codepoints.md`.
- **Zigbee Specification, Revision 23 (Document 05-3474-23)** - the Network
  (NWK) and Application Support (APS) frame formats, frame control fields,
  addressing, and the cluster/profile/endpoint fields modeled here. See
  `.agents/docs/zigbee-manifest.md` and `.agents/docs/zigbee-scope.md`.
- **tcpdump.org LINKTYPE registry** - `LINKTYPE_IEEE802_15_4_WITHFCS` (DLT 195),
  `LINKTYPE_IEEE802_15_4_NOFCS` (DLT 230), and the IEEE 802.15.4 TAP pseudo-header
  link type `LINKTYPE_IEEE802_15_4_TAP` (DLT 283).
- **WHAD protocol, 802.15.4 domain** - the sniff and send/raw-send messages and
  the received-PDU descriptors used by the live dongle backend. See
  `.agents/docs/whad-dot15d4-manifest.md`.

Deferred / out of scope for this phase: full Zigbee routing and route discovery,
network/link key management, NWK/APS security and decryption, association and
commissioning state machines, the complete ZCL command and attribute set,
Touchlink, jamming, and MITM workflows.
