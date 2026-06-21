# BLE Advertising Wire Coverage

This page describes the Bluetooth Low Energy advertising support in the
`crafter` crate: what `BleRadio`, `BleLlAdv`, `AdStructure`, and `AdList` build
and decode today, which fields are auto-filled, and where live dongle work sits
outside the offline default path.

`crafter` treats BLE advertising as packet data. It builds, compiles, decodes,
summarizes, and shows BLE layers through the same `Packet` surface as every
other protocol: `/` composition, `compile()`, `Packet::decode_from_link`,
`summary()`, `show()`, and `hexdump()`. It is not a scanner, connection
follower, pairing stack, GATT client, or full Bluetooth stack.

Protocol facts here are source-backed; the
[Standards and registries implemented](#standards-and-registries-implemented)
section below lists the source set.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| BLE radio pseudo-header | Supported | `BleRadio` models the LE Link Layer pcap pseudo-header: channel, access address, PHY, whitening, CRC metadata, RSSI, and CRC-valid metadata. |
| Advertising Link Layer PDUs | Supported | `BleLlAdv` builds and decodes legacy advertising-channel PDUs including `ADV_IND`, `ADV_NONCONN_IND`, `ADV_SCAN_IND`, `SCAN_RSP`, `SCAN_REQ`, `CONNECT_IND`, and `ADV_DIRECT_IND`. |
| GAP Advertising Data | Supported | `AdStructure` and `AdList` cover Flags, local names, service UUIDs, TX power, service data, appearance, manufacturer-specific data, and unknown raw AD types. |
| Classic pcap | Supported | `LinkType::BluetoothLeLl` maps to `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` / DLT 256 for read/write through the pcap backend. |
| Live WHAD dongle path | Explicit live surface | The crate keeps examples offline by default. Hardware-backed WHAD injection and sniffing are covered by the operations live manual added after this guide. |
| Out of scope | Deferred | Bluetooth Classic, BLE data-channel PDUs, connection following, encryption, pairing, L2CAP, ATT, GATT, SMP, and a complete BLE stack. |

## BLE Advertising Stack

A BLE advertising packet stack starts with `BleRadio`, then a `BleLlAdv`
advertising PDU, then zero or more GAP Advertising Data structures inside the
advertising payload:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let ad_list = AdList(vec![
        AdStructure::flags_general_disc(),
        AdStructure::complete_local_name("crafter-ble"),
        AdStructure::manufacturer_data(0xffff, &[0x01, 0x02, 0x03, 0x04]),
    ]);

    let packet = BleRadio::advertising(37)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
            .ad(ad_list);

    let compiled = packet.compile()?;
    println!("{} bytes", compiled.as_bytes().len());
    println!("{}", packet.summary());
    println!("{}", packet.show());

    Ok(())
}
```

`BleRadio::advertising(37)` uses the primary advertising-channel defaults:
access address `0x8e89bed6`, LE 1M PHY, whitening enabled, and advertising
CRCInit. `BleLlAdv::adv_ind()` selects the connectable and scannable undirected
legacy advertising PDU type. `compile()` fills the advertising payload length
and each AD structure length unless the caller explicitly set an override.

The example uses the documentation 48-bit address range `00:00:5e:00:53:*`,
the synthetic local name `crafter-ble`, and synthetic manufacturer data. Do not
copy real device addresses, names, captures, or company payloads from networks
or devices you are not authorized to inspect into tracked docs or fixtures.

## Radio Descriptor

`BleRadio` is the link root for BLE LE Link Layer records with the pcap
pseudo-header. It carries capture or transmit metadata for the PDU that follows
it:

```rust
use crafter::prelude::*;

fn main() {
    let radio = BleRadio::advertising(38)
        .phy(BlePhy::Le1M)
        .access_address(0x8e89bed6)
        .whitening(true)
        .crc_init(0x555555)
        .rssi(-42)
        .crc_valid(true);

    let packet = radio / BleLlAdv::adv_nonconn_ind();
    println!("{}", packet.summary());
}
```

The radio descriptor is intentionally explicit. `compile()` does not invent
RSSI, CRC-valid, or other receive metadata when the caller did not set them.
When a caller sets a malformed access address, whitening state, or CRC
initializer on purpose, the value is preserved for the emitted bytes.

## Advertising PDU And AD Structures

`BleLlAdv` models the advertising-channel Link Layer header plus the addressing
and payload shape for legacy advertising PDUs. Common constructors include
`adv_ind`, `adv_nonconn_ind`, `adv_scan_ind`, `scan_rsp`, `scan_req`,
`connect_ind`, and `adv_direct_ind`.

Address builder methods accept normal display order. The encoder handles the
BLE on-air little-endian address order internally:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let adv = BleLlAdv::adv_ind()
        .tx_add(false)
        .adv_a_str("00:00:5e:00:53:46")?
        .push_ad(AdStructure::flags_general_disc())
        .push_ad(AdStructure::complete_local_name("crafter-ble"));

    assert_eq!(
        adv.adv_a_value(),
        Some(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
    );

    Ok(())
}
```

AD structures are normal public values. Use typed constructors to build them
and typed readers to inspect their payloads:

```rust
use crafter::prelude::*;

fn main() {
    let mut ad_list = AdList(vec![AdStructure::flags_general_disc()]);
    ad_list.push(AdStructure::complete_local_name("crafter-ble"));
    ad_list.push(AdStructure::manufacturer_data(0xffff, &[0x01, 0x02]));

    for ad in &ad_list.0 {
        if let Some(flags) = ad.flags_value() {
            println!("flags=0x{flags:02x}");
        }
        if let Some(name) = ad.local_name() {
            println!("name={name}");
        }
        if let Some((company_id, data)) = ad.manufacturer_data_value() {
            println!("company=0x{company_id:04x} data={data:?}");
        }
    }
}
```

Modeled AD helpers include Flags, complete and shortened local names, complete
and incomplete 16/32/128-bit service UUID lists, TX power level, appearance,
manufacturer-specific data, service data for 16/32/128-bit UUIDs, and
`AdStructure::raw(...)` for unknown or not-yet-modeled AD types.

## Compile, Summary, And Show

`compile()` returns the exact bytes for the whole packet stack. `summary()` is
the compact single-line view, and `show()` is the multi-line packet tree used by
examples and generated tools:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = BleRadio::advertising(37)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
            .push_ad(AdStructure::flags_general_disc())
            .push_ad(AdStructure::complete_local_name("crafter-ble"))
            .push_ad(AdStructure::manufacturer_data(0xffff, &[0x01, 0x02]));

    let bytes = packet.compile()?;
    println!("{}", packet.summary());
    println!("{}", packet.show());
    println!("{}", packet.hexdump()?);
    assert!(!bytes.as_bytes().is_empty());

    Ok(())
}
```

The summary for the packet above has the same shape as other link roots:

```text
BleRadio(ch=37, aa=0x8e89bed6, phy=1M) / BleLlAdv(ADV_IND, AdvA=00:00:5E:00:53:46, len=...)
```

The exact `len=` value depends on the AD structures present and on any explicit
length override the caller set.

## Decoding Sniffed Frames

Decode BLE LE Link Layer records with the Bluetooth LE link type:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = BleRadio::advertising(37)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
            .push_ad(AdStructure::flags_general_disc())
            .push_ad(AdStructure::complete_local_name("crafter-ble"));

    let sniffed = synthetic_sniffed_record(&packet)?;

    let decoded = Packet::decode_from_link(LinkType::BluetoothLeLl, &sniffed)?;
    let adv = decoded
        .layer::<BleLlAdv>()
        .expect("decoded BLE advertising layer");

    println!("{}", decoded.summary());
    println!("{}", decoded.show());
    println!("advertiser={:?}", adv.adv_a_value());
    println!("decoded advertising layer with AD list: {adv:#?}");

    Ok(())
}

fn synthetic_sniffed_record(packet: &Packet) -> crafter::Result<Vec<u8>> {
    let compiled = packet.compile()?;
    let bytes = compiled.as_bytes();

    let mut record = Vec::with_capacity(bytes.len() + 4);
    record.extend_from_slice(&bytes[..10]);
    record.extend_from_slice(&bytes[4..8]);
    record.extend_from_slice(&bytes[10..]);
    Ok(record)
}
```

The decoded `BleLlAdv` layer preserves the AD list as typed `AdStructure`
values and preserves unknown AD types as raw AD structures. Header fields such
as PDU type, transmitter address type, payload length, and AdvA are also exposed
through `inspection_fields()` and `adv_a_value()`. Malformed or truncated input
returns structured `CrafterError` values with context, required byte count, and
available byte count; decode does not panic on short BLE buffers.

The small helper above mirrors a captured BLE LE Link Layer record: the pcap
pseudo-header is followed by the over-the-air access address and then the Link
Layer PDU. The pcap backend handles that record shape for real pcap files.

## Pcap Usage

Classic pcap support maps BLE advertising records to the BLE LE Link Layer
with pseudo-header link type:

- `LinkType::BluetoothLeLl` is the crate link root for `BleRadio / BleLlAdv`.
- `PcapLinkType::BluetoothLeLl` maps to
  `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` / DLT 256.

Use a pcap recorder with the BLE link type when the packet root is `BleRadio`:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = BleRadio::advertising(37)
        / BleLlAdv::adv_ind()
            .tx_add(false)
            .adv_a(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x46]))
            .push_ad(AdStructure::flags_general_disc())
            .push_ad(AdStructure::complete_local_name("crafter-ble"));

    let writer = PacketWire::pcap_recorder("target/ble-adv.pcap", LinkType::BluetoothLeLl)
        .open()?
        .writer()?;
    Transmitter::new(writer).send(packet.clone())?;

    let source = PacketWire::pcap_file("target/ble-adv.pcap")
        .open()?
        .source()?;
    let records = Sniffer::new(source).collect_records()?;
    assert_eq!(records[0].packet().summary(), packet.summary());

    Ok(())
}
```

Keep tracked pcap fixtures synthetic and deterministic. Do not add captures
from real devices, public device addresses, live host identifiers, credentials,
or sensitive traffic.

## Live Testing Boundary

Offline construction, decode, fixtures, pcap round trips, and oracle validation
are the normal path. BLE live work has a stricter boundary because RF injection
and sniffing can affect or observe devices outside the developer machine.

The WHAD-compatible dongle backend is a live wire backend, not a default
example path. Its default-safe behavior is dry-run planning; real serial
transmit or sniff work requires the optional `whad` feature and explicit live
opt-in. The live dongle checklist is covered by
[`docs/operations/ble-live-manual.md`](../operations/ble-live-manual.md), added
after this guide.

Examples, docs, fixtures, and tests should use documentation 48-bit addresses
from `00:00:5e:00:53:*`, documentation IP address space where IP appears,
synthetic local names such as `crafter-ble`, and synthetic payload bytes. Real
device names, addresses, captures, credentials, provider account data, public
IPs, and live host identifiers do not belong in tracked documentation or
fixtures.

## Validation

Focused automated coverage stays offline:

```sh
cargo test -p crafter ble_
cargo test -p crafter --test fixture_suite ble
tools/oracle/run offline --family ble --profile smoke --seed 3701 --count 20
tools/oracle/run pcap --family ble --profile smoke --seed 3702 --count 20
```

Provider-backed or hardware-backed BLE work must start with dry-run planning
and remain behind explicit live confirmation. Automated validation must not
require a BLE dongle, root privileges, provider credentials, or real device
identifiers.

## Standards And Registries Implemented

The BLE advertising wire facts above trace to reviewed Bluetooth specifications
and link-type registries. The source set that `crafter` implements for this
phase:

- **Bluetooth Core Specification v5.4, Vol 6, Part B** - advertising physical
  channel PDU header layout, PDU type field, addressing bits, payload length,
  ADV_IND / ADV_NONCONN_IND / ADV_SCAN_IND / SCAN_RSP / request PDU shapes,
  advertising access address, CRCInit, and whitening facts.
- **Bluetooth Core Specification v5.4, Vol 6, Part A** - BLE advertising
  channel indices and center frequencies.
- **Bluetooth Core Specification v5.4, Vol 3, Part C** - GAP Advertising Data
  as a sequence of AD structures encoded as Length, AD Type, and AD Data.
- **Bluetooth SIG Assigned Numbers / Generic Access Profile data types** - AD
  type values for Flags, local names, service UUIDs, TX power, service data,
  appearance, and manufacturer-specific data.
- **Bluetooth Core Specification Supplement v11, Part A** - AD data type
  payload shapes for the modeled common data types.
- **tcpdump.org LINKTYPE registry** - `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR`
  and DLT value 256.

Deferred / out of scope for this phase: Bluetooth Classic, extended
advertising auxiliaries, BLE data-channel PDUs, connection following, encryption
and pairing, L2CAP, ATT, GATT, SMP, and a complete Bluetooth stack.
