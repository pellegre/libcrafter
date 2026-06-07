# Dot11 Wire Coverage

This page describes the IEEE 802.11 packet-layer support in the `crafter`
crate: what the `Dot11`, `Radiotap`, `LlcSnap`, `Eapol`, `EapolKey`, and
`RsnInformation` primitives build and decode today, which fields are preserved,
and which Wi-Fi behaviors stay outside the crate.

`crafter` treats IEEE 802.11 as packet data. It builds, compiles, decodes,
summarizes, and shows Wi-Fi layers through the same `Packet` surface as every
other protocol: `/` composition, `compile()`, `decode_from_link`, `summary()`,
`show()`, and `hexdump()`. It is not a scanner, supplicant, access point,
channel manager, password-cracking tool, deauthentication workflow, or complete
Wi-Fi stack.

Protocol facts here are source-backed. The authority record is
[`docs/protocols/dot11-source-manifest.md`](protocols/dot11-source-manifest.md).
The current branch also has offline examples under `crafter/examples/`:
`dot11_radiotap_ipv4`, `dot11_beacon_rsn`, `eapol_key_parse`, and
`wpa_decrypt_offline`.

## Coverage At A Glance

| Area | State | Notes |
| --- | --- | --- |
| Bare Dot11 MAC frames | Supported | Management, control, and data frame builders, frame-control fields, addresses, sequence control, QoS control, selected fixed fields, and tagged parameters. |
| Radiotap | Supported | Version, length, present bitmap words, selected typed fields, alignment padding, raw header preservation, and FCS metadata. |
| LLC/SNAP | Supported | Explicit RFC 1042-style SNAP bridge from unprotected Dot11 data frames to EtherType-based payloads. |
| IPv4 / IPv6 / ARP over Dot11 | Supported through LLC/SNAP | The stack must include `LlcSnap`; `Dot11 / Ipv4` does not imply SNAP. |
| EAPOL | Supported | Base EAPOL header, opaque bodies, EAPOL-Key dispatch, and EtherType `0x888e` through LLC/SNAP. |
| RSN foundations | Supported | RSN information element values, suite selectors, capabilities, Dot11 RSN tagged parameter helpers, and RSN EAPOL-Key metadata. |
| WPA2-PSK CCMP decrypt | Supported through `WpaDecrypt` | Passive transform observes SSID/RSN/EAPOL state and emits decrypted packet records for supported WPA2-Personal CCMP-128 traffic. |
| Protected data frames | Preserved as Raw by direct decode | The protected bit remains visible. Unsupported or not-ready protected frames stay packet-shaped and carry inspectable WPA metadata when processed by `WpaDecrypt`. |
| Classic pcap | Supported | Bare IEEE 802.11 (`DLT_IEEE802_11`) and radiotap (`DLT_IEEE802_11_RADIO`) read/write and decode. |
| Live radiotap send | Dry-run/manual boundary | Dry-run planning is supported. Built-in automatic live injection is not part of automated validation. |

## Bare Dot11

The public MAC layer is `Dot11`, exported through `crafter::prelude::*`,
`crafter::Dot11`, and `crafter::protocols::link::Dot11`.

Bare Dot11 packets are useful for offline fixtures, pcap files with
`PcapLinkType::Ieee80211`, and decoding buffers whose link root is already an
IEEE 802.11 MAC frame:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let sta = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    let ap = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]);

    let dot11 = Dot11::data();
    let to_ds = dot11.frame_control_value().with_to_ds(true);
    let packet = dot11
        .frame_control(to_ds)
        .addr1(ap)
        .addr2(sta)
        .addr3(ap)
        .sequence_number(11)
        / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src_str("192.0.2.10")?
            .dst_str("198.51.100.20")?
            .ipv4_protocol(Ipv4Protocol::Udp)
        / Udp::new().sport(49152).dport(33434)
        / Raw::from("synthetic-dot11-ipv4");

    let bytes = packet.compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes())?;
    println!("{}", decoded.summary());
    Ok(())
}
```

Builders cover common management, control, and data shapes: `Dot11::data`,
`qos_data`, `beacon`, `probe_request`, `probe_response`,
`association_request`, `association_response`, `authentication`,
`deauthentication`, `disassociation`, `ack`, `rts`, and `cts`, plus typed
subtype constructors. The raw frame-control and sequence-control words stay
available through typed wrappers so callers can set unusual or deliberately
malformed values.

Address helpers expose both raw address slots and semantic roles. Data-frame
roles follow the To DS and From DS bits. Management frames use receiver,
transmitter, and BSSID roles. Unsupported or subtype-specific control roles
remain raw address observations.

Decode preserves valid unknown tails as `Raw`. Protected data frames stop at
`Raw` during direct packet decode. `WpaDecrypt` can later consume the resulting
packet records, maintain WPA state, and emit decrypted records for supported
WPA2-PSK CCMP traffic. Fragmented data frames keep per-frame payload bytes
instead of attempting fragment reassembly.

## Radiotap

`Radiotap` is the metadata wrapper used by common monitor-mode capture and
injection paths. A radiotap packet stack starts with `Radiotap`, then `Dot11`:

```rust
use crafter::prelude::*;

let packet = Radiotap::new()
    .rate(12)
    .channel((2412, 0))
    .antenna_signal(-42)
    / Dot11::data()
        .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
        .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]))
        .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
    / Raw::from("synthetic-radiotap-dot11");
```

`compile()` emits the radiotap fixed header, present bitmap words, alignment
padding, typed fields, and the following Dot11 frame. It does not invent
channel, signal, rate, FCS, antenna, retry, or similar metadata when the caller
did not set those fields.

Decode preserves selected typed fields and unknown header bytes needed for
round trips. Radiotap FCS-present and failed-FCS flags remain inspectable
through `Radiotap::fcs_status()`. A capture with FCS metadata is still decoded
as radiotap plus Dot11 where the enclosing headers are valid; the decoder does
not silently reject or strip the payload only because FCS metadata is present.

Use `Packet::decode_from_link(LinkType::Radiotap, bytes)` or
`PcapLinkType::Ieee80211Radiotap.decode(bytes)` for radiotap roots.

## LLC/SNAP

IEEE 802.11 data frames do not carry Ethernet EtherTypes directly. When a data
frame carries IPv4, IPv6, ARP, EAPOL, or another EtherType-shaped payload,
include `LlcSnap` explicitly:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Dot11::data()
        / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
        / Ipv4::new()
            .src_str("192.0.2.30")?
            .dst_str("198.51.100.40")?
        / Raw::from("synthetic-ip-over-snap");

    println!("{}", packet.summary());
    Ok(())
}
```

`LlcSnap::new()` uses the SNAP defaults `DSAP=0xaa`, `SSAP=0xaa`,
`Control=0x03`, and all-zero OUI. The EtherType defaults to IPv4 but can be
set with `ethertype(...)`. When the all-zero OUI and a known EtherType are
decoded, LLC/SNAP dispatches through the existing EtherType registry. Unknown
or non-SNAP payloads are preserved as `Raw`.

This explicit layer is intentional. `Dot11 / Ipv4` compiles as sequential bytes
and does not become IP-over-802.11.

## EAPOL

EAPOL is carried through LLC/SNAP with EtherType `ETHERTYPE_EAPOL` (`0x888e`).
The `Eapol` layer models the base header and opaque body length. `EapolKey`
models the RSN EAPOL-Key descriptor fields needed to inspect synthetic
handshake-shaped frames:

```rust
use crafter::prelude::*;

let key_information = EapolKeyInformation::new()
    .with_descriptor_version(2)
    .with_key_type(true)
    .with_key_ack(true)
    .with_key_mic(true);

let packet = Dot11::data()
    / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
    / Eapol::key()
    / EapolKey::new()
        .key_information(key_information)
        .replay_counter(1)
        .nonce([0x11; 32])
        .mic([0x22; 16])
        .key_data([0xdd, 0x02, 0x00, 0x01]);
```

This is packet-layer metadata, not an authentication workflow. `crafter` does
not implement a supplicant, authenticator, or EAP method parser. The
`WpaDecrypt` transform uses EAPOL-Key records for passive WPA2-PSK CCMP key
derivation and MIC verification; unsupported valid EAPOL bodies remain raw
bytes.

## RSN Foundations

RSN support covers the information element value bytes and suite selector
metadata that packet tools need to construct, decode, and inspect management
frames:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let ap = MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x10]);
    let rsn = RsnInformation::new()
        .with_group_cipher_suite(RSN_CIPHER_SUITE_CCMP_128)
        .with_pairwise_cipher_list([RSN_CIPHER_SUITE_CCMP_128])
        .with_akm_list([RSN_AKM_SUITE_PSK]);

    let beacon = Dot11::beacon()
        .addr1(MacAddr::BROADCAST)
        .addr2(ap)
        .addr3(ap)
        .ssid(b"libcrafter-rsn")
        .with_rsn_information(&rsn)?;

    let bytes = Packet::from_layer(beacon).compile()?;
    let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes())?;
    println!("{}", decoded.show());
    Ok(())
}
```

`RsnInformation` stores version, group cipher, pairwise cipher list, AKM list,
capabilities, PMKIDs, optional group management cipher, and trailing bytes that
are not modeled yet. `Dot11` stores RSN as a normal tagged parameter and parses
the typed RSN view on demand. Malformed raw RSN tags can still decode and
round-trip as Dot11 tags, while typed RSN parsing returns a structured error.

RSN EAPOL-Key parsing is intentionally narrow. It identifies descriptor type,
key-information flags, replay counter, nonce, IV, RSC, ID, MIC, key-data length,
and key-data bytes. It does not decide roles or validate credentials by itself;
`WpaDecrypt` is the stateful transform that collects handshakes, verifies
configured credentials, unwraps supported GTK key data, and attempts protected
data decryption.

## WPA Decrypt Transform

`WpaDecrypt` is a passive inbound `PacketTransform` for WPA/WPA2-Personal
traffic. It is designed for monitor-mode Dot11 packet streams and offline pcap
fixtures. It accepts configured SSID bytes with either a passphrase or a
pre-derived PMK, observes management and EAPOL-Key traffic, and emits decrypted
packet records when WPA2-PSK CCMP-128 key state is available.

The usual ordering is:

```rust
use crafter::prelude::*;

let source = PacketWire::pcap_file(
    "crafter/tests/fixtures/pcaps/wpa2-psk-ccmp-unicast.pcap",
)
    .open()?
    .source()?;

let mut sniffer = Sniffer::new(source)
    .with(Dot11Metadata::new())
    .with(WpaDecrypt::new().network("libcrafter-wpa", "libcrafter-pass")?);

while let Some(record) = sniffer.next_record()? {
    println!("{}", record.packet().summary());
    if let Some(wpa) = record
        .metadata()
        .wifi()
        .and_then(|wifi| wifi.wpa_metadata())
    {
        println!(
            "BSSID {:?} station {:?} cipher {:?} key {:?} reason {:?}",
            wpa.bssid(),
            wpa.station(),
            wpa.cipher(),
            wpa.key_kind(),
            wpa.decrypt_reason(),
        );
    }
}
# Ok::<(), crafter::CrafterError>(())
```

When decrypted plaintext is RFC 1042 LLC/SNAP with known addresses,
`WpaDecrypt` emits an Ethernet-equivalent packet so later IP, TCP, or
application transforms can continue from the normal link-layer shape. Unknown
plaintext remains `Raw` inside a `Packet`. The output `PacketRecord` preserves
available pcap and backend metadata and adds WPA details under
`record.metadata().wifi().and_then(|wifi| wifi.wpa_metadata())`, including SSID,
BSSID, station, cipher, AKM, key kind, key id, packet number, handshake status,
credential status, and decrypt reason.

The implemented decrypt path is WPA2-PSK CCMP-128. Unsupported ciphers such as
TKIP, GCMP, and CCMP-256, unsupported AKMs such as enterprise or SAE, incomplete
handshakes, MIC failures, replayed packet numbers, malformed CCMP headers, and
authentication failures are surfaced through metadata such as
`WpaDecryptReason::UnsupportedCipher`, `UnsupportedAkm`,
`WaitingForHandshake`, `MicFailed`, `ReplayDetected`, `MalformedFrame`, or
`AuthenticationFailed`.

Use the tracked synthetic fixture and offline example for repeatable validation:

```sh
cargo run -p crafter --example wpa_decrypt_offline
```

Do not commit real SSIDs, passphrases, PMKs, BSSIDs, live packet captures, or
traffic from networks you are not authorized to observe. `WpaDecrypt` is not a
password cracker and does not perform active deauthentication, scanning,
association, channel hopping, AP behavior, or supplicant behavior.

## Pcap Usage

Classic pcap support includes both new Wi-Fi link types:

- `PcapLinkType::Ieee80211` maps to `DLT_IEEE802_11` (`105`) for bare Dot11
  records.
- `PcapLinkType::Ieee80211Radiotap` maps to `DLT_IEEE802_11_RADIO` (`127`) for
  radiotap-wrapped Dot11 records.

Use `PcapReader` to preserve and decode existing files. Use `PcapWriter` with
the link type that matches the packet root:

```rust
use crafter::prelude::*;

fn main() -> crafter::Result<()> {
    let packet = Radiotap::new()
        / Dot11::data()
            .addr1(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
            .addr2(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]))
            .addr3(MacAddr::new([0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]))
        / Raw::from("synthetic-pcap-record");

    let mut pcap = Vec::new();
    PcapWriter::from_writer(&mut pcap, PcapLinkType::Ieee80211Radiotap)?
        .write_packet(&packet)?
        .flush()?;

    let decoded = PcapReader::from_reader(pcap.as_slice())?.collect_packets()?;
    assert_eq!(decoded[0].summary(), packet.summary());
    Ok(())
}
```

Keep pcap fixtures synthetic and deterministic. Do not add packet captures from
real networks, public BSSIDs, public IPs, credentials, or sensitive traffic to
tracked files.

## Monitor-Mode Capture Through Wire

For live capture on a Wi-Fi dongle, create and configure the monitor-mode
interface outside `crafter`, then open it as a pcap-backed packet source:

```rust
use crafter::prelude::*;

let source = PacketWire::pcap_interface("dot11-doc-iface")
    .filter("type mgt or type data")
    .open()?
    .source()?;

let mut sniffer = Sniffer::new(source)
    .with(Dot11Metadata::new())
    .count(25);

while let Some(record) = sniffer.next_record()? {
    println!("{}", record.packet().summary());
    if let Some(wifi) = record.metadata().wifi() {
        println!("wifi metadata: {:?}", wifi);
    }
}
# Ok::<(), crafter::CrafterError>(())
```

`PacketWire::pcap_interface` is the live libpcap interface backend. When the
interface is a monitor-mode Wi-Fi device, the records are still ordinary
`PacketRecord` values whose packets decode as radiotap or bare Dot11 depending
on the data-link type reported by pcap.

`Dot11Metadata` is an inbound `PacketTransform` that annotates the record with
best-effort Wi-Fi metadata and then passes the same packet onward. It does not
decrypt protected data frames by itself. Add `WpaDecrypt` after
`Dot11Metadata` in the `Sniffer` transform chain when an authorized caller has
configured the relevant synthetic or test-network SSID and credential material.
Later IPv4/IPv6 fragment, TCP stream, or application transforms can follow the
WPA transform. The `Sniffer` contract does not change: every emitted item is
still a `PacketRecord` with a packet and metadata.

## Live Testing Boundary

Offline construction, decode, fixtures, pcap round trips, and oracle validation
are the normal path. Live Wi-Fi work has a stricter boundary than ordinary
packet compilation because an RF interface can affect networks outside the
developer machine.

Current radiotap live support is limited to dry-run send planning. A
`Radiotap / Dot11` packet can produce a link-layer send plan with
`SendOptions::new().iface("dot11-monitor-dry-run").link_layer()`, but built-in
automatic live injection is intentionally unsupported and is not part of
automated validation. Manual dongle guidance lives in
[`docs/dot11-live-manual.md`](dot11-live-manual.md).

Examples, docs, fixtures, and tests should use documentation MAC addresses from
the `00:00:5e:00:53:00` range, documentation IP address space such as
`192.0.2.0/24`, `198.51.100.0/24`, and `2001:db8::/32`, and synthetic payload
bytes. Real SSIDs, BSSIDs, captures, credentials, public addresses, and live
host identifiers do not belong in tracked documentation or fixtures.

The tracked Dot11 artifact hygiene check intentionally allows only narrow
synthetic Wi-Fi identifiers: RFC 7042/RFC 9542 documentation MACs matching
`00:00:5e:00:53:*`, broadcast or zero MACs where the frame shape calls for
them, and the local-administered fixture range `02:00:5e:10:*:*`. Allowed
synthetic SSID or payload strings are `libcrafter-rsn`, `libcrafter-wpa`,
`libcrafter-dot11-dry-run`, `dot11-agent-*`, and fixture-only `crafter` or
`rsn-fixture`.

## Validation

Focused automated coverage stays offline:

```sh
cargo run -p crafter --example dot11_radiotap_ipv4
cargo run -p crafter --example dot11_beacon_rsn
cargo run -p crafter --example eapol_key_parse
cargo run -p crafter --example wpa_decrypt_offline
cargo test -p crafter --test fixture_suite dot11
tools/oracle/run offline --family dot11 --profile smoke --seed 1101 --count 20
tools/oracle/run pcap --family dot11 --profile smoke --seed 1102 --count 20
```

Provider-backed or hardware-backed live work must start with dry-run planning
and remain behind explicit live confirmation. Automated validation must not
require a Wi-Fi dongle, monitor mode, root privileges, provider credentials, or
real network identifiers.
