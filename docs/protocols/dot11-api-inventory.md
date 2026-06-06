# Dot11 API Inventory

This inventory records the intended public API additions for phase 1 through
phase 1.5 IEEE 802.11 support. It is not an implementation checklist for every
private helper. The public shape should remain a normal libcrafter packet stack:

```rust
use crafter::prelude::*;

let packet = Radiotap::new()
    / Dot11::data()
    / LlcSnap::new().ethertype(ETHERTYPE_IPV4)
    / Ipv4::new()
    / Raw::from("payload");
```

`Dot11::data() / Ipv4::new()` is only a sequential byte stack. It does not
create a valid IP-over-802.11 payload and must not cause hidden LLC/SNAP
insertion.

Existing public types must not be renamed. In particular, `Packet`, `Raw`,
`Layer`, `LinkType`, `NetworkLayer`, `ProtocolRegistry`, `MacAddr`, `Ethernet`,
`Vlan`, `Dot1Q`, `LinuxSll`, `NullLoopback`, `PcapLinkType`, and existing
protocol-layer names stay source compatible.

## Export Policy

The new public types should be exported from their protocol modules, the crate
root, and `crafter::prelude::*` when they are useful to packet authors.

Module placement:

- `crafter::protocols::link::Radiotap`
- `crafter::protocols::link::Dot11`
- `crafter::protocols::link::LlcSnap`
- `crafter::protocols::Eapol` or `crafter::protocols::eapol::Eapol`
- `crafter::protocols::RsnInformation` or `crafter::protocols::rsn::RsnInformation`

Decode helpers that only support registry dispatch should remain `pub(crate)`.
Public decode entrypoints should continue to be `Packet`, `PcapLinkType`, and
typed protocol APIs that match existing crate conventions.

## Link and Pcap Entrypoints

Public additions:

- `LinkType::Ieee80211` for bare IEEE 802.11 MAC frames.
- `LinkType::Radiotap` for radiotap-wrapped IEEE 802.11 frames.
- `PcapLinkType::Ieee80211` for `DLT_IEEE802_11`.
- `PcapLinkType::Ieee80211Radiotap` for `DLT_IEEE802_11_RADIO`.
- `DLT_IEEE802_11: u32 = 105`.
- `DLT_IEEE802_11_RADIO: u32 = 127`.

Public decode entrypoints:

- `Packet::decode_from_link(LinkType::Ieee80211, bytes)`.
- `Packet::decode_from_link(LinkType::Radiotap, bytes)`.
- `Packet::decode_from_link_with_registry(registry, LinkType::Ieee80211, bytes)`.
- `Packet::decode_from_link_with_registry(registry, LinkType::Radiotap, bytes)`.
- `PcapLinkType::Ieee80211.decode(bytes)`.
- `PcapLinkType::Ieee80211Radiotap.decode(bytes)`.
- `PcapLinkType::decode_with_registry` for both new pcap link types.

Internal helpers:

- Numeric DLT to `PcapLinkType` matching internals.
- Per-link decode dispatch functions used by `ProtocolRegistry`.
- Any pcap writer normalization helper that derives a pcap link type from the
  first packet layer.

## Radiotap

Public types:

- `Radiotap`
- `RadiotapPresent`
- `RadiotapField`
- `RadiotapFlags`
- `RadiotapChannel`
- `RadiotapChannelFlags`
- `RadiotapRxFlags`
- `RadiotapTxFlags`
- `RadiotapFcsStatus`

Public constants:

- `RADIOTAP_HEADER_LEN: usize = 8`.
- `RADIOTAP_PRESENT_EXT: u32 = 0x8000_0000`.
- Radiotap present-bit constants for the phase 1 typed fields: TSFT, Flags,
  Rate, Channel, DBM antenna signal, Antenna, RX flags, and TX flags.
- Radiotap flag constants for FCS-present and failed-FCS metadata.

Constructors and builders:

- `Radiotap::new()`.
- `Radiotap::version(u8)`.
- `Radiotap::pad(u8)`.
- `Radiotap::field(RadiotapField)`.
- `Radiotap::fields(Vec<RadiotapField>)`.
- `Radiotap::flags(RadiotapFlags)`.
- `Radiotap::rate_500kbps(u8)`.
- `Radiotap::channel(RadiotapChannel)`.
- `Radiotap::antenna_signal_dbm(i8)`.
- `Radiotap::antenna(u8)`.
- `Radiotap::rx_flags(RadiotapRxFlags)`.
- `Radiotap::tx_flags(RadiotapTxFlags)`.
- `Radiotap::raw_header(Vec<u8>)` for preserving decoded metadata that is not
  typed yet.

Getters:

- `Radiotap::version_value() -> Option<u8>`.
- `Radiotap::length_value() -> Option<u16>`.
- `Radiotap::present_words() -> &[u32]`.
- `Radiotap::fields_value() -> &[RadiotapField]`.
- `Radiotap::flags_value() -> Option<RadiotapFlags>`.
- `Radiotap::channel_value() -> Option<RadiotapChannel>`.
- `Radiotap::antenna_signal_dbm_value() -> Option<i8>`.
- `Radiotap::antenna_value() -> Option<u8>`.
- `Radiotap::rx_flags_value() -> Option<RadiotapRxFlags>`.
- `Radiotap::tx_flags_value() -> Option<RadiotapTxFlags>`.
- `Radiotap::fcs_status() -> RadiotapFcsStatus`.
- `Radiotap::raw_header_value() -> Option<&[u8]>`.

Internal helpers:

- Radiotap present-word iterator.
- Radiotap alignment and padding calculator.
- Radiotap typed-field parser and writer.
- Unknown-present-bit preservation logic.
- FCS byte trimming or validation helpers, if any. The public decode path must
  not silently strip or reject payload bytes solely because FCS metadata exists.

## Dot11

Public types:

- `Dot11`
- `Dot11FrameControl`
- `Dot11FrameType`
- `Dot11ManagementSubtype`
- `Dot11ControlSubtype`
- `Dot11DataSubtype`
- `Dot11SequenceControl`
- `Dot11TaggedParameter`
- `Dot11AddressRole`
- `Dot11AddressSet`
- `Dot11QosControl`
- `Dot11ReasonCode`
- `Dot11StatusCode`
- `Dot11AuthenticationAlgorithm`

Public constants:

- `DOT11_FRAME_CONTROL_LEN: usize = 2`.
- `DOT11_MIN_HEADER_LEN: usize = 10`.
- `DOT11_DATA_HEADER_LEN: usize = 24`.
- `DOT11_DATA_ADDR4_HEADER_LEN: usize = 30`.
- `DOT11_QOS_CONTROL_LEN: usize = 2`.
- `DOT11_SEQUENCE_CONTROL_LEN: usize = 2`.
- Management element IDs needed through phase 1.5, including SSID, supported
  rates, DS parameter set, TIM, RSN, extended supported rates, and vendor
  specific.

Constructors and builders:

- `Dot11::new()`.
- `Dot11::management(subtype: Dot11ManagementSubtype)`.
- `Dot11::control(subtype: Dot11ControlSubtype)`.
- `Dot11::data()`.
- `Dot11::data_subtype(subtype: Dot11DataSubtype)`.
- `Dot11::beacon()`.
- `Dot11::probe_request()`.
- `Dot11::probe_response()`.
- `Dot11::association_request()`.
- `Dot11::association_response()`.
- `Dot11::authentication()`.
- `Dot11::deauthentication()`.
- `Dot11::disassociation()`.
- `Dot11::ack()`.
- `Dot11::rts()`.
- `Dot11::cts()`.
- `Dot11::frame_control(Dot11FrameControl)`.
- `Dot11::duration_id(u16)`.
- `Dot11::addr1(MacAddr)`.
- `Dot11::addr2(MacAddr)`.
- `Dot11::addr3(MacAddr)`.
- `Dot11::addr4(MacAddr)`.
- `Dot11::receiver(MacAddr)`.
- `Dot11::transmitter(MacAddr)`.
- `Dot11::destination(MacAddr)`.
- `Dot11::source(MacAddr)`.
- `Dot11::bssid(MacAddr)`.
- `Dot11::sequence_control(Dot11SequenceControl)`.
- `Dot11::fragment_number(u8)`.
- `Dot11::sequence_number(u16)`.
- `Dot11::more_fragments(bool)`.
- `Dot11::qos_control(Dot11QosControl)`.
- `Dot11::protected(bool)`.
- `Dot11::tag(Dot11TaggedParameter)`.
- `Dot11::tags(Vec<Dot11TaggedParameter>)`.
- `Dot11::ssid(Vec<u8>)`.
- `Dot11::rsn(RsnInformation)`.

Getters:

- `Dot11::frame_control_value() -> Dot11FrameControl`.
- `Dot11::frame_type() -> Dot11FrameType`.
- `Dot11::management_subtype() -> Option<Dot11ManagementSubtype>`.
- `Dot11::control_subtype() -> Option<Dot11ControlSubtype>`.
- `Dot11::data_subtype() -> Option<Dot11DataSubtype>`.
- `Dot11::duration_id_value() -> Option<u16>`.
- `Dot11::addr1_value() -> Option<MacAddr>`.
- `Dot11::addr2_value() -> Option<MacAddr>`.
- `Dot11::addr3_value() -> Option<MacAddr>`.
- `Dot11::addr4_value() -> Option<MacAddr>`.
- `Dot11::receiver_value() -> Option<MacAddr>`.
- `Dot11::transmitter_value() -> Option<MacAddr>`.
- `Dot11::destination_value() -> Option<MacAddr>`.
- `Dot11::source_value() -> Option<MacAddr>`.
- `Dot11::bssid_value() -> Option<MacAddr>`.
- `Dot11::sequence_control_value() -> Option<Dot11SequenceControl>`.
- `Dot11::fragment_number_value() -> Option<u8>`.
- `Dot11::sequence_number_value() -> Option<u16>`.
- `Dot11::has_more_fragments() -> bool`.
- `Dot11::is_fragmented() -> bool`.
- `Dot11::qos_control_value() -> Option<Dot11QosControl>`.
- `Dot11::is_protected() -> bool`.
- `Dot11::tags_value() -> &[Dot11TaggedParameter]`.
- `Dot11::tagged_parameters() -> &[Dot11TaggedParameter]`.

Internal helpers:

- Frame-control bit packing and unpacking.
- Type/subtype header-length calculation.
- Subtype-specific minimum length validation.
- Management fixed-field parser and writer.
- Tagged parameter parser and writer.
- Address role derivation for To DS and From DS combinations.
- Payload dispatch decision logic. Protected data frames stop at `Raw`.

## LlcSnap

Public types:

- `LlcSnap`
- `LlcSnapOui`

Public constants:

- `LLC_SNAP_HEADER_LEN: usize = 8`.
- `LLC_SNAP_DSAP: u8 = 0xaa`.
- `LLC_SNAP_SSAP: u8 = 0xaa`.
- `LLC_SNAP_CONTROL: u8 = 0x03`.
- `SNAP_OUI_RFC1042: [u8; 3] = [0x00, 0x00, 0x00]`.
- `ETHERTYPE_EAPOL: u16 = 0x888e`.

Constructors and builders:

- `LlcSnap::new()`.
- `LlcSnap::ethertype(u16)`.
- `LlcSnap::ipv4()`.
- `LlcSnap::ipv6()`.
- `LlcSnap::arp()`.
- `LlcSnap::eapol()`.
- `LlcSnap::dsap(u8)`.
- `LlcSnap::ssap(u8)`.
- `LlcSnap::control(u8)`.
- `LlcSnap::oui([u8; 3])`.
- `LlcSnap::protocol_id(u16)`.

Getters:

- `LlcSnap::dsap_value() -> Option<u8>`.
- `LlcSnap::ssap_value() -> Option<u8>`.
- `LlcSnap::control_value() -> Option<u8>`.
- `LlcSnap::oui_value() -> Option<[u8; 3]>`.
- `LlcSnap::ethertype_value() -> Option<u16>`.
- `LlcSnap::protocol_id_value() -> Option<u16>`.

Internal helpers:

- SNAP header validation.
- EtherType dispatch into the existing ethertype registry.
- Non-SNAP LLC preservation as `Raw`.

## Eapol

Public types:

- `Eapol`
- `EapolType`
- `EapolKey`
- `EapolKeyInformation`
- `EapolDescriptorType`

Public constants:

- `EAPOL_HEADER_LEN: usize = 4`.
- `EAPOL_KEY_DESCRIPTOR_MIN_LEN: usize`.
- EAPOL type constants for EAP-Packet, Start, Logoff, Key, and Encapsulated
  ASF Alert if represented as constants in addition to `EapolType`.

Constructors and builders:

- `Eapol::new()`.
- `Eapol::packet_type(EapolType)`.
- `Eapol::version(u8)`.
- `Eapol::body(Vec<u8>)`.
- `Eapol::key(EapolKey)`.
- `EapolKey::new()`.
- `EapolKey::descriptor_type(EapolDescriptorType)`.
- `EapolKey::key_information(EapolKeyInformation)`.
- `EapolKey::key_length(u16)`.
- `EapolKey::replay_counter(u64)`.
- `EapolKey::nonce([u8; 32])`.
- `EapolKey::iv([u8; 16])`.
- `EapolKey::rsc([u8; 8])`.
- `EapolKey::id([u8; 8])`.
- `EapolKey::mic(Vec<u8>)`.
- `EapolKey::key_data(Vec<u8>)`.

Getters:

- `Eapol::version_value() -> Option<u8>`.
- `Eapol::packet_type_value() -> Option<EapolType>`.
- `Eapol::body_len_value() -> Option<u16>`.
- `Eapol::body_value() -> &[u8]`.
- `Eapol::key_value() -> Option<&EapolKey>`.
- `EapolKey::descriptor_type_value() -> Option<EapolDescriptorType>`.
- `EapolKey::key_information_value() -> Option<EapolKeyInformation>`.
- `EapolKey::key_length_value() -> Option<u16>`.
- `EapolKey::replay_counter_value() -> Option<u64>`.
- `EapolKey::nonce_value() -> Option<[u8; 32]>`.
- `EapolKey::iv_value() -> Option<[u8; 16]>`.
- `EapolKey::rsc_value() -> Option<[u8; 8]>`.
- `EapolKey::id_value() -> Option<[u8; 8]>`.
- `EapolKey::mic_value() -> &[u8]`.
- `EapolKey::key_data_value() -> &[u8]`.

Internal helpers:

- EAPOL body length validation.
- RSN EAPOL-Key key-information bit packing.
- Key-data length validation and trailing body preservation.
- EAP-Packet parser, unless a later phase makes EAP itself public.

## Rsn

Public types:

- `RsnInformation`
- `RsnCipherSuite`
- `RsnAkmSuite`
- `RsnSuiteSelector`
- `RsnCapabilities`

Public constants:

- `DOT11_TAG_RSN: u8 = 48`.
- `RSN_VERSION_1: u16 = 1`.
- RSN suite selector constants for the standard cipher and AKM suites needed by
  phase 1.5 tests.

Constructors and builders:

- `RsnInformation::new()`.
- `RsnInformation::version(u16)`.
- `RsnInformation::group_cipher_suite(RsnCipherSuite)`.
- `RsnInformation::pairwise_cipher_suite(RsnCipherSuite)`.
- `RsnInformation::pairwise_cipher_suites(Vec<RsnCipherSuite>)`.
- `RsnInformation::akm_suite(RsnAkmSuite)`.
- `RsnInformation::akm_suites(Vec<RsnAkmSuite>)`.
- `RsnInformation::capabilities(RsnCapabilities)`.
- `RsnInformation::pmkid(Vec<u8>)`.
- `RsnInformation::pmkids(Vec<[u8; 16]>)`.
- `RsnInformation::group_management_cipher_suite(RsnCipherSuite)`.
- `RsnCipherSuite::new(oui: [u8; 3], suite_type: u8)`.
- `RsnAkmSuite::new(oui: [u8; 3], suite_type: u8)`.

Getters:

- `RsnInformation::version_value() -> Option<u16>`.
- `RsnInformation::group_cipher_suite_value() -> Option<RsnCipherSuite>`.
- `RsnInformation::pairwise_cipher_suites_value() -> &[RsnCipherSuite]`.
- `RsnInformation::akm_suites_value() -> &[RsnAkmSuite]`.
- `RsnInformation::capabilities_value() -> Option<RsnCapabilities>`.
- `RsnInformation::pmkids_value() -> &[[u8; 16]]`.
- `RsnInformation::group_management_cipher_suite_value() -> Option<RsnCipherSuite>`.
- `RsnCipherSuite::oui() -> [u8; 3]`.
- `RsnCipherSuite::suite_type() -> u8`.
- `RsnAkmSuite::oui() -> [u8; 3]`.
- `RsnAkmSuite::suite_type() -> u8`.

Internal helpers:

- RSN information element length parser.
- Suite selector list parser.
- PMKID list parser.
- Management tagged-parameter conversion helpers.
- Vendor-specific suite preservation logic.

## Send Planning

Public additions:

- `SendPlan` summaries should identify radiotap-wrapped IEEE 802.11 as a
  link-layer send when the first layer is `Radiotap`.
- Existing `SendOptions::link_layer()`, `SendOptions::dry_run()`, and
  `SendOptions::live()` should remain the public controls.

Internal helpers:

- Link-send backend selection for monitor-mode radiotap injection.
- Datalink probing and datalink selection for live pcap handles.
- Hardware-specific live error messages.

Automated tests must exercise dry-run planning only. Manual live injection
documentation can describe dongle and monitor-mode requirements without making
them part of the public API contract.

## Explicit Non-API Items

These names should remain crate-private unless a later inventory update makes a
case for exposing them:

- Radiotap raw parser and writer structs.
- Dot11 subtype dispatch tables.
- Dot11 management fixed-field intermediate structs.
- LLC/SNAP parser cursors.
- EAPOL and RSN byte-slice cursor helpers.
- Oracle normalization structs.
- Reference or tshark backend adapters.
- Live monitor-mode setup helpers.

WPA/WPA2/WPA3 plaintext recovery, passphrase handling, key derivation,
handshake collection workflows, scanning, association, channel hopping, and
deauthentication workflows are outside this inventory.
