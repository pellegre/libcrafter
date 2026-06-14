use super::constants::{
    UDP_OPTION_APC_LEN, UDP_OPTION_CHECKSUM_LEN, UDP_OPTION_FRAG_LONG_LEN,
    UDP_OPTION_FRAG_SHORT_LEN, UDP_OPTION_MDS_LEN, UDP_OPTION_MRDS_LEN, UDP_OPTION_REQ_LEN,
    UDP_OPTION_RES_LEN, UDP_OPTION_TIME_LEN,
};
use super::datagram::{
    decode_udp_parts, decoded_udp_checksum_status as checksum_status_with_context,
};
use super::{
    udp_option_kind_class, udp_option_kind_is_unsafe, udp_option_kind_is_unsupported, Udp,
    UdpChecksumStatus, UdpOption, UdpOptionIter, UdpOptionKindClass, UdpOptionStatus, UdpOptions,
    UDP_HEADER_LEN, UDP_OPTION_APC, UDP_OPTION_AUTH, UDP_OPTION_EOL, UDP_OPTION_EXP,
    UDP_OPTION_FRAG, UDP_OPTION_MDS, UDP_OPTION_MRDS, UDP_OPTION_NOP, UDP_OPTION_REQ,
    UDP_OPTION_RES, UDP_OPTION_RESERVED_SAFE_START, UDP_OPTION_RESERVED_UNSAFE, UDP_OPTION_TIME,
    UDP_OPTION_UCMP, UDP_OPTION_UEXP, UDP_OPTION_UNASSIGNED_SAFE_START,
    UDP_OPTION_UNASSIGNED_UNSAFE_START,
};
use crate::checksum::{
    crc32c, internet_checksum_chunks, ipv4_pseudo_header_checksum, ipv6_pseudo_header_checksum,
};
use crate::{
    Dhcp, DhcpMessageType, Dns, Ipv4, Ipv4Protocol, Ipv6, Layer, LinkType, MacAddr, Packet, Raw,
    DNS_PORT, DNS_TYPE_A, IPPROTO_UDP,
};
use core::net::{Ipv4Addr, Ipv6Addr};

const VLAN_FIXTURE: &[u8] = fixture_bytes!("bytes/ethernet-vlan-ipv4-udp-raw.bin");

fn src() -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, 1)
}

fn dst() -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, 2)
}

fn ipv6_src() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
}

fn ipv6_dst() -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)
}

fn ipv4_total_len(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[2], bytes[3]]) as usize
}

fn ipv6_payload_len(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[4], bytes[5]]) as usize
}

fn udp_length(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[24], bytes[25]]) as usize
}

fn ipv6_udp_length(bytes: &[u8]) -> usize {
    u16::from_be_bytes([bytes[44], bytes[45]]) as usize
}

fn udp_surplus_start(bytes: &[u8]) -> usize {
    20 + udp_length(bytes)
}

fn ipv6_udp_surplus_start(bytes: &[u8]) -> usize {
    40 + ipv6_udp_length(bytes)
}

fn udp_surplus(bytes: &[u8]) -> &[u8] {
    &bytes[udp_surplus_start(bytes)..ipv4_total_len(bytes)]
}

fn ipv6_udp_surplus(bytes: &[u8]) -> &[u8] {
    &bytes[ipv6_udp_surplus_start(bytes)..40 + ipv6_payload_len(bytes)]
}

fn udp_surplus_option_bytes(surplus_start: usize, surplus: &[u8]) -> &[u8] {
    &surplus[(surplus_start & 1) + UDP_OPTION_CHECKSUM_LEN..]
}

fn udp_surplus_checksum_valid(bytes: &[u8]) -> bool {
    let surplus_start = udp_surplus_start(bytes);
    let surplus = udp_surplus(bytes);
    udp_surplus_checksum_valid_at(surplus_start, surplus)
}

fn udp_surplus_checksum_valid_at(surplus_start: usize, surplus: &[u8]) -> bool {
    let alignment_len = surplus_start & 1;
    let len = (surplus.len() as u16).to_be_bytes();
    internet_checksum_chunks([len.as_slice(), &surplus[alignment_len..]]) == 0
}

fn wire_checksum(checksum: u16) -> u16 {
    if checksum == 0 {
        0xffff
    } else {
        checksum
    }
}

fn udp_checksum(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[26], bytes[27]])
}

fn ipv6_udp_checksum(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[46], bytes[47]])
}

fn set_ipv4_udp_checksum(bytes: &mut [u8], checksum: u16) {
    bytes[26..28].copy_from_slice(&checksum.to_be_bytes());
}

fn set_ipv6_udp_checksum(bytes: &mut [u8], checksum: u16) {
    bytes[46..48].copy_from_slice(&checksum.to_be_bytes());
}

fn invalid_checksum(checksum: u16) -> u16 {
    if checksum == 0x1234 {
        0x5678
    } else {
        0x1234
    }
}

fn assert_udp_checksum_status(
    network_layer: crate::NetworkLayer,
    bytes: &[u8],
    expected: UdpChecksumStatus,
) -> Packet {
    let decoded = Packet::decode_from_l3(network_layer, bytes).unwrap();
    assert_eq!(decoded.layer::<Udp>().unwrap().checksum_status(), expected);
    decoded
}

fn zeroed_ipv4_udp_checksum_input(bytes: &[u8], payload_len: usize) -> Vec<u8> {
    let udp_end = 20 + UDP_HEADER_LEN + payload_len;
    let mut udp = bytes[20..udp_end].to_vec();
    udp[6] = 0;
    udp[7] = 0;
    udp
}

fn zeroed_ipv6_udp_checksum_input(bytes: &[u8], payload_len: usize) -> Vec<u8> {
    let udp_end = 40 + UDP_HEADER_LEN + payload_len;
    let mut udp = bytes[40..udp_end].to_vec();
    udp[6] = 0;
    udp[7] = 0;
    udp
}

fn expected_ipv4_udp_checksum(bytes: &[u8], payload_len: usize) -> u16 {
    let udp = zeroed_ipv4_udp_checksum_input(bytes, payload_len);
    wire_checksum(ipv4_pseudo_header_checksum(src(), dst(), IPPROTO_UDP, &udp))
}

fn expected_ipv6_udp_checksum(bytes: &[u8], payload_len: usize) -> u16 {
    let udp = zeroed_ipv6_udp_checksum_input(bytes, payload_len);
    wire_checksum(ipv6_pseudo_header_checksum(
        ipv6_src(),
        ipv6_dst(),
        IPPROTO_UDP,
        &udp,
    ))
}

fn expected_ipv4_checksum_if_surplus_were_included(bytes: &[u8]) -> u16 {
    let mut udp = bytes[20..ipv4_total_len(bytes)].to_vec();
    udp[6] = 0;
    udp[7] = 0;
    wire_checksum(ipv4_pseudo_header_checksum(src(), dst(), IPPROTO_UDP, &udp))
}

fn expected_ipv6_checksum_if_surplus_were_included(bytes: &[u8]) -> u16 {
    let mut udp = bytes[40..40 + ipv6_payload_len(bytes)].to_vec();
    udp[6] = 0;
    udp[7] = 0;
    wire_checksum(ipv6_pseudo_header_checksum(
        ipv6_src(),
        ipv6_dst(),
        IPPROTO_UDP,
        &udp,
    ))
}

fn assert_ipv4_udp_checksum_excludes_surplus(bytes: &[u8], payload_len: usize) {
    assert_eq!(
        udp_checksum(bytes),
        expected_ipv4_udp_checksum(bytes, payload_len)
    );
}

fn assert_ipv6_udp_checksum_excludes_surplus(bytes: &[u8], payload_len: usize) {
    assert_eq!(
        ipv6_udp_checksum(bytes),
        expected_ipv6_udp_checksum(bytes, payload_len)
    );
}

fn apc_checksum_value(udp_options: &UdpOptions) -> u32 {
    udp_options
        .options()
        .iter()
        .find_map(UdpOption::additional_payload_checksum_value)
        .expect("decoded APC option")
}

fn assert_udp_option_length_buffer_error(
    bytes: &[u8],
    expected_context: &'static str,
    expected_required: usize,
    expected_available: usize,
) {
    let udp_options = UdpOptions::from_bytes(bytes);
    assert_eq!(udp_options.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(udp_options.as_bytes(), bytes);

    match UdpOption::decode_all(bytes).unwrap_err() {
        crate::CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, expected_context);
            assert_eq!(required, expected_required);
            assert_eq!(available, expected_available);
        }
        other => panic!("expected UDP option length buffer error, got {other:?}"),
    }
}

fn assert_udp_option_length_field_error(bytes: &[u8], expected_field: &'static str) {
    let udp_options = UdpOptions::from_bytes(bytes);
    assert_eq!(udp_options.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(udp_options.as_bytes(), bytes);

    match UdpOption::decode_all(bytes).unwrap_err() {
        crate::CrafterError::InvalidFieldValue { field, .. } => {
            assert_eq!(field, expected_field);
        }
        other => panic!("expected UDP option length field error, got {other:?}"),
    }
}

fn assert_udp_option_encode_field_error(option: UdpOption, expected_field: &'static str) {
    match option.encode().unwrap_err() {
        crate::CrafterError::InvalidFieldValue { field, .. } => {
            assert_eq!(field, expected_field);
        }
        other => panic!("expected UDP option encode field error, got {other:?}"),
    }
}

fn assert_udp_options_status_surface(udp_options: &UdpOptions, expected_status: UdpOptionStatus) {
    let status = format!("{expected_status:?}");
    assert_eq!(udp_options.status(), expected_status);
    assert!(
        udp_options.summary().contains(&format!("status={status}")),
        "summary did not expose status {status}: {}",
        udp_options.summary()
    );
    assert!(
        udp_options
            .inspection_fields()
            .iter()
            .any(|(name, value)| *name == "status" && value == &status),
        "inspection fields did not expose status {status}: {:?}",
        udp_options.inspection_fields()
    );
}

fn assert_decoded_udp_options_status_roundtrip(
    option_bytes: &[u8],
    expected_status: UdpOptionStatus,
) {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2250)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0x55])
        / UdpOptions::from_bytes(option_bytes))
    .compile()
    .unwrap();
    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();

    assert_udp_options_status_surface(udp_options, expected_status);
    assert_eq!(udp_options.as_bytes(), option_bytes);
    assert!(decoded
        .show()
        .contains(&format!("status: {expected_status:?}")));
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

fn ipv4_udp_with_raw_surplus(user_payload: &[u8], surplus: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0x1234u16.to_be_bytes());
    datagram.extend_from_slice(&0x2222u16.to_be_bytes());
    datagram.extend_from_slice(&((UDP_HEADER_LEN + user_payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.extend_from_slice(user_payload);
    datagram.extend_from_slice(surplus);

    (Ipv4::new()
        .src(src())
        .dst(dst())
        .ipv4_protocol(Ipv4Protocol::Udp)
        .id(0x2260)
        / Raw::from_bytes(datagram))
    .compile()
    .unwrap()
    .as_bytes()
    .to_vec()
}

fn assert_udp_option_malformed_status(
    label: &str,
    surplus: &[u8],
    expected_option_bytes: &[u8],
    expected_status: UdpOptionStatus,
) {
    let user_payload = [0xaa, 0xbb];
    let bytes = ipv4_udp_with_raw_surplus(&user_payload, surplus);
    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, &bytes)
        .unwrap_or_else(|err| panic!("{label} should decode for status inspection: {err}"));
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        &user_payload,
        "{label} did not preserve UDP user payload"
    );
    let udp_options = decoded
        .layer::<UdpOptions>()
        .unwrap_or_else(|| panic!("{label} did not expose UDP options"));
    assert_eq!(
        udp_options.status(),
        expected_status,
        "{label} returned unexpected UDP option status"
    );
    assert_eq!(
        udp_options.as_bytes(),
        expected_option_bytes,
        "{label} returned unexpected UDP option bytes"
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_slice());
}

#[test]
fn udp_options_ocs_absent_is_malformed_and_preserved() {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0x1111u16.to_be_bytes());
    datagram.extend_from_slice(&0x2222u16.to_be_bytes());
    datagram.extend_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.push(0);
    let bytes = (Ipv4::new()
        .src(src())
        .dst(dst())
        .ipv4_protocol(Ipv4Protocol::Udp)
        .id(0x2210)
        / Raw::from_bytes(datagram))
    .compile()
    .unwrap();

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(udp_options.option_checksum_value(), None);
    assert_eq!(udp_options.as_bytes(), &[]);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_options_ocs_auto_filled_valid_and_inspectable() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2211)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xaa, 0xbb])
        / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
    .compile()
    .unwrap();

    let surplus = udp_surplus(bytes.as_bytes());
    assert_eq!(surplus.len(), UDP_OPTION_CHECKSUM_LEN + 2);
    let ocs = u16::from_be_bytes([surplus[0], surplus[1]]);
    assert_ne!(ocs, 0);
    assert!(udp_surplus_checksum_valid(bytes.as_bytes()));

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.option_checksum_value(), Some(ocs));
    assert_eq!(
        udp_options.options(),
        &[UdpOption::NoOperation, UdpOption::EndOfList]
    );
    assert!(udp_options
        .inspection_fields()
        .iter()
        .any(|(name, value)| { *name == "ocs" && value == &format!("0x{ocs:04x}") }));
}

#[test]
fn udp_options_ocs_invalid_is_reported_and_preserved() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2212)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xaa, 0xbb])
        / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
    .compile()
    .unwrap();
    let mut invalid = bytes.as_bytes().to_vec();
    let surplus_start = udp_surplus_start(&invalid);
    invalid[surplus_start] ^= 0x01;
    assert!(!udp_surplus_checksum_valid(&invalid));

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, &invalid).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.status(), UdpOptionStatus::OptionChecksumInvalid);
    assert_eq!(decoded.compile().unwrap().as_bytes(), invalid.as_slice());
}

#[test]
fn udp_options_ocs_explicit_override_survives_compile() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2213)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xaa, 0xbb])
        / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]).option_checksum(0x1234))
    .compile()
    .unwrap();

    let surplus = udp_surplus(bytes.as_bytes());
    assert_eq!(
        &surplus[..UDP_OPTION_CHECKSUM_LEN],
        &0x1234u16.to_be_bytes()
    );
    assert!(!udp_surplus_checksum_valid(bytes.as_bytes()));

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.option_checksum_value(), Some(0x1234));
    assert_eq!(udp_options.status(), UdpOptionStatus::OptionChecksumInvalid);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_options_alignment_even_and_odd_surplus_offsets() {
    let even = (Ipv4::new().src(src()).dst(dst()).id(0x2214)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xaa, 0xbb])
        / UdpOptions::from_bytes([UDP_OPTION_EOL]))
    .compile()
    .unwrap();
    let even_surplus = udp_surplus(even.as_bytes());
    assert_eq!(even_surplus.len(), UDP_OPTION_CHECKSUM_LEN + 1);
    assert!(udp_surplus_checksum_valid(even.as_bytes()));
    let even_decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, even.as_bytes()).unwrap();
    assert_eq!(
        even_decoded
            .layer::<UdpOptions>()
            .unwrap()
            .alignment_bytes(),
        Some([].as_slice())
    );

    let odd = (Ipv4::new().src(src()).dst(dst()).id(0x2215)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xaa])
        / UdpOptions::from_bytes([UDP_OPTION_EOL]))
    .compile()
    .unwrap();
    let odd_surplus = udp_surplus(odd.as_bytes());
    assert_eq!(odd_surplus.len(), 1 + UDP_OPTION_CHECKSUM_LEN + 1);
    assert_eq!(odd_surplus[0], 0);
    assert!(udp_surplus_checksum_valid(odd.as_bytes()));
    let odd_decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, odd.as_bytes()).unwrap();
    let odd_options = odd_decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(odd_options.status(), UdpOptionStatus::Valid);
    assert_eq!(odd_options.alignment_bytes(), Some([0].as_slice()));
}

#[test]
fn udp_options_alignment_nonzero_fill_ignores_options() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2216)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xaa])
        / UdpOptions::from_bytes([UDP_OPTION_EOL]))
    .compile()
    .unwrap();
    let mut invalid = bytes.as_bytes().to_vec();
    let surplus_start = udp_surplus_start(&invalid);
    invalid[surplus_start] = 0x7f;

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, &invalid).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.status(), UdpOptionStatus::Ignored);
    assert_eq!(udp_options.alignment_bytes(), Some([0x7f].as_slice()));
    assert_eq!(decoded.compile().unwrap().as_bytes(), invalid.as_slice());
}

#[test]
fn udp_public_constants_and_statuses_are_stable() {
    assert_eq!(UDP_HEADER_LEN, 8);
    assert_eq!(UDP_OPTION_NOP, 1);
    assert_eq!(UDP_OPTION_APC, 2);
    assert_eq!(UDP_OPTION_FRAG, 3);
    assert_eq!(UDP_OPTION_MDS, 4);
    assert_eq!(UDP_OPTION_MRDS, 5);
    assert_eq!(UDP_OPTION_REQ, 6);
    assert_eq!(UDP_OPTION_RES, 7);
    assert_eq!(UDP_OPTION_TIME, 8);
    assert_eq!(UDP_OPTION_EXP, 127);
    assert_eq!(UDP_OPTION_UEXP, 254);

    let checksum_status = UdpChecksumStatus::NotChecked;
    let option_status = UdpOptionStatus::NotParsed;
    assert_eq!(checksum_status, UdpChecksumStatus::NotChecked);
    assert_eq!(option_status, UdpOptionStatus::NotParsed);
}

#[test]
fn udp_option_encode_decode_generic_forms() {
    let short = UdpOption::generic(UDP_OPTION_MDS, [0x05, 0xb4]);
    assert_eq!(short.kind(), UDP_OPTION_MDS);
    assert_eq!(short.data(), &[0x05, 0xb4]);
    assert!(!short.uses_extended_length());
    assert_eq!(short.encoded_len(), 4);
    assert_eq!(short.encode().unwrap(), vec![UDP_OPTION_MDS, 4, 0x05, 0xb4]);

    let extended = UdpOption::extended_generic(UDP_OPTION_EXP, [0x12, 0x34]);
    assert!(extended.uses_extended_length());
    assert_eq!(extended.encoded_len(), 6);
    assert_eq!(
        extended.encode().unwrap(),
        vec![UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34]
    );

    let decoded =
        UdpOption::decode_all(&[UDP_OPTION_NOP, UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34]).unwrap();
    assert_eq!(
        decoded,
        vec![
            UdpOption::NoOperation,
            UdpOption::ExtendedExperimental {
                exid_and_data: vec![0x12, 0x34]
            }
        ]
    );
}

#[test]
fn udp_option_apc_encode_decode_fixed_length() {
    let apc = UdpOption::additional_payload_checksum(0x0102_0304);
    assert_eq!(apc.kind(), UDP_OPTION_APC);
    assert_eq!(apc.data(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(apc.additional_payload_checksum_value(), Some(0x0102_0304));
    assert_eq!(apc.encoded_len(), UDP_OPTION_APC_LEN);
    assert_eq!(
        apc.encode().unwrap(),
        vec![
            UDP_OPTION_APC,
            UDP_OPTION_APC_LEN as u8,
            0x01,
            0x02,
            0x03,
            0x04
        ]
    );

    let decoded =
        UdpOption::decode_all(&[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8, 1, 2, 3, 4]).unwrap();
    assert_eq!(decoded, vec![apc]);

    let malformed_len = UdpOptions::from_bytes([UDP_OPTION_APC, 5, 1, 2, 3]);
    assert_eq!(
        malformed_len.status(),
        UdpOptionStatus::AdditionalPayloadChecksumInvalid
    );
}

#[test]
fn udp_option_mds_encode_decode_fixed_length_and_display() {
    let mds = UdpOption::maximum_datagram_size(1500);
    assert_eq!(mds, UdpOption::mds(1500));
    assert_eq!(mds.kind(), UDP_OPTION_MDS);
    assert_eq!(mds.data(), &1500u16.to_be_bytes());
    assert_eq!(mds.maximum_datagram_size_value(), Some(1500));
    assert_eq!(mds.maximum_reassembled_datagram_size_values(), None);
    assert!(!mds.uses_extended_length());
    assert_eq!(mds.encoded_len(), UDP_OPTION_MDS_LEN);
    assert_eq!(
        mds.encode().unwrap(),
        vec![UDP_OPTION_MDS, UDP_OPTION_MDS_LEN as u8, 0x05, 0xdc]
    );
    assert_eq!(mds.to_string(), "MDS(size=1500)");

    let decoded =
        UdpOption::decode_all(&[UDP_OPTION_MDS, UDP_OPTION_MDS_LEN as u8, 0x05, 0xdc]).unwrap();
    assert_eq!(decoded, vec![mds.clone()]);

    let udp_options = UdpOptions::from_bytes([UDP_OPTION_MDS, 4, 0x05, 0xdc]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), std::slice::from_ref(&mds));
    assert!(udp_options
        .inspection_fields()
        .iter()
        .any(|(name, value)| *name == "options" && value == "MDS(size=1500)"));

    let typed = UdpOptions::from_options(vec![mds]).unwrap();
    assert_eq!(typed.as_bytes(), &[UDP_OPTION_MDS, 4, 0x05, 0xdc]);
    assert_eq!(typed.status(), UdpOptionStatus::Valid);
}

#[test]
fn udp_option_mds_malformed_lengths_are_rejected() {
    for bytes in [
        [UDP_OPTION_MDS, 3, 0x05].as_slice(),
        [UDP_OPTION_MDS, 5, 0x05, 0xdc, 0x00].as_slice(),
        [UDP_OPTION_MDS, 255, 0, 4].as_slice(),
    ] {
        assert_udp_option_length_field_error(bytes, "udp.option.mds.length");
    }
}

#[test]
fn udp_option_mrds_encode_decode_fixed_length_and_display() {
    let mrds = UdpOption::maximum_reassembled_datagram_size(9000, 32);
    assert_eq!(mrds, UdpOption::mrds(9000, 32));
    assert_eq!(mrds.kind(), UDP_OPTION_MRDS);
    assert_eq!(mrds.data(), &[0x23, 0x28, 0x20]);
    assert_eq!(
        mrds.maximum_reassembled_datagram_size_values(),
        Some((9000, 32))
    );
    assert_eq!(mrds.maximum_datagram_size_value(), None);
    assert!(!mrds.uses_extended_length());
    assert_eq!(mrds.encoded_len(), UDP_OPTION_MRDS_LEN);
    assert_eq!(
        mrds.encode().unwrap(),
        vec![UDP_OPTION_MRDS, UDP_OPTION_MRDS_LEN as u8, 0x23, 0x28, 0x20]
    );
    assert_eq!(mrds.to_string(), "MRDS(size=9000,segments=32)");

    let decoded =
        UdpOption::decode_all(&[UDP_OPTION_MRDS, UDP_OPTION_MRDS_LEN as u8, 0x23, 0x28, 0x20])
            .unwrap();
    assert_eq!(decoded, vec![mrds.clone()]);

    let udp_options = UdpOptions::from_bytes([UDP_OPTION_MRDS, 5, 0x23, 0x28, 0x20]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), std::slice::from_ref(&mrds));
    assert!(udp_options
        .inspection_fields()
        .iter()
        .any(|(name, value)| { *name == "options" && value == "MRDS(size=9000,segments=32)" }));

    let typed = UdpOptions::from_options(vec![mrds]).unwrap();
    assert_eq!(typed.as_bytes(), &[UDP_OPTION_MRDS, 5, 0x23, 0x28, 0x20]);
    assert_eq!(typed.status(), UdpOptionStatus::Valid);
}

#[test]
fn udp_option_mrds_malformed_lengths_are_rejected() {
    for bytes in [
        [UDP_OPTION_MRDS, 4, 0x23, 0x28].as_slice(),
        [UDP_OPTION_MRDS, 6, 0x23, 0x28, 0x20, 0x00].as_slice(),
        [UDP_OPTION_MRDS, 255, 0, 5, 0x20].as_slice(),
    ] {
        assert_udp_option_length_field_error(bytes, "udp.option.mrds.length");
    }
}

#[test]
fn udp_option_req_encode_decode_fixed_length_and_display() {
    let req = UdpOption::echo_request(0x0102_0304);
    assert_eq!(req, UdpOption::req(0x0102_0304));
    assert_eq!(req.kind(), UDP_OPTION_REQ);
    assert_eq!(req.data(), &[0x01, 0x02, 0x03, 0x04]);
    assert_eq!(req.echo_request_token(), Some(0x0102_0304));
    assert_eq!(req.echo_response_token(), None);
    assert!(!req.uses_extended_length());
    assert_eq!(req.encoded_len(), UDP_OPTION_REQ_LEN);
    assert_eq!(
        req.encode().unwrap(),
        vec![
            UDP_OPTION_REQ,
            UDP_OPTION_REQ_LEN as u8,
            0x01,
            0x02,
            0x03,
            0x04
        ]
    );
    assert_eq!(req.to_string(), "REQ(token=0x01020304)");

    let decoded =
        UdpOption::decode_all(&[UDP_OPTION_REQ, UDP_OPTION_REQ_LEN as u8, 1, 2, 3, 4]).unwrap();
    assert_eq!(decoded, vec![req.clone()]);

    let udp_options = UdpOptions::from_bytes([UDP_OPTION_REQ, 6, 0x01, 0x02, 0x03, 0x04]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), std::slice::from_ref(&req));
    assert!(udp_options
        .inspection_fields()
        .iter()
        .any(|(name, value)| *name == "options" && value == "REQ(token=0x01020304)"));

    let typed = UdpOptions::from_options(vec![req]).unwrap();
    assert_eq!(
        typed.as_bytes(),
        &[UDP_OPTION_REQ, 6, 0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(typed.status(), UdpOptionStatus::Valid);
}

#[test]
fn udp_option_req_malformed_lengths_are_rejected() {
    for bytes in [
        [UDP_OPTION_REQ, 5, 0x01, 0x02, 0x03].as_slice(),
        [UDP_OPTION_REQ, 7, 0x01, 0x02, 0x03, 0x04, 0x05].as_slice(),
        [UDP_OPTION_REQ, 255, 0, 6, 0x01, 0x02].as_slice(),
    ] {
        assert_udp_option_length_field_error(bytes, "udp.option.req.length");
    }
}

#[test]
fn udp_option_res_encode_decode_fixed_length_and_display() {
    let res = UdpOption::echo_response(0x0a0b_0c0d);
    assert_eq!(res, UdpOption::res(0x0a0b_0c0d));
    assert_eq!(res.kind(), UDP_OPTION_RES);
    assert_eq!(res.data(), &[0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(res.echo_response_token(), Some(0x0a0b_0c0d));
    assert_eq!(res.echo_request_token(), None);
    assert!(!res.uses_extended_length());
    assert_eq!(res.encoded_len(), UDP_OPTION_RES_LEN);
    assert_eq!(
        res.encode().unwrap(),
        vec![
            UDP_OPTION_RES,
            UDP_OPTION_RES_LEN as u8,
            0x0a,
            0x0b,
            0x0c,
            0x0d
        ]
    );
    assert_eq!(res.to_string(), "RES(token=0x0a0b0c0d)");

    let decoded =
        UdpOption::decode_all(&[UDP_OPTION_RES, UDP_OPTION_RES_LEN as u8, 10, 11, 12, 13]).unwrap();
    assert_eq!(decoded, vec![res.clone()]);

    let udp_options = UdpOptions::from_bytes([UDP_OPTION_RES, 6, 0x0a, 0x0b, 0x0c, 0x0d]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), std::slice::from_ref(&res));
    assert!(udp_options
        .inspection_fields()
        .iter()
        .any(|(name, value)| *name == "options" && value == "RES(token=0x0a0b0c0d)"));

    let typed = UdpOptions::from_options(vec![res]).unwrap();
    assert_eq!(
        typed.as_bytes(),
        &[UDP_OPTION_RES, 6, 0x0a, 0x0b, 0x0c, 0x0d]
    );
    assert_eq!(typed.status(), UdpOptionStatus::Valid);
}

#[test]
fn udp_option_res_malformed_lengths_are_rejected() {
    for bytes in [
        [UDP_OPTION_RES, 5, 0x0a, 0x0b, 0x0c].as_slice(),
        [UDP_OPTION_RES, 7, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e].as_slice(),
        [UDP_OPTION_RES, 255, 0, 6, 0x0a, 0x0b].as_slice(),
    ] {
        assert_udp_option_length_field_error(bytes, "udp.option.res.length");
    }
}

#[test]
fn udp_option_time_encode_decode_fixed_length_and_display() {
    let time = UdpOption::timestamp(0x0102_0304, 0x0a0b_0c0d);
    assert_eq!(time, UdpOption::time(0x0102_0304, 0x0a0b_0c0d));
    assert_eq!(time.kind(), UDP_OPTION_TIME);
    assert_eq!(
        time.data(),
        &[0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c, 0x0d]
    );
    assert_eq!(time.timestamp_values(), Some((0x0102_0304, 0x0a0b_0c0d)));
    assert_eq!(time.echo_request_token(), None);
    assert_eq!(time.echo_response_token(), None);
    assert!(!time.uses_extended_length());
    assert_eq!(time.encoded_len(), UDP_OPTION_TIME_LEN);
    assert_eq!(
        time.encode().unwrap(),
        vec![
            UDP_OPTION_TIME,
            UDP_OPTION_TIME_LEN as u8,
            0x01,
            0x02,
            0x03,
            0x04,
            0x0a,
            0x0b,
            0x0c,
            0x0d
        ]
    );
    assert_eq!(time.to_string(), "TIME(tsval=0x01020304,tsecr=0x0a0b0c0d)");

    let decoded = UdpOption::decode_all(&[
        UDP_OPTION_TIME,
        UDP_OPTION_TIME_LEN as u8,
        1,
        2,
        3,
        4,
        10,
        11,
        12,
        13,
    ])
    .unwrap();
    assert_eq!(decoded, vec![time.clone()]);

    let udp_options = UdpOptions::from_bytes([
        UDP_OPTION_TIME,
        10,
        0x01,
        0x02,
        0x03,
        0x04,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
    ]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), std::slice::from_ref(&time));
    assert!(udp_options.inspection_fields().iter().any(|(name, value)| {
        *name == "options" && value == "TIME(tsval=0x01020304,tsecr=0x0a0b0c0d)"
    }));

    let typed = UdpOptions::from_options(vec![time]).unwrap();
    assert_eq!(
        typed.as_bytes(),
        &[
            UDP_OPTION_TIME,
            10,
            0x01,
            0x02,
            0x03,
            0x04,
            0x0a,
            0x0b,
            0x0c,
            0x0d
        ]
    );
    assert_eq!(typed.status(), UdpOptionStatus::Valid);
}

#[test]
fn udp_option_time_zero_values_are_explicitly_preserved() {
    let request = UdpOption::timestamp(0, 0);
    assert_eq!(request.timestamp_values(), Some((0, 0)));
    assert_eq!(
        request.encode().unwrap(),
        vec![
            UDP_OPTION_TIME,
            UDP_OPTION_TIME_LEN as u8,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0
        ]
    );
    assert_eq!(
        request.to_string(),
        "TIME(tsval=0x00000000,tsecr=0x00000000)"
    );
}

#[test]
fn udp_option_time_malformed_lengths_are_rejected() {
    for bytes in [
        [UDP_OPTION_TIME, 9, 0x01, 0x02, 0x03, 0x04, 0x0a, 0x0b, 0x0c].as_slice(),
        [
            UDP_OPTION_TIME,
            11,
            0x01,
            0x02,
            0x03,
            0x04,
            0x0a,
            0x0b,
            0x0c,
            0x0d,
            0x00,
        ]
        .as_slice(),
        [
            UDP_OPTION_TIME,
            255,
            0,
            10,
            0x01,
            0x02,
            0x03,
            0x04,
            0x0a,
            0x0b,
        ]
        .as_slice(),
    ] {
        assert_udp_option_length_field_error(bytes, "udp.option.time.length");
    }
}

#[test]
fn udp_option_exp_encode_decode_variable_length_and_display() {
    let empty_data: &[u8] = &[];
    let empty = UdpOption::experimental(0x1234, empty_data);
    assert_eq!(empty, UdpOption::exp(0x1234, empty_data));
    assert_eq!(empty.kind(), UDP_OPTION_EXP);
    assert_eq!(empty.data(), &[0x12, 0x34]);
    assert_eq!(empty.experiment_id(), Some(0x1234));
    assert_eq!(empty.experiment_data(), Some(empty_data));
    assert!(!empty.is_unsafe());
    assert!(!empty.uses_extended_length());
    assert_eq!(empty.encoded_len(), 4);
    assert_eq!(empty.encode().unwrap(), vec![UDP_OPTION_EXP, 4, 0x12, 0x34]);
    assert_eq!(empty.to_string(), "EXP(exid=0x1234,data=empty,safety=SAFE)");
    assert_eq!(
        UdpOption::decode_all(&[UDP_OPTION_EXP, 4, 0x12, 0x34]).unwrap(),
        vec![empty.clone()]
    );

    let non_empty = UdpOption::experimental(0xabcd, [0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(non_empty.data(), &[0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(non_empty.experiment_id(), Some(0xabcd));
    assert_eq!(
        non_empty.experiment_data(),
        Some([0xde, 0xad, 0xbe, 0xef].as_slice())
    );
    assert!(!non_empty.is_unsafe());
    assert_eq!(
        non_empty.encode().unwrap(),
        vec![UDP_OPTION_EXP, 8, 0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(
        non_empty.to_string(),
        "EXP(exid=0xabcd,data=de ad be ef,safety=SAFE)"
    );

    let udp_options =
        UdpOptions::from_bytes([UDP_OPTION_EXP, 8, 0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), std::slice::from_ref(&non_empty));
    assert!(udp_options.inspection_fields().iter().any(|(name, value)| {
        *name == "options" && value == "EXP(exid=0xabcd,data=de ad be ef,safety=SAFE)"
    }));

    let typed = UdpOptions::from_options(vec![non_empty]).unwrap();
    assert_eq!(
        typed.as_bytes(),
        &[UDP_OPTION_EXP, 8, 0xab, 0xcd, 0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(typed.status(), UdpOptionStatus::Valid);

    let long = UdpOption::experimental(0xbeef, vec![0x5a; 251]);
    assert!(long.uses_extended_length());
    let encoded = long.encode().unwrap();
    assert_eq!(
        &encoded[..6],
        &[UDP_OPTION_EXP, 255, 0x01, 0x01, 0xbe, 0xef]
    );
}

#[test]
fn udp_option_exp_malformed_lengths_are_rejected() {
    for bytes in [
        [UDP_OPTION_EXP, 3, 0x12].as_slice(),
        [UDP_OPTION_EXP, 255, 0, 4].as_slice(),
        [UDP_OPTION_EXP, 255, 0, 5, 0x12].as_slice(),
    ] {
        assert_udp_option_length_field_error(bytes, "udp.option.exp.length");
    }

    let malformed = UdpOption::Experimental {
        exid_and_data: vec![0x12],
    };
    assert_udp_option_encode_field_error(malformed, "udp.option.exp.length");
}

#[test]
fn udp_option_uexp_encode_decode_variable_length_and_safety() {
    let empty_data: &[u8] = &[];
    let empty = UdpOption::unsafe_experimental(0x5678, empty_data);
    assert_eq!(empty, UdpOption::uexp(0x5678, empty_data));
    assert_eq!(empty.kind(), UDP_OPTION_UEXP);
    assert_eq!(empty.data(), &[0x56, 0x78]);
    assert_eq!(empty.experiment_id(), Some(0x5678));
    assert_eq!(empty.experiment_data(), Some(empty_data));
    assert!(empty.is_unsafe());
    assert!(!empty.uses_extended_length());
    assert_eq!(empty.encoded_len(), 4);
    assert_eq!(
        empty.encode().unwrap(),
        vec![UDP_OPTION_UEXP, 4, 0x56, 0x78]
    );
    assert_eq!(
        empty.to_string(),
        "UEXP(exid=0x5678,data=empty,safety=UNSAFE)"
    );
    assert_eq!(
        UdpOption::decode_all(&[UDP_OPTION_UEXP, 4, 0x56, 0x78]).unwrap(),
        vec![empty.clone()]
    );

    let generic_unsafe = UdpOption::generic(UDP_OPTION_UEXP, [0x56, 0x78]);
    assert!(generic_unsafe.is_unsafe());

    let non_empty = UdpOption::unsafe_experimental(0xcafe, [0x01, 0x02, 0x03]);
    assert_eq!(non_empty.data(), &[0xca, 0xfe, 0x01, 0x02, 0x03]);
    assert_eq!(non_empty.experiment_id(), Some(0xcafe));
    assert_eq!(
        non_empty.experiment_data(),
        Some([0x01, 0x02, 0x03].as_slice())
    );
    assert!(non_empty.is_unsafe());
    assert_eq!(
        non_empty.encode().unwrap(),
        vec![UDP_OPTION_UEXP, 7, 0xca, 0xfe, 0x01, 0x02, 0x03]
    );
    assert_eq!(
        non_empty.to_string(),
        "UEXP(exid=0xcafe,data=01 02 03,safety=UNSAFE)"
    );

    let udp_options = UdpOptions::from_bytes([UDP_OPTION_UEXP, 7, 0xca, 0xfe, 0x01, 0x02, 0x03]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), std::slice::from_ref(&non_empty));
    assert!(udp_options.inspection_fields().iter().any(|(name, value)| {
        *name == "options" && value == "UEXP(exid=0xcafe,data=01 02 03,safety=UNSAFE)"
    }));

    let typed = UdpOptions::from_options(vec![non_empty]).unwrap();
    assert_eq!(
        typed.as_bytes(),
        &[UDP_OPTION_UEXP, 7, 0xca, 0xfe, 0x01, 0x02, 0x03]
    );
    assert_eq!(typed.status(), UdpOptionStatus::Valid);

    let long = UdpOption::unsafe_experimental(0xace0, vec![0x77; 251]);
    assert!(long.uses_extended_length());
    let encoded = long.encode().unwrap();
    assert_eq!(
        &encoded[..6],
        &[UDP_OPTION_UEXP, 255, 0x01, 0x01, 0xac, 0xe0]
    );
}

#[test]
fn udp_option_uexp_malformed_lengths_are_rejected() {
    for bytes in [
        [UDP_OPTION_UEXP, 3, 0x56].as_slice(),
        [UDP_OPTION_UEXP, 255, 0, 4].as_slice(),
        [UDP_OPTION_UEXP, 255, 0, 5, 0x56].as_slice(),
    ] {
        assert_udp_option_length_field_error(bytes, "udp.option.uexp.length");
    }

    let malformed = UdpOption::UnsafeExperimental {
        exid_and_data: vec![0x56],
    };
    assert_udp_option_encode_field_error(malformed, "udp.option.uexp.length");
}

#[test]
fn udp_option_unknown_safe_roundtrips_and_reports_metadata() {
    let option = UdpOption::generic(UDP_OPTION_UNASSIGNED_SAFE_START, [0xaa, 0xbb]);
    let encoded = [
        UDP_OPTION_UNASSIGNED_SAFE_START,
        4,
        0xaa,
        0xbb,
        UDP_OPTION_EOL,
    ];

    assert_eq!(option.kind_class(), UdpOptionKindClass::UnassignedSafe);
    assert!(!option.is_unsafe());
    assert!(!option.is_unsupported());
    assert_eq!(
        option.to_string(),
        "Generic(kind=10,len=4,class=UnassignedSafe,safety=SAFE)"
    );

    let udp_options = UdpOptions::from_bytes(encoded);
    assert_eq!(udp_options.status(), UdpOptionStatus::UnknownSafe);
    assert_eq!(
        udp_options.options(),
        &[option.clone(), UdpOption::EndOfList]
    );
    assert_eq!(udp_options.as_bytes(), &encoded);
    assert!(udp_options.summary().contains("status=UnknownSafe"));
    assert!(udp_options.summary().contains("UnassignedSafe"));
    assert!(udp_options.summary().contains("safety=SAFE"));

    let typed = UdpOptions::from_options(vec![option, UdpOption::EndOfList]).unwrap();
    assert_eq!(typed.as_bytes(), &encoded);
    assert_eq!(typed.status(), UdpOptionStatus::UnknownSafe);
}

#[test]
fn udp_option_unknown_unsafe_roundtrips_and_reports_unsupported_metadata() {
    let option = UdpOption::generic(UDP_OPTION_UNASSIGNED_UNSAFE_START, [0xde, 0xad]);
    let encoded = [
        UDP_OPTION_UNASSIGNED_UNSAFE_START,
        4,
        0xde,
        0xad,
        UDP_OPTION_MDS,
        4,
        0x05,
        0xdc,
    ];

    assert_eq!(option.kind_class(), UdpOptionKindClass::UnassignedUnsafe);
    assert!(option.is_unsafe());
    assert!(option.is_unsupported());
    assert_eq!(
        option.to_string(),
        "Generic(kind=194,len=4,class=UnassignedUnsafe,safety=UNSAFE,support=unsupported)"
    );

    let udp_options = UdpOptions::from_bytes(encoded);
    assert_eq!(udp_options.status(), UdpOptionStatus::UnknownUnsafe);
    assert_eq!(udp_options.options(), std::slice::from_ref(&option));
    assert_eq!(udp_options.as_bytes(), &encoded);
    assert!(udp_options.summary().contains("status=UnknownUnsafe"));
    assert!(udp_options.summary().contains("UnassignedUnsafe"));
    assert!(udp_options.summary().contains("safety=UNSAFE"));

    let packet = Ipv4::new().src(src()).dst(dst()).id(0x2246)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0x55])
        / UdpOptions::from_options(vec![option]).unwrap();
    let compiled = packet.compile().unwrap();
    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
    let decoded_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(decoded_options.status(), UdpOptionStatus::UnknownUnsafe);
    assert_eq!(
        decoded_options.options(),
        &[UdpOption::generic(
            UDP_OPTION_UNASSIGNED_UNSAFE_START,
            [0xde, 0xad],
        )]
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
}

#[test]
fn udp_option_frag_unsupported_preserves_valid_and_malformed_bytes() {
    let frag10 = UdpOption::generic(
        UDP_OPTION_FRAG,
        [0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xdd],
    );
    let frag12 = UdpOption::generic(
        UDP_OPTION_FRAG,
        [0x00, 0x02, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
    );

    assert_eq!(frag10.encoded_len(), UDP_OPTION_FRAG_SHORT_LEN);
    assert_eq!(frag12.encoded_len(), UDP_OPTION_FRAG_LONG_LEN);
    assert_eq!(frag10.kind_class(), UdpOptionKindClass::KnownSafe);
    assert!(!frag10.is_unsafe());
    assert!(frag10.is_unsupported());
    assert_eq!(
        frag10.to_string(),
        "Generic(kind=3,len=10,class=KnownSafe,safety=SAFE,support=unsupported)"
    );

    let valid10 = UdpOptions::from_options(vec![frag10.clone()]).unwrap();
    assert_eq!(valid10.status(), UdpOptionStatus::UnsupportedFragmentation);
    assert_eq!(valid10.options(), std::slice::from_ref(&frag10));
    assert_eq!(
        valid10.as_bytes(),
        &[
            UDP_OPTION_FRAG,
            UDP_OPTION_FRAG_SHORT_LEN as u8,
            0x00,
            0x01,
            0x00,
            0x03,
            0xaa,
            0xbb,
            0xcc,
            0xdd
        ]
    );

    let valid12 = UdpOptions::from_options(vec![frag12.clone()]).unwrap();
    assert_eq!(valid12.status(), UdpOptionStatus::UnsupportedFragmentation);
    assert_eq!(valid12.options(), std::slice::from_ref(&frag12));

    let malformed_short = [UDP_OPTION_FRAG, 9, 0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc];
    let malformed = UdpOptions::from_bytes(malformed_short);
    assert_eq!(malformed.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(malformed.as_bytes(), &malformed_short);
    assert_eq!(
        malformed.options(),
        &[UdpOption::generic(
            UDP_OPTION_FRAG,
            [0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb, 0xcc],
        )]
    );

    let malformed_extended = [
        UDP_OPTION_FRAG,
        255,
        0,
        10,
        0x00,
        0x01,
        0x00,
        0x03,
        0xaa,
        0xbb,
    ];
    let malformed = UdpOptions::from_bytes(malformed_extended);
    assert_eq!(malformed.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(malformed.as_bytes(), &malformed_extended);
    assert_eq!(
        malformed.options(),
        &[UdpOption::ExtendedGeneric {
            kind: UDP_OPTION_FRAG,
            data: vec![0x00, 0x01, 0x00, 0x03, 0xaa, 0xbb],
        }]
    );

    let user_payload = [0x55, 0x66];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2247)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(user_payload)
        / UdpOptions::from_options(vec![frag12.clone()]).unwrap())
    .compile()
    .unwrap();
    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();
    let decoded_options = decoded.layer::<UdpOptions>().unwrap();

    assert_eq!(raw_layers.len(), 1);
    assert_eq!(raw_layers[0].as_bytes(), user_payload);
    assert_eq!(
        decoded_options.status(),
        UdpOptionStatus::UnsupportedFragmentation
    );
    assert_eq!(decoded_options.options(), &[frag12]);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_option_metadata_classifies_registry_ranges() {
    assert_eq!(
        udp_option_kind_class(UDP_OPTION_MDS),
        UdpOptionKindClass::KnownSafe
    );
    assert_eq!(
        udp_option_kind_class(UDP_OPTION_FRAG),
        UdpOptionKindClass::KnownSafe
    );
    assert!(udp_option_kind_is_unsupported(UDP_OPTION_FRAG));

    assert_eq!(
        udp_option_kind_class(UDP_OPTION_AUTH),
        UdpOptionKindClass::ReservedSafe
    );
    assert!(!udp_option_kind_is_unsafe(UDP_OPTION_AUTH));
    assert!(!udp_option_kind_is_unsupported(UDP_OPTION_AUTH));

    assert_eq!(
        udp_option_kind_class(UDP_OPTION_RESERVED_SAFE_START),
        UdpOptionKindClass::ReservedSafe
    );
    assert_eq!(
        udp_option_kind_class(UDP_OPTION_UCMP),
        UdpOptionKindClass::ReservedUnsafe
    );
    assert!(udp_option_kind_is_unsafe(UDP_OPTION_UCMP));
    assert!(udp_option_kind_is_unsupported(UDP_OPTION_UCMP));

    assert_eq!(
        udp_option_kind_class(UDP_OPTION_UNASSIGNED_SAFE_START),
        UdpOptionKindClass::UnassignedSafe
    );
    assert_eq!(
        udp_option_kind_class(UDP_OPTION_UNASSIGNED_UNSAFE_START),
        UdpOptionKindClass::UnassignedUnsafe
    );
    assert!(udp_option_kind_is_unsupported(
        UDP_OPTION_UNASSIGNED_UNSAFE_START
    ));

    assert_eq!(
        udp_option_kind_class(UDP_OPTION_EXP),
        UdpOptionKindClass::ExperimentalSafe
    );
    assert_eq!(
        udp_option_kind_class(UDP_OPTION_UEXP),
        UdpOptionKindClass::ExperimentalUnsafe
    );
    assert!(!udp_option_kind_is_unsupported(UDP_OPTION_UEXP));

    assert_eq!(
        udp_option_kind_class(UDP_OPTION_RESERVED_UNSAFE),
        UdpOptionKindClass::ReservedUnsafe
    );
    assert!(udp_option_kind_is_unsupported(UDP_OPTION_RESERVED_UNSAFE));
}

#[test]
fn udp_option_status_values_appear_in_inspection_fields_and_roundtrip() {
    let frag = [
        UDP_OPTION_FRAG,
        UDP_OPTION_FRAG_SHORT_LEN as u8,
        0x00,
        0x01,
        0x00,
        0x03,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
    ];
    let cases: [(&[u8], UdpOptionStatus); 8] = [
        (&[UDP_OPTION_NOP, UDP_OPTION_EOL], UdpOptionStatus::Valid),
        (&[UDP_OPTION_MDS, 1], UdpOptionStatus::MalformedEnvelope),
        (
            &[UDP_OPTION_EOL, 0, 0x5a],
            UdpOptionStatus::NonzeroAfterEndOfList,
        ),
        (&[UDP_OPTION_NOP; 8], UdpOptionStatus::TooManyNoOperations),
        (&frag, UdpOptionStatus::UnsupportedFragmentation),
        (
            &[UDP_OPTION_UNASSIGNED_SAFE_START, 2, UDP_OPTION_EOL],
            UdpOptionStatus::UnknownSafe,
        ),
        (
            &[
                UDP_OPTION_UNASSIGNED_UNSAFE_START,
                2,
                UDP_OPTION_MDS,
                4,
                0x05,
                0xdc,
            ],
            UdpOptionStatus::UnknownUnsafe,
        ),
        (
            &[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8, 0, 0, 0, 0],
            UdpOptionStatus::AdditionalPayloadChecksumInvalid,
        ),
    ];

    for (option_bytes, expected_status) in cases {
        assert_decoded_udp_options_status_roundtrip(option_bytes, expected_status);
    }

    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2251)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0x55])
        / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
    .compile()
    .unwrap();
    let mut invalid_ocs = bytes.as_bytes().to_vec();
    let surplus_start = udp_surplus_start(&invalid_ocs);
    let ocs_start = surplus_start + (surplus_start & 1);
    invalid_ocs[ocs_start] ^= 0x01;

    let decoded =
        Packet::decode_from_l3(crate::NetworkLayer::Ipv4, invalid_ocs.as_slice()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_udp_options_status_surface(udp_options, UdpOptionStatus::OptionChecksumInvalid);
    assert!(decoded.show().contains("status: OptionChecksumInvalid"));
    assert_eq!(
        decoded.compile().unwrap().as_bytes(),
        invalid_ocs.as_slice()
    );
}

#[test]
fn udp_options_summary_exposes_processing_policy_statuses() {
    let known = UdpOptions::from_bytes([UDP_OPTION_TIME, 10, 1, 2, 3, 4, 5, 6, 7, 8]);
    let unknown_safe = UdpOptions::from_bytes([UDP_OPTION_UNASSIGNED_SAFE_START, 2]);
    let unknown_unsafe = UdpOptions::from_bytes([UDP_OPTION_UNASSIGNED_UNSAFE_START, 2]);
    let frag = UdpOptions::from_bytes([
        UDP_OPTION_FRAG,
        UDP_OPTION_FRAG_LONG_LEN as u8,
        0x00,
        0x02,
        0x00,
        0x04,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
    ]);

    assert_udp_options_status_surface(&known, UdpOptionStatus::Valid);
    assert_udp_options_status_surface(&unknown_safe, UdpOptionStatus::UnknownSafe);
    assert_udp_options_status_surface(&unknown_unsafe, UdpOptionStatus::UnknownUnsafe);
    assert_udp_options_status_surface(&frag, UdpOptionStatus::UnsupportedFragmentation);
    assert!(known.summary().contains("TIME(tsval=0x01020304"));
    assert!(unknown_safe.summary().contains("class=UnassignedSafe"));
    assert!(unknown_unsafe.summary().contains("safety=UNSAFE"));
    assert!(frag.summary().contains("support=unsupported"));

    let packet = Ipv4::new().src(src()).dst(dst()).id(0x2252)
        / Udp::new().sport(1234).dport(4321)
        / unknown_safe.clone();
    assert!(packet.summary().contains("status=UnknownSafe"));
}

#[test]
fn udp_options_show_includes_time_option() {
    let packet = Ipv4::new().src(src()).dst(dst()).id(0x2241)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xde, 0xad])
        / UdpOptions::from_options(vec![UdpOption::timestamp(0x0102_0304, 0)]).unwrap();

    let show = packet.show();
    assert!(show.contains("UdpOptions"));
    assert!(show.contains("options: TIME(tsval=0x01020304,tsecr=0x00000000)"));
}

#[test]
fn udp_option_apc_valid_auto_fill_decodes_valid_status() {
    let payload = [0xde, 0xad, 0xbe, 0xef];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2240)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / UdpOptions::new().additional_payload_checksum())
    .compile()
    .unwrap();

    assert!(udp_surplus_checksum_valid(bytes.as_bytes()));

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(apc_checksum_value(udp_options), crc32c(&payload));
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_option_apc_invalid_crc_reports_status() {
    let payload = [0x10, 0x20, 0x30, 0x40];
    let wrong = crc32c(&payload) ^ 0x0000_0001;
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2241)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / UdpOptions::new().additional_payload_checksum_value(wrong))
    .compile()
    .unwrap();

    assert!(udp_surplus_checksum_valid(bytes.as_bytes()));

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(
        udp_options.status(),
        UdpOptionStatus::AdditionalPayloadChecksumInvalid
    );
    assert_eq!(apc_checksum_value(udp_options), wrong);
}

#[test]
fn udp_option_apc_explicit_override_survives_compile() {
    let override_checksum = 0x1234_5678;
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2242)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes([0xaa, 0xbb])
        / UdpOptions::new().additional_payload_checksum_value(override_checksum))
    .compile()
    .unwrap();

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(
        &udp_options.as_bytes()[..UDP_OPTION_APC_LEN],
        &[
            UDP_OPTION_APC,
            UDP_OPTION_APC_LEN as u8,
            0x12,
            0x34,
            0x56,
            0x78
        ]
    );
    assert_eq!(apc_checksum_value(udp_options), override_checksum);
    assert_eq!(
        udp_options.status(),
        UdpOptionStatus::AdditionalPayloadChecksumInvalid
    );
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_option_apc_zero_length_user_data() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2243)
        / Udp::new().sport(1234).dport(4321)
        / UdpOptions::new().additional_payload_checksum())
    .compile()
    .unwrap();

    assert_eq!(udp_length(bytes.as_bytes()), UDP_HEADER_LEN);

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(apc_checksum_value(udp_options), crc32c(&[]));
    assert!(decoded.layers::<Raw>().next().is_none());
}

#[test]
fn udp_option_apc_odd_length_user_data() {
    let payload = [0xaa, 0xbb, 0xcc];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2244)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / UdpOptions::new().additional_payload_checksum())
    .compile()
    .unwrap();

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.alignment_bytes(), Some([0].as_slice()));
    assert_eq!(apc_checksum_value(udp_options), crc32c(&payload));
}

#[test]
fn udp_options_apc_payload_boundary_uses_user_data_only() {
    let payload = [0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64];
    let udp_options = UdpOptions::new()
        .additional_payload_checksum()
        .udp_option(UdpOption::NoOperation)
        .unwrap()
        .udp_option(UdpOption::EndOfList)
        .unwrap();
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2245)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / udp_options)
        .compile()
        .unwrap();

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    let apc = apc_checksum_value(udp_options);

    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(
        &bytes.as_bytes()[20 + UDP_HEADER_LEN..udp_surplus_start(bytes.as_bytes())],
        payload.as_slice()
    );
    assert_eq!(apc, crc32c(&payload));

    let mut payload_plus_options = payload.to_vec();
    payload_plus_options.extend_from_slice(udp_options.as_bytes());
    assert_ne!(apc, crc32c(&payload_plus_options));
}

#[test]
fn udp_option_length_parses_one_byte_short_and_extended_envelopes() {
    let decoded = UdpOption::decode_all(&[UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0]).unwrap();
    assert_eq!(decoded, vec![UdpOption::NoOperation, UdpOption::EndOfList]);

    let decoded = UdpOption::decode_all(&[UDP_OPTION_MDS, 4, 0x05, 0xb4]).unwrap();
    assert_eq!(decoded, vec![UdpOption::maximum_datagram_size(0x05b4)]);

    let decoded = UdpOption::decode_all(&[UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34]).unwrap();
    assert_eq!(
        decoded,
        vec![UdpOption::ExtendedExperimental {
            exid_and_data: vec![0x12, 0x34]
        }]
    );
}

#[test]
fn udp_option_length_reports_short_envelope_errors() {
    assert_udp_option_length_buffer_error(&[UDP_OPTION_MDS], "udp option length", 2, 1);
    assert_udp_option_length_field_error(&[UDP_OPTION_MDS, 0], "udp.option.length");
    assert_udp_option_length_field_error(&[UDP_OPTION_MDS, 1], "udp.option.length");
    assert_udp_option_length_buffer_error(&[UDP_OPTION_MDS, 4, 0xaa], "udp option payload", 4, 3);
}

#[test]
fn udp_option_length_reports_extended_envelope_errors() {
    assert_udp_option_length_buffer_error(
        &[UDP_OPTION_EXP, 255],
        "udp option extended length",
        4,
        2,
    );
    assert_udp_option_length_buffer_error(
        &[UDP_OPTION_EXP, 255, 0],
        "udp option extended length",
        4,
        3,
    );
    assert_udp_option_length_field_error(
        &[UDP_OPTION_EXP, 255, 0, 0],
        "udp.option.extended_length",
    );
    assert_udp_option_length_field_error(
        &[UDP_OPTION_EXP, 255, 0, 1],
        "udp.option.extended_length",
    );
    assert_udp_option_length_field_error(
        &[UDP_OPTION_EXP, 255, 0, 3],
        "udp.option.extended_length",
    );
    assert_udp_option_length_buffer_error(
        &[UDP_OPTION_EXP, 255, 0, 6, 0xaa],
        "udp option extended payload",
        6,
        5,
    );
}

#[test]
fn udp_option_length_preserves_valid_prefix_before_malformed_envelope() {
    let bytes = [UDP_OPTION_NOP, UDP_OPTION_MDS, 4, 0xaa];
    let udp_options = UdpOptions::from_bytes(bytes);

    assert_eq!(udp_options.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(udp_options.as_bytes(), &bytes);
    assert_eq!(udp_options.options(), &[UdpOption::NoOperation]);
}

#[test]
fn udp_option_eol_encode_decode_and_inspection_output() {
    let eol = UdpOption::end_of_list();
    assert_eq!(eol, UdpOption::EndOfList);
    assert_eq!(eol.kind(), UDP_OPTION_EOL);
    assert_eq!(eol.data(), &[]);
    assert_eq!(eol.encoded_len(), 1);
    assert_eq!(eol.encode().unwrap(), vec![UDP_OPTION_EOL]);

    let decoded = UdpOption::decode_all(&[UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0, 0]).unwrap();
    assert_eq!(decoded, vec![UdpOption::NoOperation, UdpOption::EndOfList]);

    let udp_options = UdpOptions::from_bytes([UDP_OPTION_EOL, 0, 0]);
    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.options(), &[UdpOption::EndOfList]);
    assert_eq!(udp_options.as_bytes(), &[UDP_OPTION_EOL, 0, 0]);
    assert!(udp_options.summary().contains("status=Valid"));
    assert!(udp_options
        .inspection_fields()
        .iter()
        .any(|(name, value)| *name == "options" && value == "EOL"));
}

#[test]
fn udp_option_nop_encode_decode_padding_and_limit() {
    let nop = UdpOption::no_operation();
    assert_eq!(nop, UdpOption::NoOperation);
    assert_eq!(nop.kind(), UDP_OPTION_NOP);
    assert_eq!(nop.data(), &[]);
    assert_eq!(nop.encoded_len(), 1);
    assert_eq!(nop.encode().unwrap(), vec![UDP_OPTION_NOP]);

    let seven_nops = [UDP_OPTION_NOP; 7];
    let decoded = UdpOption::decode_all(&seven_nops).unwrap();
    assert_eq!(decoded, vec![UdpOption::NoOperation; 7]);
    assert_eq!(
        UdpOptions::from_bytes(seven_nops).status(),
        UdpOptionStatus::Valid
    );

    let eight_nops = [UDP_OPTION_NOP; 8];
    assert_eq!(
        UdpOptions::from_bytes(eight_nops).status(),
        UdpOptionStatus::TooManyNoOperations
    );
    match UdpOption::decode_all(&eight_nops).unwrap_err() {
        crate::CrafterError::InvalidFieldValue { field, .. } => {
            assert_eq!(field, "udp.option.nop");
        }
        other => panic!("expected excessive NOP validation error, got {other:?}"),
    }
}

#[test]
fn udp_option_iterator_reports_malformed_lengths() {
    let mut iter = UdpOptionIter::new(&[UDP_OPTION_MDS, 1]);
    match iter.next().unwrap() {
        Err(crate::CrafterError::InvalidFieldValue { field, .. }) => {
            assert_eq!(field, "udp.option.length");
        }
        other => panic!("expected malformed short length, got {other:?}"),
    }
    assert!(iter.next().is_none());

    match UdpOption::decode_all(&[UDP_OPTION_EXP, 255, 0, 8, 0xaa]).unwrap_err() {
        crate::CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "udp option extended payload");
            assert_eq!(required, 8);
            assert_eq!(available, 5);
        }
        other => panic!("expected malformed extended length, got {other:?}"),
    }
}

#[test]
fn udp_options_padding_empty_zero_fill_and_nonzero_after_eol() {
    let empty = UdpOptions::new();
    assert!(empty.is_empty());
    assert_eq!(empty.status(), UdpOptionStatus::NoSurplus);
    assert_eq!(empty.options(), &[]);

    let zero_fill = UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0, 0]);
    assert_eq!(zero_fill.status(), UdpOptionStatus::Valid);
    assert_eq!(
        zero_fill.options(),
        &[UdpOption::NoOperation, UdpOption::EndOfList]
    );
    assert_eq!(
        zero_fill.as_bytes(),
        &[UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0, 0]
    );

    let nonzero_fill = UdpOptions::from_bytes([UDP_OPTION_EOL, 0, 0x5a]);
    assert_eq!(
        nonzero_fill.status(),
        UdpOptionStatus::NonzeroAfterEndOfList
    );
    assert_eq!(nonzero_fill.options(), &[UdpOption::EndOfList]);
    assert_eq!(nonzero_fill.as_bytes(), &[UDP_OPTION_EOL, 0, 0x5a]);

    match UdpOption::decode_all(nonzero_fill.as_bytes()).unwrap_err() {
        crate::CrafterError::InvalidFieldValue { field, .. } => {
            assert_eq!(field, "udp.option.eol_padding");
        }
        other => panic!("expected EOL padding validation error, got {other:?}"),
    }
}

#[test]
fn udp_options_layer_preserves_bytes_and_caches_parse_status() {
    let bytes = [UDP_OPTION_NOP, UDP_OPTION_EXP, 255, 0, 6, 0x12, 0x34];
    let udp_options = UdpOptions::from_bytes(bytes);

    assert_eq!(udp_options.status(), UdpOptionStatus::Valid);
    assert_eq!(udp_options.as_bytes(), &bytes);
    assert_eq!(
        udp_options.options(),
        &[
            UdpOption::NoOperation,
            UdpOption::ExtendedExperimental {
                exid_and_data: vec![0x12, 0x34]
            }
        ]
    );
    assert_eq!(udp_options.parsed_options().unwrap(), udp_options.options());

    let typed = UdpOptions::from_options(vec![
        UdpOption::NoOperation,
        UdpOption::generic(UDP_OPTION_MDS, [0x05, 0xb4]),
    ])
    .unwrap();
    assert_eq!(
        typed.as_bytes(),
        &[UDP_OPTION_NOP, UDP_OPTION_MDS, 4, 0x05, 0xb4]
    );

    let malformed = UdpOptions::from_bytes([UDP_OPTION_MDS, 1]);
    assert_eq!(malformed.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(malformed.as_bytes(), &[UDP_OPTION_MDS, 1]);
}

#[test]
fn udp_option_malformed_status_boundary_preserves_udp_payload() {
    assert_udp_option_malformed_status(
        "short surplus envelope",
        &[0],
        &[],
        UdpOptionStatus::MalformedEnvelope,
    );
    assert_udp_option_malformed_status(
        "invalid fixed MDS length",
        &[0, 0, UDP_OPTION_MDS, 3, 0xaa],
        &[UDP_OPTION_MDS, 3, 0xaa],
        UdpOptionStatus::MalformedEnvelope,
    );
    assert_udp_option_malformed_status(
        "extended length overrun",
        &[0, 0, UDP_OPTION_EXP, 255, 0, 8, 0xaa],
        &[UDP_OPTION_EXP, 255, 0, 8, 0xaa],
        UdpOptionStatus::MalformedEnvelope,
    );
    assert_udp_option_malformed_status(
        "nonzero after EOL",
        &[0, 0, UDP_OPTION_EOL, 0, 0x5a],
        &[UDP_OPTION_EOL, 0, 0x5a],
        UdpOptionStatus::NonzeroAfterEndOfList,
    );
    assert_udp_option_malformed_status(
        "invalid OCS",
        &[0x12, 0x34, UDP_OPTION_NOP, UDP_OPTION_EOL],
        &[UDP_OPTION_NOP, UDP_OPTION_EOL],
        UdpOptionStatus::OptionChecksumInvalid,
    );
    assert_udp_option_malformed_status(
        "invalid APC",
        &[0, 0, UDP_OPTION_APC, 6, 0, 0, 0, 1],
        &[UDP_OPTION_APC, 6, 0, 0, 0, 1],
        UdpOptionStatus::AdditionalPayloadChecksumInvalid,
    );
    assert_udp_option_malformed_status(
        "malformed FRAG",
        &[0, 0, UDP_OPTION_FRAG, 4, 0xaa, 0xbb],
        &[UDP_OPTION_FRAG, 4, 0xaa, 0xbb],
        UdpOptionStatus::MalformedEnvelope,
    );
}

#[test]
fn udp_autofills_length_and_ipv4_checksum_for_odd_payload() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2222)
        / Udp::new().sport(0x1234).dport(53)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap();

    assert_eq!(&bytes.as_bytes()[2..4], &(31u16).to_be_bytes());
    assert_eq!(&bytes.as_bytes()[20..22], &0x1234u16.to_be_bytes());
    assert_eq!(&bytes.as_bytes()[22..24], &53u16.to_be_bytes());
    assert_eq!(&bytes.as_bytes()[24..26], &11u16.to_be_bytes());
    let mut udp = bytes.as_bytes()[20..].to_vec();
    udp[6] = 0;
    udp[7] = 0;
    assert_eq!(
        u16::from_be_bytes([bytes.as_bytes()[26], bytes.as_bytes()[27]]),
        ipv4_pseudo_header_checksum(src(), dst(), IPPROTO_UDP, &udp)
    );
}

#[test]
fn udp_length_eight_and_zero_ports_are_preserved() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2223)
        / Udp::new().sport(0).dport(0).checksum(0))
    .compile()
    .unwrap();

    assert_eq!(&bytes.as_bytes()[20..22], &0u16.to_be_bytes());
    assert_eq!(&bytes.as_bytes()[22..24], &0u16.to_be_bytes());
    assert_eq!(
        &bytes.as_bytes()[24..26],
        &(UDP_HEADER_LEN as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp = decoded.layer::<Udp>().unwrap();
    assert_eq!(udp.source_port_value(), 0);
    assert_eq!(udp.destination_port_value(), 0);
    assert_eq!(udp.length_value(), Some(UDP_HEADER_LEN as u16));
    assert!(decoded.layers::<Raw>().next().is_none());
    assert!(decoded.layers::<UdpOptions>().next().is_none());
}

#[test]
fn explicit_udp_length_is_preserved() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2224)
        / Udp::new().sport(0x1234).dport(0x5678).len(42)
        / Raw::from("abc"))
    .compile()
    .unwrap();

    assert_eq!(&bytes.as_bytes()[2..4], &(31u16).to_be_bytes());
    assert_eq!(&bytes.as_bytes()[24..26], &(42u16).to_be_bytes());
}

#[test]
fn udp_decode_from_ipv4_exposes_ports_and_payload() {
    let decoded = Packet::decode_from_link(LinkType::Ethernet, VLAN_FIXTURE).unwrap();
    let udp = decoded.layer::<Udp>().unwrap();
    let raw = decoded.layer::<Raw>().unwrap();

    assert_eq!(udp.source_port_value(), 53002);
    assert_eq!(udp.destination_port_value(), 9999);
    assert_eq!(udp.length_value(), Some(16));
    assert_eq!(udp.checksum_value(), Some(0xb3a1));
    assert_eq!(raw.as_bytes(), b"vlan-udp");
    assert_eq!(decoded.compile().unwrap().as_bytes(), VLAN_FIXTURE);
}

#[test]
fn explicit_udp_checksum_is_preserved() {
    for checksum in [0, 0x1badu16] {
        let bytes =
            (Ipv4::new().src(src()).dst(dst()) / Udp::new().checksum(checksum) / Raw::from("abc"))
                .compile()
                .unwrap();

        assert_eq!(&bytes.as_bytes()[26..28], &checksum.to_be_bytes());
    }
}

#[test]
fn udp_checksum_generation_ipv4_matches_hand_computed_without_options() {
    let payload = [0xde, 0xad, 0xbe];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2270)
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes(payload))
    .compile()
    .unwrap();

    assert_eq!(udp_length(bytes.as_bytes()), UDP_HEADER_LEN + payload.len());
    assert_eq!(
        udp_checksum(bytes.as_bytes()),
        expected_ipv4_udp_checksum(bytes.as_bytes(), payload.len())
    );
}

#[test]
fn udp_checksum_generation_ipv4_excludes_surplus_options() {
    let payload = [0xaa, 0xbb, 0xcc];
    let option_bytes = [UDP_OPTION_NOP, UDP_OPTION_EOL];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2271)
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes(payload)
        / UdpOptions::from_bytes(option_bytes).option_checksum(0x1234))
    .compile()
    .unwrap();

    assert_eq!(udp_length(bytes.as_bytes()), UDP_HEADER_LEN + payload.len());
    assert_eq!(
        udp_checksum(bytes.as_bytes()),
        expected_ipv4_udp_checksum(bytes.as_bytes(), payload.len())
    );
    assert_ne!(
        udp_checksum(bytes.as_bytes()),
        expected_ipv4_checksum_if_surplus_were_included(bytes.as_bytes())
    );
}

#[test]
fn udp_checksum_generation_ipv6_matches_hand_computed_without_options() {
    let payload = [0xde, 0xad, 0xbe];
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes(payload))
    .compile()
    .unwrap();

    assert_eq!(
        ipv6_udp_length(bytes.as_bytes()),
        UDP_HEADER_LEN + payload.len()
    );
    assert_eq!(
        ipv6_udp_checksum(bytes.as_bytes()),
        expected_ipv6_udp_checksum(bytes.as_bytes(), payload.len())
    );
}

#[test]
fn udp_checksum_generation_ipv6_excludes_surplus_options() {
    let payload = [0xaa, 0xbb, 0xcc];
    let option_bytes = [UDP_OPTION_NOP, UDP_OPTION_EOL];
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes(payload)
        / UdpOptions::from_bytes(option_bytes).option_checksum(0x1234))
    .compile()
    .unwrap();

    assert_eq!(
        ipv6_udp_length(bytes.as_bytes()),
        UDP_HEADER_LEN + payload.len()
    );
    assert_eq!(
        ipv6_udp_checksum(bytes.as_bytes()),
        expected_ipv6_udp_checksum(bytes.as_bytes(), payload.len())
    );
    assert_ne!(
        ipv6_udp_checksum(bytes.as_bytes()),
        expected_ipv6_checksum_if_surplus_were_included(bytes.as_bytes())
    );
}

#[test]
fn udp_checksum_generation_auto_zero_is_transmitted_as_ffff_ipv4() {
    let payload = [0xaa, 0xf6];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2272)
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes(payload))
    .compile()
    .unwrap();

    let udp = zeroed_ipv4_udp_checksum_input(bytes.as_bytes(), payload.len());
    assert_eq!(
        ipv4_pseudo_header_checksum(src(), dst(), IPPROTO_UDP, &udp),
        0
    );
    assert_eq!(udp_checksum(bytes.as_bytes()), 0xffff);
}

#[test]
fn udp_checksum_generation_auto_zero_is_transmitted_as_ffff_ipv6() {
    let payload = [0x3b, 0xb9];
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes(payload))
    .compile()
    .unwrap();

    let udp = zeroed_ipv6_udp_checksum_input(bytes.as_bytes(), payload.len());
    assert_eq!(
        ipv6_pseudo_header_checksum(ipv6_src(), ipv6_dst(), IPPROTO_UDP, &udp),
        0
    );
    assert_eq!(ipv6_udp_checksum(bytes.as_bytes()), 0xffff);
}

#[test]
fn udp_checksum_generation_explicit_ipv4_zero_survives_with_surplus() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2273)
        / Udp::new().sport(0x1234).dport(0x5678).checksum(0)
        / Raw::from_bytes([0xde, 0xad, 0xbe])
        / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
    .compile()
    .unwrap();

    assert_eq!(udp_checksum(bytes.as_bytes()), 0);
}

#[test]
fn udp_checksum_status_ipv4_valid() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2280)
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap();

    let decoded = assert_udp_checksum_status(
        crate::NetworkLayer::Ipv4,
        bytes.as_bytes(),
        UdpChecksumStatus::Valid,
    );
    assert!(decoded.summary().contains("checksum_status=Valid"));
    assert!(decoded.show().contains("checksum_status: Valid"));
}

#[test]
fn udp_checksum_status_ipv4_invalid() {
    let mut bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2281)
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap()
    .into_bytes();
    let checksum = udp_checksum(&bytes);
    set_ipv4_udp_checksum(&mut bytes, invalid_checksum(checksum));

    let decoded = assert_udp_checksum_status(
        crate::NetworkLayer::Ipv4,
        &bytes,
        UdpChecksumStatus::Invalid,
    );
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        &[0xde, 0xad, 0xbe]
    );
}

#[test]
fn udp_checksum_status_ipv4_zero_checksum_absent() {
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2282)
        / Udp::new().sport(0x1234).dport(0x5678).checksum(0)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap();

    assert_eq!(udp_checksum(bytes.as_bytes()), 0);
    assert_udp_checksum_status(
        crate::NetworkLayer::Ipv4,
        bytes.as_bytes(),
        UdpChecksumStatus::Ipv4NoChecksum,
    );
}

#[test]
fn udp_checksum_status_ipv6_valid() {
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap();

    assert_udp_checksum_status(
        crate::NetworkLayer::Ipv6,
        bytes.as_bytes(),
        UdpChecksumStatus::Valid,
    );
}

#[test]
fn udp_checksum_status_ipv6_invalid() {
    let mut bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(0x1234).dport(0x5678)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap()
    .into_bytes();
    let checksum = ipv6_udp_checksum(&bytes);
    set_ipv6_udp_checksum(&mut bytes, invalid_checksum(checksum));

    let decoded = assert_udp_checksum_status(
        crate::NetworkLayer::Ipv6,
        &bytes,
        UdpChecksumStatus::Invalid,
    );
    assert_eq!(
        decoded.layer::<Raw>().unwrap().as_bytes(),
        &[0xde, 0xad, 0xbe]
    );
}

#[test]
fn udp_checksum_status_ipv6_zero_checksum_forbidden() {
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(0x1234).dport(0x5678).checksum(0)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap();

    assert_eq!(ipv6_udp_checksum(bytes.as_bytes()), 0);
    assert_udp_checksum_status(
        crate::NetworkLayer::Ipv6,
        bytes.as_bytes(),
        UdpChecksumStatus::Ipv6ZeroChecksum,
    );
}

#[test]
fn udp_ipv6_zero_checksum_default_requires_exception_status_and_roundtrips() {
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(0x1234).dport(0x5678).checksum(0)
        / Raw::from_bytes([0xde, 0xad, 0xbe]))
    .compile()
    .unwrap();

    assert_eq!(ipv6_udp_checksum(bytes.as_bytes()), 0);

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
    let status = decoded.layer::<Udp>().unwrap().checksum_status();
    assert_eq!(status, UdpChecksumStatus::Ipv6ZeroChecksum);
    assert!(status.requires_ipv6_zero_checksum_exception());
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_checksum_status_unchecked_without_pseudo_header_context() {
    let bytes = (Udp::new().sport(0x1234).dport(0x5678) / Raw::from_bytes([0xaa, 0xbb]))
        .compile()
        .unwrap();
    let decoded = decode_udp_parts(bytes.as_bytes()).unwrap();
    let udp_length = decoded.udp.length_value().unwrap() as usize;
    let udp_checksum = decoded.udp.checksum_value().unwrap();

    assert_eq!(
        checksum_status_with_context(&Packet::new(), bytes.as_bytes(), udp_length, udp_checksum),
        UdpChecksumStatus::NotChecked
    );
}

#[test]
fn ipv4_udp_compile_surplus_user_data_and_options_uses_ip_total_length() {
    let payload = [0xaa, 0xbb, 0xcc];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2260)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / UdpOptions::new().additional_payload_checksum())
    .compile()
    .unwrap();

    let surplus_start = udp_surplus_start(bytes.as_bytes());
    let surplus = udp_surplus(bytes.as_bytes());
    assert_eq!(ipv4_total_len(bytes.as_bytes()), bytes.len());
    assert_eq!(udp_length(bytes.as_bytes()), UDP_HEADER_LEN + payload.len());
    assert_eq!(surplus_start, 20 + UDP_HEADER_LEN + payload.len());
    assert_eq!(surplus[0], 0);
    assert!(udp_surplus_checksum_valid(bytes.as_bytes()));
    assert_eq!(
        udp_surplus_option_bytes(surplus_start, surplus),
        [
            UDP_OPTION_APC,
            UDP_OPTION_APC_LEN as u8,
            crc32c(&payload).to_be_bytes()[0],
            crc32c(&payload).to_be_bytes()[1],
            crc32c(&payload).to_be_bytes()[2],
            crc32c(&payload).to_be_bytes()[3],
        ]
    );
    assert_ipv4_udp_checksum_excludes_surplus(bytes.as_bytes(), payload.len());
}

#[test]
fn ipv6_udp_compile_surplus_user_data_and_options_uses_payload_length() {
    let payload = [0xaa, 0xbb, 0xcc];
    let option_bytes = [UDP_OPTION_NOP, UDP_OPTION_EOL];
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / UdpOptions::from_bytes(option_bytes))
    .compile()
    .unwrap();

    let surplus_start = ipv6_udp_surplus_start(bytes.as_bytes());
    let surplus = ipv6_udp_surplus(bytes.as_bytes());
    assert_eq!(ipv6_payload_len(bytes.as_bytes()), bytes.len() - 40);
    assert_eq!(
        ipv6_udp_length(bytes.as_bytes()),
        UDP_HEADER_LEN + payload.len()
    );
    assert_eq!(surplus_start, 40 + UDP_HEADER_LEN + payload.len());
    assert_eq!(surplus[0], 0);
    assert!(udp_surplus_checksum_valid_at(surplus_start, surplus));
    assert_eq!(
        udp_surplus_option_bytes(surplus_start, surplus),
        option_bytes
    );
    assert_ipv6_udp_checksum_excludes_surplus(bytes.as_bytes(), payload.len());
}

#[test]
fn ipv4_udp_compile_surplus_options_without_user_data() {
    let option_bytes = [UDP_OPTION_EOL];
    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2261)
        / Udp::new().sport(1234).dport(4321)
        / UdpOptions::from_bytes(option_bytes))
    .compile()
    .unwrap();

    let surplus_start = udp_surplus_start(bytes.as_bytes());
    let surplus = udp_surplus(bytes.as_bytes());
    assert_eq!(ipv4_total_len(bytes.as_bytes()), bytes.len());
    assert_eq!(udp_length(bytes.as_bytes()), UDP_HEADER_LEN);
    assert_eq!(surplus_start, 20 + UDP_HEADER_LEN);
    assert!(udp_surplus_checksum_valid(bytes.as_bytes()));
    assert_eq!(
        udp_surplus_option_bytes(surplus_start, surplus),
        option_bytes
    );
    assert_ipv4_udp_checksum_excludes_surplus(bytes.as_bytes(), 0);
}

#[test]
fn ipv6_udp_compile_surplus_options_without_user_data() {
    let option_bytes = [UDP_OPTION_EOL];
    let bytes = (Ipv6::new().src(ipv6_src()).dst(ipv6_dst())
        / Udp::new().sport(1234).dport(4321)
        / UdpOptions::from_bytes(option_bytes))
    .compile()
    .unwrap();

    let surplus_start = ipv6_udp_surplus_start(bytes.as_bytes());
    let surplus = ipv6_udp_surplus(bytes.as_bytes());
    assert_eq!(ipv6_payload_len(bytes.as_bytes()), bytes.len() - 40);
    assert_eq!(ipv6_udp_length(bytes.as_bytes()), UDP_HEADER_LEN);
    assert_eq!(surplus_start, 40 + UDP_HEADER_LEN);
    assert!(udp_surplus_checksum_valid_at(surplus_start, surplus));
    assert_eq!(
        udp_surplus_option_bytes(surplus_start, surplus),
        option_bytes
    );
    assert_ipv6_udp_checksum_excludes_surplus(bytes.as_bytes(), 0);
}

#[test]
fn ipv4_udp_compile_surplus_preserves_explicit_malformed_lengths() {
    let bytes = (Ipv4::new()
        .src(src())
        .dst(dst())
        .id(0x2262)
        .total_length(0x1234)
        / Udp::new().sport(1234).dport(4321).len(0x0033)
        / Raw::from_bytes([0xaa, 0xbb])
        / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
    .compile()
    .unwrap();

    assert_eq!(&bytes.as_bytes()[2..4], &0x1234u16.to_be_bytes());
    assert_eq!(&bytes.as_bytes()[24..26], &0x0033u16.to_be_bytes());
}

#[test]
fn ipv6_udp_compile_surplus_preserves_explicit_malformed_lengths() {
    let bytes = (Ipv6::new()
        .src(ipv6_src())
        .dst(ipv6_dst())
        .payload_length(0x1234)
        / Udp::new().sport(1234).dport(4321).len(0x0033)
        / Raw::from_bytes([0xaa, 0xbb])
        / UdpOptions::from_bytes([UDP_OPTION_NOP, UDP_OPTION_EOL]))
    .compile()
    .unwrap();

    assert_eq!(&bytes.as_bytes()[4..6], &0x1234u16.to_be_bytes());
    assert_eq!(&bytes.as_bytes()[44..46], &0x0033u16.to_be_bytes());
}

#[test]
fn udp_decode_surplus_dns_uses_user_payload_and_preserves_options() {
    let dns = Dns::a_query("example.com").id(0xbeef);
    let dns_len = dns.encoded_len();
    let surplus = [UDP_OPTION_NOP, UDP_OPTION_EOL, 0, 0];

    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2226)
        / Udp::new().sport(53_001).dport(DNS_PORT)
        / dns
        / UdpOptions::from_bytes(surplus))
    .compile()
    .unwrap();

    assert_eq!(
        &bytes.as_bytes()[2..4],
        &((20 + UDP_HEADER_LEN + dns_len + udp_surplus(bytes.as_bytes()).len()) as u16)
            .to_be_bytes()
    );
    assert_eq!(
        &bytes.as_bytes()[24..26],
        &((UDP_HEADER_LEN + dns_len) as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp = decoded.layer::<Udp>().unwrap();
    let dns = decoded.layer::<Dns>().unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();

    assert_eq!(udp.length_value(), Some((UDP_HEADER_LEN + dns_len) as u16));
    assert_eq!(dns.id_value(), 0xbeef);
    assert_eq!(dns.questions().len(), 1);
    assert_eq!(dns.questions()[0].name(), "example.com.");
    assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
    assert!(decoded.layers::<Raw>().next().is_none());
    assert_eq!(udp_options.as_bytes(), &surplus);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_decode_surplus_dhcp_uses_user_payload_and_preserves_options() {
    let client_mac = MacAddr::new([0x02, 0x00, 0x5e, 0x00, 0x53, 0x01]);
    let dhcp = Dhcp::discover(client_mac)
        .transaction_id(0x3903_f326)
        .flags(0x8000)
        .host_name("agent");
    let dhcp_len = dhcp.encoded_len();
    let surplus = [UDP_OPTION_NOP, UDP_OPTION_EOL, 0];

    let bytes = (Ipv4::new()
        .src(Ipv4Addr::UNSPECIFIED)
        .dst(Ipv4Addr::BROADCAST)
        .id(0x2227)
        / Udp::dhcp_client()
        / dhcp
        / UdpOptions::from_bytes(surplus))
    .compile()
    .unwrap();

    assert_eq!(
        &bytes.as_bytes()[2..4],
        &((20 + UDP_HEADER_LEN + dhcp_len + udp_surplus(bytes.as_bytes()).len()) as u16)
            .to_be_bytes()
    );
    assert_eq!(
        &bytes.as_bytes()[24..26],
        &((UDP_HEADER_LEN + dhcp_len) as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let udp = decoded.layer::<Udp>().unwrap();
    let dhcp = decoded.layer::<Dhcp>().unwrap();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();

    assert_eq!(udp.length_value(), Some((UDP_HEADER_LEN + dhcp_len) as u16));
    assert_eq!(dhcp.transaction_id_value(), 0x3903_f326);
    assert_eq!(dhcp.message_type_value(), Some(DhcpMessageType::Discover));
    assert_eq!(dhcp.host_name_value(), Some("agent"));
    assert!(decoded.layers::<Raw>().next().is_none());
    assert_eq!(udp_options.as_bytes(), &surplus);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_decode_surplus_raw_payload_uses_typed_options_for_ipv4_and_ipv6() {
    let malformed_option = [UDP_OPTION_MDS, 1];
    let payload = [0xaa, 0xbb, 0xcc];

    let bytes = (Ipv4::new().src(src()).dst(dst()).id(0x2228)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / UdpOptions::from_bytes(malformed_option))
    .compile()
    .unwrap();

    assert_eq!(
        &bytes.as_bytes()[2..4],
        &((20 + UDP_HEADER_LEN + payload.len() + udp_surplus(bytes.as_bytes()).len()) as u16)
            .to_be_bytes()
    );
    assert_eq!(
        &bytes.as_bytes()[24..26],
        &((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &payload);
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.as_bytes(), &malformed_option);
    assert_eq!(udp_options.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());

    let ipv6_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    let ipv6_dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
    let bytes = (Ipv6::new().src(ipv6_src).dst(ipv6_dst)
        / Udp::new().sport(1234).dport(4321)
        / Raw::from_bytes(payload)
        / UdpOptions::from_bytes(malformed_option))
    .compile()
    .unwrap();

    assert_eq!(
        &bytes.as_bytes()[4..6],
        &((bytes.as_bytes().len() - 40) as u16).to_be_bytes()
    );
    assert_eq!(
        &bytes.as_bytes()[44..46],
        &((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes()
    );

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv6, bytes.as_bytes()).unwrap();
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &payload);
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(udp_options.as_bytes(), &malformed_option);
    assert_eq!(udp_options.status(), UdpOptionStatus::MalformedEnvelope);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_length_shorter_than_ip_payload_preserves_surplus_tail() {
    let udp_payload = [0xaa, 0xbb, 0xcc];
    let surplus = [0xde, 0xad, 0xbe, 0xef];
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0x1111u16.to_be_bytes());
    datagram.extend_from_slice(&0x2222u16.to_be_bytes());
    datagram.extend_from_slice(&((UDP_HEADER_LEN + udp_payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.extend_from_slice(&udp_payload);
    datagram.extend_from_slice(&surplus);
    let bytes = (Ipv4::new()
        .src(src())
        .dst(dst())
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Raw::from_bytes(datagram))
    .compile()
    .unwrap();

    let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
    let raw_layers = decoded.layers::<Raw>().collect::<Vec<_>>();
    let udp_options = decoded.layer::<UdpOptions>().unwrap();
    assert_eq!(decoded.layer::<Udp>().unwrap().length_value(), Some(11));
    assert_eq!(raw_layers.len(), 1);
    assert_eq!(raw_layers[0].as_bytes(), udp_payload);
    assert_eq!(udp_options.status(), UdpOptionStatus::Ignored);
    assert_eq!(udp_options.alignment_bytes(), Some([0xde].as_slice()));
    assert_eq!(udp_options.option_checksum_value(), Some(0xadbe));
    assert_eq!(udp_options.as_bytes(), &[0xef]);
    assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
}

#[test]
fn udp_length_longer_than_ip_payload_reports_structured_error() {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0x1111u16.to_be_bytes());
    datagram.extend_from_slice(&0x2222u16.to_be_bytes());
    datagram.extend_from_slice(&16u16.to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    let bytes = (Ipv4::new()
        .src(src())
        .dst(dst())
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Raw::from_bytes(datagram))
    .compile()
    .unwrap();

    match Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bytes.as_bytes()) {
        Err(crate::CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(context, "udp datagram");
            assert_eq!(required, 16);
            assert_eq!(available, 11);
        }
        other => panic!("expected structured UDP length overrun error, got {other:?}"),
    }
}

#[test]
fn udp_option_malformed_udp_length_overrun_remains_structured_error() {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&0x1111u16.to_be_bytes());
    datagram.extend_from_slice(&0x2222u16.to_be_bytes());
    datagram.extend_from_slice(&16u16.to_be_bytes());
    datagram.extend_from_slice(&0u16.to_be_bytes());
    datagram.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

    let ipv4 = (Ipv4::new()
        .src(src())
        .dst(dst())
        .ipv4_protocol(Ipv4Protocol::Udp)
        / Raw::from_bytes(datagram.clone()))
    .compile()
    .unwrap();
    match Packet::decode_from_l3(crate::NetworkLayer::Ipv4, ipv4.as_bytes()) {
        Err(crate::CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(context, "udp datagram");
            assert_eq!(required, 16);
            assert_eq!(available, 11);
        }
        other => panic!("expected structured IPv4 UDP length overrun error, got {other:?}"),
    }

    let ipv6 = (Ipv6::new()
        .src(ipv6_src())
        .dst(ipv6_dst())
        .next_header(IPPROTO_UDP)
        / Raw::from_bytes(datagram))
    .compile()
    .unwrap();
    match Packet::decode_from_l3(crate::NetworkLayer::Ipv6, ipv6.as_bytes()) {
        Err(crate::CrafterError::BufferTooShort {
            context,
            required,
            available,
        }) => {
            assert_eq!(context, "udp datagram");
            assert_eq!(required, 16);
            assert_eq!(available, 11);
        }
        other => panic!("expected structured IPv6 UDP length overrun error, got {other:?}"),
    }
}

#[test]
fn udp_decode_rejects_short_and_malformed_inputs() {
    let short = (Ipv4::new().ipv4_protocol(Ipv4Protocol::Udp) / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();
    assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, short.as_bytes()).is_err());

    let bad_length = (Ipv4::new().ipv4_protocol(Ipv4Protocol::Udp)
        / Raw::from_bytes([0x12, 0x34, 0x00, 0x35, 0x00, 0x07, 0, 0]))
    .compile()
    .unwrap();
    assert!(Packet::decode_from_l3(crate::NetworkLayer::Ipv4, bad_length.as_bytes()).is_err());
}
