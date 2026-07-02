use std::net::{Ipv4Addr, Ipv6Addr};

use crafter::prelude::*;

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const EXPECTED_IPV4_TOTAL_LEN: u16 =
    (IPV4_HEADER_LEN + UDP_HEADER_LEN + NTP_FIXED_HEADER_LEN) as u16;
const EXPECTED_IPV6_PAYLOAD_LEN: u16 = (UDP_HEADER_LEN + NTP_FIXED_HEADER_LEN) as u16;
const EXPECTED_UDP_LEN: u16 = (UDP_HEADER_LEN + NTP_FIXED_HEADER_LEN) as u16;

fn documentation_ipv4_ntp_packet() -> Packet {
    Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::ntp().sport(49_152)
        / Ntp::client()
            .poll(6)
            .precision(-20)
            .root_delay_raw(0x0001_0000)
            .root_dispersion_raw(0x0002_0000)
            .reference_id(*b"LOCL")
            .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678))
}

fn documentation_ipv6_ntp_packet() -> Packet {
    Ipv6::new()
        .src(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10))
        .dst(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20))
        / Udp::ntp().sport(49_152)
        / Ntp::client()
            .poll(6)
            .precision(-20)
            .root_delay_raw(0x0001_0000)
            .root_dispersion_raw(0x0002_0000)
            .reference_id(*b"LOCL")
            .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678))
}

#[test]
fn ipv4_ntp_compile_decode_stack_fields_and_lengths() -> crafter::Result<()> {
    let compiled = documentation_ipv4_ntp_packet().compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(bytes.len(), usize::from(EXPECTED_IPV4_TOTAL_LEN));
    assert_eq!(bytes[9], IPPROTO_UDP);
    assert_eq!(&bytes[2..4], &EXPECTED_IPV4_TOTAL_LEN.to_be_bytes());
    assert_eq!(
        &bytes[IPV4_HEADER_LEN + 4..IPV4_HEADER_LEN + 6],
        &EXPECTED_UDP_LEN.to_be_bytes()
    );
    assert_ne!(&bytes[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8], &[0, 0]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes)?;

    let ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
    assert_eq!(ipv4.protocol_value(), IPPROTO_UDP);
    assert_eq!(ipv4.total_length_value(), Some(EXPECTED_IPV4_TOTAL_LEN));

    let udp = decoded.layer::<Udp>().expect("decoded UDP layer");
    assert_eq!(udp.source_port_value(), 49_152);
    assert_eq!(udp.destination_port_value(), NTP_PORT);
    assert_eq!(udp.length_value(), Some(EXPECTED_UDP_LEN));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    let ntp = decoded.layer::<Ntp>().expect("decoded NTP layer");
    assert_eq!(ntp.mode_value(), NtpMode::Client);
    assert_eq!(ntp.version_value_effective(), NtpVersion::current());
    assert_eq!(ntp.stratum_value().value(), NTP_DEFAULT_STRATUM);
    assert_eq!(ntp.poll_value(), 6);
    assert_eq!(ntp.precision_value(), -20);
    assert_eq!(ntp.root_delay_value().raw(), 0x0001_0000);
    assert_eq!(ntp.root_dispersion_value().raw(), 0x0002_0000);
    assert_eq!(ntp.reference_id_value().bytes(), *b"LOCL");
    assert_eq!(ntp.transmit_timestamp_value().raw(), 0xecc0_0000_1234_5678);
    assert!(decoded.layer::<Raw>().is_none());
    Ok(())
}

#[test]
fn ipv6_ntp_compile_decode_stack_fields_and_lengths() -> crafter::Result<()> {
    let compiled = documentation_ipv6_ntp_packet().compile()?;
    let bytes = compiled.as_bytes();

    assert_eq!(
        bytes.len(),
        IPV6_HEADER_LEN + usize::from(EXPECTED_IPV6_PAYLOAD_LEN)
    );
    assert_eq!(bytes[6], IPPROTO_UDP);
    assert_eq!(&bytes[4..6], &EXPECTED_IPV6_PAYLOAD_LEN.to_be_bytes());
    assert_eq!(
        &bytes[IPV6_HEADER_LEN + 4..IPV6_HEADER_LEN + 6],
        &EXPECTED_UDP_LEN.to_be_bytes()
    );
    assert_ne!(&bytes[IPV6_HEADER_LEN + 6..IPV6_HEADER_LEN + 8], &[0, 0]);

    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv6, bytes)?;

    let ipv6 = decoded.layer::<Ipv6>().expect("decoded IPv6 layer");
    assert_eq!(ipv6.next_header_value(), IPPROTO_UDP);
    assert_eq!(ipv6.payload_length_value(), Some(EXPECTED_IPV6_PAYLOAD_LEN));

    let udp = decoded.layer::<Udp>().expect("decoded UDP layer");
    assert_eq!(udp.source_port_value(), 49_152);
    assert_eq!(udp.destination_port_value(), NTP_PORT);
    assert_eq!(udp.length_value(), Some(EXPECTED_UDP_LEN));
    assert_eq!(udp.checksum_status(), UdpChecksumStatus::Valid);

    let ntp = decoded.layer::<Ntp>().expect("decoded NTP layer");
    assert_eq!(ntp.mode_value(), NtpMode::Client);
    assert_eq!(ntp.version_value_effective(), NtpVersion::current());
    assert_eq!(ntp.stratum_value().value(), NTP_DEFAULT_STRATUM);
    assert_eq!(ntp.poll_value(), 6);
    assert_eq!(ntp.precision_value(), -20);
    assert_eq!(ntp.root_delay_value().raw(), 0x0001_0000);
    assert_eq!(ntp.root_dispersion_value().raw(), 0x0002_0000);
    assert_eq!(ntp.reference_id_value().bytes(), *b"LOCL");
    assert_eq!(ntp.transmit_timestamp_value().raw(), 0xecc0_0000_1234_5678);
    assert!(decoded.layer::<Raw>().is_none());
    Ok(())
}

#[test]
fn ipv4_ntp_summary_and_show_are_inspectable() -> crafter::Result<()> {
    let compiled = documentation_ipv4_ntp_packet().compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    let summary = decoded.summary();
    assert!(summary.contains("Ipv4("), "{summary}");
    assert!(summary.contains("proto=udp(17)"), "{summary}");
    assert!(summary.contains("Udp("), "{summary}");
    assert!(summary.contains("len=56"), "{summary}");
    assert!(summary.contains("checksum_status=Valid"), "{summary}");
    assert!(summary.contains("Ntp("), "{summary}");
    assert!(summary.contains("mode=client"), "{summary}");
    assert!(summary.contains("tail=none"), "{summary}");

    let show = decoded.show();
    assert!(show.contains("total_length: 76"), "{show}");
    assert!(show.contains("protocol: udp(17)"), "{show}");
    assert!(show.contains("length: 56"), "{show}");
    assert!(show.contains("checksum_status: Valid"), "{show}");
    assert!(show.contains("mode: client"), "{show}");
    assert!(show.contains("legacy_mac_len: 0"), "{show}");
    assert!(show.contains("mac_status: none"), "{show}");
    Ok(())
}
