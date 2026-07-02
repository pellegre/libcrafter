use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use crafter::prelude::*;

const IPV4_UDP_NTP_CLIENT_SUMMARY: &str = "summaries/ipv4-udp-ntp-client.summary.txt";

fn fixture_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path)
}

fn read_summary_fixture(path: &str) -> String {
    fs::read_to_string(fixture_path(path))
        .unwrap_or_else(|err| panic!("summary fixture {path} should be readable: {err}"))
}

fn ntp_summary_stack() -> Packet {
    Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 123))
        .id(0x4e54)
        .ttl(64)
        / Udp::ntp().sport(49_152)
        / Ntp::client()
            .stratum(NTP_STRATUM_PRIMARY)
            .reference_id(NtpReferenceId::from_bytes(*b"GPS\0"))
            .transmit_timestamp(NtpTimestamp::from_parts(0xecc0_0000, 0x1234_5678))
            .legacy_mac(NtpLegacyMac::from_key_id_and_digest(
                0x0102_0304,
                [0xab; 16],
            ))
}

fn ntp_summary_packet() -> crafter::Result<Packet> {
    let compiled = ntp_summary_stack().compile()?;
    Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())
}

#[test]
fn ntp_summary_golden_matches_ipv4_udp_ntp_client() -> crafter::Result<()> {
    let packet = ntp_summary_packet()?;
    let summary = packet.summary();
    let expected = read_summary_fixture(IPV4_UDP_NTP_CLIENT_SUMMARY);

    assert_eq!(summary.trim_end(), expected.trim_end());
    assert!(summary.contains("mode=client"), "{summary}");
    assert!(
        summary.contains("refid=Global Position System"),
        "{summary}"
    );
    assert!(summary.contains("tail=legacy-mac"), "{summary}");
    assert!(!summary.contains("01020304"), "{summary}");
    assert!(!summary.contains("abababab"), "{summary}");
    assert!(!summary.contains("ab ab"), "{summary}");
    Ok(())
}
