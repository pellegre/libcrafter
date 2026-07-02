use std::net::Ipv4Addr;

use crafter::prelude::*;

fn decode_udp_123_payload(payload: &[u8]) -> crafter::Result<Packet> {
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 123))
        / Udp::new().source_port(NTP_PORT).destination_port(NTP_PORT)
        / Raw::from_bytes(payload.to_vec());

    Packet::decode_from_l3(NetworkLayer::Ipv4, packet.compile()?.as_bytes())
}

fn assert_ntp_raw_fallback(payload: &[u8]) -> crafter::Result<()> {
    let decoded = decode_udp_123_payload(payload)?;

    assert!(decoded.layer::<Ntp>().is_none());
    assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), payload);
    Ok(())
}

#[test]
fn ntp_raw_fallback_preserves_too_short_udp_123_payload() -> crafter::Result<()> {
    let payload = [0x23, 0x00, 0x00, 0x00];

    match Ntp::decode(&payload).unwrap_err() {
        CrafterError::BufferTooShort {
            context,
            required,
            available,
        } => {
            assert_eq!(context, "ntp.header");
            assert_eq!(required, NTP_FIXED_HEADER_LEN);
            assert_eq!(available, payload.len());
        }
        other => panic!("unexpected NTP decode error: {other:?}"),
    }

    assert!(!looks_like_ntp_payload(&payload));
    assert_ntp_raw_fallback(&payload)
}

#[test]
fn ntp_raw_fallback_preserves_random_shape_invalid_udp_123_payload() -> crafter::Result<()> {
    let payload = [
        0x05, 0x8d, 0x4a, 0x73, 0x91, 0x02, 0xee, 0x19, 0x44, 0xb8, 0x6d, 0x0c, 0x37, 0xfa, 0x51,
        0x28, 0x90, 0xce, 0x11, 0x62, 0x5b, 0x07, 0xd4, 0x39, 0xac, 0x13, 0x55, 0x80, 0x0f, 0x24,
        0x6a, 0xbd, 0x71, 0x09, 0xc2, 0xef, 0x3e, 0x48, 0x84, 0x16, 0xd9, 0x5a, 0x22, 0x67, 0x9c,
        0x30, 0xab, 0xfe,
    ];

    assert!(!looks_like_ntp_payload(&payload));
    assert_ntp_raw_fallback(&payload)
}

#[test]
fn ntp_raw_fallback_preserves_shape_invalid_extension_tail() -> crafter::Result<()> {
    let mut payload = Packet::from_layer(Ntp::client()).compile()?.into_bytes();
    payload.extend_from_slice(&0x0204u16.to_be_bytes());
    payload.extend_from_slice(&12u16.to_be_bytes());
    payload.extend_from_slice(&[0; 8]);

    assert!(Ntp::decode(&payload).is_err());
    assert!(!looks_like_ntp_payload(&payload));
    assert_ntp_raw_fallback(&payload)
}
