use std::net::Ipv4Addr;

use crate::error::CrafterError;
use crate::field::FieldState;
use crate::packet::{Layer, NetworkLayer, Packet, Raw};
use crate::protocols::ip::v4::Ipv4;
use crate::protocols::transport::Udp;

use super::decode::{append_quic_packet, decode_quic_datagram};
use super::Quic;

#[test]
fn quic_module_skeleton_layer_compiles_raw_payload() -> crate::Result<()> {
    let payload = [0xc3, 0x00, 0x00, 0x00, 0x01];
    let quic = Quic::from_bytes(payload);
    let packet = Packet::from_layer(quic.clone());
    let compiled = packet.compile()?;

    assert_eq!(compiled.as_bytes(), payload);
    assert_eq!(quic.payload_state(), FieldState::User);
    assert_eq!(quic.payload_bytes(), payload);
    assert_eq!(quic.summary(), "Quic(raw_len=5, packets=0, status=raw)");
    Ok(())
}

#[test]
fn quic_module_skeleton_explicit_decode_stub_preserves_payload() -> crate::Result<()> {
    let payload = [0xc3, 0x00, 0x00, 0x00, 0x01, 0xaa, 0xbb];
    let packet = append_quic_packet(Packet::new(), &payload)?;
    let quic = packet.layer::<Quic>().expect("QUIC placeholder layer");

    assert_eq!(quic.payload_state(), FieldState::User);
    assert_eq!(quic.payload_bytes(), payload);
    assert_eq!(packet.compile()?.as_bytes(), payload);
    Ok(())
}

#[test]
fn quic_module_skeleton_empty_decode_returns_structured_error() {
    let err = decode_quic_datagram(&[]).expect_err("empty QUIC datagram is malformed");

    assert_eq!(
        err,
        CrafterError::BufferTooShort {
            context: "quic.datagram",
            required: 1,
            available: 0,
        }
    );
}

#[test]
fn quic_module_skeleton_udp_payload_remains_raw_without_dispatch() -> crate::Result<()> {
    let quic_like_payload = [0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00];
    let packet = Ipv4::new()
        .src(Ipv4Addr::new(192, 0, 2, 10))
        .dst(Ipv4Addr::new(198, 51, 100, 20))
        / Udp::new().sport(49_152).dport(4_433)
        / Raw::from_bytes(quic_like_payload);
    let compiled = packet.compile()?;
    let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes())?;

    assert!(decoded.layer::<Quic>().is_none());
    assert_eq!(
        decoded
            .layer::<Raw>()
            .expect("unsupported UDP payload remains raw")
            .as_bytes(),
        quic_like_payload
    );
    Ok(())
}
