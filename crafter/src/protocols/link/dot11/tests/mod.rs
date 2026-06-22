use super::*;
use crate::mac::MacAddr;
use crate::registry::ProtocolRegistry;
use crate::Packet;

mod codepoints;
mod decode;
mod fields;
mod layer;

fn dot11_role_mac(index: u8) -> MacAddr {
    MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, index])
}

fn dot11_test_frame_control(frame_type: u8, subtype: u8) -> Dot11FrameControl {
    Dot11FrameControl::new()
        .with_frame_type(frame_type)
        .with_subtype(subtype)
}

fn dot11_test_bytes(frame_control: Dot11FrameControl, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    let frame_control = frame_control.compile();
    if len > 0 {
        bytes[0] = frame_control[0];
    }
    if len > 1 {
        bytes[1] = frame_control[1];
    }
    bytes
}

fn dot11_decode_test_header(frame_control: Dot11FrameControl) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&frame_control.compile());
    bytes.extend_from_slice(&0x1234u16.to_le_bytes());
    bytes.extend_from_slice(&dot11_role_mac(1).octets());
    bytes.extend_from_slice(&dot11_role_mac(2).octets());
    bytes.extend_from_slice(&dot11_role_mac(3).octets());
    bytes.extend_from_slice(&0x5678u16.to_le_bytes());
    bytes
}

fn decode_dot11_basic(bytes: &[u8]) -> Packet {
    decode_dot11_with_registry(&ProtocolRegistry::new(), bytes).unwrap()
}

fn decode_dot11_management_fixed_fields_frame(
    subtype: u8,
    fixed: &[u8],
    tail: &[u8],
) -> (Packet, Vec<u8>) {
    let frame_control = dot11_test_frame_control(DOT11_FRAME_TYPE_MANAGEMENT, subtype);
    let mut bytes = dot11_decode_test_header(frame_control);
    bytes.extend_from_slice(fixed);
    bytes.extend_from_slice(tail);

    (decode_dot11_basic(&bytes), bytes)
}

fn dot11_compiled_management_body(dot11: Dot11) -> Vec<u8> {
    Packet::from_layer(dot11).compile().unwrap().into_bytes()[DOT11_DATA_HEADER_LEN..].to_vec()
}

fn dot11_inspection_value(fields: &[(&'static str, String)], name: &str) -> Option<String> {
    fields
        .iter()
        .find(|(field, _)| *field == name)
        .map(|(_, value)| value.clone())
}
