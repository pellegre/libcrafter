//! IEEE 802.11 MAC frame decode entrypoints and byte readers.

use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::mac::MacAddr;
use crate::packet::{Packet, Raw};
use crate::protocols::link::append_llc_snap_packet_with_registry;
use crate::registry::ProtocolRegistry;

use super::header::*;
use super::*;

/// Decode a bare IEEE 802.11 MAC frame and preserve the undecoded body as Raw.
pub(crate) fn decode_dot11_with_registry(
    registry: &ProtocolRegistry,
    bytes: &[u8],
) -> Result<Packet> {
    let (dot11, tail) = decode_dot11(bytes)?;
    let decode_llc_snap = dot11_should_dispatch_llc_snap(&dot11);
    let packet = Packet::new().push(dot11);

    if tail.is_empty() {
        return Ok(packet);
    }

    if decode_llc_snap {
        append_llc_snap_packet_with_registry(registry, packet, tail)
    } else {
        Ok(packet.push(Raw::from_bytes(tail)))
    }
}

fn dot11_should_dispatch_llc_snap(dot11: &Dot11) -> bool {
    let frame_control = dot11.frame_control_value();

    frame_control.frame_type_value() == Dot11FrameType::Data
        && dot11_data_subtype_carries_payload(frame_control.subtype())
        && !frame_control.protected()
        && !dot11.is_fragmented()
}

fn decode_dot11(bytes: &[u8]) -> Result<(Dot11, &[u8])> {
    let frame_control = Dot11FrameControl::decode(bytes)?;
    let header_len = dot11_required_header_len(frame_control);

    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            "dot11.header",
            header_len,
            bytes.len(),
        ));
    }

    let mut dot11 = Dot11 {
        frame_control: Field::user(frame_control),
        duration_id: Field::user(read_u16_le_at(bytes, DOT11_FRAME_CONTROL_LEN)),
        addr1: Field::user(read_mac_at(
            bytes,
            DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN,
        )),
        addr2: Field::unset(),
        addr3: Field::unset(),
        sequence_control: Field::unset(),
        addr4: Field::unset(),
        qos_control: Field::unset(),
        ht_control: Field::unset(),
        fixed_parameters: Vec::new(),
        tagged_parameters: Vec::new(),
        encrypted_body_len: None,
    };

    match frame_control.frame_type_value() {
        Dot11FrameType::Management => {
            let mut offset = decode_dot11_three_address_header(bytes, &mut dot11);

            if frame_control.order() {
                dot11.ht_control = Field::user(read_u32_le_at(bytes, offset));
                offset += DOT11_HT_CONTROL_LEN;
            }

            let fixed_len = dot11_management_fixed_parameters_len(frame_control);
            dot11.fixed_parameters = bytes[offset..offset + fixed_len].to_vec();
            offset += fixed_len;

            if dot11_management_subtype_has_tagged_parameters(frame_control.subtype()) {
                dot11.tagged_parameters = decode_dot11_tagged_parameters(&bytes[offset..])?;
                Ok((dot11, &bytes[bytes.len()..]))
            } else {
                Ok((dot11, &bytes[offset..]))
            }
        }
        Dot11FrameType::Control => {
            if dot11_mac_header_len(frame_control) >= DOT11_CONTROL_TWO_ADDRESS_HEADER_LEN {
                dot11.addr2 = Field::user(read_mac_at(
                    bytes,
                    DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + DOT11_ADDRESS_LEN,
                ));
            }

            Ok((dot11, &bytes[header_len..]))
        }
        Dot11FrameType::Data => {
            let mut offset = decode_dot11_three_address_header(bytes, &mut dot11);

            if frame_control.to_ds() && frame_control.from_ds() {
                dot11.addr4 = Field::user(read_mac_at(bytes, offset));
                offset += DOT11_ADDRESS_LEN;
            }
            if dot11_data_subtype_has_qos(frame_control.subtype()) {
                dot11.qos_control = Field::user(read_u16_le_at(bytes, offset));
                offset += DOT11_QOS_CONTROL_LEN;

                if frame_control.order() {
                    dot11.ht_control = Field::user(read_u32_le_at(bytes, offset));
                    offset += DOT11_HT_CONTROL_LEN;
                }
            }
            if frame_control.protected() {
                dot11.encrypted_body_len = Some(bytes.len() - offset);
            }

            Ok((dot11, &bytes[offset..]))
        }
        Dot11FrameType::Extension | Dot11FrameType::Unknown(_) => Ok((dot11, &bytes[header_len..])),
    }
}

fn decode_dot11_three_address_header(bytes: &[u8], dot11: &mut Dot11) -> usize {
    dot11.addr2 = Field::user(read_mac_at(
        bytes,
        DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + DOT11_ADDRESS_LEN,
    ));
    dot11.addr3 = Field::user(read_mac_at(
        bytes,
        DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 2),
    ));
    dot11.sequence_control = Field::user(Dot11SequenceControl::from_le_bytes([
        bytes[DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 3)],
        bytes[DOT11_FRAME_CONTROL_LEN + DOT11_DURATION_ID_LEN + (DOT11_ADDRESS_LEN * 3) + 1],
    ]));

    DOT11_DATA_HEADER_LEN
}

pub(super) fn read_u16_le_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn read_u32_le_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

pub(super) fn read_mac_at(bytes: &[u8], offset: usize) -> MacAddr {
    MacAddr::new([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
    ])
}

fn decode_dot11_tagged_parameters(bytes: &[u8]) -> Result<Vec<Dot11TaggedParameter>> {
    let mut tags = Vec::new();
    let mut offset = 0usize;

    while offset < bytes.len() {
        if bytes.len() - offset < 2 {
            return Err(CrafterError::buffer_too_short(
                "dot11.tagged_parameter",
                offset + 2,
                bytes.len(),
            ));
        }

        let id = bytes[offset];
        let length = bytes[offset + 1];
        let value_start = offset + 2;
        let value_end = value_start + length as usize;

        if value_end > bytes.len() {
            return Err(CrafterError::buffer_too_short(
                "dot11.tagged_parameter",
                value_end,
                bytes.len(),
            ));
        }

        tags.push(Dot11TaggedParameter::from_wire(
            id,
            length,
            &bytes[value_start..value_end],
        ));
        offset = value_end;
    }

    Ok(tags)
}
