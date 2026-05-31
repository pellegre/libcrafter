use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Packet, Raw};

use super::constants::ARP_FIXED_HEADER_LEN;
use super::layer::Arp;

/// Append a decoded ARP packet to an existing packet stack.
pub(crate) fn append_arp_packet(mut packet: Packet, payload: &[u8]) -> Result<Packet> {
    let (arp, rest) = decode_arp(payload)?;
    packet = packet.push(arp);
    if !rest.is_empty() {
        packet = packet.push(Raw::from_bytes(rest));
    }
    Ok(packet)
}

fn decode_arp(bytes: &[u8]) -> Result<(Arp, &[u8])> {
    if bytes.len() < ARP_FIXED_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "arp header",
            ARP_FIXED_HEADER_LEN,
            bytes.len(),
        ));
    }

    let hardware_len = bytes[4] as usize;
    let protocol_len = bytes[5] as usize;
    let total_len = ARP_FIXED_HEADER_LEN + hardware_len * 2 + protocol_len * 2;
    if bytes.len() < total_len {
        return Err(CrafterError::buffer_too_short(
            "arp addresses",
            total_len,
            bytes.len(),
        ));
    }

    let mut offset = ARP_FIXED_HEADER_LEN;
    let sender_hardware_addr = bytes[offset..offset + hardware_len].to_vec();
    offset += hardware_len;
    let sender_protocol_addr = bytes[offset..offset + protocol_len].to_vec();
    offset += protocol_len;
    let target_hardware_addr = bytes[offset..offset + hardware_len].to_vec();
    offset += hardware_len;
    let target_protocol_addr = bytes[offset..offset + protocol_len].to_vec();

    let arp = Arp {
        hardware_type: Field::user(read_u16_be(&bytes[0..2])?),
        protocol_type: Field::user(read_u16_be(&bytes[2..4])?),
        hardware_len: Field::user(bytes[4]),
        protocol_len: Field::user(bytes[5]),
        operation: Field::user(read_u16_be(&bytes[6..8])?),
        sender_hardware_addr: Field::user(sender_hardware_addr),
        sender_protocol_addr: Field::user(sender_protocol_addr),
        target_hardware_addr: Field::user(target_hardware_addr),
        target_protocol_addr: Field::user(target_protocol_addr),
    };

    Ok((arp, &bytes[total_len..]))
}
