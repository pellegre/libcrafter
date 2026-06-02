//! TCP header splitting and registry-driven segment decode.

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::packet::Packet;
use crate::registry::ProtocolRegistry;

use super::constants::{TCP_MAX_RESERVED, TCP_MIN_HEADER_LEN};
use super::option::validate_tcp_options;
use super::segment::Tcp;

/// Append a decoded TCP segment using an explicit registry.
pub(crate) fn append_tcp_packet_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let (tcp, payload) = decode_tcp_parts(bytes)?;
    let source_port = tcp.source_port_value();
    let destination_port = tcp.destination_port_value();
    packet = packet.push(tcp);
    if !payload.is_empty() {
        packet = registry.decode_tcp_application(packet, source_port, destination_port, payload)?;
    }
    Ok(packet)
}

fn decode_tcp_parts(bytes: &[u8]) -> Result<(Tcp, &[u8])> {
    if bytes.len() < TCP_MIN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "tcp header",
            TCP_MIN_HEADER_LEN,
            bytes.len(),
        ));
    }

    let data_offset = bytes[12] >> 4;
    if data_offset < 5 {
        return Err(CrafterError::invalid_field_value(
            "tcp.data_offset",
            "TCP data offset must be at least 5 words",
        ));
    }

    let header_len = (data_offset as usize) * 4;
    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            "tcp header",
            header_len,
            bytes.len(),
        ));
    }
    validate_tcp_options(&bytes[TCP_MIN_HEADER_LEN..header_len])?;

    let flags = (((bytes[12] & 1) as u16) << 8) | bytes[13] as u16;
    let tcp = Tcp::from_decoded_parts(
        read_u16_be(&bytes[0..2])?,
        read_u16_be(&bytes[2..4])?,
        read_u32_be(&bytes[4..8])?,
        read_u32_be(&bytes[8..12])?,
        data_offset,
        (bytes[12] >> 1) & TCP_MAX_RESERVED,
        flags,
        read_u16_be(&bytes[14..16])?,
        read_u16_be(&bytes[16..18])?,
        read_u16_be(&bytes[18..20])?,
        bytes[TCP_MIN_HEADER_LEN..header_len].to_vec(),
    );

    Ok((tcp, &bytes[header_len..]))
}
