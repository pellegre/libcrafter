//! TCP header splitting and registry-driven segment decode.

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
    packet = packet.push_tcp(tcp);
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
        u16::from_be_bytes([bytes[0], bytes[1]]),
        u16::from_be_bytes([bytes[2], bytes[3]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        data_offset,
        (bytes[12] >> 1) & TCP_MAX_RESERVED,
        flags,
        u16::from_be_bytes([bytes[14], bytes[15]]),
        u16::from_be_bytes([bytes[16], bytes[17]]),
        u16::from_be_bytes([bytes[18], bytes[19]]),
        bytes[TCP_MIN_HEADER_LEN..header_len].to_vec(),
    );

    Ok((tcp, &bytes[header_len..]))
}
