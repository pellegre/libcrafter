//! IPv6 decode and registry dispatch.

use core::net::Ipv6Addr;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Packet, Raw};
use crate::registry::ProtocolRegistry;

use super::constants::{
    IPPROTO_IPV6_DSTOPTS, IPPROTO_IPV6_FRAGMENT, IPPROTO_IPV6_HOPOPTS, IPPROTO_IPV6_ROUTE,
    IPV6_FRAGMENT_HEADER_LEN, IPV6_HEADER_LEN, IPV6_MAX_FLOW_LABEL, IPV6_ROUTING_TYPE_MOBILE,
    IPV6_ROUTING_TYPE_SEGMENT, IPV6_SEGMENT_BASE_LEN, IPV6_SEGMENT_HMAC_LEN,
    IPV6_SEGMENT_POLICY_UNSET,
};
use super::extension::{
    decode_destination_options_header, decode_extension_total_len, decode_hop_by_hop_header,
    decode_mobile_routing_header,
};
use super::{
    copy_array_16, Ipv6, Ipv6FragmentHeader, Ipv6MobileRoutingHeader, Ipv6RoutingHeader,
    Ipv6SegmentRoutingHeader,
};

enum DecodedRoutingHeader {
    Generic(Ipv6RoutingHeader),
    Mobile(Ipv6MobileRoutingHeader),
    Segment(Ipv6SegmentRoutingHeader),
}

/// Append a decoded IPv6 packet using an explicit registry.
pub(crate) fn append_ipv6_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let (ipv6, payload, rest) = decode_ipv6_parts(bytes)?;
    let next_header = ipv6.next_header_value();
    append_ipv6_payload_with_registry(registry, packet.push_ipv6(ipv6), next_header, payload, rest)
}

fn decode_ipv6_parts(bytes: &[u8]) -> Result<(Ipv6, &[u8], &[u8])> {
    if bytes.len() < IPV6_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv6 header",
            IPV6_HEADER_LEN,
            bytes.len(),
        ));
    }

    let version_class_flow = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let version = (version_class_flow >> 28) as u8;
    if version != 6 {
        return Err(CrafterError::invalid_field_value(
            "ipv6.version",
            "IPv6 packets must have version 6",
        ));
    }

    let payload_length = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let total_length = IPV6_HEADER_LEN + payload_length;
    if bytes.len() < total_length {
        return Err(CrafterError::buffer_too_short(
            "ipv6 packet",
            total_length,
            bytes.len(),
        ));
    }

    let ipv6 = Ipv6 {
        version: Field::user(version),
        traffic_class: Field::user(((version_class_flow >> 20) & 0xff) as u8),
        flow_label: Field::user(version_class_flow & IPV6_MAX_FLOW_LABEL),
        payload_length: Field::user(payload_length as u16),
        next_header: Field::user(bytes[6]),
        hop_limit: Field::user(bytes[7]),
        source: Field::user(Ipv6Addr::from(copy_array_16(&bytes[8..24]))),
        destination: Field::user(Ipv6Addr::from(copy_array_16(&bytes[24..40]))),
    };

    Ok((
        ipv6,
        &bytes[IPV6_HEADER_LEN..total_length],
        &bytes[total_length..],
    ))
}

fn append_ipv6_payload_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    next_header: u8,
    payload: &[u8],
    rest: &[u8],
) -> Result<Packet> {
    packet = append_ipv6_next_with_registry(registry, packet, next_header, payload)?;

    if !rest.is_empty() {
        packet = packet.push_raw(Raw::from_bytes(rest));
    }

    Ok(packet)
}

fn append_ipv6_next_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    mut next_header: u8,
    mut payload: &[u8],
) -> Result<Packet> {
    loop {
        match next_header {
            IPPROTO_IPV6_HOPOPTS => {
                let (hop_by_hop, inner_next_header, remaining) = decode_hop_by_hop_header(payload)?;
                packet = packet.push(hop_by_hop);
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_DSTOPTS => {
                let (destination_options, inner_next_header, remaining) =
                    decode_destination_options_header(payload)?;
                packet = packet.push(destination_options);
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_ROUTE => {
                let (routing, inner_next_header, remaining) = decode_routing_header(payload)?;
                packet = match routing {
                    DecodedRoutingHeader::Generic(layer) => packet.push(layer),
                    DecodedRoutingHeader::Mobile(layer) => packet.push(layer),
                    DecodedRoutingHeader::Segment(layer) => packet.push(layer),
                };
                next_header = inner_next_header;
                payload = remaining;
            }
            IPPROTO_IPV6_FRAGMENT => {
                let (fragment, inner_next_header, remaining) = decode_fragment_header(payload)?;
                let is_non_initial_fragment = fragment.fragment_offset_value() > 0;
                packet = packet.push(fragment);
                if is_non_initial_fragment {
                    if !remaining.is_empty() {
                        packet = packet.push_raw(Raw::from_bytes(remaining));
                    }
                    return Ok(packet);
                }
                next_header = inner_next_header;
                payload = remaining;
            }
            _ => return registry.decode_ipv6_next_header(packet, next_header, payload),
        }
    }
}

fn decode_routing_header(bytes: &[u8]) -> Result<(DecodedRoutingHeader, u8, &[u8])> {
    let total_len = decode_extension_total_len("ipv6 routing header", bytes)?;
    let next_header = bytes[0];
    let routing_type = bytes[2];

    let header = match routing_type {
        IPV6_ROUTING_TYPE_MOBILE => {
            DecodedRoutingHeader::Mobile(decode_mobile_routing_header(bytes, total_len)?)
        }
        IPV6_ROUTING_TYPE_SEGMENT => {
            DecodedRoutingHeader::Segment(decode_segment_routing_header(bytes, total_len)?)
        }
        _ => DecodedRoutingHeader::Generic(Ipv6RoutingHeader {
            next_header: Field::user(next_header),
            header_ext_len: Field::user(bytes[1]),
            routing_type: Field::user(bytes[2]),
            segments_left: Field::user(bytes[3]),
            type_data: bytes[4..total_len].to_vec(),
        }),
    };

    Ok((header, next_header, &bytes[total_len..]))
}

fn decode_fragment_header(bytes: &[u8]) -> Result<(Ipv6FragmentHeader, u8, &[u8])> {
    if bytes.len() < IPV6_FRAGMENT_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv6 fragment header",
            IPV6_FRAGMENT_HEADER_LEN,
            bytes.len(),
        ));
    }

    let fragment_field = read_u16_be(&bytes[2..4])?;
    let fragment = Ipv6FragmentHeader {
        next_header: Field::user(bytes[0]),
        reserved: Field::user(bytes[1]),
        fragment_offset: Field::user(fragment_field >> 3),
        res: Field::user(((fragment_field >> 1) & 0x03) as u8),
        more_fragments: Field::user(fragment_field & 1 != 0),
        identification: Field::user(read_u32_be(&bytes[4..8])?),
    };

    Ok((fragment, bytes[0], &bytes[IPV6_FRAGMENT_HEADER_LEN..]))
}

fn decode_segment_routing_header(
    bytes: &[u8],
    total_len: usize,
) -> Result<Ipv6SegmentRoutingHeader> {
    if total_len < IPV6_SEGMENT_BASE_LEN {
        return Err(CrafterError::invalid_field_value(
            "ipv6.segment.header_ext_len",
            "segment routing header must be at least 8 bytes",
        ));
    }

    let flags = bytes[5];
    let tag = read_u16_be(&bytes[6..8])?;
    let last_entry = bytes[4] as usize;
    let segment_count = last_entry + 1;
    let required_variable_len = segment_count * 16;
    let variable = &bytes[IPV6_SEGMENT_BASE_LEN..total_len];
    if variable.len() < required_variable_len {
        return Err(CrafterError::invalid_field_value(
            "ipv6.segment.header_ext_len",
            "segment routing data is shorter than its fields require",
        ));
    }

    let mut cursor = 0;
    let mut segments = Vec::with_capacity(segment_count);
    for _ in 0..segment_count {
        segments.push(Ipv6Addr::from(copy_array_16(
            &variable[cursor..cursor + 16],
        )));
        cursor += 16;
    }
    let trailing_data = variable[cursor..].to_vec();
    validate_segment_routing_tlv_shape(&trailing_data)?;

    Ok(Ipv6SegmentRoutingHeader {
        next_header: Field::user(bytes[0]),
        header_ext_len: Field::user(bytes[1]),
        routing_type: Field::user(bytes[2]),
        segments_left: Field::user(bytes[3]),
        last_entry: Field::user(bytes[4]),
        flags: Field::user(flags),
        tag: Field::user(tag),
        policy_flag1: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        policy_flag2: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        policy_flag3: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        policy_flag4: Field::defaulted(IPV6_SEGMENT_POLICY_UNSET),
        hmac_key_id: Field::defaulted(0),
        segments,
        policies: [Ipv6Addr::UNSPECIFIED; 4],
        hmac: [0; IPV6_SEGMENT_HMAC_LEN],
        trailing_data,
    })
}

pub(in crate::protocols::ip::v6) fn validate_segment_routing_tlv_shape(bytes: &[u8]) -> Result<()> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let tlv_type = bytes[cursor];
        cursor += 1;
        if tlv_type == 0 {
            continue;
        }
        if cursor >= bytes.len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.tlv",
                "segment routing TLV is missing its length byte",
            ));
        }

        let value_len = bytes[cursor] as usize;
        cursor += 1;
        if bytes.len() - cursor < value_len {
            return Err(CrafterError::invalid_field_value(
                "ipv6.segment.tlv",
                "segment routing TLV length exceeds trailing data",
            ));
        }
        cursor += value_len;
    }
    Ok(())
}
