//! IPv4 decode and registry dispatch.

use core::net::Ipv4Addr;

use crate::checksum::ipv4_header_checksum;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Packet, Raw};
use crate::protocols::ip::shared::{IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};
use crate::registry::ProtocolRegistry;

use super::constants::{IPV4_FLAG_MORE_FRAGMENTS, IPV4_MIN_HEADER_LEN};
use super::fragment::{flags_from_flags_fragment, fragment_offset_from_flags_fragment};
use super::header::{Ipv4, Ipv4ChecksumStatus};
use super::options::validate_ipv4_options;

const QUOTED_ICMP_HEADER_LEN: usize = 8;
const QUOTED_TCP_MIN_HEADER_LEN: usize = 20;
const QUOTED_UDP_HEADER_LEN: usize = 8;

/// Append a decoded IPv4 packet using an explicit registry.
pub(crate) fn append_ipv4_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let decoded = decode_ipv4_parts(bytes, registry.validates_checksums())?;
    append_ipv4_payload_with_registry(
        registry,
        packet.push_ipv4(decoded.ipv4),
        decoded.protocol,
        decoded.fragment_offset,
        decoded.has_more_fragments,
        decoded.payload,
        decoded.rest,
    )
}

struct DecodedIpv4Packet<'a> {
    ipv4: Ipv4,
    protocol: u8,
    fragment_offset: u16,
    has_more_fragments: bool,
    payload: &'a [u8],
    rest: &'a [u8],
}

fn decode_ipv4_parts(bytes: &[u8], validate_checksum: bool) -> Result<DecodedIpv4Packet<'_>> {
    if bytes.len() < IPV4_MIN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ipv4 header",
            IPV4_MIN_HEADER_LEN,
            bytes.len(),
        ));
    }

    let version = bytes[0] >> 4;
    let ihl = bytes[0] & 0x0f;
    if version != 4 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.version",
            "IPv4 packets must have version 4",
        ));
    }
    if ihl < 5 {
        return Err(CrafterError::invalid_field_value(
            "ipv4.ihl",
            "internet header length must be at least 5 words",
        ));
    }

    let header_len = (ihl as usize) * 4;
    if bytes.len() < header_len {
        return Err(CrafterError::buffer_too_short(
            "ipv4 header",
            header_len,
            bytes.len(),
        ));
    }

    let total_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if total_length < header_len {
        return Err(CrafterError::invalid_field_value(
            "ipv4.total_length",
            "total length must be at least the IPv4 header length",
        ));
    }
    if bytes.len() < total_length {
        return Err(CrafterError::buffer_too_short(
            "ipv4 packet",
            total_length,
            bytes.len(),
        ));
    }

    let flags_fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    let flags = flags_from_flags_fragment(flags_fragment);
    let fragment_offset = fragment_offset_from_flags_fragment(flags_fragment);
    let options = if header_len > IPV4_MIN_HEADER_LEN {
        bytes[IPV4_MIN_HEADER_LEN..header_len].to_vec()
    } else {
        Vec::new()
    };
    if !options.is_empty() {
        validate_ipv4_options(&options)?;
    }
    let checksum_status = if validate_checksum {
        decoded_ipv4_checksum_status(&bytes[..header_len])
    } else {
        Ipv4ChecksumStatus::NotChecked
    };
    let protocol = bytes[9];

    let ipv4 = Ipv4 {
        version: Field::user(version),
        ihl: Field::user(ihl),
        tos: Field::user(bytes[1]),
        total_length: Field::user(total_length as u16),
        identification: Field::user(u16::from_be_bytes([bytes[4], bytes[5]])),
        flags: Field::user(flags),
        fragment_offset: Field::user(fragment_offset),
        ttl: Field::user(bytes[8]),
        protocol: Field::user(protocol),
        checksum: Field::user(u16::from_be_bytes([bytes[10], bytes[11]])),
        checksum_status,
        source: Field::user(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
        destination: Field::user(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
        options,
    };

    Ok(DecodedIpv4Packet {
        ipv4,
        protocol,
        fragment_offset,
        has_more_fragments: flags & IPV4_FLAG_MORE_FRAGMENTS != 0,
        payload: &bytes[header_len..total_length],
        rest: &bytes[total_length..],
    })
}

fn append_ipv4_payload_with_registry(
    registry: &ProtocolRegistry,
    mut packet: Packet,
    protocol: u8,
    fragment_offset: u16,
    has_more_fragments: bool,
    payload: &[u8],
    rest: &[u8],
) -> Result<Packet> {
    if fragment_offset != 0 {
        if !payload.is_empty() {
            packet = packet.push_raw(Raw::from_bytes(payload));
        }
    } else if has_more_fragments {
        packet = match registry.decode_ipv4_protocol(packet.clone(), protocol, payload) {
            Ok(decoded) => decoded,
            Err(_) => {
                if payload.is_empty() {
                    packet
                } else {
                    packet.push_raw(Raw::from_bytes(payload))
                }
            }
        };
    } else {
        packet = registry.decode_ipv4_protocol(packet, protocol, payload)?;
    }

    if !rest.is_empty() {
        packet = packet.push_raw(Raw::from_bytes(rest));
    }

    Ok(packet)
}

/// Leniently decode a quoted original IPv4 datagram carried inside an ICMPv4
/// error message (RFC 792 "Internet Header + 64 bits of Original Data
/// Datagram").
///
/// Quoted datagrams are usually truncated: routers copy the IPv4 header plus a
/// small prefix of the payload, so the IPv4 `total_length` typically exceeds the
/// bytes actually present. This decoder therefore validates and types the IPv4
/// header but never requires the full `total_length` to be present:
///
/// - The IPv4 header is parsed as typed [`Ipv4`] fields when the version is 4,
///   the IHL is at least five words, and all header bytes (including options)
///   are present.
/// - When the post-header bytes form a complete, self-consistent transport
///   datagram (so a strict decode succeeds), they are typed (UDP/TCP/ICMP/...);
///   otherwise — including the common truncated-quote case — they remain a
///   [`Raw`] tail rather than panicking or being dropped.
/// - Returns the decoded layers plus the number of leading bytes consumed by the
///   quoted datagram, so the caller can preserve any trailing bytes as `Raw`.
///
/// Returns `None` when `bytes` does not begin with a parseable IPv4 header, so
/// the caller can keep the whole ICMP payload as raw bytes.
pub(crate) fn decode_quoted_ipv4(bytes: &[u8], validate_checksum: bool) -> Option<(Packet, usize)> {
    if bytes.len() < IPV4_MIN_HEADER_LEN {
        return None;
    }

    let version = bytes[0] >> 4;
    let ihl = bytes[0] & 0x0f;
    if version != 4 || ihl < 5 {
        return None;
    }

    let header_len = (ihl as usize) * 4;
    if bytes.len() < header_len {
        return None;
    }

    let total_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    // Trust `total_length` only when it is internally consistent and fully
    // present; otherwise treat every available byte as part of the quote so a
    // truncated datagram still round-trips.
    let consumed = if total_length >= header_len && total_length <= bytes.len() {
        total_length
    } else {
        bytes.len()
    };
    let datagram = &bytes[..consumed];

    let flags_fragment = u16::from_be_bytes([datagram[6], datagram[7]]);
    let flags = flags_from_flags_fragment(flags_fragment);
    let fragment_offset = fragment_offset_from_flags_fragment(flags_fragment);
    let protocol = datagram[9];
    let options = if header_len > IPV4_MIN_HEADER_LEN {
        datagram[IPV4_MIN_HEADER_LEN..header_len].to_vec()
    } else {
        Vec::new()
    };
    if !options.is_empty() && validate_ipv4_options(&options).is_err() {
        return None;
    }
    let checksum_status = if validate_checksum {
        decoded_ipv4_checksum_status(&datagram[..header_len])
    } else {
        Ipv4ChecksumStatus::NotChecked
    };

    let ipv4 = Ipv4 {
        version: Field::user(version),
        ihl: Field::user(ihl),
        tos: Field::user(datagram[1]),
        total_length: Field::user(total_length as u16),
        identification: Field::user(u16::from_be_bytes([datagram[4], datagram[5]])),
        flags: Field::user(flags),
        fragment_offset: Field::user(fragment_offset),
        ttl: Field::user(datagram[8]),
        protocol: Field::user(protocol),
        checksum: Field::user(u16::from_be_bytes([datagram[10], datagram[11]])),
        checksum_status,
        source: Field::user(Ipv4Addr::new(
            datagram[12],
            datagram[13],
            datagram[14],
            datagram[15],
        )),
        destination: Field::user(Ipv4Addr::new(
            datagram[16],
            datagram[17],
            datagram[18],
            datagram[19],
        )),
        options,
    };

    let payload = &datagram[header_len..];
    let can_decode_transport = fragment_offset == 0
        && !payload.is_empty()
        && quoted_transport_decode_can_succeed(protocol, payload);
    let packet_capacity = match (payload.is_empty(), can_decode_transport) {
        (true, _) => 1,
        (_, true) => 3,
        _ => 2,
    };
    let mut packet = Packet::with_capacity(packet_capacity).push_ipv4(ipv4);

    // Best-effort typed transport decode. A strict failure (truncated quote or
    // unknown next protocol) keeps the remaining bytes raw-compatible. A
    // transport-only registry is used so a short quoted prefix never trips an
    // application-layer decoder (DNS, DHCP) and discards the typed L4 header.
    if fragment_offset != 0 {
        if !payload.is_empty() {
            packet = packet.push_raw(Raw::from_bytes(payload));
        }
    } else if payload.is_empty() {
        // No quoted transport bytes to type.
    } else if can_decode_transport {
        let registry = ProtocolRegistry::transport_only_builtin();
        packet = match registry.decode_ipv4_protocol(packet.clone(), protocol, payload) {
            Ok(typed) => typed,
            Err(_) => {
                if payload.is_empty() {
                    packet
                } else {
                    packet.push_raw(Raw::from_bytes(payload))
                }
            }
        };
    } else {
        packet = packet.push_raw(Raw::from_bytes(payload));
    }

    Some((packet, consumed))
}

fn quoted_transport_decode_can_succeed(protocol: u8, payload: &[u8]) -> bool {
    match protocol {
        IPPROTO_TCP => {
            if payload.len() < QUOTED_TCP_MIN_HEADER_LEN {
                return false;
            }
            let data_offset = payload[12] >> 4;
            data_offset >= 5 && payload.len() >= (data_offset as usize) * 4
        }
        IPPROTO_UDP => {
            if payload.len() < QUOTED_UDP_HEADER_LEN {
                return false;
            }
            let length = u16::from_be_bytes([payload[4], payload[5]]) as usize;
            length >= QUOTED_UDP_HEADER_LEN && payload.len() >= length
        }
        IPPROTO_ICMP => payload.len() >= QUOTED_ICMP_HEADER_LEN,
        _ => true,
    }
}

fn decoded_ipv4_checksum_status(header: &[u8]) -> Ipv4ChecksumStatus {
    if ipv4_header_checksum(header) == 0 {
        Ipv4ChecksumStatus::Valid
    } else {
        Ipv4ChecksumStatus::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::decode_quoted_ipv4;
    use crate::{Raw, Udp};

    fn quoted_udp_prefix(total_len: u16, udp_len: u16, udp_payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![
            0x45,
            0,
            (total_len >> 8) as u8,
            total_len as u8,
            0x12,
            0x34,
            0,
            0,
            64,
            17,
            0,
            0,
            192,
            0,
            2,
            1,
            198,
            51,
            100,
            1,
            0x9c,
            0x40,
            0,
            53,
            (udp_len >> 8) as u8,
            udp_len as u8,
            0,
            0,
        ];
        bytes.extend_from_slice(udp_payload);
        bytes
    }

    #[test]
    fn quoted_ipv4_keeps_truncated_udp_header_raw() {
        let quoted = quoted_udp_prefix(34, 14, &[]);

        let (packet, consumed) = decode_quoted_ipv4(&quoted, true).unwrap();

        assert_eq!(consumed, quoted.len());
        assert!(packet.layer::<Udp>().is_none());
        assert_eq!(packet.layer::<Raw>().unwrap().as_bytes(), &quoted[20..]);
    }

    #[test]
    fn quoted_ipv4_still_types_complete_udp_datagram() {
        let quoted = quoted_udp_prefix(34, 14, b"quoted");

        let (packet, consumed) = decode_quoted_ipv4(&quoted, true).unwrap();

        assert_eq!(consumed, quoted.len());
        assert!(packet.layer::<Udp>().is_some());
        assert_eq!(packet.layer::<Raw>().unwrap().as_bytes(), b"quoted");
    }
}
