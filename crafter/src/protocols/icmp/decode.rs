//! ICMPv4 decode path.
//!
//! Turns wire bytes into a typed [`Icmp`] header plus body, extension, and
//! quoted-datagram trailers, falling back to [`Raw`] for anything that fails
//! the defensible-parse gate. The entrypoint is [`append_icmp_packet`], used by
//! the registry and the IP layer; the rest are its private dispatch helpers.

use core::net::Ipv4Addr;

use super::*;
use crate::checksum::internet_checksum;
use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, Packet, Raw};
use crate::protocols::ipv4::decode_quoted_ipv4;

/// Append a decoded ICMP packet to an existing packet stack.
pub(crate) fn append_icmp_packet(mut packet: Packet, bytes: &[u8]) -> Result<Packet> {
    let (icmp, payload) = decode_icmp_parts(bytes)?;
    let icmp_type = icmp.icmp_type_value();
    // RFC 1256 router advertisement fields are read from the fixed header before
    // it is pushed (and moved) so the entry parser below can use them.
    let ra_num_addrs = icmp.num_addrs_value().unwrap_or(0) as usize;
    let ra_entry_words = icmp.addr_entry_size_value().unwrap_or(0) as usize;
    // RFC 4884 length field (32-bit words of the padded original datagram) for
    // the extension-capable error types; read before the header is moved.
    let rfc4884_length_words = if icmpv4_type_allows_extensions(icmp_type) {
        icmp.length_value().unwrap_or(0) as usize
    } else {
        0
    };
    packet = packet.push(icmp);

    if payload.is_empty() {
        return Ok(packet);
    }

    // RFC 792 error messages quote the original datagram after the fixed
    // header. Type it as an `Icmpv4QuotedIp` layer when the quote begins with a
    // parseable IPv4 header; anything left over (or an unparseable quote)
    // stays raw-compatible so the bytes are never dropped.
    if icmpv4_type_is_error(icmp_type) {
        if let Some((quoted, consumed)) = decode_quoted_ipv4(payload) {
            packet = packet.push(Icmpv4QuotedIp { datagram: quoted });
            let trailing = &payload[consumed..];
            if trailing.is_empty() {
                return Ok(packet);
            }
            // RFC 4884: when the length field claims a padded original datagram
            // and a valid extension structure follows, split the trailing bytes
            // into the extension header and its objects. Anything that does not
            // parse defensibly (bad version, bad checksum, non-canonical
            // padding, impossible object lengths) stays a single `Raw` tail.
            match decode_icmp_extensions(payload, consumed, rfc4884_length_words) {
                Some(layers) => {
                    for layer in layers {
                        packet = packet.push_box(layer);
                    }
                }
                None => {
                    packet = packet.push(Raw::from_bytes(trailing));
                }
            }
            return Ok(packet);
        }
    }

    // RFC 8335 extended echo request carries an RFC 4884 extension structure
    // (extension header plus a single Interface Identification Object) directly
    // after the fixed header — no quoted datagram and no original-datagram
    // padding. Type it when the structure parses defensibly; anything else
    // (bad version, bad checksum, impossible object lengths) stays raw so the
    // bytes survive and decoding never panics. The reply has no body, so any
    // trailing bytes on a reply fall through to the raw tail below.
    if icmp_type == ICMP_EXTENDED_ECHO_REQUEST {
        if let Some(layers) = decode_extended_echo_extension(payload) {
            for layer in layers {
                packet = packet.push_box(layer);
            }
            return Ok(packet);
        }
    }

    // RFC 792 timestamp messages carry exactly three 32-bit timestamps after
    // the fixed header. Type the body only when its length is exactly right;
    // a short or oversized region is a malformed timestamp and stays raw so the
    // bytes survive and decoding never panics.
    if matches!(icmp_type, ICMP_TIMESTAMP | ICMP_TIMESTAMP_REPLY)
        && payload.len() == ICMP_TIMESTAMP_BODY_LEN
    {
        let originate = read_u32_be(&payload[0..4])?;
        let receive = read_u32_be(&payload[4..8])?;
        let transmit = read_u32_be(&payload[8..12])?;
        packet = packet.push(Icmpv4Timestamp {
            originate: Field::user(originate),
            receive: Field::user(receive),
            transmit: Field::user(transmit),
        });
        return Ok(packet);
    }

    // RFC 950 address mask messages carry exactly one 32-bit mask after the
    // fixed header. Type the body only when its length is exactly right; any
    // other length is malformed and stays raw so the bytes survive and decoding
    // never panics.
    if matches!(
        icmp_type,
        ICMP_ADDRESS_MASK_REQUEST | ICMP_ADDRESS_MASK_REPLY
    ) && payload.len() == ICMP_ADDRESS_MASK_BODY_LEN
    {
        let mask = Ipv4Addr::from(copy_array_4(&payload[0..4]));
        packet = packet.push(Icmpv4AddressMask {
            mask: Field::user(mask),
        });
        return Ok(packet);
    }

    // RFC 1256 router advertisement entries follow the fixed header. Type them
    // only when the message uses the standard entry size (two 32-bit words) and
    // the body length is exactly Num Addrs entries; any other shape (a
    // non-standard Addr Entry Size, a count/length mismatch, or trailing data)
    // is left raw so unusual or malformed bodies survive and decoding never
    // panics.
    if icmp_type == ICMP_ROUTER_ADVERTISEMENT
        && ra_entry_words == ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS as usize
        && payload.len() == ra_num_addrs * ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN
        && ra_num_addrs > 0
    {
        for chunk in payload.chunks_exact(ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN) {
            let router_address = Ipv4Addr::from(copy_array_4(&chunk[0..4]));
            let preference_level = read_u32_be(&chunk[4..8])? as i32;
            packet = packet.push(Icmpv4RouterAdvertisementEntry {
                router_address: Field::user(router_address),
                preference_level: Field::user(preference_level),
            });
        }
        return Ok(packet);
    }

    packet = packet.push(Raw::from_bytes(payload));
    Ok(packet)
}

/// Decode the RFC 4884 extension structure that follows a quoted original
/// datagram, returning the typed [`IcmpExtension`] and [`IcmpExtensionObject`]
/// layers (plus a `Raw` body per object) when the parse is defensible.
///
/// `payload` is the ICMP body after the fixed header, `quoted_len` is the
/// number of bytes consumed by the quoted datagram, and `length_words` is the
/// RFC 4884 length field (32-bit words of the padded original datagram).
///
/// Returns `None` — so the caller keeps the trailing bytes as a single `Raw`
/// tail — whenever the length field claims no extensions, the claimed offset is
/// out of range, the padding is non-canonical (so a typed round-trip would not
/// reproduce the bytes), the extension version is not 2, the extension checksum
/// does not verify, or an object length is impossible. The quoted datagram is
/// never dropped, so an ambiguous structure stays inspectable as raw bytes.
fn decode_icmp_extensions(
    payload: &[u8],
    quoted_len: usize,
    length_words: usize,
) -> Option<Vec<Box<dyn Layer>>> {
    // A zero length field means "no extensions" per RFC 4884.
    if length_words == 0 {
        return None;
    }

    let ext_start = length_words * ICMP_EXTENSION_OBJECT_LEN;
    // The claimed original datagram region must contain the quote and leave room
    // for at least the extension header.
    if ext_start < quoted_len || ext_start + ICMP_EXTENSION_HEADER_LEN > payload.len() {
        return None;
    }

    // The padding between the quote and the extension header is part of the
    // original datagram. Only a canonical (zero) padding round-trips, because
    // the encoder regenerates it from the length field; anything else is left
    // raw so the bytes survive unchanged.
    if payload[quoted_len..ext_start].iter().any(|&byte| byte != 0) {
        return None;
    }

    let extension = &payload[ext_start..];
    let version = extension[0] >> 4;
    if version != ICMP_EXTENSION_VERSION {
        return None;
    }
    let reserved = u16::from_be_bytes([extension[0], extension[1]]) & 0x0fff;
    let stored_checksum = u16::from_be_bytes([extension[2], extension[3]]);

    // RFC 4884: a zero checksum means none was transmitted; otherwise the one's
    // complement sum over the whole extension structure must verify. A bad
    // checksum is treated as "not really an extension" and the bytes stay raw.
    if stored_checksum != 0 && internet_checksum(extension) != 0 {
        return None;
    }

    let objects = decode_icmp_extension_objects(&extension[ICMP_EXTENSION_HEADER_LEN..])?;

    let mut layers: Vec<Box<dyn Layer>> = Vec::with_capacity(1 + objects.len());
    layers.push(Box::new(
        IcmpExtension::new()
            .version(version)
            .reserved(reserved)
            .checksum(stored_checksum),
    ));
    layers.extend(objects);
    Some(layers)
}

/// Decode the RFC 4884 extension structure carried by an RFC 8335 extended echo
/// request, which begins immediately after the fixed ICMP header (no quoted
/// original datagram and no original-datagram padding).
///
/// Shared by both ICMPv4 (type 42) and ICMPv6 (type 160) extended echo requests:
/// RFC 8335 defines the same extension structure for both versions, so the
/// ICMPv6 decode path in `icmp/v6/mod.rs` reuses this function rather than
/// duplicating the extension framework.
///
/// Returns the typed [`IcmpExtension`] header and its objects (an
/// [`IcmpExtensionInterfaceId`] for the standard single Interface Identification
/// Object, or generic objects otherwise) when the structure parses defensibly.
/// Returns `None` — so the caller keeps the payload as a single `Raw` body —
/// when the payload is too short for the extension header, the version is not 2,
/// the extension checksum does not verify, or an object length is impossible.
pub(crate) fn decode_extended_echo_extension(payload: &[u8]) -> Option<Vec<Box<dyn Layer>>> {
    if payload.len() < ICMP_EXTENSION_HEADER_LEN {
        return None;
    }

    let version = payload[0] >> 4;
    if version != ICMP_EXTENSION_VERSION {
        return None;
    }
    let reserved = u16::from_be_bytes([payload[0], payload[1]]) & 0x0fff;
    let stored_checksum = u16::from_be_bytes([payload[2], payload[3]]);

    // RFC 4884: a zero checksum means none was transmitted; otherwise the one's
    // complement sum over the whole extension structure must verify.
    if stored_checksum != 0 && internet_checksum(payload) != 0 {
        return None;
    }

    let objects = decode_icmp_extension_objects(&payload[ICMP_EXTENSION_HEADER_LEN..])?;

    let mut layers: Vec<Box<dyn Layer>> = Vec::with_capacity(1 + objects.len());
    layers.push(Box::new(
        IcmpExtension::new()
            .version(version)
            .reserved(reserved)
            .checksum(stored_checksum),
    ));
    layers.extend(objects);
    Some(layers)
}

/// Decode the object stream that follows an RFC 4884 extension header into
/// [`IcmpExtensionObject`] layers, each followed by the object body.
///
/// RFC 4950 MPLS label stack objects (class 1, C-Type 1) whose body is a whole
/// number of 4-octet entries decode into typed [`IcmpExtensionMpls`] layers,
/// preserving the label, experimental/traffic-class bits, bottom-of-stack bit,
/// and TTL of each entry. RFC 5837 interface information objects (class 2)
/// whose body parses cleanly per the C-Type presence bits decode into a typed
/// [`IcmpExtensionInterfaceInfo`] layer. Every other object — and any object
/// whose body does not parse defensibly — keeps its body as a single `Raw`
/// payload so unknown classes/sub-types and malformed bodies round-trip
/// byte-for-byte.
///
/// Returns `None` when an object header is truncated or claims a length that
/// does not fit the remaining bytes, so the caller can keep the whole region
/// raw rather than fabricating a structure.
fn decode_icmp_extension_objects(mut bytes: &[u8]) -> Option<Vec<Box<dyn Layer>>> {
    let mut objects: Vec<Box<dyn Layer>> = Vec::new();

    while !bytes.is_empty() {
        if bytes.len() < ICMP_EXTENSION_OBJECT_LEN {
            return None;
        }
        let length = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        // The length covers the 4-byte object header plus its payload and must
        // fit in the remaining bytes; anything else is an impossible object.
        if length < ICMP_EXTENSION_OBJECT_LEN || length > bytes.len() {
            return None;
        }
        let class_num = bytes[2];
        let c_type = bytes[3];
        objects.push(Box::new(
            IcmpExtensionObject::new()
                .length(length as u16)
                .class_num(class_num)
                .c_type(c_type),
        ));
        let body = &bytes[ICMP_EXTENSION_OBJECT_LEN..length];
        if !body.is_empty() {
            // RFC 4950: a MPLS label stack object carries one or more 4-octet
            // label stack entries. Type them only when the body is a whole
            // number of entries; a partial entry is a malformed body and stays
            // raw so the bytes survive and decoding never panics.
            if class_num == ICMP_EXTENSION_CLASS_MPLS
                && c_type == ICMP_EXTENSION_CTYPE_MPLS_INCOMING
                && body.len() % ICMP_EXTENSION_MPLS_LEN == 0
            {
                for chunk in body.chunks_exact(ICMP_EXTENSION_MPLS_LEN) {
                    objects.push(Box::new(decode_mpls_entry(chunk)));
                }
            } else if class_num == ICMP_EXTENSION_CLASS_INTERFACE_INFO {
                // RFC 5837: type the body per the C-Type presence bits, but only
                // when the sub-objects consume the whole body exactly (so a
                // re-compile reproduces the bytes). Anything else stays raw.
                match decode_interface_info(c_type, body) {
                    Some(info) => objects.push(Box::new(info)),
                    None => objects.push(Box::new(Raw::from_bytes(body))),
                }
            } else if class_num == ICMP_EXTENSION_CLASS_INTERFACE_ID {
                // RFC 8335: type the Interface Identification Object body per its
                // C-Type (name/index/address) when it parses defensibly with
                // canonical zero padding; anything else stays raw so the bytes
                // round-trip unchanged.
                match decode_interface_id(c_type, body) {
                    Some(id) => objects.push(Box::new(id)),
                    None => objects.push(Box::new(Raw::from_bytes(body))),
                }
            } else {
                objects.push(Box::new(Raw::from_bytes(body)));
            }
        }
        bytes = &bytes[length..];
    }

    Some(objects)
}

fn decode_icmp_parts(bytes: &[u8]) -> Result<(Icmpv4, &[u8])> {
    if bytes.len() < ICMP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "icmp header",
            ICMP_HEADER_LEN,
            bytes.len(),
        ));
    }

    let rest = copy_array_4(&bytes[4..8]);
    let icmp_type = bytes[0];
    // RFC 8335 extended echo: identifier (bytes 0-1), an 8-bit sequence number
    // (byte 2, zero-extended into the u16 sequence field), and a flag byte
    // (byte 3). RFC 792/RFC 950 query families keep their 16-bit sequence.
    let extended = is_extended_echo_v4(icmp_type);
    let identifier = if extended {
        Field::user(u16::from_be_bytes([rest[0], rest[1]]))
    } else {
        field_from_echo(icmp_type, &rest, 0, is_query_v4)
    };
    let sequence_number = if extended {
        Field::user(u16::from(rest[2]))
    } else {
        field_from_echo(icmp_type, &rest, 2, is_query_v4)
    };
    let icmp = Icmpv4 {
        icmp_type: Field::user(icmp_type),
        code: Field::user(bytes[1]),
        checksum: Field::user(read_u16_be(&bytes[2..4])?),
        rest_of_header: Field::user(rest),
        identifier,
        sequence_number,
        pointer: if icmp_type == ICMP_PARAMETER_PROBLEM {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        gateway: if icmp_type == ICMP_REDIRECT {
            Field::user(Ipv4Addr::from(rest))
        } else {
            Field::unset()
        },
        length: if icmpv4_type_allows_extensions(icmp_type) {
            Field::user(rest[1])
        } else {
            Field::unset()
        },
        mtu_next_hop: if icmp_type == ICMP_DESTINATION_UNREACHABLE {
            Field::user(u16::from_be_bytes([rest[2], rest[3]]))
        } else {
            Field::unset()
        },
        num_addrs: if icmp_type == ICMP_ROUTER_ADVERTISEMENT {
            Field::user(rest[0])
        } else {
            Field::unset()
        },
        addr_entry_size: if icmp_type == ICMP_ROUTER_ADVERTISEMENT {
            Field::user(rest[1])
        } else {
            Field::unset()
        },
        lifetime: if icmp_type == ICMP_ROUTER_ADVERTISEMENT {
            Field::user(u16::from_be_bytes([rest[2], rest[3]]))
        } else {
            Field::unset()
        },
        extended_flags: if extended {
            Field::user(rest[3])
        } else {
            Field::unset()
        },
    };

    Ok((icmp, &bytes[ICMP_HEADER_LEN..]))
}

#[cfg(test)]
mod icmp_tests {
    use super::{
        IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpKind, Icmpv4, ICMP_ECHO_REQUEST,
        ICMP_TIME_EXCEEDED,
    };
    use crate::{Ipv4, Ipv4Protocol, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    const IPV4_ICMP_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv4-icmp-echo-request.bin");

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    #[test]
    fn icmp_echo_request_matches_golden_bytes() {
        let packet = Ipv4::new()
            .src(src())
            .dst(dst())
            .id(0x1234)
            .dont_fragment(true)
            / Icmpv4::echo_request().id(0x4242).seq(1)
            / Raw::from("libcrafter-icmp");
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes(), IPV4_ICMP_FIXTURE);
        assert_eq!(&bytes.as_bytes()[20..22], &[ICMP_ECHO_REQUEST, 0]);
        assert_eq!(&bytes.as_bytes()[22..24], &0xa7d0u16.to_be_bytes());
    }

    #[test]
    fn icmp_decode_from_ipv4_exposes_echo_fields_and_payload() {
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, IPV4_ICMP_FIXTURE).unwrap();
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(icmp.kind_value(), Some(IcmpKind::EchoRequest));
        assert_eq!(icmp.code_value(), 0);
        assert_eq!(icmp.checksum_value(), Some(0xa7d0));
        assert_eq!(icmp.identifier_value(), Some(0x4242));
        assert_eq!(icmp.sequence_number_value(), Some(1));
        assert_eq!(raw.as_bytes(), b"libcrafter-icmp");
        assert_eq!(decoded.compile().unwrap().as_bytes(), IPV4_ICMP_FIXTURE);
    }

    #[test]
    fn icmp_explicit_checksum_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::echo_request().id(7).seq(8).checksum(0x1111)
            / Raw::from("abc"))
        .compile()
        .unwrap();

        assert_eq!(&bytes.as_bytes()[22..24], &[0x11, 0x11]);
    }

    #[test]
    fn icmp_time_exceeded_autofills_length_and_extension_objects() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded().code(0)
            / (Ipv4::new()
                .src(Ipv4Addr::new(5, 6, 7, 8))
                .dst(Ipv4Addr::new(10, 11, 12, 13))
                .ipv4_protocol(Ipv4Protocol::Udp)
                / Udp::new().sport(53).dport(1111)
                / Raw::from("data"))
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1234).ttl(100)
            / IcmpExtensionMpls::new()
                .label(2345)
                .experimental(6)
                .ttl(150);
        let bytes = packet.compile().unwrap();

        assert_eq!(bytes.as_bytes()[20], ICMP_TIME_EXCEEDED);
        // RFC 4884: the 32-byte quoted datagram is zero padded up to the 128
        // octet minimum, so the length field reports 32 words and the extension
        // structure starts 96 padding bytes after the 32-byte quote.
        assert_eq!(bytes.as_bytes()[25], 32);
        assert!(bytes.as_bytes()[60..156].iter().all(|&byte| byte == 0));
        // Extension header (version 2, reserved 0) at the padded boundary.
        assert_eq!(&bytes.as_bytes()[156..158], &[0x20, 0x00]);
        // Extension object: length 12 (4-byte header + two MPLS words), class 1
        // (MPLS), C-Type 1 (incoming label stack).
        assert_eq!(&bytes.as_bytes()[160..164], &[0x00, 0x0c, 0x01, 0x01]);
        assert_eq!(bytes.as_bytes()[166] & 0x01, 0);
        assert_eq!(bytes.as_bytes()[170] & 0x01, 1);
    }

    #[test]
    fn icmp_decode_rejects_short_inputs() {
        let short = (Ipv4::new().ipv4_protocol(Ipv4Protocol::Icmpv4) / Raw::from_bytes([0u8; 7]))
            .compile()
            .unwrap();
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, short.as_bytes()).is_err());
    }
}

#[cfg(test)]
mod ping_roundtrip {
    use super::{IcmpKind, IcmpLayer, Icmpv4, Icmpv6};
    use crate::{Ipv4, Ipv6, NetworkLayer, Packet, Raw};
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn echo_reply_matches(request: &dyn IcmpLayer, reply: &dyn IcmpLayer) -> bool {
        request.kind() == Some(IcmpKind::EchoRequest)
            && reply.kind() == Some(IcmpKind::EchoReply)
            && request.identifier_value() == reply.identifier_value()
            && request.sequence_number_value() == reply.sequence_number_value()
    }

    #[test]
    fn ping_roundtrip_matches_ipv4_echo_reply_by_id_and_sequence() {
        let src = Ipv4Addr::new(192, 0, 2, 10);
        let dst = Ipv4Addr::new(198, 51, 100, 20);
        let request = Ipv4::new().src(src).dst(dst)
            / Icmpv4::echo_request().id(0x7777).seq(9)
            / Raw::from("ping");
        let reply = Ipv4::new().src(dst).dst(src)
            / Icmpv4::echo_reply().id(0x7777).seq(9)
            / Raw::from("ping");

        let decoded_request =
            Packet::decode_from_l3(NetworkLayer::Ipv4, request.compile().unwrap()).unwrap();
        let decoded_reply =
            Packet::decode_from_l3(NetworkLayer::Ipv4, reply.compile().unwrap()).unwrap();

        assert!(echo_reply_matches(
            decoded_request.layer::<Icmpv4>().unwrap(),
            decoded_reply.layer::<Icmpv4>().unwrap()
        ));
    }

    #[test]
    fn ping_roundtrip_matches_ipv6_echo_reply_by_id_and_sequence() {
        let src = Ipv6Addr::new(0x2001, 0x0db8, 1, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0x0db8, 2, 0, 0, 0, 0, 2);
        let request = Ipv6::new().src(src).dst(dst)
            / Icmpv6::echo_request().id(0x8888).seq(10)
            / Raw::from("ping6");
        let reply = Ipv6::new().src(dst).dst(src)
            / Icmpv6::echo_reply().id(0x8888).seq(10)
            / Raw::from("ping6");

        let decoded_request =
            Packet::decode_from_l3(NetworkLayer::Ipv6, request.compile().unwrap()).unwrap();
        let decoded_reply =
            Packet::decode_from_l3(NetworkLayer::Ipv6, reply.compile().unwrap()).unwrap();

        assert!(echo_reply_matches(
            decoded_request.layer::<Icmpv6>().unwrap(),
            decoded_reply.layer::<Icmpv6>().unwrap()
        ));
    }
}

#[cfg(test)]
mod icmpv4_rfc792_errors {
    use super::{
        icmpv4_code_summary, icmpv4_type_is_deprecated, Icmpv4, Icmpv4QuotedIp,
        ICMP_CODE_DU_FRAGMENTATION_NEEDED, ICMP_CODE_DU_PORT_UNREACHABLE,
        ICMP_CODE_PARAMETER_PROBLEM_POINTER, ICMP_CODE_REDIRECT_HOST,
        ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY, ICMP_DESTINATION_UNREACHABLE,
        ICMP_PARAMETER_PROBLEM, ICMP_REDIRECT, ICMP_SOURCE_QUENCH, ICMP_TIME_EXCEEDED,
    };
    use crate::packet::Layer;
    use crate::{Ipv4, Ipv4Protocol, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // A complete quoted original datagram (IPv4 + UDP + payload) that an agent
    // would construct for an error message.
    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .ipv4_protocol(Ipv4Protocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // Each RFC 792 error type compiles with the type/code the caller chose and
    // carries its quoted datagram. The quoted IPv4 source/destination survive a
    // full decode round-trip as typed layers.
    #[test]
    fn icmpv4_rfc792_errors_each_type_quotes_original_datagram() {
        for (icmp_type, code) in [
            (ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_PORT_UNREACHABLE),
            (ICMP_SOURCE_QUENCH, 0),
            (
                ICMP_TIME_EXCEEDED,
                ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY,
            ),
            (ICMP_PARAMETER_PROBLEM, ICMP_CODE_PARAMETER_PROBLEM_POINTER),
        ] {
            let packet = Ipv4::new().src(src()).dst(dst())
                / Icmpv4::new().icmp_type(icmp_type).code(code)
                / Icmpv4QuotedIp::new(quoted_udp());
            let compiled = packet.compile().unwrap();
            assert_eq!(compiled.as_bytes()[20], icmp_type);
            assert_eq!(compiled.as_bytes()[21], code);

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            let icmp = decoded.layer::<Icmpv4>().unwrap();
            assert_eq!(icmp.icmp_type_value(), icmp_type);
            assert_eq!(icmp.code_value(), code);

            let quoted = decoded.layer::<Icmpv4QuotedIp>().unwrap();
            let inner = quoted.quoted_layer::<Ipv4>().unwrap();
            assert_eq!(inner.source(), Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(inner.destination(), Ipv4Addr::new(198, 51, 100, 1));
            let inner_udp = quoted.quoted_layer::<Udp>().unwrap();
            assert_eq!(inner_udp.destination_port_value(), 53);
            assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
        }
    }

    // Representative codes for the error types that carry an IANA code registry
    // render their stable names while keeping the numeric value visible.
    #[test]
    fn icmpv4_rfc792_errors_representative_codes_summarize() {
        assert_eq!(
            icmpv4_code_summary(ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_DU_PORT_UNREACHABLE),
            "port-unreachable(3)"
        );
        assert_eq!(
            icmpv4_code_summary(
                ICMP_TIME_EXCEEDED,
                ICMP_CODE_TIME_EXCEEDED_FRAGMENT_REASSEMBLY
            ),
            "fragment-reassembly-time-exceeded(1)"
        );
        assert_eq!(
            icmpv4_code_summary(ICMP_PARAMETER_PROBLEM, ICMP_CODE_PARAMETER_PROBLEM_POINTER),
            "pointer(0)"
        );
    }

    // Redirect carries the gateway address in the rest-of-header; the typed
    // gateway accessor survives a decode round-trip and the quoted datagram is
    // typed alongside it.
    #[test]
    fn icmpv4_rfc792_errors_redirect_gateway_and_quote_roundtrip() {
        let gateway = Ipv4Addr::new(192, 0, 2, 254);
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new()
                .icmp_type(ICMP_REDIRECT)
                .code(ICMP_CODE_REDIRECT_HOST)
                .gateway(gateway)
            / Icmpv4QuotedIp::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        // Rest-of-header (ICMP bytes 4..8) holds the gateway address.
        assert_eq!(&compiled.as_bytes()[24..28], &gateway.octets());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        assert_eq!(icmp.gateway_value(), Some(gateway));
        assert_eq!(icmp.code_value(), ICMP_CODE_REDIRECT_HOST);
        assert!(decoded.layer::<Icmpv4QuotedIp>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Parameter problem carries the pointer byte at rest-of-header[0]; it
    // survives a decode round-trip.
    #[test]
    fn icmpv4_rfc792_errors_parameter_problem_pointer_roundtrip() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new().icmp_type(ICMP_PARAMETER_PROBLEM).pointer(12)
            / Icmpv4QuotedIp::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        assert_eq!(compiled.as_bytes()[24], 12);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(decoded.layer::<Icmpv4>().unwrap().pointer_value(), Some(12));
    }

    // Source quench (type 4) is deprecated by RFC 6633 but still constructible
    // and decodable as an error message with a quoted datagram.
    #[test]
    fn icmpv4_rfc792_errors_source_quench_is_deprecated_but_usable() {
        assert!(icmpv4_type_is_deprecated(ICMP_SOURCE_QUENCH));

        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new().icmp_type(ICMP_SOURCE_QUENCH)
            / Icmpv4QuotedIp::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv4>().unwrap().icmp_type_value(),
            ICMP_SOURCE_QUENCH
        );
        assert!(decoded.layer::<Icmpv4QuotedIp>().is_some());
    }

    // RFC 1191: destination unreachable code 4 (fragmentation needed) carries an
    // unused high-order 16 bits and a 16-bit next-hop MTU in the second word.
    #[test]
    fn icmpv4_rfc792_errors_rfc1191_next_hop_mtu_roundtrips() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new()
                .icmp_type(ICMP_DESTINATION_UNREACHABLE)
                .code(ICMP_CODE_DU_FRAGMENTATION_NEEDED)
                .mtu_next_hop(1492)
            / Icmpv4QuotedIp::new(quoted_udp());
        let compiled = packet.compile().unwrap();
        // ICMP rest-of-header: bytes 4..6 unused (RFC 4884 length byte aside),
        // bytes 6..8 are the next-hop MTU. Byte index 24 is rest-of-header[0].
        assert_eq!(&compiled.as_bytes()[26..28], &1492u16.to_be_bytes());
        // The high-order unused word must stay zero.
        assert_eq!(compiled.as_bytes()[24], 0);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmpv4>().unwrap().mtu_next_hop_value(),
            Some(1492)
        );
    }

    // A quoted datagram that is only the IPv4 header plus the first 8 bytes of
    // the original payload (the RFC 792 minimum) is the common truncated case:
    // the IPv4 header is typed, the truncated payload stays raw-compatible, and
    // nothing panics.
    #[test]
    fn icmpv4_rfc792_errors_truncated_quote_does_not_panic() {
        // Build a full datagram, then keep only header + 8 payload bytes so the
        // quoted IPv4 total_length deliberately overshoots the present bytes.
        let original = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .ipv4_protocol(Ipv4Protocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("a-long-original-payload"))
        .compile()
        .unwrap();
        let mut quote = original.as_bytes().to_vec();
        quote.truncate(20 + 8); // IPv4 header (20) + 64 bits of original data.

        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new().icmp_type(ICMP_TIME_EXCEEDED)
            / Raw::from_bytes(&quote);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let quoted = decoded.layer::<Icmpv4QuotedIp>().unwrap();
        let inner = quoted.quoted_layer::<Ipv4>().unwrap();
        assert_eq!(inner.source(), Ipv4Addr::new(192, 0, 2, 1));
        // The truncated UDP header could not be fully decoded, so it stays raw.
        assert!(quoted.quoted_layer::<Udp>().is_none());
        assert!(quoted.datagram().layer::<Raw>().is_some());
        // The whole message still round-trips byte-for-byte.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A quoted next protocol crafter does not decode (here protocol 254) keeps
    // the quoted IPv4 header typed and the rest of the quote raw-compatible.
    #[test]
    fn icmpv4_rfc792_errors_unknown_quoted_protocol_falls_back_to_raw() {
        let quoted = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .protocol(254)
            / Raw::from("opaque-upper-layer");
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new().icmp_type(ICMP_DESTINATION_UNREACHABLE)
            / Icmpv4QuotedIp::new(quoted);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let quoted = decoded.layer::<Icmpv4QuotedIp>().unwrap();
        let inner = quoted.quoted_layer::<Ipv4>().unwrap();
        assert_eq!(inner.protocol_value(), 254);
        assert_eq!(
            quoted.datagram().layer::<Raw>().unwrap().as_bytes(),
            b"opaque-upper-layer"
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A non-IPv4 quote (the bytes do not start with a valid IPv4 header) is not
    // forced into the typed quoted layer; it remains a plain Raw payload so no
    // bytes are lost.
    #[test]
    fn icmpv4_rfc792_errors_non_ipv4_quote_stays_raw() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new().icmp_type(ICMP_DESTINATION_UNREACHABLE)
            / Raw::from_bytes([0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<Icmpv4QuotedIp>().is_none());
        assert_eq!(
            decoded.layer::<Raw>().unwrap().as_bytes(),
            &[0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
    }

    // Explicit malformed overrides on an error message survive compilation: a
    // deliberately wrong checksum and a pinned raw rest-of-header are emitted
    // verbatim even though the type would otherwise auto-fill them.
    #[test]
    fn icmpv4_rfc792_errors_explicit_malformed_overrides_are_preserved() {
        let raw_rest = [0xde, 0xad, 0xbe, 0xef];
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new()
                .icmp_type(ICMP_TIME_EXCEEDED)
                .code(0)
                .checksum(0xbeef)
                .rest_of_header(raw_rest)
            / Icmpv4QuotedIp::new(quoted_udp());
        let compiled = packet.compile().unwrap();

        // The intentionally wrong checksum is honored verbatim.
        assert_eq!(&compiled.as_bytes()[22..24], &0xbeefu16.to_be_bytes());
        // The pinned rest-of-header survives the RFC 4884 length auto-fill.
        assert_eq!(&compiled.as_bytes()[24..28], &raw_rest);
    }

    // The quoted layer summary keeps the nested datagram inspectable.
    #[test]
    fn icmpv4_rfc792_errors_quoted_layer_summary_is_inspectable() {
        let quoted = Icmpv4QuotedIp::new(quoted_udp());
        let summary = quoted.summary();
        assert!(summary.starts_with("IcmpQuotedIpv4("));
        assert!(summary.contains("Ipv4"));
    }
}
