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
use crate::protocols::ip::decode_quoted_ipv4;

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
    // header. Type it as an `IcmpQuotedIpv4` layer when the quote begins with a
    // parseable IPv4 header; anything left over (or an unparseable quote)
    // stays raw-compatible so the bytes are never dropped.
    if icmpv4_type_is_error(icmp_type) {
        if let Some((quoted, consumed)) = decode_quoted_ipv4(payload) {
            packet = packet.push(IcmpQuotedIpv4 { datagram: quoted });
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
        packet = packet.push(IcmpTimestamp {
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
        packet = packet.push(IcmpAddressMask {
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
            packet = packet.push(IcmpRouterAdvertisementEntry {
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
/// Returns the typed [`IcmpExtension`] header and its objects (an
/// [`IcmpExtensionInterfaceId`] for the standard single Interface Identification
/// Object, or generic objects otherwise) when the structure parses defensibly.
/// Returns `None` — so the caller keeps the payload as a single `Raw` body —
/// when the payload is too short for the extension header, the version is not 2,
/// the extension checksum does not verify, or an object length is impossible.
fn decode_extended_echo_extension(payload: &[u8]) -> Option<Vec<Box<dyn Layer>>> {
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

fn decode_icmp_parts(bytes: &[u8]) -> Result<(Icmp, &[u8])> {
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
    let icmp = Icmp {
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
