//! AH decode (no SA) and the registry append hook (RFC 4302).
//!
//! Unlike ESP, the Authentication Header never encrypts: it only authenticates
//! (RFC 4302 §1). The protected upper-layer data — and, in tunnel mode, the
//! entire inner IP datagram — travels in the clear after the AH header, so a
//! receiver can always parse the fixed header, capture the variable-length
//! Integrity Check Value, and dispatch the inner protocol by Next Header even
//! without keys. With no SA the ICV bytes are preserved verbatim (a re-compile
//! reproduces them); verifying them against an SA is a later step.
//!
//! The ICV length is derived from the Payload Len field: the field counts the
//! whole AH header in 32-bit words minus 2 (RFC 4302 §2.2), so the on-wire AH
//! header is `(payload_len + 2) * 4` octets and the ICV is that minus the fixed
//! 12-octet portion. Truncation before the fixed header, or before the ICV the
//! Payload Len advertises, is a structured error, never a panic. Mirrors UDP's
//! and ESP's `decode_<proto>_parts` / `append_<proto>_packet_with_registry`
//! shape.

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::packet::Packet;
use crate::protocols::ip::shared::protocol_numbers::IPPROTO_IPV6;
use crate::registry::ProtocolRegistry;

use super::header::{AH_FIXED_LEN, AH_LENGTH_UNIT, AH_PAYLOAD_LEN_OFFSET};
use super::Ah;

/// IP protocol number for IPv4-in-IP encapsulation (tunnel-mode inner IPv4).
///
/// IANA assigns protocol number 4 to "IPv4 encapsulation". The shared
/// `protocol_numbers` table has no constant for it, so the AH decode carries a
/// local one to recognize a tunnel-mode inner IPv4 datagram via the AH Next
/// Header (RFC 4302 §3.1.2). The inner IPv6 case uses the shared
/// [`IPPROTO_IPV6`] (41).
const IPPROTO_IPV4: u8 = 4;

/// Decode an AH header (no SA) into a typed [`Ah`], its inner offset, and the
/// Next Header octet (RFC 4302 §2).
///
/// The fixed header is Next Header (1), Payload Len (1), Reserved (2), SPI (4),
/// and Sequence Number (4) = 12 octets, followed by the variable-length ICV.
/// The ICV length comes from the Payload Len field: the AH header is
/// `(payload_len + 2) * 4` octets total (RFC 4302 §2.2), so the ICV occupies
/// that minus the fixed 12. Every field — including the captured ICV bytes — is
/// reconstructed as a caller-set [`crate::field::Field::user`] value (via the
/// `Ah` builder setters), so a re-compile reproduces the header byte-for-byte
/// without consulting an SA.
///
/// Returns the [`Ah`] layer, the offset at which the inner protocol begins
/// (`AH_FIXED_LEN + icv_len`), and the Next Header octet that dispatches it.
///
/// A buffer shorter than the 12-octet fixed header, or shorter than the ICV the
/// Payload Len advertises, yields a structured
/// [`CrafterError::buffer_too_short`] carrying `context`, `required`, and
/// `available` — never a panic.
pub(crate) fn decode_ah_parts(bytes: &[u8]) -> Result<(Ah, usize, u8)> {
    if bytes.len() < AH_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ah header",
            AH_FIXED_LEN,
            bytes.len(),
        ));
    }

    let next_header = bytes[0];
    let payload_len = bytes[1];
    let reserved = read_u16_be(&bytes[2..4])?;
    let spi = read_u32_be(&bytes[4..8])?;
    let sequence = read_u32_be(&bytes[8..12])?;

    // RFC 4302 §2.2: Payload Len is the whole AH header in 32-bit words minus 2,
    // so the on-wire header is `(payload_len + 2) * 4` octets and the ICV is that
    // minus the fixed 12-octet portion. usize math avoids any u8 overflow.
    let total_len =
        (usize::from(payload_len) + usize::from(AH_PAYLOAD_LEN_OFFSET)) * AH_LENGTH_UNIT;
    // A Payload Len so small the header cannot even cover its fixed 12 octets
    // means there is no room for an ICV; clamp the ICV length to zero rather than
    // underflowing. The buffer-length check below still guards the inner offset.
    let icv_len = total_len.saturating_sub(AH_FIXED_LEN);
    let inner_offset = AH_FIXED_LEN + icv_len;

    if bytes.len() < inner_offset {
        return Err(CrafterError::buffer_too_short(
            "ah icv",
            inner_offset,
            bytes.len(),
        ));
    }

    let icv = &bytes[AH_FIXED_LEN..inner_offset];

    // Reconstruct the AH layer with every field marked caller-set so a re-compile
    // reproduces the decoded header exactly. The builder setters call `set_user`;
    // `.icv(..)` pins the captured ICV bytes verbatim (no SA recomputes them).
    let ah = Ah::new()
        .next_header(next_header)
        .payload_len(payload_len)
        .reserved(reserved)
        .spi(spi)
        .sequence(sequence)
        .icv(icv.to_vec());

    Ok((ah, inner_offset, next_header))
}

/// Dispatch the cleartext data following an AH header to nested typed layers
/// (RFC 4302 §2.1, §3.1).
///
/// The AH Next Header tells the receiver what the protected data is, exactly as
/// the enclosing IP header's Protocol / Next Header field would. AH never
/// encrypts, so this data is always in the clear:
///
/// - **Tunnel mode** (`next_header` 4 = IPv4-in-IP or 41 = IPv6): the data is an
///   entire inner IP datagram (RFC 4302 §3.1.2). It is decoded through the
///   registry's L3 path ([`ProtocolRegistry::decode_ipv4`] /
///   [`ProtocolRegistry::decode_ipv6`]) and the recovered layers (inner IP plus
///   its own nested layers) are appended in order.
/// - **Transport mode** (any other `next_header`): the data is the protected
///   upper-layer payload, dispatched by protocol number through the registry's
///   IPv4-protocol routing ([`ProtocolRegistry::decode_ipv4_protocol`]). A bound
///   protocol (TCP, UDP, ICMP, …) decodes to its typed layer; an unknown
///   protocol number falls back to a preserved `Raw` payload, matching the
///   crate's unknown-next-protocol contract.
///
/// The IPv4-protocol routing is shared across IP versions (the protocol-number
/// space is identical for IPv4 Protocol and IPv6 Next Header), so it is the
/// correct transport-mode dispatcher regardless of the enclosing IP version.
fn dispatch_ah_inner(
    registry: &ProtocolRegistry,
    packet: Packet,
    next_header: u8,
    inner: &[u8],
) -> Result<Packet> {
    match next_header {
        // Tunnel mode: the data is a full inner IP datagram. Decode it with the
        // registry's L3 path and append the recovered layers in order.
        IPPROTO_IPV4 => {
            let decoded = registry.decode_ipv4(inner)?;
            Ok(packet.concat(decoded))
        }
        IPPROTO_IPV6 => {
            let decoded = registry.decode_ipv6(inner)?;
            Ok(packet.concat(decoded))
        }
        // Transport mode: dispatch the upper-layer data by protocol number,
        // falling back to `Raw` for an unknown protocol.
        protocol => registry.decode_ipv4_protocol(packet, protocol, inner),
    }
}

/// Append a decoded AH datagram using an explicit registry (RFC 4302).
///
/// Decodes the fixed header and ICV ([`decode_ah_parts`]), pushes the typed
/// [`Ah`] layer, then dispatches the cleartext data following the AH header
/// ([`dispatch_ah_inner`]): transport mode by protocol number, tunnel mode as an
/// inner IP datagram, with an unknown protocol preserved as `Raw`. Because AH
/// only authenticates, no SA is needed to recover the inner protocol — the data
/// is always in the clear (RFC 4302 §1).
///
/// The built-in IPv4-protocol-51 / IPv6-next-header AH bindings (a later step)
/// call this hook. Mirrors UDP's `append_udp_packet_with_registry` shape: decode
/// parts, push the layer, dispatch inner. A truncated buffer surfaces the
/// structured error from `decode_ah_parts`.
#[allow(dead_code)]
pub(crate) fn append_ah_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let (ah, inner_offset, next_header) = decode_ah_parts(bytes)?;
    let packet = packet.push(ah);
    dispatch_ah_inner(registry, packet, next_header, &bytes[inner_offset..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::sa::{IntegrityAlgorithm, SecurityAssociation};
    use crate::protocols::ipv4::{Ipv4, IPPROTO_AH, IPPROTO_TCP};
    use crate::protocols::Tcp;

    /// Compile `Ipv4 / Ah::secured(sa) / Tcp / Raw`, returning the AH datagram
    /// bytes that follow the outer IPv4 header.
    ///
    /// AH authenticates but does not consume the following layers, so the bytes
    /// after the outer IPv4 header are `AH header || ICV || cleartext Tcp / Raw`.
    /// The decode must recover the AH header, the ICV, and the inner Tcp.
    fn compile_ah_packet() -> Vec<u8> {
        // HMAC-SHA-256-128 (RFC 4868), 16-octet ICV; a fixed documentation key.
        let sa = SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x77u8; 32]);
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_AH)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap())
            .ttl(64);
        let ah = Ah::secured(sa).spi(0x0000_2000).sequence(1);
        let tcp = Tcp::new().sport(1234).dport(443);
        let raw = Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let packet: Packet = Packet::from_layer(ipv4) / ah / tcp / raw;
        let compiled = packet.compile().expect("compile AH packet").into_bytes();

        // Strip the outer IPv4 header using its IHL nibble (×4 octets).
        let ip_header_len = usize::from(compiled[0] & 0x0f) * 4;
        assert_eq!(compiled[9], IPPROTO_AH, "enclosing IPv4 advertises AH (51)");
        compiled[ip_header_len..].to_vec()
    }

    /// Compile a bare `Ah` layer in isolation, reading its preceding IPv4 header
    /// from the packet so the ICV input is the real one, and return the AH bytes.
    fn compile_ah_layer(packet: &Packet, index: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let ctx = LayerContext::new(packet, index);
        packet.get(index).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    #[test]
    fn decode_without_sa_exposes_all_fields_and_inner_tcp() {
        let ah_bytes = compile_ah_packet();

        let (ah, inner_offset, next_header) = decode_ah_parts(&ah_bytes).expect("decode AH parts");

        // Fixed header fields are recovered exactly (RFC 4302 §2).
        assert_eq!(
            next_header, IPPROTO_TCP,
            "Next Header is the inner protocol"
        );
        assert_eq!(ah.next_header_value(), Some(IPPROTO_TCP));
        // HMAC-SHA-256-128 ICV is 16 octets: Payload Len = (12 + 16)/4 − 2 = 5.
        assert_eq!(ah.payload_len_value(), Some(5));
        assert_eq!(ah.reserved_value(), Some(0));
        assert_eq!(ah.spi_value(), Some(0x0000_2000));
        assert_eq!(ah.sequence_value(), Some(1));

        // The ICV is captured verbatim: 16 octets immediately after the fixed
        // header, and the inner protocol begins right after it.
        let icv_len = 16usize;
        assert_eq!(
            ah.icv_value(),
            Some(&ah_bytes[AH_FIXED_LEN..AH_FIXED_LEN + icv_len])
        );
        assert_eq!(inner_offset, AH_FIXED_LEN + icv_len);

        // The inner data after AH is the cleartext Tcp header (4-octet ports
        // 1234/443) plus the Raw payload — AH does not encrypt, so it decodes
        // without keys. Dispatching it through the registry recovers a typed Tcp.
        assert_eq!(
            &ah_bytes[inner_offset..inner_offset + 4],
            &[0x04, 0xD2, 0x01, 0xBB]
        );
        assert_eq!(&ah_bytes[ah_bytes.len() - 4..], &[0xDE, 0xAD, 0xBE, 0xEF]);

        let registry = ProtocolRegistry::with_builtin_bindings();
        let decoded = dispatch_ah_inner(
            &registry,
            Packet::new(),
            next_header,
            &ah_bytes[inner_offset..],
        )
        .expect("dispatch AH inner");
        let tcp = decoded.layer::<Tcp>().expect("inner Tcp decoded");
        assert_eq!(tcp.source_port_value(), 1234);
        assert_eq!(tcp.destination_port_value(), 443);
    }

    #[test]
    fn decoded_ah_recompiles_byte_exact() {
        let ah_bytes = compile_ah_packet();
        let (ah, inner_offset, _) = decode_ah_parts(&ah_bytes).expect("decode AH parts");

        // The decoded AH layer reproduces the AH header and ICV byte-for-byte:
        // every field is caller-set and the ICV is pinned, so no SA recomputes
        // anything. `compile()` still reads the preceding IP header to validate
        // the version, so place the decoded AH after an IPv4 header (the ICV
        // override means the IP bytes never feed back into the emitted ICV).
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_AH)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap())
            .ttl(64);
        let packet: Packet = Packet::from_layer(ipv4) / ah;
        let recompiled = compile_ah_layer(&packet, 1);
        assert_eq!(recompiled, ah_bytes[..inner_offset]);
    }

    #[test]
    fn append_with_registry_pushes_ah_and_inner_tcp() {
        let ah_bytes = compile_ah_packet();
        let registry = ProtocolRegistry::with_builtin_bindings();
        let packet = append_ah_packet_with_registry(&registry, Packet::new(), &ah_bytes)
            .expect("append AH with registry");

        // AH header layer, then the nested typed Tcp layer (transport mode), then
        // the trailing Raw payload — all in the clear (AH does not encrypt).
        let ah = packet
            .get(0)
            .unwrap()
            .as_any()
            .downcast_ref::<Ah>()
            .expect("first layer is Ah");
        assert_eq!(ah.spi_value(), Some(0x0000_2000));
        assert_eq!(ah.next_header_value(), Some(IPPROTO_TCP));

        let tcp = packet.layer::<Tcp>().expect("inner Tcp decoded");
        assert_eq!(tcp.source_port_value(), 1234);
        assert_eq!(tcp.destination_port_value(), 443);
        assert_eq!(
            packet.layer::<Raw>().expect("inner Raw decoded").as_bytes(),
            &[0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn truncated_before_fixed_header_is_structured_error() {
        // A buffer shorter than the 12-octet fixed AH header is a structured
        // buffer error, never a panic.
        let truncated = vec![0x06, 0x05, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00];
        let err = decode_ah_parts(&truncated).expect_err("must reject short fixed header");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ah header");
                assert_eq!(required, AH_FIXED_LEN);
                assert_eq!(available, truncated.len());
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    #[test]
    fn one_byte_short_of_icv_is_structured_error() {
        // Take a real AH datagram and truncate it one octet short of the full ICV
        // the Payload Len advertises. The inner offset (12 + 16 = 28) exceeds the
        // available length (27), so decode must surface buffer_too_short, not a
        // panic and not a half-read ICV.
        let ah_bytes = compile_ah_packet();
        let inner_offset = AH_FIXED_LEN + 16; // HMAC-SHA-256-128 ICV is 16 octets
        let truncated = ah_bytes[..inner_offset - 1].to_vec();

        let err = decode_ah_parts(&truncated).expect_err("must reject short ICV");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "ah icv");
                assert_eq!(required, inner_offset);
                assert_eq!(available, truncated.len());
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }
}
