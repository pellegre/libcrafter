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

use subtle::ConstantTimeEq;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::packet::{LayerContext, Packet};
use crate::protocols::ip::shared::protocol_numbers::IPPROTO_IPV6;
use crate::protocols::ipsec::sa::SecurityAssociation;
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
/// The built-in IPv4-protocol-51 / IPv6-next-header AH bindings call this hook.
/// Mirrors UDP's `append_udp_packet_with_registry` shape: decode parts, push the
/// layer, dispatch inner. A truncated buffer surfaces the structured error from
/// `decode_ah_parts`.
pub(crate) fn append_ah_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    let (ah, inner_offset, next_header) = decode_ah_parts(bytes)?;
    let packet = packet.push(ah);
    dispatch_ah_inner(registry, packet, next_header, &bytes[inner_offset..])
}

/// Verify a decoded AH layer's ICV against a supplied SA (RFC 4302 §3.4.4).
///
/// `packet` is the layer stack the receiver assembled — the preceding IP header,
/// the [`Ah`] layer at `ah_index`, and the cleartext upper-layer data following
/// it — and `sa` is the integrity context to verify against. Verification
/// recomputes the ICV input *exactly* as the sender's [`Ah::compile_ah`] does
/// (RFC 4302 §3.4.4 says the receiver computes the ICV "in the same way as the
/// sender"):
///
/// 1. canonicalize the immutable fields of the preceding IP header,
/// 2. assemble the AH header with the ICV field zeroed at its padded length,
/// 3. append the cleartext upper-layer data, and
/// 4. append the high-order ESN word when the SA enables it.
///
/// The assembly is the shared [`Ah::ah_icv_input`] helper, so the receiver's
/// input is byte-identical to the sealed one. The recomputed ICV is then compared
/// against the decoded ICV (the [`Ah`] layer's captured `icv` bytes) using the SA
/// integrity transform's constant-time [`verify`]. The comparison runs over the
/// *transmitted* (unpadded) ICV length, the high-order octets a §2.6 boundary pad
/// would leave zero notwithstanding.
///
/// Fails closed: a mismatch — from a tampered immutable IP field, a tampered
/// upper-layer byte, or a tampered ICV — returns a structured
/// [`CrafterError::invalid_field_value`] on `ipsec.ah.icv` rather than a panic or
/// a silently accepted forgery. A missing SA integrity transform, an absent ICV,
/// or a missing enclosing IP header also surface as structured errors.
///
/// [`verify`]: crate::protocols::ipsec::crypto::IntegrityTransform::verify
pub(crate) fn verify_ah(packet: &Packet, ah_index: usize, sa: &SecurityAssociation) -> Result<()> {
    let ctx = LayerContext::new(packet, ah_index);

    let ah = packet
        .get(ah_index)
        .and_then(|layer| layer.as_any().downcast_ref::<Ah>())
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ipsec.ah.verify",
                "layer at the given index is not an AH header",
            )
        })?;

    // The transmitted ICV is the AH layer's captured ICV bytes (decoded verbatim
    // by `decode_ah_parts`). Without one there is nothing to verify.
    let transmitted_icv = ah.icv_value().ok_or_else(|| {
        CrafterError::invalid_field_value("ipsec.ah.icv", "AH layer carries no ICV to verify")
    })?;

    // Resolve the IP version and the AH field values exactly as `compile()` does,
    // then assemble the ICV input through the shared helper so the recomputed
    // input is byte-identical to the sealed one (RFC 4302 §3.4.4).
    let ip_version = Ah::preceding_ip_version(&ctx)?;
    let padded_icv_len = ah.effective_icv_len(ip_version);
    let fields = ah.resolved_icv_fields(&ctx, ip_version);
    let input = ah.ah_icv_input(&ctx, sa, ip_version, &fields, padded_icv_len)?;

    // Recompute the ICV over the assembled input, zero-padded to the boundary the
    // AH header reserves (RFC 4302 §2.6) so it lines up with the transmitted ICV's
    // length, then compare in constant time. The SA integrity transform's own
    // `verify` already runs the comparison in constant time when the lengths match
    // (the common HMAC-SHA2 case, where no boundary padding is added); the
    // padded-length fallback below re-pads the recomputed ICV and compares it the
    // same way for the rare boundary-padded transforms. RFC 4302 §3.4.4: either
    // way, a mismatch fails closed.
    let transform = sa.integ.integrity_transform()?;
    let matched = if transform.icv_len() == transmitted_icv.len() {
        transform.verify(&sa.integ_key, &input, transmitted_icv)?
    } else {
        let mut expected = transform.compute(&sa.integ_key, &input)?;
        if expected.len() < transmitted_icv.len() {
            expected.resize(transmitted_icv.len(), 0);
        }
        expected.as_slice().ct_eq(transmitted_icv).into()
    };

    if !matched {
        return Err(CrafterError::invalid_field_value(
            "ipsec.ah.icv",
            "AH ICV verification failed: recomputed integrity check value does not match",
        ));
    }
    Ok(())
}

/// Append a decoded AH datagram using an explicit registry and an optional SA
/// (RFC 4302).
///
/// This is the SA-aware decode entry: when an SA is supplied, it recovers the AH
/// layer and inner data ([`append_ah_packet_with_registry`]), then re-verifies
/// the ICV ([`verify_ah`]) over the assembled stack and stamps the verified
/// status onto the recovered [`Ah`] layer ([`Ah::verification_status`]).
///
/// - **`Some(sa)`** — verify the ICV; on success record `Some(true)` on the AH
///   layer; on failure return the structured `ipsec.ah.icv` mismatch error from
///   [`verify_ah`] (the decode fails closed). AH never encrypts, so the inner
///   layers are recovered identically to the no-SA path; the SA only adds the
///   verification.
/// - **`None`** — the opaque path: recover the AH header and dispatch the
///   cleartext inner protocol without verifying, leaving the verification status
///   `None` ([`append_ah_packet_with_registry`]).
pub(crate) fn append_ah_packet_with_registry_sa(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
    sa: Option<&SecurityAssociation>,
) -> Result<Packet> {
    let Some(sa) = sa else {
        // No SA for this SPI: fall back to the opaque (no-verify) decode path.
        return append_ah_packet_with_registry(registry, packet, bytes);
    };

    // Recover the AH layer and dispatch the cleartext inner protocol; AH does not
    // encrypt, so the inner layers are the same as the no-SA path.
    let ah_index = packet.len();
    let mut decoded = append_ah_packet_with_registry(registry, packet, bytes)?;

    // Verify the ICV over the assembled stack (preceding IP + AH + upper layers).
    // A mismatch returns the structured `ipsec.ah.icv` error — fail closed.
    verify_ah(&decoded, ah_index, sa)?;

    // Stamp the verified status onto the recovered AH layer.
    if let Some(ah) = decoded
        .get_mut(ah_index)
        .and_then(|layer| layer.as_any_mut().downcast_mut::<Ah>())
    {
        ah.set_verification_status(true);
    }
    Ok(decoded)
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

    // --- SA-driven ICV verification (RFC 4302 §3.4.4) ----------------------

    /// The shared HMAC-SHA-256-128 (RFC 4868) SA used by the verify tests, with a
    /// fixed documentation key. SPI matches the AH header the sender emits.
    fn verify_sa() -> SecurityAssociation {
        SecurityAssociation::new(0x0000_2000)
            .integrity(IntegrityAlgorithm::HmacSha2_256_128, vec![0x77u8; 32])
    }

    /// A representative documentation IPv4 header that enclosed the AH datagram.
    fn verify_ipv4() -> Ipv4 {
        Ipv4::new()
            .protocol(IPPROTO_AH)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap())
            .ttl(64)
    }

    /// Build the decoded layer stack a receiver would assemble from an
    /// `Ipv4 / Ah::secured(sa) / Tcp / Raw` datagram: the enclosing IPv4 header,
    /// the AH layer with its on-wire ICV captured verbatim (no SA attached, fields
    /// caller-set per `decode_ah_parts`), and the cleartext inner Tcp / Raw. This
    /// mirrors what the SA-aware registry decode produces, but without depending on
    /// the (later-step) AH registry binding.
    fn decoded_verify_packet() -> Packet {
        let ah_bytes = compile_ah_packet();
        let (decoded_ah, _, _) = decode_ah_parts(&ah_bytes).expect("decode AH parts");
        Packet::from_layer(verify_ipv4())
            / decoded_ah
            / Tcp::new().sport(1234).dport(443)
            / Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])
    }

    #[test]
    fn verify_ah_with_matching_sa_passes() {
        // The receiver recomputes the ICV over the canonicalized IPv4 header, the
        // AH header with the ICV field zeroed, and the cleartext Tcp / Raw, and it
        // matches the on-wire ICV the sender emitted (RFC 4302 §3.4.4).
        let packet = decoded_verify_packet();
        verify_ah(&packet, 1, &verify_sa()).expect("ICV verifies with the matching SA");
    }

    #[test]
    fn verify_ah_detects_tampered_payload_byte() {
        // Flipping one upper-layer payload byte changes the ICV input, so the
        // recomputed ICV no longer matches the captured one: verification fails
        // closed with a structured `ipsec.ah.icv` error, never a panic.
        let ah_bytes = compile_ah_packet();
        let (decoded_ah, _, _) = decode_ah_parts(&ah_bytes).expect("decode AH parts");
        let tampered: Packet = Packet::from_layer(verify_ipv4())
            / decoded_ah
            / Tcp::new().sport(1234).dport(443)
            // One payload byte flipped (0xDE -> 0xDF) versus the sealed datagram.
            / Raw::from_bytes(vec![0xDF, 0xAD, 0xBE, 0xEF]);

        let err = verify_ah(&tampered, 1, &verify_sa())
            .expect_err("a flipped payload byte must fail verification");
        match err {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "ipsec.ah.icv", "tamper fails on the ICV field");
            }
            other => panic!("expected an ICV mismatch error, got {other:?}"),
        }
    }

    #[test]
    fn verify_ah_detects_tampered_immutable_ipv4_field() {
        // Change an immutable IPv4 field that AH canonicalization does NOT zero —
        // a source-address byte (192.0.2.1 -> 192.0.2.9). It survives into the
        // canonical IP header, so the recomputed ICV differs from the captured one
        // and verification fails closed (RFC 4302 §3.3.3.1.1 covers the source
        // address as immutable).
        let ah_bytes = compile_ah_packet();
        let (decoded_ah, _, _) = decode_ah_parts(&ah_bytes).expect("decode AH parts");
        let tampered_ip = Ipv4::new()
            .protocol(IPPROTO_AH)
            .src("192.0.2.9".parse().unwrap()) // immutable source address altered
            .dst("192.0.2.2".parse().unwrap())
            .ttl(64);
        let tampered: Packet = Packet::from_layer(tampered_ip)
            / decoded_ah
            / Tcp::new().sport(1234).dport(443)
            / Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let err = verify_ah(&tampered, 1, &verify_sa())
            .expect_err("a flipped immutable IPv4 field must fail verification");
        assert!(
            matches!(err, CrafterError::InvalidFieldValue { field, .. } if field == "ipsec.ah.icv"),
            "expected an ICV mismatch error, got {err:?}"
        );
    }

    #[test]
    fn verify_ah_ignores_mutable_ipv4_field_changes() {
        // A change to a *mutable* IPv4 field (TTL) is zeroed by canonicalization,
        // so it does NOT affect the ICV: verification still passes. This guards the
        // canonicalization being applied on the receiver side (RFC 4302
        // §3.3.3.1.1: TTL is mutable and zeroed before the ICV).
        let ah_bytes = compile_ah_packet();
        let (decoded_ah, _, _) = decode_ah_parts(&ah_bytes).expect("decode AH parts");
        let retimed_ip = Ipv4::new()
            .protocol(IPPROTO_AH)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap())
            .ttl(7); // different TTL than the sender (64); mutable, so zeroed
        let packet: Packet = Packet::from_layer(retimed_ip)
            / decoded_ah
            / Tcp::new().sport(1234).dport(443)
            / Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        verify_ah(&packet, 1, &verify_sa())
            .expect("a mutable-field (TTL) change is canonicalized away and still verifies");
    }

    #[test]
    fn decode_with_sa_records_verified_status() {
        // The SA-aware decode entry recovers the AH layer, verifies the ICV, and
        // stamps a verified status on the recovered `Ah` layer. The inner Tcp is
        // recovered in the clear (AH does not encrypt).
        let ah_bytes = compile_ah_packet();
        let registry = ProtocolRegistry::with_builtin_bindings();
        let sa = verify_sa();
        // Seed the in-progress packet with the enclosing IPv4 header so `verify_ah`
        // can read the preceding IP header through the layer context.
        let seeded = Packet::from_layer(verify_ipv4());
        let decoded = append_ah_packet_with_registry_sa(&registry, seeded, &ah_bytes, Some(&sa))
            .expect("SA-aware decode + verify succeeds");

        let ah = decoded
            .get(1)
            .and_then(|layer| layer.as_any().downcast_ref::<Ah>())
            .expect("AH layer at index 1");
        assert_eq!(
            ah.verification_status(),
            Some(true),
            "verified status recorded on the AH layer"
        );

        let tcp = decoded
            .layer::<Tcp>()
            .expect("inner Tcp decoded in the clear");
        assert_eq!(tcp.source_port_value(), 1234);
        assert_eq!(tcp.destination_port_value(), 443);
    }

    #[test]
    fn decode_with_sa_fails_closed_on_tampered_icv() {
        // Flip one octet of the on-wire ICV before the SA-aware decode. The
        // recovered AH layer captures the tampered ICV, so verification fails
        // closed with the structured `ipsec.ah.icv` error — no layer, no panic, no
        // silently accepted forgery.
        let mut ah_bytes = compile_ah_packet();
        // The ICV starts right after the 12-octet fixed header; flip its first bit.
        ah_bytes[AH_FIXED_LEN] ^= 0x01;

        let registry = ProtocolRegistry::with_builtin_bindings();
        let sa = verify_sa();
        let seeded = Packet::from_layer(verify_ipv4());
        let err = append_ah_packet_with_registry_sa(&registry, seeded, &ah_bytes, Some(&sa))
            .expect_err("a tampered ICV must fail the SA-aware decode");
        assert!(
            matches!(err, CrafterError::InvalidFieldValue { field, .. } if field == "ipsec.ah.icv"),
            "expected an ICV mismatch error, got {err:?}"
        );
    }

    #[test]
    fn decode_without_sa_leaves_verification_status_unset() {
        // The opaque (no-SA) path recovers the AH header and inner protocol but
        // never verifies, so the verification status stays `None`.
        let ah_bytes = compile_ah_packet();
        let registry = ProtocolRegistry::with_builtin_bindings();
        let seeded = Packet::from_layer(verify_ipv4());
        let decoded = append_ah_packet_with_registry_sa(&registry, seeded, &ah_bytes, None)
            .expect("opaque decode without an SA succeeds");

        let ah = decoded
            .get(1)
            .and_then(|layer| layer.as_any().downcast_ref::<Ah>())
            .expect("AH layer at index 1");
        assert_eq!(
            ah.verification_status(),
            None,
            "no verification attempted without an SA"
        );
    }
}
