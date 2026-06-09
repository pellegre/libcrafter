//! AH ICV input — IPv4 immutable-field canonicalization (RFC 4302 §3.3.3.1.1).
//!
//! AH integrity covers the IP header, but several IP header fields change in
//! transit ("mutable"). Before the Integrity Check Value is computed, both the
//! sender and the receiver canonicalize the IP header by zeroing those mutable
//! fields so the two ends compute the MAC over identical bytes (RFC 4302
//! §3.3.3, §3.3.3.1).
//!
//! For the IPv4 base header (RFC 4302 §3.3.3.1.1.1) the mutable fields zeroed
//! before ICV calculation are:
//!
//! - the DSCP + ECN octet (the TOS/Differentiated-Services byte) — byte 1;
//! - Flags + Fragment Offset — bytes 6–7;
//! - Time to Live (TTL) — byte 8;
//! - Header Checksum — bytes 10–11.
//!
//! Every other base-header field (Version, IHL, Total Length, Identification,
//! Protocol, Source Address, Destination Address) is immutable and is covered
//! as-is. In particular the Protocol byte is left untouched: for AH it is the
//! AH protocol number (51), and Total Length is left as compiled.
//!
//! IPv4 options are handled per RFC 4302 §3.3.3.1.1.2: each option is classified
//! by its option type as immutable (covered as-is) or mutable (the entire
//! option — type, length, and value — is zeroed). This module takes the
//! conservative handling the step permits: when options are present it zeroes
//! the entire option region of the canonical header. Zeroing a superset of the
//! mutable options is safe because the sender and receiver run the *same*
//! canonicalization, so both compute the ICV over identical bytes and the value
//! still verifies; it only declines to authenticate immutable option bytes
//! rather than authenticating mutable ones. A future step can refine this to
//! the per-option-type table without changing the public shape.

use crate::error::{CrafterError, Result};
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipv4::Ipv4;

/// Length in octets of the fixed IPv4 base header (RFC 791 §3.1). Option bytes,
/// when present, follow this prefix.
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Offset of the DSCP + ECN (TOS / Differentiated Services) octet.
const IPV4_TOS_OFFSET: usize = 1;
/// First offset of the Flags + Fragment Offset 16-bit field.
const IPV4_FLAGS_FRAGMENT_OFFSET: usize = 6;
/// Offset of the Time to Live octet.
const IPV4_TTL_OFFSET: usize = 8;
/// First offset of the Header Checksum 16-bit field.
const IPV4_CHECKSUM_OFFSET: usize = 10;

/// Canonicalize a compiled IPv4 header for AH ICV computation (RFC 4302
/// §3.3.3.1.1).
///
/// Takes the bytes of a compiled IPv4 header (fixed 20-byte base header
/// optionally followed by option bytes) and returns a copy with the mutable
/// fields zeroed: the DSCP+ECN octet (byte 1), Flags+Fragment Offset (bytes
/// 6–7), TTL (byte 8), and Header Checksum (bytes 10–11). The Protocol byte
/// (which for AH is 51) and the Total Length field are left as-is. When option
/// bytes follow the base header they are zeroed wholesale per the conservative
/// §3.3.3.1.1.2 handling documented on this module.
///
/// Returns a structured error when the input is shorter than the 20-byte IPv4
/// base header, so a truncated buffer surfaces as a typed error rather than a
/// panic.
#[allow(dead_code)]
pub(crate) fn canonical_ipv4_for_ah(ipv4_header_bytes: &[u8]) -> Result<Vec<u8>> {
    if ipv4_header_bytes.len() < IPV4_MIN_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ah.icv.canonical_ipv4",
            IPV4_MIN_HEADER_LEN,
            ipv4_header_bytes.len(),
        ));
    }

    let mut canonical = ipv4_header_bytes.to_vec();

    // RFC 4302 §3.3.3.1.1.1: zero the mutable base-header fields. Protocol
    // (byte 9), Total Length (bytes 2–3), and the addresses stay as-is.
    canonical[IPV4_TOS_OFFSET] = 0;
    canonical[IPV4_FLAGS_FRAGMENT_OFFSET] = 0;
    canonical[IPV4_FLAGS_FRAGMENT_OFFSET + 1] = 0;
    canonical[IPV4_TTL_OFFSET] = 0;
    canonical[IPV4_CHECKSUM_OFFSET] = 0;
    canonical[IPV4_CHECKSUM_OFFSET + 1] = 0;

    // RFC 4302 §3.3.3.1.1.2 (conservative handling): zero any option bytes that
    // follow the 20-byte base header. See the module docs for why a superset is
    // safe for self-consistent seal/verify.
    if canonical.len() > IPV4_MIN_HEADER_LEN {
        for byte in &mut canonical[IPV4_MIN_HEADER_LEN..] {
            *byte = 0;
        }
    }

    Ok(canonical)
}

/// Extract the compiled bytes of the IPv4 header immediately preceding the AH
/// layer in the packet stack.
///
/// The AH layer reads its enclosing IP header through `ctx.previous()`. This
/// helper downcasts that previous layer to [`Ipv4`] and compiles it into bytes
/// using a context positioned at the previous layer's index, so auto-filled
/// fields (IHL, Total Length, Protocol, Checksum) reflect the real header. It
/// returns a structured error when there is no preceding layer or it is not an
/// IPv4 header, so an AH built without an enclosing IPv4 surfaces a typed error.
#[allow(dead_code)]
pub(crate) fn preceding_ipv4_header_bytes(ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
    let previous = ctx.previous().ok_or_else(|| {
        CrafterError::invalid_field_value(
            "ah.icv.previous",
            "AH requires a preceding IP header to authenticate",
        )
    })?;

    let ipv4 = previous.as_any().downcast_ref::<Ipv4>().ok_or_else(|| {
        CrafterError::invalid_field_value(
            "ah.icv.previous",
            "preceding layer is not an IPv4 header",
        )
    })?;

    let previous_index = ctx.index().checked_sub(1).ok_or_else(|| {
        CrafterError::invalid_field_value(
            "ah.icv.previous",
            "AH requires a preceding IP header to authenticate",
        )
    })?;
    let previous_ctx = LayerContext::new(ctx.packet(), previous_index);

    let mut header = Vec::new();
    ipv4.compile(&previous_ctx, &mut header)?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Packet, Raw};
    use crate::protocols::ipv4::Ipv4;
    use core::net::Ipv4Addr;

    /// A representative compiled IPv4 base header (no options) with every
    /// mutable field set to a recognizable non-zero value, so the
    /// canonicalization is observable byte-for-byte.
    fn sample_ipv4_header() -> Vec<u8> {
        vec![
            0x45, // Version 4, IHL 5
            0xB8, // TOS / DSCP+ECN (mutable)
            0x00, 0x54, // Total Length 84 (immutable)
            0x12, 0x34, // Identification (immutable)
            0x40, 0x00, // Flags + Fragment Offset (mutable)
            0x33, // TTL 51 (mutable)
            0x33, // Protocol = AH (51) (immutable)
            0xAB, 0xCD, // Header Checksum (mutable)
            192, 0, 2, 1, // Source 192.0.2.1 (immutable)
            192, 0, 2, 2, // Destination 192.0.2.2 (immutable)
        ]
    }

    #[test]
    fn canonicalizes_exactly_the_mutable_fields() {
        let header = sample_ipv4_header();
        let canonical = canonical_ipv4_for_ah(&header).expect("20-byte header canonicalizes");

        // The mutable fields are zeroed.
        assert_eq!(canonical[IPV4_TOS_OFFSET], 0, "TOS/DSCP+ECN zeroed");
        assert_eq!(canonical[IPV4_FLAGS_FRAGMENT_OFFSET], 0, "Flags zeroed");
        assert_eq!(
            canonical[IPV4_FLAGS_FRAGMENT_OFFSET + 1],
            0,
            "Fragment Offset zeroed"
        );
        assert_eq!(canonical[IPV4_TTL_OFFSET], 0, "TTL zeroed");
        assert_eq!(canonical[IPV4_CHECKSUM_OFFSET], 0, "Checksum high zeroed");
        assert_eq!(
            canonical[IPV4_CHECKSUM_OFFSET + 1],
            0,
            "Checksum low zeroed"
        );

        // Every immutable byte is preserved exactly.
        let expected: Vec<u8> = vec![
            0x45, // Version + IHL
            0x00, // TOS zeroed
            0x00, 0x54, // Total Length preserved
            0x12, 0x34, // Identification preserved
            0x00, 0x00, // Flags + Fragment Offset zeroed
            0x00, // TTL zeroed
            0x33, // Protocol = AH preserved
            0x00, 0x00, // Checksum zeroed
            192, 0, 2, 1, // Source preserved
            192, 0, 2, 2, // Destination preserved
        ];
        assert_eq!(canonical, expected);
        // Same length as input — only field values change.
        assert_eq!(canonical.len(), header.len());
    }

    #[test]
    fn protocol_and_total_length_are_preserved() {
        let header = sample_ipv4_header();
        let canonical = canonical_ipv4_for_ah(&header).expect("canonicalizes");
        // Protocol byte (offset 9) is the AH number 51 and survives.
        assert_eq!(canonical[9], 0x33);
        // Total Length (offsets 2-3) survives.
        assert_eq!(&canonical[2..4], &[0x00, 0x54]);
    }

    #[test]
    fn options_are_zeroed_but_base_header_canonicalizes_normally() {
        let mut header = sample_ipv4_header();
        // Bump IHL to 6 words and append a 4-byte option (Router Alert-like).
        header[0] = 0x46;
        header.extend_from_slice(&[0x94, 0x04, 0x00, 0x00]);
        let canonical = canonical_ipv4_for_ah(&header).expect("canonicalizes with options");

        // The 4 option bytes after the 20-byte base header are zeroed.
        assert_eq!(&canonical[IPV4_MIN_HEADER_LEN..], &[0u8; 4]);
        // The base header is canonicalized as usual.
        assert_eq!(canonical[IPV4_TOS_OFFSET], 0);
        assert_eq!(canonical[IPV4_TTL_OFFSET], 0);
        // IHL byte (immutable) is preserved.
        assert_eq!(canonical[0], 0x46);
    }

    #[test]
    fn rejects_a_truncated_header() {
        let err = canonical_ipv4_for_ah(&[0x45, 0x00, 0x00])
            .expect_err("a 3-byte buffer is too short for an IPv4 header");
        // Surfaces as a structured error, never a panic.
        let _ = err;
    }

    #[test]
    fn preceding_ipv4_header_is_extracted_and_compiled() {
        // Build Ipv4 / <following layer> and read the compiled IPv4 header
        // through the following layer's context. `Ah` does not implement
        // `Layer` until a later step, so a `Raw` layer stands in for the AH
        // position — `preceding_ipv4_header_bytes` only inspects the *previous*
        // layer, which is the IPv4 header here.
        let ipv4 = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(192, 0, 2, 2))
            .ttl(51);
        let packet: Packet = ipv4 / Raw::from_bytes([0u8; 4]);

        // The following layer sits at index 1; its previous layer is the IPv4
        // header at index 0.
        let ctx = LayerContext::new(&packet, 1);
        let header = preceding_ipv4_header_bytes(&ctx).expect("preceding IPv4 header extracted");

        // A compiled IPv4 base header is at least 20 bytes, version nibble 4.
        assert!(header.len() >= IPV4_MIN_HEADER_LEN);
        assert_eq!(header[0] >> 4, 4);
        // Source/destination survive into the compiled bytes.
        assert_eq!(&header[12..16], &[192, 0, 2, 1]);
        assert_eq!(&header[16..20], &[192, 0, 2, 2]);

        // Canonicalizing it zeroes the TTL we set.
        let canonical = canonical_ipv4_for_ah(&header).expect("canonicalizes");
        assert_eq!(canonical[IPV4_TTL_OFFSET], 0);
    }

    #[test]
    fn preceding_layer_must_be_ipv4() {
        // A packet whose first (index 0) layer is the AH position has no
        // preceding IP header at all, so extraction reports a structured error.
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 4]));
        let ctx = LayerContext::new(&packet, 0);
        let err = preceding_ipv4_header_bytes(&ctx).expect_err("no preceding IP header");
        let _ = err;
    }

    #[test]
    fn preceding_non_ipv4_layer_is_rejected() {
        // When the preceding layer exists but is not IPv4, extraction reports a
        // structured error rather than misreading another layer as a header.
        let packet: Packet =
            Packet::from_layer(Raw::from_bytes([0xDEu8; 8])).push(Raw::from_bytes([0u8; 4]));
        let ctx = LayerContext::new(&packet, 1);
        let err = preceding_ipv4_header_bytes(&ctx).expect_err("preceding layer is not IPv4");
        let _ = err;
    }
}
