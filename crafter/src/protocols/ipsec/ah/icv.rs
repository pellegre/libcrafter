//! AH ICV input — IPv4 and IPv6 immutable-field canonicalization (RFC 4302
//! §3.3.3.1.1 and §3.3.3.1.2).
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
//!
//! For the IPv6 base header (RFC 4302 §3.3.3.1.2.1) the mutable fields zeroed
//! before ICV calculation are:
//!
//! - the DSCP (6 bits) + ECN (2 bits) of the Traffic Class, and the Flow Label —
//!   these are the lower 28 bits of the first 4-byte word (the high 4 bits are
//!   the Version nibble, which is immutable and preserved);
//! - the Hop Limit — byte 7.
//!
//! Every other base-header field (Version, Payload Length, Next Header, Source
//! Address, Destination Address) is immutable and is covered as-is.
//!
//! Preceding IPv6 extension headers (Hop-by-Hop Options, Routing, Destination
//! Options, etc.) are canonicalized per RFC 4302 §3.3.3.1.2.2. Each TLV option
//! carries its mutability in the third-highest bit of its option-type byte (the
//! "change en route" bit, mask `0x20`, RFC 8200 §4.2): when set, the option's
//! *data* is zeroed (its type and length bytes are preserved so the chain still
//! parses); when clear, the option is immutable and covered as-is. The step
//! describes this as the option type's "high bit"; the RFC-defined bit is the
//! `0x20` "change en route" bit, which this module uses. Routing headers are
//! handled conservatively in their *final-destination* form: a Routing Header is
//! authenticated as it appears at the final destination (RFC 4302 §3.3.3.1.2.2),
//! and because this module canonicalizes already-compiled bytes that are not
//! rearranged in transit, it covers the Routing Header as-is rather than
//! attempting the en-route reordering a router would perform. Sender and
//! receiver run the same canonicalization, so the ICV still verifies.

use crate::error::{CrafterError, Result};
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipv4::Ipv4;
use crate::protocols::ipv6::Ipv6;

/// Length in octets of the fixed IPv4 base header (RFC 791 §3.1). Option bytes,
/// when present, follow this prefix.
const IPV4_MIN_HEADER_LEN: usize = 20;

/// Length in octets of the fixed IPv6 base header (RFC 8200 §3). Extension
/// headers, when present, follow this prefix.
const IPV6_BASE_HEADER_LEN: usize = 40;
/// Minimum length of a length-bearing IPv6 extension header (RFC 8200 §4):
/// Next Header (1) + Hdr Ext Len (1) + 6 bytes, in 8-byte units.
const IPV6_EXT_MIN_LEN: usize = 8;
/// Offset of the Hop Limit octet in the IPv6 base header.
const IPV6_HOP_LIMIT_OFFSET: usize = 7;
/// Mask selecting the 28 mutable bits (Traffic Class + Flow Label) of the first
/// IPv6 header word; the high 4 bits are the immutable Version nibble.
const IPV6_VERSION_NIBBLE_MASK: u32 = 0xF000_0000;
/// IPv6 option-type "change en route" bit (RFC 8200 §4.2): when set the option's
/// data is mutable and is zeroed for the AH ICV (RFC 4302 §3.3.3.1.2.2).
const IPV6_OPTION_MUTABLE_MASK: u8 = 0x20;
/// IPv6 Pad1 option type (RFC 8200 §4.2): a single zero byte with no length or
/// data octets.
const IPV6_OPTION_PAD1: u8 = 0x00;

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

/// Canonicalize a compiled IPv6 header (and any preceding extension headers) for
/// AH ICV computation (RFC 4302 §3.3.3.1.2).
///
/// `ipv6_header_bytes` is the 40-byte IPv6 base header. `preceding_ext_headers`
/// is the concatenation of every extension header that sits between the base
/// header and the AH header (Hop-by-Hop Options, Routing, Destination Options,
/// Fragment, etc.); pass an empty slice when AH directly follows the base
/// header.
///
/// The returned buffer is `canonical base header || canonical extension
/// headers`. In the base header the mutable fields are zeroed — the Traffic
/// Class and Flow Label (the lower 28 bits of the first word; the Version nibble
/// is preserved) and the Hop Limit (byte 7). Payload Length, Next Header, and
/// the Source and Destination addresses are immutable and preserved. Extension
/// headers are walked in order and canonicalized per the option mutability rules
/// documented on this module: a TLV option with the `0x20` "change en route"
/// bit set has its data zeroed (type and length preserved); everything else is
/// covered as-is, including Routing headers in their final-destination form.
///
/// Returns a structured error when the base header is shorter than 40 bytes or
/// an extension header runs off the end of the supplied bytes, so a truncated
/// buffer surfaces as a typed error rather than a panic.
pub(crate) fn canonical_ipv6_for_ah(
    ipv6_header_bytes: &[u8],
    preceding_ext_headers: &[u8],
) -> Result<Vec<u8>> {
    if ipv6_header_bytes.len() < IPV6_BASE_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "ah.icv.canonical_ipv6",
            IPV6_BASE_HEADER_LEN,
            ipv6_header_bytes.len(),
        ));
    }

    let mut canonical = ipv6_header_bytes[..IPV6_BASE_HEADER_LEN].to_vec();

    // RFC 4302 §3.3.3.1.2.1: zero the Traffic Class (DSCP+ECN) and Flow Label —
    // the lower 28 bits of the first 4-byte word — while preserving the Version
    // nibble in the high 4 bits.
    let first_word = u32::from_be_bytes([canonical[0], canonical[1], canonical[2], canonical[3]]);
    let version_only = first_word & IPV6_VERSION_NIBBLE_MASK;
    canonical[..4].copy_from_slice(&version_only.to_be_bytes());

    // Zero the Hop Limit (byte 7). Payload Length (4-5), Next Header (6), and the
    // 32 address bytes (8-39) are immutable and stay as-is.
    canonical[IPV6_HOP_LIMIT_OFFSET] = 0;

    // RFC 4302 §3.3.3.1.2.2: canonicalize any preceding extension headers.
    let next_header = canonical[6];
    let extensions = canonical_ipv6_extension_headers(next_header, preceding_ext_headers)?;
    canonical.extend_from_slice(&extensions);

    Ok(canonical)
}

/// Canonicalize the chain of IPv6 extension headers that precede AH.
///
/// Walks the extension-header chain starting from `first_next_header` (the base
/// header's Next Header value), zeroing mutable option data per RFC 4302
/// §3.3.3.1.2.2 and preserving immutable bytes. Headers that are not
/// option-bearing (Routing, Fragment, and any unrecognized extension) are
/// covered as-is in their final-destination form. Returns a structured error
/// when a header's declared length runs past the supplied bytes.
fn canonical_ipv6_extension_headers(first_next_header: u8, ext_bytes: &[u8]) -> Result<Vec<u8>> {
    use crate::protocols::ip::shared::{IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS};

    let mut canonical = ext_bytes.to_vec();
    let mut offset = 0usize;
    let mut next_header = first_next_header;

    while offset < canonical.len() {
        // Each length-bearing extension header starts with Next Header (1) and
        // Hdr Ext Len (1); the Fragment header is a fixed 8 bytes regardless.
        if canonical.len() - offset < IPV6_EXT_MIN_LEN {
            return Err(CrafterError::buffer_too_short(
                "ah.icv.canonical_ipv6.ext",
                offset + IPV6_EXT_MIN_LEN,
                canonical.len(),
            ));
        }

        let this_next_header = canonical[offset];
        let header_len = if next_header == IPPROTO_FRAGMENT {
            IPV6_EXT_MIN_LEN
        } else {
            IPV6_EXT_MIN_LEN + canonical[offset + 1] as usize * 8
        };

        if canonical.len() - offset < header_len {
            return Err(CrafterError::buffer_too_short(
                "ah.icv.canonical_ipv6.ext",
                offset + header_len,
                canonical.len(),
            ));
        }

        // Hop-by-Hop Options and Destination Options carry TLV options whose data
        // is zeroed when the option is mutable. Other extension headers (Routing,
        // Fragment, unknown) are covered as-is in final-destination form.
        if next_header == IPPROTO_HOPOPTS || next_header == IPPROTO_DSTOPTS {
            canonicalize_ipv6_options(&mut canonical[offset + 2..offset + header_len]);
        }

        next_header = this_next_header;
        offset += header_len;
    }

    Ok(canonical)
}

/// Zero the data of mutable options in an IPv6 options area (the option TLVs of
/// a Hop-by-Hop or Destination Options header), preserving type and length and
/// leaving immutable options untouched (RFC 4302 §3.3.3.1.2.2, RFC 8200 §4.2).
fn canonicalize_ipv6_options(options: &mut [u8]) {
    let mut index = 0usize;
    while index < options.len() {
        let option_type = options[index];
        if option_type == IPV6_OPTION_PAD1 {
            // Pad1 is a lone zero byte with no length or data.
            index += 1;
            continue;
        }

        // A length-bearing option needs at least its type and length octets.
        if index + 2 > options.len() {
            break;
        }
        let data_len = options[index + 1] as usize;
        let data_start = index + 2;
        let data_end = data_start + data_len;
        if data_end > options.len() {
            break;
        }

        if option_type & IPV6_OPTION_MUTABLE_MASK != 0 {
            for byte in &mut options[data_start..data_end] {
                *byte = 0;
            }
        }

        index = data_end;
    }
}

/// Gather the compiled bytes of the preceding IPv6 base header and every
/// extension header that sits between it and the AH layer.
///
/// Walks `ctx.previous()` outward from the AH position: the immediately
/// preceding IPv6 extension headers (Hop-by-Hop Options, Routing, Destination
/// Options, Fragment, etc.) and finally the IPv6 base header, each compiled in a
/// context positioned at its own index so auto-filled fields are honored.
/// Returns `(base_header_bytes, preceding_ext_header_bytes)`, the two inputs
/// [`canonical_ipv6_for_ah`] expects.
///
/// Returns a structured error when there is no preceding layer chain ending in
/// an IPv6 base header, so an AH built without an enclosing IPv6 surfaces a
/// typed error.
pub(crate) fn preceding_ipv6_header_bytes(ctx: &LayerContext<'_>) -> Result<(Vec<u8>, Vec<u8>)> {
    let ah_index = ctx.index();
    if ah_index == 0 {
        return Err(CrafterError::invalid_field_value(
            "ah.icv.previous",
            "AH requires a preceding IP header to authenticate",
        ));
    }

    // Walk from the layer just before AH back toward the network layer, compiling
    // each extension header until the IPv6 base header is reached.
    let mut ext_headers: Vec<Vec<u8>> = Vec::new();
    let mut base_header: Option<Vec<u8>> = None;
    for index in (0..ah_index).rev() {
        let layer = ctx.packet().iter().nth(index).ok_or_else(|| {
            CrafterError::invalid_field_value(
                "ah.icv.previous",
                "AH requires a preceding IP header to authenticate",
            )
        })?;
        let layer_ctx = LayerContext::new(ctx.packet(), index);

        if let Some(ipv6) = layer.as_any().downcast_ref::<Ipv6>() {
            let mut header = Vec::new();
            ipv6.compile(&layer_ctx, &mut header)?;
            base_header = Some(header);
            break;
        }

        if is_ipv6_extension_layer(layer) {
            let mut header = Vec::new();
            layer.compile(&layer_ctx, &mut header)?;
            ext_headers.push(header);
            continue;
        }

        // Anything else between AH and the IPv6 base header is not an extension
        // header chain we can canonicalize.
        return Err(CrafterError::invalid_field_value(
            "ah.icv.previous",
            "AH requires the preceding layers to be an IPv6 header and its extension headers",
        ));
    }

    let base_header = base_header.ok_or_else(|| {
        CrafterError::invalid_field_value(
            "ah.icv.previous",
            "preceding layer is not an IPv6 header",
        )
    })?;

    // `ext_headers` was collected AH-to-base (reverse wire order); restore the
    // base-to-AH order before concatenating.
    ext_headers.reverse();
    let preceding_ext: Vec<u8> = ext_headers.into_iter().flatten().collect();
    Ok((base_header, preceding_ext))
}

/// Whether a layer is one of the IPv6 extension headers that can precede AH in
/// the header chain.
fn is_ipv6_extension_layer(layer: &dyn Layer) -> bool {
    use crate::protocols::ipv6::{
        Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6HopByHopOptionsHeader,
        Ipv6MobileRoutingHeader, Ipv6RoutingHeader, Ipv6SegmentRoutingHeader,
    };

    let any = layer.as_any();
    any.is::<Ipv6HopByHopOptionsHeader>()
        || any.is::<Ipv6DestinationOptionsHeader>()
        || any.is::<Ipv6RoutingHeader>()
        || any.is::<Ipv6MobileRoutingHeader>()
        || any.is::<Ipv6SegmentRoutingHeader>()
        || any.is::<Ipv6FragmentHeader>()
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

    /// A representative compiled IPv6 base header with non-zero Version, Traffic
    /// Class, Flow Label, and Hop Limit so the canonicalization is observable.
    fn sample_ipv6_header() -> Vec<u8> {
        let mut header = Vec::with_capacity(IPV6_BASE_HEADER_LEN);
        // Version 6, Traffic Class 0xB8, Flow Label 0x12345 (mutable bits set).
        // version_class_flow = (6 << 28) | (0xB8 << 20) | 0x12345 = 0x6B812345.
        header.extend_from_slice(&0x6B81_2345u32.to_be_bytes());
        header.extend_from_slice(&0x0010u16.to_be_bytes()); // Payload Length 16 (immutable)
        header.push(51); // Next Header = AH (51) (immutable)
        header.push(0x40); // Hop Limit 64 (mutable)
                           // Source 2001:db8::1 (immutable)
        header.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ]);
        // Destination 2001:db8::2 (immutable)
        header.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
        ]);
        assert_eq!(header.len(), IPV6_BASE_HEADER_LEN);
        header
    }

    #[test]
    fn canonicalizes_ipv6_traffic_class_flow_label_and_hop_limit() {
        let header = sample_ipv6_header();
        let canonical =
            canonical_ipv6_for_ah(&header, &[]).expect("40-byte IPv6 header canonicalizes");

        // The first word keeps the Version nibble (6) but zeroes the lower 28
        // bits (Traffic Class + Flow Label).
        assert_eq!(&canonical[..4], &0x6000_0000u32.to_be_bytes());
        assert_eq!(canonical[0] >> 4, 6, "Version nibble preserved");
        // Hop Limit (byte 7) is zeroed.
        assert_eq!(canonical[IPV6_HOP_LIMIT_OFFSET], 0, "Hop Limit zeroed");

        // Payload Length (bytes 4-5) is preserved.
        assert_eq!(&canonical[4..6], &0x0010u16.to_be_bytes());
        // Next Header (byte 6) is preserved (AH = 51).
        assert_eq!(canonical[6], 51, "Next Header preserved");
        // Source and destination addresses are preserved verbatim.
        assert_eq!(&canonical[8..24], &header[8..24], "Source preserved");
        assert_eq!(&canonical[24..40], &header[24..40], "Destination preserved");
        // No extension headers were supplied, so length is unchanged.
        assert_eq!(canonical.len(), IPV6_BASE_HEADER_LEN);
    }

    #[test]
    fn ipv6_canonicalization_zeroes_only_the_mutable_bits() {
        let header = sample_ipv6_header();
        let canonical = canonical_ipv6_for_ah(&header, &[]).expect("canonicalizes");

        let mut expected = header.clone();
        // Zero Traffic Class + Flow Label while keeping the Version nibble.
        expected[0] = 0x60;
        expected[1] = 0x00;
        expected[2] = 0x00;
        expected[3] = 0x00;
        // Zero Hop Limit.
        expected[IPV6_HOP_LIMIT_OFFSET] = 0;
        assert_eq!(canonical, expected);
    }

    #[test]
    fn ipv6_rejects_a_truncated_base_header() {
        let err = canonical_ipv6_for_ah(&[0x60, 0, 0, 0], &[])
            .expect_err("a 4-byte buffer is too short for an IPv6 header");
        let _ = err;
    }

    #[test]
    fn ipv6_destination_options_mutable_data_is_zeroed() {
        use crate::protocols::ip::shared::IPPROTO_DSTOPTS;

        // Base header whose Next Header points at a Destination Options header.
        let mut header = sample_ipv6_header();
        header[6] = IPPROTO_DSTOPTS;

        // An 8-byte Destination Options header: Next Header = AH (51), Hdr Ext
        // Len = 0, then a single option. Option type 0xE0 (1110_0000: the 0x20
        // "change en route" bit is set -> mutable), length 4, data 0xDEADBEEF.
        let ext = vec![
            51, // Next Header = AH
            0,  // Hdr Ext Len = 0 -> total 8 bytes
            0xE0, 0x04, 0xDE, 0xAD, 0xBE, 0xEF,
        ];

        let canonical =
            canonical_ipv6_for_ah(&header, &ext).expect("canonicalizes with ext header");

        // Base header still canonicalizes.
        assert_eq!(&canonical[..4], &0x6000_0000u32.to_be_bytes());
        assert_eq!(canonical[IPV6_HOP_LIMIT_OFFSET], 0);

        // Extension header follows the 40-byte base header. The option type and
        // length survive; the 4 mutable data bytes are zeroed.
        let ext_region = &canonical[IPV6_BASE_HEADER_LEN..];
        assert_eq!(ext_region[0], 51, "ext Next Header preserved");
        assert_eq!(ext_region[1], 0, "ext Hdr Ext Len preserved");
        assert_eq!(ext_region[2], 0xE0, "option type preserved");
        assert_eq!(ext_region[3], 0x04, "option length preserved");
        assert_eq!(
            &ext_region[4..8],
            &[0, 0, 0, 0],
            "mutable option data zeroed"
        );
    }

    #[test]
    fn ipv6_immutable_option_data_is_preserved() {
        use crate::protocols::ip::shared::IPPROTO_DSTOPTS;

        let mut header = sample_ipv6_header();
        header[6] = IPPROTO_DSTOPTS;

        // Option type 0x04 (the 0x20 mutable bit is clear -> immutable), length 4.
        let ext = vec![51, 0, 0x04, 0x04, 0x11, 0x22, 0x33, 0x44];
        let canonical = canonical_ipv6_for_ah(&header, &ext).expect("canonicalizes");

        let ext_region = &canonical[IPV6_BASE_HEADER_LEN..];
        assert_eq!(
            &ext_region[4..8],
            &[0x11, 0x22, 0x33, 0x44],
            "immutable option data preserved"
        );
    }

    #[test]
    fn ipv6_routing_header_is_covered_as_is() {
        use crate::protocols::ip::shared::IPPROTO_ROUTE;

        let mut header = sample_ipv6_header();
        header[6] = IPPROTO_ROUTE;

        // An 8-byte Routing header: Next Header = AH (51), Hdr Ext Len = 0,
        // Routing Type, Segments Left, then 4 type-specific bytes. Routing
        // headers are covered as-is (final-destination form).
        let ext = vec![51, 0, 0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let canonical = canonical_ipv6_for_ah(&header, &ext).expect("canonicalizes");

        // The routing header bytes survive unchanged.
        assert_eq!(&canonical[IPV6_BASE_HEADER_LEN..], &ext[..]);
    }

    #[test]
    fn ipv6_extension_header_truncation_is_a_structured_error() {
        use crate::protocols::ip::shared::IPPROTO_DSTOPTS;

        let mut header = sample_ipv6_header();
        header[6] = IPPROTO_DSTOPTS;
        // Hdr Ext Len = 1 claims a 16-byte header but only 8 bytes are supplied.
        let ext = vec![51, 1, 0x01, 0x00, 0, 0, 0, 0];
        let err = canonical_ipv6_for_ah(&header, &ext)
            .expect_err("extension header runs off the supplied bytes");
        let _ = err;
    }

    #[test]
    fn preceding_ipv6_header_is_extracted_and_canonicalizes() {
        use crate::protocols::ipv6::Ipv6;
        use core::net::Ipv6Addr;

        let ipv6 = Ipv6::new()
            .src(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1))
            .dst(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2))
            .traffic_class(0xB8)
            .flow_label(0x12345)
            .hop_limit(51);
        let packet: Packet = ipv6 / Raw::from_bytes([0u8; 4]);

        // The following layer sits at index 1; its previous layer is the IPv6
        // base header at index 0.
        let ctx = LayerContext::new(&packet, 1);
        let (base, ext) =
            preceding_ipv6_header_bytes(&ctx).expect("preceding IPv6 header extracted");

        assert_eq!(base.len(), IPV6_BASE_HEADER_LEN);
        assert_eq!(base[0] >> 4, 6, "version nibble is 6");
        assert!(ext.is_empty(), "no preceding extension headers");
        // Source/destination survive into the compiled bytes.
        assert_eq!(
            &base[8..24],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        // Canonicalizing zeroes the Traffic Class, Flow Label, and Hop Limit we
        // set.
        let canonical = canonical_ipv6_for_ah(&base, &ext).expect("canonicalizes");
        assert_eq!(&canonical[..4], &0x6000_0000u32.to_be_bytes());
        assert_eq!(canonical[IPV6_HOP_LIMIT_OFFSET], 0);
    }

    #[test]
    fn preceding_ipv6_layer_must_be_ipv6() {
        let packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 4]));
        let ctx = LayerContext::new(&packet, 0);
        let err = preceding_ipv6_header_bytes(&ctx).expect_err("no preceding IP header");
        let _ = err;
    }
}
