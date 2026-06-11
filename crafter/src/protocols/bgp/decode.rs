//! BGP-4 (RFC 4271) decode entrypoints.
//!
//! BGP decode follows the crate's structured-error contract: a buffer too short
//! for the field being read surfaces a typed [`CrafterError::BufferTooShort`]
//! carrying `context`, `required`, and `available` — never a panic and never a
//! half-read field. Mirrors the IPsec/ICMP decode shape (see
//! `crate::protocols::ipsec::ah::decode` and
//! `crate::protocols::ipsec::esp::decode`).
//!
//! The decode contract for BGP messages and path attributes:
//!
//! - **Unknown items are preserved.** An unrecognized message type, path
//!   attribute type code, or capability is kept as opaque bytes rather than
//!   discarded, matching the crate's unknown-next-protocol `Raw` fallback. The
//!   enclosing framing stays valid and re-compiles byte-for-byte.
//! - **Malformed items are typed.** A length that overruns the buffer, or a
//!   header shorter than its fixed minimum, becomes a structured
//!   [`CrafterError`] with the field's `context`, the bytes it `required`, and
//!   the bytes `available` — the same shape every other decoder emits.
//! - **Never panic.** Every slice into the buffer is length-checked first
//!   (through [`take`]), so truncation can only ever produce an `Err`, not an
//!   out-of-bounds index.

use crate::error::{CrafterError, Result};

use super::constants::{
    BGP_HEADER_LEN, BGP_MARKER_LEN, BGP_MAX_MESSAGE_LEN, BGP_TYPE_KEEPALIVE,
};
use super::{Bgp, BgpBody};

/// Build the structured truncation error BGP decode uses for a short buffer.
///
/// `context` names the field being read, `required` is the byte count that
/// field needs, and `available` is what the buffer actually holds. This is the
/// crate-wide [`CrafterError::buffer_too_short`] shape, named locally so the BGP
/// decoders read uniformly (RFC 4271 framing has many fixed-width fields).
#[allow(dead_code)]
fn need(context: &'static str, required: usize, available: usize) -> CrafterError {
    CrafterError::buffer_too_short(context, required, available)
}

/// Split `n` bytes off the front of `buf`, returning `(head, rest)`.
///
/// Returns `Ok((&buf[..n], &buf[n..]))` when the buffer holds at least `n`
/// bytes, or the structured [`need`] error (context `context`, required `n`,
/// available `buf.len()`) when it does not. Every BGP field read goes through
/// this helper so a truncated buffer can only ever yield an `Err`, never an
/// out-of-bounds panic.
#[allow(dead_code)]
fn take<'a>(buf: &'a [u8], n: usize, context: &'static str) -> Result<(&'a [u8], &'a [u8])> {
    if buf.len() < n {
        return Err(need(context, n, buf.len()));
    }
    Ok(buf.split_at(n))
}

/// Decode a single BGP message (RFC 4271 §4.1) from the front of `bytes`.
///
/// Reads the shared 19-octet header — the 16-octet Marker, the 2-octet Length,
/// and the 1-octet Type — through [`take`] so a buffer too short for any header
/// field surfaces a structured [`CrafterError::BufferTooShort`] (context
/// `"bgp header"`) rather than a panic. The declared Length is then validated
/// against the RFC 4271 §4.1 bounds (`[BGP_HEADER_LEN, BGP_MAX_MESSAGE_LEN]`)
/// and confirmed to fit within the buffer (a short buffer for the declared
/// length is a truncation error, context `"bgp message"`).
///
/// On success the returned [`Bgp`] carries the observed marker/length/type so a
/// round-trip re-compiles byte-for-byte, and the `usize` is the number of bytes
/// consumed (the message Length). KEEPALIVE (RFC 4271 §4.4) is header-only.
/// Every other type is preserved as a [`BgpBody::Unknown`] holding the raw body
/// bytes (the `length - BGP_HEADER_LEN` octets after the header); the real
/// typed bodies arrive in later steps.
#[allow(dead_code)]
pub(crate) fn decode_bgp_message(bytes: &[u8]) -> Result<(Bgp, usize)> {
    // The fixed 19-octet header: Marker (16), Length (2), Type (1). Each field
    // is length-checked through `take` so truncation can only yield an `Err`.
    let (marker_bytes, rest) = take(bytes, BGP_MARKER_LEN, "bgp header")?;
    let (length_bytes, rest) = take(rest, 2, "bgp header")?;
    let (type_bytes, _rest) = take(rest, 1, "bgp header")?;

    let mut marker = [0u8; BGP_MARKER_LEN];
    marker.copy_from_slice(marker_bytes);
    let length = u16::from_be_bytes([length_bytes[0], length_bytes[1]]);
    let message_type = type_bytes[0];

    // RFC 4271 §4.1: Length covers the whole message and must lie within
    // [19, 4096]. A value outside that range is a malformed header, not a
    // truncation, so it is a structured InvalidFieldValue.
    let length_usize = length as usize;
    if length_usize < BGP_HEADER_LEN {
        return Err(CrafterError::invalid_field_value(
            "bgp.header.length",
            "BGP message Length is below the 19-octet header minimum",
        ));
    }
    if length_usize > BGP_MAX_MESSAGE_LEN {
        return Err(CrafterError::invalid_field_value(
            "bgp.header.length",
            "BGP message Length exceeds the 4096-octet maximum",
        ));
    }

    // The buffer must hold the whole declared message; a short buffer here is a
    // truncation error carrying the declared length as `required`.
    if bytes.len() < length_usize {
        return Err(need("bgp message", length_usize, bytes.len()));
    }

    // The body is the octets after the 19-octet header, up to the declared
    // message length.
    let body_bytes = &bytes[BGP_HEADER_LEN..length_usize];
    let body = match message_type {
        BGP_TYPE_KEEPALIVE => BgpBody::Keepalive,
        // Other message types are preserved verbatim for now; later steps
        // replace this with the typed OPEN/UPDATE/NOTIFICATION bodies.
        other => BgpBody::Unknown {
            type_code: other,
            body: body_bytes.to_vec(),
        },
    };

    let bgp = Bgp::from_decoded_parts(marker, length, message_type, body);
    Ok((bgp, length_usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Layer;

    #[test]
    fn take_splits_when_enough_bytes() {
        let buf = [0x01, 0x02, 0x03, 0x04];
        let (head, rest) = take(&buf, 2, "bgp.test").expect("buffer has enough bytes");
        assert_eq!(head, &[0x01, 0x02]);
        assert_eq!(rest, &[0x03, 0x04]);
    }

    #[test]
    fn take_on_short_buffer_is_structured_error() {
        // A buffer shorter than the requested split surfaces the structured
        // truncation error carrying context/required/available — never a panic.
        let buf = [0x01, 0x02];
        let err = take(&buf, 4, "bgp.header").expect_err("must reject a short buffer");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "bgp.header");
                assert_eq!(required, 4);
                assert_eq!(available, buf.len());
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
    }

    /// A valid 19-octet KEEPALIVE decodes to a `Bgp` KEEPALIVE layer and reports
    /// 19 bytes consumed (RFC 4271 §4.4).
    #[test]
    fn decode_keepalive_consumes_nineteen_bytes() {
        let mut bytes = [0u8; BGP_HEADER_LEN];
        bytes[..BGP_MARKER_LEN].copy_from_slice(&[0xFF; BGP_MARKER_LEN]);
        bytes[BGP_MARKER_LEN..BGP_MARKER_LEN + 2]
            .copy_from_slice(&(BGP_HEADER_LEN as u16).to_be_bytes());
        bytes[BGP_MARKER_LEN + 2] = BGP_TYPE_KEEPALIVE;

        let (bgp, consumed) = decode_bgp_message(&bytes).expect("valid keepalive decodes");
        assert_eq!(consumed, BGP_HEADER_LEN);
        assert_eq!(bgp.summary(), "BGP KEEPALIVE len=19");
    }

    /// A 10-byte buffer cannot even hold the 16-octet marker, so decode surfaces
    /// the structured truncation error; its rendered message references the
    /// required length.
    #[test]
    fn decode_short_buffer_is_truncation_error() {
        let bytes = [0u8; 10];
        let err = decode_bgp_message(&bytes).expect_err("a 10-byte buffer is too short");
        match err {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, "bgp header");
                assert_eq!(required, BGP_MARKER_LEN);
                assert_eq!(available, 10);
            }
            other => panic!("expected buffer_too_short, got {other:?}"),
        }
        // The rendered message references the required length so an agent sees
        // why the buffer was rejected without log-fishing.
        let rendered = decode_bgp_message(&bytes).unwrap_err().to_string();
        assert!(
            rendered.contains(&BGP_MARKER_LEN.to_string()),
            "truncation message should reference the required length, got: {rendered}"
        );
    }
}
