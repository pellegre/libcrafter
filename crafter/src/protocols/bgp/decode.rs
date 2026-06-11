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

#[cfg(test)]
mod tests {
    use super::*;

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
}
