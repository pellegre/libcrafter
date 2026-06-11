//! BGP-4 (RFC 4271) message layers.

use crate::field::Field;

use super::constants::{BGP_HEADER_LEN, BGP_MARKER_LEN};

/// The shared 19-octet BGP message header (RFC 4271 §4.1).
///
/// Every BGP message begins with this fixed header: a 16-octet Marker (all
/// ones by default), a 2-octet Length covering the whole message, and a
/// 1-octet Type. Each field uses [`Field`] so that `compile()` can auto-fill
/// values the caller left unset while preserving anything the caller set
/// explicitly, including wrong-on-purpose values used to build malformed
/// messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BgpHeader {
    /// 16-octet Marker. Defaults to all ones (`[0xFF; 16]`).
    marker: Field<[u8; BGP_MARKER_LEN]>,
    /// 2-octet total message Length. Left unset so it is auto-filled.
    length: Field<u16>,
    /// 1-octet message Type code.
    message_type: Field<u8>,
}

impl BgpHeader {
    /// Create a header for the given message type with builder defaults:
    /// the marker defaults to all ones and the length is left unset so
    /// `compile()` fills it from the body size.
    pub(crate) fn new(message_type: u8) -> Self {
        Self {
            marker: Field::defaulted([0xFF; BGP_MARKER_LEN]),
            length: Field::unset(),
            message_type: Field::defaulted(message_type),
        }
    }

    /// Construct a header from decoded wire fields, marking every field as
    /// caller-supplied so auto-fill leaves them untouched.
    #[allow(dead_code)]
    pub(crate) fn from_decoded_parts(
        marker: [u8; BGP_MARKER_LEN],
        length: u16,
        message_type: u8,
    ) -> Self {
        Self {
            marker: Field::user(marker),
            length: Field::user(length),
            message_type: Field::user(message_type),
        }
    }

    /// Force a specific marker, overriding the default. Allows building
    /// malformed messages with a non-all-ones marker.
    #[allow(dead_code)]
    pub(crate) fn set_marker(&mut self, marker: [u8; BGP_MARKER_LEN]) {
        self.marker.set_user(marker);
    }

    /// Force a specific Length, overriding auto-fill. Allows building
    /// malformed messages whose declared length disagrees with the body.
    #[allow(dead_code)]
    pub(crate) fn set_length(&mut self, length: u16) {
        self.length.set_user(length);
    }

    /// Force a specific message Type, overriding the default.
    #[allow(dead_code)]
    pub(crate) fn set_type(&mut self, message_type: u8) {
        self.message_type.set_user(message_type);
    }

    /// The Marker to emit: the caller/default value if set, else all ones.
    pub(crate) fn effective_marker(&self) -> [u8; BGP_MARKER_LEN] {
        self.marker.value().copied().unwrap_or([0xFF; BGP_MARKER_LEN])
    }

    /// The Length to emit: the caller value if set, otherwise the header
    /// length plus `body_len` (the full on-wire message length).
    pub(crate) fn effective_length(&self, body_len: usize) -> u16 {
        match self.length.value() {
            Some(&length) => length,
            None => (BGP_HEADER_LEN + body_len) as u16,
        }
    }

    /// The message Type to emit: the caller/default value if set, else 0.
    pub(crate) fn effective_type(&self) -> u8 {
        self.message_type.value().copied().unwrap_or(0)
    }

    /// Append the 19-octet header to `out`: the 16-octet marker, the 2-octet
    /// big-endian length, and the 1-octet type. `body_len` is the length of
    /// the message body that follows the header.
    pub(crate) fn write_header(&self, body_len: usize, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.effective_marker());
        out.extend_from_slice(&self.effective_length(body_len).to_be_bytes());
        out.push(self.effective_type());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::bgp::constants::BGP_TYPE_KEEPALIVE;

    #[test]
    fn unset_length_is_header_plus_body() {
        let header = BgpHeader::new(BGP_TYPE_KEEPALIVE);

        assert_eq!(header.effective_length(0), BGP_HEADER_LEN as u16);
        assert_eq!(header.effective_length(10), (BGP_HEADER_LEN + 10) as u16);
    }

    #[test]
    fn user_set_length_is_preserved_verbatim() {
        let mut header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        header.set_length(4096);

        // Body size is ignored once the caller forces a length, even when the
        // forced value disagrees with the body (malformed-on-purpose).
        assert_eq!(header.effective_length(0), 4096);
        assert_eq!(header.effective_length(99), 4096);
    }

    #[test]
    fn default_marker_is_all_ones() {
        let header = BgpHeader::new(BGP_TYPE_KEEPALIVE);

        assert_eq!(header.effective_marker(), [0xFF; BGP_MARKER_LEN]);
    }

    #[test]
    fn set_marker_overrides_default() {
        let mut header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        header.set_marker([0x00; BGP_MARKER_LEN]);

        assert_eq!(header.effective_marker(), [0x00; BGP_MARKER_LEN]);
    }

    #[test]
    fn effective_type_reflects_constructor_and_override() {
        let mut header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        assert_eq!(header.effective_type(), BGP_TYPE_KEEPALIVE);

        header.set_type(99);
        assert_eq!(header.effective_type(), 99);
    }

    #[test]
    fn write_header_emits_marker_length_type() {
        let header = BgpHeader::new(BGP_TYPE_KEEPALIVE);
        let mut out = Vec::new();
        header.write_header(0, &mut out);

        assert_eq!(out.len(), BGP_HEADER_LEN);
        assert_eq!(&out[..BGP_MARKER_LEN], &[0xFF; BGP_MARKER_LEN]);
        // Length = 19 + 0, big-endian.
        assert_eq!(&out[BGP_MARKER_LEN..BGP_MARKER_LEN + 2], &[0x00, 0x13]);
        assert_eq!(out[BGP_MARKER_LEN + 2], BGP_TYPE_KEEPALIVE);
    }

    #[test]
    fn from_decoded_parts_marks_fields_user_set() {
        let header = BgpHeader::from_decoded_parts([0xAB; BGP_MARKER_LEN], 23, 2);

        assert_eq!(header.effective_marker(), [0xAB; BGP_MARKER_LEN]);
        // User-set length ignores body size.
        assert_eq!(header.effective_length(1000), 23);
        assert_eq!(header.effective_type(), 2);
    }
}
