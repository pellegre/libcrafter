//! Shared TLS length-prefixed vector codecs.
//!
//! TLS vectors carry one-, two-, or three-octet big-endian length prefixes.
//! These helpers keep prefix parsing, vector bounds, cursor advancement, and
//! structured short-buffer errors consistent across record, handshake, and
//! extension bodies.

use crate::{CrafterError, Result};

/// TLS vector length-prefix width for `u8` vector lengths.
pub const TLS_VECTOR_U8_PREFIX_LEN: usize = 1;
/// TLS vector length-prefix width for `u16` vector lengths.
pub const TLS_VECTOR_U16_PREFIX_LEN: usize = 2;
/// TLS vector length-prefix width for `u24` vector lengths.
pub const TLS_VECTOR_U24_PREFIX_LEN: usize = 3;

/// Maximum payload length representable by a TLS `u8` vector prefix.
pub const TLS_VECTOR_U8_MAX_LEN: usize = u8::MAX as usize;
/// Maximum payload length representable by a TLS `u16` vector prefix.
pub const TLS_VECTOR_U16_MAX_LEN: usize = u16::MAX as usize;
/// Maximum payload length representable by a TLS `u24` vector prefix.
pub const TLS_VECTOR_U24_MAX_LEN: usize = 0x00ff_ffff;

/// Length-prefix width used by a TLS vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsVectorLengthPrefix {
    /// One-octet vector length.
    U8,
    /// Two-octet vector length.
    U16,
    /// Three-octet vector length.
    U24,
}

impl TlsVectorLengthPrefix {
    /// Number of bytes occupied by the vector length prefix.
    pub const fn width(self) -> usize {
        match self {
            Self::U8 => TLS_VECTOR_U8_PREFIX_LEN,
            Self::U16 => TLS_VECTOR_U16_PREFIX_LEN,
            Self::U24 => TLS_VECTOR_U24_PREFIX_LEN,
        }
    }

    /// Maximum body length representable by this prefix width.
    pub const fn max_len(self) -> usize {
        match self {
            Self::U8 => TLS_VECTOR_U8_MAX_LEN,
            Self::U16 => TLS_VECTOR_U16_MAX_LEN,
            Self::U24 => TLS_VECTOR_U24_MAX_LEN,
        }
    }

    /// Append `len` using this TLS vector prefix width.
    pub fn encode_len(
        self,
        len: usize,
        length_context: &'static str,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        if len > self.max_len() {
            return Err(CrafterError::invalid_field_value(
                length_context,
                "length exceeds prefix capacity",
            ));
        }

        match self {
            Self::U8 => out.push(len as u8),
            Self::U16 => out.extend_from_slice(&(len as u16).to_be_bytes()),
            Self::U24 => {
                out.push(((len >> 16) & 0xff) as u8);
                out.push(((len >> 8) & 0xff) as u8);
                out.push((len & 0xff) as u8);
            }
        }

        Ok(())
    }

    /// Decode a vector length prefix from the front of `bytes`.
    pub fn decode_len<'a>(
        self,
        bytes: &'a [u8],
        length_context: &'static str,
    ) -> Result<(usize, &'a [u8])> {
        let width = self.width();
        if bytes.len() < width {
            return Err(CrafterError::buffer_too_short(
                length_context,
                width,
                bytes.len(),
            ));
        }

        let len = match self {
            Self::U8 => bytes[0] as usize,
            Self::U16 => u16::from_be_bytes([bytes[0], bytes[1]]) as usize,
            Self::U24 => {
                ((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize
            }
        };

        Ok((len, &bytes[width..]))
    }
}

/// Bounds and error contexts for one TLS vector field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsVectorBounds {
    prefix: TlsVectorLengthPrefix,
    min_len: usize,
    max_len: usize,
    vector_context: &'static str,
    length_context: &'static str,
}

impl TlsVectorBounds {
    /// Create bounds for a TLS vector using `prefix`.
    pub const fn new(
        prefix: TlsVectorLengthPrefix,
        min_len: usize,
        max_len: usize,
        vector_context: &'static str,
        length_context: &'static str,
    ) -> Self {
        Self {
            prefix,
            min_len,
            max_len,
            vector_context,
            length_context,
        }
    }

    /// Create bounds for a one-octet length-prefixed TLS vector.
    pub const fn u8(
        min_len: usize,
        max_len: usize,
        vector_context: &'static str,
        length_context: &'static str,
    ) -> Self {
        Self::new(
            TlsVectorLengthPrefix::U8,
            min_len,
            max_len,
            vector_context,
            length_context,
        )
    }

    /// Create bounds for a two-octet length-prefixed TLS vector.
    pub const fn u16(
        min_len: usize,
        max_len: usize,
        vector_context: &'static str,
        length_context: &'static str,
    ) -> Self {
        Self::new(
            TlsVectorLengthPrefix::U16,
            min_len,
            max_len,
            vector_context,
            length_context,
        )
    }

    /// Create bounds for a three-octet length-prefixed TLS vector.
    pub const fn u24(
        min_len: usize,
        max_len: usize,
        vector_context: &'static str,
        length_context: &'static str,
    ) -> Self {
        Self::new(
            TlsVectorLengthPrefix::U24,
            min_len,
            max_len,
            vector_context,
            length_context,
        )
    }

    /// Return the configured length-prefix width.
    pub const fn prefix(self) -> TlsVectorLengthPrefix {
        self.prefix
    }

    /// Minimum permitted vector body length.
    pub const fn min_len(self) -> usize {
        self.min_len
    }

    /// Maximum permitted vector body length.
    pub const fn max_len(self) -> usize {
        self.max_len
    }

    /// Context used when the vector body is truncated.
    pub const fn vector_context(self) -> &'static str {
        self.vector_context
    }

    /// Context used when the vector length prefix or declared length is invalid.
    pub const fn length_context(self) -> &'static str {
        self.length_context
    }

    /// Validate that the declared vector bounds fit this prefix width.
    pub fn validate(self) -> Result<()> {
        if self.min_len > self.max_len {
            return Err(CrafterError::invalid_field_value(
                self.length_context,
                "minimum length exceeds maximum length",
            ));
        }

        if self.max_len > self.prefix.max_len() {
            return Err(CrafterError::invalid_field_value(
                self.length_context,
                "maximum length exceeds prefix capacity",
            ));
        }

        Ok(())
    }

    /// Validate a decoded or caller-supplied vector body length against bounds.
    pub fn validate_len(self, len: usize) -> Result<()> {
        self.validate()?;

        if len < self.min_len || len > self.max_len {
            return Err(CrafterError::invalid_field_value(
                self.length_context,
                "length outside allowed bounds",
            ));
        }

        Ok(())
    }

    /// Return the encoded byte count for a body of `body_len` bytes.
    pub fn encoded_len_for_body_len(self, body_len: usize) -> Result<usize> {
        self.validate_len(body_len)?;
        self.prefix.width().checked_add(body_len).ok_or_else(|| {
            CrafterError::invalid_field_value(self.length_context, "length overflow")
        })
    }

    /// Return the encoded byte count for `body`.
    pub fn encoded_len_for_body(self, body: &[u8]) -> Result<usize> {
        self.encoded_len_for_body_len(body.len())
    }

    /// Append a bounded TLS vector to `out`.
    pub fn encode(self, body: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.validate_len(body.len())?;
        self.prefix
            .encode_len(body.len(), self.length_context, out)?;
        out.extend_from_slice(body);
        Ok(())
    }

    /// Return a bounded TLS vector encoding.
    pub fn encode_to_vec(self, body: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len_for_body(body)?);
        self.encode(body, &mut out)?;
        Ok(out)
    }

    /// Decode a bounded TLS vector from the front of `bytes`.
    pub fn decode_prefix<'a>(self, bytes: &'a [u8]) -> Result<(TlsVector<'a>, &'a [u8])> {
        self.validate()?;

        let (declared_len, body_and_tail) = self.prefix.decode_len(bytes, self.length_context)?;
        self.validate_len(declared_len)?;

        if body_and_tail.len() < declared_len {
            let required = self
                .prefix
                .width()
                .checked_add(declared_len)
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(self.length_context, "length overflow")
                })?;
            return Err(CrafterError::buffer_too_short(
                self.vector_context,
                required,
                bytes.len(),
            ));
        }

        let (body, tail) = body_and_tail.split_at(declared_len);
        Ok((TlsVector::new(self.prefix, body), tail))
    }

    /// Decode a bounded TLS vector at `cursor`, advancing only on success.
    pub fn decode_from<'a>(self, bytes: &'a [u8], cursor: &mut usize) -> Result<TlsVector<'a>> {
        let start = *cursor;
        let remaining = bytes.get(start..).ok_or_else(|| {
            CrafterError::buffer_too_short(self.vector_context, start, bytes.len())
        })?;

        let (vector, _) = self.decode_prefix(remaining)?;
        *cursor = start.checked_add(vector.encoded_len()).ok_or_else(|| {
            CrafterError::invalid_field_value(self.length_context, "cursor overflow")
        })?;
        Ok(vector)
    }
}

/// Borrowed raw body bytes decoded from a bounded TLS vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsVector<'a> {
    prefix: TlsVectorLengthPrefix,
    body: &'a [u8],
}

impl<'a> TlsVector<'a> {
    /// Create a borrowed raw TLS vector body with the prefix width it used.
    pub const fn new(prefix: TlsVectorLengthPrefix, body: &'a [u8]) -> Self {
        Self { prefix, body }
    }

    /// Return the vector length-prefix width.
    pub const fn prefix(self) -> TlsVectorLengthPrefix {
        self.prefix
    }

    /// Borrow the preserved raw vector body bytes.
    pub const fn body(self) -> &'a [u8] {
        self.body
    }

    /// Number of preserved body bytes.
    pub const fn len(self) -> usize {
        self.body.len()
    }

    /// Return true when the vector body is empty.
    pub const fn is_empty(self) -> bool {
        self.body.is_empty()
    }

    /// Number of bytes occupied by the complete encoded vector.
    pub const fn encoded_len(self) -> usize {
        self.prefix.width() + self.body.len()
    }

    /// Copy the preserved body bytes into an owned vector.
    pub fn to_vec(self) -> Vec<u8> {
        self.body.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const U8_BOUNDS: TlsVectorBounds =
        TlsVectorBounds::u8(0, 3, "tls.test.u8_vector", "tls.test.u8_vector.length");
    const U16_BOUNDS: TlsVectorBounds = TlsVectorBounds::u16(
        0,
        TLS_VECTOR_U16_MAX_LEN,
        "tls.test.u16_vector",
        "tls.test.u16_vector.length",
    );
    const U24_BOUNDS: TlsVectorBounds = TlsVectorBounds::u24(
        0,
        TLS_VECTOR_U24_MAX_LEN,
        "tls.test.u24_vector",
        "tls.test.u24_vector.length",
    );

    #[test]
    fn tls_vector_u8_empty_vector_round_trips_and_advances_cursor() {
        let encoded = U8_BOUNDS.encode_to_vec(&[]).unwrap();
        assert_eq!(encoded, [0x00]);

        let with_tail = [0xaa, 0x00, 0xbb];
        let mut cursor = 1;
        let vector = U8_BOUNDS.decode_from(&with_tail, &mut cursor).unwrap();

        assert_eq!(vector.prefix(), TlsVectorLengthPrefix::U8);
        assert!(vector.is_empty());
        assert_eq!(vector.body(), &[]);
        assert_eq!(vector.encoded_len(), 1);
        assert_eq!(cursor, 2);
    }

    #[test]
    fn tls_vector_u16_max_boundary_round_trips() {
        let body = vec![0xa5; TLS_VECTOR_U16_MAX_LEN];
        let encoded = U16_BOUNDS.encode_to_vec(&body).unwrap();

        assert_eq!(&encoded[..2], &[0xff, 0xff]);
        assert_eq!(
            encoded.len(),
            TLS_VECTOR_U16_PREFIX_LEN + TLS_VECTOR_U16_MAX_LEN
        );

        let (decoded, tail) = U16_BOUNDS.decode_prefix(&encoded).unwrap();
        assert!(tail.is_empty());
        assert_eq!(decoded.prefix(), TlsVectorLengthPrefix::U16);
        assert_eq!(decoded.body(), body.as_slice());
        assert_eq!(
            U16_BOUNDS.encoded_len_for_body_len(TLS_VECTOR_U16_MAX_LEN),
            Ok(TLS_VECTOR_U16_PREFIX_LEN + TLS_VECTOR_U16_MAX_LEN)
        );
    }

    #[test]
    fn tls_vector_u24_length_prefix_supports_max_boundary() {
        let mut encoded_len = Vec::new();
        TlsVectorLengthPrefix::U24
            .encode_len(
                TLS_VECTOR_U24_MAX_LEN,
                "tls.test.u24_vector.length",
                &mut encoded_len,
            )
            .unwrap();

        assert_eq!(encoded_len, [0xff, 0xff, 0xff]);
        assert_eq!(
            TlsVectorLengthPrefix::U24
                .decode_len(&encoded_len, "tls.test.u24_vector.length")
                .unwrap(),
            (TLS_VECTOR_U24_MAX_LEN, &[][..])
        );

        let encoded = U24_BOUNDS.encode_to_vec(&[0xde, 0xad, 0xbe]).unwrap();
        assert_eq!(encoded, [0x00, 0x00, 0x03, 0xde, 0xad, 0xbe]);
        let (decoded, tail) = U24_BOUNDS.decode_prefix(&encoded).unwrap();
        assert!(tail.is_empty());
        assert_eq!(decoded.prefix(), TlsVectorLengthPrefix::U24);
        assert_eq!(decoded.body(), &[0xde, 0xad, 0xbe]);
    }

    #[test]
    fn tls_vector_decode_reports_prefix_and_body_overrun_without_advancing_cursor() {
        assert_eq!(
            U16_BOUNDS.decode_prefix(&[0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.test.u16_vector.length",
                TLS_VECTOR_U16_PREFIX_LEN,
                1,
            )
        );

        let mut cursor = 0;
        let err = U16_BOUNDS
            .decode_from(&[0x00, 0x04, 0xaa, 0xbb], &mut cursor)
            .unwrap_err();
        assert_eq!(
            err,
            CrafterError::buffer_too_short("tls.test.u16_vector", 6, 4)
        );
        assert_eq!(cursor, 0);

        let mut past_end = 4;
        assert_eq!(
            U8_BOUNDS.decode_from(&[0x00], &mut past_end).unwrap_err(),
            CrafterError::buffer_too_short("tls.test.u8_vector", 4, 1)
        );
        assert_eq!(past_end, 4);
    }

    #[test]
    fn tls_vector_rejects_invalid_declared_and_encoded_lengths() {
        let bounded = TlsVectorBounds::u8(
            1,
            3,
            "tls.test.bounded_vector",
            "tls.test.bounded_vector.length",
        );

        assert_eq!(
            bounded.decode_prefix(&[0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.test.bounded_vector.length",
                "length outside allowed bounds",
            )
        );
        assert_eq!(
            bounded
                .decode_prefix(&[0x04, 0xaa, 0xbb, 0xcc, 0xdd])
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.test.bounded_vector.length",
                "length outside allowed bounds",
            )
        );
        assert_eq!(
            bounded.encode_to_vec(&[]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.test.bounded_vector.length",
                "length outside allowed bounds",
            )
        );
        assert_eq!(
            U8_BOUNDS.encode_to_vec(&[0, 1, 2, 3]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.test.u8_vector.length",
                "length outside allowed bounds",
            )
        );

        let impossible = TlsVectorBounds::u8(
            0,
            TLS_VECTOR_U8_MAX_LEN + 1,
            "tls.test.impossible_vector",
            "tls.test.impossible_vector.length",
        );
        assert_eq!(
            impossible.encode_to_vec(&[]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.test.impossible_vector.length",
                "maximum length exceeds prefix capacity",
            )
        );
    }
}
