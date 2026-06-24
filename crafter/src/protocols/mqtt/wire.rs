//! MQTT data representation helpers.
//!
//! MQTT 3.1.1 uses two-byte big-endian length prefixes for UTF-8 strings and
//! binary fields. [`decode_string_raw`] is available for malformed-packet or
//! diagnostic paths that need the exact string octets without UTF-8 validation.

use core::str;

use crate::endian::{read_u16_be, read_u32_be};
use crate::CrafterError;

const U16_LEN: usize = 2;
const U32_LEN: usize = 4;

fn need(context: &'static str, required: usize, available: usize) -> CrafterError {
    CrafterError::buffer_too_short(context, required, available)
}

fn encode_length_prefixed(
    value: &[u8],
    out: &mut Vec<u8>,
    field: &'static str,
) -> crate::Result<()> {
    let length = u16::try_from(value.len())
        .map_err(|_| CrafterError::invalid_field_value(field, "length must fit in two bytes"))?;

    encode_u16(length, out);
    out.extend_from_slice(value);
    Ok(())
}

fn decode_length_prefixed<'a>(
    bytes: &'a [u8],
    prefix_context: &'static str,
    value_context: &'static str,
) -> crate::Result<(&'a [u8], usize)> {
    if bytes.len() < U16_LEN {
        return Err(need(prefix_context, U16_LEN, bytes.len()));
    }

    let length = read_u16_be(bytes)? as usize;
    let required = U16_LEN + length;
    if bytes.len() < required {
        return Err(need(value_context, required, bytes.len()));
    }

    Ok((&bytes[U16_LEN..required], required))
}

/// Append an MQTT UTF-8 encoded string with its two-byte length prefix.
pub fn encode_string(value: &str, out: &mut Vec<u8>) -> crate::Result<()> {
    if value.as_bytes().contains(&0) {
        return Err(CrafterError::invalid_field_value(
            "mqtt.string",
            "string must not contain U+0000",
        ));
    }

    encode_length_prefixed(value.as_bytes(), out, "mqtt.string.length")
}

/// Decode an MQTT UTF-8 encoded string, returning the value and consumed bytes.
pub fn decode_string(bytes: &[u8]) -> crate::Result<(String, usize)> {
    let (raw, consumed) = decode_string_raw(bytes)?;
    let value = str::from_utf8(raw).map_err(|_| {
        CrafterError::invalid_field_value("mqtt.string", "string bytes must be valid UTF-8")
    })?;

    if value.as_bytes().contains(&0) {
        return Err(CrafterError::invalid_field_value(
            "mqtt.string",
            "string must not contain U+0000",
        ));
    }

    Ok((value.to_owned(), consumed))
}

/// Decode an MQTT string field as raw octets without validating UTF-8.
pub fn decode_string_raw(bytes: &[u8]) -> crate::Result<(&[u8], usize)> {
    decode_length_prefixed(bytes, "mqtt.string.length", "mqtt.string")
}

/// Append an MQTT binary field with its two-byte length prefix.
pub fn encode_binary(value: &[u8], out: &mut Vec<u8>) -> crate::Result<()> {
    encode_length_prefixed(value, out, "mqtt.binary.length")
}

/// Decode an MQTT binary field, returning the opaque bytes and consumed bytes.
pub fn decode_binary(bytes: &[u8]) -> crate::Result<(Vec<u8>, usize)> {
    let (raw, consumed) = decode_binary_raw(bytes)?;
    Ok((raw.to_vec(), consumed))
}

/// Decode an MQTT binary field as a borrowed slice.
pub fn decode_binary_raw(bytes: &[u8]) -> crate::Result<(&[u8], usize)> {
    decode_length_prefixed(bytes, "mqtt.binary.length", "mqtt.binary")
}

/// Append a two-byte big-endian integer.
pub fn encode_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Decode a two-byte big-endian integer.
pub fn decode_u16(bytes: &[u8]) -> crate::Result<(u16, usize)> {
    if bytes.len() < U16_LEN {
        return Err(need("mqtt.u16", U16_LEN, bytes.len()));
    }

    Ok((read_u16_be(bytes)?, U16_LEN))
}

/// Append a four-byte big-endian integer.
pub fn encode_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Decode a four-byte big-endian integer.
pub fn decode_u32(bytes: &[u8]) -> crate::Result<(u32, usize)> {
    if bytes.len() < U32_LEN {
        return Err(need("mqtt.u32", U32_LEN, bytes.len()));
    }

    Ok((read_u32_be(bytes)?, U32_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topic_string_round_trips() {
        let mut out = Vec::new();
        encode_string("sensors/temperature", &mut out).unwrap();

        assert_eq!(&out[..2], &[0x00, 0x13]);
        let (decoded, consumed) = decode_string(&out).unwrap();
        assert_eq!(decoded, "sensors/temperature");
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn binary_payload_round_trips() {
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut out = Vec::new();
        encode_binary(&payload, &mut out).unwrap();

        assert_eq!(&out[..2], &[0x00, 0x04]);
        let (decoded, consumed) = decode_binary(&out).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(consumed, out.len());
    }

    #[test]
    fn overrunning_length_prefix_errors() {
        let result = std::panic::catch_unwind(|| decode_binary(&[0x00, 0x04, 0xaa]));
        assert!(result.is_ok());

        match result.unwrap() {
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "mqtt.binary");
                assert_eq!(required, 6);
                assert_eq!(available, 3);
            }
            other => panic!("expected buffer-too-short error, got {other:?}"),
        }
    }

    #[test]
    fn empty_string_and_binary_round_trip() {
        let mut string = Vec::new();
        encode_string("", &mut string).unwrap();
        assert_eq!(string, [0x00, 0x00]);
        let (decoded_string, string_consumed) = decode_string(&string).unwrap();
        assert_eq!(decoded_string, "");
        assert_eq!(string_consumed, string.len());

        let mut binary = Vec::new();
        encode_binary(&[], &mut binary).unwrap();
        assert_eq!(binary, [0x00, 0x00]);
        let (decoded_binary, binary_consumed) = decode_binary(&binary).unwrap();
        assert!(decoded_binary.is_empty());
        assert_eq!(binary_consumed, binary.len());
    }

    #[test]
    fn integer_helpers_round_trip_boundaries() {
        for value in [u16::MIN, 1, 0x1234, u16::MAX] {
            let mut out = Vec::new();
            encode_u16(value, &mut out);
            let (decoded, consumed) = decode_u16(&out).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, U16_LEN);
        }

        for value in [u32::MIN, 1, 0x1234_5678, u32::MAX] {
            let mut out = Vec::new();
            encode_u32(value, &mut out);
            let (decoded, consumed) = decode_u32(&out).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, U32_LEN);
        }
    }

    #[test]
    fn invalid_utf8_errors_without_panicking() {
        let result = std::panic::catch_unwind(|| decode_string(&[0x00, 0x01, 0xff]));
        assert!(result.is_ok());

        match result.unwrap() {
            Err(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "mqtt.string");
                assert!(reason.contains("UTF-8"));
            }
            other => panic!("expected invalid-field-value error, got {other:?}"),
        }
    }
}
