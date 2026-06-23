//! MQTT Remaining Length variable-byte-integer helpers.

use crate::CrafterError;

const MAX_REMAINING_LENGTH: u32 = 268_435_455;

/// Append an MQTT Remaining Length variable-byte-integer encoding.
pub fn encode_remaining_length(value: u32, out: &mut Vec<u8>) -> crate::Result<()> {
    if value > MAX_REMAINING_LENGTH {
        return Err(CrafterError::invalid_field_value(
            "mqtt.remaining_length",
            "remaining length must be <= 268435455",
        ));
    }

    let mut remaining = value;
    loop {
        let mut encoded = (remaining % 128) as u8;
        remaining /= 128;
        if remaining > 0 {
            encoded |= 0x80;
        }
        out.push(encoded);
        if remaining == 0 {
            break;
        }
    }

    Ok(())
}

/// Decode an MQTT Remaining Length variable-byte-integer.
pub fn decode_remaining_length(bytes: &[u8]) -> crate::Result<(u32, usize)> {
    let mut value = 0u32;
    let mut multiplier = 1u32;

    for offset in 0..4 {
        let Some(&encoded) = bytes.get(offset) else {
            return Err(CrafterError::buffer_too_short(
                "mqtt.remaining_length",
                offset + 1,
                bytes.len(),
            ));
        };

        value += u32::from(encoded & 0x7f) * multiplier;
        if encoded & 0x80 == 0 {
            return Ok((value, offset + 1));
        }

        if offset == 3 {
            return Err(CrafterError::invalid_field_value(
                "mqtt.remaining_length",
                "remaining length uses more than four bytes",
            ));
        }

        multiplier *= 128;
    }

    unreachable!("MQTT remaining length loop is bounded to four bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_remaining_length_boundaries() {
        for (value, expected) in [
            (0, &[0x00][..]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (16_383, &[0xff, 0x7f]),
            (16_384, &[0x80, 0x80, 0x01]),
            (2_097_151, &[0xff, 0xff, 0x7f]),
            (2_097_152, &[0x80, 0x80, 0x80, 0x01]),
            (268_435_455, &[0xff, 0xff, 0xff, 0x7f]),
        ] {
            let mut out = Vec::new();
            encode_remaining_length(value, &mut out).unwrap();
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn rejects_values_above_maximum() {
        let mut out = Vec::new();
        assert!(encode_remaining_length(268_435_456, &mut out).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn decodes_remaining_length_boundaries() {
        for value in [
            0,
            127,
            128,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            268_435_455,
        ] {
            let mut encoded = Vec::new();
            encode_remaining_length(value, &mut encoded).unwrap();

            let (decoded, consumed) = decode_remaining_length(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn truncated_remaining_length_is_structured_error() {
        let result = std::panic::catch_unwind(|| decode_remaining_length(&[0x80]));
        assert!(result.is_ok());

        match result.unwrap() {
            Err(CrafterError::BufferTooShort {
                context,
                required,
                available,
            }) => {
                assert_eq!(context, "mqtt.remaining_length");
                assert_eq!(required, 2);
                assert_eq!(available, 1);
            }
            other => panic!("expected buffer-too-short error, got {other:?}"),
        }
    }

    #[test]
    fn overlong_remaining_length_is_structured_error() {
        let result =
            std::panic::catch_unwind(|| decode_remaining_length(&[0xff, 0xff, 0xff, 0xff]));
        assert!(result.is_ok());

        match result.unwrap() {
            Err(CrafterError::InvalidFieldValue { field, reason }) => {
                assert_eq!(field, "mqtt.remaining_length");
                assert!(reason.contains("more than four bytes"));
            }
            other => panic!("expected invalid-field-value error, got {other:?}"),
        }
    }
}
