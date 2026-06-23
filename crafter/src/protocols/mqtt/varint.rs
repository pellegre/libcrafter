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
}
