//! Network byte-order read and write helpers.

use crate::error::{CrafterError, Result};

fn ensure_len(slice: &[u8], required: usize, context: &'static str) -> Result<()> {
    if slice.len() < required {
        Err(CrafterError::buffer_too_short(
            context,
            required,
            slice.len(),
        ))
    } else {
        Ok(())
    }
}

/// Read a big-endian `u16`.
pub fn read_u16_be(bytes: &[u8]) -> Result<u16> {
    ensure_len(bytes, 2, "u16")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Read a little-endian `u16`.
pub fn read_u16_le(bytes: &[u8]) -> Result<u16> {
    ensure_len(bytes, 2, "u16")?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a big-endian `u32`.
pub fn read_u32_be(bytes: &[u8]) -> Result<u32> {
    ensure_len(bytes, 4, "u32")?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian `u32`.
pub fn read_u32_le(bytes: &[u8]) -> Result<u32> {
    ensure_len(bytes, 4, "u32")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Write a big-endian `u16`.
pub fn write_u16_be(bytes: &mut [u8], value: u16) -> Result<()> {
    ensure_len(bytes, 2, "u16")?;
    bytes[..2].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Write a little-endian `u16`.
pub fn write_u16_le(bytes: &mut [u8], value: u16) -> Result<()> {
    ensure_len(bytes, 2, "u16")?;
    bytes[..2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

/// Write a big-endian `u32`.
pub fn write_u32_be(bytes: &mut [u8], value: u32) -> Result<()> {
    ensure_len(bytes, 4, "u32")?;
    bytes[..4].copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Write a little-endian `u32`.
pub fn write_u32_le(bytes: &mut [u8], value: u32) -> Result<()> {
    ensure_len(bytes, 4, "u32")?;
    bytes[..4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod field_primitives {
    use super::{
        read_u16_be, read_u16_le, read_u32_be, read_u32_le, write_u16_be, write_u16_le,
        write_u32_be, write_u32_le,
    };

    #[test]
    fn reads_big_and_little_endian_values() {
        let bytes = [0x12, 0x34, 0x56, 0x78];

        assert_eq!(read_u16_be(&bytes).unwrap(), 0x1234);
        assert_eq!(read_u16_le(&bytes).unwrap(), 0x3412);
        assert_eq!(read_u32_be(&bytes).unwrap(), 0x12345678);
        assert_eq!(read_u32_le(&bytes).unwrap(), 0x78563412);
    }

    #[test]
    fn writes_big_and_little_endian_values() {
        let mut bytes = [0u8; 4];

        write_u16_be(&mut bytes, 0x1234).unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x34]);

        write_u16_le(&mut bytes, 0x1234).unwrap();
        assert_eq!(&bytes[..2], &[0x34, 0x12]);

        write_u32_be(&mut bytes, 0x12345678).unwrap();
        assert_eq!(bytes, [0x12, 0x34, 0x56, 0x78]);

        write_u32_le(&mut bytes, 0x12345678).unwrap();
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn reports_short_buffers() {
        let mut one = [0u8; 1];

        assert!(read_u16_be(&one).is_err());
        assert!(write_u16_be(&mut one, 1).is_err());
    }
}
