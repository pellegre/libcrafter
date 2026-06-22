//! Shared internal helpers for the IEEE 802.11 MAC layer.

use crate::field::Field;

pub(super) const fn set_subfield(bits: u16, mask: u16, shift: u8, value: u8) -> u16 {
    (bits & !mask) | (((value as u16) << shift) & mask)
}

pub(super) const fn set_flag(bits: u16, flag: u16, enabled: bool) -> u16 {
    if enabled {
        bits | flag
    } else {
        bits & !flag
    }
}

pub(super) fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

pub(super) fn dot11_hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}
