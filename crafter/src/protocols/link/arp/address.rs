use core::net::Ipv4Addr;

use crate::error::{CrafterError, Result};
use crate::field::Field;

use super::super::{hex_bytes, ETHERTYPE_IPV4};

/// Clamp a byte length into the [`u8`] ARP length field without overflow. A
/// length beyond 255 is saturated rather than wrapped so it surfaces as a
/// length mismatch at compile time instead of silently aliasing a small value.
pub(super) fn saturating_len_u8(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(u8::MAX)
}

pub(super) fn value_or_vec(field: &Field<Vec<u8>>, len: u8) -> Vec<u8> {
    field
        .value()
        .cloned()
        .unwrap_or_else(|| vec![0; len as usize])
}

pub(super) fn validate_len(
    field: &'static str,
    value: Option<&Vec<u8>>,
    expected: u8,
) -> Result<()> {
    if let Some(value) = value {
        if value.len() != expected as usize {
            // The declared ARP length field and the explicit address byte vector
            // disagree. Surface a structured error that names the failing field
            // and both the expected length (the declared length field) and the
            // available length (the supplied byte count). `expected` is a `u8`,
            // so the required/available widths are bounded and the comparison
            // cannot overflow even at the `u8::MAX` boundary.
            return Err(CrafterError::buffer_too_short(
                field,
                expected as usize,
                value.len(),
            ));
        }
    }
    Ok(())
}

pub(super) fn parse_ipv4(input: &str) -> Result<Ipv4Addr> {
    input.parse().map_err(|_| {
        CrafterError::invalid_field_value("ipv4_address", "expected dotted-quad IPv4 address")
    })
}

pub(super) fn ipv4_from_bytes(protocol_type: u16, bytes: &[u8]) -> Option<Ipv4Addr> {
    if protocol_type == ETHERTYPE_IPV4 && bytes.len() == 4 {
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        None
    }
}

pub(super) fn address_summary_ipv4(protocol_type: u16, bytes: &[u8]) -> String {
    ipv4_from_bytes(protocol_type, bytes)
        .map(|addr| addr.to_string())
        .unwrap_or_else(|| hex_bytes(bytes))
}
