use core::net::Ipv4Addr;

use crate::error::{CrafterError, Result};
use crate::field::Field;

use super::super::{hex_bytes, ETHERTYPE_IPV4};

const INLINE_ADDRESS_CAP: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ArpAddressBytes {
    Len4([u8; 4]),
    Len6([u8; 6]),
    Len8([u8; 8]),
    Len16([u8; 16]),
    Inline {
        len: u8,
        bytes: [u8; INLINE_ADDRESS_CAP],
    },
    Heap(Box<[u8]>),
}

impl ArpAddressBytes {
    pub(super) fn from_len4(bytes: [u8; 4]) -> Self {
        Self::Len4(bytes)
    }

    pub(super) fn from_len6(bytes: [u8; 6]) -> Self {
        Self::Len6(bytes)
    }

    pub(super) fn from_slice(bytes: &[u8]) -> Self {
        match bytes.len() {
            4 => {
                let mut out = [0u8; 4];
                out.copy_from_slice(bytes);
                Self::Len4(out)
            }
            6 => {
                let mut out = [0u8; 6];
                out.copy_from_slice(bytes);
                Self::Len6(out)
            }
            8 => {
                let mut out = [0u8; 8];
                out.copy_from_slice(bytes);
                Self::Len8(out)
            }
            16 => {
                let mut out = [0u8; 16];
                out.copy_from_slice(bytes);
                Self::Len16(out)
            }
            len if len <= INLINE_ADDRESS_CAP => {
                let mut inline = [0u8; INLINE_ADDRESS_CAP];
                inline[..bytes.len()].copy_from_slice(bytes);
                Self::Inline {
                    len: bytes.len() as u8,
                    bytes: inline,
                }
            }
            _ => Self::Heap(bytes.to_vec().into_boxed_slice()),
        }
    }

    pub(super) fn from_vec(bytes: Vec<u8>) -> Self {
        if bytes.len() <= INLINE_ADDRESS_CAP {
            Self::from_slice(&bytes)
        } else {
            Self::Heap(bytes.into_boxed_slice())
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Len4(bytes) => bytes,
            Self::Len6(bytes) => bytes,
            Self::Len8(bytes) => bytes,
            Self::Len16(bytes) => bytes,
            Self::Inline { len, bytes } => &bytes[..*len as usize],
            Self::Heap(bytes) => bytes,
        }
    }

    pub(super) fn len(&self) -> usize {
        match self {
            Self::Len4(_) => 4,
            Self::Len6(_) => 6,
            Self::Len8(_) => 8,
            Self::Len16(_) => 16,
            Self::Inline { len, .. } => *len as usize,
            Self::Heap(bytes) => bytes.len(),
        }
    }

    pub(super) fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

/// Clamp a byte length into the [`u8`] ARP length field without overflow. A
/// length beyond 255 is saturated rather than wrapped so it surfaces as a
/// length mismatch at compile time instead of silently aliasing a small value.
pub(super) fn saturating_len_u8(len: usize) -> u8 {
    u8::try_from(len).unwrap_or(u8::MAX)
}

pub(super) fn value_or_vec(field: &Field<ArpAddressBytes>, len: u8) -> Vec<u8> {
    field
        .value()
        .map(ArpAddressBytes::to_vec)
        .unwrap_or_else(|| vec![0; len as usize])
}

pub(super) fn extend_value_or_zeros(out: &mut Vec<u8>, field: &Field<ArpAddressBytes>, len: u8) {
    if let Some(value) = field.value() {
        out.extend_from_slice(value.as_slice());
    } else {
        out.resize(out.len() + len as usize, 0);
    }
}

pub(super) fn validate_len(
    field: &'static str,
    value: Option<&ArpAddressBytes>,
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
