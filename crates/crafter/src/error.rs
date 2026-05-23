//! Shared error types for core packet parsing and encoding.

use core::fmt;

/// Convenient result alias used by core packet primitives.
pub type Result<T> = core::result::Result<T, CrafterError>;

/// Errors returned by core packet parsing and encoding helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrafterError {
    /// A fixed-size buffer did not contain enough bytes.
    BufferTooShort {
        /// Name of the value being read or written.
        context: &'static str,
        /// Required byte count.
        required: usize,
        /// Available byte count.
        available: usize,
    },
    /// A textual MAC address could not be parsed.
    InvalidMacAddress {
        /// The original input.
        input: String,
        /// Short, stable reason for diagnostics.
        reason: &'static str,
    },
    /// A protocol field value is internally inconsistent or out of range.
    InvalidFieldValue {
        /// Stable protocol field name.
        field: &'static str,
        /// Short, stable reason for diagnostics.
        reason: &'static str,
    },
}

impl CrafterError {
    /// Build a buffer length error.
    pub fn buffer_too_short(context: &'static str, required: usize, available: usize) -> Self {
        Self::BufferTooShort {
            context,
            required,
            available,
        }
    }

    /// Build a MAC address parse error.
    pub fn invalid_mac_address(input: impl Into<String>, reason: &'static str) -> Self {
        Self::InvalidMacAddress {
            input: input.into(),
            reason,
        }
    }

    /// Build a protocol field validation error.
    pub const fn invalid_field_value(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidFieldValue { field, reason }
    }
}

impl fmt::Display for CrafterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort {
                context,
                required,
                available,
            } => write!(
                f,
                "{context} requires {required} bytes, but only {available} bytes are available"
            ),
            Self::InvalidMacAddress { input, reason } => {
                write!(f, "invalid MAC address '{input}': {reason}")
            }
            Self::InvalidFieldValue { field, reason } => {
                write!(f, "invalid value for {field}: {reason}")
            }
        }
    }
}

impl std::error::Error for CrafterError {}
