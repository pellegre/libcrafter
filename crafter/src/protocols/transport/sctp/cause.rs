//! SCTP error-cause model.
//!
//! RFC 9260 section 3.3.10 defines error causes as parameter-shaped,
//! four-octet-aligned envelopes: cause code, cause length, cause-specific
//! information bytes, and padding. This module keeps that envelope
//! byte-preserving while later steps add decode and encode loops.

#![allow(dead_code)]

use crate::error::{CrafterError, Result};

use super::constants::{
    SCTP_ALIGNMENT, SCTP_CAUSE_CODE_COOKIE_RECEIVED_WHILE_SHUTTING_DOWN,
    SCTP_CAUSE_CODE_INVALID_MANDATORY_PARAMETER, SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER,
    SCTP_CAUSE_CODE_MISSING_MANDATORY_PARAMETER, SCTP_CAUSE_CODE_NO_USER_DATA,
    SCTP_CAUSE_CODE_OUT_OF_RESOURCE, SCTP_CAUSE_CODE_PROTOCOL_VIOLATION,
    SCTP_CAUSE_CODE_RESTART_WITH_NEW_ADDRESSES, SCTP_CAUSE_CODE_STALE_COOKIE,
    SCTP_CAUSE_CODE_UNRECOGNIZED_CHUNK_TYPE, SCTP_CAUSE_CODE_UNRECOGNIZED_PARAMETERS,
    SCTP_CAUSE_CODE_UNRESOLVABLE_ADDRESS, SCTP_CAUSE_CODE_USER_INITIATED_ABORT,
    SCTP_ERROR_CAUSE_HEADER_LEN,
};

/// Raw-preserving SCTP error-cause code value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SctpErrorCauseCode(u16);

impl SctpErrorCauseCode {
    /// Preserve a raw 16-bit SCTP error-cause code.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// Preserve a raw 16-bit SCTP error-cause code.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Return the preserved raw SCTP error-cause code.
    pub const fn raw(self) -> u16 {
        self.0
    }

    /// Return the preserved raw SCTP error-cause code.
    pub const fn as_u16(self) -> u16 {
        self.raw()
    }
}

impl From<u16> for SctpErrorCauseCode {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<SctpErrorCauseCode> for u16 {
    fn from(value: SctpErrorCauseCode) -> Self {
        value.raw()
    }
}

/// Return the SCTP error-cause padding length implied by a declared cause length.
pub const fn sctp_error_cause_padding_len(declared_length: usize) -> usize {
    (SCTP_ALIGNMENT - (declared_length % SCTP_ALIGNMENT)) % SCTP_ALIGNMENT
}

/// Return a declared SCTP error-cause length rounded up to the next boundary.
pub const fn sctp_error_cause_padded_len(declared_length: usize) -> usize {
    declared_length + sctp_error_cause_padding_len(declared_length)
}

/// Decode a byte sequence of SCTP error causes into raw-preserving cause models.
pub fn decode_causes(bytes: impl AsRef<[u8]>) -> Result<Vec<SctpErrorCause>> {
    let bytes = bytes.as_ref();
    let mut causes = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() {
        let available = bytes.len() - offset;
        if available < SCTP_ERROR_CAUSE_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "sctp.error_cause.header",
                SCTP_ERROR_CAUSE_HEADER_LEN,
                available,
            ));
        }

        let cause_code = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let declared_length = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        let declared_length_usize = usize::from(declared_length);
        if declared_length_usize < SCTP_ERROR_CAUSE_HEADER_LEN {
            return Err(CrafterError::invalid_field_value(
                "sctp.error_cause.length",
                "declared length must be at least 4 bytes",
            ));
        }

        let padded_length = sctp_error_cause_padded_len(declared_length_usize);
        if padded_length > available {
            return Err(CrafterError::buffer_too_short(
                "sctp.error_cause",
                padded_length,
                available,
            ));
        }

        let info_start = offset + SCTP_ERROR_CAUSE_HEADER_LEN;
        let info_end = offset + declared_length_usize;
        let padding_end = offset + padded_length;
        causes.push(SctpErrorCause::from_preserved_parts(
            cause_code,
            declared_length,
            bytes[info_start..info_end].to_vec(),
            bytes[info_end..padding_end].to_vec(),
        ));
        offset += padded_length;
    }

    Ok(causes)
}

/// Append one SCTP error-cause envelope to `out`.
pub fn encode_cause(cause: &SctpErrorCause, out: &mut Vec<u8>) -> Result<()> {
    let raw = cause.raw_cause();
    let declared_length = raw.explicit_declared_length().map_or_else(
        || {
            let declared_length = SCTP_ERROR_CAUSE_HEADER_LEN
                .checked_add(raw.info_len())
                .ok_or_else(|| {
                    CrafterError::invalid_field_value("sctp.error_cause.length", "length overflow")
                })?;
            u16::try_from(declared_length).map_err(|_| {
                CrafterError::invalid_field_value(
                    "sctp.error_cause.length",
                    "length must fit in two bytes",
                )
            })
        },
        Ok,
    )?;

    out.extend_from_slice(&raw.cause_code_value().to_be_bytes());
    out.extend_from_slice(&declared_length.to_be_bytes());
    out.extend_from_slice(raw.info());

    if raw.padding().is_empty() {
        out.resize(
            out.len() + sctp_error_cause_padding_len(usize::from(declared_length)),
            0,
        );
    } else {
        out.extend_from_slice(raw.padding());
    }

    Ok(())
}

/// Append a sequence of SCTP error-cause envelopes to `out`.
pub fn encode_causes(causes: &[SctpErrorCause], out: &mut Vec<u8>) -> Result<()> {
    for cause in causes {
        encode_cause(cause, out)?;
    }
    Ok(())
}

/// Byte-preserving storage for one SCTP error-cause envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpRawErrorCause {
    cause_code: SctpErrorCauseCode,
    declared_length: Option<u16>,
    info: Vec<u8>,
    padding: Vec<u8>,
}

impl SctpRawErrorCause {
    /// Construct an error-cause envelope with an auto-derived declared length.
    pub fn new(cause_code: impl Into<SctpErrorCauseCode>, info: impl Into<Vec<u8>>) -> Self {
        Self {
            cause_code: cause_code.into(),
            declared_length: None,
            info: info.into(),
            padding: Vec::new(),
        }
    }

    /// Construct an error-cause envelope from observed or caller-preserved wire parts.
    pub fn from_raw_parts(
        cause_code: impl Into<SctpErrorCauseCode>,
        info: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            padding: padding.into(),
            ..Self::new(cause_code, info)
        }
    }

    /// Construct an error-cause envelope with an explicit declared length override.
    pub fn from_preserved_parts(
        cause_code: impl Into<SctpErrorCauseCode>,
        declared_length: u16,
        info: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            cause_code: cause_code.into(),
            declared_length: Some(declared_length),
            info: info.into(),
            padding: padding.into(),
        }
    }

    /// Replace the raw error-cause code.
    pub fn with_cause_code(mut self, cause_code: impl Into<SctpErrorCauseCode>) -> Self {
        self.cause_code = cause_code.into();
        self
    }

    /// Preserve an explicit error-cause length field value.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.declared_length = Some(declared_length);
        self
    }

    /// Compatibility alias for preserving an explicit error-cause length.
    pub fn with_length(self, length: u16) -> Self {
        self.with_declared_length(length)
    }

    /// Return to auto-derived error-cause length behavior.
    pub fn with_auto_length(mut self) -> Self {
        self.declared_length = None;
        self
    }

    /// Replace the cause-specific information bytes.
    pub fn with_info(mut self, info: impl Into<Vec<u8>>) -> Self {
        self.info = info.into();
        self
    }

    /// Compatibility alias for replacing cause-specific information bytes.
    pub fn with_value(self, value: impl Into<Vec<u8>>) -> Self {
        self.with_info(value)
    }

    /// Replace the transmitted padding bytes.
    pub fn with_padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
        self.padding = padding.into();
        self
    }

    /// SCTP error-cause code.
    pub const fn cause_code(&self) -> SctpErrorCauseCode {
        self.cause_code
    }

    /// Raw SCTP error-cause code.
    pub const fn cause_code_value(&self) -> u16 {
        self.cause_code.raw()
    }

    /// Declared error-cause length, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.declared_length
            .map(usize::from)
            .unwrap_or_else(|| SCTP_ERROR_CAUSE_HEADER_LEN + self.info.len())
    }

    /// Compatibility alias for the declared error-cause length.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared error-cause length override, if one is preserved.
    pub const fn explicit_declared_length(&self) -> Option<u16> {
        self.declared_length
    }

    /// Compatibility alias for the explicit declared error-cause length.
    pub const fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Cause-specific information bytes, excluding padding.
    pub fn info(&self) -> &[u8] {
        &self.info
    }

    /// Compatibility alias for cause-specific information bytes.
    pub fn value(&self) -> &[u8] {
        self.info()
    }

    /// Transmitted error-cause padding bytes, excluded from information bytes.
    pub fn padding(&self) -> &[u8] {
        &self.padding
    }

    /// Cause-specific information length, excluding padding.
    pub fn info_len(&self) -> usize {
        self.info.len()
    }

    /// Compatibility alias for cause-specific information length.
    pub fn value_len(&self) -> usize {
        self.info_len()
    }

    /// Transmitted error-cause padding length.
    pub fn padding_len(&self) -> usize {
        self.padding.len()
    }

    /// Protocol padding length implied by the declared error-cause length.
    pub fn required_padding_len(&self) -> usize {
        sctp_error_cause_padding_len(self.declared_length())
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        if self.padding.is_empty() {
            self.required_padding_len()
        } else {
            self.padding.len()
        }
    }

    /// Declared error-cause length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        sctp_error_cause_padded_len(self.declared_length())
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        SCTP_ERROR_CAUSE_HEADER_LEN + self.info.len() + self.encoded_padding_len()
    }
}

macro_rules! define_sctp_typed_error_cause_structs {
    ($($name:ident),+ $(,)?) => {
        $(
            /// Raw-envelope storage for a typed SCTP error-cause variant.
            #[derive(Debug, Clone, PartialEq, Eq)]
            pub struct $name {
                raw: SctpRawErrorCause,
            }
        )+
    };
}

define_sctp_typed_error_cause_structs!(
    SctpInvalidStreamIdentifierCause,
    SctpMissingMandatoryParameterCause,
    SctpStaleCookieCause,
    SctpOutOfResourceCause,
    SctpUnresolvableAddressCause,
    SctpUnrecognizedChunkTypeCause,
    SctpInvalidMandatoryParameterCause,
    SctpUnrecognizedParametersCause,
    SctpNoUserDataCause,
    SctpCookieReceivedWhileShuttingDownCause,
    SctpRestartWithNewAddressesCause,
    SctpUserInitiatedAbortCause,
    SctpProtocolViolationCause,
);

/// Raw-envelope storage for an untyped SCTP error-cause code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SctpUnknownErrorCause {
    raw: SctpRawErrorCause,
}

impl SctpUnknownErrorCause {
    /// Construct an unknown error cause with an auto-derived declared length.
    pub fn new(cause_code: u16, info: impl Into<Vec<u8>>) -> Self {
        Self {
            raw: SctpRawErrorCause::new(cause_code, info),
        }
    }

    /// Construct an unknown error cause from raw wire parts.
    pub fn from_raw_parts(
        cause_code: u16,
        info: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawErrorCause::from_raw_parts(cause_code, info, padding),
        }
    }

    /// Construct an unknown error cause with an explicit declared length override.
    pub fn from_preserved_parts(
        cause_code: u16,
        declared_length: u16,
        info: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            raw: SctpRawErrorCause::from_preserved_parts(
                cause_code,
                declared_length,
                info,
                padding,
            ),
        }
    }

    /// Replace the raw error-cause code.
    pub fn with_cause_code(mut self, cause_code: u16) -> Self {
        self.raw = self.raw.with_cause_code(cause_code);
        self
    }

    /// Preserve an explicit error-cause length field value.
    pub fn with_declared_length(mut self, declared_length: u16) -> Self {
        self.raw = self.raw.with_declared_length(declared_length);
        self
    }

    /// Compatibility alias for preserving an explicit error-cause length.
    pub fn with_length(self, length: u16) -> Self {
        self.with_declared_length(length)
    }

    /// Replace the cause-specific information bytes.
    pub fn with_info(mut self, info: impl Into<Vec<u8>>) -> Self {
        self.raw = self.raw.with_info(info);
        self
    }

    /// Compatibility alias for replacing cause-specific information bytes.
    pub fn with_value(self, value: impl Into<Vec<u8>>) -> Self {
        self.with_info(value)
    }

    /// Replace the transmitted padding bytes.
    pub fn with_padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
        self.raw = self.raw.with_padding(padding);
        self
    }

    /// Borrow the preserved raw error-cause envelope.
    pub fn raw_cause(&self) -> &SctpRawErrorCause {
        &self.raw
    }

    /// SCTP error-cause code.
    pub const fn cause_code(&self) -> SctpErrorCauseCode {
        self.raw.cause_code()
    }

    /// Raw SCTP error-cause code.
    pub const fn cause_code_value(&self) -> u16 {
        self.raw.cause_code_value()
    }

    /// Declared error-cause length, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.raw.declared_length()
    }

    /// Compatibility alias for the declared error-cause length.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared error-cause length override, if one is preserved.
    pub const fn explicit_declared_length(&self) -> Option<u16> {
        self.raw.explicit_declared_length()
    }

    /// Compatibility alias for the explicit declared error-cause length.
    pub const fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Cause-specific information bytes, excluding padding.
    pub fn info(&self) -> &[u8] {
        self.raw.info()
    }

    /// Compatibility alias for cause-specific information bytes.
    pub fn value(&self) -> &[u8] {
        self.info()
    }

    /// Transmitted error-cause padding bytes, excluded from information bytes.
    pub fn padding(&self) -> &[u8] {
        self.raw.padding()
    }

    /// Cause-specific information length, excluding padding.
    pub fn info_len(&self) -> usize {
        self.raw.info_len()
    }

    /// Compatibility alias for cause-specific information length.
    pub fn value_len(&self) -> usize {
        self.info_len()
    }

    /// Transmitted error-cause padding length.
    pub fn padding_len(&self) -> usize {
        self.raw.padding_len()
    }

    /// Protocol padding length implied by the declared error-cause length.
    pub fn required_padding_len(&self) -> usize {
        self.raw.required_padding_len()
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        self.raw.encoded_padding_len()
    }

    /// Declared error-cause length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        self.raw.padded_declared_len()
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        self.raw.encoded_len()
    }
}

/// SCTP error cause with typed variants and raw-preserving fallback storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SctpErrorCause {
    /// Invalid Stream Identifier cause.
    InvalidStreamIdentifier(SctpInvalidStreamIdentifierCause),
    /// Missing Mandatory Parameter cause.
    MissingMandatoryParameter(SctpMissingMandatoryParameterCause),
    /// Stale Cookie cause.
    StaleCookie(SctpStaleCookieCause),
    /// Out of Resource cause.
    OutOfResource(SctpOutOfResourceCause),
    /// Unresolvable Address cause.
    UnresolvableAddress(SctpUnresolvableAddressCause),
    /// Unrecognized Chunk Type cause.
    UnrecognizedChunkType(SctpUnrecognizedChunkTypeCause),
    /// Invalid Mandatory Parameter cause.
    InvalidMandatoryParameter(SctpInvalidMandatoryParameterCause),
    /// Unrecognized Parameters cause.
    UnrecognizedParameters(SctpUnrecognizedParametersCause),
    /// No User Data cause.
    NoUserData(SctpNoUserDataCause),
    /// Cookie Received While Shutting Down cause.
    CookieReceivedWhileShuttingDown(SctpCookieReceivedWhileShuttingDownCause),
    /// Restart of an Association with New Addresses cause.
    RestartWithNewAddresses(SctpRestartWithNewAddressesCause),
    /// User-Initiated Abort cause.
    UserInitiatedAbort(SctpUserInitiatedAbortCause),
    /// Protocol Violation cause.
    ProtocolViolation(SctpProtocolViolationCause),
    /// Unknown, reserved, unassigned, extension, private, or future cause.
    Unknown(SctpUnknownErrorCause),
}

macro_rules! impl_sctp_typed_error_cause {
    ($name:ident, $variant:ident, $code_const:ident) => {
        impl $name {
            /// Construct the cause with an auto-derived declared length.
            pub fn new(info: impl Into<Vec<u8>>) -> Self {
                Self {
                    raw: SctpRawErrorCause::new($code_const, info),
                }
            }

            /// Construct the cause from raw wire parts.
            pub fn from_raw_parts(info: impl Into<Vec<u8>>, padding: impl Into<Vec<u8>>) -> Self {
                Self {
                    raw: SctpRawErrorCause::from_raw_parts($code_const, info, padding),
                }
            }

            /// Construct the cause with an explicit declared length override.
            pub fn from_preserved_parts(
                declared_length: u16,
                info: impl Into<Vec<u8>>,
                padding: impl Into<Vec<u8>>,
            ) -> Self {
                Self {
                    raw: SctpRawErrorCause::from_preserved_parts(
                        $code_const,
                        declared_length,
                        info,
                        padding,
                    ),
                }
            }

            /// Preserve an explicit error-cause length field value.
            pub fn with_declared_length(mut self, declared_length: u16) -> Self {
                self.raw = self.raw.with_declared_length(declared_length);
                self
            }

            /// Compatibility alias for preserving an explicit error-cause length.
            pub fn with_length(self, length: u16) -> Self {
                self.with_declared_length(length)
            }

            /// Replace the cause-specific information bytes.
            pub fn with_info(mut self, info: impl Into<Vec<u8>>) -> Self {
                self.raw = self.raw.with_info(info);
                self
            }

            /// Compatibility alias for replacing cause-specific information bytes.
            pub fn with_value(self, value: impl Into<Vec<u8>>) -> Self {
                self.with_info(value)
            }

            /// Replace the transmitted padding bytes.
            pub fn with_padding(mut self, padding: impl Into<Vec<u8>>) -> Self {
                self.raw = self.raw.with_padding(padding);
                self
            }

            /// Borrow the preserved raw error-cause envelope.
            pub fn raw_cause(&self) -> &SctpRawErrorCause {
                &self.raw
            }

            /// SCTP error-cause code.
            pub const fn cause_code(&self) -> SctpErrorCauseCode {
                self.raw.cause_code()
            }

            /// Raw SCTP error-cause code.
            pub const fn cause_code_value(&self) -> u16 {
                self.raw.cause_code_value()
            }

            /// Declared error-cause length, using the explicit value when present.
            pub fn declared_length(&self) -> usize {
                self.raw.declared_length()
            }

            /// Compatibility alias for the declared error-cause length.
            pub fn length(&self) -> usize {
                self.declared_length()
            }

            /// Explicit declared error-cause length override, if one is preserved.
            pub const fn explicit_declared_length(&self) -> Option<u16> {
                self.raw.explicit_declared_length()
            }

            /// Compatibility alias for the explicit declared error-cause length.
            pub const fn explicit_length(&self) -> Option<u16> {
                self.explicit_declared_length()
            }

            /// Cause-specific information bytes, excluding padding.
            pub fn info(&self) -> &[u8] {
                self.raw.info()
            }

            /// Compatibility alias for cause-specific information bytes.
            pub fn value(&self) -> &[u8] {
                self.info()
            }

            /// Transmitted error-cause padding bytes, excluded from information bytes.
            pub fn padding(&self) -> &[u8] {
                self.raw.padding()
            }

            /// Cause-specific information length, excluding padding.
            pub fn info_len(&self) -> usize {
                self.raw.info_len()
            }

            /// Compatibility alias for cause-specific information length.
            pub fn value_len(&self) -> usize {
                self.info_len()
            }

            /// Transmitted error-cause padding length.
            pub fn padding_len(&self) -> usize {
                self.raw.padding_len()
            }

            /// Protocol padding length implied by the declared error-cause length.
            pub fn required_padding_len(&self) -> usize {
                self.raw.required_padding_len()
            }

            /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
            pub fn encoded_padding_len(&self) -> usize {
                self.raw.encoded_padding_len()
            }

            /// Declared error-cause length rounded up to the next four-octet boundary.
            pub fn padded_declared_len(&self) -> usize {
                self.raw.padded_declared_len()
            }

            /// Number of bytes encoded for this envelope, including padding.
            pub fn encoded_len(&self) -> usize {
                self.raw.encoded_len()
            }
        }

        impl From<$name> for SctpErrorCause {
            fn from(value: $name) -> Self {
                Self::$variant(value)
            }
        }
    };
}

impl_sctp_typed_error_cause!(
    SctpInvalidStreamIdentifierCause,
    InvalidStreamIdentifier,
    SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER
);
impl_sctp_typed_error_cause!(
    SctpMissingMandatoryParameterCause,
    MissingMandatoryParameter,
    SCTP_CAUSE_CODE_MISSING_MANDATORY_PARAMETER
);
impl_sctp_typed_error_cause!(
    SctpStaleCookieCause,
    StaleCookie,
    SCTP_CAUSE_CODE_STALE_COOKIE
);
impl_sctp_typed_error_cause!(
    SctpOutOfResourceCause,
    OutOfResource,
    SCTP_CAUSE_CODE_OUT_OF_RESOURCE
);
impl_sctp_typed_error_cause!(
    SctpUnresolvableAddressCause,
    UnresolvableAddress,
    SCTP_CAUSE_CODE_UNRESOLVABLE_ADDRESS
);
impl_sctp_typed_error_cause!(
    SctpUnrecognizedChunkTypeCause,
    UnrecognizedChunkType,
    SCTP_CAUSE_CODE_UNRECOGNIZED_CHUNK_TYPE
);
impl_sctp_typed_error_cause!(
    SctpInvalidMandatoryParameterCause,
    InvalidMandatoryParameter,
    SCTP_CAUSE_CODE_INVALID_MANDATORY_PARAMETER
);
impl_sctp_typed_error_cause!(
    SctpUnrecognizedParametersCause,
    UnrecognizedParameters,
    SCTP_CAUSE_CODE_UNRECOGNIZED_PARAMETERS
);
impl_sctp_typed_error_cause!(
    SctpNoUserDataCause,
    NoUserData,
    SCTP_CAUSE_CODE_NO_USER_DATA
);
impl_sctp_typed_error_cause!(
    SctpCookieReceivedWhileShuttingDownCause,
    CookieReceivedWhileShuttingDown,
    SCTP_CAUSE_CODE_COOKIE_RECEIVED_WHILE_SHUTTING_DOWN
);
impl_sctp_typed_error_cause!(
    SctpRestartWithNewAddressesCause,
    RestartWithNewAddresses,
    SCTP_CAUSE_CODE_RESTART_WITH_NEW_ADDRESSES
);
impl_sctp_typed_error_cause!(
    SctpUserInitiatedAbortCause,
    UserInitiatedAbort,
    SCTP_CAUSE_CODE_USER_INITIATED_ABORT
);
impl_sctp_typed_error_cause!(
    SctpProtocolViolationCause,
    ProtocolViolation,
    SCTP_CAUSE_CODE_PROTOCOL_VIOLATION
);

impl From<SctpUnknownErrorCause> for SctpErrorCause {
    fn from(value: SctpUnknownErrorCause) -> Self {
        Self::Unknown(value)
    }
}

impl From<SctpRawErrorCause> for SctpErrorCause {
    fn from(raw: SctpRawErrorCause) -> Self {
        match raw.cause_code_value() {
            SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER => {
                Self::InvalidStreamIdentifier(SctpInvalidStreamIdentifierCause { raw })
            }
            SCTP_CAUSE_CODE_MISSING_MANDATORY_PARAMETER => {
                Self::MissingMandatoryParameter(SctpMissingMandatoryParameterCause { raw })
            }
            SCTP_CAUSE_CODE_STALE_COOKIE => Self::StaleCookie(SctpStaleCookieCause { raw }),
            SCTP_CAUSE_CODE_OUT_OF_RESOURCE => Self::OutOfResource(SctpOutOfResourceCause { raw }),
            SCTP_CAUSE_CODE_UNRESOLVABLE_ADDRESS => {
                Self::UnresolvableAddress(SctpUnresolvableAddressCause { raw })
            }
            SCTP_CAUSE_CODE_UNRECOGNIZED_CHUNK_TYPE => {
                Self::UnrecognizedChunkType(SctpUnrecognizedChunkTypeCause { raw })
            }
            SCTP_CAUSE_CODE_INVALID_MANDATORY_PARAMETER => {
                Self::InvalidMandatoryParameter(SctpInvalidMandatoryParameterCause { raw })
            }
            SCTP_CAUSE_CODE_UNRECOGNIZED_PARAMETERS => {
                Self::UnrecognizedParameters(SctpUnrecognizedParametersCause { raw })
            }
            SCTP_CAUSE_CODE_NO_USER_DATA => Self::NoUserData(SctpNoUserDataCause { raw }),
            SCTP_CAUSE_CODE_COOKIE_RECEIVED_WHILE_SHUTTING_DOWN => {
                Self::CookieReceivedWhileShuttingDown(SctpCookieReceivedWhileShuttingDownCause {
                    raw,
                })
            }
            SCTP_CAUSE_CODE_RESTART_WITH_NEW_ADDRESSES => {
                Self::RestartWithNewAddresses(SctpRestartWithNewAddressesCause { raw })
            }
            SCTP_CAUSE_CODE_USER_INITIATED_ABORT => {
                Self::UserInitiatedAbort(SctpUserInitiatedAbortCause { raw })
            }
            SCTP_CAUSE_CODE_PROTOCOL_VIOLATION => {
                Self::ProtocolViolation(SctpProtocolViolationCause { raw })
            }
            _ => Self::Unknown(SctpUnknownErrorCause { raw }),
        }
    }
}

impl SctpErrorCause {
    /// Construct an error cause from raw wire parts, dispatching known codes.
    pub fn from_raw_parts(
        cause_code: u16,
        info: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        SctpRawErrorCause::from_raw_parts(cause_code, info, padding).into()
    }

    /// Construct an error cause with an explicit declared length, dispatching known codes.
    pub fn from_preserved_parts(
        cause_code: u16,
        declared_length: u16,
        info: impl Into<Vec<u8>>,
        padding: impl Into<Vec<u8>>,
    ) -> Self {
        SctpRawErrorCause::from_preserved_parts(cause_code, declared_length, info, padding).into()
    }

    /// Construct an unknown error cause with an auto-derived declared length.
    pub fn unknown(cause_code: u16, info: impl Into<Vec<u8>>) -> Self {
        SctpUnknownErrorCause::new(cause_code, info).into()
    }

    /// Borrow the preserved raw error-cause envelope.
    pub fn raw_cause(&self) -> &SctpRawErrorCause {
        match self {
            Self::InvalidStreamIdentifier(value) => value.raw_cause(),
            Self::MissingMandatoryParameter(value) => value.raw_cause(),
            Self::StaleCookie(value) => value.raw_cause(),
            Self::OutOfResource(value) => value.raw_cause(),
            Self::UnresolvableAddress(value) => value.raw_cause(),
            Self::UnrecognizedChunkType(value) => value.raw_cause(),
            Self::InvalidMandatoryParameter(value) => value.raw_cause(),
            Self::UnrecognizedParameters(value) => value.raw_cause(),
            Self::NoUserData(value) => value.raw_cause(),
            Self::CookieReceivedWhileShuttingDown(value) => value.raw_cause(),
            Self::RestartWithNewAddresses(value) => value.raw_cause(),
            Self::UserInitiatedAbort(value) => value.raw_cause(),
            Self::ProtocolViolation(value) => value.raw_cause(),
            Self::Unknown(value) => value.raw_cause(),
        }
    }

    /// SCTP error-cause code.
    pub fn cause_code(&self) -> SctpErrorCauseCode {
        self.raw_cause().cause_code()
    }

    /// Raw SCTP error-cause code.
    pub fn cause_code_value(&self) -> u16 {
        self.raw_cause().cause_code_value()
    }

    /// Declared error-cause length, using the explicit value when present.
    pub fn declared_length(&self) -> usize {
        self.raw_cause().declared_length()
    }

    /// Compatibility alias for the declared error-cause length.
    pub fn length(&self) -> usize {
        self.declared_length()
    }

    /// Explicit declared error-cause length override, if one is preserved.
    pub fn explicit_declared_length(&self) -> Option<u16> {
        self.raw_cause().explicit_declared_length()
    }

    /// Compatibility alias for the explicit declared error-cause length.
    pub fn explicit_length(&self) -> Option<u16> {
        self.explicit_declared_length()
    }

    /// Cause-specific information bytes, excluding padding.
    pub fn info(&self) -> &[u8] {
        self.raw_cause().info()
    }

    /// Compatibility alias for cause-specific information bytes.
    pub fn value(&self) -> &[u8] {
        self.info()
    }

    /// Transmitted error-cause padding bytes, excluded from information bytes.
    pub fn padding(&self) -> &[u8] {
        self.raw_cause().padding()
    }

    /// Cause-specific information length, excluding padding.
    pub fn info_len(&self) -> usize {
        self.raw_cause().info_len()
    }

    /// Compatibility alias for cause-specific information length.
    pub fn value_len(&self) -> usize {
        self.info_len()
    }

    /// Transmitted error-cause padding length.
    pub fn padding_len(&self) -> usize {
        self.raw_cause().padding_len()
    }

    /// Protocol padding length implied by the declared error-cause length.
    pub fn required_padding_len(&self) -> usize {
        self.raw_cause().required_padding_len()
    }

    /// Padding length an encoder would emit: preserved bytes, or auto zero padding.
    pub fn encoded_padding_len(&self) -> usize {
        self.raw_cause().encoded_padding_len()
    }

    /// Declared error-cause length rounded up to the next four-octet boundary.
    pub fn padded_declared_len(&self) -> usize {
        self.raw_cause().padded_declared_len()
    }

    /// Number of bytes encoded for this envelope, including padding.
    pub fn encoded_len(&self) -> usize {
        self.raw_cause().encoded_len()
    }
}

#[cfg(test)]
mod tests {
    use super::super::constants::{
        SCTP_CAUSE_CODE_DELETE_LAST_REMAINING_IP_ADDRESS,
        SCTP_CAUSE_CODE_UNSUPPORTED_HMAC_IDENTIFIER,
    };
    use super::*;

    #[test]
    fn sctp_cause_model_typed_variants_keep_common_wire_fields() {
        let cause = SctpInvalidStreamIdentifierCause::new([0x00, 0x07]).with_padding([0xaa, 0xbb]);

        assert_eq!(
            cause.cause_code(),
            SctpErrorCauseCode::new(SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER)
        );
        assert_eq!(
            cause.cause_code_value(),
            SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER
        );
        assert_eq!(cause.length(), SCTP_ERROR_CAUSE_HEADER_LEN + 2);
        assert_eq!(cause.explicit_length(), None);
        assert_eq!(cause.info(), &[0x00, 0x07]);
        assert_eq!(cause.value(), &[0x00, 0x07]);
        assert_eq!(cause.info_len(), 2);
        assert_eq!(cause.padding(), &[0xaa, 0xbb]);
        assert_eq!(cause.padding_len(), 2);
        assert_eq!(cause.required_padding_len(), 2);
        assert_eq!(cause.encoded_padding_len(), 2);
        assert_eq!(cause.encoded_len(), SCTP_ERROR_CAUSE_HEADER_LEN + 4);

        let enum_cause = SctpErrorCause::from(cause);
        assert!(matches!(
            enum_cause,
            SctpErrorCause::InvalidStreamIdentifier(_)
        ));
        assert_eq!(enum_cause.value(), &[0x00, 0x07]);
        assert_eq!(enum_cause.padding(), &[0xaa, 0xbb]);
    }

    #[test]
    fn sctp_cause_model_preserves_explicit_length_value_and_padding() {
        let cause = SctpProtocolViolationCause::from_preserved_parts(4, [0xde, 0xad, 0xbe], [0xef]);

        assert_eq!(cause.cause_code_value(), SCTP_CAUSE_CODE_PROTOCOL_VIOLATION);
        assert_eq!(cause.length(), 4);
        assert_eq!(cause.explicit_length(), Some(4));
        assert_eq!(cause.info(), &[0xde, 0xad, 0xbe]);
        assert_eq!(cause.padding(), &[0xef]);
        assert_eq!(cause.required_padding_len(), 0);
        assert_eq!(cause.encoded_padding_len(), 1);
        assert_eq!(cause.encoded_len(), SCTP_ERROR_CAUSE_HEADER_LEN + 4);

        let raw = cause.raw_cause().clone().with_auto_length();
        assert_eq!(raw.length(), SCTP_ERROR_CAUSE_HEADER_LEN + 3);
        assert_eq!(raw.required_padding_len(), 1);
        assert_eq!(raw.padded_declared_len(), SCTP_ERROR_CAUSE_HEADER_LEN + 4);
    }

    #[test]
    fn sctp_cause_model_dispatches_core_cause_codes() {
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER, [], []),
            SctpErrorCause::InvalidStreamIdentifier(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_MISSING_MANDATORY_PARAMETER, [], []),
            SctpErrorCause::MissingMandatoryParameter(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_STALE_COOKIE, [], []),
            SctpErrorCause::StaleCookie(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_OUT_OF_RESOURCE, [], []),
            SctpErrorCause::OutOfResource(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_UNRESOLVABLE_ADDRESS, [], []),
            SctpErrorCause::UnresolvableAddress(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_UNRECOGNIZED_CHUNK_TYPE, [], []),
            SctpErrorCause::UnrecognizedChunkType(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_INVALID_MANDATORY_PARAMETER, [], []),
            SctpErrorCause::InvalidMandatoryParameter(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_UNRECOGNIZED_PARAMETERS, [], []),
            SctpErrorCause::UnrecognizedParameters(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_NO_USER_DATA, [], []),
            SctpErrorCause::NoUserData(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(
                SCTP_CAUSE_CODE_COOKIE_RECEIVED_WHILE_SHUTTING_DOWN,
                [],
                [],
            ),
            SctpErrorCause::CookieReceivedWhileShuttingDown(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_RESTART_WITH_NEW_ADDRESSES, [], []),
            SctpErrorCause::RestartWithNewAddresses(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_USER_INITIATED_ABORT, [], []),
            SctpErrorCause::UserInitiatedAbort(_)
        ));
        assert!(matches!(
            SctpErrorCause::from_raw_parts(SCTP_CAUSE_CODE_PROTOCOL_VIOLATION, [], []),
            SctpErrorCause::ProtocolViolation(_)
        ));
    }

    #[test]
    fn sctp_cause_model_preserves_unknown_extension_and_future_codes() {
        for cause_code in [
            0,
            14,
            SCTP_CAUSE_CODE_DELETE_LAST_REMAINING_IP_ADDRESS,
            SCTP_CAUSE_CODE_UNSUPPORTED_HMAC_IDENTIFIER,
            0xffff,
        ] {
            let cause =
                SctpErrorCause::from_preserved_parts(cause_code, 7, [0xde, 0xad, 0xbe], [0xcc]);
            let SctpErrorCause::Unknown(unknown) = cause else {
                panic!("cause code {cause_code} must remain unknown");
            };

            assert_eq!(unknown.cause_code_value(), cause_code);
            assert_eq!(unknown.length(), 7);
            assert_eq!(unknown.explicit_length(), Some(7));
            assert_eq!(unknown.info(), &[0xde, 0xad, 0xbe]);
            assert_eq!(unknown.padding(), &[0xcc]);
            assert_eq!(unknown.required_padding_len(), 1);
            assert_eq!(unknown.encoded_len(), SCTP_ERROR_CAUSE_HEADER_LEN + 4);
        }
    }

    #[test]
    fn sctp_decode_causes_walks_declared_lengths_and_preserves_padding() -> Result<()> {
        let bytes = [
            0x00, 0x01, 0x00, 0x06, 0x00, 0x07, 0xaa, 0xbb, 0x00, 0x0d, 0x00, 0x04, 0x00, 0xa0,
            0x00, 0x05, 0xde, 0x00, 0x00, 0x00,
        ];

        let causes = decode_causes(bytes)?;
        assert_eq!(causes.len(), 3);

        let SctpErrorCause::InvalidStreamIdentifier(invalid_stream) = &causes[0] else {
            panic!("expected Invalid Stream Identifier cause");
        };
        assert_eq!(
            invalid_stream.cause_code_value(),
            SCTP_CAUSE_CODE_INVALID_STREAM_IDENTIFIER
        );
        assert_eq!(invalid_stream.length(), 6);
        assert_eq!(invalid_stream.explicit_length(), Some(6));
        assert_eq!(invalid_stream.info(), &[0x00, 0x07]);
        assert_eq!(invalid_stream.padding(), &[0xaa, 0xbb]);
        assert_eq!(invalid_stream.encoded_len(), 8);

        let SctpErrorCause::ProtocolViolation(protocol_violation) = &causes[1] else {
            panic!("expected Protocol Violation cause");
        };
        assert_eq!(
            protocol_violation.cause_code_value(),
            SCTP_CAUSE_CODE_PROTOCOL_VIOLATION
        );
        assert_eq!(protocol_violation.length(), 4);
        assert_eq!(protocol_violation.info(), &[]);
        assert_eq!(protocol_violation.padding(), &[]);

        let SctpErrorCause::Unknown(unknown) = &causes[2] else {
            panic!("extension cause must remain unknown until typed");
        };
        assert_eq!(
            unknown.cause_code_value(),
            SCTP_CAUSE_CODE_DELETE_LAST_REMAINING_IP_ADDRESS
        );
        assert_eq!(unknown.length(), 5);
        assert_eq!(unknown.info(), &[0xde]);
        assert_eq!(unknown.padding(), &[0x00, 0x00, 0x00]);

        Ok(())
    }

    #[test]
    fn sctp_decode_causes_preserves_unknown_and_future_codes() -> Result<()> {
        let bytes = [
            0xbe, 0xef, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff, 0x00, 0x04,
        ];

        let causes = decode_causes(bytes)?;
        assert_eq!(causes.len(), 2);

        let SctpErrorCause::Unknown(first) = &causes[0] else {
            panic!("future cause must remain unknown");
        };
        assert_eq!(first.cause_code_value(), 0xbeef);
        assert_eq!(first.info(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(first.padding(), &[]);

        let SctpErrorCause::Unknown(second) = &causes[1] else {
            panic!("reserved future cause must remain unknown");
        };
        assert_eq!(second.cause_code_value(), 0xffff);
        assert_eq!(second.info(), &[]);
        assert_eq!(second.padding(), &[]);

        Ok(())
    }

    #[test]
    fn sctp_malformed_causes_reject_short_header_and_invalid_length() {
        assert_eq!(
            decode_causes([0x00, 0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "sctp.error_cause.header",
                SCTP_ERROR_CAUSE_HEADER_LEN,
                3,
            )
        );

        assert_eq!(
            decode_causes([0x00, 0x01, 0x00, 0x03]).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.error_cause.length",
                "declared length must be at least 4 bytes",
            )
        );
    }

    #[test]
    fn sctp_malformed_causes_reject_declared_length_or_padding_overrun() {
        assert_eq!(
            decode_causes([0x00, 0x01, 0x00, 0x05, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("sctp.error_cause", 8, 5)
        );

        assert_eq!(
            decode_causes([0x00, 0x01, 0x00, 0x04, 0xff]).unwrap_err(),
            CrafterError::buffer_too_short(
                "sctp.error_cause.header",
                SCTP_ERROR_CAUSE_HEADER_LEN,
                1,
            )
        );
    }

    #[test]
    fn sctp_encode_causes_writes_envelopes_and_auto_zero_padding() -> Result<()> {
        let causes = vec![
            SctpErrorCause::from(SctpInvalidStreamIdentifierCause::new([0x00, 0x07])),
            SctpErrorCause::unknown(0xbeef, [0xde, 0xad, 0xbe, 0xef]),
            SctpErrorCause::from(SctpProtocolViolationCause::new([])),
        ];
        let mut bytes = Vec::new();

        encode_causes(&causes, &mut bytes)?;

        assert_eq!(
            bytes,
            [
                0x00, 0x01, 0x00, 0x06, 0x00, 0x07, 0x00, 0x00, 0xbe, 0xef, 0x00, 0x08, 0xde, 0xad,
                0xbe, 0xef, 0x00, 0x0d, 0x00, 0x04,
            ]
        );

        let decoded = decode_causes(&bytes)?;
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].padding(), &[0x00, 0x00]);
        assert_eq!(decoded[1].padding(), &[]);
        assert_eq!(decoded[2].padding(), &[]);

        Ok(())
    }

    #[test]
    fn sctp_encode_causes_preserves_explicit_malformed_length_and_padding() -> Result<()> {
        let cause = SctpErrorCause::from_preserved_parts(
            SCTP_CAUSE_CODE_PROTOCOL_VIOLATION,
            4,
            [0xde, 0xad, 0xbe],
            [0xef],
        );
        let mut bytes = Vec::new();

        encode_cause(&cause, &mut bytes)?;

        assert_eq!(bytes, [0x00, 0x0d, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef]);

        Ok(())
    }

    #[test]
    fn sctp_encode_causes_rejects_auto_declared_length_overflow() {
        let oversized_info = vec![0; usize::from(u16::MAX) - SCTP_ERROR_CAUSE_HEADER_LEN + 1];
        let cause = SctpErrorCause::unknown(0xbeef, oversized_info);
        let mut bytes = Vec::new();

        assert_eq!(
            encode_cause(&cause, &mut bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                "sctp.error_cause.length",
                "length must fit in two bytes",
            )
        );
        assert!(bytes.is_empty());
    }

    #[test]
    fn sctp_cause_model_code_and_padding_helpers_are_raw_preserving() {
        let code = SctpErrorCauseCode::from_u16(0xbeef);
        assert_eq!(code.raw(), 0xbeef);
        assert_eq!(code.as_u16(), 0xbeef);
        assert_eq!(u16::from(code), 0xbeef);
        assert_eq!(SctpErrorCauseCode::from(0xbeef), code);

        assert_eq!(sctp_error_cause_padding_len(SCTP_ERROR_CAUSE_HEADER_LEN), 0);
        assert_eq!(
            sctp_error_cause_padding_len(SCTP_ERROR_CAUSE_HEADER_LEN + 1),
            3
        );
        assert_eq!(
            sctp_error_cause_padding_len(SCTP_ERROR_CAUSE_HEADER_LEN + 2),
            2
        );
        assert_eq!(
            sctp_error_cause_padding_len(SCTP_ERROR_CAUSE_HEADER_LEN + 3),
            1
        );
        assert_eq!(
            sctp_error_cause_padded_len(SCTP_ERROR_CAUSE_HEADER_LEN + 1),
            SCTP_ERROR_CAUSE_HEADER_LEN + 4
        );

        let cause = SctpRawErrorCause::new(0xbeef, [1, 2, 3])
            .with_cause_code(0xcafe)
            .with_declared_length(5)
            .with_info([4, 5])
            .with_padding([0xaa]);
        assert_eq!(cause.cause_code_value(), 0xcafe);
        assert_eq!(cause.length(), 5);
        assert_eq!(cause.info(), &[4, 5]);
        assert_eq!(cause.padding(), &[0xaa]);
    }
}
