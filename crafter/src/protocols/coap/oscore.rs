//! OSCORE option metadata and immutable security-context inputs.
//!
//! The compressed option grammar, context derivation, nonce construction, and
//! External AAD follow RFC 8613 Sections 2, 3.1, 3.2.1, 5.2, 5.4, and 6.1.
//! Packet protection is an explicit typed transform; this module does not
//! allocate sequence numbers, replay windows, contexts, or any other protocol
//! state.

use core::fmt;

use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit as AeadKeyInit},
    consts::{U13, U8},
    Ccm,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::CrafterError;

use super::constants::{
    COAP_OPTION_OBSERVE, COAP_OPTION_OSCORE, COAP_OPTION_PROXY_SCHEME, COAP_OPTION_PROXY_URI,
    COAP_OPTION_URI_HOST, COAP_OPTION_URI_PORT, COAP_PAYLOAD_MARKER,
};
use super::message::{Coap, CoapCode, CoapOptionOrder, CoapPayloadMarker};
use super::option::{decode_option_sequence, encode_option_sequence, CoapOption, CoapOptions};

const OSCORE_PARTIAL_IV_LENGTH_MASK: u8 = 0x07;
const OSCORE_KID_FLAG: u8 = 0x08;
const OSCORE_KID_CONTEXT_FLAG: u8 = 0x10;
const OSCORE_EXTENSION_FLAGS_MASK: u8 = 0xe0;
const OSCORE_PROVISIONAL_GROUP_FLAG: u8 = 0x20;
const OSCORE_MAX_PARTIAL_IV_LEN: usize = 5;
const OSCORE_MAX_OPTION_LEN: usize = u8::MAX as usize;
const OSCORE_AES_CCM_16_64_128_ID: i32 = 10;
const OSCORE_HKDF_SHA_256_ID: i32 = -10;
const OSCORE_AES_CCM_16_64_128_KEY_LEN: usize = 16;
const OSCORE_AES_CCM_16_64_128_NONCE_LEN: usize = 13;
const OSCORE_AES_CCM_16_64_128_TAG_LEN: usize = 8;
const OSCORE_AES_CCM_16_64_128_MAX_ID_LEN: usize = OSCORE_AES_CCM_16_64_128_NONCE_LEN - 6;
const OSCORE_VERSION: u64 = 1;
const HKDF_SHA_256_OUTPUT_LEN: usize = 32;
const HKDF_MAX_BLOCKS: usize = u8::MAX as usize;

type HmacSha256 = Hmac<Sha256>;
type OscoreAesCcm = Ccm<Aes128, U8, U13>;

/// AEAD algorithm identifier stored in an OSCORE security context.
///
/// The mandatory RFC 8613 profile is supported directly.  Other COSE
/// identifiers remain inspectable and produce a typed unsupported result when
/// context derivation or packet protection is requested.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OscoreAeadAlgorithm {
    /// AES-CCM-16-64-128 (COSE algorithm 10).
    #[default]
    AesCcm16_64_128,
    /// An unsupported COSE AEAD identifier preserved verbatim.
    Unknown(i32),
}

impl OscoreAeadAlgorithm {
    /// Interpret a numeric COSE AEAD algorithm identifier.
    pub const fn from_id(id: i32) -> Self {
        match id {
            OSCORE_AES_CCM_16_64_128_ID => Self::AesCcm16_64_128,
            value => Self::Unknown(value),
        }
    }

    /// Return the preserved numeric COSE algorithm identifier.
    pub const fn id(self) -> i32 {
        match self {
            Self::AesCcm16_64_128 => OSCORE_AES_CCM_16_64_128_ID,
            Self::Unknown(value) => value,
        }
    }

    /// Return whether this implementation supports the algorithm.
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::AesCcm16_64_128)
    }

    /// Return a stable inspection label.
    pub fn label(self) -> String {
        match self {
            Self::AesCcm16_64_128 => "AES-CCM-16-64-128".to_string(),
            Self::Unknown(id) => format!("unknown-aead-{id}"),
        }
    }

    /// Return the source-backed AEAD key length.
    pub fn key_len(self) -> Result<usize, OscoreError> {
        match self {
            Self::AesCcm16_64_128 => Ok(OSCORE_AES_CCM_16_64_128_KEY_LEN),
            Self::Unknown(id) => Err(OscoreError::UnsupportedAeadAlgorithm { id }),
        }
    }

    /// Return the source-backed AEAD nonce length.
    pub fn nonce_len(self) -> Result<usize, OscoreError> {
        match self {
            Self::AesCcm16_64_128 => Ok(OSCORE_AES_CCM_16_64_128_NONCE_LEN),
            Self::Unknown(id) => Err(OscoreError::UnsupportedAeadAlgorithm { id }),
        }
    }

    /// Return the source-backed authentication-tag length.
    pub fn tag_len(self) -> Result<usize, OscoreError> {
        match self {
            Self::AesCcm16_64_128 => Ok(OSCORE_AES_CCM_16_64_128_TAG_LEN),
            Self::Unknown(id) => Err(OscoreError::UnsupportedAeadAlgorithm { id }),
        }
    }

    fn max_identifier_len(self) -> Result<usize, OscoreError> {
        match self {
            Self::AesCcm16_64_128 => Ok(OSCORE_AES_CCM_16_64_128_MAX_ID_LEN),
            Self::Unknown(id) => Err(OscoreError::UnsupportedAeadAlgorithm { id }),
        }
    }
}

/// HMAC-based key-derivation algorithm stored in an OSCORE context.
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OscoreKdfAlgorithm {
    /// HKDF SHA-256 (COSE algorithm -10).
    #[default]
    HkdfSha256,
    /// An unsupported COSE KDF identifier preserved verbatim.
    Unknown(i32),
}

impl OscoreKdfAlgorithm {
    /// Interpret a numeric COSE KDF algorithm identifier.
    pub const fn from_id(id: i32) -> Self {
        match id {
            OSCORE_HKDF_SHA_256_ID => Self::HkdfSha256,
            value => Self::Unknown(value),
        }
    }

    /// Return the preserved numeric COSE algorithm identifier.
    pub const fn id(self) -> i32 {
        match self {
            Self::HkdfSha256 => OSCORE_HKDF_SHA_256_ID,
            Self::Unknown(value) => value,
        }
    }

    /// Return whether this implementation supports the algorithm.
    pub const fn is_supported(self) -> bool {
        matches!(self, Self::HkdfSha256)
    }

    /// Return a stable inspection label.
    pub fn label(self) -> String {
        match self {
            Self::HkdfSha256 => "HKDF-SHA-256".to_string(),
            Self::Unknown(id) => format!("unknown-kdf-{id}"),
        }
    }
}

/// Structured failures from OSCORE metadata, derivation, and transforms.
///
/// The buffer and field variants mirror the core packet error vocabulary,
/// while algorithm identifiers remain numeric and inspectable.  Later packet
/// protection steps reuse the redacted context and authentication variants.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OscoreError {
    /// A declared OSCORE field did not fit in the supplied buffer.
    BufferTooShort {
        /// Stable field context.
        context: &'static str,
        /// Required bytes at this local boundary.
        required: usize,
        /// Available bytes at this local boundary.
        available: usize,
    },
    /// A structurally impossible or context-incompatible value was supplied.
    InvalidFieldValue {
        /// Stable field name.
        field: &'static str,
        /// Stable non-secret reason.
        reason: &'static str,
    },
    /// The preserved AEAD algorithm is not implemented.
    UnsupportedAeadAlgorithm {
        /// Numeric COSE algorithm identifier.
        id: i32,
    },
    /// The preserved KDF algorithm is not implemented.
    UnsupportedKdfAlgorithm {
        /// Numeric COSE algorithm identifier.
        id: i32,
    },
    /// Group OSCORE processing is unavailable while its specification remains provisional.
    UnsupportedGroupOscoreOperation {
        /// Stable non-secret operation name.
        operation: &'static str,
    },
    /// A preserved countersignature algorithm has no admitted implementation.
    UnsupportedCountersignatureAlgorithm {
        /// Numeric COSE algorithm identifier.
        id: i32,
    },
    /// Required request or context metadata was not supplied.
    MissingContext {
        /// Stable non-secret context name.
        context: &'static str,
    },
    /// Authentication failed without disclosing which security input differed.
    AuthenticationFailed {
        /// Stable redacted authentication context.
        context: &'static str,
    },
}

impl OscoreError {
    fn buffer_too_short(context: &'static str, required: usize, available: usize) -> Self {
        Self::BufferTooShort {
            context,
            required,
            available,
        }
    }

    fn invalid_field_value(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidFieldValue { field, reason }
    }
}

impl fmt::Display for OscoreError {
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
            Self::InvalidFieldValue { field, reason } => {
                write!(f, "invalid value for {field}: {reason}")
            }
            Self::UnsupportedAeadAlgorithm { id } => {
                write!(f, "unsupported OSCORE AEAD algorithm {id}")
            }
            Self::UnsupportedKdfAlgorithm { id } => {
                write!(f, "unsupported OSCORE KDF algorithm {id}")
            }
            Self::UnsupportedGroupOscoreOperation { operation } => {
                write!(
                    f,
                    "unsupported provisional Group OSCORE operation {operation}"
                )
            }
            Self::UnsupportedCountersignatureAlgorithm { id } => {
                write!(
                    f,
                    "unsupported Group OSCORE countersignature algorithm {id}"
                )
            }
            Self::MissingContext { context } => {
                write!(f, "missing required OSCORE context {context}")
            }
            Self::AuthenticationFailed { context } => {
                write!(f, "OSCORE authentication failed for {context}")
            }
        }
    }
}

impl std::error::Error for OscoreError {}

/// Parsed, byte-exact RFC 8613 OSCORE option value.
///
/// An absent flag byte (the canonical empty option) remains distinct from an
/// explicitly encoded zero flag byte.  Empty-but-present KID and KID Context
/// values are represented by `Some(&[])`.  Unknown high flag bits and their
/// uninterpreted trailing bytes are retained for inspection but are not
/// assigned pairwise OSCORE semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OscoreOption {
    raw: Vec<u8>,
    flag_byte: Option<u8>,
    partial_iv: Option<Vec<u8>>,
    kid_context: Option<Vec<u8>>,
    kid: Option<Vec<u8>>,
    unparsed_extension: Vec<u8>,
}

impl OscoreOption {
    /// Build the canonical empty OSCORE option value.
    pub const fn empty() -> Self {
        Self {
            raw: Vec::new(),
            flag_byte: None,
            partial_iv: None,
            kid_context: None,
            kid: None,
            unparsed_extension: Vec::new(),
        }
    }

    /// Build and validate a canonical base RFC 8613 option value.
    ///
    /// `Some(Vec::new())` is meaningful for KID and KID Context because their
    /// presence flags are independent of their lengths.  A zero-length
    /// Partial IV has no distinct wire form and is therefore rejected.
    pub fn new(
        partial_iv: Option<Vec<u8>>,
        kid_context: Option<Vec<u8>>,
        kid: Option<Vec<u8>>,
    ) -> Result<Self, OscoreError> {
        if partial_iv.as_ref().is_some_and(Vec::is_empty) {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.option.partial-iv",
                "a present Partial IV must contain at least one byte",
            ));
        }

        let partial_iv_len = partial_iv.as_ref().map_or(0, Vec::len);
        if partial_iv_len > OSCORE_MAX_PARTIAL_IV_LEN {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.option.partial-iv-length",
                "Partial IV length exceeds five bytes",
            ));
        }

        let kid_context_len = kid_context.as_ref().map_or(0, Vec::len);
        if kid_context_len > u8::MAX as usize {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.option.kid-context",
                "KID Context length exceeds one-byte encoding",
            ));
        }

        if partial_iv.is_none() && kid_context.is_none() && kid.is_none() {
            return Ok(Self::empty());
        }

        let mut flag = partial_iv_len as u8;
        if kid_context.is_some() {
            flag |= OSCORE_KID_CONTEXT_FLAG;
        }
        if kid.is_some() {
            flag |= OSCORE_KID_FLAG;
        }

        let encoded_len = 1usize
            .checked_add(partial_iv_len)
            .and_then(|len| len.checked_add(usize::from(kid_context.is_some())))
            .and_then(|len| len.checked_add(kid_context_len))
            .and_then(|len| len.checked_add(kid.as_ref().map_or(0, Vec::len)))
            .ok_or_else(|| {
                OscoreError::invalid_field_value(
                    "coap.oscore.option.length",
                    "OSCORE option length overflow",
                )
            })?;
        if encoded_len > OSCORE_MAX_OPTION_LEN {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.option.length",
                "OSCORE option length exceeds 255 bytes",
            ));
        }

        let mut raw = Vec::with_capacity(encoded_len);
        raw.push(flag);
        if let Some(value) = partial_iv.as_deref() {
            raw.extend_from_slice(value);
        }
        if let Some(value) = kid_context.as_deref() {
            raw.push(value.len() as u8);
            raw.extend_from_slice(value);
        }
        if let Some(value) = kid.as_deref() {
            raw.extend_from_slice(value);
        }

        Ok(Self {
            raw,
            flag_byte: Some(flag),
            partial_iv,
            kid_context,
            kid,
            unparsed_extension: Vec::new(),
        })
    }

    /// Parse and structurally validate exact OSCORE option value bytes.
    pub fn parse(bytes: impl AsRef<[u8]>) -> Result<Self, OscoreError> {
        let bytes = bytes.as_ref();
        let Some(&flag) = bytes.first() else {
            return Ok(Self::empty());
        };

        let partial_iv_len = usize::from(flag & OSCORE_PARTIAL_IV_LENGTH_MASK);
        if partial_iv_len > OSCORE_MAX_PARTIAL_IV_LEN {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.option.partial-iv-length",
                "reserved Partial IV length encoding",
            ));
        }

        let available_after_flag = bytes.len() - 1;
        if available_after_flag < partial_iv_len {
            return Err(OscoreError::buffer_too_short(
                "coap.oscore.option.partial-iv",
                partial_iv_len,
                available_after_flag,
            ));
        }

        let mut cursor = 1;
        let partial_iv = if partial_iv_len == 0 {
            None
        } else {
            let end = cursor + partial_iv_len;
            let value = bytes[cursor..end].to_vec();
            cursor = end;
            Some(value)
        };

        let kid_context = if flag & OSCORE_KID_CONTEXT_FLAG != 0 {
            if cursor >= bytes.len() {
                return Err(OscoreError::buffer_too_short(
                    "coap.oscore.option.kid-context-length",
                    1,
                    0,
                ));
            }
            let length = usize::from(bytes[cursor]);
            cursor += 1;
            let available = bytes.len() - cursor;
            if available < length {
                return Err(OscoreError::buffer_too_short(
                    "coap.oscore.option.kid-context",
                    length,
                    available,
                ));
            }
            let end = cursor + length;
            let value = bytes[cursor..end].to_vec();
            cursor = end;
            Some(value)
        } else {
            None
        };

        let kid = if flag & OSCORE_KID_FLAG != 0 {
            let value = bytes[cursor..].to_vec();
            cursor = bytes.len();
            Some(value)
        } else {
            None
        };

        let unparsed_extension = if cursor < bytes.len() {
            if flag & OSCORE_EXTENSION_FLAGS_MASK == 0 {
                return Err(OscoreError::invalid_field_value(
                    "coap.oscore.option.trailing-bytes",
                    "bytes remain without a KID or extension flag",
                ));
            }
            bytes[cursor..].to_vec()
        } else {
            Vec::new()
        };

        Ok(Self {
            raw: bytes.to_vec(),
            flag_byte: Some(flag),
            partial_iv,
            kid_context,
            kid,
            unparsed_extension,
        })
    }

    /// Alias for the checked parser used by generated tools.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self, OscoreError> {
        Self::parse(bytes)
    }

    /// Return whether the canonical empty representation omitted the flag byte.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Return the exact flag byte if it was present on the wire.
    pub const fn flag_byte(&self) -> Option<u8> {
        self.flag_byte
    }

    /// Return unknown or provisional high flag bits without interpreting them.
    pub fn extension_flags(&self) -> u8 {
        self.flag_byte.unwrap_or(0) & OSCORE_EXTENSION_FLAGS_MASK
    }

    /// Return whether IANA's provisional Group Flag (bit position 2) is set.
    ///
    /// This is inspection metadata only. It does not select a Group OSCORE
    /// serializer, protection algorithm, or countersignature grammar.
    pub fn has_provisional_group_flag(&self) -> bool {
        self.extension_flags() & OSCORE_PROVISIONAL_GROUP_FLAG != 0
    }

    /// Borrow the Partial IV when its encoded length is nonzero.
    pub fn partial_iv(&self) -> Option<&[u8]> {
        self.partial_iv.as_deref()
    }

    /// Borrow the KID Context, preserving absent versus present-empty states.
    pub fn kid_context(&self) -> Option<&[u8]> {
        self.kid_context.as_deref()
    }

    /// Borrow the KID, preserving absent versus present-empty states.
    pub fn kid(&self) -> Option<&[u8]> {
        self.kid.as_deref()
    }

    /// Borrow bytes retained under unknown or provisional extension flags.
    pub fn unparsed_extension(&self) -> &[u8] {
        &self.unparsed_extension
    }

    /// Borrow the complete exact option value bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Serialize the complete option value without normalization.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.raw.clone()
    }

    /// Consume the model and return the complete exact option value bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.raw
    }

    /// Convert this value into an ordinary CoAP option 9 envelope.
    pub fn into_coap_option(self) -> CoapOption {
        self.into()
    }
}

impl TryFrom<&CoapOption> for OscoreOption {
    type Error = OscoreError;

    fn try_from(option: &CoapOption) -> Result<Self, Self::Error> {
        if option.number().value() != COAP_OPTION_OSCORE {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.option.number",
                "option number is not OSCORE",
            ));
        }
        Self::parse(option.value())
    }
}

impl From<OscoreOption> for CoapOption {
    fn from(value: OscoreOption) -> Self {
        CoapOption::new(COAP_OPTION_OSCORE, value.into_bytes())
    }
}

/// Request metadata retained by a caller for protecting an OSCORE response.
///
/// RFC 8613 binds every protected response to the request KID and Partial IV
/// through External AAD.  This value owns only non-secret packet metadata; it
/// does not allocate sequence numbers or retain replay state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OscoreRequestBinding {
    request_kid: Vec<u8>,
    request_partial_iv: Vec<u8>,
}

impl OscoreRequestBinding {
    /// Build checked request-binding metadata for the admitted AEAD profile.
    pub fn new(
        request_kid: impl Into<Vec<u8>>,
        request_partial_iv: impl Into<Vec<u8>>,
    ) -> Result<Self, OscoreError> {
        let request_kid = request_kid.into();
        let request_partial_iv = request_partial_iv.into();
        validate_oscore_identifier(
            &request_kid,
            OSCORE_AES_CCM_16_64_128_MAX_ID_LEN,
            "coap.oscore.aad.request-kid",
        )?;
        validate_partial_iv(&request_partial_iv, "coap.oscore.aad.request-partial-iv")?;
        Ok(Self {
            request_kid,
            request_partial_iv,
        })
    }

    /// Borrow the request KID used by response External AAD.
    pub fn request_kid(&self) -> &[u8] {
        &self.request_kid
    }

    /// Borrow the request Partial IV used by response External AAD.
    pub fn request_partial_iv(&self) -> &[u8] {
        &self.request_partial_iv
    }
}

/// Explicit packet-local inputs for one OSCORE protection operation.
///
/// Requests require a Partial IV. Responses require an
/// [`OscoreRequestBinding`] and may either omit their own Partial IV to reuse
/// the request nonce or carry a new caller-supplied Partial IV. Sequence
/// allocation remains entirely outside this packet primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OscoreProtectParams {
    partial_iv: Option<Vec<u8>>,
    kid_context: Option<Vec<u8>>,
    request_binding: Option<OscoreRequestBinding>,
}

/// Explicit packet-local inputs for one OSCORE unprotection operation.
///
/// Incoming requests carry their request KID and Partial IV in the OSCORE
/// option. Incoming responses require caller-retained request binding metadata
/// for External AAD and for responses that reuse the request nonce. This value
/// owns no replay-window, transaction, or context-selection state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OscoreUnprotectParams {
    request_binding: Option<OscoreRequestBinding>,
}

impl OscoreUnprotectParams {
    /// Build parameters for an incoming protected request.
    pub const fn request() -> Self {
        Self {
            request_binding: None,
        }
    }

    /// Alias for [`Self::request`] used by request-oriented generated tools.
    pub const fn new() -> Self {
        Self::request()
    }

    /// Build parameters for an incoming protected response.
    pub fn response(request_binding: OscoreRequestBinding) -> Self {
        Self {
            request_binding: Some(request_binding),
        }
    }

    /// Borrow response request-binding metadata, when present.
    pub fn request_binding(&self) -> Option<&OscoreRequestBinding> {
        self.request_binding.as_ref()
    }
}

impl Default for OscoreUnprotectParams {
    fn default() -> Self {
        Self::request()
    }
}

impl OscoreProtectParams {
    /// Build request protection parameters with an explicit Partial IV.
    pub fn request(partial_iv: impl Into<Vec<u8>>) -> Self {
        Self {
            partial_iv: Some(partial_iv.into()),
            kid_context: None,
            request_binding: None,
        }
    }

    /// Alias for [`Self::request`] used by request-oriented generated tools.
    pub fn new(partial_iv: impl Into<Vec<u8>>) -> Self {
        Self::request(partial_iv)
    }

    /// Build response parameters that reuse the request nonce.
    pub fn response(request_binding: OscoreRequestBinding) -> Self {
        Self {
            partial_iv: None,
            kid_context: None,
            request_binding: Some(request_binding),
        }
    }

    /// Build response parameters with a new explicit sender Partial IV.
    pub fn response_with_partial_iv(
        request_binding: OscoreRequestBinding,
        partial_iv: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            partial_iv: Some(partial_iv.into()),
            kid_context: None,
            request_binding: Some(request_binding),
        }
    }

    /// Include an explicit KID Context in the compressed OSCORE option.
    pub fn with_kid_context(mut self, kid_context: impl Into<Vec<u8>>) -> Self {
        self.kid_context = Some(kid_context.into());
        self
    }

    /// Attach or replace request binding metadata.
    pub fn with_request_binding(mut self, request_binding: OscoreRequestBinding) -> Self {
        self.request_binding = Some(request_binding);
        self
    }

    /// Borrow the caller-supplied sender Partial IV, when present.
    pub fn partial_iv(&self) -> Option<&[u8]> {
        self.partial_iv.as_deref()
    }

    /// Borrow the optional KID Context.
    pub fn kid_context(&self) -> Option<&[u8]> {
        self.kid_context.as_deref()
    }

    /// Borrow response request-binding metadata, when present.
    pub fn request_binding(&self) -> Option<&OscoreRequestBinding> {
        self.request_binding.as_ref()
    }
}

/// Immutable pairwise OSCORE context inputs and derived material.
///
/// The constructor derives the sender key, recipient key, and Common IV with
/// RFC 8613's mandatory AES-CCM-16-64-128 / HKDF-SHA-256 profile.  Secrets and
/// derived material are never exposed by `Debug`, `Display`, or `summary`.
#[derive(Clone)]
pub struct OscoreContext {
    master_secret: Vec<u8>,
    master_salt: Vec<u8>,
    sender_id: Vec<u8>,
    recipient_id: Vec<u8>,
    id_context: Option<Vec<u8>>,
    aead_algorithm: OscoreAeadAlgorithm,
    kdf_algorithm: OscoreKdfAlgorithm,
    sender_key_info: Vec<u8>,
    recipient_key_info: Vec<u8>,
    common_iv_info: Vec<u8>,
    sender_key: Vec<u8>,
    recipient_key: Vec<u8>,
    common_iv: Vec<u8>,
}

impl OscoreContext {
    /// Validate immutable inputs and derive the mandatory-profile context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        master_secret: impl Into<Vec<u8>>,
        master_salt: impl Into<Vec<u8>>,
        sender_id: impl Into<Vec<u8>>,
        recipient_id: impl Into<Vec<u8>>,
        id_context: Option<Vec<u8>>,
        aead_algorithm: OscoreAeadAlgorithm,
        kdf_algorithm: OscoreKdfAlgorithm,
    ) -> Result<Self, OscoreError> {
        let master_secret = master_secret.into();
        let master_salt = master_salt.into();
        let sender_id = sender_id.into();
        let recipient_id = recipient_id.into();

        let key_len = aead_algorithm.key_len()?;
        let nonce_len = aead_algorithm.nonce_len()?;
        let max_identifier_len = aead_algorithm.max_identifier_len()?;
        if let OscoreKdfAlgorithm::Unknown(id) = kdf_algorithm {
            return Err(OscoreError::UnsupportedKdfAlgorithm { id });
        }

        if sender_id.len() > max_identifier_len {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.context.sender-id",
                "Sender ID exceeds the selected AEAD nonce limit",
            ));
        }
        if recipient_id.len() > max_identifier_len {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.context.recipient-id",
                "Recipient ID exceeds the selected AEAD nonce limit",
            ));
        }

        let sender_key_info = encode_context_info(
            &sender_id,
            id_context.as_deref(),
            aead_algorithm.id(),
            "Key",
            key_len,
        )?;
        let recipient_key_info = encode_context_info(
            &recipient_id,
            id_context.as_deref(),
            aead_algorithm.id(),
            "Key",
            key_len,
        )?;
        let common_iv_info = encode_context_info(
            &[],
            id_context.as_deref(),
            aead_algorithm.id(),
            "IV",
            nonce_len,
        )?;

        let mut prk = hkdf_extract_sha256(&master_salt, &master_secret);
        let sender_key = hkdf_expand_sha256(&prk, &sender_key_info, key_len)?;
        let recipient_key = hkdf_expand_sha256(&prk, &recipient_key_info, key_len)?;
        let common_iv = hkdf_expand_sha256(&prk, &common_iv_info, nonce_len)?;
        prk.as_mut_slice().fill(0);

        Ok(Self {
            master_secret,
            master_salt,
            sender_id,
            recipient_id,
            id_context,
            aead_algorithm,
            kdf_algorithm,
            sender_key_info,
            recipient_key_info,
            common_iv_info,
            sender_key,
            recipient_key,
            common_iv,
        })
    }

    /// Construct a context using RFC 8613's default algorithms.
    pub fn with_default_algorithms(
        master_secret: impl Into<Vec<u8>>,
        master_salt: impl Into<Vec<u8>>,
        sender_id: impl Into<Vec<u8>>,
        recipient_id: impl Into<Vec<u8>>,
        id_context: Option<Vec<u8>>,
    ) -> Result<Self, OscoreError> {
        Self::new(
            master_secret,
            master_salt,
            sender_id,
            recipient_id,
            id_context,
            OscoreAeadAlgorithm::default(),
            OscoreKdfAlgorithm::default(),
        )
    }

    /// Return the selected AEAD algorithm.
    pub const fn aead_algorithm(&self) -> OscoreAeadAlgorithm {
        self.aead_algorithm
    }

    /// Return the selected KDF algorithm.
    pub const fn kdf_algorithm(&self) -> OscoreKdfAlgorithm {
        self.kdf_algorithm
    }

    /// Return the Master Secret length without exposing its bytes.
    pub fn master_secret_len(&self) -> usize {
        self.master_secret.len()
    }

    /// Return the Master Salt length without exposing its bytes.
    pub fn master_salt_len(&self) -> usize {
        self.master_salt.len()
    }

    /// Borrow the non-secret Sender ID.
    pub fn sender_id(&self) -> &[u8] {
        &self.sender_id
    }

    /// Borrow the non-secret Recipient ID.
    pub fn recipient_id(&self) -> &[u8] {
        &self.recipient_id
    }

    /// Borrow the ID Context, preserving absent versus present-empty states.
    pub fn id_context(&self) -> Option<&[u8]> {
        self.id_context.as_deref()
    }

    /// Borrow canonical CBOR metadata used to derive the Sender Key.
    pub fn sender_key_derivation_info(&self) -> &[u8] {
        &self.sender_key_info
    }

    /// Borrow canonical CBOR metadata used to derive the Recipient Key.
    pub fn recipient_key_derivation_info(&self) -> &[u8] {
        &self.recipient_key_info
    }

    /// Borrow canonical CBOR metadata used to derive the Common IV.
    pub fn common_iv_derivation_info(&self) -> &[u8] {
        &self.common_iv_info
    }

    /// Return the derived Sender Key length without exposing its bytes.
    pub fn sender_key_len(&self) -> usize {
        self.sender_key.len()
    }

    /// Return the derived Recipient Key length without exposing its bytes.
    pub fn recipient_key_len(&self) -> usize {
        self.recipient_key.len()
    }

    /// Return the derived Common IV length without exposing its bytes.
    pub fn common_iv_len(&self) -> usize {
        self.common_iv.len()
    }

    /// Derive an AEAD nonce for a message produced by this context's sender.
    ///
    /// `partial_iv` is the minimally encoded network-order Sender Sequence
    /// Number and therefore contains between one and five bytes.  The returned
    /// nonce is packet metadata rather than long-lived key material and may be
    /// passed directly to the selected AEAD implementation.
    pub fn sender_nonce(&self, partial_iv: impl AsRef<[u8]>) -> Result<Vec<u8>, OscoreError> {
        self.derive_nonce(&self.sender_id, partial_iv.as_ref())
    }

    /// Derive an AEAD nonce for a message produced by the peer represented by
    /// this context's recipient.
    pub fn recipient_nonce(&self, partial_iv: impl AsRef<[u8]>) -> Result<Vec<u8>, OscoreError> {
        self.derive_nonce(&self.recipient_id, partial_iv.as_ref())
    }

    /// Encode RFC 8613's canonical five-element `aad_array`.
    ///
    /// `class_i_options` is the already encoded Class I option sequence whose
    /// deltas begin at zero.  RFC 8613 defines no Class I options at
    /// publication, so callers normally pass an empty slice.
    pub fn aad_array(
        &self,
        request_kid: impl AsRef<[u8]>,
        request_partial_iv: impl AsRef<[u8]>,
        class_i_options: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, OscoreError> {
        let request_kid = request_kid.as_ref();
        let request_partial_iv = request_partial_iv.as_ref();
        validate_oscore_identifier(
            request_kid,
            self.aead_algorithm.max_identifier_len()?,
            "coap.oscore.aad.request-kid",
        )?;
        validate_partial_iv(request_partial_iv, "coap.oscore.aad.request-piv")?;

        let mut out = Vec::new();
        out.push(0x85); // canonical CBOR array(5)
        append_cbor_unsigned(0, OSCORE_VERSION, &mut out);
        out.push(0x81); // canonical CBOR array(1)
        append_cbor_integer(i64::from(self.aead_algorithm.id()), &mut out);
        append_cbor_bytes(request_kid, &mut out)?;
        append_cbor_bytes(request_partial_iv, &mut out)?;
        append_cbor_bytes(class_i_options.as_ref(), &mut out)?;
        Ok(out)
    }

    /// Encode the CBOR byte string that carries the RFC 8613 External AAD.
    pub fn external_aad(
        &self,
        request_kid: impl AsRef<[u8]>,
        request_partial_iv: impl AsRef<[u8]>,
        class_i_options: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, OscoreError> {
        let aad_array = self.aad_array(request_kid, request_partial_iv, class_i_options)?;
        let mut out = Vec::new();
        append_cbor_bytes(&aad_array, &mut out)?;
        Ok(out)
    }

    /// Encode the complete COSE Encrypt0 `Enc_structure` used as AEAD AAD.
    pub fn cose_encrypt0_aad(
        &self,
        request_kid: impl AsRef<[u8]>,
        request_partial_iv: impl AsRef<[u8]>,
        class_i_options: impl AsRef<[u8]>,
    ) -> Result<Vec<u8>, OscoreError> {
        let external_aad = self.external_aad(request_kid, request_partial_iv, class_i_options)?;
        let mut out = Vec::new();
        out.push(0x83); // canonical CBOR array(3)
        append_cbor_text(b"Encrypt0", &mut out)?;
        append_cbor_bytes(&[], &mut out)?; // empty COSE protected header
        out.extend_from_slice(&external_aad);
        Ok(out)
    }

    /// Protect one typed CoAP datagram with RFC 8613 OSCORE.
    ///
    /// Class E fields become the authenticated ciphertext, Class U fields
    /// remain on the returned typed outer message, and the current RFC 8613
    /// Class I sequence is empty. The caller supplies every Partial IV and
    /// request binding explicitly; this context never owns mutable sequence
    /// or replay state.
    pub fn protect(
        &self,
        message: &Coap,
        params: OscoreProtectParams,
    ) -> Result<Coap, OscoreError> {
        protect_oscore(self, message, params)
    }

    /// Authenticate and decode one typed RFC 8613 OSCORE outer message.
    ///
    /// Authentication completes before any protected Code, option, or payload
    /// is interpreted. The returned value is an ordinary typed [`Coap`] layer;
    /// failures retain ciphertext only in the caller-owned outer message.
    pub fn unprotect(
        &self,
        message: &Coap,
        params: OscoreUnprotectParams,
    ) -> Result<Coap, OscoreError> {
        unprotect_oscore(self, message, params)
    }

    /// Stable redacted context summary.
    pub fn summary(&self) -> String {
        let id_context = match self.id_context.as_deref() {
            None => "absent".to_string(),
            Some(value) => format!("present({} bytes)", value.len()),
        };
        format!(
            "OscoreContext(aead={}, kdf={}, sender_id={} bytes, recipient_id={} bytes, id_context={}, master_secret=<{} bytes redacted>, master_salt=<{} bytes redacted>)",
            self.aead_algorithm.label(),
            self.kdf_algorithm.label(),
            self.sender_id.len(),
            self.recipient_id.len(),
            id_context,
            self.master_secret.len(),
            self.master_salt.len(),
        )
    }

    pub(super) fn sender_key(&self) -> &[u8] {
        &self.sender_key
    }

    pub(super) fn recipient_key(&self) -> &[u8] {
        &self.recipient_key
    }

    #[cfg(test)]
    pub(super) fn common_iv(&self) -> &[u8] {
        &self.common_iv
    }

    fn derive_nonce(&self, sender_id: &[u8], partial_iv: &[u8]) -> Result<Vec<u8>, OscoreError> {
        let nonce_len = self.aead_algorithm.nonce_len()?;
        let padded_id_len = nonce_len.checked_sub(6).ok_or_else(|| {
            OscoreError::invalid_field_value(
                "coap.oscore.nonce.length",
                "selected AEAD nonce is shorter than seven bytes",
            )
        })?;
        validate_oscore_identifier(sender_id, padded_id_len, "coap.oscore.nonce.sender-id")?;
        validate_partial_iv(partial_iv, "coap.oscore.nonce.partial-iv")?;

        if self.common_iv.len() != nonce_len {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.nonce.common-iv",
                "Common IV length differs from the selected AEAD nonce length",
            ));
        }

        let id_end = nonce_len
            .checked_sub(OSCORE_MAX_PARTIAL_IV_LEN)
            .ok_or_else(|| {
                OscoreError::invalid_field_value(
                    "coap.oscore.nonce.length",
                    "selected AEAD nonce cannot contain a five-byte Partial IV",
                )
            })?;
        let id_start = id_end.checked_sub(sender_id.len()).ok_or_else(|| {
            OscoreError::invalid_field_value(
                "coap.oscore.nonce.sender-id",
                "Sender ID exceeds the selected AEAD nonce limit",
            )
        })?;
        let partial_iv_start = nonce_len.checked_sub(partial_iv.len()).ok_or_else(|| {
            OscoreError::invalid_field_value(
                "coap.oscore.nonce.partial-iv",
                "Partial IV exceeds the selected AEAD nonce length",
            )
        })?;

        let mut nonce = vec![0; nonce_len];
        nonce[0] = u8::try_from(sender_id.len()).map_err(|_| {
            OscoreError::invalid_field_value(
                "coap.oscore.nonce.sender-id",
                "Sender ID length exceeds one-byte nonce encoding",
            )
        })?;
        nonce[id_start..id_end].copy_from_slice(sender_id);
        nonce[partial_iv_start..].copy_from_slice(partial_iv);
        for (byte, common_iv_byte) in nonce.iter_mut().zip(&self.common_iv) {
            *byte ^= common_iv_byte;
        }
        Ok(nonce)
    }
}

/// Protect one typed CoAP datagram and return its typed OSCORE outer message.
pub fn protect_oscore(
    context: &OscoreContext,
    message: &Coap,
    params: OscoreProtectParams,
) -> Result<Coap, OscoreError> {
    if message
        .options_value()
        .iter()
        .any(|option| option.number().value() == COAP_OPTION_OSCORE)
    {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.message.option",
            "nested OSCORE protection is not supported",
        ));
    }

    let is_request = message.is_request();
    let is_response = message.is_response();
    if !is_request && !is_response {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.message.code",
            "OSCORE protection requires a request or response Code",
        ));
    }

    if let Some(kid_context) = params.kid_context() {
        if context.id_context() != Some(kid_context) {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.option.kid-context",
                "KID Context differs from the selected security context",
            ));
        }
    }

    let (request_kid, request_partial_iv, nonce, option) = if is_request {
        if params.request_binding().is_some() {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.params.request-binding",
                "request protection must not carry response binding metadata",
            ));
        }
        let partial_iv = params.partial_iv().ok_or(OscoreError::MissingContext {
            context: "coap.oscore.nonce.partial-iv",
        })?;
        validate_partial_iv(partial_iv, "coap.oscore.nonce.partial-iv")?;
        let nonce = context.sender_nonce(partial_iv)?;
        let option = OscoreOption::new(
            Some(partial_iv.to_vec()),
            params.kid_context.clone(),
            Some(context.sender_id().to_vec()),
        )?;
        (
            context.sender_id().to_vec(),
            partial_iv.to_vec(),
            nonce,
            option,
        )
    } else {
        let binding = params
            .request_binding()
            .ok_or(OscoreError::MissingContext {
                context: "coap.oscore.aad.request-binding",
            })?;
        let nonce = match params.partial_iv() {
            Some(partial_iv) => context.sender_nonce(partial_iv)?,
            None => context.derive_nonce(binding.request_kid(), binding.request_partial_iv())?,
        };
        let option =
            OscoreOption::new(params.partial_iv.clone(), params.kid_context.clone(), None)?;
        (
            binding.request_kid().to_vec(),
            binding.request_partial_iv().to_vec(),
            nonce,
            option,
        )
    };

    let mut inner_options = Vec::new();
    let mut outer_options = Vec::new();
    for option in message.options_value() {
        if is_oscore_class_u_only(option.number().value()) {
            outer_options.push(option.clone());
        } else {
            inner_options.push(option.clone());
            if option.number().value() == COAP_OPTION_OBSERVE {
                // RFC 8613 Section 4.1.3.5 carries Observe at both levels.
                outer_options.push(option.clone());
            }
        }
    }

    let mut plaintext = Vec::new();
    plaintext.push(message.code_value().wire_value());
    plaintext.extend_from_slice(&encode_protected_options(
        inner_options,
        message.option_order_value(),
        "coap.oscore.plaintext.options",
    )?);
    if !message.payload_value().is_empty() {
        plaintext.push(COAP_PAYLOAD_MARKER);
        plaintext.extend_from_slice(message.payload_value());
    }

    // RFC 8613 defines no Class I options. Keep the encoded input explicit so
    // future source-backed Class I assignments have one narrow integration
    // point instead of changing the AEAD construction.
    let class_i_options: &[u8] = &[];
    let aad = context.cose_encrypt0_aad(&request_kid, &request_partial_iv, class_i_options)?;
    let cipher =
        <OscoreAesCcm as AeadKeyInit>::new_from_slice(context.sender_key()).map_err(|_| {
            OscoreError::invalid_field_value(
                "coap.oscore.context.sender-key",
                "Sender Key length differs from the selected AEAD key length",
            )
        })?;
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut plaintext)
        .map_err(|_| {
            OscoreError::invalid_field_value("coap.oscore.ciphertext", "AEAD encryption failed")
        })?;
    plaintext.extend_from_slice(&tag);

    outer_options.push(option.into_coap_option());
    let outer_code = if message.has_observe() {
        if is_request {
            CoapCode::fetch()
        } else {
            CoapCode::content()
        }
    } else if is_request {
        CoapCode::post()
    } else {
        CoapCode::changed()
    };

    let token_length = message.token_length_value().map_err(|_| {
        OscoreError::invalid_field_value(
            "coap.oscore.message.token-length",
            "outer Token Length metadata cannot be encoded",
        )
    })?;
    Ok(Coap::new()
        .version(message.version_value())
        .message_type(message.message_type_value())
        .token_length(token_length)
        .code(outer_code)
        .message_id(message.message_id_value())
        .token(message.token_value().clone())
        .options(outer_options)
        .option_order(CoapOptionOrder::Canonical)
        .payload_marker(CoapPayloadMarker::Present)
        .payload(plaintext))
}

/// Authenticate and decode one typed OSCORE outer message.
pub fn unprotect_oscore(
    context: &OscoreContext,
    message: &Coap,
    params: OscoreUnprotectParams,
) -> Result<Coap, OscoreError> {
    let mut oscore_options = message
        .options_value()
        .iter()
        .filter(|option| option.number().value() == COAP_OPTION_OSCORE);
    let oscore_option = oscore_options.next().ok_or(OscoreError::MissingContext {
        context: "coap.oscore.message.option",
    })?;
    if oscore_options.next().is_some() {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.message.option",
            "OSCORE option must not be repeated",
        ));
    }
    let oscore_option = OscoreOption::try_from(oscore_option)?;
    if oscore_option.has_provisional_group_flag() {
        return Err(OscoreError::UnsupportedGroupOscoreOperation {
            operation: "pairwise-unprotect",
        });
    }
    if oscore_option.extension_flags() != 0 {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.option.flags",
            "unsupported provisional OSCORE flag metadata",
        ));
    }

    if message.payload_marker_value() != CoapPayloadMarker::Present {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.message.payload-marker",
            "OSCORE ciphertext requires an outer payload marker",
        ));
    }
    let tag_len = context.aead_algorithm().tag_len()?;
    let required = 1usize.checked_add(tag_len).ok_or_else(|| {
        OscoreError::invalid_field_value(
            "coap.oscore.ciphertext",
            "ciphertext minimum length overflow",
        )
    })?;
    let payload = message.payload_value();
    if payload.len() < required {
        return Err(OscoreError::buffer_too_short(
            "coap.oscore.ciphertext",
            required,
            payload.len(),
        ));
    }

    let outer_is_request = message.is_request();
    let outer_is_response = message.is_response();
    if !outer_is_request && !outer_is_response {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.message.code",
            "OSCORE outer message requires a request or response Code",
        ));
    }

    if let Some(kid_context) = oscore_option.kid_context() {
        if context.id_context() != Some(kid_context) {
            return Err(OscoreError::AuthenticationFailed {
                context: "coap.oscore.authentication",
            });
        }
    }

    let (request_kid, request_partial_iv, nonce) = if outer_is_request {
        if params.request_binding().is_some() {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.params.request-binding",
                "request unprotection must not carry response binding metadata",
            ));
        }
        let partial_iv = oscore_option
            .partial_iv()
            .ok_or(OscoreError::MissingContext {
                context: "coap.oscore.nonce.partial-iv",
            })?;
        let kid = oscore_option.kid().ok_or(OscoreError::MissingContext {
            context: "coap.oscore.aad.request-kid",
        })?;
        if !secret_eq(kid, context.recipient_id()) {
            return Err(OscoreError::AuthenticationFailed {
                context: "coap.oscore.authentication",
            });
        }
        (
            kid.to_vec(),
            partial_iv.to_vec(),
            context.recipient_nonce(partial_iv)?,
        )
    } else {
        let binding = params
            .request_binding()
            .ok_or(OscoreError::MissingContext {
                context: "coap.oscore.aad.request-binding",
            })?;
        let nonce = match oscore_option.partial_iv() {
            Some(partial_iv) => context.recipient_nonce(partial_iv)?,
            None => context.derive_nonce(binding.request_kid(), binding.request_partial_iv())?,
        };
        (
            binding.request_kid().to_vec(),
            binding.request_partial_iv().to_vec(),
            nonce,
        )
    };

    // RFC 8613 defines no Class I options. Keep this explicit so any future
    // source-backed assignment has one narrow AAD integration point.
    let class_i_options: &[u8] = &[];
    let aad = context.cose_encrypt0_aad(&request_kid, &request_partial_iv, class_i_options)?;
    let split_at = payload.len() - tag_len;
    let mut plaintext = payload[..split_at].to_vec();
    let tag = GenericArray::from_slice(&payload[split_at..]);
    let cipher =
        <OscoreAesCcm as AeadKeyInit>::new_from_slice(context.recipient_key()).map_err(|_| {
            OscoreError::invalid_field_value(
                "coap.oscore.context.recipient-key",
                "Recipient Key length differs from the selected AEAD key length",
            )
        })?;
    cipher
        .decrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut plaintext, tag)
        .map_err(|_| OscoreError::AuthenticationFailed {
            context: "coap.oscore.authentication",
        })?;

    let inner_code = plaintext.first().copied().ok_or_else(|| {
        OscoreError::buffer_too_short("coap.oscore.plaintext", 1, plaintext.len())
    })?;
    let decoded = decode_option_sequence(&plaintext[1..]).map_err(map_plaintext_decode_error)?;
    let payload_offset = 1usize.checked_add(decoded.consumed).ok_or_else(|| {
        OscoreError::invalid_field_value(
            "coap.oscore.plaintext",
            "plaintext option boundary overflow",
        )
    })?;
    let (payload_marker, inner_payload) = if decoded.payload_marker {
        let payload_start = payload_offset.checked_add(1).ok_or_else(|| {
            OscoreError::invalid_field_value(
                "coap.oscore.plaintext",
                "plaintext payload boundary overflow",
            )
        })?;
        let inner_payload = plaintext.get(payload_start..).unwrap_or_default();
        if inner_payload.is_empty() {
            return Err(OscoreError::buffer_too_short(
                "coap.oscore.plaintext.payload",
                1,
                inner_payload.len(),
            ));
        }
        (CoapPayloadMarker::Present, inner_payload.to_vec())
    } else {
        (CoapPayloadMarker::Absent, Vec::new())
    };

    let inner_code = CoapCode::from_wire(inner_code);
    if (outer_is_request && !inner_code.is_request())
        || (outer_is_response && !inner_code.is_response())
    {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.plaintext.code",
            "inner and outer Code classes disagree",
        ));
    }

    let mut merged_options = CoapOptions::new();
    for option in message.options_value() {
        let number = option.number().value();
        if number == COAP_OPTION_OSCORE || number == COAP_OPTION_OBSERVE {
            continue;
        }
        if !is_oscore_class_u_only(number) {
            return Err(OscoreError::invalid_field_value(
                "coap.oscore.message.outer-option",
                "option is not assigned to OSCORE Class U",
            ));
        }
        merged_options.add(CoapOption::new(number, option.value().to_vec()));
    }
    for option in decoded.options.iter() {
        merged_options.add(CoapOption::new(
            option.number().value(),
            option.value().to_vec(),
        ));
    }
    merged_options.sort_canonical();

    let token_length = message.token_length_value().map_err(|_| {
        OscoreError::invalid_field_value(
            "coap.oscore.message.token-length",
            "outer Token Length metadata cannot be decoded",
        )
    })?;
    Ok(Coap::new()
        .version(message.version_value())
        .message_type(message.message_type_value())
        .token_length(token_length)
        .code(inner_code)
        .message_id(message.message_id_value())
        .token(message.token_value().clone())
        .options(merged_options)
        .option_order(CoapOptionOrder::Canonical)
        .payload_marker(payload_marker)
        .payload(inner_payload))
}

fn map_plaintext_decode_error(error: CrafterError) -> OscoreError {
    match error {
        CrafterError::BufferTooShort {
            required,
            available,
            ..
        } => OscoreError::buffer_too_short("coap.oscore.plaintext.options", required, available),
        CrafterError::InvalidFieldValue { .. } | CrafterError::InvalidMacAddress { .. } => {
            OscoreError::invalid_field_value(
                "coap.oscore.plaintext.options",
                "protected option sequence is malformed",
            )
        }
    }
}

fn is_oscore_class_u_only(number: u16) -> bool {
    matches!(
        number,
        COAP_OPTION_URI_HOST
            | COAP_OPTION_URI_PORT
            | COAP_OPTION_PROXY_URI
            | COAP_OPTION_PROXY_SCHEME
    )
}

fn encode_protected_options(
    options: Vec<CoapOption>,
    order: CoapOptionOrder,
    field: &'static str,
) -> Result<Vec<u8>, OscoreError> {
    let mut options = CoapOptions::from_options(options);
    if order == CoapOptionOrder::Canonical {
        options.sort_canonical();
    }
    let mut encoded = Vec::new();
    encode_option_sequence(&options, &mut encoded).map_err(|_| {
        OscoreError::invalid_field_value(field, "protected options cannot be encoded")
    })?;
    Ok(encoded)
}

impl PartialEq for OscoreContext {
    fn eq(&self, other: &Self) -> bool {
        self.aead_algorithm == other.aead_algorithm
            && self.kdf_algorithm == other.kdf_algorithm
            && self.sender_id == other.sender_id
            && self.recipient_id == other.recipient_id
            && self.id_context == other.id_context
            && self.sender_key_info == other.sender_key_info
            && self.recipient_key_info == other.recipient_key_info
            && self.common_iv_info == other.common_iv_info
            && secret_eq(&self.master_secret, &other.master_secret)
            && secret_eq(&self.master_salt, &other.master_salt)
            && secret_eq(&self.sender_key, &other.sender_key)
            && secret_eq(&self.recipient_key, &other.recipient_key)
            && secret_eq(&self.common_iv, &other.common_iv)
    }
}

impl Eq for OscoreContext {}

impl fmt::Debug for OscoreContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OscoreContext")
            .field("aead_algorithm", &self.aead_algorithm)
            .field("kdf_algorithm", &self.kdf_algorithm)
            .field("sender_id", &self.sender_id)
            .field("recipient_id", &self.recipient_id)
            .field("id_context", &self.id_context)
            .field(
                "master_secret",
                &format_args!("<{} bytes redacted>", self.master_secret.len()),
            )
            .field(
                "master_salt",
                &format_args!("<{} bytes redacted>", self.master_salt.len()),
            )
            .field(
                "sender_key",
                &format_args!("<{} bytes redacted>", self.sender_key.len()),
            )
            .field(
                "recipient_key",
                &format_args!("<{} bytes redacted>", self.recipient_key.len()),
            )
            .field(
                "common_iv",
                &format_args!("<{} bytes redacted>", self.common_iv.len()),
            )
            .finish()
    }
}

impl fmt::Display for OscoreContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.summary())
    }
}

impl Drop for OscoreContext {
    fn drop(&mut self) {
        self.master_secret.fill(0);
        self.master_salt.fill(0);
        self.sender_key.fill(0);
        self.recipient_key.fill(0);
        self.common_iv.fill(0);
    }
}

fn secret_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

fn hkdf_extract_sha256(salt: &[u8], input_key_material: &[u8]) -> hmac::digest::Output<HmacSha256> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(salt)
        .expect("HMAC-SHA-256 accepts keys of every OSCORE Master Salt length");
    mac.update(input_key_material);
    mac.finalize().into_bytes()
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Result<Vec<u8>, OscoreError> {
    let block_count = length
        .checked_add(HKDF_SHA_256_OUTPUT_LEN - 1)
        .ok_or_else(|| {
            OscoreError::invalid_field_value(
                "coap.oscore.hkdf.length",
                "HKDF output length overflow",
            )
        })?
        / HKDF_SHA_256_OUTPUT_LEN;
    if block_count > HKDF_MAX_BLOCKS {
        return Err(OscoreError::invalid_field_value(
            "coap.oscore.hkdf.length",
            "HKDF output exceeds 255 hash blocks",
        ));
    }

    let mut output = Vec::with_capacity(length);
    let mut previous = [0u8; HKDF_SHA_256_OUTPUT_LEN];
    let mut previous_len = 0;
    for block_index in 1..=block_count {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(prk)
            .expect("an HKDF-SHA-256 pseudorandom key is a valid HMAC key");
        mac.update(&previous[..previous_len]);
        mac.update(info);
        mac.update(&[u8::try_from(block_index).expect("HKDF block count is at most 255")]);
        let mut block = mac.finalize().into_bytes();
        previous.copy_from_slice(&block);
        previous_len = HKDF_SHA_256_OUTPUT_LEN;

        let remaining = length - output.len();
        let take = remaining.min(HKDF_SHA_256_OUTPUT_LEN);
        output.extend_from_slice(&block[..take]);
        block.as_mut_slice().fill(0);
    }
    previous.fill(0);
    Ok(output)
}

fn validate_oscore_identifier(
    identifier: &[u8],
    maximum_len: usize,
    field: &'static str,
) -> Result<(), OscoreError> {
    if identifier.len() > maximum_len {
        return Err(OscoreError::invalid_field_value(
            field,
            "identifier exceeds the selected AEAD nonce limit",
        ));
    }
    Ok(())
}

fn validate_partial_iv(partial_iv: &[u8], field: &'static str) -> Result<(), OscoreError> {
    if partial_iv.is_empty() {
        return Err(OscoreError::invalid_field_value(
            field,
            "Partial IV must contain at least one byte",
        ));
    }
    if partial_iv.len() > OSCORE_MAX_PARTIAL_IV_LEN {
        return Err(OscoreError::invalid_field_value(
            field,
            "Partial IV exceeds five bytes",
        ));
    }
    Ok(())
}

fn encode_context_info(
    id: &[u8],
    id_context: Option<&[u8]>,
    aead_algorithm: i32,
    kind: &'static str,
    length: usize,
) -> Result<Vec<u8>, OscoreError> {
    let mut out = Vec::new();
    out.push(0x85); // canonical CBOR array(5)
    append_cbor_bytes(id, &mut out)?;
    match id_context {
        Some(value) => append_cbor_bytes(value, &mut out)?,
        None => out.push(0xf6),
    }
    append_cbor_integer(i64::from(aead_algorithm), &mut out);
    append_cbor_text(kind.as_bytes(), &mut out)?;
    append_cbor_unsigned(
        0,
        u64::try_from(length).map_err(|_| {
            OscoreError::invalid_field_value(
                "coap.oscore.context.derivation-info",
                "derivation output length exceeds CBOR integer range",
            )
        })?,
        &mut out,
    );
    Ok(out)
}

fn append_cbor_bytes(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), OscoreError> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        OscoreError::invalid_field_value(
            "coap.oscore.context.derivation-info",
            "byte string length exceeds CBOR integer range",
        )
    })?;
    append_cbor_unsigned(2, length, out);
    out.extend_from_slice(bytes);
    Ok(())
}

fn append_cbor_text(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), OscoreError> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        OscoreError::invalid_field_value(
            "coap.oscore.context.derivation-info",
            "text string length exceeds CBOR integer range",
        )
    })?;
    append_cbor_unsigned(3, length, out);
    out.extend_from_slice(bytes);
    Ok(())
}

fn append_cbor_integer(value: i64, out: &mut Vec<u8>) {
    if value >= 0 {
        append_cbor_unsigned(0, value as u64, out);
    } else {
        append_cbor_unsigned(1, (-1 - value) as u64, out);
    }
}

fn append_cbor_unsigned(major: u8, value: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => {
            out.push(major | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::message::CoapToken;
    use super::*;
    use crate::packet::Packet;

    fn appendix_c_master_secret() -> Vec<u8> {
        (1u8..=16).collect()
    }

    fn appendix_c_master_salt() -> Vec<u8> {
        vec![0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40]
    }

    fn appendix_c_client_context() -> OscoreContext {
        OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
        )
        .unwrap()
    }

    fn appendix_c_server_context() -> OscoreContext {
        OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            vec![0x01],
            Vec::new(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn protect_request_matches_rfc_8613_appendix_c_4() {
        let request = Coap::get()
            .message_id(0x5d1f)
            .token(CoapToken::from_bytes([0x00, 0x00, 0x39, 0x74]))
            .option(CoapOption::new(COAP_OPTION_URI_HOST, b"localhost"))
            .option(CoapOption::new(11, b"tv1"));

        let protected = appendix_c_client_context()
            .protect(&request, OscoreProtectParams::request([0x14]))
            .unwrap();
        assert_eq!(protected.code_value(), CoapCode::post());
        assert_eq!(protected.options_value().len(), 2);
        assert_eq!(
            protected.options_value()[0].number().value(),
            COAP_OPTION_URI_HOST
        );
        assert_eq!(
            protected.options_value()[1].number().value(),
            COAP_OPTION_OSCORE
        );
        assert_eq!(protected.options_value()[1].value(), [0x09, 0x14]);
        assert_eq!(
            Packet::from_layer(protected).compile().unwrap().as_bytes(),
            [
                0x44, 0x02, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
                0x68, 0x6f, 0x73, 0x74, 0x62, 0x09, 0x14, 0xff, 0x61, 0x2f, 0x10, 0x92, 0xf1, 0x77,
                0x6f, 0x1c, 0x16, 0x68, 0xb3, 0x82, 0x5e,
            ]
        );
    }

    #[test]
    fn protect_response_matches_rfc_8613_appendix_c_7() {
        let response = Coap::content()
            .acknowledgement()
            .message_id(0x5d1f)
            .token(CoapToken::from_bytes([0x00, 0x00, 0x39, 0x74]))
            .payload(b"Hello World!");
        let server_context = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            vec![0x01],
            Vec::new(),
            None,
        )
        .unwrap();
        let binding = OscoreRequestBinding::new(Vec::new(), [0x14]).unwrap();

        let protected = server_context
            .protect(&response, OscoreProtectParams::response(binding))
            .unwrap();
        assert_eq!(protected.code_value(), CoapCode::changed());
        assert_eq!(protected.options_value().len(), 1);
        assert_eq!(
            protected.options_value()[0].number().value(),
            COAP_OPTION_OSCORE
        );
        assert!(protected.options_value()[0].value().is_empty());
        assert_eq!(
            Packet::from_layer(protected).compile().unwrap().as_bytes(),
            [
                0x64, 0x44, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x90, 0xff, 0xdb, 0xaa, 0xd1, 0xe9,
                0xa7, 0xe7, 0xb2, 0xa8, 0x13, 0xd3, 0xc3, 0x15, 0x24, 0x37, 0x83, 0x03, 0xcd, 0xaf,
                0xae, 0x11, 0x91, 0x06,
            ]
        );
    }

    #[test]
    fn protect_empty_payload_and_unknown_option_remain_typed() {
        let unknown = CoapOption::new(65_000, [0xde, 0xad]);
        let request = Coap::post().message_id(7).option(unknown.clone());
        let protected = appendix_c_client_context()
            .protect(&request, OscoreProtectParams::request([0x01]))
            .unwrap();

        assert_eq!(protected.payload_marker_value(), CoapPayloadMarker::Present);
        assert_eq!(protected.payload_value().len(), 1 + 3 + 2 + 8);
        assert!(protected
            .options_value()
            .iter()
            .all(|option| option.number().value() != unknown.number().value()));
        assert_eq!(protected.options_value().len(), 1);
        assert_eq!(
            protected.options_value()[0].number().value(),
            COAP_OPTION_OSCORE
        );
        Packet::from_layer(protected).compile().unwrap();
    }

    #[test]
    fn protect_preserves_explicit_outer_header_and_class_u_fields() {
        let token_length = super::super::message::CoapTokenLength::explicit(2, Vec::new(), 2);
        let request = Coap::get()
            .version(3u8)
            .reset()
            .token_length(token_length.clone())
            .message_id(0xabcd)
            .token(CoapToken::from_bytes([0x12, 0x34]))
            .option(CoapOption::new(COAP_OPTION_URI_HOST, b"example.test"));

        let protected = appendix_c_client_context()
            .protect(&request, OscoreProtectParams::request([0x02]))
            .unwrap();

        assert_eq!(protected.version_value().value(), 3);
        assert_eq!(
            protected.message_type_value(),
            super::super::message::CoapMessageType::Reset
        );
        assert_eq!(protected.token_length_value().unwrap(), token_length);
        assert_eq!(protected.message_id_value(), 0xabcd);
        assert_eq!(protected.token_value().as_bytes(), [0x12, 0x34]);
        assert_eq!(
            protected.options_value()[0].number().value(),
            COAP_OPTION_URI_HOST
        );
        assert_eq!(protected.options_value()[0].value(), b"example.test");
    }

    #[test]
    fn unprotect_request_and_response_round_trip_typed_messages() {
        let request = Coap::get()
            .message_id(0x5d1f)
            .token(CoapToken::from_bytes([0x00, 0x00, 0x39, 0x74]))
            .option(CoapOption::new(COAP_OPTION_URI_HOST, b"localhost"))
            .option(CoapOption::new(11, b"tv1"));
        let protected_request = appendix_c_client_context()
            .protect(&request, OscoreProtectParams::request([0x14]))
            .unwrap();
        let recovered_request = appendix_c_server_context()
            .unprotect(&protected_request, OscoreUnprotectParams::request())
            .unwrap();
        assert_eq!(recovered_request.code_value(), CoapCode::get());
        assert_eq!(recovered_request.options_value().len(), 2);
        assert_eq!(
            Packet::from_layer(recovered_request)
                .compile()
                .unwrap()
                .as_bytes(),
            Packet::from_layer(request).compile().unwrap().as_bytes()
        );

        let response = Coap::content()
            .acknowledgement()
            .message_id(0x5d1f)
            .token(CoapToken::from_bytes([0x00, 0x00, 0x39, 0x74]))
            .payload(b"Hello World!");
        let binding = OscoreRequestBinding::new(Vec::new(), [0x14]).unwrap();
        let protected_response = appendix_c_server_context()
            .protect(&response, OscoreProtectParams::response(binding.clone()))
            .unwrap();
        let recovered_response = appendix_c_client_context()
            .unprotect(
                &protected_response,
                OscoreUnprotectParams::response(binding),
            )
            .unwrap();
        assert_eq!(recovered_response.code_value(), CoapCode::content());
        assert_eq!(recovered_response.payload_value(), b"Hello World!");
        assert_eq!(
            Packet::from_layer(recovered_response)
                .compile()
                .unwrap()
                .as_bytes(),
            Packet::from_layer(response).compile().unwrap().as_bytes()
        );
    }

    #[test]
    fn unprotect_preserves_unknown_authenticated_inner_option() {
        let unknown = CoapOption::new(65_000, [0xde, 0xad, 0xbe, 0xef]);
        let request = Coap::post()
            .message_id(7)
            .option(CoapOption::new(COAP_OPTION_URI_HOST, b"example.test"))
            .option(unknown.clone())
            .payload([0x00, 0xff, 0x80]);
        let protected = appendix_c_client_context()
            .protect(&request, OscoreProtectParams::request([0x01]))
            .unwrap();
        let recovered = appendix_c_server_context()
            .unprotect(&protected, OscoreUnprotectParams::request())
            .unwrap();

        assert_eq!(recovered.payload_value(), [0x00, 0xff, 0x80]);
        assert!(recovered.options_value().iter().any(|option| {
            option.number() == unknown.number() && option.value() == unknown.value()
        }));
        assert_eq!(
            Packet::from_layer(recovered).compile().unwrap().as_bytes(),
            Packet::from_layer(request).compile().unwrap().as_bytes()
        );
    }

    #[test]
    fn unprotect_rejects_tampered_ciphertext_tag_and_request_aad() {
        let request = Coap::get().message_id(1).option(CoapOption::new(11, b"s"));
        let protected = appendix_c_client_context()
            .protect(&request, OscoreProtectParams::request([0x14]))
            .unwrap();

        for index in [0, protected.payload_value().len() - 1] {
            let mut tampered_payload = protected.payload_value().to_vec();
            tampered_payload[index] ^= 0x80;
            let tampered = protected.clone().payload(tampered_payload);
            assert_eq!(
                appendix_c_server_context()
                    .unprotect(&tampered, OscoreUnprotectParams::request())
                    .unwrap_err(),
                OscoreError::AuthenticationFailed {
                    context: "coap.oscore.authentication",
                }
            );
        }

        let response = Coap::content().payload(b"bound response");
        let binding = OscoreRequestBinding::new(Vec::new(), [0x14]).unwrap();
        let protected_response = appendix_c_server_context()
            .protect(&response, OscoreProtectParams::response(binding.clone()))
            .unwrap();
        let wrong_binding = OscoreRequestBinding::new(Vec::new(), [0x15]).unwrap();
        assert_eq!(
            appendix_c_client_context()
                .unprotect(
                    &protected_response,
                    OscoreUnprotectParams::response(wrong_binding),
                )
                .unwrap_err(),
            OscoreError::AuthenticationFailed {
                context: "coap.oscore.authentication",
            }
        );
    }

    #[test]
    fn unprotect_rejects_wrong_key_and_identifier_without_exposing_plaintext() {
        let request = Coap::get().payload(b"secret plaintext");
        let protected = appendix_c_client_context()
            .protect(&request, OscoreProtectParams::request([0x02]))
            .unwrap();

        let mut wrong_secret = appendix_c_master_secret();
        wrong_secret[0] ^= 0xff;
        let wrong_key_context = OscoreContext::with_default_algorithms(
            wrong_secret,
            appendix_c_master_salt(),
            vec![0x01],
            Vec::new(),
            None,
        )
        .unwrap();
        let wrong_key_error = wrong_key_context
            .unprotect(&protected, OscoreUnprotectParams::request())
            .unwrap_err();
        assert_eq!(
            wrong_key_error,
            OscoreError::AuthenticationFailed {
                context: "coap.oscore.authentication",
            }
        );
        assert!(!wrong_key_error.to_string().contains("secret plaintext"));

        let mut options = protected.options_value().to_vec();
        let option = options
            .iter_mut()
            .find(|option| option.number().value() == COAP_OPTION_OSCORE)
            .unwrap();
        *option = CoapOption::new(COAP_OPTION_OSCORE, [0x09, 0x02, 0x7f]);
        let wrong_identifier = protected.clone().options(options);
        assert_eq!(
            appendix_c_server_context()
                .unprotect(&wrong_identifier, OscoreUnprotectParams::request())
                .unwrap_err(),
            OscoreError::AuthenticationFailed {
                context: "coap.oscore.authentication",
            }
        );
    }

    #[test]
    fn unprotect_reports_malformed_option_and_truncated_ciphertext() {
        let malformed_option = Coap::post()
            .option(CoapOption::new(COAP_OPTION_OSCORE, [0x05, 0xaa]))
            .payload([0; 9]);
        assert_eq!(
            appendix_c_server_context()
                .unprotect(&malformed_option, OscoreUnprotectParams::request())
                .unwrap_err(),
            OscoreError::BufferTooShort {
                context: "coap.oscore.option.partial-iv",
                required: 5,
                available: 1,
            }
        );

        let truncated = Coap::post()
            .option(CoapOption::new(COAP_OPTION_OSCORE, [0x09, 0x01]))
            .payload([0; 8]);
        assert_eq!(
            appendix_c_server_context()
                .unprotect(&truncated, OscoreUnprotectParams::request())
                .unwrap_err(),
            OscoreError::BufferTooShort {
                context: "coap.oscore.ciphertext",
                required: 9,
                available: 8,
            }
        );
    }

    #[test]
    fn unprotect_authenticates_before_reporting_truncated_inner_payload() {
        let sender = appendix_c_client_context();
        let partial_iv = [0x03];
        let option = OscoreOption::new(
            Some(partial_iv.to_vec()),
            None,
            Some(sender.sender_id().to_vec()),
        )
        .unwrap();
        let nonce = sender.sender_nonce(partial_iv).unwrap();
        let aad = sender
            .cose_encrypt0_aad(sender.sender_id(), partial_iv, [])
            .unwrap();
        let cipher = <OscoreAesCcm as AeadKeyInit>::new_from_slice(sender.sender_key()).unwrap();
        let mut plaintext = vec![CoapCode::get().wire_value(), COAP_PAYLOAD_MARKER];
        let tag = cipher
            .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut plaintext)
            .unwrap();
        plaintext.extend_from_slice(&tag);
        let protected = Coap::post()
            .option(option.into_coap_option())
            .payload(plaintext);

        assert_eq!(
            appendix_c_server_context()
                .unprotect(&protected, OscoreUnprotectParams::request())
                .unwrap_err(),
            OscoreError::BufferTooShort {
                context: "coap.oscore.plaintext.payload",
                required: 1,
                available: 0,
            }
        );
    }

    #[test]
    fn option_preserves_absent_and_explicit_zero_flag_byte() {
        let empty = OscoreOption::parse([]).unwrap();
        let explicit_zero = OscoreOption::parse([0x00]).unwrap();

        assert!(empty.is_empty());
        assert_eq!(empty.flag_byte(), None);
        assert_eq!(empty.to_bytes(), Vec::<u8>::new());
        assert!(!explicit_zero.is_empty());
        assert_eq!(explicit_zero.flag_byte(), Some(0));
        assert_eq!(explicit_zero.to_bytes(), vec![0x00]);
        assert_ne!(empty, explicit_zero);
    }

    #[test]
    fn option_parses_and_serializes_rfc_8613_examples_exactly() {
        // RFC 8613 Appendix C.4: Partial IV 0x14 and an empty, present KID.
        let request = OscoreOption::parse([0x09, 0x14]).unwrap();
        assert_eq!(request.partial_iv(), Some(&[0x14][..]));
        assert_eq!(request.kid_context(), None);
        assert_eq!(request.kid(), Some(&[][..]));
        assert_eq!(request.to_bytes(), vec![0x09, 0x14]);

        // RFC 8613 Section 6.3 example 3: KID Context "Dalek" and empty KID.
        let raw = [0x19, 0x05, 0x05, b'D', b'a', b'l', b'e', b'k'];
        let with_context = OscoreOption::decode(raw).unwrap();
        assert_eq!(with_context.partial_iv(), Some(&[0x05][..]));
        assert_eq!(with_context.kid_context(), Some(&b"Dalek"[..]));
        assert_eq!(with_context.kid(), Some(&[][..]));
        assert_eq!(with_context.as_bytes(), raw);

        let envelope = CoapOption::new(COAP_OPTION_OSCORE, raw);
        let typed = OscoreOption::try_from(&envelope).unwrap();
        let round_trip: CoapOption = typed.into();
        assert_eq!(round_trip.number().value(), COAP_OPTION_OSCORE);
        assert_eq!(round_trip.value(), raw);
    }

    #[test]
    fn canonical_option_builder_preserves_present_empty_fields() {
        let option =
            OscoreOption::new(Some(vec![0x01, 0x02]), Some(Vec::new()), Some(Vec::new())).unwrap();
        assert_eq!(option.as_bytes(), [0x1a, 0x01, 0x02, 0x00]);
        assert_eq!(option.kid_context(), Some(&[][..]));
        assert_eq!(option.kid(), Some(&[][..]));
        assert_eq!(OscoreOption::parse(option.as_bytes()).unwrap(), option);
    }

    #[test]
    fn option_reports_stable_malformed_boundaries() {
        assert_eq!(
            OscoreOption::parse([0x06]).unwrap_err(),
            OscoreError::InvalidFieldValue {
                field: "coap.oscore.option.partial-iv-length",
                reason: "reserved Partial IV length encoding",
            }
        );
        assert_eq!(
            OscoreOption::parse([0x05, 0xaa, 0xbb]).unwrap_err(),
            OscoreError::BufferTooShort {
                context: "coap.oscore.option.partial-iv",
                required: 5,
                available: 2,
            }
        );
        assert_eq!(
            OscoreOption::parse([0x10]).unwrap_err(),
            OscoreError::BufferTooShort {
                context: "coap.oscore.option.kid-context-length",
                required: 1,
                available: 0,
            }
        );
        assert_eq!(
            OscoreOption::parse([0x10, 0x03, 0xaa]).unwrap_err(),
            OscoreError::BufferTooShort {
                context: "coap.oscore.option.kid-context",
                required: 3,
                available: 1,
            }
        );
        assert!(matches!(
            OscoreOption::parse([0x00, 0xaa]).unwrap_err(),
            OscoreError::InvalidFieldValue {
                field: "coap.oscore.option.trailing-bytes",
                ..
            }
        ));

        let provisional = OscoreOption::parse([0x20, 0xaa, 0xbb]).unwrap();
        assert_eq!(provisional.extension_flags(), 0x20);
        assert_eq!(provisional.unparsed_extension(), [0xaa, 0xbb]);
        assert_eq!(provisional.as_bytes(), [0x20, 0xaa, 0xbb]);
    }

    #[test]
    fn context_derivation_matches_rfc_8613_appendix_c_1() {
        let context = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
        )
        .unwrap();

        assert_eq!(
            context.sender_key_derivation_info(),
            [0x85, 0x40, 0xf6, 0x0a, 0x63, b'K', b'e', b'y', 0x10]
        );
        assert_eq!(
            context.recipient_key_derivation_info(),
            [0x85, 0x41, 0x01, 0xf6, 0x0a, 0x63, b'K', b'e', b'y', 0x10]
        );
        assert_eq!(
            context.common_iv_derivation_info(),
            [0x85, 0x40, 0xf6, 0x0a, 0x62, b'I', b'V', 0x0d]
        );
        assert_eq!(
            context.sender_key(),
            [
                0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4, 0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43,
                0x02, 0xff,
            ]
        );
        assert_eq!(
            context.recipient_key(),
            [
                0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca, 0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9,
                0x87, 0x10,
            ]
        );
        assert_eq!(
            context.common_iv(),
            [0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c,]
        );
    }

    #[test]
    fn hkdf_extract_expand_matches_rfc_5869_test_case_1() {
        let input_key_material = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut prk = hkdf_extract_sha256(&salt, &input_key_material);
        assert_eq!(
            prk.as_slice(),
            [
                0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
                0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
                0xd7, 0xc2, 0xb3, 0xe5,
            ]
        );
        assert_eq!(
            hkdf_expand_sha256(&prk, &info, 42).unwrap(),
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
            ]
        );
        assert!(matches!(
            hkdf_expand_sha256(&prk, &info, HKDF_SHA_256_OUTPUT_LEN * HKDF_MAX_BLOCKS + 1),
            Err(OscoreError::InvalidFieldValue {
                field: "coap.oscore.hkdf.length",
                ..
            })
        ));
        prk.as_mut_slice().fill(0);
    }

    #[test]
    fn nonce_construction_matches_rfc_8613_appendices_c_3_and_c_4() {
        let appendix_c_1 = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
        )
        .unwrap();
        assert_eq!(
            appendix_c_1.sender_nonce([0x14]).unwrap(),
            [0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x68]
        );

        let appendix_c_3 = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            Some(vec![0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3]),
        )
        .unwrap();
        assert_eq!(
            appendix_c_3.sender_nonce([0x00]).unwrap(),
            [0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c, 0x0b, 0x71, 0x81, 0xb8, 0x5e]
        );
        assert_eq!(
            appendix_c_3.recipient_nonce([0x00]).unwrap(),
            [0x2d, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1d, 0x0b, 0x71, 0x81, 0xb8, 0x5e]
        );
    }

    #[test]
    fn external_aad_matches_rfc_8613_section_5_4_and_appendix_c_4() {
        let context = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
        )
        .unwrap();

        assert_eq!(
            context.aad_array([], [0x14], []).unwrap(),
            [0x85, 0x01, 0x81, 0x0a, 0x40, 0x41, 0x14, 0x40]
        );
        assert_eq!(
            context.external_aad([], [0x14], []).unwrap(),
            [0x48, 0x85, 0x01, 0x81, 0x0a, 0x40, 0x41, 0x14, 0x40]
        );
        assert_eq!(
            context.cose_encrypt0_aad([], [0x14], []).unwrap(),
            [
                0x83, 0x68, b'E', b'n', b'c', b'r', b'y', b'p', b't', b'0', 0x40, 0x48, 0x85, 0x01,
                0x81, 0x0a, 0x40, 0x41, 0x14, 0x40,
            ]
        );

        assert_eq!(
            context.aad_array([0x00], [0x25], []).unwrap(),
            [0x85, 0x01, 0x81, 0x0a, 0x41, 0x00, 0x41, 0x25, 0x40]
        );
        assert_eq!(
            context.cose_encrypt0_aad([0x00], [0x25], []).unwrap(),
            [
                0x83, 0x68, b'E', b'n', b'c', b'r', b'y', b'p', b't', b'0', 0x40, 0x49, 0x85, 0x01,
                0x81, 0x0a, 0x41, 0x00, 0x41, 0x25, 0x40,
            ]
        );
    }

    #[test]
    fn nonce_and_aad_reject_invalid_identifier_and_partial_iv_lengths() {
        let context = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
        )
        .unwrap();

        assert_eq!(
            context.sender_nonce([]).unwrap_err(),
            OscoreError::InvalidFieldValue {
                field: "coap.oscore.nonce.partial-iv",
                reason: "Partial IV must contain at least one byte",
            }
        );
        assert_eq!(
            context.sender_nonce([0; 6]).unwrap_err(),
            OscoreError::InvalidFieldValue {
                field: "coap.oscore.nonce.partial-iv",
                reason: "Partial IV exceeds five bytes",
            }
        );
        assert_eq!(
            context.aad_array([0; 8], [0x01], []).unwrap_err(),
            OscoreError::InvalidFieldValue {
                field: "coap.oscore.aad.request-kid",
                reason: "identifier exceeds the selected AEAD nonce limit",
            }
        );
        assert_eq!(
            context.aad_array([], [], []).unwrap_err(),
            OscoreError::InvalidFieldValue {
                field: "coap.oscore.aad.request-piv",
                reason: "Partial IV must contain at least one byte",
            }
        );
    }

    #[test]
    fn context_equality_includes_secrets_and_id_context_presence() {
        let make = |secret: Vec<u8>, id_context: Option<Vec<u8>>| {
            OscoreContext::with_default_algorithms(
                secret,
                appendix_c_master_salt(),
                Vec::new(),
                vec![0x01],
                id_context,
            )
            .unwrap()
        };

        let first = make(appendix_c_master_secret(), None);
        let same = make(appendix_c_master_secret(), None);
        let mut changed_secret = appendix_c_master_secret();
        changed_secret[0] ^= 0xff;
        let different_secret = make(changed_secret, None);
        let present_empty_context = make(appendix_c_master_secret(), Some(Vec::new()));

        assert_eq!(first, same);
        assert_ne!(first, different_secret);
        assert_ne!(first, present_empty_context);
        assert_eq!(first.id_context(), None);
        assert_eq!(present_empty_context.id_context(), Some(&[][..]));
    }

    #[test]
    fn context_diagnostics_redact_secret_and_derived_material() {
        let context = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
        )
        .unwrap();
        let debug = format!("{context:?}");
        let display = context.to_string();

        for rendered in [&debug, &display] {
            assert!(rendered.contains("redacted"));
            assert!(!rendered.contains("f0910ed7"));
            assert!(!rendered.contains("01020304"));
            assert!(!rendered.contains("9e7ca922"));
            assert!(!rendered.contains("4622d4dd"));
        }
    }

    #[test]
    fn unsupported_algorithms_and_invalid_ids_are_typed() {
        let unsupported_aead = OscoreContext::new(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
            OscoreAeadAlgorithm::Unknown(65_000),
            OscoreKdfAlgorithm::HkdfSha256,
        )
        .unwrap_err();
        assert_eq!(
            unsupported_aead,
            OscoreError::UnsupportedAeadAlgorithm { id: 65_000 }
        );

        let unsupported_kdf = OscoreContext::new(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            Vec::new(),
            vec![0x01],
            None,
            OscoreAeadAlgorithm::AesCcm16_64_128,
            OscoreKdfAlgorithm::Unknown(7),
        )
        .unwrap_err();
        assert_eq!(
            unsupported_kdf,
            OscoreError::UnsupportedKdfAlgorithm { id: 7 }
        );

        let long_sender = OscoreContext::with_default_algorithms(
            appendix_c_master_secret(),
            appendix_c_master_salt(),
            vec![0; 8],
            vec![0x01],
            None,
        )
        .unwrap_err();
        assert!(matches!(
            long_sender,
            OscoreError::InvalidFieldValue {
                field: "coap.oscore.context.sender-id",
                ..
            }
        ));

        assert_eq!(OscoreAeadAlgorithm::from_id(10).id(), 10);
        assert_eq!(OscoreKdfAlgorithm::from_id(-10).id(), -10);
        assert_eq!(
            OscoreAeadAlgorithm::Unknown(-999).tag_len().unwrap_err(),
            OscoreError::UnsupportedAeadAlgorithm { id: -999 }
        );
    }
}
