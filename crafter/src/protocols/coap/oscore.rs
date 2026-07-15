//! OSCORE option metadata and immutable security-context inputs.
//!
//! The compressed option grammar and context derivation follow RFC 8613
//! Sections 2, 3.1, 3.2.1, and 6.1.  Packet protection remains an explicit
//! later transform; this module does not allocate sequence numbers, replay
//! windows, contexts, or any other protocol state.

use core::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::constants::COAP_OPTION_OSCORE;
use super::option::CoapOption;

const OSCORE_PARTIAL_IV_LENGTH_MASK: u8 = 0x07;
const OSCORE_KID_FLAG: u8 = 0x08;
const OSCORE_KID_CONTEXT_FLAG: u8 = 0x10;
const OSCORE_EXTENSION_FLAGS_MASK: u8 = 0xe0;
const OSCORE_MAX_PARTIAL_IV_LEN: usize = 5;
const OSCORE_MAX_OPTION_LEN: usize = u8::MAX as usize;
const OSCORE_AES_CCM_16_64_128_ID: i32 = 10;
const OSCORE_HKDF_SHA_256_ID: i32 = -10;
const OSCORE_AES_CCM_16_64_128_KEY_LEN: usize = 16;
const OSCORE_AES_CCM_16_64_128_NONCE_LEN: usize = 13;
const OSCORE_AES_CCM_16_64_128_TAG_LEN: usize = 8;
const OSCORE_AES_CCM_16_64_128_MAX_ID_LEN: usize = OSCORE_AES_CCM_16_64_128_NONCE_LEN - 6;

type HmacSha256 = Hmac<Sha256>;

/// AEAD algorithm identifier stored in an OSCORE security context.
///
/// The mandatory RFC 8613 profile is supported directly.  Other COSE
/// identifiers remain inspectable and produce a typed unsupported result when
/// context derivation or packet protection is requested.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OscoreAeadAlgorithm {
    /// AES-CCM-16-64-128 (COSE algorithm 10).
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

impl Default for OscoreAeadAlgorithm {
    fn default() -> Self {
        Self::AesCcm16_64_128
    }
}

/// HMAC-based key-derivation algorithm stored in an OSCORE context.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OscoreKdfAlgorithm {
    /// HKDF SHA-256 (COSE algorithm -10).
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

impl Default for OscoreKdfAlgorithm {
    fn default() -> Self {
        Self::HkdfSha256
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
    pub const fn is_empty(&self) -> bool {
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
        let sender_key = hkdf_expand_sha256(&prk, &sender_key_info, key_len);
        let recipient_key = hkdf_expand_sha256(&prk, &recipient_key_info, key_len);
        let common_iv = hkdf_expand_sha256(&prk, &common_iv_info, nonce_len);
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

    pub(super) fn common_iv(&self) -> &[u8] {
        &self.common_iv
    }
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
    let mut mac = HmacSha256::new_from_slice(salt)
        .expect("HMAC-SHA-256 accepts keys of every OSCORE Master Salt length");
    mac.update(input_key_material);
    mac.finalize().into_bytes()
}

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    debug_assert!(length <= 32);
    let mut mac = HmacSha256::new_from_slice(prk)
        .expect("an HKDF-SHA-256 pseudorandom key is a valid HMAC key");
    mac.update(info);
    mac.update(&[1]);
    let mut block = mac.finalize().into_bytes();
    let output = block[..length].to_vec();
    block.as_mut_slice().fill(0);
    output
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
    use super::*;

    fn appendix_c_master_secret() -> Vec<u8> {
        (1u8..=16).collect()
    }

    fn appendix_c_master_salt() -> Vec<u8> {
        vec![0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40]
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
