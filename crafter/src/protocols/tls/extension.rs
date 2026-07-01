//! TLS extension type helpers.
//!
//! TLS extensions are length-prefixed entries keyed by a raw two-octet
//! `ExtensionType`. This module models the codepoint, a single raw extension
//! entry, and the ordered extension-list framing shared by hello and
//! certificate contexts so unknown or deferred extension bodies stay
//! round-trippable.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
use super::named_group::{
    TlsNamedGroup, TlsNamedGroupList, TLS_NAMED_GROUP_LEN, TLS_NAMED_GROUP_LIST_PREFIX_LEN,
};
use super::signature_scheme::{
    TlsSignatureScheme, TlsSignatureSchemeList, TLS_SIGNATURE_SCHEME_LEN,
    TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN,
};
use super::version::TlsVersion;
use crate::protocols::transport::common::hex_bytes;
use crate::{CrafterError, Result};

/// TLS ExtensionType codepoint width in bytes.
pub const TLS_EXTENSION_TYPE_LEN: usize = 2;
/// TLS extension body length field width in bytes.
pub const TLS_EXTENSION_LENGTH_LEN: usize = 2;
/// TLS extension entry header width in bytes.
pub const TLS_EXTENSION_HEADER_LEN: usize = TLS_EXTENSION_TYPE_LEN + TLS_EXTENSION_LENGTH_LEN;
/// TLS extension-list aggregate length field width in bytes.
pub const TLS_EXTENSION_LIST_LENGTH_LEN: usize = 2;
/// TLS ServerName `NameType` field width in bytes.
pub const TLS_SERVER_NAME_TYPE_LEN: usize = 1;
/// TLS ServerName selected-name length field width in bytes.
pub const TLS_SERVER_NAME_LENGTH_LEN: usize = 2;
/// TLS ServerName entry header width in bytes.
pub const TLS_SERVER_NAME_HEADER_LEN: usize = TLS_SERVER_NAME_TYPE_LEN + TLS_SERVER_NAME_LENGTH_LEN;
/// TLS ServerNameList aggregate length field width in bytes.
pub const TLS_SERVER_NAME_LIST_LENGTH_LEN: usize = 2;
/// TLS ServerName `host_name` NameType value from RFC 6066.
pub const TLS_SERVER_NAME_TYPE_HOST_NAME: u8 = 0;
/// TLS ALPN ProtocolName length field width in bytes.
pub const TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN: usize = 1;
/// TLS ALPN ProtocolNameList aggregate length field width in bytes.
pub const TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN: usize = 2;
/// TLS supported_versions ClientHello vector length field width in bytes.
pub const TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN: usize = 1;
/// TLS supported_versions ProtocolVersion width in bytes.
pub const TLS_SUPPORTED_VERSION_LEN: usize = 2;
/// TLS psk_key_exchange_modes vector length field width in bytes.
pub const TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN: usize = 1;
/// TLS PskKeyExchangeMode width in bytes.
pub const TLS_PSK_KEY_EXCHANGE_MODE_LEN: usize = 1;
/// TLS 1.3 PskKeyExchangeMode `psk_ke`.
pub const TLS_PSK_KEY_EXCHANGE_MODE_PSK_KE: u8 = constants::TLS_PSK_MODE_PSK_KE;
/// TLS 1.3 PskKeyExchangeMode `psk_dhe_ke`.
pub const TLS_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE: u8 = constants::TLS_PSK_MODE_PSK_DHE_KE;
/// TLS pre_shared_key selected_identity width in bytes.
pub const TLS_PRE_SHARED_KEY_SELECTED_IDENTITY_LEN: usize = 2;
/// TLS PSK identity opaque identity length field width in bytes.
pub const TLS_PSK_IDENTITY_LENGTH_LEN: usize = 2;
/// TLS PSK identity obfuscated_ticket_age width in bytes.
pub const TLS_PSK_IDENTITY_OBFUSCATED_TICKET_AGE_LEN: usize = 4;
/// TLS PSK identity fixed header width in bytes.
pub const TLS_PSK_IDENTITY_HEADER_LEN: usize =
    TLS_PSK_IDENTITY_LENGTH_LEN + TLS_PSK_IDENTITY_OBFUSCATED_TICKET_AGE_LEN;
/// TLS PSK identities vector length field width in bytes.
pub const TLS_PSK_IDENTITIES_LENGTH_LEN: usize = 2;
/// TLS PSK binder entry length field width in bytes.
pub const TLS_PSK_BINDER_LENGTH_LEN: usize = 1;
/// TLS PSK binders vector length field width in bytes.
pub const TLS_PSK_BINDERS_LENGTH_LEN: usize = 2;
/// TLS supported_groups NamedGroupList length field width in bytes.
pub const TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN: usize = TLS_NAMED_GROUP_LIST_PREFIX_LEN;
/// TLS supported_groups NamedGroup width in bytes.
pub const TLS_SUPPORTED_GROUP_LEN: usize = TLS_NAMED_GROUP_LEN;
/// TLS signature_algorithms SignatureSchemeList length field width in bytes.
pub const TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN: usize = TLS_SIGNATURE_SCHEME_LIST_PREFIX_LEN;
/// TLS signature_algorithms SignatureScheme width in bytes.
pub const TLS_SIGNATURE_ALGORITHM_LEN: usize = TLS_SIGNATURE_SCHEME_LEN;
/// TLS key_share ClientHello client_shares vector length field width in bytes.
pub const TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN: usize = 2;
/// TLS key_share NamedGroup field width in bytes.
pub const TLS_KEY_SHARE_GROUP_LEN: usize = TLS_NAMED_GROUP_LEN;
/// TLS key_share opaque key_exchange length field width in bytes.
pub const TLS_KEY_SHARE_KEY_EXCHANGE_LENGTH_LEN: usize = 2;
/// TLS key_share KeyShareEntry fixed header width in bytes.
pub const TLS_KEY_SHARE_ENTRY_HEADER_LEN: usize =
    TLS_KEY_SHARE_GROUP_LEN + TLS_KEY_SHARE_KEY_EXCHANGE_LENGTH_LEN;
/// TLS cookie opaque vector length field width in bytes.
pub const TLS_COOKIE_LENGTH_LEN: usize = 2;
/// RFC 8446 minimum cookie length.
pub const TLS_COOKIE_MIN_LEN: usize = 1;
/// RFC 8446 maximum cookie length.
pub const TLS_COOKIE_MAX_LEN: usize = u16::MAX as usize;
/// TLS record_size_limit body width in bytes.
pub const TLS_RECORD_SIZE_LIMIT_LEN: usize = 2;
/// RFC 8449 minimum record_size_limit value.
pub const TLS_RECORD_SIZE_LIMIT_MIN: u16 = 64;
/// RFC 8449 TLS 1.2 and earlier protocol-defined maximum plaintext record size.
pub const TLS_RECORD_SIZE_LIMIT_TLS12_MAX: u16 = 1 << 14;
/// RFC 8449 TLS 1.3 protocol-defined maximum TLSInnerPlaintext size.
pub const TLS_RECORD_SIZE_LIMIT_TLS13_MAX: u16 = (1 << 14) + 1;
/// TLS ec_point_formats vector length field width in bytes.
pub const TLS_EC_POINT_FORMATS_LENGTH_LEN: usize = 1;
/// TLS ECPointFormat wire value width in bytes.
pub const TLS_EC_POINT_FORMAT_LEN: usize = 1;
/// RFC 8422 ECPointFormat `uncompressed`.
pub const TLS_EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0;
/// RFC 8422 ECPointFormat `ansiX962_compressed_prime`, deprecated by RFC 8422.
pub const TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME: u8 = 1;
/// RFC 8422 ECPointFormat `ansiX962_compressed_char2`, deprecated by RFC 8422.
pub const TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2: u8 = 2;
/// TLS CertificateStatusType field width in bytes.
pub const TLS_CERTIFICATE_STATUS_TYPE_LEN: usize = 1;
/// Reserved CertificateStatusType zero value.
pub const TLS_CERTIFICATE_STATUS_TYPE_RESERVED: u8 =
    constants::TLS_CERTIFICATE_STATUS_TYPE_RESERVED;
/// RFC 6066 CertificateStatusType `ocsp`.
pub const TLS_CERTIFICATE_STATUS_TYPE_OCSP: u8 = constants::TLS_CERTIFICATE_STATUS_TYPE_OCSP;
/// RFC 6961 CertificateStatusType `ocsp_multi`, now registry-reserved for TLS 1.3.
pub const TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED: u8 =
    constants::TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED;
/// TLS OCSP ResponderID opaque vector length field width in bytes.
pub const TLS_OCSP_RESPONDER_ID_LENGTH_LEN: usize = 2;
/// RFC 6066 minimum ResponderID length.
pub const TLS_OCSP_RESPONDER_ID_MIN_LEN: usize = 1;
/// RFC 6066 maximum ResponderID length.
pub const TLS_OCSP_RESPONDER_ID_MAX_LEN: usize = u16::MAX as usize;
/// TLS OCSP responder_id_list aggregate length field width in bytes.
pub const TLS_OCSP_RESPONDER_ID_LIST_LENGTH_LEN: usize = 2;
/// TLS OCSP request_extensions opaque vector length field width in bytes.
pub const TLS_OCSP_REQUEST_EXTENSIONS_LENGTH_LEN: usize = 2;
/// RFC 6961 status_request_v2 request list length field width in bytes.
pub const TLS_STATUS_REQUEST_V2_LIST_LENGTH_LEN: usize = 2;
/// RFC 6961 status_request_v2 item request_length field width in bytes.
pub const TLS_STATUS_REQUEST_V2_ITEM_REQUEST_LENGTH_LEN: usize = 2;
/// RFC 6961 status_request_v2 item fixed header width in bytes.
pub const TLS_STATUS_REQUEST_V2_ITEM_HEADER_LEN: usize =
    TLS_CERTIFICATE_STATUS_TYPE_LEN + TLS_STATUS_REQUEST_V2_ITEM_REQUEST_LENGTH_LEN;
/// TLS DistinguishedName opaque vector length field width in bytes.
pub const TLS_DISTINGUISHED_NAME_LENGTH_LEN: usize = 2;
/// RFC 8446 minimum DistinguishedName length.
pub const TLS_DISTINGUISHED_NAME_MIN_LEN: usize = 1;
/// RFC 8446 maximum DistinguishedName length.
pub const TLS_DISTINGUISHED_NAME_MAX_LEN: usize = u16::MAX as usize;
/// TLS certificate_authorities vector length field width in bytes.
pub const TLS_CERTIFICATE_AUTHORITIES_LENGTH_LEN: usize = 2;
/// RFC 8446 minimum certificate_authorities vector body length.
pub const TLS_CERTIFICATE_AUTHORITIES_MIN_LEN: usize =
    TLS_DISTINGUISHED_NAME_LENGTH_LEN + TLS_DISTINGUISHED_NAME_MIN_LEN;
/// RFC 8446 maximum certificate_authorities vector body length.
pub const TLS_CERTIFICATE_AUTHORITIES_MAX_LEN: usize = u16::MAX as usize;
/// TLS OIDFilter certificate_extension_oid length field width in bytes.
pub const TLS_OID_FILTER_OID_LENGTH_LEN: usize = 1;
/// RFC 8446 minimum OIDFilter certificate_extension_oid length.
pub const TLS_OID_FILTER_OID_MIN_LEN: usize = 1;
/// RFC 8446 maximum OIDFilter certificate_extension_oid length.
pub const TLS_OID_FILTER_OID_MAX_LEN: usize = u8::MAX as usize;
/// TLS OIDFilter certificate_extension_values length field width in bytes.
pub const TLS_OID_FILTER_VALUES_LENGTH_LEN: usize = 2;
/// RFC 8446 maximum OIDFilter certificate_extension_values length.
pub const TLS_OID_FILTER_VALUES_MAX_LEN: usize = u16::MAX as usize;
/// TLS oid_filters vector length field width in bytes.
pub const TLS_OID_FILTERS_LENGTH_LEN: usize = 2;
/// RFC 8446 minimum encoded OIDFilter item length.
pub const TLS_OID_FILTER_MIN_LEN: usize =
    TLS_OID_FILTER_OID_LENGTH_LEN + TLS_OID_FILTER_OID_MIN_LEN + TLS_OID_FILTER_VALUES_LENGTH_LEN;
/// RFC 8446 maximum oid_filters vector body length.
pub const TLS_OID_FILTERS_MAX_LEN: usize = u16::MAX as usize;

/// A raw-preserving TLS `ExtensionType` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsExtensionType {
    raw: u16,
}

impl TlsExtensionType {
    /// TLS ExtensionType `server_name`.
    pub const SERVER_NAME: Self = Self::new(constants::TLS_EXTENSION_SERVER_NAME);
    /// TLS ExtensionType `max_fragment_length`.
    pub const MAX_FRAGMENT_LENGTH: Self = Self::new(constants::TLS_EXTENSION_MAX_FRAGMENT_LENGTH);
    /// TLS ExtensionType `status_request`.
    pub const STATUS_REQUEST: Self = Self::new(constants::TLS_EXTENSION_STATUS_REQUEST);
    /// TLS ExtensionType `supported_groups`.
    pub const SUPPORTED_GROUPS: Self = Self::new(constants::TLS_EXTENSION_SUPPORTED_GROUPS);
    /// TLS ExtensionType `ec_point_formats`.
    pub const EC_POINT_FORMATS: Self = Self::new(constants::TLS_EXTENSION_EC_POINT_FORMATS);
    /// TLS ExtensionType `signature_algorithms`.
    pub const SIGNATURE_ALGORITHMS: Self = Self::new(constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS);
    /// TLS ExtensionType `heartbeat`.
    pub const HEARTBEAT: Self = Self::new(constants::TLS_EXTENSION_HEARTBEAT);
    /// TLS ExtensionType `application_layer_protocol_negotiation`.
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: Self =
        Self::new(constants::TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION);
    /// TLS ExtensionType `status_request_v2`.
    pub const STATUS_REQUEST_V2: Self = Self::new(constants::TLS_EXTENSION_STATUS_REQUEST_V2);
    /// TLS ExtensionType `padding`.
    pub const PADDING: Self = Self::new(constants::TLS_EXTENSION_PADDING);
    /// TLS ExtensionType `compress_certificate`.
    pub const COMPRESS_CERTIFICATE: Self = Self::new(constants::TLS_EXTENSION_COMPRESS_CERTIFICATE);
    /// TLS ExtensionType `record_size_limit`.
    pub const RECORD_SIZE_LIMIT: Self = Self::new(constants::TLS_EXTENSION_RECORD_SIZE_LIMIT);
    /// Reserved TLS ExtensionType 40.
    pub const RESERVED_40: Self = Self::new(constants::TLS_EXTENSION_RESERVED_40);
    /// TLS ExtensionType `pre_shared_key`.
    pub const PRE_SHARED_KEY: Self = Self::new(constants::TLS_EXTENSION_PRE_SHARED_KEY);
    /// TLS ExtensionType `early_data`.
    pub const EARLY_DATA: Self = Self::new(constants::TLS_EXTENSION_EARLY_DATA);
    /// TLS ExtensionType `supported_versions`.
    pub const SUPPORTED_VERSIONS: Self = Self::new(constants::TLS_EXTENSION_SUPPORTED_VERSIONS);
    /// TLS ExtensionType `cookie`.
    pub const COOKIE: Self = Self::new(constants::TLS_EXTENSION_COOKIE);
    /// TLS ExtensionType `psk_key_exchange_modes`.
    pub const PSK_KEY_EXCHANGE_MODES: Self =
        Self::new(constants::TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES);
    /// Reserved TLS ExtensionType 46.
    pub const RESERVED_46: Self = Self::new(constants::TLS_EXTENSION_RESERVED_46);
    /// TLS ExtensionType `certificate_authorities`.
    pub const CERTIFICATE_AUTHORITIES: Self =
        Self::new(constants::TLS_EXTENSION_CERTIFICATE_AUTHORITIES);
    /// TLS ExtensionType `oid_filters`.
    pub const OID_FILTERS: Self = Self::new(constants::TLS_EXTENSION_OID_FILTERS);
    /// TLS ExtensionType `post_handshake_auth`.
    pub const POST_HANDSHAKE_AUTH: Self = Self::new(constants::TLS_EXTENSION_POST_HANDSHAKE_AUTH);
    /// TLS ExtensionType `signature_algorithms_cert`.
    pub const SIGNATURE_ALGORITHMS_CERT: Self =
        Self::new(constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT);
    /// TLS ExtensionType `key_share`.
    pub const KEY_SHARE: Self = Self::new(constants::TLS_EXTENSION_KEY_SHARE);
    /// TLS ExtensionType `quic_transport_parameters`, preserved outside TLS-over-TCP.
    pub const QUIC_TRANSPORT_PARAMETERS: Self =
        Self::new(constants::TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
    /// TLS ExtensionType `ech_outer_extensions`, ECH deferred.
    pub const ECH_OUTER_EXTENSIONS: Self = Self::new(constants::TLS_EXTENSION_ECH_OUTER_EXTENSIONS);
    /// TLS ExtensionType `encrypted_client_hello`, ECH deferred.
    pub const ENCRYPTED_CLIENT_HELLO: Self =
        Self::new(constants::TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO);
    /// TLS ExtensionType `renegotiation_info`.
    pub const RENEGOTIATION_INFO: Self = Self::new(constants::TLS_EXTENSION_RENEGOTIATION_INFO);

    /// Preserve a caller-supplied raw two-octet extension type value.
    pub const fn new(raw: u16) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied raw two-octet extension type value.
    pub const fn from_u16(raw: u16) -> Self {
        Self::new(raw)
    }

    /// Decode a big-endian TLS extension type value from exactly two bytes.
    pub const fn from_be_bytes(bytes: [u8; TLS_EXTENSION_TYPE_LEN]) -> Self {
        Self::new(u16::from_be_bytes(bytes))
    }

    /// TLS ExtensionType `server_name` constructor.
    pub const fn server_name() -> Self {
        Self::SERVER_NAME
    }

    /// TLS ExtensionType `status_request` constructor.
    pub const fn status_request() -> Self {
        Self::STATUS_REQUEST
    }

    /// TLS ExtensionType `status_request_v2` constructor.
    pub const fn status_request_v2() -> Self {
        Self::STATUS_REQUEST_V2
    }

    /// TLS ExtensionType `supported_groups` constructor.
    pub const fn supported_groups() -> Self {
        Self::SUPPORTED_GROUPS
    }

    /// TLS ExtensionType `ec_point_formats` constructor.
    pub const fn ec_point_formats() -> Self {
        Self::EC_POINT_FORMATS
    }

    /// TLS ExtensionType `signature_algorithms` constructor.
    pub const fn signature_algorithms() -> Self {
        Self::SIGNATURE_ALGORITHMS
    }

    /// TLS ExtensionType `signature_algorithms_cert` constructor.
    pub const fn signature_algorithms_cert() -> Self {
        Self::SIGNATURE_ALGORITHMS_CERT
    }

    /// TLS ExtensionType `application_layer_protocol_negotiation` constructor.
    pub const fn application_layer_protocol_negotiation() -> Self {
        Self::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    }

    /// TLS ExtensionType `padding` constructor.
    pub const fn padding() -> Self {
        Self::PADDING
    }

    /// TLS ExtensionType `record_size_limit` constructor.
    pub const fn record_size_limit() -> Self {
        Self::RECORD_SIZE_LIMIT
    }

    /// TLS ExtensionType `supported_versions` constructor.
    pub const fn supported_versions() -> Self {
        Self::SUPPORTED_VERSIONS
    }

    /// TLS ExtensionType `cookie` constructor.
    pub const fn cookie() -> Self {
        Self::COOKIE
    }

    /// TLS ExtensionType `certificate_authorities` constructor.
    pub const fn certificate_authorities() -> Self {
        Self::CERTIFICATE_AUTHORITIES
    }

    /// TLS ExtensionType `oid_filters` constructor.
    pub const fn oid_filters() -> Self {
        Self::OID_FILTERS
    }

    /// TLS ExtensionType `pre_shared_key` constructor.
    pub const fn pre_shared_key() -> Self {
        Self::PRE_SHARED_KEY
    }

    /// TLS ExtensionType `key_share` constructor.
    pub const fn key_share() -> Self {
        Self::KEY_SHARE
    }

    /// Return the preserved raw two-octet wire value.
    pub const fn raw(self) -> u16 {
        self.raw
    }

    /// Return the preserved raw two-octet wire value.
    pub const fn as_u16(self) -> u16 {
        self.raw
    }

    /// Return the big-endian two-byte wire encoding.
    pub const fn to_be_bytes(self) -> [u8; TLS_EXTENSION_TYPE_LEN] {
        self.raw.to_be_bytes()
    }

    /// Append the two-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.to_be_bytes());
    }

    /// Return the two-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    /// Decode a TLS extension type from the first two bytes of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (extension_type, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(extension_type)
    }

    /// Decode a TLS extension type from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_EXTENSION_TYPE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.extension.type",
                TLS_EXTENSION_TYPE_LEN,
                bytes.len(),
            ));
        }

        Ok((
            Self::from_be_bytes([bytes[0], bytes[1]]),
            &bytes[TLS_EXTENSION_TYPE_LEN..],
        ))
    }

    /// Return the source-backed extension type name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_extension_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_extension_status(self.raw)
    }

    /// Return true when this extension type has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for extension types selected for default TLS builders.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true for RFC 8701 sparse GREASE extension type values.
    pub const fn is_grease(self) -> bool {
        constants::is_tls_grease_u16(self.raw)
    }

    /// Return true for IANA private-use extension type values.
    pub const fn is_private_use(self) -> bool {
        matches!(self.raw, 0xff00 | 0xff02..=0xffff)
    }

    /// Return true for ECH extension types selected as preserve-only in the codepoint notes.
    pub const fn is_ech(self) -> bool {
        matches!(
            self.raw,
            constants::TLS_EXTENSION_ECH_OUTER_EXTENSIONS
                | constants::TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO
        )
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_extension_label(self.raw)
    }

    /// Stable one-line summary with raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:04x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("extension_type", self.label()),
            ("extension_type_raw", format!("0x{:04x}", self.raw)),
            ("extension_type_status", self.status().label().to_string()),
            ("grease", self.is_grease().to_string()),
            ("private_use", self.is_private_use().to_string()),
            ("ech", self.is_ech().to_string()),
        ]
    }
}

impl From<u16> for TlsExtensionType {
    fn from(value: u16) -> Self {
        Self::new(value)
    }
}

impl From<TlsExtensionType> for u16 {
    fn from(value: TlsExtensionType) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsExtensionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// A raw-preserving single TLS extension entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsRawExtension {
    extension_type: TlsExtensionType,
    body: Vec<u8>,
}

impl TlsRawExtension {
    /// Create a raw extension entry from an extension type and body bytes.
    pub fn new(extension_type: impl Into<TlsExtensionType>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            extension_type: extension_type.into(),
            body: body.into(),
        }
    }

    /// Create a raw extension entry from a raw two-octet extension type value.
    pub fn from_raw(extension_type: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::new(TlsExtensionType::from_u16(extension_type), body)
    }

    /// Return the preserved extension type.
    pub const fn extension_type(&self) -> TlsExtensionType {
        self.extension_type
    }

    /// Return the preserved raw extension type value.
    pub const fn raw_type(&self) -> u16 {
        self.extension_type.raw()
    }

    /// Borrow the preserved extension body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Consume the raw extension and return the body bytes.
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Number of bytes in the extension body.
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Number of bytes in the complete encoded extension entry.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_EXTENSION_HEADER_LEN
            .checked_add(self.body.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.extension.length", "length overflow")
            })
    }

    /// Append the extension entry with uint16 body length to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let body_len = u16::try_from(self.body.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.extension.length",
                "length must fit in two bytes",
            )
        })?;

        self.extension_type.encode(out);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(())
    }

    /// Return the encoded extension entry.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one TLS extension entry from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (extension, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(extension)
    }

    /// Decode one TLS extension entry from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_EXTENSION_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.extension",
                TLS_EXTENSION_HEADER_LEN,
                bytes.len(),
            ));
        }

        let extension_type = TlsExtensionType::from_be_bytes([bytes[0], bytes[1]]);
        let body_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let required = TLS_EXTENSION_HEADER_LEN + body_len;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.extension.body",
                required,
                bytes.len(),
            ));
        }

        let body = bytes[TLS_EXTENSION_HEADER_LEN..required].to_vec();
        Ok((Self::new(extension_type, body), &bytes[required..]))
    }

    /// Stable one-line summary preserving the type and body size.
    pub fn summary(&self) -> String {
        format!(
            "extension type={} raw=0x{:04x} body_bytes={}",
            self.extension_type.label(),
            self.extension_type.raw(),
            self.body.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("extension_type", self.extension_type.label()),
            (
                "extension_type_raw",
                format!("0x{:04x}", self.extension_type.raw()),
            ),
            (
                "extension_type_status",
                self.extension_type.status().label().to_string(),
            ),
            ("extension_body_bytes", self.body.len().to_string()),
        ]
    }
}

/// Raw-preserving TLS CertificateStatusType value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsCertificateStatusType {
    raw: u8,
}

impl TlsCertificateStatusType {
    /// Reserved CertificateStatusType zero value.
    pub const RESERVED: Self = Self::new(TLS_CERTIFICATE_STATUS_TYPE_RESERVED);
    /// RFC 6066 `ocsp` status type.
    pub const OCSP: Self = Self::new(TLS_CERTIFICATE_STATUS_TYPE_OCSP);
    /// RFC 6961 `ocsp_multi`, now registry-reserved for TLS 1.3.
    pub const OCSP_MULTI_RESERVED: Self =
        Self::new(TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED);

    /// Preserve a caller-supplied one-octet certificate status type value.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied one-octet certificate status type value.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// Decode a TLS certificate status type from exactly one byte.
    pub const fn from_be_bytes(bytes: [u8; TLS_CERTIFICATE_STATUS_TYPE_LEN]) -> Self {
        Self::new(bytes[0])
    }

    /// Reserved CertificateStatusType zero constructor.
    pub const fn reserved() -> Self {
        Self::RESERVED
    }

    /// RFC 6066 `ocsp` constructor.
    pub const fn ocsp() -> Self {
        Self::OCSP
    }

    /// RFC 6961 `ocsp_multi` constructor for legacy status_request_v2 bodies.
    pub const fn ocsp_multi_reserved() -> Self {
        Self::OCSP_MULTI_RESERVED
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the one-byte wire encoding.
    pub const fn to_be_bytes(self) -> [u8; TLS_CERTIFICATE_STATUS_TYPE_LEN] {
        [self.raw]
    }

    /// Append the one-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.push(self.raw);
    }

    /// Return the one-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    /// Decode a TLS certificate status type from the first byte of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (status_type, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(status_type)
    }

    /// Decode a TLS certificate status type from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_CERTIFICATE_STATUS_TYPE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.certificate_status_type",
                TLS_CERTIFICATE_STATUS_TYPE_LEN,
                bytes.len(),
            ));
        }

        Ok((Self::from_be_bytes([bytes[0]]), &bytes[1..]))
    }

    /// Return the source-backed certificate status type name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_certificate_status_type_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_certificate_status_type_status(self.raw)
    }

    /// Return true for RFC 6066 `ocsp`.
    pub const fn is_ocsp(self) -> bool {
        self.raw == TLS_CERTIFICATE_STATUS_TYPE_OCSP
    }

    /// Return true for RFC 6961 `ocsp_multi`, now registry-reserved for TLS 1.3.
    pub const fn is_ocsp_multi_reserved(self) -> bool {
        self.raw == TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED
    }

    /// Return true for status types with the RFC 6066/RFC 6961 OCSP request grammar.
    pub const fn uses_ocsp_status_request(self) -> bool {
        self.is_ocsp() || self.is_ocsp_multi_reserved()
    }

    /// Return true when this is the reserved zero value.
    pub const fn is_reserved(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::Reserved)
    }

    /// Return true when this value is unassigned in the IANA registry.
    pub const fn is_unassigned(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::Unassigned)
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_certificate_status_type_label(self.raw)
    }

    /// Stable one-line summary preserving raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:02x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("certificate_status_type", self.label()),
            ("certificate_status_type_raw", format!("0x{:02x}", self.raw)),
            (
                "certificate_status_type_status",
                self.status().label().to_string(),
            ),
        ]
    }
}

impl From<u8> for TlsCertificateStatusType {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsCertificateStatusType> for u8 {
    fn from(value: TlsCertificateStatusType) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsCertificateStatusType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// RFC 6066/RFC 6961 opaque OCSP ResponderID vector entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsOcspResponderId {
    bytes: Vec<u8>,
}

impl TlsOcspResponderId {
    /// Create a ResponderID from caller-provided DER bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Create a ResponderID from caller-provided DER bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(bytes)
    }

    /// Borrow the preserved opaque ResponderID bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the ResponderID and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of opaque ResponderID bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no opaque bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Number of bytes occupied by this length-prefixed ResponderID.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_ocsp_responder_id_len(self.bytes.len())?;
        TLS_OCSP_RESPONDER_ID_LENGTH_LEN
            .checked_add(self.bytes.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request.ocsp.responder_id.length",
                    "length overflow",
                )
            })
    }

    /// Append this length-prefixed ResponderID to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_ocsp_responder_id_len(self.bytes.len())?;
        let len = u16::try_from(self.bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.status_request.ocsp.responder_id.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(())
    }

    /// Return this length-prefixed ResponderID encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one length-prefixed ResponderID.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (responder_id, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.status_request.ocsp.responder_id.length",
                "length must match buffer",
            ));
        }
        Ok(responder_id)
    }

    /// Decode one length-prefixed ResponderID from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_OCSP_RESPONDER_ID_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request.ocsp.responder_id.length",
                TLS_OCSP_RESPONDER_ID_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_ocsp_responder_id_len(len)?;
        let required = TLS_OCSP_RESPONDER_ID_LENGTH_LEN
            .checked_add(len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request.ocsp.responder_id.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request.ocsp.responder_id",
                required,
                bytes.len(),
            ));
        }

        Ok((
            Self::new(bytes[TLS_OCSP_RESPONDER_ID_LENGTH_LEN..required].to_vec()),
            &bytes[required..],
        ))
    }

    /// Stable one-line summary preserving opaque ResponderID size.
    pub fn summary(&self) -> String {
        format!("ocsp_responder_id bytes={}", self.bytes.len())
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("ocsp_responder_id_bytes", self.bytes.len().to_string()),
            ("ocsp_responder_id", hex_bytes(&self.bytes)),
        ]
    }
}

impl From<Vec<u8>> for TlsOcspResponderId {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for TlsOcspResponderId {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for TlsOcspResponderId {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(Vec::from(bytes))
    }
}

/// Ordered RFC 6066/RFC 6961 responder_id_list vector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsOcspResponderIds {
    responder_ids: Vec<TlsOcspResponderId>,
}

impl TlsOcspResponderIds {
    /// Create an ordered responder_id_list.
    pub fn new(responder_ids: impl Into<Vec<TlsOcspResponderId>>) -> Self {
        Self {
            responder_ids: responder_ids.into(),
        }
    }

    /// Create an ordered responder_id_list from opaque ResponderID byte vectors.
    pub fn from_bytes_iter<I, B>(responder_ids: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: Into<TlsOcspResponderId>,
    {
        Self::new(
            responder_ids
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
        )
    }

    /// Borrow the ordered ResponderID values.
    pub fn responder_ids(&self) -> &[TlsOcspResponderId] {
        &self.responder_ids
    }

    /// Return the ordered ResponderID byte lengths.
    pub fn byte_lengths(&self) -> Vec<usize> {
        self.responder_ids.iter().map(|id| id.len()).collect()
    }

    /// Consume the list and return the ordered ResponderID values.
    pub fn into_vec(self) -> Vec<TlsOcspResponderId> {
        self.responder_ids
    }

    /// Append one ResponderID.
    pub fn push(&mut self, responder_id: impl Into<TlsOcspResponderId>) {
        self.responder_ids.push(responder_id.into());
    }

    /// Number of ResponderID values.
    pub fn len(&self) -> usize {
        self.responder_ids.len()
    }

    /// Return true when the responder_id_list is empty.
    pub fn is_empty(&self) -> bool {
        self.responder_ids.is_empty()
    }

    /// Number of bytes occupied by responder_id_list entries, excluding the list prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let mut byte_len = 0usize;
        for responder_id in &self.responder_ids {
            byte_len = byte_len
                .checked_add(responder_id.encoded_len()?)
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(
                        "tls.status_request.ocsp.responder_id_list.length",
                        "length overflow",
                    )
                })?;
        }
        validate_ocsp_responder_id_list_len(byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete responder_id_list.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_OCSP_RESPONDER_ID_LIST_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request.ocsp.responder_id_list.length",
                    "length overflow",
                )
            })
    }

    /// Append the responder_id_list to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let byte_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.status_request.ocsp.responder_id_list.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&byte_len.to_be_bytes());
        for responder_id in &self.responder_ids {
            responder_id.encode(out)?;
        }
        Ok(())
    }

    /// Return the responder_id_list encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a responder_id_list.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (responder_ids, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.status_request.ocsp.responder_id_list.length",
                "length must match buffer",
            ));
        }
        Ok(responder_ids)
    }

    /// Decode a responder_id_list from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_OCSP_RESPONDER_ID_LIST_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request.ocsp.responder_id_list.length",
                TLS_OCSP_RESPONDER_ID_LIST_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_ocsp_responder_id_list_len(byte_len)?;
        let required = TLS_OCSP_RESPONDER_ID_LIST_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request.ocsp.responder_id_list.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request.ocsp.responder_id_list",
                required,
                bytes.len(),
            ));
        }

        let mut entries = Vec::new();
        let mut cursor = &bytes[TLS_OCSP_RESPONDER_ID_LIST_LENGTH_LEN..required];
        while !cursor.is_empty() {
            let (responder_id, tail) = TlsOcspResponderId::decode_prefix(cursor)?;
            entries.push(responder_id);
            cursor = tail;
        }

        Ok((Self::new(entries), &bytes[required..]))
    }

    /// Stable one-line summary preserving responder count and byte sizes.
    pub fn summary(&self) -> String {
        format!(
            "ocsp_responder_ids count={} bytes={} responder_lengths={}",
            self.len(),
            self.byte_lengths().iter().sum::<usize>(),
            self.byte_lengths()
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("ocsp_responder_ids_count", self.len().to_string()),
            (
                "ocsp_responder_ids_bytes",
                self.byte_lengths().iter().sum::<usize>().to_string(),
            ),
            (
                "ocsp_responder_id_lengths",
                self.byte_lengths()
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "ocsp_responder_ids",
                self.responder_ids
                    .iter()
                    .map(|id| hex_bytes(id.bytes()))
                    .collect::<Vec<_>>()
                    .join("|"),
            ),
        ]
    }
}

impl From<Vec<TlsOcspResponderId>> for TlsOcspResponderIds {
    fn from(responder_ids: Vec<TlsOcspResponderId>) -> Self {
        Self::new(responder_ids)
    }
}

impl<const N: usize> From<[TlsOcspResponderId; N]> for TlsOcspResponderIds {
    fn from(responder_ids: [TlsOcspResponderId; N]) -> Self {
        Self::new(Vec::from(responder_ids))
    }
}

impl From<TlsOcspResponderId> for TlsOcspResponderIds {
    fn from(responder_id: TlsOcspResponderId) -> Self {
        Self::new(vec![responder_id])
    }
}

/// RFC 6066/RFC 6961 OCSPStatusRequest with opaque DER fields preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsOcspStatusRequest {
    responder_ids: TlsOcspResponderIds,
    request_extensions: Vec<u8>,
}

impl TlsOcspStatusRequest {
    /// Create an OCSPStatusRequest from responder IDs and request-extension bytes.
    pub fn new(
        responder_ids: impl Into<TlsOcspResponderIds>,
        request_extensions: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            responder_ids: responder_ids.into(),
            request_extensions: request_extensions.into(),
        }
    }

    /// Create an OCSPStatusRequest with empty responder_id_list and request_extensions.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an OCSPStatusRequest from opaque ResponderID byte vectors.
    pub fn from_responder_bytes<I, B>(
        responder_ids: I,
        request_extensions: impl Into<Vec<u8>>,
    ) -> Self
    where
        I: IntoIterator<Item = B>,
        B: Into<TlsOcspResponderId>,
    {
        Self::new(
            TlsOcspResponderIds::from_bytes_iter(responder_ids),
            request_extensions,
        )
    }

    /// Borrow the ordered ResponderID list.
    pub const fn responder_id_list(&self) -> &TlsOcspResponderIds {
        &self.responder_ids
    }

    /// Borrow the ordered ResponderID values.
    pub fn responder_ids(&self) -> &[TlsOcspResponderId] {
        self.responder_ids.responder_ids()
    }

    /// Borrow the preserved opaque request_extensions bytes.
    pub fn request_extensions(&self) -> &[u8] {
        &self.request_extensions
    }

    /// Consume the body and return its ResponderIDs and request_extensions.
    pub fn into_parts(self) -> (TlsOcspResponderIds, Vec<u8>) {
        (self.responder_ids, self.request_extensions)
    }

    /// Number of ResponderID values.
    pub fn responder_id_count(&self) -> usize {
        self.responder_ids.len()
    }

    /// Return true when the responder_id_list is empty.
    pub fn responder_id_list_is_empty(&self) -> bool {
        self.responder_ids.is_empty()
    }

    /// Number of request_extensions bytes.
    pub fn request_extensions_len(&self) -> usize {
        self.request_extensions.len()
    }

    /// Number of bytes occupied by this OCSPStatusRequest.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_ocsp_request_extensions_len(self.request_extensions.len())?;
        let len = self
            .responder_ids
            .encoded_len()?
            .checked_add(TLS_OCSP_REQUEST_EXTENSIONS_LENGTH_LEN)
            .and_then(|len| len.checked_add(self.request_extensions.len()))
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request.ocsp.length",
                    "length overflow",
                )
            })?;
        validate_ocsp_status_request_len(len)?;
        Ok(len)
    }

    /// Append this OCSPStatusRequest to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start_len = out.len();
        validate_ocsp_request_extensions_len(self.request_extensions.len())?;
        self.responder_ids.encode(out)?;
        let request_extensions_len =
            u16::try_from(self.request_extensions.len()).map_err(|_| {
                CrafterError::invalid_field_value(
                    "tls.status_request.ocsp.request_extensions.length",
                    "length must fit in two bytes",
                )
            })?;
        out.extend_from_slice(&request_extensions_len.to_be_bytes());
        out.extend_from_slice(&self.request_extensions);
        validate_ocsp_status_request_len(out.len() - start_len)?;
        Ok(())
    }

    /// Return this OCSPStatusRequest encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode an OCSPStatusRequest body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (request, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.status_request.ocsp.length",
                "length must match buffer",
            ));
        }
        Ok(request)
    }

    /// Decode an OCSPStatusRequest body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (responder_ids, tail) = TlsOcspResponderIds::decode_prefix(bytes)?;
        if tail.len() < TLS_OCSP_REQUEST_EXTENSIONS_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request.ocsp.request_extensions.length",
                TLS_OCSP_REQUEST_EXTENSIONS_LENGTH_LEN,
                tail.len(),
            ));
        }

        let extensions_len = u16::from_be_bytes([tail[0], tail[1]]) as usize;
        validate_ocsp_request_extensions_len(extensions_len)?;
        let required = TLS_OCSP_REQUEST_EXTENSIONS_LENGTH_LEN
            .checked_add(extensions_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request.ocsp.request_extensions.length",
                    "length overflow",
                )
            })?;
        if tail.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request.ocsp.request_extensions",
                required,
                tail.len(),
            ));
        }

        let request = Self::new(
            responder_ids,
            tail[TLS_OCSP_REQUEST_EXTENSIONS_LENGTH_LEN..required].to_vec(),
        );
        validate_ocsp_status_request_len(request.encoded_len()?)?;
        Ok((request, &tail[required..]))
    }

    /// Stable one-line summary preserving opaque vector sizes.
    pub fn summary(&self) -> String {
        format!(
            "ocsp_status_request responders={} responder_bytes={} request_extensions_bytes={}",
            self.responder_id_count(),
            self.responder_ids.byte_lengths().iter().sum::<usize>(),
            self.request_extensions.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = self.responder_ids.inspection_fields();
        fields.extend([
            (
                "ocsp_request_extensions_bytes",
                self.request_extensions.len().to_string(),
            ),
            (
                "ocsp_request_extensions",
                hex_bytes(&self.request_extensions),
            ),
        ]);
        fields
    }
}

impl From<(TlsOcspResponderIds, Vec<u8>)> for TlsOcspStatusRequest {
    fn from(value: (TlsOcspResponderIds, Vec<u8>)) -> Self {
        Self::new(value.0, value.1)
    }
}

/// Raw-preserving body for a status request selected by CertificateStatusType.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsStatusRequestBody {
    /// RFC 6066/RFC 6961 OCSPStatusRequest.
    Ocsp(TlsOcspStatusRequest),
    /// Unknown status-type request bytes, preserved exactly.
    Opaque(Vec<u8>),
}

impl TlsStatusRequestBody {
    /// Create an OCSPStatusRequest body.
    pub fn ocsp(request: impl Into<TlsOcspStatusRequest>) -> Self {
        Self::Ocsp(request.into())
    }

    /// Preserve unknown request bytes.
    pub fn opaque(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Opaque(bytes.into())
    }

    /// Return true when this body is an OCSPStatusRequest.
    pub const fn is_ocsp(&self) -> bool {
        matches!(self, Self::Ocsp(_))
    }

    /// Borrow the OCSPStatusRequest when available.
    pub const fn as_ocsp(&self) -> Option<&TlsOcspStatusRequest> {
        match self {
            Self::Ocsp(request) => Some(request),
            Self::Opaque(_) => None,
        }
    }

    /// Borrow opaque unknown request bytes when available.
    pub fn opaque_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Opaque(bytes) => Some(bytes),
            Self::Ocsp(_) => None,
        }
    }

    /// Number of bytes occupied by this request body.
    pub fn encoded_len(&self) -> Result<usize> {
        match self {
            Self::Ocsp(request) => request.encoded_len(),
            Self::Opaque(bytes) => {
                validate_status_request_opaque_len(bytes.len())?;
                Ok(bytes.len())
            }
        }
    }

    /// Append this request body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Ocsp(request) => request.encode(out),
            Self::Opaque(bytes) => {
                validate_status_request_opaque_len(bytes.len())?;
                out.extend_from_slice(bytes);
                Ok(())
            }
        }
    }

    /// Return this request body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    fn summary_kind(&self) -> &'static str {
        match self {
            Self::Ocsp(_) => "ocsp",
            Self::Opaque(_) => "opaque",
        }
    }
}

impl From<TlsOcspStatusRequest> for TlsStatusRequestBody {
    fn from(request: TlsOcspStatusRequest) -> Self {
        Self::Ocsp(request)
    }
}

impl From<Vec<u8>> for TlsStatusRequestBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self::Opaque(bytes)
    }
}

impl From<&[u8]> for TlsStatusRequestBody {
    fn from(bytes: &[u8]) -> Self {
        Self::Opaque(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for TlsStatusRequestBody {
    fn from(bytes: [u8; N]) -> Self {
        Self::Opaque(Vec::from(bytes))
    }
}

/// RFC 6066 `status_request` CertificateStatusRequest extension body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsStatusRequest {
    status_type: TlsCertificateStatusType,
    request: TlsStatusRequestBody,
}

impl TlsStatusRequest {
    /// Create a status_request body, preserving the status type and request bytes.
    pub fn new(
        status_type: impl Into<TlsCertificateStatusType>,
        request: impl Into<TlsStatusRequestBody>,
    ) -> Self {
        Self {
            status_type: status_type.into(),
            request: request.into(),
        }
    }

    /// Create a status_request body with RFC 6066 `ocsp` grammar.
    pub fn ocsp(request: impl Into<TlsOcspStatusRequest>) -> Self {
        Self::new(TlsCertificateStatusType::OCSP, request.into())
    }

    /// Create a status_request body for an unknown status type, preserving request bytes.
    pub fn unknown(
        status_type: impl Into<TlsCertificateStatusType>,
        request: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(status_type, TlsStatusRequestBody::opaque(request))
    }

    /// Return the preserved certificate status type.
    pub const fn status_type(&self) -> TlsCertificateStatusType {
        self.status_type
    }

    /// Borrow the selected request body.
    pub const fn request(&self) -> &TlsStatusRequestBody {
        &self.request
    }

    /// Borrow the OCSPStatusRequest when this body carries one.
    pub const fn ocsp_request(&self) -> Option<&TlsOcspStatusRequest> {
        self.request.as_ocsp()
    }

    /// Number of bytes occupied by this status_request extension body.
    pub fn encoded_len(&self) -> Result<usize> {
        let len = TLS_CERTIFICATE_STATUS_TYPE_LEN
            .checked_add(self.request.encoded_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.status_request.length", "length overflow")
            })?;
        validate_status_request_len(len)?;
        Ok(len)
    }

    /// Append this status_request extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start_len = out.len();
        self.status_type.encode(out);
        self.request.encode(out)?;
        validate_status_request_len(out.len() - start_len)?;
        Ok(())
    }

    /// Return this status_request extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this body into a raw `status_request` extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::STATUS_REQUEST,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a status_request extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (request, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.status_request.length",
                "length must match extension body",
            ));
        }
        Ok(request)
    }

    /// Decode a status_request body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_CERTIFICATE_STATUS_TYPE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request.status_type",
                TLS_CERTIFICATE_STATUS_TYPE_LEN,
                bytes.len(),
            ));
        }

        let status_type = TlsCertificateStatusType::from_be_bytes([bytes[0]]);
        let request_bytes = &bytes[TLS_CERTIFICATE_STATUS_TYPE_LEN..];
        if status_type.is_ocsp() {
            let (request, tail) = TlsOcspStatusRequest::decode_prefix(request_bytes)?;
            return Ok((Self::ocsp(request), tail));
        }

        Ok((Self::unknown(status_type, request_bytes.to_vec()), &[]))
    }

    /// Decode a raw `status_request` extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::STATUS_REQUEST {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be status_request",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving status type and opaque sizes.
    pub fn summary(&self) -> String {
        format!(
            "status_request status_type={} raw=0x{:02x} request={} request_bytes={}",
            self.status_type.label(),
            self.status_type.raw(),
            self.request.summary_kind(),
            self.request.encoded_len().unwrap_or(0)
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("status_request_status_type", self.status_type.label()),
            (
                "status_request_status_type_raw",
                format!("0x{:02x}", self.status_type.raw()),
            ),
            (
                "status_request_status_type_status",
                self.status_type.status().label().to_string(),
            ),
            (
                "status_request_body_kind",
                self.request.summary_kind().to_string(),
            ),
            (
                "status_request_body_bytes",
                self.request.encoded_len().unwrap_or(0).to_string(),
            ),
        ];
        match &self.request {
            TlsStatusRequestBody::Ocsp(request) => fields.extend(request.inspection_fields()),
            TlsStatusRequestBody::Opaque(bytes) => {
                fields.push(("status_request_opaque", hex_bytes(bytes)));
            }
        }
        fields
    }
}

impl From<TlsOcspStatusRequest> for TlsStatusRequest {
    fn from(request: TlsOcspStatusRequest) -> Self {
        Self::ocsp(request)
    }
}

impl TryFrom<&TlsRawExtension> for TlsStatusRequest {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsStatusRequest> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsStatusRequest) -> Result<Self> {
        value.to_raw_extension()
    }
}

/// RFC 6961 status_request_v2 item.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsStatusRequestV2Item {
    status_type: TlsCertificateStatusType,
    request: TlsStatusRequestBody,
}

impl TlsStatusRequestV2Item {
    /// Create a status_request_v2 item, preserving the status type and request bytes.
    pub fn new(
        status_type: impl Into<TlsCertificateStatusType>,
        request: impl Into<TlsStatusRequestBody>,
    ) -> Self {
        Self {
            status_type: status_type.into(),
            request: request.into(),
        }
    }

    /// Create an RFC 6961 `ocsp` item.
    pub fn ocsp(request: impl Into<TlsOcspStatusRequest>) -> Self {
        Self::new(TlsCertificateStatusType::OCSP, request.into())
    }

    /// Create an RFC 6961 legacy `ocsp_multi` item, preserving the current registry status.
    pub fn ocsp_multi(request: impl Into<TlsOcspStatusRequest>) -> Self {
        Self::new(
            TlsCertificateStatusType::OCSP_MULTI_RESERVED,
            request.into(),
        )
    }

    /// Create an item for an unknown status type, preserving request bytes.
    pub fn unknown(
        status_type: impl Into<TlsCertificateStatusType>,
        request: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(status_type, TlsStatusRequestBody::opaque(request))
    }

    /// Return the preserved certificate status type.
    pub const fn status_type(&self) -> TlsCertificateStatusType {
        self.status_type
    }

    /// Borrow the selected request body.
    pub const fn request(&self) -> &TlsStatusRequestBody {
        &self.request
    }

    /// Borrow the OCSPStatusRequest when this item carries one.
    pub const fn ocsp_request(&self) -> Option<&TlsOcspStatusRequest> {
        self.request.as_ocsp()
    }

    /// Number of request bytes.
    pub fn request_len(&self) -> Result<usize> {
        self.request.encoded_len()
    }

    /// Number of bytes occupied by this status_request_v2 item.
    pub fn encoded_len(&self) -> Result<usize> {
        let request_len = self.request_len()?;
        validate_status_request_v2_item_request_len(request_len)?;
        TLS_STATUS_REQUEST_V2_ITEM_HEADER_LEN
            .checked_add(request_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request_v2.item.length",
                    "length overflow",
                )
            })
    }

    /// Append this status_request_v2 item to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let request = self.request.encode_to_vec()?;
        validate_status_request_v2_item_request_len(request.len())?;
        self.status_type.encode(out);
        let request_len = u16::try_from(request.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.status_request_v2.item.request.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&request_len.to_be_bytes());
        out.extend_from_slice(&request);
        Ok(())
    }

    /// Return this status_request_v2 item encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one status_request_v2 item.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (item, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.status_request_v2.item.length",
                "length must match buffer",
            ));
        }
        Ok(item)
    }

    /// Decode one status_request_v2 item from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_STATUS_REQUEST_V2_ITEM_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request_v2.item",
                TLS_STATUS_REQUEST_V2_ITEM_HEADER_LEN,
                bytes.len(),
            ));
        }

        let status_type = TlsCertificateStatusType::from_be_bytes([bytes[0]]);
        let request_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        validate_status_request_v2_item_request_len(request_len)?;
        let required = TLS_STATUS_REQUEST_V2_ITEM_HEADER_LEN
            .checked_add(request_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.status_request_v2.item.request.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request_v2.item.request",
                required,
                bytes.len(),
            ));
        }

        let request_bytes = &bytes[TLS_STATUS_REQUEST_V2_ITEM_HEADER_LEN..required];
        let request = if status_type.uses_ocsp_status_request() {
            TlsStatusRequestBody::ocsp(TlsOcspStatusRequest::decode(request_bytes)?)
        } else {
            TlsStatusRequestBody::opaque(request_bytes.to_vec())
        };

        Ok((Self::new(status_type, request), &bytes[required..]))
    }

    /// Stable one-line summary preserving status type and request size.
    pub fn summary(&self) -> String {
        format!(
            "status_request_v2_item status_type={} raw=0x{:02x} request={} request_bytes={}",
            self.status_type.label(),
            self.status_type.raw(),
            self.request.summary_kind(),
            self.request_len().unwrap_or(0)
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "status_request_v2_item_status_type",
                self.status_type.label(),
            ),
            (
                "status_request_v2_item_status_type_raw",
                format!("0x{:02x}", self.status_type.raw()),
            ),
            (
                "status_request_v2_item_status_type_status",
                self.status_type.status().label().to_string(),
            ),
            (
                "status_request_v2_item_request_kind",
                self.request.summary_kind().to_string(),
            ),
            (
                "status_request_v2_item_request_bytes",
                self.request_len().unwrap_or(0).to_string(),
            ),
        ];
        match &self.request {
            TlsStatusRequestBody::Ocsp(request) => fields.extend(request.inspection_fields()),
            TlsStatusRequestBody::Opaque(bytes) => {
                fields.push(("status_request_v2_item_opaque", hex_bytes(bytes)));
            }
        }
        fields
    }
}

/// RFC 6961 `status_request_v2` CertificateStatusRequestListV2 extension body.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsStatusRequestV2 {
    items: Vec<TlsStatusRequestV2Item>,
}

impl TlsStatusRequestV2 {
    /// Create an ordered status_request_v2 item list.
    pub fn new(items: impl Into<Vec<TlsStatusRequestV2Item>>) -> Self {
        Self {
            items: items.into(),
        }
    }

    /// Create an ordered status_request_v2 item list.
    pub fn from_items(items: impl Into<Vec<TlsStatusRequestV2Item>>) -> Self {
        Self::new(items)
    }

    /// Borrow the ordered status_request_v2 items.
    pub fn items(&self) -> &[TlsStatusRequestV2Item] {
        &self.items
    }

    /// Consume the body and return the ordered status_request_v2 items.
    pub fn into_vec(self) -> Vec<TlsStatusRequestV2Item> {
        self.items
    }

    /// Append one status_request_v2 item.
    pub fn push(&mut self, item: TlsStatusRequestV2Item) {
        self.items.push(item);
    }

    /// Number of status_request_v2 items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Return true when there are no status_request_v2 items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Number of bytes occupied by list items, excluding the list prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let mut byte_len = 0usize;
        for item in &self.items {
            byte_len = byte_len.checked_add(item.encoded_len()?).ok_or_else(|| {
                CrafterError::invalid_field_value("tls.status_request_v2.length", "length overflow")
            })?;
        }
        validate_status_request_v2_list_len(byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete status_request_v2 body.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_STATUS_REQUEST_V2_LIST_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.status_request_v2.length", "length overflow")
            })
    }

    /// Append this status_request_v2 extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let byte_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.status_request_v2.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&byte_len.to_be_bytes());
        for item in &self.items {
            item.encode(out)?;
        }
        Ok(())
    }

    /// Return this status_request_v2 extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this body into a raw `status_request_v2` extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::STATUS_REQUEST_V2,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a status_request_v2 extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (request, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.status_request_v2.length",
                "length must match extension body",
            ));
        }
        Ok(request)
    }

    /// Decode a status_request_v2 body from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_STATUS_REQUEST_V2_LIST_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request_v2.length",
                TLS_STATUS_REQUEST_V2_LIST_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_status_request_v2_list_len(byte_len)?;
        let required = TLS_STATUS_REQUEST_V2_LIST_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.status_request_v2.length", "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.status_request_v2",
                required,
                bytes.len(),
            ));
        }

        let mut items = Vec::new();
        let mut cursor = &bytes[TLS_STATUS_REQUEST_V2_LIST_LENGTH_LEN..required];
        while !cursor.is_empty() {
            let (item, tail) = TlsStatusRequestV2Item::decode_prefix(cursor)?;
            items.push(item);
            cursor = tail;
        }

        Ok((Self::new(items), &bytes[required..]))
    }

    /// Decode a raw `status_request_v2` extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::STATUS_REQUEST_V2 {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be status_request_v2",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving item count and status types.
    pub fn summary(&self) -> String {
        format!(
            "status_request_v2 items={} bytes={} status_types={}",
            self.len(),
            self.byte_len().unwrap_or(0),
            self.items
                .iter()
                .map(|item| item.status_type.label())
                .collect::<Vec<_>>()
                .join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("status_request_v2_items", self.len().to_string()),
            (
                "status_request_v2_bytes",
                self.byte_len().unwrap_or(0).to_string(),
            ),
            (
                "status_request_v2_status_types",
                self.items
                    .iter()
                    .map(|item| item.status_type.label())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "status_request_v2_status_type_raws",
                self.items
                    .iter()
                    .map(|item| format!("0x{:02x}", item.status_type.raw()))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }
}

impl From<Vec<TlsStatusRequestV2Item>> for TlsStatusRequestV2 {
    fn from(items: Vec<TlsStatusRequestV2Item>) -> Self {
        Self::new(items)
    }
}

impl<const N: usize> From<[TlsStatusRequestV2Item; N]> for TlsStatusRequestV2 {
    fn from(items: [TlsStatusRequestV2Item; N]) -> Self {
        Self::new(Vec::from(items))
    }
}

impl From<TlsStatusRequestV2Item> for TlsStatusRequestV2 {
    fn from(item: TlsStatusRequestV2Item) -> Self {
        Self::new(vec![item])
    }
}

impl TryFrom<&TlsRawExtension> for TlsStatusRequestV2 {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsStatusRequestV2> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsStatusRequestV2) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_ocsp_responder_id_len(len: usize) -> Result<()> {
    if len < TLS_OCSP_RESPONDER_ID_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request.ocsp.responder_id.length",
            "length must be at least one byte",
        ));
    }
    if len > TLS_OCSP_RESPONDER_ID_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request.ocsp.responder_id.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_ocsp_responder_id_list_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request.ocsp.responder_id_list.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_ocsp_request_extensions_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request.ocsp.request_extensions.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_ocsp_status_request_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request.ocsp.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_status_request_opaque_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request.opaque.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_status_request_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_status_request_v2_item_request_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request_v2.item.request.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_status_request_v2_list_len(len: usize) -> Result<()> {
    if len < TLS_STATUS_REQUEST_V2_ITEM_HEADER_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request_v2.length",
            "length must be at least three bytes",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.status_request_v2.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

/// TLS 1.3 opaque DistinguishedName value used by `certificate_authorities`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsDistinguishedName {
    bytes: Vec<u8>,
}

impl TlsDistinguishedName {
    /// Create a DistinguishedName from caller-provided opaque bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Create a DistinguishedName from caller-provided opaque bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(bytes)
    }

    /// Borrow the preserved DistinguishedName bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the DistinguishedName and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of DistinguishedName bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no DistinguishedName bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Number of bytes occupied by the complete encoded DistinguishedName item.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_distinguished_name_len(self.bytes.len())?;
        TLS_DISTINGUISHED_NAME_LENGTH_LEN
            .checked_add(self.bytes.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.distinguished_name.length",
                    "length overflow",
                )
            })
    }

    /// Append this length-prefixed DistinguishedName item to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_distinguished_name_len(self.bytes.len())?;
        let len = u16::try_from(self.bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.distinguished_name.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(())
    }

    /// Return this length-prefixed DistinguishedName item encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one DistinguishedName item.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (name, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.distinguished_name.length",
                "length must match item body",
            ));
        }
        Ok(name)
    }

    /// Decode one DistinguishedName item from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_DISTINGUISHED_NAME_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.distinguished_name.length",
                TLS_DISTINGUISHED_NAME_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_distinguished_name_len(len)?;
        let required = TLS_DISTINGUISHED_NAME_LENGTH_LEN
            .checked_add(len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.distinguished_name.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.distinguished_name",
                required,
                bytes.len(),
            ));
        }

        Ok((
            Self::new(bytes[TLS_DISTINGUISHED_NAME_LENGTH_LEN..required].to_vec()),
            &bytes[required..],
        ))
    }

    /// Stable one-line summary preserving opaque DistinguishedName size.
    pub fn summary(&self) -> String {
        format!("distinguished_name bytes={}", self.bytes.len())
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("distinguished_name_bytes", self.bytes.len().to_string()),
            ("distinguished_name", hex_bytes(&self.bytes)),
        ]
    }
}

impl From<Vec<u8>> for TlsDistinguishedName {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for TlsDistinguishedName {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for TlsDistinguishedName {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(Vec::from(bytes))
    }
}

/// TLS `certificate_authorities` extension body as an RFC 8446 DistinguishedName list.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsCertificateAuthorities {
    distinguished_names: Vec<TlsDistinguishedName>,
}

impl TlsCertificateAuthorities {
    /// Create an ordered certificate_authorities extension body.
    pub fn new(distinguished_names: impl Into<Vec<TlsDistinguishedName>>) -> Self {
        Self {
            distinguished_names: distinguished_names.into(),
        }
    }

    /// Create an ordered certificate_authorities extension body.
    pub fn from_distinguished_names(
        distinguished_names: impl Into<Vec<TlsDistinguishedName>>,
    ) -> Self {
        Self::new(distinguished_names)
    }

    /// Create an ordered certificate_authorities body from raw DistinguishedName bytes.
    pub fn from_raws<I, B>(distinguished_names: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: Into<TlsDistinguishedName>,
    {
        Self::new(
            distinguished_names
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>(),
        )
    }

    /// Borrow the ordered DistinguishedName values.
    pub fn distinguished_names(&self) -> &[TlsDistinguishedName] {
        &self.distinguished_names
    }

    /// Return DistinguishedName byte lengths in wire order.
    pub fn byte_lengths(&self) -> Vec<usize> {
        self.distinguished_names
            .iter()
            .map(TlsDistinguishedName::len)
            .collect()
    }

    /// Return DistinguishedName byte strings in wire order.
    pub fn raw_values(&self) -> Vec<Vec<u8>> {
        self.distinguished_names
            .iter()
            .map(|name| name.bytes().to_vec())
            .collect()
    }

    /// Consume the extension body and return the ordered DistinguishedName values.
    pub fn into_vec(self) -> Vec<TlsDistinguishedName> {
        self.distinguished_names
    }

    /// Append one DistinguishedName to the ordered list.
    pub fn push(&mut self, distinguished_name: impl Into<TlsDistinguishedName>) {
        self.distinguished_names.push(distinguished_name.into());
    }

    /// Number of DistinguishedName entries.
    pub fn len(&self) -> usize {
        self.distinguished_names.len()
    }

    /// Return true when the body carries no DistinguishedName entries.
    pub fn is_empty(&self) -> bool {
        self.distinguished_names.is_empty()
    }

    /// Number of bytes occupied by the DistinguishedName vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let mut byte_len = 0usize;
        for name in &self.distinguished_names {
            byte_len = byte_len.checked_add(name.encoded_len()?).ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.certificate_authorities.length",
                    "length overflow",
                )
            })?;
        }
        validate_certificate_authorities_len(byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete encoded certificate_authorities body.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_CERTIFICATE_AUTHORITIES_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.certificate_authorities.length",
                    "length overflow",
                )
            })
    }

    /// Append this certificate_authorities extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let byte_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.certificate_authorities.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&byte_len.to_be_bytes());
        for name in &self.distinguished_names {
            name.encode(out)?;
        }
        Ok(())
    }

    /// Return this certificate_authorities extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this certificate_authorities body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::CERTIFICATE_AUTHORITIES,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a certificate_authorities extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (authorities, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.certificate_authorities.length",
                "length must match extension body",
            ));
        }
        Ok(authorities)
    }

    /// Decode a certificate_authorities body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_CERTIFICATE_AUTHORITIES_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.certificate_authorities.length",
                TLS_CERTIFICATE_AUTHORITIES_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_certificate_authorities_len(byte_len)?;
        let required = TLS_CERTIFICATE_AUTHORITIES_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.certificate_authorities.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.certificate_authorities",
                required,
                bytes.len(),
            ));
        }

        let mut cursor = TLS_CERTIFICATE_AUTHORITIES_LENGTH_LEN;
        let body_end = required;
        let mut distinguished_names = Vec::new();
        while cursor < body_end {
            let (distinguished_name, tail) =
                TlsDistinguishedName::decode_prefix(&bytes[cursor..body_end])?;
            distinguished_names.push(distinguished_name);
            cursor = body_end - tail.len();
        }

        Ok((Self::new(distinguished_names), &bytes[required..]))
    }

    /// Decode a raw certificate_authorities extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::CERTIFICATE_AUTHORITIES {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be certificate_authorities",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving DistinguishedName order.
    pub fn summary(&self) -> String {
        format!(
            "certificate_authorities count={} bytes={}",
            self.len(),
            self.distinguished_names
                .iter()
                .map(|name| name.encoded_len().unwrap_or(0))
                .sum::<usize>()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("certificate_authorities_count", self.len().to_string()),
            (
                "certificate_authorities_bytes",
                self.distinguished_names
                    .iter()
                    .map(|name| name.encoded_len().unwrap_or(0))
                    .sum::<usize>()
                    .to_string(),
            ),
            (
                "certificate_authorities_lengths",
                self.byte_lengths()
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "certificate_authorities",
                self.distinguished_names
                    .iter()
                    .map(|name| hex_bytes(name.bytes()))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }
}

impl From<Vec<TlsDistinguishedName>> for TlsCertificateAuthorities {
    fn from(distinguished_names: Vec<TlsDistinguishedName>) -> Self {
        Self::new(distinguished_names)
    }
}

impl<const N: usize> From<[TlsDistinguishedName; N]> for TlsCertificateAuthorities {
    fn from(distinguished_names: [TlsDistinguishedName; N]) -> Self {
        Self::new(Vec::from(distinguished_names))
    }
}

impl From<TlsDistinguishedName> for TlsCertificateAuthorities {
    fn from(distinguished_name: TlsDistinguishedName) -> Self {
        Self::new(vec![distinguished_name])
    }
}

impl TryFrom<&TlsRawExtension> for TlsCertificateAuthorities {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsCertificateAuthorities> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsCertificateAuthorities) -> Result<Self> {
        value.to_raw_extension()
    }
}

/// TLS 1.3 opaque OID/value pair used by `oid_filters`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsOidFilter {
    oid: Vec<u8>,
    values: Vec<u8>,
}

impl TlsOidFilter {
    /// Create an OIDFilter from opaque certificate-extension OID and value bytes.
    pub fn new(oid: impl Into<Vec<u8>>, values: impl Into<Vec<u8>>) -> Self {
        Self {
            oid: oid.into(),
            values: values.into(),
        }
    }

    /// Create an OIDFilter from opaque certificate-extension OID and value bytes.
    pub fn from_pair(oid: impl Into<Vec<u8>>, values: impl Into<Vec<u8>>) -> Self {
        Self::new(oid, values)
    }

    /// Borrow the preserved certificate_extension_oid bytes.
    pub fn oid(&self) -> &[u8] {
        &self.oid
    }

    /// Borrow the preserved certificate_extension_values bytes.
    pub fn values(&self) -> &[u8] {
        &self.values
    }

    /// Consume the OIDFilter and return its opaque OID and value bytes.
    pub fn into_pair(self) -> (Vec<u8>, Vec<u8>) {
        (self.oid, self.values)
    }

    /// Number of certificate_extension_oid bytes.
    pub fn oid_len(&self) -> usize {
        self.oid.len()
    }

    /// Number of certificate_extension_values bytes.
    pub fn values_len(&self) -> usize {
        self.values.len()
    }

    /// Number of bytes occupied by the complete encoded OIDFilter item.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_oid_filter_oid_len(self.oid.len())?;
        validate_oid_filter_values_len(self.values.len())?;
        TLS_OID_FILTER_OID_LENGTH_LEN
            .checked_add(self.oid.len())
            .and_then(|len| len.checked_add(TLS_OID_FILTER_VALUES_LENGTH_LEN))
            .and_then(|len| len.checked_add(self.values.len()))
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.oid_filter.length", "length overflow")
            })
    }

    /// Append this OIDFilter item to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_oid_filter_oid_len(self.oid.len())?;
        validate_oid_filter_values_len(self.values.len())?;
        let oid_len = u8::try_from(self.oid.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.oid_filter.oid.length",
                "length must fit in one byte",
            )
        })?;
        let values_len = u16::try_from(self.values.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.oid_filter.values.length",
                "length must fit in two bytes",
            )
        })?;
        out.push(oid_len);
        out.extend_from_slice(&self.oid);
        out.extend_from_slice(&values_len.to_be_bytes());
        out.extend_from_slice(&self.values);
        Ok(())
    }

    /// Return this OIDFilter item encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one OIDFilter item.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (filter, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.oid_filter.length",
                "length must match item body",
            ));
        }
        Ok(filter)
    }

    /// Decode one OIDFilter item from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_OID_FILTER_OID_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.oid_filter.oid.length",
                TLS_OID_FILTER_OID_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let oid_len = bytes[0] as usize;
        validate_oid_filter_oid_len(oid_len)?;
        let oid_end = TLS_OID_FILTER_OID_LENGTH_LEN
            .checked_add(oid_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.oid_filter.oid.length", "length overflow")
            })?;
        if bytes.len() < oid_end {
            return Err(CrafterError::buffer_too_short(
                "tls.oid_filter.oid",
                oid_end,
                bytes.len(),
            ));
        }

        let values_length_end = oid_end
            .checked_add(TLS_OID_FILTER_VALUES_LENGTH_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.oid_filter.values.length", "length overflow")
            })?;
        if bytes.len() < values_length_end {
            return Err(CrafterError::buffer_too_short(
                "tls.oid_filter.values.length",
                values_length_end,
                bytes.len(),
            ));
        }

        let values_len = u16::from_be_bytes([bytes[oid_end], bytes[oid_end + 1]]) as usize;
        validate_oid_filter_values_len(values_len)?;
        let required = values_length_end.checked_add(values_len).ok_or_else(|| {
            CrafterError::invalid_field_value("tls.oid_filter.values.length", "length overflow")
        })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.oid_filter.values",
                required,
                bytes.len(),
            ));
        }

        Ok((
            Self::new(
                bytes[1..oid_end].to_vec(),
                bytes[values_length_end..required].to_vec(),
            ),
            &bytes[required..],
        ))
    }

    /// Stable one-line summary preserving opaque OIDFilter sizes.
    pub fn summary(&self) -> String {
        format!(
            "oid_filter oid_bytes={} values_bytes={}",
            self.oid.len(),
            self.values.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("oid_filter_oid_bytes", self.oid.len().to_string()),
            ("oid_filter_oid", hex_bytes(&self.oid)),
            ("oid_filter_values_bytes", self.values.len().to_string()),
            ("oid_filter_values", hex_bytes(&self.values)),
        ]
    }
}

impl<O, V> From<(O, V)> for TlsOidFilter
where
    O: Into<Vec<u8>>,
    V: Into<Vec<u8>>,
{
    fn from((oid, values): (O, V)) -> Self {
        Self::new(oid, values)
    }
}

/// TLS `oid_filters` extension body as an RFC 8446 OIDFilter list.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsOidFilters {
    filters: Vec<TlsOidFilter>,
}

impl TlsOidFilters {
    /// Create an ordered oid_filters extension body.
    pub fn new(filters: impl Into<Vec<TlsOidFilter>>) -> Self {
        Self {
            filters: filters.into(),
        }
    }

    /// Create an empty oid_filters extension body.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an ordered oid_filters extension body.
    pub fn from_filters(filters: impl Into<Vec<TlsOidFilter>>) -> Self {
        Self::new(filters)
    }

    /// Create an ordered oid_filters body from raw OID/value byte pairs.
    pub fn from_pairs<I, O, V>(filters: I) -> Self
    where
        I: IntoIterator<Item = (O, V)>,
        O: Into<Vec<u8>>,
        V: Into<Vec<u8>>,
    {
        Self::new(
            filters
                .into_iter()
                .map(TlsOidFilter::from)
                .collect::<Vec<_>>(),
        )
    }

    /// Borrow the ordered OIDFilter values.
    pub fn filters(&self) -> &[TlsOidFilter] {
        &self.filters
    }

    /// Return OIDFilter byte lengths in wire order.
    pub fn byte_lengths(&self) -> Vec<usize> {
        self.filters
            .iter()
            .map(|filter| filter.encoded_len().unwrap_or(0))
            .collect()
    }

    /// Consume the extension body and return the ordered OIDFilter values.
    pub fn into_vec(self) -> Vec<TlsOidFilter> {
        self.filters
    }

    /// Append one OIDFilter to the ordered list.
    pub fn push(&mut self, filter: impl Into<TlsOidFilter>) {
        self.filters.push(filter.into());
    }

    /// Number of OIDFilter entries.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Return true when the body carries no OIDFilter entries.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Number of bytes occupied by the OIDFilter vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let mut byte_len = 0usize;
        for filter in &self.filters {
            byte_len = byte_len.checked_add(filter.encoded_len()?).ok_or_else(|| {
                CrafterError::invalid_field_value("tls.oid_filters.length", "length overflow")
            })?;
        }
        validate_oid_filters_len(byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete encoded oid_filters body.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_OID_FILTERS_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.oid_filters.length", "length overflow")
            })
    }

    /// Append this oid_filters extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let byte_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.oid_filters.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&byte_len.to_be_bytes());
        for filter in &self.filters {
            filter.encode(out)?;
        }
        Ok(())
    }

    /// Return this oid_filters extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this oid_filters body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::OID_FILTERS,
            self.encode_to_vec()?,
        ))
    }

    /// Decode an oid_filters extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (filters, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.oid_filters.length",
                "length must match extension body",
            ));
        }
        Ok(filters)
    }

    /// Decode an oid_filters body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_OID_FILTERS_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.oid_filters.length",
                TLS_OID_FILTERS_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_oid_filters_len(byte_len)?;
        let required = TLS_OID_FILTERS_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.oid_filters.length", "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.oid_filters",
                required,
                bytes.len(),
            ));
        }

        let mut cursor = TLS_OID_FILTERS_LENGTH_LEN;
        let body_end = required;
        let mut filters = Vec::new();
        while cursor < body_end {
            let (filter, tail) = TlsOidFilter::decode_prefix(&bytes[cursor..body_end])?;
            filters.push(filter);
            cursor = body_end - tail.len();
        }

        Ok((Self::new(filters), &bytes[required..]))
    }

    /// Decode a raw oid_filters extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::OID_FILTERS {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be oid_filters",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving OIDFilter order.
    pub fn summary(&self) -> String {
        format!(
            "oid_filters count={} bytes={}",
            self.len(),
            self.filters
                .iter()
                .map(|filter| filter.encoded_len().unwrap_or(0))
                .sum::<usize>()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("oid_filters_count", self.len().to_string()),
            (
                "oid_filters_bytes",
                self.filters
                    .iter()
                    .map(|filter| filter.encoded_len().unwrap_or(0))
                    .sum::<usize>()
                    .to_string(),
            ),
            (
                "oid_filters_lengths",
                self.byte_lengths()
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "oid_filters_oids",
                self.filters
                    .iter()
                    .map(|filter| hex_bytes(filter.oid()))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }
}

impl From<Vec<TlsOidFilter>> for TlsOidFilters {
    fn from(filters: Vec<TlsOidFilter>) -> Self {
        Self::new(filters)
    }
}

impl<const N: usize> From<[TlsOidFilter; N]> for TlsOidFilters {
    fn from(filters: [TlsOidFilter; N]) -> Self {
        Self::new(Vec::from(filters))
    }
}

impl From<TlsOidFilter> for TlsOidFilters {
    fn from(filter: TlsOidFilter) -> Self {
        Self::new(vec![filter])
    }
}

impl TryFrom<&TlsRawExtension> for TlsOidFilters {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsOidFilters> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsOidFilters) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_distinguished_name_len(len: usize) -> Result<()> {
    if len < TLS_DISTINGUISHED_NAME_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.distinguished_name.length",
            "length must be at least one byte",
        ));
    }
    if len > TLS_DISTINGUISHED_NAME_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.distinguished_name.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_certificate_authorities_len(len: usize) -> Result<()> {
    if len < TLS_CERTIFICATE_AUTHORITIES_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.certificate_authorities.length",
            "length must be at least three bytes",
        ));
    }
    if len > TLS_CERTIFICATE_AUTHORITIES_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.certificate_authorities.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_oid_filter_oid_len(len: usize) -> Result<()> {
    if len < TLS_OID_FILTER_OID_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.oid_filter.oid.length",
            "length must be at least one byte",
        ));
    }
    if len > TLS_OID_FILTER_OID_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.oid_filter.oid.length",
            "length must fit in one byte",
        ));
    }
    Ok(())
}

fn validate_oid_filter_values_len(len: usize) -> Result<()> {
    if len > TLS_OID_FILTER_VALUES_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.oid_filter.values.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_oid_filters_len(len: usize) -> Result<()> {
    if len > TLS_OID_FILTERS_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.oid_filters.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

/// TLS 1.3 `cookie` extension body with opaque cookie bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsCookie {
    bytes: Vec<u8>,
}

impl TlsCookie {
    /// Create a cookie extension body from opaque cookie bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Create a cookie extension body from opaque cookie bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(bytes)
    }

    /// Borrow the preserved opaque cookie bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the cookie and return its opaque bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of opaque cookie bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no opaque cookie bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Number of bytes occupied by the complete encoded Cookie body.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_cookie_len(self.bytes.len())?;
        TLS_COOKIE_LENGTH_LEN
            .checked_add(self.bytes.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.cookie.length", "length overflow")
            })
    }

    /// Append this Cookie body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_cookie_len(self.bytes.len())?;
        let len = u16::try_from(self.bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value("tls.cookie.length", "length must fit in two bytes")
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(())
    }

    /// Return this Cookie body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this Cookie body into a raw `cookie` extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::COOKIE,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a Cookie extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (cookie, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.cookie.length",
                "length must match extension body",
            ));
        }
        Ok(cookie)
    }

    /// Decode a Cookie body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_COOKIE_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.cookie.length",
                TLS_COOKIE_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_cookie_len(len)?;
        let required = TLS_COOKIE_LENGTH_LEN.checked_add(len).ok_or_else(|| {
            CrafterError::invalid_field_value("tls.cookie.length", "length overflow")
        })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.cookie",
                required,
                bytes.len(),
            ));
        }

        Ok((
            Self::new(bytes[TLS_COOKIE_LENGTH_LEN..required].to_vec()),
            &bytes[required..],
        ))
    }

    /// Decode a raw `cookie` extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::COOKIE {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be cookie",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving opaque cookie size.
    pub fn summary(&self) -> String {
        format!("cookie bytes={}", self.bytes.len())
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("cookie_bytes", self.bytes.len().to_string()),
            ("cookie", hex_bytes(&self.bytes)),
        ]
    }
}

impl From<Vec<u8>> for TlsCookie {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for TlsCookie {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for TlsCookie {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(Vec::from(bytes))
    }
}

impl TryFrom<&TlsRawExtension> for TlsCookie {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsCookie> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsCookie) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_cookie_len(len: usize) -> Result<()> {
    if len < TLS_COOKIE_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.cookie.length",
            "length must be at least one byte",
        ));
    }
    if len > TLS_COOKIE_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.cookie.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

/// TLS `padding` extension body with caller-provided bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsPadding {
    bytes: Vec<u8>,
}

impl TlsPadding {
    /// Create a padding extension body from caller-provided bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Create a padding extension body from caller-provided bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self::new(bytes)
    }

    /// Create a padding extension body filled with zero bytes.
    pub fn zeros(len: usize) -> Self {
        Self::new(vec![0; len])
    }

    /// Borrow the preserved padding bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the padding body and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of padding bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no padding bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return true when every padding byte is zero.
    pub fn is_zero_filled(&self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }

    /// Number of bytes occupied by this padding extension body.
    pub fn encoded_len(&self) -> Result<usize> {
        validate_padding_len(self.bytes.len())?;
        Ok(self.bytes.len())
    }

    /// Append this padding extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_padding_len(self.bytes.len())?;
        out.extend_from_slice(&self.bytes);
        Ok(())
    }

    /// Return this padding extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this padding body into a raw `padding` extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::PADDING,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a padding extension body, preserving all bytes exactly.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        validate_padding_len(bytes.len())?;
        Ok(Self::new(bytes.to_vec()))
    }

    /// Decode a raw `padding` extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::PADDING {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be padding",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving padding size and zero-fill state.
    pub fn summary(&self) -> String {
        format!(
            "padding bytes={} zero_filled={}",
            self.bytes.len(),
            self.is_zero_filled()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("padding_bytes", self.bytes.len().to_string()),
            ("padding", hex_bytes(&self.bytes)),
            ("padding_zero_filled", self.is_zero_filled().to_string()),
        ]
    }
}

impl From<Vec<u8>> for TlsPadding {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for TlsPadding {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl<const N: usize> From<[u8; N]> for TlsPadding {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(Vec::from(bytes))
    }
}

impl TryFrom<&TlsRawExtension> for TlsPadding {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsPadding> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsPadding) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_padding_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.padding.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

/// TLS `record_size_limit` extension body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsRecordSizeLimit {
    limit: u16,
}

impl TlsRecordSizeLimit {
    /// Create a record_size_limit extension body, preserving the caller-supplied value.
    pub const fn new(limit: u16) -> Self {
        Self { limit }
    }

    /// Create a record_size_limit extension body, preserving the caller-supplied value.
    pub const fn from_u16(limit: u16) -> Self {
        Self::new(limit)
    }

    /// Create a record_size_limit body for the TLS 1.2 and earlier maximum.
    pub const fn tls_1_2_max() -> Self {
        Self::new(TLS_RECORD_SIZE_LIMIT_TLS12_MAX)
    }

    /// Create a record_size_limit body for the TLS 1.3 maximum.
    pub const fn tls_1_3_max() -> Self {
        Self::new(TLS_RECORD_SIZE_LIMIT_TLS13_MAX)
    }

    /// Return the preserved record size limit value.
    pub const fn limit(self) -> u16 {
        self.limit
    }

    /// Return the preserved record size limit value.
    pub const fn as_u16(self) -> u16 {
        self.limit
    }

    /// Return true when this value satisfies the RFC 8449 lower bound.
    pub const fn is_valid(self) -> bool {
        self.limit >= TLS_RECORD_SIZE_LIMIT_MIN
    }

    /// Return true when this value is within RFC 8449 TLS 1.2 and earlier bounds.
    pub const fn is_valid_for_tls_1_2(self) -> bool {
        self.is_valid() && self.limit <= TLS_RECORD_SIZE_LIMIT_TLS12_MAX
    }

    /// Return true when this value is within RFC 8449 TLS 1.3 bounds.
    pub const fn is_valid_for_tls_1_3(self) -> bool {
        self.is_valid() && self.limit <= TLS_RECORD_SIZE_LIMIT_TLS13_MAX
    }

    /// Validate the RFC 8449 lower bound without rewriting the stored value.
    pub fn validate(self) -> Result<()> {
        validate_record_size_limit_min("tls.record_size_limit", self.limit)
    }

    /// Validate RFC 8449 TLS 1.2 and earlier bounds without rewriting the stored value.
    pub fn validate_for_tls_1_2(self) -> Result<()> {
        self.validate()?;
        validate_record_size_limit_max(
            "tls.record_size_limit",
            self.limit,
            TLS_RECORD_SIZE_LIMIT_TLS12_MAX,
        )
    }

    /// Validate RFC 8449 TLS 1.3 bounds without rewriting the stored value.
    pub fn validate_for_tls_1_3(self) -> Result<()> {
        self.validate()?;
        validate_record_size_limit_max(
            "tls.record_size_limit",
            self.limit,
            TLS_RECORD_SIZE_LIMIT_TLS13_MAX,
        )
    }

    /// Number of bytes occupied by this record_size_limit extension body.
    pub const fn encoded_len(self) -> usize {
        TLS_RECORD_SIZE_LIMIT_LEN
    }

    /// Append this record_size_limit extension body to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.limit.to_be_bytes());
    }

    /// Return this record_size_limit extension body encoding.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.limit.to_be_bytes().to_vec()
    }

    /// Convert this record_size_limit body into a raw `record_size_limit` extension.
    pub fn to_raw_extension(self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::RECORD_SIZE_LIMIT,
            self.encode_to_vec(),
        ))
    }

    /// Decode a record_size_limit extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < TLS_RECORD_SIZE_LIMIT_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.record_size_limit",
                TLS_RECORD_SIZE_LIMIT_LEN,
                bytes.len(),
            ));
        }
        if bytes.len() != TLS_RECORD_SIZE_LIMIT_LEN {
            return Err(CrafterError::invalid_field_value(
                "tls.record_size_limit.length",
                "length must be exactly two bytes",
            ));
        }
        Ok(Self::new(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    /// Decode a raw `record_size_limit` extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::RECORD_SIZE_LIMIT {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be record_size_limit",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving the limit and RFC 8449 validity state.
    pub fn summary(self) -> String {
        format!(
            "record_size_limit limit={} valid={}",
            self.limit,
            self.is_valid()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("record_size_limit", self.limit.to_string()),
            ("record_size_limit_valid", self.is_valid().to_string()),
            (
                "record_size_limit_min",
                TLS_RECORD_SIZE_LIMIT_MIN.to_string(),
            ),
        ]
    }
}

impl From<u16> for TlsRecordSizeLimit {
    fn from(limit: u16) -> Self {
        Self::new(limit)
    }
}

impl From<TlsRecordSizeLimit> for u16 {
    fn from(value: TlsRecordSizeLimit) -> Self {
        value.limit()
    }
}

impl TryFrom<&TlsRawExtension> for TlsRecordSizeLimit {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsRecordSizeLimit> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsRecordSizeLimit) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_record_size_limit_min(field: &'static str, limit: u16) -> Result<()> {
    if limit < TLS_RECORD_SIZE_LIMIT_MIN {
        return Err(CrafterError::invalid_field_value(
            field,
            "limit must be at least 64 bytes",
        ));
    }
    Ok(())
}

fn validate_record_size_limit_max(field: &'static str, limit: u16, max: u16) -> Result<()> {
    if limit > max {
        return Err(CrafterError::invalid_field_value(
            field,
            "limit exceeds protocol-defined maximum",
        ));
    }
    Ok(())
}

/// Raw-preserving TLS ServerName `NameType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsServerNameType {
    raw: u8,
}

impl TlsServerNameType {
    /// RFC 6066 `host_name` server name type.
    pub const HOST_NAME: Self = Self::new(TLS_SERVER_NAME_TYPE_HOST_NAME);

    /// Preserve a caller-supplied one-octet server name type.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied one-octet server name type.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// RFC 6066 `host_name` constructor.
    pub const fn host_name() -> Self {
        Self::HOST_NAME
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the source-backed server-name type name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        match self.raw {
            TLS_SERVER_NAME_TYPE_HOST_NAME => Some("host_name"),
            _ => None,
        }
    }

    /// Return true when this server-name type is `host_name`.
    pub const fn is_host_name(self) -> bool {
        self.raw == TLS_SERVER_NAME_TYPE_HOST_NAME
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        self.name()
            .map(str::to_string)
            .unwrap_or_else(|| format!("unknown server name type 0x{:02x}", self.raw))
    }

    /// Stable one-line summary preserving the raw value.
    pub fn summary(self) -> String {
        format!("{} raw=0x{:02x}", self.label(), self.raw)
    }
}

impl From<u8> for TlsServerNameType {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsServerNameType> for u8 {
    fn from(value: TlsServerNameType) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsServerNameType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// One TLS ServerName entry from a `server_name` extension body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsServerName {
    /// RFC 6066 `host_name` bytes.
    HostName(Vec<u8>),
    /// Unknown or future name type with its selected-name body preserved.
    Unknown {
        /// Preserved server-name type.
        name_type: TlsServerNameType,
        /// Preserved selected-name body bytes after the uint16 length field.
        body: Vec<u8>,
    },
}

impl TlsServerName {
    /// Build an RFC 6066 `host_name` entry from a DNS hostname string.
    pub fn host_name(name: impl Into<String>) -> Self {
        Self::HostName(name.into().into_bytes())
    }

    /// Build an RFC 6066 `host_name` entry from caller-supplied bytes.
    pub fn host_name_bytes(name: impl Into<Vec<u8>>) -> Self {
        Self::HostName(name.into())
    }

    /// Build an unknown or future server-name entry, preserving type and body bytes.
    pub fn unknown(name_type: impl Into<TlsServerNameType>, body: impl Into<Vec<u8>>) -> Self {
        Self::Unknown {
            name_type: name_type.into(),
            body: body.into(),
        }
    }

    /// Return the selected server-name type.
    pub const fn name_type(&self) -> TlsServerNameType {
        match self {
            Self::HostName(_) => TlsServerNameType::HOST_NAME,
            Self::Unknown { name_type, .. } => *name_type,
        }
    }

    /// Borrow the selected-name body bytes.
    pub fn body(&self) -> &[u8] {
        match self {
            Self::HostName(name) | Self::Unknown { body: name, .. } => name,
        }
    }

    /// Borrow the `host_name` bytes when this entry is a host name.
    pub fn host_name_bytes_value(&self) -> Option<&[u8]> {
        match self {
            Self::HostName(name) => Some(name),
            Self::Unknown { .. } => None,
        }
    }

    /// Borrow the `host_name` as UTF-8 when this entry is a host name.
    pub fn host_name_value(&self) -> Option<&str> {
        self.host_name_bytes_value()
            .and_then(|name| core::str::from_utf8(name).ok())
    }

    /// Number of bytes occupied by the complete encoded ServerName entry.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_SERVER_NAME_HEADER_LEN
            .checked_add(self.body().len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.server_name.length", "length overflow")
            })
    }

    /// Append this ServerName entry to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_server_name_entry(self)?;
        out.push(self.name_type().raw());
        let body_len = u16::try_from(self.body().len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.server_name.name.length",
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(self.body());
        Ok(())
    }

    /// Return the encoded ServerName entry.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one ServerName entry from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (server_name, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(server_name)
    }

    /// Decode one ServerName entry from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_SERVER_NAME_TYPE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.server_name.name_type",
                TLS_SERVER_NAME_TYPE_LEN,
                bytes.len(),
            ));
        }
        if bytes.len() < TLS_SERVER_NAME_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.server_name.name.length",
                TLS_SERVER_NAME_HEADER_LEN,
                bytes.len(),
            ));
        }

        let name_type = TlsServerNameType::from_u8(bytes[0]);
        let body_len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        let required = TLS_SERVER_NAME_HEADER_LEN
            .checked_add(body_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.server_name.name.length", "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.server_name.name",
                required,
                bytes.len(),
            ));
        }

        let body = bytes[TLS_SERVER_NAME_HEADER_LEN..required].to_vec();
        let server_name = if name_type.is_host_name() {
            let server_name = Self::HostName(body);
            validate_server_name_entry(&server_name)?;
            server_name
        } else {
            Self::Unknown { name_type, body }
        };

        Ok((server_name, &bytes[required..]))
    }

    /// Stable one-line summary preserving type and visible synthetic host names.
    pub fn summary(&self) -> String {
        match self {
            Self::HostName(name) => format!(
                "server_name type=host_name host_name={} bytes={}",
                String::from_utf8_lossy(name),
                name.len()
            ),
            Self::Unknown { name_type, body } => format!(
                "server_name type={} raw=0x{:02x} body_bytes={}",
                name_type.label(),
                name_type.raw(),
                body.len()
            ),
        }
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("server_name_type", self.name_type().label()),
            (
                "server_name_type_raw",
                format!("0x{:02x}", self.name_type().raw()),
            ),
            ("server_name_body_bytes", self.body().len().to_string()),
        ];
        if let Some(host_name) = self.host_name_value() {
            fields.push(("server_name_host_name", host_name.to_string()));
        }
        fields
    }
}

/// TLS `server_name` extension body as an RFC 6066 ServerNameList.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsServerNameList {
    names: Vec<TlsServerName>,
}

impl TlsServerNameList {
    /// Create an ordered ServerNameList.
    pub fn new(names: impl Into<Vec<TlsServerName>>) -> Self {
        Self {
            names: names.into(),
        }
    }

    /// Create a one-entry ServerNameList containing `host_name`.
    pub fn from_host_name(name: impl Into<String>) -> Self {
        Self::new(vec![TlsServerName::host_name(name)])
    }

    /// Borrow the ordered server-name entries.
    pub fn names(&self) -> &[TlsServerName] {
        &self.names
    }

    /// Compatibility alias for borrowing the ordered server-name entries.
    pub fn as_slice(&self) -> &[TlsServerName] {
        self.names()
    }

    /// Consume the list and return the ordered server-name entries.
    pub fn into_vec(self) -> Vec<TlsServerName> {
        self.names
    }

    /// Append one server-name entry.
    pub fn push(&mut self, name: TlsServerName) {
        self.names.push(name);
    }

    /// Number of server-name entries.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Return true when the list carries no server-name entries.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Return host_name values in wire order, excluding unknown name types.
    pub fn host_names(&self) -> Vec<&str> {
        self.names
            .iter()
            .filter_map(TlsServerName::host_name_value)
            .collect()
    }

    /// Number of bytes occupied by server-name entries, excluding the list length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        validate_server_name_list_entries(&self.names)?;
        let mut len = 0usize;
        for name in &self.names {
            len = len.checked_add(name.encoded_len()?).ok_or_else(|| {
                CrafterError::invalid_field_value("tls.server_name_list.length", "length overflow")
            })?;
        }
        validate_server_name_list_len(len)?;
        Ok(len)
    }

    /// Number of bytes occupied by the complete encoded ServerNameList.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_SERVER_NAME_LIST_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.server_name_list.length", "length overflow")
            })
    }

    /// Append the uint16 length-prefixed ServerNameList.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let body_len = self.byte_len()?;
        let body_len = u16::try_from(body_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.server_name_list.length",
                "length must fit in two bytes",
            )
        })?;

        out.extend_from_slice(&body_len.to_be_bytes());
        for name in &self.names {
            name.encode(out)?;
        }
        Ok(())
    }

    /// Return the uint16 length-prefixed ServerNameList encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this ServerNameList into a raw `server_name` extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::SERVER_NAME,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a uint16 length-prefixed ServerNameList.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (names, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(names)
    }

    /// Decode a uint16 length-prefixed ServerNameList from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_SERVER_NAME_LIST_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.server_name_list.length",
                TLS_SERVER_NAME_LIST_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_server_name_list_len(byte_len)?;
        let required = TLS_SERVER_NAME_LIST_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.server_name_list.length", "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.server_name_list",
                required,
                bytes.len(),
            ));
        }

        let mut cursor = TLS_SERVER_NAME_LIST_LENGTH_LEN;
        let body_end = required;
        let mut names = Vec::new();
        while cursor < body_end {
            let (name, tail) = TlsServerName::decode_prefix(&bytes[cursor..body_end])?;
            cursor = body_end - tail.len();
            names.push(name);
        }

        validate_server_name_list_entries(&names)?;
        Ok((Self::new(names), &bytes[required..]))
    }

    /// Decode a raw `server_name` extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::SERVER_NAME {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be server_name",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving order and visible synthetic host names.
    pub fn summary(&self) -> String {
        let values = self
            .names
            .iter()
            .map(|name| match name {
                TlsServerName::HostName(host_name) => {
                    format!("host_name:{}", String::from_utf8_lossy(host_name))
                }
                TlsServerName::Unknown { name_type, body } => {
                    format!("{}:{} bytes", name_type.label(), body.len())
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "server_name list count={} bytes={} values={}",
            self.len(),
            self.names
                .iter()
                .map(|name| name.encoded_len().unwrap_or(0))
                .sum::<usize>(),
            values
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("server_name_count", self.len().to_string()),
            ("server_name_host_names", self.host_names().join(",")),
            (
                "server_name_bytes",
                self.names
                    .iter()
                    .map(|name| name.encoded_len().unwrap_or(0))
                    .sum::<usize>()
                    .to_string(),
            ),
        ]
    }
}

impl From<Vec<TlsServerName>> for TlsServerNameList {
    fn from(names: Vec<TlsServerName>) -> Self {
        Self::new(names)
    }
}

impl<const N: usize> From<[TlsServerName; N]> for TlsServerNameList {
    fn from(names: [TlsServerName; N]) -> Self {
        Self::new(Vec::from(names))
    }
}

impl TryFrom<&TlsRawExtension> for TlsServerNameList {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsServerNameList> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsServerNameList) -> Result<Self> {
        value.to_raw_extension()
    }
}

impl TlsRawExtension {
    /// Create a raw `server_name` extension from a typed ServerNameList.
    pub fn server_name(names: impl Into<TlsServerNameList>) -> Result<Self> {
        names.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed ServerNameList.
    pub fn as_server_name_list(&self) -> Result<TlsServerNameList> {
        TlsServerNameList::from_raw_extension(self)
    }

    /// Create a raw `status_request` extension from a typed CertificateStatusRequest.
    pub fn status_request(request: impl Into<TlsStatusRequest>) -> Result<Self> {
        request.into().to_raw_extension()
    }

    /// Create a raw `status_request` extension carrying an OCSPStatusRequest.
    pub fn status_request_ocsp(request: impl Into<TlsOcspStatusRequest>) -> Result<Self> {
        TlsStatusRequest::ocsp(request).to_raw_extension()
    }

    /// Decode this raw extension as a typed `status_request` body.
    pub fn as_status_request(&self) -> Result<TlsStatusRequest> {
        TlsStatusRequest::from_raw_extension(self)
    }

    /// Create a raw `status_request_v2` extension from a typed request list.
    pub fn status_request_v2(request: impl Into<TlsStatusRequestV2>) -> Result<Self> {
        request.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed `status_request_v2` body.
    pub fn as_status_request_v2(&self) -> Result<TlsStatusRequestV2> {
        TlsStatusRequestV2::from_raw_extension(self)
    }

    /// Create a raw `certificate_authorities` extension from a typed DistinguishedName list.
    pub fn certificate_authorities(
        authorities: impl Into<TlsCertificateAuthorities>,
    ) -> Result<Self> {
        authorities.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed certificate_authorities body.
    pub fn as_certificate_authorities(&self) -> Result<TlsCertificateAuthorities> {
        TlsCertificateAuthorities::from_raw_extension(self)
    }

    /// Create a raw `oid_filters` extension from a typed OIDFilter list.
    pub fn oid_filters(filters: impl Into<TlsOidFilters>) -> Result<Self> {
        filters.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed oid_filters body.
    pub fn as_oid_filters(&self) -> Result<TlsOidFilters> {
        TlsOidFilters::from_raw_extension(self)
    }

    /// Create a raw `supported_groups` extension from a typed group list.
    pub fn supported_groups(groups: impl Into<TlsSupportedGroups>) -> Result<Self> {
        groups.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed supported_groups NamedGroupList.
    pub fn as_supported_groups(&self) -> Result<TlsSupportedGroups> {
        TlsSupportedGroups::from_raw_extension(self)
    }

    /// Create a raw `ec_point_formats` extension from a typed ECPointFormatList.
    pub fn ec_point_formats(formats: impl Into<TlsEcPointFormats>) -> Result<Self> {
        formats.into().to_raw_extension()
    }

    /// Create a raw `ec_point_formats` extension containing only `uncompressed`.
    pub fn ec_point_formats_uncompressed_only() -> Result<Self> {
        TlsEcPointFormats::uncompressed_only().to_raw_extension()
    }

    /// Decode this raw extension as a typed ECPointFormatList.
    pub fn as_ec_point_formats(&self) -> Result<TlsEcPointFormats> {
        TlsEcPointFormats::from_raw_extension(self)
    }

    /// Create a raw `signature_algorithms` extension from a typed signature scheme list.
    pub fn signature_algorithms(schemes: impl Into<TlsSignatureAlgorithms>) -> Result<Self> {
        schemes.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed signature_algorithms SignatureSchemeList.
    pub fn as_signature_algorithms(&self) -> Result<TlsSignatureAlgorithms> {
        TlsSignatureAlgorithms::from_raw_extension(self)
    }

    /// Create a raw `signature_algorithms_cert` extension from a typed signature scheme list.
    pub fn signature_algorithms_cert(
        schemes: impl Into<TlsSignatureAlgorithmsCert>,
    ) -> Result<Self> {
        schemes.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed signature_algorithms_cert SignatureSchemeList.
    pub fn as_signature_algorithms_cert(&self) -> Result<TlsSignatureAlgorithmsCert> {
        TlsSignatureAlgorithmsCert::from_raw_extension(self)
    }

    /// Create a raw `application_layer_protocol_negotiation` extension.
    pub fn application_layer_protocol_negotiation(
        protocols: impl Into<TlsAlpnProtocols>,
    ) -> Result<Self> {
        protocols.into().to_raw_extension()
    }

    /// Create a raw `application_layer_protocol_negotiation` extension.
    pub fn alpn(protocols: impl Into<TlsAlpnProtocols>) -> Result<Self> {
        Self::application_layer_protocol_negotiation(protocols)
    }

    /// Decode this raw extension as a typed ALPN ProtocolNameList.
    pub fn as_alpn_protocols(&self) -> Result<TlsAlpnProtocols> {
        TlsAlpnProtocols::from_raw_extension(self)
    }

    /// Create a raw `padding` extension filled with zero bytes.
    pub fn padding(len: usize) -> Result<Self> {
        TlsPadding::zeros(len).to_raw_extension()
    }

    /// Create a raw `padding` extension from caller-provided bytes.
    pub fn padding_bytes(bytes: impl Into<TlsPadding>) -> Result<Self> {
        bytes.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed `padding` body.
    pub fn as_padding(&self) -> Result<TlsPadding> {
        TlsPadding::from_raw_extension(self)
    }

    /// Create a raw `record_size_limit` extension.
    pub fn record_size_limit(limit: u16) -> Result<Self> {
        TlsRecordSizeLimit::new(limit).to_raw_extension()
    }

    /// Decode this raw extension as a typed `record_size_limit` body.
    pub fn as_record_size_limit(&self) -> Result<TlsRecordSizeLimit> {
        TlsRecordSizeLimit::from_raw_extension(self)
    }

    /// Create a raw ClientHello `supported_versions` extension.
    pub fn supported_versions_client(versions: impl Into<Vec<TlsVersion>>) -> Result<Self> {
        TlsSupportedVersions::client(versions).to_raw_extension()
    }

    /// Create a raw `cookie` extension.
    pub fn cookie(cookie: impl Into<TlsCookie>) -> Result<Self> {
        cookie.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed `cookie` body.
    pub fn as_cookie(&self) -> Result<TlsCookie> {
        TlsCookie::from_raw_extension(self)
    }

    /// Create a raw ServerHello or HelloRetryRequest `supported_versions` extension.
    pub fn supported_versions_server(selected_version: impl Into<TlsVersion>) -> Result<Self> {
        TlsSupportedVersions::server(selected_version).to_raw_extension()
    }

    /// Decode this raw extension as a ClientHello `supported_versions` body.
    pub fn as_supported_versions_client(&self) -> Result<TlsSupportedVersions> {
        TlsSupportedVersions::from_client_hello_raw_extension(self)
    }

    /// Decode this raw extension as a ServerHello `supported_versions` body.
    pub fn as_supported_versions_server(&self) -> Result<TlsSupportedVersions> {
        TlsSupportedVersions::from_server_hello_raw_extension(self)
    }

    /// Decode this raw extension as a context-selected `supported_versions` body.
    pub fn as_supported_versions_with_context(
        &self,
        context: TlsSupportedVersionsContext,
    ) -> Result<TlsSupportedVersions> {
        TlsSupportedVersions::from_raw_extension_with_context(context, self)
    }

    /// Create a raw `psk_key_exchange_modes` extension.
    pub fn psk_key_exchange_modes(modes: impl Into<TlsPskKeyExchangeModes>) -> Result<Self> {
        modes.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed `psk_key_exchange_modes` body.
    pub fn as_psk_key_exchange_modes(&self) -> Result<TlsPskKeyExchangeModes> {
        TlsPskKeyExchangeModes::from_raw_extension(self)
    }

    /// Create a raw ClientHello `pre_shared_key` extension.
    pub fn pre_shared_key_client(
        identities: impl Into<TlsPskIdentities>,
        binders: impl Into<TlsPskBinders>,
    ) -> Result<Self> {
        TlsPreSharedKey::client(identities, binders).to_raw_extension()
    }

    /// Create a raw ServerHello `pre_shared_key` extension.
    pub fn pre_shared_key_server(selected_identity: u16) -> Result<Self> {
        TlsPreSharedKey::server(selected_identity).to_raw_extension()
    }

    /// Decode this raw extension as a ClientHello `pre_shared_key` body.
    pub fn as_pre_shared_key_client(&self) -> Result<TlsPreSharedKey> {
        TlsPreSharedKey::from_client_hello_raw_extension(self)
    }

    /// Decode this raw extension as a ServerHello `pre_shared_key` body.
    pub fn as_pre_shared_key_server(&self) -> Result<TlsPreSharedKey> {
        TlsPreSharedKey::from_server_hello_raw_extension(self)
    }

    /// Decode this raw extension as a context-selected `pre_shared_key` body.
    pub fn as_pre_shared_key_with_context(
        &self,
        context: TlsPreSharedKeyContext,
    ) -> Result<TlsPreSharedKey> {
        TlsPreSharedKey::from_raw_extension_with_context(context, self)
    }

    /// Create a raw ClientHello `key_share` extension.
    pub fn key_share_client(entries: impl Into<Vec<TlsKeyShareEntry>>) -> Result<Self> {
        TlsKeyShare::client(entries).to_raw_extension()
    }

    /// Create a raw ServerHello `key_share` extension.
    pub fn key_share_server(selected: impl Into<TlsKeyShareEntry>) -> Result<Self> {
        TlsKeyShare::server(selected).to_raw_extension()
    }

    /// Create a raw HelloRetryRequest `key_share` extension.
    pub fn key_share_hello_retry_request(selected_group: impl Into<TlsNamedGroup>) -> Result<Self> {
        TlsKeyShare::hello_retry_request(selected_group).to_raw_extension()
    }

    /// Decode this raw extension as a ClientHello `key_share` body.
    pub fn as_key_share_client(&self) -> Result<TlsKeyShare> {
        TlsKeyShare::from_client_hello_raw_extension(self)
    }

    /// Decode this raw extension as a ServerHello `key_share` body.
    pub fn as_key_share_server(&self) -> Result<TlsKeyShare> {
        TlsKeyShare::from_server_hello_raw_extension(self)
    }

    /// Decode this raw extension as a HelloRetryRequest `key_share` body.
    pub fn as_key_share_hello_retry_request(&self) -> Result<TlsKeyShare> {
        TlsKeyShare::from_hello_retry_request_raw_extension(self)
    }

    /// Decode this raw extension as a context-selected `key_share` body.
    pub fn as_key_share_with_context(&self, context: TlsKeyShareContext) -> Result<TlsKeyShare> {
        TlsKeyShare::from_raw_extension_with_context(context, self)
    }
}

/// TLS `supported_groups` extension body as an RFC 8446 NamedGroupList.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsSupportedGroups {
    groups: TlsNamedGroupList,
}

impl TlsSupportedGroups {
    /// Create an ordered supported_groups extension body.
    pub fn new(groups: impl Into<TlsNamedGroupList>) -> Self {
        Self {
            groups: groups.into(),
        }
    }

    /// Create an ordered supported_groups extension body from named group values.
    pub fn from_groups(groups: impl Into<Vec<TlsNamedGroup>>) -> Self {
        Self::new(TlsNamedGroupList::new(groups))
    }

    /// Create an ordered supported_groups extension body from raw two-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u16>) -> Self {
        Self::new(TlsNamedGroupList::from_raws(raws))
    }

    /// Borrow the ordered named group list.
    pub const fn named_group_list(&self) -> &TlsNamedGroupList {
        &self.groups
    }

    /// Borrow the ordered named group list.
    pub const fn as_named_group_list(&self) -> &TlsNamedGroupList {
        self.named_group_list()
    }

    /// Borrow the ordered named group values.
    pub fn groups(&self) -> &[TlsNamedGroup] {
        self.groups.groups()
    }

    /// Return the ordered raw named group values.
    pub fn raw_values(&self) -> Vec<u16> {
        self.groups.raw_values()
    }

    /// Return group labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.groups.labels()
    }

    /// Consume the extension body and return its named group list.
    pub fn into_named_group_list(self) -> TlsNamedGroupList {
        self.groups
    }

    /// Consume the extension body and return the ordered named group values.
    pub fn into_vec(self) -> Vec<TlsNamedGroup> {
        self.groups.into_vec()
    }

    /// Append one named group to the ordered list.
    pub fn push(&mut self, group: TlsNamedGroup) {
        self.groups.push(group);
    }

    /// Number of named groups.
    pub fn len(&self) -> usize {
        self.groups.len()
    }

    /// Return true when the body carries no named group values.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Number of bytes occupied by the NamedGroup vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let byte_len = self.groups.byte_len()?;
        validate_supported_groups_list_len(byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete encoded NamedGroupList.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.supported_groups.length", "length overflow")
            })
    }

    /// Append the supported_groups extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_supported_groups(self)?;
        self.groups.encode(out)
    }

    /// Return this supported_groups extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this supported_groups body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::SUPPORTED_GROUPS,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a supported_groups extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (groups, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.supported_groups.length",
                "length must match extension body",
            ));
        }
        Ok(groups)
    }

    /// Decode a supported_groups body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.supported_groups.length",
                TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_supported_groups_list_len(byte_len)?;
        let required = TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.supported_groups.length", "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.supported_groups",
                required,
                bytes.len(),
            ));
        }

        let (groups, tail) = TlsNamedGroupList::decode_prefix(&bytes[..required])?;
        debug_assert!(tail.is_empty());
        Ok((Self::new(groups), &bytes[required..]))
    }

    /// Decode a raw supported_groups extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::SUPPORTED_GROUPS {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be supported_groups",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving group order.
    pub fn summary(&self) -> String {
        format!(
            "supported_groups count={} bytes={} values={}",
            self.len(),
            self.len() * TLS_SUPPORTED_GROUP_LEN,
            self.labels().join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("supported_groups_count", self.len().to_string()),
            (
                "supported_groups_bytes",
                (self.len() * TLS_SUPPORTED_GROUP_LEN).to_string(),
            ),
            ("supported_groups", self.labels().join(",")),
            (
                "supported_groups_raw",
                self.groups
                    .groups()
                    .iter()
                    .map(|group| format!("0x{:04x}", group.raw()))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }
}

impl From<TlsNamedGroupList> for TlsSupportedGroups {
    fn from(groups: TlsNamedGroupList) -> Self {
        Self::new(groups)
    }
}

impl From<Vec<TlsNamedGroup>> for TlsSupportedGroups {
    fn from(groups: Vec<TlsNamedGroup>) -> Self {
        Self::from_groups(groups)
    }
}

impl<const N: usize> From<[TlsNamedGroup; N]> for TlsSupportedGroups {
    fn from(groups: [TlsNamedGroup; N]) -> Self {
        Self::from_groups(Vec::from(groups))
    }
}

impl TryFrom<&TlsRawExtension> for TlsSupportedGroups {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsSupportedGroups> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsSupportedGroups) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_supported_groups(groups: &TlsSupportedGroups) -> Result<()> {
    let byte_len = groups.groups.byte_len()?;
    validate_supported_groups_list_len(byte_len)
}

fn validate_supported_groups_list_len(len: usize) -> Result<()> {
    if len < TLS_SUPPORTED_GROUP_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.supported_groups.length",
            "length must be at least two bytes",
        ));
    }
    if len % TLS_SUPPORTED_GROUP_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "tls.supported_groups.length",
            "length must be a multiple of two bytes",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.supported_groups.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

/// A raw-preserving TLS legacy `ECPointFormat` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsEcPointFormat {
    raw: u8,
}

impl TlsEcPointFormat {
    /// RFC 8422 `uncompressed` point format.
    pub const UNCOMPRESSED: Self = Self::new(TLS_EC_POINT_FORMAT_UNCOMPRESSED);
    /// RFC 8422 `ansiX962_compressed_prime` point format, deprecated by RFC 8422.
    pub const ANSIX962_COMPRESSED_PRIME: Self =
        Self::new(TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME);
    /// RFC 8422 `ansiX962_compressed_char2` point format, deprecated by RFC 8422.
    pub const ANSIX962_COMPRESSED_CHAR2: Self =
        Self::new(TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2);

    /// Preserve a caller-supplied one-octet EC point format value.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied one-octet EC point format value.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// Decode a TLS EC point format from exactly one byte.
    pub const fn from_be_bytes(bytes: [u8; TLS_EC_POINT_FORMAT_LEN]) -> Self {
        Self::new(bytes[0])
    }

    /// RFC 8422 `uncompressed` constructor.
    pub const fn uncompressed() -> Self {
        Self::UNCOMPRESSED
    }

    /// RFC 8422 `ansiX962_compressed_prime` constructor.
    pub const fn ansi_x962_compressed_prime() -> Self {
        Self::ANSIX962_COMPRESSED_PRIME
    }

    /// RFC 8422 `ansiX962_compressed_char2` constructor.
    pub const fn ansi_x962_compressed_char2() -> Self {
        Self::ANSIX962_COMPRESSED_CHAR2
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the one-byte wire encoding.
    pub const fn to_be_bytes(self) -> [u8; TLS_EC_POINT_FORMAT_LEN] {
        [self.raw]
    }

    /// Append the one-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.push(self.raw);
    }

    /// Return the one-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    /// Decode a TLS EC point format from the first byte of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (format, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(format)
    }

    /// Decode a TLS EC point format from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_EC_POINT_FORMAT_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.ec_point_format",
                TLS_EC_POINT_FORMAT_LEN,
                bytes.len(),
            ));
        }

        Ok((Self::from_be_bytes([bytes[0]]), &bytes[1..]))
    }

    /// Return the source-backed EC point format name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        match self.raw {
            TLS_EC_POINT_FORMAT_UNCOMPRESSED => Some("uncompressed"),
            TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME => Some("ansiX962_compressed_prime"),
            TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2 => Some("ansiX962_compressed_char2"),
            _ => None,
        }
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        match self.raw {
            TLS_EC_POINT_FORMAT_UNCOMPRESSED => TlsCodepointStatus::DefaultEligible,
            TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME
            | TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2 => TlsCodepointStatus::PreserveOnly,
            3..=247 => TlsCodepointStatus::Unassigned,
            248..=255 => TlsCodepointStatus::PrivateUse,
        }
    }

    /// Return true when this is the RFC 8422 uncompressed point format.
    pub const fn is_uncompressed(self) -> bool {
        self.raw == TLS_EC_POINT_FORMAT_UNCOMPRESSED
    }

    /// Return true for RFC 8422's deprecated compressed point formats.
    pub const fn is_deprecated_compressed(self) -> bool {
        matches!(
            self.raw,
            TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME
                | TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2
        )
    }

    /// Return true for IANA private-use EC point format values.
    pub const fn is_private_use(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::PrivateUse)
    }

    /// Return true for the point format selected for the convenience builder.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        if let Some(name) = self.name() {
            return name.to_string();
        }

        match self.status() {
            TlsCodepointStatus::PrivateUse => {
                format!("private-use ec point format 0x{:02x}", self.raw)
            }
            TlsCodepointStatus::Unassigned => {
                format!("unassigned ec point format 0x{:02x}", self.raw)
            }
            _ => format!("unknown ec point format 0x{:02x}", self.raw),
        }
    }

    /// Stable one-line summary preserving raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:02x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("ec_point_format", self.label()),
            ("ec_point_format_raw", format!("0x{:02x}", self.raw)),
            ("ec_point_format_status", self.status().label().to_string()),
            (
                "ec_point_format_deprecated_compressed",
                self.is_deprecated_compressed().to_string(),
            ),
            ("private_use", self.is_private_use().to_string()),
        ]
    }
}

impl From<u8> for TlsEcPointFormat {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsEcPointFormat> for u8 {
    fn from(value: TlsEcPointFormat) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsEcPointFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// TLS legacy `ec_point_formats` extension body as an RFC 8422 ECPointFormatList.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsEcPointFormats {
    formats: Vec<TlsEcPointFormat>,
}

impl TlsEcPointFormats {
    /// Create an ordered ec_point_formats extension body.
    pub fn new(formats: impl Into<Vec<TlsEcPointFormat>>) -> Self {
        Self {
            formats: formats.into(),
        }
    }

    /// Create an ordered ec_point_formats extension body from point format values.
    pub fn from_formats(formats: impl Into<Vec<TlsEcPointFormat>>) -> Self {
        Self::new(formats)
    }

    /// Create an ordered ec_point_formats extension body from raw one-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u8>) -> Self {
        Self::new(
            raws.into_iter()
                .map(TlsEcPointFormat::from_u8)
                .collect::<Vec<_>>(),
        )
    }

    /// Create the RFC 8422 compatibility form containing only `uncompressed`.
    pub fn uncompressed_only() -> Self {
        Self::new(vec![TlsEcPointFormat::UNCOMPRESSED])
    }

    /// Borrow the ordered EC point format values.
    pub fn formats(&self) -> &[TlsEcPointFormat] {
        &self.formats
    }

    /// Return the ordered raw EC point format values.
    pub fn raw_values(&self) -> Vec<u8> {
        self.formats.iter().map(|format| format.raw()).collect()
    }

    /// Return EC point format labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.formats.iter().map(|format| format.label()).collect()
    }

    /// Consume the extension body and return the ordered EC point format values.
    pub fn into_vec(self) -> Vec<TlsEcPointFormat> {
        self.formats
    }

    /// Append one EC point format to the ordered list.
    pub fn push(&mut self, format: TlsEcPointFormat) {
        self.formats.push(format);
    }

    /// Number of EC point format values.
    pub fn len(&self) -> usize {
        self.formats.len()
    }

    /// Return true when the body carries no EC point format values.
    pub fn is_empty(&self) -> bool {
        self.formats.is_empty()
    }

    /// Return true when the body is exactly the RFC 8422 uncompressed-only form.
    pub fn is_uncompressed_only(&self) -> bool {
        self.formats == [TlsEcPointFormat::UNCOMPRESSED]
    }

    /// Number of bytes occupied by the point-format vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let byte_len = self
            .formats
            .len()
            .checked_mul(TLS_EC_POINT_FORMAT_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.ec_point_formats.length", "length overflow")
            })?;
        validate_ec_point_formats_len(byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete encoded ECPointFormatList body.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_EC_POINT_FORMATS_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.ec_point_formats.length", "length overflow")
            })
    }

    /// Append the ec_point_formats extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let byte_len = u8::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.ec_point_formats.length",
                "length must fit in one byte",
            )
        })?;
        out.push(byte_len);
        for format in &self.formats {
            format.encode(out);
        }
        Ok(())
    }

    /// Return this ec_point_formats extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this ec_point_formats body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::EC_POINT_FORMATS,
            self.encode_to_vec()?,
        ))
    }

    /// Decode an ec_point_formats extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (formats, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.ec_point_formats.length",
                "length must match extension body",
            ));
        }
        Ok(formats)
    }

    /// Decode an ec_point_formats body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_EC_POINT_FORMATS_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.ec_point_formats.length",
                TLS_EC_POINT_FORMATS_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = bytes[0] as usize;
        validate_ec_point_formats_len(byte_len)?;
        let required = TLS_EC_POINT_FORMATS_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value("tls.ec_point_formats.length", "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.ec_point_formats",
                required,
                bytes.len(),
            ));
        }

        let formats = bytes[TLS_EC_POINT_FORMATS_LENGTH_LEN..required]
            .iter()
            .copied()
            .map(TlsEcPointFormat::from_u8)
            .collect::<Vec<_>>();
        Ok((Self::new(formats), &bytes[required..]))
    }

    /// Decode a raw ec_point_formats extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::EC_POINT_FORMATS {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be ec_point_formats",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving point-format order.
    pub fn summary(&self) -> String {
        format!(
            "ec_point_formats count={} bytes={} values={}",
            self.len(),
            self.len() * TLS_EC_POINT_FORMAT_LEN,
            self.labels().join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("ec_point_formats_count", self.len().to_string()),
            (
                "ec_point_formats_bytes",
                (self.len() * TLS_EC_POINT_FORMAT_LEN).to_string(),
            ),
            ("ec_point_formats", self.labels().join(",")),
            (
                "ec_point_formats_raw",
                self.formats
                    .iter()
                    .map(|format| format!("0x{:02x}", format.raw()))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "ec_point_formats_uncompressed_only",
                self.is_uncompressed_only().to_string(),
            ),
        ]
    }
}

impl From<Vec<TlsEcPointFormat>> for TlsEcPointFormats {
    fn from(formats: Vec<TlsEcPointFormat>) -> Self {
        Self::new(formats)
    }
}

impl<const N: usize> From<[TlsEcPointFormat; N]> for TlsEcPointFormats {
    fn from(formats: [TlsEcPointFormat; N]) -> Self {
        Self::new(Vec::from(formats))
    }
}

impl TryFrom<&TlsRawExtension> for TlsEcPointFormats {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsEcPointFormats> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsEcPointFormats) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_ec_point_formats_len(len: usize) -> Result<()> {
    if len < TLS_EC_POINT_FORMAT_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.ec_point_formats.length",
            "length must be at least one byte",
        ));
    }
    if len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.ec_point_formats.length",
            "length must fit in one byte",
        ));
    }
    Ok(())
}

/// TLS `signature_algorithms` extension body as an RFC 8446 SignatureSchemeList.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsSignatureAlgorithms {
    schemes: TlsSignatureSchemeList,
}

impl TlsSignatureAlgorithms {
    /// Create an ordered signature_algorithms extension body.
    pub fn new(schemes: impl Into<TlsSignatureSchemeList>) -> Self {
        Self {
            schemes: schemes.into(),
        }
    }

    /// Create an ordered signature_algorithms extension body from signature scheme values.
    pub fn from_schemes(schemes: impl Into<Vec<TlsSignatureScheme>>) -> Self {
        Self::new(TlsSignatureSchemeList::new(schemes))
    }

    /// Create an ordered signature_algorithms extension body from raw two-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u16>) -> Self {
        Self::new(TlsSignatureSchemeList::from_raws(raws))
    }

    /// Borrow the ordered signature scheme list.
    pub const fn signature_scheme_list(&self) -> &TlsSignatureSchemeList {
        &self.schemes
    }

    /// Borrow the ordered signature scheme list.
    pub const fn as_signature_scheme_list(&self) -> &TlsSignatureSchemeList {
        self.signature_scheme_list()
    }

    /// Borrow the ordered signature scheme values.
    pub fn schemes(&self) -> &[TlsSignatureScheme] {
        self.schemes.schemes()
    }

    /// Return the ordered raw signature scheme values.
    pub fn raw_values(&self) -> Vec<u16> {
        self.schemes.raw_values()
    }

    /// Return signature scheme labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.schemes.labels()
    }

    /// Consume the extension body and return its signature scheme list.
    pub fn into_signature_scheme_list(self) -> TlsSignatureSchemeList {
        self.schemes
    }

    /// Consume the extension body and return the ordered signature scheme values.
    pub fn into_vec(self) -> Vec<TlsSignatureScheme> {
        self.schemes.into_vec()
    }

    /// Append one signature scheme to the ordered list.
    pub fn push(&mut self, scheme: TlsSignatureScheme) {
        self.schemes.push(scheme);
    }

    /// Number of signature schemes.
    pub fn len(&self) -> usize {
        self.schemes.len()
    }

    /// Return true when the body carries no signature scheme values.
    pub fn is_empty(&self) -> bool {
        self.schemes.is_empty()
    }

    /// Number of bytes occupied by the SignatureScheme vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let byte_len =
            signature_scheme_list_byte_len("tls.signature_algorithms.length", &self.schemes)?;
        validate_signature_scheme_list_len("tls.signature_algorithms.length", byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete encoded SignatureSchemeList.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.signature_algorithms.length",
                    "length overflow",
                )
            })
    }

    /// Append the signature_algorithms extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        out.extend_from_slice(&(byte_len as u16).to_be_bytes());
        for scheme in self.schemes() {
            scheme.encode(out);
        }
        Ok(())
    }

    /// Return this signature_algorithms extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this signature_algorithms body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::SIGNATURE_ALGORITHMS,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a signature_algorithms extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (algorithms, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.signature_algorithms.length",
                "length must match extension body",
            ));
        }
        Ok(algorithms)
    }

    /// Decode a signature_algorithms body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (schemes, tail) = decode_signature_scheme_list_prefix(
            "tls.signature_algorithms.length",
            "tls.signature_algorithms",
            bytes,
        )?;
        Ok((Self::new(schemes), tail))
    }

    /// Decode a raw signature_algorithms extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::SIGNATURE_ALGORITHMS {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be signature_algorithms",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving signature scheme order.
    pub fn summary(&self) -> String {
        format!(
            "signature_algorithms count={} bytes={} values={}",
            self.len(),
            self.len() * TLS_SIGNATURE_ALGORITHM_LEN,
            self.labels().join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("signature_algorithms_count", self.len().to_string()),
            (
                "signature_algorithms_bytes",
                (self.len() * TLS_SIGNATURE_ALGORITHM_LEN).to_string(),
            ),
            ("signature_algorithms", self.labels().join(",")),
            (
                "signature_algorithms_raw",
                format_signature_scheme_raw_values(&self.schemes),
            ),
        ]
    }
}

impl From<TlsSignatureSchemeList> for TlsSignatureAlgorithms {
    fn from(schemes: TlsSignatureSchemeList) -> Self {
        Self::new(schemes)
    }
}

impl From<Vec<TlsSignatureScheme>> for TlsSignatureAlgorithms {
    fn from(schemes: Vec<TlsSignatureScheme>) -> Self {
        Self::from_schemes(schemes)
    }
}

impl<const N: usize> From<[TlsSignatureScheme; N]> for TlsSignatureAlgorithms {
    fn from(schemes: [TlsSignatureScheme; N]) -> Self {
        Self::from_schemes(Vec::from(schemes))
    }
}

impl TryFrom<&TlsRawExtension> for TlsSignatureAlgorithms {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsSignatureAlgorithms> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsSignatureAlgorithms) -> Result<Self> {
        value.to_raw_extension()
    }
}

/// TLS `signature_algorithms_cert` extension body as an RFC 8446 SignatureSchemeList.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsSignatureAlgorithmsCert {
    schemes: TlsSignatureSchemeList,
}

impl TlsSignatureAlgorithmsCert {
    /// Create an ordered signature_algorithms_cert extension body.
    pub fn new(schemes: impl Into<TlsSignatureSchemeList>) -> Self {
        Self {
            schemes: schemes.into(),
        }
    }

    /// Create an ordered signature_algorithms_cert extension body from signature scheme values.
    pub fn from_schemes(schemes: impl Into<Vec<TlsSignatureScheme>>) -> Self {
        Self::new(TlsSignatureSchemeList::new(schemes))
    }

    /// Create an ordered signature_algorithms_cert extension body from raw two-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u16>) -> Self {
        Self::new(TlsSignatureSchemeList::from_raws(raws))
    }

    /// Borrow the ordered signature scheme list.
    pub const fn signature_scheme_list(&self) -> &TlsSignatureSchemeList {
        &self.schemes
    }

    /// Borrow the ordered signature scheme list.
    pub const fn as_signature_scheme_list(&self) -> &TlsSignatureSchemeList {
        self.signature_scheme_list()
    }

    /// Borrow the ordered signature scheme values.
    pub fn schemes(&self) -> &[TlsSignatureScheme] {
        self.schemes.schemes()
    }

    /// Return the ordered raw signature scheme values.
    pub fn raw_values(&self) -> Vec<u16> {
        self.schemes.raw_values()
    }

    /// Return signature scheme labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.schemes.labels()
    }

    /// Consume the extension body and return its signature scheme list.
    pub fn into_signature_scheme_list(self) -> TlsSignatureSchemeList {
        self.schemes
    }

    /// Consume the extension body and return the ordered signature scheme values.
    pub fn into_vec(self) -> Vec<TlsSignatureScheme> {
        self.schemes.into_vec()
    }

    /// Append one signature scheme to the ordered list.
    pub fn push(&mut self, scheme: TlsSignatureScheme) {
        self.schemes.push(scheme);
    }

    /// Number of signature schemes.
    pub fn len(&self) -> usize {
        self.schemes.len()
    }

    /// Return true when the body carries no signature scheme values.
    pub fn is_empty(&self) -> bool {
        self.schemes.is_empty()
    }

    /// Number of bytes occupied by the SignatureScheme vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let byte_len =
            signature_scheme_list_byte_len("tls.signature_algorithms_cert.length", &self.schemes)?;
        validate_signature_scheme_list_len("tls.signature_algorithms_cert.length", byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete encoded SignatureSchemeList.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.signature_algorithms_cert.length",
                    "length overflow",
                )
            })
    }

    /// Append the signature_algorithms_cert extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        out.extend_from_slice(&(byte_len as u16).to_be_bytes());
        for scheme in self.schemes() {
            scheme.encode(out);
        }
        Ok(())
    }

    /// Return this signature_algorithms_cert extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this signature_algorithms_cert body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::SIGNATURE_ALGORITHMS_CERT,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a signature_algorithms_cert extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (algorithms, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.signature_algorithms_cert.length",
                "length must match extension body",
            ));
        }
        Ok(algorithms)
    }

    /// Decode a signature_algorithms_cert body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        let (schemes, tail) = decode_signature_scheme_list_prefix(
            "tls.signature_algorithms_cert.length",
            "tls.signature_algorithms_cert",
            bytes,
        )?;
        Ok((Self::new(schemes), tail))
    }

    /// Decode a raw signature_algorithms_cert extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::SIGNATURE_ALGORITHMS_CERT {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be signature_algorithms_cert",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving signature scheme order.
    pub fn summary(&self) -> String {
        format!(
            "signature_algorithms_cert count={} bytes={} values={}",
            self.len(),
            self.len() * TLS_SIGNATURE_ALGORITHM_LEN,
            self.labels().join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("signature_algorithms_cert_count", self.len().to_string()),
            (
                "signature_algorithms_cert_bytes",
                (self.len() * TLS_SIGNATURE_ALGORITHM_LEN).to_string(),
            ),
            ("signature_algorithms_cert", self.labels().join(",")),
            (
                "signature_algorithms_cert_raw",
                format_signature_scheme_raw_values(&self.schemes),
            ),
        ]
    }
}

impl From<TlsSignatureSchemeList> for TlsSignatureAlgorithmsCert {
    fn from(schemes: TlsSignatureSchemeList) -> Self {
        Self::new(schemes)
    }
}

impl From<Vec<TlsSignatureScheme>> for TlsSignatureAlgorithmsCert {
    fn from(schemes: Vec<TlsSignatureScheme>) -> Self {
        Self::from_schemes(schemes)
    }
}

impl<const N: usize> From<[TlsSignatureScheme; N]> for TlsSignatureAlgorithmsCert {
    fn from(schemes: [TlsSignatureScheme; N]) -> Self {
        Self::from_schemes(Vec::from(schemes))
    }
}

impl TryFrom<&TlsRawExtension> for TlsSignatureAlgorithmsCert {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsSignatureAlgorithmsCert> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsSignatureAlgorithmsCert) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn signature_scheme_list_byte_len(
    field: &'static str,
    schemes: &TlsSignatureSchemeList,
) -> Result<usize> {
    schemes
        .len()
        .checked_mul(TLS_SIGNATURE_ALGORITHM_LEN)
        .ok_or_else(|| CrafterError::invalid_field_value(field, "length overflow"))
}

fn validate_signature_scheme_list_len(field: &'static str, len: usize) -> Result<()> {
    if len < TLS_SIGNATURE_ALGORITHM_LEN {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must be at least two bytes",
        ));
    }
    if len % TLS_SIGNATURE_ALGORITHM_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must be a multiple of two bytes",
        ));
    }
    if len > u16::MAX as usize - 1 {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn decode_signature_scheme_list_prefix<'a>(
    field: &'static str,
    body_context: &'static str,
    bytes: &'a [u8],
) -> Result<(TlsSignatureSchemeList, &'a [u8])> {
    if bytes.len() < TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN {
        return Err(CrafterError::buffer_too_short(
            field,
            TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN,
            bytes.len(),
        ));
    }

    let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    validate_signature_scheme_list_len(field, byte_len)?;
    let required = TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN
        .checked_add(byte_len)
        .ok_or_else(|| CrafterError::invalid_field_value(field, "length overflow"))?;
    if bytes.len() < required {
        return Err(CrafterError::buffer_too_short(
            body_context,
            required,
            bytes.len(),
        ));
    }

    let (schemes, tail) = TlsSignatureSchemeList::decode_prefix(&bytes[..required])?;
    debug_assert!(tail.is_empty());
    Ok((schemes, &bytes[required..]))
}

fn format_signature_scheme_raw_values(schemes: &TlsSignatureSchemeList) -> String {
    schemes
        .schemes()
        .iter()
        .map(|scheme| format!("0x{:04x}", scheme.raw()))
        .collect::<Vec<_>>()
        .join(",")
}

/// Context that selects the TLS `supported_versions` extension body shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsSupportedVersionsContext {
    /// ClientHello carries a uint8 length-prefixed ProtocolVersion list.
    ClientHello,
    /// ServerHello carries one selected ProtocolVersion.
    ServerHello,
    /// HelloRetryRequest uses the ServerHello extension body shape.
    HelloRetryRequest,
}

impl TlsSupportedVersionsContext {
    /// ClientHello context constructor.
    pub const fn client_hello() -> Self {
        Self::ClientHello
    }

    /// ServerHello context constructor.
    pub const fn server_hello() -> Self {
        Self::ServerHello
    }

    /// HelloRetryRequest context constructor.
    pub const fn hello_retry_request() -> Self {
        Self::HelloRetryRequest
    }

    const fn is_client_list(self) -> bool {
        matches!(self, Self::ClientHello)
    }

    const fn length_field(self) -> &'static str {
        match self {
            Self::ClientHello => "tls.supported_versions.client.length",
            Self::ServerHello => "tls.supported_versions.server.length",
            Self::HelloRetryRequest => "tls.supported_versions.hello_retry_request.length",
        }
    }

    const fn version_field(self) -> &'static str {
        match self {
            Self::ClientHello => "tls.supported_versions.client.version",
            Self::ServerHello => "tls.supported_versions.server.version",
            Self::HelloRetryRequest => "tls.supported_versions.hello_retry_request.version",
        }
    }
}

impl Default for TlsSupportedVersionsContext {
    fn default() -> Self {
        Self::ClientHello
    }
}

/// TLS `supported_versions` extension body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsSupportedVersions {
    /// ClientHello uint8 length-prefixed ProtocolVersion list.
    Client { versions: Vec<TlsVersion> },
    /// ServerHello or HelloRetryRequest selected ProtocolVersion.
    Server { selected_version: TlsVersion },
}

impl TlsSupportedVersions {
    /// Create a ClientHello supported-version list.
    pub fn client(versions: impl Into<Vec<TlsVersion>>) -> Self {
        Self::Client {
            versions: versions.into(),
        }
    }

    /// Create a ClientHello list advertising only TLS 1.2.
    pub fn client_tls_1_2() -> Self {
        Self::client(vec![TlsVersion::tls_1_2()])
    }

    /// Create a ClientHello list advertising only TLS 1.3.
    pub fn client_tls_1_3() -> Self {
        Self::client(vec![TlsVersion::tls_1_3()])
    }

    /// Create a ClientHello list advertising TLS 1.3, then TLS 1.2.
    pub fn client_tls_1_3_then_tls_1_2() -> Self {
        Self::client(vec![TlsVersion::tls_1_3(), TlsVersion::tls_1_2()])
    }

    /// Create a ServerHello or HelloRetryRequest selected version.
    pub fn server(selected_version: impl Into<TlsVersion>) -> Self {
        Self::Server {
            selected_version: selected_version.into(),
        }
    }

    /// Create a ServerHello selected TLS 1.2 version.
    pub fn server_tls_1_2() -> Self {
        Self::server(TlsVersion::tls_1_2())
    }

    /// Create a ServerHello or HelloRetryRequest selected TLS 1.3 version.
    pub fn server_tls_1_3() -> Self {
        Self::server(TlsVersion::tls_1_3())
    }

    /// Return true when this is a ClientHello list form.
    pub const fn is_client(&self) -> bool {
        matches!(self, Self::Client { .. })
    }

    /// Return true when this is a ServerHello or HelloRetryRequest selected form.
    pub const fn is_server(&self) -> bool {
        matches!(self, Self::Server { .. })
    }

    /// Borrow ClientHello supported versions, if this is the client-list form.
    pub fn versions(&self) -> Option<&[TlsVersion]> {
        match self {
            Self::Client { versions } => Some(versions),
            Self::Server { .. } => None,
        }
    }

    /// Borrow the selected ServerHello or HelloRetryRequest version, if present.
    pub const fn selected_version(&self) -> Option<TlsVersion> {
        match self {
            Self::Client { .. } => None,
            Self::Server { selected_version } => Some(*selected_version),
        }
    }

    /// Number of bytes occupied by this extension body.
    pub fn encoded_len(&self) -> Result<usize> {
        match self {
            Self::Client { versions } => {
                validate_supported_versions_client(versions)?;
                TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN
                    .checked_add(versions.len() * TLS_SUPPORTED_VERSION_LEN)
                    .ok_or_else(|| {
                        CrafterError::invalid_field_value(
                            "tls.supported_versions.client.length",
                            "length overflow",
                        )
                    })
            }
            Self::Server { .. } => Ok(TLS_SUPPORTED_VERSION_LEN),
        }
    }

    /// Append this supported_versions body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Client { versions } => {
                validate_supported_versions_client(versions)?;
                let byte_len = versions.len() * TLS_SUPPORTED_VERSION_LEN;
                let byte_len = u8::try_from(byte_len).map_err(|_| {
                    CrafterError::invalid_field_value(
                        "tls.supported_versions.client.length",
                        "length must fit in one byte",
                    )
                })?;
                out.push(byte_len);
                for version in versions {
                    out.extend_from_slice(&version.to_be_bytes());
                }
            }
            Self::Server { selected_version } => {
                out.extend_from_slice(&selected_version.to_be_bytes());
            }
        }
        Ok(())
    }

    /// Return this supported_versions body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this supported_versions body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::SUPPORTED_VERSIONS,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a context-selected supported_versions body.
    pub fn decode_with_context(
        context: TlsSupportedVersionsContext,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let bytes = bytes.as_ref();
        if context.is_client_list() {
            Self::decode_client(bytes)
        } else {
            Self::decode_server_like(context, bytes)
        }
    }

    /// Decode a ClientHello supported_versions body.
    pub fn decode_client(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.supported_versions.client.length",
                TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let list_len = bytes[0] as usize;
        validate_supported_versions_client_list_len(list_len)?;
        let required = TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN
            .checked_add(list_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.supported_versions.client.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.supported_versions.client",
                required,
                bytes.len(),
            ));
        }
        if bytes.len() != required {
            return Err(CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length must match extension body",
            ));
        }

        let mut versions = Vec::with_capacity(list_len / TLS_SUPPORTED_VERSION_LEN);
        let mut cursor = TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN;
        while cursor < required {
            versions.push(TlsVersion::from_be_bytes([
                bytes[cursor],
                bytes[cursor + 1],
            ]));
            cursor += TLS_SUPPORTED_VERSION_LEN;
        }
        validate_supported_versions_client(&versions)?;
        Ok(Self::client(versions))
    }

    /// Decode a ServerHello supported_versions body.
    pub fn decode_server(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Self::decode_server_like(TlsSupportedVersionsContext::ServerHello, bytes.as_ref())
    }

    /// Decode a HelloRetryRequest supported_versions body.
    pub fn decode_hello_retry_request(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Self::decode_server_like(
            TlsSupportedVersionsContext::HelloRetryRequest,
            bytes.as_ref(),
        )
    }

    fn decode_server_like(context: TlsSupportedVersionsContext, bytes: &[u8]) -> Result<Self> {
        if bytes.len() < TLS_SUPPORTED_VERSION_LEN {
            return Err(CrafterError::buffer_too_short(
                context.version_field(),
                TLS_SUPPORTED_VERSION_LEN,
                bytes.len(),
            ));
        }
        if bytes.len() != TLS_SUPPORTED_VERSION_LEN {
            return Err(CrafterError::invalid_field_value(
                context.length_field(),
                "length must be exactly two bytes",
            ));
        }

        Ok(Self::server(TlsVersion::from_be_bytes([
            bytes[0], bytes[1],
        ])))
    }

    /// Decode a raw supported_versions extension body using a context.
    pub fn from_raw_extension_with_context(
        context: TlsSupportedVersionsContext,
        extension: &TlsRawExtension,
    ) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::SUPPORTED_VERSIONS {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be supported_versions",
            ));
        }
        Self::decode_with_context(context, extension.body())
    }

    /// Decode a raw ClientHello supported_versions extension body.
    pub fn from_client_hello_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(TlsSupportedVersionsContext::ClientHello, extension)
    }

    /// Decode a raw ServerHello supported_versions extension body.
    pub fn from_server_hello_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(TlsSupportedVersionsContext::ServerHello, extension)
    }

    /// Decode a raw HelloRetryRequest supported_versions extension body.
    pub fn from_hello_retry_request_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(
            TlsSupportedVersionsContext::HelloRetryRequest,
            extension,
        )
    }

    /// Stable one-line summary preserving body shape and raw versions.
    pub fn summary(&self) -> String {
        match self {
            Self::Client { versions } => {
                let values = versions
                    .iter()
                    .map(|version| format!("{}:0x{:04x}", version.label(), version.raw()))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    "supported_versions context=client count={} values={}",
                    versions.len(),
                    values
                )
            }
            Self::Server { selected_version } => format!(
                "supported_versions context=server selected={}:0x{:04x}",
                selected_version.label(),
                selected_version.raw()
            ),
        }
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Client { versions } => vec![
                ("supported_versions_context", "client".to_string()),
                ("supported_versions_count", versions.len().to_string()),
                (
                    "supported_versions",
                    versions
                        .iter()
                        .map(|version| version.label())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "supported_versions_raw",
                    versions
                        .iter()
                        .map(|version| format!("0x{:04x}", version.raw()))
                        .collect::<Vec<_>>()
                        .join(","),
                ),
            ],
            Self::Server { selected_version } => vec![
                ("supported_versions_context", "server".to_string()),
                ("supported_versions_selected", selected_version.label()),
                (
                    "supported_versions_selected_raw",
                    format!("0x{:04x}", selected_version.raw()),
                ),
            ],
        }
    }
}

impl From<Vec<TlsVersion>> for TlsSupportedVersions {
    fn from(versions: Vec<TlsVersion>) -> Self {
        Self::client(versions)
    }
}

impl<const N: usize> From<[TlsVersion; N]> for TlsSupportedVersions {
    fn from(versions: [TlsVersion; N]) -> Self {
        Self::client(Vec::from(versions))
    }
}

impl TryFrom<TlsSupportedVersions> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsSupportedVersions) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_supported_versions_client(versions: &[TlsVersion]) -> Result<()> {
    let byte_len = versions
        .len()
        .checked_mul(TLS_SUPPORTED_VERSION_LEN)
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length overflow",
            )
        })?;
    validate_supported_versions_client_list_len(byte_len)
}

fn validate_supported_versions_client_list_len(len: usize) -> Result<()> {
    if len == 0 {
        return Err(CrafterError::invalid_field_value(
            "tls.supported_versions.client.length",
            "length must be at least two bytes",
        ));
    }
    if len % TLS_SUPPORTED_VERSION_LEN != 0 {
        return Err(CrafterError::invalid_field_value(
            "tls.supported_versions.client.length",
            "length must be a multiple of two bytes",
        ));
    }
    if len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.supported_versions.client.length",
            "length must fit in one byte",
        ));
    }
    Ok(())
}

/// A raw-preserving TLS 1.3 `PskKeyExchangeMode` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TlsPskKeyExchangeMode {
    raw: u8,
}

impl TlsPskKeyExchangeMode {
    /// TLS 1.3 PskKeyExchangeMode `psk_ke`.
    pub const PSK_KE: Self = Self::new(TLS_PSK_KEY_EXCHANGE_MODE_PSK_KE);
    /// TLS 1.3 PskKeyExchangeMode `psk_dhe_ke`.
    pub const PSK_DHE_KE: Self = Self::new(TLS_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE);

    /// Preserve a caller-supplied one-octet PSK key exchange mode value.
    pub const fn new(raw: u8) -> Self {
        Self { raw }
    }

    /// Preserve a caller-supplied one-octet PSK key exchange mode value.
    pub const fn from_u8(raw: u8) -> Self {
        Self::new(raw)
    }

    /// Decode a TLS PSK key exchange mode from exactly one byte.
    pub const fn from_be_bytes(bytes: [u8; TLS_PSK_KEY_EXCHANGE_MODE_LEN]) -> Self {
        Self::new(bytes[0])
    }

    /// TLS 1.3 PskKeyExchangeMode `psk_ke` constructor.
    pub const fn psk_ke() -> Self {
        Self::PSK_KE
    }

    /// TLS 1.3 PskKeyExchangeMode `psk_dhe_ke` constructor.
    pub const fn psk_dhe_ke() -> Self {
        Self::PSK_DHE_KE
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn raw(self) -> u8 {
        self.raw
    }

    /// Return the preserved raw one-octet wire value.
    pub const fn as_u8(self) -> u8 {
        self.raw
    }

    /// Return the one-byte wire encoding.
    pub const fn to_be_bytes(self) -> [u8; TLS_PSK_KEY_EXCHANGE_MODE_LEN] {
        [self.raw]
    }

    /// Append the one-byte wire encoding to `out`.
    pub fn encode(self, out: &mut Vec<u8>) {
        out.push(self.raw);
    }

    /// Return the one-byte wire encoding as a vector.
    pub fn encode_to_vec(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }

    /// Decode a TLS PSK key exchange mode from the first byte of `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (mode, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(mode)
    }

    /// Decode a TLS PSK key exchange mode from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_PSK_KEY_EXCHANGE_MODE_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.psk_key_exchange_mode",
                TLS_PSK_KEY_EXCHANGE_MODE_LEN,
                bytes.len(),
            ));
        }

        Ok((Self::from_be_bytes([bytes[0]]), &bytes[1..]))
    }

    /// Return the source-backed PSK key exchange mode name, when selected.
    pub const fn name(self) -> Option<&'static str> {
        constants::tls_psk_mode_name(self.raw)
    }

    /// Return the source-backed assignment status.
    pub const fn status(self) -> TlsCodepointStatus {
        constants::tls_psk_mode_status(self.raw)
    }

    /// Return true when this mode has a selected source-backed name.
    pub const fn is_known(self) -> bool {
        self.name().is_some()
    }

    /// Return true for modes selected for default TLS builders.
    pub const fn is_default_eligible(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::DefaultEligible)
    }

    /// Return true for RFC 8701 sparse GREASE PSK key exchange mode values.
    pub const fn is_grease(self) -> bool {
        constants::is_tls_psk_mode_grease(self.raw)
    }

    /// Return true for IANA private-use PSK key exchange mode values.
    pub const fn is_private_use(self) -> bool {
        matches!(self.status(), TlsCodepointStatus::PrivateUse)
    }

    /// Human-readable label preserving unknown values numerically.
    pub fn label(self) -> String {
        constants::tls_psk_mode_label(self.raw)
    }

    /// Stable one-line summary preserving raw value and source-backed status.
    pub fn summary(self) -> String {
        format!(
            "{} raw=0x{:02x} status={}",
            self.label(),
            self.raw,
            self.status().label()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(self) -> Vec<(&'static str, String)> {
        vec![
            ("psk_key_exchange_mode", self.label()),
            ("psk_key_exchange_mode_raw", format!("0x{:02x}", self.raw)),
            (
                "psk_key_exchange_mode_status",
                self.status().label().to_string(),
            ),
            ("grease", self.is_grease().to_string()),
            ("private_use", self.is_private_use().to_string()),
        ]
    }
}

impl From<u8> for TlsPskKeyExchangeMode {
    fn from(value: u8) -> Self {
        Self::new(value)
    }
}

impl From<TlsPskKeyExchangeMode> for u8 {
    fn from(value: TlsPskKeyExchangeMode) -> Self {
        value.raw()
    }
}

impl fmt::Display for TlsPskKeyExchangeMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// TLS `psk_key_exchange_modes` extension body as an RFC 8446 PskKeyExchangeModes vector.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsPskKeyExchangeModes {
    modes: Vec<TlsPskKeyExchangeMode>,
}

impl TlsPskKeyExchangeModes {
    /// Create an ordered psk_key_exchange_modes extension body.
    pub fn new(modes: impl Into<Vec<TlsPskKeyExchangeMode>>) -> Self {
        Self {
            modes: modes.into(),
        }
    }

    /// Create an ordered psk_key_exchange_modes extension body from mode values.
    pub fn from_modes(modes: impl Into<Vec<TlsPskKeyExchangeMode>>) -> Self {
        Self::new(modes)
    }

    /// Create an ordered psk_key_exchange_modes extension body from raw one-octet values.
    pub fn from_raws(raws: impl IntoIterator<Item = u8>) -> Self {
        Self::new(
            raws.into_iter()
                .map(TlsPskKeyExchangeMode::from_u8)
                .collect::<Vec<_>>(),
        )
    }

    /// Create a psk_key_exchange_modes body advertising only `psk_ke`.
    pub fn psk_ke() -> Self {
        Self::new(vec![TlsPskKeyExchangeMode::PSK_KE])
    }

    /// Create a psk_key_exchange_modes body advertising only `psk_dhe_ke`.
    pub fn psk_dhe_ke() -> Self {
        Self::new(vec![TlsPskKeyExchangeMode::PSK_DHE_KE])
    }

    /// Create a psk_key_exchange_modes body advertising `psk_ke`, then `psk_dhe_ke`.
    pub fn psk_ke_then_psk_dhe_ke() -> Self {
        Self::new(vec![
            TlsPskKeyExchangeMode::PSK_KE,
            TlsPskKeyExchangeMode::PSK_DHE_KE,
        ])
    }

    /// Borrow the ordered PSK key exchange mode values.
    pub fn modes(&self) -> &[TlsPskKeyExchangeMode] {
        &self.modes
    }

    /// Borrow the ordered PSK key exchange mode values.
    pub fn as_slice(&self) -> &[TlsPskKeyExchangeMode] {
        self.modes()
    }

    /// Return the ordered raw mode values.
    pub fn raw_values(&self) -> Vec<u8> {
        self.modes.iter().map(|mode| mode.raw()).collect()
    }

    /// Return mode labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.modes.iter().map(|mode| mode.label()).collect()
    }

    /// Consume the extension body and return the ordered mode values.
    pub fn into_vec(self) -> Vec<TlsPskKeyExchangeMode> {
        self.modes
    }

    /// Append one PSK key exchange mode to the ordered list.
    pub fn push(&mut self, mode: TlsPskKeyExchangeMode) {
        self.modes.push(mode);
    }

    /// Number of PSK key exchange modes.
    pub fn len(&self) -> usize {
        self.modes.len()
    }

    /// Return true when the body carries no PSK key exchange modes.
    pub fn is_empty(&self) -> bool {
        self.modes.is_empty()
    }

    /// Number of bytes occupied by the mode vector body, excluding the length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        let byte_len = self
            .modes
            .len()
            .checked_mul(TLS_PSK_KEY_EXCHANGE_MODE_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.psk_key_exchange_modes.length",
                    "length overflow",
                )
            })?;
        validate_psk_key_exchange_modes_len(byte_len)?;
        Ok(byte_len)
    }

    /// Number of bytes occupied by the complete encoded PskKeyExchangeModes body.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.psk_key_exchange_modes.length",
                    "length overflow",
                )
            })
    }

    /// Append the psk_key_exchange_modes extension body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len()?;
        let byte_len = u8::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.psk_key_exchange_modes.length",
                "length must fit in one byte",
            )
        })?;
        out.push(byte_len);
        for mode in &self.modes {
            mode.encode(out);
        }
        Ok(())
    }

    /// Return this psk_key_exchange_modes extension body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this psk_key_exchange_modes body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::PSK_KEY_EXCHANGE_MODES,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a psk_key_exchange_modes extension body.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (modes, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.psk_key_exchange_modes.length",
                "length must match extension body",
            ));
        }
        Ok(modes)
    }

    /// Decode a psk_key_exchange_modes body from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.psk_key_exchange_modes.length",
                TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = bytes[0] as usize;
        validate_psk_key_exchange_modes_len(byte_len)?;
        let required = TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.psk_key_exchange_modes.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.psk_key_exchange_modes",
                required,
                bytes.len(),
            ));
        }

        let modes = bytes[TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN..required]
            .iter()
            .copied()
            .map(TlsPskKeyExchangeMode::from_u8)
            .collect::<Vec<_>>();
        Ok((Self::new(modes), &bytes[required..]))
    }

    /// Decode a raw psk_key_exchange_modes extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::PSK_KEY_EXCHANGE_MODES {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be psk_key_exchange_modes",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving mode order.
    pub fn summary(&self) -> String {
        format!(
            "psk_key_exchange_modes count={} bytes={} values={}",
            self.len(),
            self.len() * TLS_PSK_KEY_EXCHANGE_MODE_LEN,
            self.labels().join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("psk_key_exchange_modes_count", self.len().to_string()),
            (
                "psk_key_exchange_modes_bytes",
                (self.len() * TLS_PSK_KEY_EXCHANGE_MODE_LEN).to_string(),
            ),
            ("psk_key_exchange_modes", self.labels().join(",")),
            (
                "psk_key_exchange_modes_raw",
                self.modes
                    .iter()
                    .map(|mode| format!("0x{:02x}", mode.raw()))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
        ]
    }
}

impl From<Vec<TlsPskKeyExchangeMode>> for TlsPskKeyExchangeModes {
    fn from(modes: Vec<TlsPskKeyExchangeMode>) -> Self {
        Self::new(modes)
    }
}

impl<const N: usize> From<[TlsPskKeyExchangeMode; N]> for TlsPskKeyExchangeModes {
    fn from(modes: [TlsPskKeyExchangeMode; N]) -> Self {
        Self::new(Vec::from(modes))
    }
}

impl TryFrom<&TlsRawExtension> for TlsPskKeyExchangeModes {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsPskKeyExchangeModes> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsPskKeyExchangeModes) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_psk_key_exchange_modes_len(len: usize) -> Result<()> {
    if len < TLS_PSK_KEY_EXCHANGE_MODE_LEN {
        return Err(CrafterError::invalid_field_value(
            "tls.psk_key_exchange_modes.length",
            "length must be at least one byte",
        ));
    }
    if len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.psk_key_exchange_modes.length",
            "length must fit in one byte",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsPskIdentityContext {
    identity_length: &'static str,
    identity: &'static str,
    obfuscated_ticket_age: &'static str,
}

impl TlsPskIdentityContext {
    const fn generic() -> Self {
        Self {
            identity_length: "tls.pre_shared_key.identity.bytes.length",
            identity: "tls.pre_shared_key.identity.bytes",
            obfuscated_ticket_age: "tls.pre_shared_key.identity.obfuscated_ticket_age",
        }
    }

    const fn client_hello() -> Self {
        Self {
            identity_length: "tls.pre_shared_key.client.identity.bytes.length",
            identity: "tls.pre_shared_key.client.identity.bytes",
            obfuscated_ticket_age: "tls.pre_shared_key.client.identity.obfuscated_ticket_age",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsPskIdentitiesContext {
    list_length: &'static str,
    list: &'static str,
    identity: TlsPskIdentityContext,
}

impl TlsPskIdentitiesContext {
    const fn generic() -> Self {
        Self {
            list_length: "tls.pre_shared_key.identities.length",
            list: "tls.pre_shared_key.identities",
            identity: TlsPskIdentityContext::generic(),
        }
    }

    const fn client_hello() -> Self {
        Self {
            list_length: "tls.pre_shared_key.client.identities.length",
            list: "tls.pre_shared_key.client.identities",
            identity: TlsPskIdentityContext::client_hello(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsPskBinderContext {
    binder_length: &'static str,
    binder: &'static str,
}

impl TlsPskBinderContext {
    const fn generic() -> Self {
        Self {
            binder_length: "tls.pre_shared_key.binder.length",
            binder: "tls.pre_shared_key.binder",
        }
    }

    const fn client_hello() -> Self {
        Self {
            binder_length: "tls.pre_shared_key.client.binder.length",
            binder: "tls.pre_shared_key.client.binder",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsPskBindersContext {
    list_length: &'static str,
    list: &'static str,
    binder: TlsPskBinderContext,
}

impl TlsPskBindersContext {
    const fn generic() -> Self {
        Self {
            list_length: "tls.pre_shared_key.binders.length",
            list: "tls.pre_shared_key.binders",
            binder: TlsPskBinderContext::generic(),
        }
    }

    const fn client_hello() -> Self {
        Self {
            list_length: "tls.pre_shared_key.client.binders.length",
            list: "tls.pre_shared_key.client.binders",
            binder: TlsPskBinderContext::client_hello(),
        }
    }
}

/// Context that selects the TLS 1.3 `pre_shared_key` extension body shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsPreSharedKeyContext {
    /// ClientHello carries identities and binders vectors.
    ClientHello,
    /// ServerHello carries a selected identity index.
    ServerHello,
}

impl TlsPreSharedKeyContext {
    /// ClientHello context constructor.
    pub const fn client_hello() -> Self {
        Self::ClientHello
    }

    /// ServerHello context constructor.
    pub const fn server_hello() -> Self {
        Self::ServerHello
    }

    const fn is_client(self) -> bool {
        matches!(self, Self::ClientHello)
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ClientHello => "client",
            Self::ServerHello => "server",
        }
    }

    const fn length_field(self) -> &'static str {
        match self {
            Self::ClientHello => "tls.pre_shared_key.client.length",
            Self::ServerHello => "tls.pre_shared_key.server.length",
        }
    }

    const fn selected_identity_field(self) -> &'static str {
        match self {
            Self::ClientHello => "tls.pre_shared_key.client.selected_identity",
            Self::ServerHello => "tls.pre_shared_key.server.selected_identity",
        }
    }

    const fn identities_context(self) -> TlsPskIdentitiesContext {
        match self {
            Self::ClientHello => TlsPskIdentitiesContext::client_hello(),
            Self::ServerHello => TlsPskIdentitiesContext::generic(),
        }
    }

    const fn binders_context(self) -> TlsPskBindersContext {
        match self {
            Self::ClientHello => TlsPskBindersContext::client_hello(),
            Self::ServerHello => TlsPskBindersContext::generic(),
        }
    }
}

impl Default for TlsPreSharedKeyContext {
    fn default() -> Self {
        Self::ClientHello
    }
}

/// One TLS 1.3 PskIdentity with opaque identity bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsPskIdentity {
    identity: Vec<u8>,
    obfuscated_ticket_age: u32,
}

impl TlsPskIdentity {
    /// Create a PskIdentity from opaque identity bytes and obfuscated_ticket_age.
    pub fn new(identity: impl Into<Vec<u8>>, obfuscated_ticket_age: u32) -> Self {
        Self {
            identity: identity.into(),
            obfuscated_ticket_age,
        }
    }

    /// Borrow the preserved opaque identity bytes.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// Return the preserved obfuscated_ticket_age value.
    pub const fn obfuscated_ticket_age(&self) -> u32 {
        self.obfuscated_ticket_age
    }

    /// Consume the identity and return the opaque identity bytes.
    pub fn into_identity(self) -> Vec<u8> {
        self.identity
    }

    /// Number of bytes occupied by the complete encoded PskIdentity.
    pub fn encoded_len(&self) -> Result<usize> {
        self.encoded_len_with_context(TlsPskIdentityContext::generic())
    }

    fn encoded_len_with_context(&self, context: TlsPskIdentityContext) -> Result<usize> {
        validate_psk_identity_len(context.identity_length, self.identity.len())?;
        TLS_PSK_IDENTITY_HEADER_LEN
            .checked_add(self.identity.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.identity_length, "length overflow")
            })
    }

    /// Append this PskIdentity to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_context(TlsPskIdentityContext::generic(), out)
    }

    fn encode_with_context(&self, context: TlsPskIdentityContext, out: &mut Vec<u8>) -> Result<()> {
        validate_psk_identity_len(context.identity_length, self.identity.len())?;
        let identity_len = u16::try_from(self.identity.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                context.identity_length,
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&identity_len.to_be_bytes());
        out.extend_from_slice(&self.identity);
        out.extend_from_slice(&self.obfuscated_ticket_age.to_be_bytes());
        Ok(())
    }

    /// Return this PskIdentity encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one PskIdentity from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (identity, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(identity)
    }

    /// Decode one PskIdentity from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        Self::decode_prefix_with_context(TlsPskIdentityContext::generic(), bytes)
    }

    fn decode_prefix_with_context(
        context: TlsPskIdentityContext,
        bytes: &[u8],
    ) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_PSK_IDENTITY_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                context.identity_length,
                TLS_PSK_IDENTITY_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let identity_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_psk_identity_len(context.identity_length, identity_len)?;
        let identity_end = TLS_PSK_IDENTITY_LENGTH_LEN
            .checked_add(identity_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.identity_length, "length overflow")
            })?;
        if bytes.len() < identity_end {
            return Err(CrafterError::buffer_too_short(
                context.identity,
                identity_end,
                bytes.len(),
            ));
        }

        let required = identity_end
            .checked_add(TLS_PSK_IDENTITY_OBFUSCATED_TICKET_AGE_LEN)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.identity_length, "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                context.obfuscated_ticket_age,
                required,
                bytes.len(),
            ));
        }

        let obfuscated_ticket_age = u32::from_be_bytes([
            bytes[identity_end],
            bytes[identity_end + 1],
            bytes[identity_end + 2],
            bytes[identity_end + 3],
        ]);
        Ok((
            Self::new(
                bytes[TLS_PSK_IDENTITY_LENGTH_LEN..identity_end].to_vec(),
                obfuscated_ticket_age,
            ),
            &bytes[required..],
        ))
    }

    /// Stable one-line summary preserving identity size and obfuscated_ticket_age.
    pub fn summary(&self) -> String {
        format!(
            "psk_identity identity_bytes={} obfuscated_ticket_age={}",
            self.identity.len(),
            self.obfuscated_ticket_age
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("psk_identity_bytes", self.identity.len().to_string()),
            ("psk_identity", hex_bytes(&self.identity)),
            (
                "psk_obfuscated_ticket_age",
                self.obfuscated_ticket_age.to_string(),
            ),
        ]
    }
}

impl<I> From<(I, u32)> for TlsPskIdentity
where
    I: Into<Vec<u8>>,
{
    fn from(value: (I, u32)) -> Self {
        Self::new(value.0, value.1)
    }
}

/// TLS 1.3 PskIdentity vector with opaque identity bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsPskIdentities {
    identities: Vec<TlsPskIdentity>,
}

impl TlsPskIdentities {
    /// Create an ordered PSK identities vector.
    pub fn new(identities: impl Into<Vec<TlsPskIdentity>>) -> Self {
        Self {
            identities: identities.into(),
        }
    }

    /// Create an ordered PSK identities vector.
    pub fn from_identities(identities: impl Into<Vec<TlsPskIdentity>>) -> Self {
        Self::new(identities)
    }

    /// Borrow the ordered PSK identities.
    pub fn identities(&self) -> &[TlsPskIdentity] {
        &self.identities
    }

    /// Consume the vector and return the ordered PSK identities.
    pub fn into_vec(self) -> Vec<TlsPskIdentity> {
        self.identities
    }

    /// Append one PSK identity.
    pub fn push(&mut self, identity: TlsPskIdentity) {
        self.identities.push(identity);
    }

    /// Number of PSK identities.
    pub fn len(&self) -> usize {
        self.identities.len()
    }

    /// Return true when no identities are present.
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    /// Return identity byte lengths in wire order.
    pub fn identity_lengths(&self) -> Vec<usize> {
        self.identities
            .iter()
            .map(|identity| identity.identity().len())
            .collect()
    }

    /// Return obfuscated_ticket_age values in wire order.
    pub fn obfuscated_ticket_ages(&self) -> Vec<u32> {
        self.identities
            .iter()
            .map(TlsPskIdentity::obfuscated_ticket_age)
            .collect()
    }

    /// Number of bytes occupied by PskIdentity entries, excluding the vector length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        self.byte_len_with_context(TlsPskIdentitiesContext::generic())
    }

    fn byte_len_with_context(&self, context: TlsPskIdentitiesContext) -> Result<usize> {
        let mut len = 0usize;
        for identity in &self.identities {
            len = len
                .checked_add(identity.encoded_len_with_context(context.identity)?)
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(context.list_length, "length overflow")
                })?;
        }
        validate_psk_identities_list_len(context.list_length, len)?;
        Ok(len)
    }

    /// Number of bytes occupied by the complete encoded PSK identities vector.
    pub fn encoded_len(&self) -> Result<usize> {
        self.encoded_len_with_context(TlsPskIdentitiesContext::generic())
    }

    fn encoded_len_with_context(&self, context: TlsPskIdentitiesContext) -> Result<usize> {
        TLS_PSK_IDENTITIES_LENGTH_LEN
            .checked_add(self.byte_len_with_context(context)?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.list_length, "length overflow")
            })
    }

    /// Append the uint16 length-prefixed PSK identities vector.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_context(TlsPskIdentitiesContext::generic(), out)
    }

    fn encode_with_context(
        &self,
        context: TlsPskIdentitiesContext,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let byte_len = self.byte_len_with_context(context)?;
        let byte_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(context.list_length, "length must fit in two bytes")
        })?;
        out.extend_from_slice(&byte_len.to_be_bytes());
        for identity in &self.identities {
            identity.encode_with_context(context.identity, out)?;
        }
        Ok(())
    }

    /// Return this PSK identities vector encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a PSK identities vector.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (identities, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.pre_shared_key.identities.length",
                "length must match vector body",
            ));
        }
        Ok(identities)
    }

    /// Decode a PSK identities vector from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        Self::decode_prefix_with_context(TlsPskIdentitiesContext::generic(), bytes)
    }

    fn decode_prefix_with_context(
        context: TlsPskIdentitiesContext,
        bytes: &[u8],
    ) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_PSK_IDENTITIES_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                context.list_length,
                TLS_PSK_IDENTITIES_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_psk_identities_list_len(context.list_length, byte_len)?;
        let required = TLS_PSK_IDENTITIES_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.list_length, "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                context.list,
                required,
                bytes.len(),
            ));
        }

        let mut identities = Vec::new();
        let mut cursor = TLS_PSK_IDENTITIES_LENGTH_LEN;
        let body_end = required;
        while cursor < body_end {
            let (identity, tail) = TlsPskIdentity::decode_prefix_with_context(
                context.identity,
                &bytes[cursor..body_end],
            )?;
            cursor = body_end - tail.len();
            identities.push(identity);
        }

        Ok((Self::new(identities), &bytes[required..]))
    }

    /// Stable one-line summary preserving identity order and sizes.
    pub fn summary(&self) -> String {
        format!(
            "psk_identities count={} bytes={} identities={}",
            self.len(),
            self.byte_len().unwrap_or(0),
            format_psk_identity_entries(&self.identities)
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("psk_identities_count", self.len().to_string()),
            (
                "psk_identities_bytes",
                self.byte_len().unwrap_or(0).to_string(),
            ),
            (
                "psk_identity_bytes",
                self.identity_lengths()
                    .iter()
                    .map(|len| len.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "psk_obfuscated_ticket_ages",
                self.obfuscated_ticket_ages()
                    .iter()
                    .map(|age| age.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "psk_identities",
                self.identities
                    .iter()
                    .map(|identity| hex_bytes(identity.identity()))
                    .collect::<Vec<_>>()
                    .join("|"),
            ),
        ]
    }
}

impl From<Vec<TlsPskIdentity>> for TlsPskIdentities {
    fn from(identities: Vec<TlsPskIdentity>) -> Self {
        Self::new(identities)
    }
}

impl<const N: usize> From<[TlsPskIdentity; N]> for TlsPskIdentities {
    fn from(identities: [TlsPskIdentity; N]) -> Self {
        Self::new(Vec::from(identities))
    }
}

/// One opaque TLS 1.3 PskBinderEntry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsPskBinderEntry {
    bytes: Vec<u8>,
}

impl TlsPskBinderEntry {
    /// Create a PskBinderEntry from caller-supplied opaque binder bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Borrow the preserved opaque binder bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the binder and return its opaque bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of bytes occupied by the complete encoded PskBinderEntry.
    pub fn encoded_len(&self) -> Result<usize> {
        self.encoded_len_with_context(TlsPskBinderContext::generic())
    }

    fn encoded_len_with_context(&self, context: TlsPskBinderContext) -> Result<usize> {
        validate_psk_binder_len(context.binder_length, self.bytes.len())?;
        TLS_PSK_BINDER_LENGTH_LEN
            .checked_add(self.bytes.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.binder_length, "length overflow")
            })
    }

    /// Append this PskBinderEntry to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_context(TlsPskBinderContext::generic(), out)
    }

    fn encode_with_context(&self, context: TlsPskBinderContext, out: &mut Vec<u8>) -> Result<()> {
        validate_psk_binder_len(context.binder_length, self.bytes.len())?;
        let len = u8::try_from(self.bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value(context.binder_length, "length must fit in one byte")
        })?;
        out.push(len);
        out.extend_from_slice(&self.bytes);
        Ok(())
    }

    /// Return this PskBinderEntry encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one PskBinderEntry from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (binder, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(binder)
    }

    /// Decode one PskBinderEntry from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        Self::decode_prefix_with_context(TlsPskBinderContext::generic(), bytes)
    }

    fn decode_prefix_with_context(
        context: TlsPskBinderContext,
        bytes: &[u8],
    ) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_PSK_BINDER_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                context.binder_length,
                TLS_PSK_BINDER_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let len = bytes[0] as usize;
        validate_psk_binder_len(context.binder_length, len)?;
        let required = TLS_PSK_BINDER_LENGTH_LEN.checked_add(len).ok_or_else(|| {
            CrafterError::invalid_field_value(context.binder_length, "length overflow")
        })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                context.binder,
                required,
                bytes.len(),
            ));
        }

        Ok((
            Self::new(bytes[TLS_PSK_BINDER_LENGTH_LEN..required].to_vec()),
            &bytes[required..],
        ))
    }

    /// Stable one-line summary preserving binder size.
    pub fn summary(&self) -> String {
        format!("psk_binder bytes={}", self.bytes.len())
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("psk_binder_bytes", self.bytes.len().to_string()),
            ("psk_binder", hex_bytes(&self.bytes)),
        ]
    }
}

impl From<Vec<u8>> for TlsPskBinderEntry {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for TlsPskBinderEntry {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> From<[u8; N]> for TlsPskBinderEntry {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

/// TLS 1.3 PskBinderEntry vector with opaque binder bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsPskBinders {
    binders: Vec<TlsPskBinderEntry>,
}

impl TlsPskBinders {
    /// Create an ordered PSK binders vector.
    pub fn new(binders: impl Into<Vec<TlsPskBinderEntry>>) -> Self {
        Self {
            binders: binders.into(),
        }
    }

    /// Create an ordered PSK binders vector.
    pub fn from_binders(binders: impl Into<Vec<TlsPskBinderEntry>>) -> Self {
        Self::new(binders)
    }

    /// Borrow the ordered PSK binders.
    pub fn binders(&self) -> &[TlsPskBinderEntry] {
        &self.binders
    }

    /// Consume the vector and return the ordered PSK binders.
    pub fn into_vec(self) -> Vec<TlsPskBinderEntry> {
        self.binders
    }

    /// Append one PSK binder.
    pub fn push(&mut self, binder: TlsPskBinderEntry) {
        self.binders.push(binder);
    }

    /// Number of PSK binders.
    pub fn len(&self) -> usize {
        self.binders.len()
    }

    /// Return true when no binders are present.
    pub fn is_empty(&self) -> bool {
        self.binders.is_empty()
    }

    /// Return binder byte lengths in wire order.
    pub fn binder_lengths(&self) -> Vec<usize> {
        self.binders
            .iter()
            .map(|binder| binder.bytes().len())
            .collect()
    }

    /// Number of bytes occupied by PskBinderEntry entries, excluding the vector length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        self.byte_len_with_context(TlsPskBindersContext::generic())
    }

    fn byte_len_with_context(&self, context: TlsPskBindersContext) -> Result<usize> {
        let mut len = 0usize;
        for binder in &self.binders {
            len = len
                .checked_add(binder.encoded_len_with_context(context.binder)?)
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(context.list_length, "length overflow")
                })?;
        }
        validate_psk_binders_list_len(context.list_length, len)?;
        Ok(len)
    }

    /// Number of bytes occupied by the complete encoded PSK binders vector.
    pub fn encoded_len(&self) -> Result<usize> {
        self.encoded_len_with_context(TlsPskBindersContext::generic())
    }

    fn encoded_len_with_context(&self, context: TlsPskBindersContext) -> Result<usize> {
        TLS_PSK_BINDERS_LENGTH_LEN
            .checked_add(self.byte_len_with_context(context)?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.list_length, "length overflow")
            })
    }

    /// Append the uint16 length-prefixed PSK binders vector.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_context(TlsPskBindersContext::generic(), out)
    }

    fn encode_with_context(&self, context: TlsPskBindersContext, out: &mut Vec<u8>) -> Result<()> {
        let byte_len = self.byte_len_with_context(context)?;
        let byte_len = u16::try_from(byte_len).map_err(|_| {
            CrafterError::invalid_field_value(context.list_length, "length must fit in two bytes")
        })?;
        out.extend_from_slice(&byte_len.to_be_bytes());
        for binder in &self.binders {
            binder.encode_with_context(context.binder, out)?;
        }
        Ok(())
    }

    /// Return this PSK binders vector encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode a PSK binders vector.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (binders, tail) = Self::decode_prefix(bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.pre_shared_key.binders.length",
                "length must match vector body",
            ));
        }
        Ok(binders)
    }

    /// Decode a PSK binders vector from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        Self::decode_prefix_with_context(TlsPskBindersContext::generic(), bytes)
    }

    fn decode_prefix_with_context(
        context: TlsPskBindersContext,
        bytes: &[u8],
    ) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_PSK_BINDERS_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                context.list_length,
                TLS_PSK_BINDERS_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_psk_binders_list_len(context.list_length, byte_len)?;
        let required = TLS_PSK_BINDERS_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.list_length, "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                context.list,
                required,
                bytes.len(),
            ));
        }

        let mut binders = Vec::new();
        let mut cursor = TLS_PSK_BINDERS_LENGTH_LEN;
        let body_end = required;
        while cursor < body_end {
            let (binder, tail) = TlsPskBinderEntry::decode_prefix_with_context(
                context.binder,
                &bytes[cursor..body_end],
            )?;
            cursor = body_end - tail.len();
            binders.push(binder);
        }

        Ok((Self::new(binders), &bytes[required..]))
    }

    /// Stable one-line summary preserving binder order and sizes.
    pub fn summary(&self) -> String {
        format!(
            "psk_binders count={} bytes={} binders={}",
            self.len(),
            self.byte_len().unwrap_or(0),
            format_psk_binder_entries(&self.binders)
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("psk_binders_count", self.len().to_string()),
            (
                "psk_binders_bytes",
                self.byte_len().unwrap_or(0).to_string(),
            ),
            (
                "psk_binder_bytes",
                self.binder_lengths()
                    .iter()
                    .map(|len| len.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "psk_binders",
                self.binders
                    .iter()
                    .map(|binder| hex_bytes(binder.bytes()))
                    .collect::<Vec<_>>()
                    .join("|"),
            ),
        ]
    }
}

impl From<Vec<TlsPskBinderEntry>> for TlsPskBinders {
    fn from(binders: Vec<TlsPskBinderEntry>) -> Self {
        Self::new(binders)
    }
}

impl<const N: usize> From<[TlsPskBinderEntry; N]> for TlsPskBinders {
    fn from(binders: [TlsPskBinderEntry; N]) -> Self {
        Self::new(Vec::from(binders))
    }
}

/// TLS 1.3 `pre_shared_key` extension body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsPreSharedKey {
    /// ClientHello OfferedPsks form.
    Client {
        identities: TlsPskIdentities,
        binders: TlsPskBinders,
    },
    /// ServerHello selected identity index.
    Server { selected_identity: u16 },
}

impl TlsPreSharedKey {
    /// Create a ClientHello pre_shared_key body.
    pub fn client(
        identities: impl Into<TlsPskIdentities>,
        binders: impl Into<TlsPskBinders>,
    ) -> Self {
        Self::Client {
            identities: identities.into(),
            binders: binders.into(),
        }
    }

    /// Create a ServerHello pre_shared_key body.
    pub const fn server(selected_identity: u16) -> Self {
        Self::Server { selected_identity }
    }

    /// Return true when this is the ClientHello OfferedPsks form.
    pub const fn is_client(&self) -> bool {
        matches!(self, Self::Client { .. })
    }

    /// Return true when this is the ServerHello selected_identity form.
    pub const fn is_server(&self) -> bool {
        matches!(self, Self::Server { .. })
    }

    /// Borrow ClientHello PSK identities, if this is the client form.
    pub const fn identities(&self) -> Option<&TlsPskIdentities> {
        match self {
            Self::Client { identities, .. } => Some(identities),
            Self::Server { .. } => None,
        }
    }

    /// Borrow ClientHello PSK binders, if this is the client form.
    pub const fn binders(&self) -> Option<&TlsPskBinders> {
        match self {
            Self::Client { binders, .. } => Some(binders),
            Self::Server { .. } => None,
        }
    }

    /// Return ServerHello selected_identity, if this is the server form.
    pub const fn selected_identity(&self) -> Option<u16> {
        match self {
            Self::Client { .. } => None,
            Self::Server { selected_identity } => Some(*selected_identity),
        }
    }

    /// Return true when the ClientHello binder count matches the identity count.
    pub fn binder_count_matches_identities(&self) -> Option<bool> {
        match self {
            Self::Client {
                identities,
                binders,
            } => Some(identities.len() == binders.len()),
            Self::Server { .. } => None,
        }
    }

    /// Validate the RFC 8446 one-binder-per-identity relationship on demand.
    pub fn validate_binder_count_matches_identities(&self) -> Result<()> {
        match self {
            Self::Client {
                identities,
                binders,
            } if identities.len() != binders.len() => Err(CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.binders.count",
                "binder count must match identity count",
            )),
            Self::Client { .. } | Self::Server { .. } => Ok(()),
        }
    }

    /// Number of bytes occupied by this extension body.
    pub fn encoded_len(&self) -> Result<usize> {
        match self {
            Self::Client {
                identities,
                binders,
            } => identities
                .encoded_len_with_context(TlsPreSharedKeyContext::ClientHello.identities_context())?
                .checked_add(binders.encoded_len_with_context(
                    TlsPreSharedKeyContext::ClientHello.binders_context(),
                )?)
                .ok_or_else(|| {
                    CrafterError::invalid_field_value(
                        TlsPreSharedKeyContext::ClientHello.length_field(),
                        "length overflow",
                    )
                }),
            Self::Server { .. } => Ok(TLS_PRE_SHARED_KEY_SELECTED_IDENTITY_LEN),
        }
    }

    /// Append this pre_shared_key body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Client {
                identities,
                binders,
            } => {
                identities.encode_with_context(
                    TlsPreSharedKeyContext::ClientHello.identities_context(),
                    out,
                )?;
                binders.encode_with_context(
                    TlsPreSharedKeyContext::ClientHello.binders_context(),
                    out,
                )?;
            }
            Self::Server { selected_identity } => {
                out.extend_from_slice(&selected_identity.to_be_bytes());
            }
        }
        Ok(())
    }

    /// Return this pre_shared_key body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this pre_shared_key body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::PRE_SHARED_KEY,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a context-selected pre_shared_key body.
    pub fn decode_with_context(
        context: TlsPreSharedKeyContext,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let bytes = bytes.as_ref();
        if context.is_client() {
            Self::decode_client(bytes)
        } else {
            Self::decode_server(bytes)
        }
    }

    /// Decode a ClientHello pre_shared_key body.
    pub fn decode_client(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let context = TlsPreSharedKeyContext::ClientHello;
        let (identities, tail) =
            TlsPskIdentities::decode_prefix_with_context(context.identities_context(), bytes)?;
        let (binders, tail) =
            TlsPskBinders::decode_prefix_with_context(context.binders_context(), tail)?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                context.length_field(),
                "length must match extension body",
            ));
        }
        Ok(Self::client(identities, binders))
    }

    /// Decode a ServerHello pre_shared_key body.
    pub fn decode_server(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let context = TlsPreSharedKeyContext::ServerHello;
        if bytes.len() < TLS_PRE_SHARED_KEY_SELECTED_IDENTITY_LEN {
            return Err(CrafterError::buffer_too_short(
                context.selected_identity_field(),
                TLS_PRE_SHARED_KEY_SELECTED_IDENTITY_LEN,
                bytes.len(),
            ));
        }
        if bytes.len() != TLS_PRE_SHARED_KEY_SELECTED_IDENTITY_LEN {
            return Err(CrafterError::invalid_field_value(
                context.length_field(),
                "length must be exactly two bytes",
            ));
        }
        Ok(Self::server(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    /// Decode a raw pre_shared_key extension body using a context.
    pub fn from_raw_extension_with_context(
        context: TlsPreSharedKeyContext,
        extension: &TlsRawExtension,
    ) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::PRE_SHARED_KEY {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be pre_shared_key",
            ));
        }
        Self::decode_with_context(context, extension.body())
    }

    /// Decode a raw ClientHello pre_shared_key extension body.
    pub fn from_client_hello_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(TlsPreSharedKeyContext::ClientHello, extension)
    }

    /// Decode a raw ServerHello pre_shared_key extension body.
    pub fn from_server_hello_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(TlsPreSharedKeyContext::ServerHello, extension)
    }

    /// Stable one-line summary preserving body shape and opaque byte sizes.
    pub fn summary(&self) -> String {
        match self {
            Self::Client {
                identities,
                binders,
            } => format!(
                "pre_shared_key context=client identities={} identities_bytes={} binders={} binders_bytes={}",
                identities.len(),
                identities.byte_len().unwrap_or(0),
                binders.len(),
                binders.byte_len().unwrap_or(0)
            ),
            Self::Server { selected_identity } => format!(
                "pre_shared_key context=server selected_identity={}",
                selected_identity
            ),
        }
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Client {
                identities,
                binders,
            } => vec![
                (
                    "pre_shared_key_context",
                    TlsPreSharedKeyContext::ClientHello.label().to_string(),
                ),
                ("psk_identities_count", identities.len().to_string()),
                (
                    "psk_identities_bytes",
                    identities.byte_len().unwrap_or(0).to_string(),
                ),
                (
                    "psk_identity_bytes",
                    identities
                        .identity_lengths()
                        .iter()
                        .map(|len| len.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "psk_obfuscated_ticket_ages",
                    identities
                        .obfuscated_ticket_ages()
                        .iter()
                        .map(|age| age.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "psk_identities",
                    identities
                        .identities()
                        .iter()
                        .map(|identity| hex_bytes(identity.identity()))
                        .collect::<Vec<_>>()
                        .join("|"),
                ),
                ("psk_binders_count", binders.len().to_string()),
                (
                    "psk_binders_bytes",
                    binders.byte_len().unwrap_or(0).to_string(),
                ),
                (
                    "psk_binder_bytes",
                    binders
                        .binder_lengths()
                        .iter()
                        .map(|len| len.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                (
                    "psk_binders",
                    binders
                        .binders()
                        .iter()
                        .map(|binder| hex_bytes(binder.bytes()))
                        .collect::<Vec<_>>()
                        .join("|"),
                ),
            ],
            Self::Server { selected_identity } => vec![
                (
                    "pre_shared_key_context",
                    TlsPreSharedKeyContext::ServerHello.label().to_string(),
                ),
                (
                    "pre_shared_key_selected_identity",
                    selected_identity.to_string(),
                ),
                (
                    "pre_shared_key_selected_identity_raw",
                    format!("0x{:04x}", selected_identity),
                ),
            ],
        }
    }
}

impl TryFrom<TlsPreSharedKey> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsPreSharedKey) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_psk_identity_len(field: &'static str, len: usize) -> Result<()> {
    if len == 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must be at least one byte",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_psk_identities_list_len(field: &'static str, len: usize) -> Result<()> {
    if len < TLS_PSK_IDENTITY_HEADER_LEN + 1 {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must be at least seven bytes",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_psk_binder_len(field: &'static str, len: usize) -> Result<()> {
    if len < 32 {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must be at least 32 bytes",
        ));
    }
    if len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in one byte",
        ));
    }
    Ok(())
}

fn validate_psk_binders_list_len(field: &'static str, len: usize) -> Result<()> {
    if len < TLS_PSK_BINDER_LENGTH_LEN + 32 {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must be at least 33 bytes",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn format_psk_identity_entries(identities: &[TlsPskIdentity]) -> String {
    identities
        .iter()
        .map(|identity| {
            format!(
                "{} bytes age={}",
                identity.identity().len(),
                identity.obfuscated_ticket_age()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_psk_binder_entries(binders: &[TlsPskBinderEntry]) -> String {
    binders
        .iter()
        .map(|binder| format!("{} bytes", binder.bytes().len()))
        .collect::<Vec<_>>()
        .join(",")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TlsKeyShareEntryContext {
    group: &'static str,
    key_exchange_length: &'static str,
    key_exchange: &'static str,
}

impl TlsKeyShareEntryContext {
    const fn generic() -> Self {
        Self {
            group: "tls.key_share.entry.group",
            key_exchange_length: "tls.key_share.entry.key_exchange.length",
            key_exchange: "tls.key_share.entry.key_exchange",
        }
    }

    const fn client_hello() -> Self {
        Self {
            group: "tls.key_share.client.group",
            key_exchange_length: "tls.key_share.client.key_exchange.length",
            key_exchange: "tls.key_share.client.key_exchange",
        }
    }

    const fn server_hello() -> Self {
        Self {
            group: "tls.key_share.server.group",
            key_exchange_length: "tls.key_share.server.key_exchange.length",
            key_exchange: "tls.key_share.server.key_exchange",
        }
    }
}

/// Context that selects the TLS 1.3 `key_share` extension body shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsKeyShareContext {
    /// ClientHello carries a uint16 length-prefixed KeyShareEntry list.
    ClientHello,
    /// ServerHello carries one selected KeyShareEntry.
    ServerHello,
    /// HelloRetryRequest carries one selected NamedGroup and no key_exchange bytes.
    HelloRetryRequest,
}

impl TlsKeyShareContext {
    /// ClientHello context constructor.
    pub const fn client_hello() -> Self {
        Self::ClientHello
    }

    /// ServerHello context constructor.
    pub const fn server_hello() -> Self {
        Self::ServerHello
    }

    /// HelloRetryRequest context constructor.
    pub const fn hello_retry_request() -> Self {
        Self::HelloRetryRequest
    }

    const fn is_client_list(self) -> bool {
        matches!(self, Self::ClientHello)
    }

    const fn is_server_entry(self) -> bool {
        matches!(self, Self::ServerHello)
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ClientHello => "client",
            Self::ServerHello => "server",
            Self::HelloRetryRequest => "hello_retry_request",
        }
    }

    const fn length_field(self) -> &'static str {
        match self {
            Self::ClientHello => "tls.key_share.client.length",
            Self::ServerHello => "tls.key_share.server.length",
            Self::HelloRetryRequest => "tls.key_share.hello_retry_request.length",
        }
    }

    const fn selected_group_field(self) -> &'static str {
        match self {
            Self::ClientHello => "tls.key_share.client.group",
            Self::ServerHello => "tls.key_share.server.group",
            Self::HelloRetryRequest => "tls.key_share.hello_retry_request.selected_group",
        }
    }

    const fn entry_context(self) -> TlsKeyShareEntryContext {
        match self {
            Self::ClientHello => TlsKeyShareEntryContext::client_hello(),
            Self::ServerHello => TlsKeyShareEntryContext::server_hello(),
            Self::HelloRetryRequest => TlsKeyShareEntryContext::generic(),
        }
    }
}

impl Default for TlsKeyShareContext {
    fn default() -> Self {
        Self::ClientHello
    }
}

/// One TLS 1.3 KeyShareEntry with opaque key_exchange bytes preserved.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsKeyShareEntry {
    group: TlsNamedGroup,
    key_exchange: Vec<u8>,
}

impl TlsKeyShareEntry {
    /// Create a KeyShareEntry from a NamedGroup and opaque key_exchange bytes.
    pub fn new(group: impl Into<TlsNamedGroup>, key_exchange: impl Into<Vec<u8>>) -> Self {
        Self {
            group: group.into(),
            key_exchange: key_exchange.into(),
        }
    }

    /// Create a KeyShareEntry from a raw NamedGroup codepoint.
    pub fn from_raw_group(raw_group: u16, key_exchange: impl Into<Vec<u8>>) -> Self {
        Self::new(TlsNamedGroup::from_u16(raw_group), key_exchange)
    }

    /// Create an X25519 KeyShareEntry with caller-supplied opaque key_exchange bytes.
    pub fn x25519(key_exchange: impl Into<Vec<u8>>) -> Self {
        Self::new(TlsNamedGroup::X25519, key_exchange)
    }

    /// Create a secp256r1 KeyShareEntry with caller-supplied opaque key_exchange bytes.
    pub fn secp256r1(key_exchange: impl Into<Vec<u8>>) -> Self {
        Self::new(TlsNamedGroup::SECP256R1, key_exchange)
    }

    /// Return the selected NamedGroup.
    pub const fn group(&self) -> TlsNamedGroup {
        self.group
    }

    /// Return the preserved raw NamedGroup codepoint.
    pub const fn raw_group(&self) -> u16 {
        self.group.raw()
    }

    /// Borrow the preserved opaque key_exchange bytes.
    pub fn key_exchange(&self) -> &[u8] {
        &self.key_exchange
    }

    /// Consume the entry and return the opaque key_exchange bytes.
    pub fn into_key_exchange(self) -> Vec<u8> {
        self.key_exchange
    }

    /// Number of bytes occupied by the complete encoded KeyShareEntry.
    pub fn encoded_len(&self) -> Result<usize> {
        self.encoded_len_with_context(TlsKeyShareEntryContext::generic())
    }

    fn encoded_len_with_context(&self, context: TlsKeyShareEntryContext) -> Result<usize> {
        validate_key_share_entry(context, self)?;
        TLS_KEY_SHARE_ENTRY_HEADER_LEN
            .checked_add(self.key_exchange.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.key_exchange_length, "length overflow")
            })
    }

    /// Append this KeyShareEntry to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_context(TlsKeyShareEntryContext::generic(), out)
    }

    fn encode_with_context(
        &self,
        context: TlsKeyShareEntryContext,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        validate_key_share_entry(context, self)?;
        self.group.encode(out);
        let key_exchange_len = u16::try_from(self.key_exchange.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                context.key_exchange_length,
                "length must fit in two bytes",
            )
        })?;
        out.extend_from_slice(&key_exchange_len.to_be_bytes());
        out.extend_from_slice(&self.key_exchange);
        Ok(())
    }

    /// Return this KeyShareEntry encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one KeyShareEntry from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (entry, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(entry)
    }

    /// Decode one KeyShareEntry from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        Self::decode_prefix_with_context(TlsKeyShareEntryContext::generic(), bytes)
    }

    fn decode_prefix_with_context(
        context: TlsKeyShareEntryContext,
        bytes: &[u8],
    ) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_KEY_SHARE_GROUP_LEN {
            return Err(CrafterError::buffer_too_short(
                context.group,
                TLS_KEY_SHARE_GROUP_LEN,
                bytes.len(),
            ));
        }
        if bytes.len() < TLS_KEY_SHARE_ENTRY_HEADER_LEN {
            return Err(CrafterError::buffer_too_short(
                context.key_exchange_length,
                TLS_KEY_SHARE_ENTRY_HEADER_LEN,
                bytes.len(),
            ));
        }

        let group = TlsNamedGroup::from_be_bytes([bytes[0], bytes[1]]);
        let key_exchange_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        validate_key_share_key_exchange_len(context.key_exchange_length, key_exchange_len)?;
        let required = TLS_KEY_SHARE_ENTRY_HEADER_LEN
            .checked_add(key_exchange_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.key_exchange_length, "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                context.key_exchange,
                required,
                bytes.len(),
            ));
        }

        Ok((
            Self::new(
                group,
                bytes[TLS_KEY_SHARE_ENTRY_HEADER_LEN..required].to_vec(),
            ),
            &bytes[required..],
        ))
    }

    /// Stable one-line summary preserving group and key_exchange size.
    pub fn summary(&self) -> String {
        format!(
            "key_share_entry group={}:0x{:04x} key_exchange_bytes={}",
            self.group.label(),
            self.group.raw(),
            self.key_exchange.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("key_share_group", self.group.label()),
            ("key_share_group_raw", format!("0x{:04x}", self.group.raw())),
            (
                "key_share_group_status",
                self.group.status().label().to_string(),
            ),
            (
                "key_share_key_exchange_bytes",
                self.key_exchange.len().to_string(),
            ),
            ("key_share_key_exchange", hex_bytes(&self.key_exchange)),
        ]
    }
}

impl<G, B> From<(G, B)> for TlsKeyShareEntry
where
    G: Into<TlsNamedGroup>,
    B: Into<Vec<u8>>,
{
    fn from(value: (G, B)) -> Self {
        Self::new(value.0, value.1)
    }
}

/// TLS 1.3 `key_share` extension body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TlsKeyShare {
    /// ClientHello uint16 length-prefixed KeyShareEntry list.
    Client { entries: Vec<TlsKeyShareEntry> },
    /// ServerHello selected KeyShareEntry.
    Server { selected: TlsKeyShareEntry },
    /// HelloRetryRequest selected NamedGroup with no key_exchange bytes.
    HelloRetryRequest { selected_group: TlsNamedGroup },
}

impl TlsKeyShare {
    /// Create a ClientHello key_share entry list.
    pub fn client(entries: impl Into<Vec<TlsKeyShareEntry>>) -> Self {
        Self::Client {
            entries: entries.into(),
        }
    }

    /// Create an empty ClientHello key_share list.
    pub fn client_empty() -> Self {
        Self::client(Vec::new())
    }

    /// Create a ServerHello selected key_share entry.
    pub fn server(selected: impl Into<TlsKeyShareEntry>) -> Self {
        Self::Server {
            selected: selected.into(),
        }
    }

    /// Create a HelloRetryRequest selected-group key_share body.
    pub fn hello_retry_request(selected_group: impl Into<TlsNamedGroup>) -> Self {
        Self::HelloRetryRequest {
            selected_group: selected_group.into(),
        }
    }

    /// Return true when this is the ClientHello list form.
    pub const fn is_client(&self) -> bool {
        matches!(self, Self::Client { .. })
    }

    /// Return true when this is the ServerHello selected-entry form.
    pub const fn is_server(&self) -> bool {
        matches!(self, Self::Server { .. })
    }

    /// Return true when this is the HelloRetryRequest selected-group form.
    pub const fn is_hello_retry_request(&self) -> bool {
        matches!(self, Self::HelloRetryRequest { .. })
    }

    /// Borrow ClientHello entries, if this is the client-list form.
    pub fn entries(&self) -> Option<&[TlsKeyShareEntry]> {
        match self {
            Self::Client { entries } => Some(entries),
            Self::Server { .. } | Self::HelloRetryRequest { .. } => None,
        }
    }

    /// Borrow the selected ServerHello entry, if present.
    pub const fn selected_entry(&self) -> Option<&TlsKeyShareEntry> {
        match self {
            Self::Client { .. } | Self::HelloRetryRequest { .. } => None,
            Self::Server { selected } => Some(selected),
        }
    }

    /// Return the selected ServerHello or HelloRetryRequest group, if present.
    pub const fn selected_group(&self) -> Option<TlsNamedGroup> {
        match self {
            Self::Client { .. } => None,
            Self::Server { selected } => Some(selected.group()),
            Self::HelloRetryRequest { selected_group } => Some(*selected_group),
        }
    }

    /// Return all NamedGroup values carried by this body.
    pub fn groups(&self) -> Vec<TlsNamedGroup> {
        match self {
            Self::Client { entries } => entries.iter().map(TlsKeyShareEntry::group).collect(),
            Self::Server { selected } => vec![selected.group()],
            Self::HelloRetryRequest { selected_group } => vec![*selected_group],
        }
    }

    /// Return raw NamedGroup codepoints carried by this body.
    pub fn raw_groups(&self) -> Vec<u16> {
        self.groups().iter().map(|group| group.raw()).collect()
    }

    /// Return NamedGroup labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.groups().iter().map(|group| group.label()).collect()
    }

    /// Return key_exchange byte lengths in wire order.
    pub fn key_exchange_lengths(&self) -> Vec<usize> {
        match self {
            Self::Client { entries } => entries
                .iter()
                .map(|entry| entry.key_exchange().len())
                .collect(),
            Self::Server { selected } => vec![selected.key_exchange().len()],
            Self::HelloRetryRequest { .. } => Vec::new(),
        }
    }

    /// Number of bytes occupied by this extension body.
    pub fn encoded_len(&self) -> Result<usize> {
        match self {
            Self::Client { entries } => {
                let byte_len = key_share_client_entries_byte_len(entries)?;
                TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN
                    .checked_add(byte_len)
                    .ok_or_else(|| {
                        CrafterError::invalid_field_value(
                            TlsKeyShareContext::ClientHello.length_field(),
                            "length overflow",
                        )
                    })
            }
            Self::Server { selected } => {
                selected.encoded_len_with_context(TlsKeyShareContext::ServerHello.entry_context())
            }
            Self::HelloRetryRequest { .. } => Ok(TLS_KEY_SHARE_GROUP_LEN),
        }
    }

    /// Append this key_share body to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Client { entries } => {
                let byte_len = key_share_client_entries_byte_len(entries)?;
                let byte_len = u16::try_from(byte_len).map_err(|_| {
                    CrafterError::invalid_field_value(
                        TlsKeyShareContext::ClientHello.length_field(),
                        "length must fit in two bytes",
                    )
                })?;
                out.extend_from_slice(&byte_len.to_be_bytes());
                for entry in entries {
                    entry.encode_with_context(
                        TlsKeyShareContext::ClientHello.entry_context(),
                        out,
                    )?;
                }
            }
            Self::Server { selected } => {
                selected
                    .encode_with_context(TlsKeyShareContext::ServerHello.entry_context(), out)?;
            }
            Self::HelloRetryRequest { selected_group } => {
                selected_group.encode(out);
            }
        }
        Ok(())
    }

    /// Return this key_share body encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this key_share body into a raw extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::KEY_SHARE,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a context-selected key_share body.
    pub fn decode_with_context(
        context: TlsKeyShareContext,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let bytes = bytes.as_ref();
        if context.is_client_list() {
            Self::decode_client(bytes)
        } else if context.is_server_entry() {
            Self::decode_server(bytes)
        } else {
            Self::decode_hello_retry_request(bytes)
        }
    }

    /// Decode a ClientHello key_share body.
    pub fn decode_client(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let context = TlsKeyShareContext::ClientHello;
        if bytes.len() < TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                context.length_field(),
                TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_key_share_client_list_len(byte_len)?;
        let required = TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.length_field(), "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.key_share.client",
                required,
                bytes.len(),
            ));
        }
        if bytes.len() != required {
            return Err(CrafterError::invalid_field_value(
                context.length_field(),
                "length must match extension body",
            ));
        }

        let mut entries = Vec::new();
        let mut cursor = TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN;
        let body_end = required;
        while cursor < body_end {
            let (entry, tail) = TlsKeyShareEntry::decode_prefix_with_context(
                context.entry_context(),
                &bytes[cursor..body_end],
            )?;
            cursor = body_end - tail.len();
            entries.push(entry);
        }

        Ok(Self::client(entries))
    }

    /// Decode a ServerHello key_share body.
    pub fn decode_server(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let context = TlsKeyShareContext::ServerHello;
        let (selected, tail) =
            TlsKeyShareEntry::decode_prefix_with_context(context.entry_context(), bytes.as_ref())?;
        if !tail.is_empty() {
            return Err(CrafterError::invalid_field_value(
                context.length_field(),
                "length must match extension body",
            ));
        }
        Ok(Self::server(selected))
    }

    /// Decode a HelloRetryRequest key_share body.
    pub fn decode_hello_retry_request(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let context = TlsKeyShareContext::HelloRetryRequest;
        if bytes.len() < TLS_KEY_SHARE_GROUP_LEN {
            return Err(CrafterError::buffer_too_short(
                context.selected_group_field(),
                TLS_KEY_SHARE_GROUP_LEN,
                bytes.len(),
            ));
        }
        if bytes.len() != TLS_KEY_SHARE_GROUP_LEN {
            return Err(CrafterError::invalid_field_value(
                context.length_field(),
                "length must be exactly two bytes",
            ));
        }

        Ok(Self::hello_retry_request(TlsNamedGroup::from_be_bytes([
            bytes[0], bytes[1],
        ])))
    }

    /// Decode a raw key_share extension body using a context.
    pub fn from_raw_extension_with_context(
        context: TlsKeyShareContext,
        extension: &TlsRawExtension,
    ) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::KEY_SHARE {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be key_share",
            ));
        }
        Self::decode_with_context(context, extension.body())
    }

    /// Decode a raw ClientHello key_share extension body.
    pub fn from_client_hello_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(TlsKeyShareContext::ClientHello, extension)
    }

    /// Decode a raw ServerHello key_share extension body.
    pub fn from_server_hello_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(TlsKeyShareContext::ServerHello, extension)
    }

    /// Decode a raw HelloRetryRequest key_share extension body.
    pub fn from_hello_retry_request_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension_with_context(TlsKeyShareContext::HelloRetryRequest, extension)
    }

    /// Stable one-line summary preserving body shape and group order.
    pub fn summary(&self) -> String {
        match self {
            Self::Client { entries } => format!(
                "key_share context=client count={} bytes={} entries={}",
                entries.len(),
                key_share_client_entries_byte_len(entries).unwrap_or(0),
                format_key_share_entries(entries)
            ),
            Self::Server { selected } => format!(
                "key_share context=server selected={}:0x{:04x} key_exchange_bytes={}",
                selected.group().label(),
                selected.raw_group(),
                selected.key_exchange().len()
            ),
            Self::HelloRetryRequest { selected_group } => format!(
                "key_share context=hello_retry_request selected_group={}:0x{:04x}",
                selected_group.label(),
                selected_group.raw()
            ),
        }
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::Client { entries } => vec![
                (
                    "key_share_context",
                    TlsKeyShareContext::ClientHello.label().to_string(),
                ),
                ("key_share_count", entries.len().to_string()),
                (
                    "key_share_bytes",
                    key_share_client_entries_byte_len(entries)
                        .unwrap_or(0)
                        .to_string(),
                ),
                ("key_share_groups", format_key_share_group_labels(entries)),
                ("key_share_groups_raw", format_key_share_raw_groups(entries)),
                (
                    "key_share_key_exchange_bytes",
                    format_key_share_key_exchange_lengths(entries),
                ),
                (
                    "key_share_key_exchanges",
                    format_key_share_key_exchanges(entries),
                ),
            ],
            Self::Server { selected } => vec![
                (
                    "key_share_context",
                    TlsKeyShareContext::ServerHello.label().to_string(),
                ),
                ("key_share_selected_group", selected.group().label()),
                (
                    "key_share_selected_group_raw",
                    format!("0x{:04x}", selected.raw_group()),
                ),
                (
                    "key_share_key_exchange_bytes",
                    selected.key_exchange().len().to_string(),
                ),
                ("key_share_key_exchange", hex_bytes(selected.key_exchange())),
            ],
            Self::HelloRetryRequest { selected_group } => vec![
                (
                    "key_share_context",
                    TlsKeyShareContext::HelloRetryRequest.label().to_string(),
                ),
                ("key_share_selected_group", selected_group.label()),
                (
                    "key_share_selected_group_raw",
                    format!("0x{:04x}", selected_group.raw()),
                ),
            ],
        }
    }
}

impl From<Vec<TlsKeyShareEntry>> for TlsKeyShare {
    fn from(entries: Vec<TlsKeyShareEntry>) -> Self {
        Self::client(entries)
    }
}

impl<const N: usize> From<[TlsKeyShareEntry; N]> for TlsKeyShare {
    fn from(entries: [TlsKeyShareEntry; N]) -> Self {
        Self::client(Vec::from(entries))
    }
}

impl TryFrom<TlsKeyShare> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsKeyShare) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_key_share_entry(
    context: TlsKeyShareEntryContext,
    entry: &TlsKeyShareEntry,
) -> Result<()> {
    validate_key_share_key_exchange_len(context.key_exchange_length, entry.key_exchange().len())
}

fn validate_key_share_key_exchange_len(field: &'static str, len: usize) -> Result<()> {
    if len == 0 {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must be at least one byte",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn key_share_client_entries_byte_len(entries: &[TlsKeyShareEntry]) -> Result<usize> {
    let mut len = 0usize;
    for entry in entries {
        len = len
            .checked_add(
                entry.encoded_len_with_context(TlsKeyShareContext::ClientHello.entry_context())?,
            )
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    TlsKeyShareContext::ClientHello.length_field(),
                    "length overflow",
                )
            })?;
    }
    validate_key_share_client_list_len(len)?;
    Ok(len)
}

fn validate_key_share_client_list_len(len: usize) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.key_share.client.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn format_key_share_entries(entries: &[TlsKeyShareEntry]) -> String {
    entries
        .iter()
        .map(|entry| {
            format!(
                "{}:{} bytes",
                entry.group().label(),
                entry.key_exchange().len()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn format_key_share_group_labels(entries: &[TlsKeyShareEntry]) -> String {
    entries
        .iter()
        .map(|entry| entry.group().label())
        .collect::<Vec<_>>()
        .join(",")
}

fn format_key_share_raw_groups(entries: &[TlsKeyShareEntry]) -> String {
    entries
        .iter()
        .map(|entry| format!("0x{:04x}", entry.raw_group()))
        .collect::<Vec<_>>()
        .join(",")
}

fn format_key_share_key_exchange_lengths(entries: &[TlsKeyShareEntry]) -> String {
    entries
        .iter()
        .map(|entry| entry.key_exchange().len().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn format_key_share_key_exchanges(entries: &[TlsKeyShareEntry]) -> String {
    entries
        .iter()
        .map(|entry| hex_bytes(entry.key_exchange()))
        .collect::<Vec<_>>()
        .join("|")
}

/// One opaque RFC 7301 ALPN `ProtocolName`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsAlpnProtocol {
    bytes: Vec<u8>,
}

impl TlsAlpnProtocol {
    /// Build an opaque ALPN protocol name from caller-supplied bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Build the IANA-registered HTTP/1.1 ALPN identifier (`http/1.1`).
    pub fn http_1_1() -> Self {
        Self::new(b"http/1.1")
    }

    /// Build the IANA-registered HTTP/2-over-TLS ALPN identifier (`h2`).
    pub fn h2() -> Self {
        Self::new(b"h2")
    }

    /// Borrow the preserved opaque protocol-name bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Compatibility alias for borrowing the preserved opaque protocol-name bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes()
    }

    /// Consume the protocol name and return its opaque bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of bytes occupied by the complete encoded ProtocolName entry.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN
            .checked_add(self.bytes.len())
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.alpn.protocol_name.length",
                    "length overflow",
                )
            })
    }

    /// Append this length-prefixed ProtocolName entry to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_alpn_protocol(self)?;
        let len = u8::try_from(self.bytes.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name.length",
                "length must fit in one byte",
            )
        })?;

        out.push(len);
        out.extend_from_slice(&self.bytes);
        Ok(())
    }

    /// Return the encoded ProtocolName entry.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Decode one ALPN ProtocolName entry from `bytes`.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (protocol, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(protocol)
    }

    /// Decode one ALPN ProtocolName entry from the front of `bytes`, returning any tail bytes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.alpn.protocol_name.length",
                TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let len = bytes[0] as usize;
        let required = TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN
            .checked_add(len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.alpn.protocol_name.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.alpn.protocol_name",
                required,
                bytes.len(),
            ));
        }

        let protocol = Self::new(bytes[TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN..required].to_vec());
        validate_alpn_protocol(&protocol)?;
        Ok((protocol, &bytes[required..]))
    }

    /// Stable one-line summary preserving the opaque protocol bytes.
    pub fn summary(&self) -> String {
        format!(
            "alpn protocol={} bytes={}",
            String::from_utf8_lossy(&self.bytes),
            self.bytes.len()
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "alpn_protocol",
                String::from_utf8_lossy(&self.bytes).to_string(),
            ),
            ("alpn_protocol_bytes", self.bytes.len().to_string()),
        ]
    }
}

impl From<Vec<u8>> for TlsAlpnProtocol {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for TlsAlpnProtocol {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes)
    }
}

impl<const N: usize> From<[u8; N]> for TlsAlpnProtocol {
    fn from(bytes: [u8; N]) -> Self {
        Self::new(bytes)
    }
}

impl From<&str> for TlsAlpnProtocol {
    fn from(value: &str) -> Self {
        Self::new(value.as_bytes())
    }
}

impl From<String> for TlsAlpnProtocol {
    fn from(value: String) -> Self {
        Self::new(value.into_bytes())
    }
}

/// TLS `application_layer_protocol_negotiation` extension body as an RFC 7301 ProtocolNameList.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsAlpnProtocols {
    protocols: Vec<TlsAlpnProtocol>,
}

impl TlsAlpnProtocols {
    /// Create an ordered ALPN ProtocolNameList.
    pub fn new(protocols: impl Into<Vec<TlsAlpnProtocol>>) -> Self {
        Self {
            protocols: protocols.into(),
        }
    }

    /// Create a one-entry ProtocolNameList containing `protocol`.
    pub fn from_protocol(protocol: impl Into<TlsAlpnProtocol>) -> Self {
        Self::new(vec![protocol.into()])
    }

    /// Create a one-entry ProtocolNameList containing `http/1.1`.
    pub fn http_1_1() -> Self {
        Self::from_protocol(TlsAlpnProtocol::http_1_1())
    }

    /// Create a one-entry ProtocolNameList containing `h2`.
    pub fn h2() -> Self {
        Self::from_protocol(TlsAlpnProtocol::h2())
    }

    /// Create a ProtocolNameList containing `h2`, then `http/1.1`.
    pub fn h2_then_http_1_1() -> Self {
        Self::new(vec![TlsAlpnProtocol::h2(), TlsAlpnProtocol::http_1_1()])
    }

    /// Borrow the ordered protocol names.
    pub fn protocols(&self) -> &[TlsAlpnProtocol] {
        &self.protocols
    }

    /// Compatibility alias for borrowing the ordered protocol names.
    pub fn as_slice(&self) -> &[TlsAlpnProtocol] {
        self.protocols()
    }

    /// Return the ordered opaque protocol-name bytes.
    pub fn protocol_bytes(&self) -> Vec<&[u8]> {
        self.protocols.iter().map(TlsAlpnProtocol::bytes).collect()
    }

    /// Consume the list and return the ordered protocol names.
    pub fn into_vec(self) -> Vec<TlsAlpnProtocol> {
        self.protocols
    }

    /// Append one protocol name.
    pub fn push(&mut self, protocol: impl Into<TlsAlpnProtocol>) {
        self.protocols.push(protocol.into());
    }

    /// Number of protocol names.
    pub fn len(&self) -> usize {
        self.protocols.len()
    }

    /// Return true when the list carries no protocol names.
    pub fn is_empty(&self) -> bool {
        self.protocols.is_empty()
    }

    /// Number of bytes occupied by ProtocolName entries, excluding the list length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        validate_alpn_protocols(&self.protocols)?;
        let mut len = 0usize;
        for protocol in &self.protocols {
            len = len.checked_add(protocol.encoded_len()?).ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.alpn.protocol_name_list.length",
                    "length overflow",
                )
            })?;
        }
        validate_alpn_protocol_name_list_len(len)?;
        Ok(len)
    }

    /// Number of bytes occupied by the complete encoded ProtocolNameList.
    pub fn encoded_len(&self) -> Result<usize> {
        TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN
            .checked_add(self.byte_len()?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.alpn.protocol_name_list.length",
                    "length overflow",
                )
            })
    }

    /// Append the uint16 length-prefixed ProtocolNameList.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let body_len = self.byte_len()?;
        let body_len = u16::try_from(body_len).map_err(|_| {
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name_list.length",
                "length must fit in two bytes",
            )
        })?;

        out.extend_from_slice(&body_len.to_be_bytes());
        for protocol in &self.protocols {
            protocol.encode(out)?;
        }
        Ok(())
    }

    /// Return the uint16 length-prefixed ProtocolNameList encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len()?);
        self.encode(&mut out)?;
        Ok(out)
    }

    /// Convert this ProtocolNameList into a raw ALPN extension.
    pub fn to_raw_extension(&self) -> Result<TlsRawExtension> {
        Ok(TlsRawExtension::new(
            TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
            self.encode_to_vec()?,
        ))
    }

    /// Decode a uint16 length-prefixed ProtocolNameList.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (protocols, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(protocols)
    }

    /// Decode a uint16 length-prefixed ProtocolNameList from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                "tls.alpn.protocol_name_list.length",
                TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        validate_alpn_protocol_name_list_len(byte_len)?;
        let required = TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(
                    "tls.alpn.protocol_name_list.length",
                    "length overflow",
                )
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                "tls.alpn.protocol_name_list",
                required,
                bytes.len(),
            ));
        }

        let mut cursor = TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN;
        let body_end = required;
        let mut protocols = Vec::new();
        while cursor < body_end {
            let (protocol, tail) = TlsAlpnProtocol::decode_prefix(&bytes[cursor..body_end])?;
            cursor = body_end - tail.len();
            protocols.push(protocol);
        }

        validate_alpn_protocols(&protocols)?;
        Ok((Self::new(protocols), &bytes[required..]))
    }

    /// Decode a raw ALPN extension body.
    pub fn from_raw_extension(extension: &TlsRawExtension) -> Result<Self> {
        if extension.extension_type() != TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION {
            return Err(CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be application_layer_protocol_negotiation",
            ));
        }
        Self::decode(extension.body())
    }

    /// Stable one-line summary preserving protocol order.
    pub fn summary(&self) -> String {
        let values = self
            .protocols
            .iter()
            .map(|protocol| String::from_utf8_lossy(protocol.bytes()).to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "alpn protocols count={} bytes={} values={}",
            self.len(),
            self.protocols
                .iter()
                .map(|protocol| protocol.encoded_len().unwrap_or(0))
                .sum::<usize>(),
            values
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("alpn_protocol_count", self.len().to_string()),
            (
                "alpn_protocols",
                self.protocols
                    .iter()
                    .map(|protocol| String::from_utf8_lossy(protocol.bytes()).to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            (
                "alpn_protocol_bytes",
                self.protocols
                    .iter()
                    .map(|protocol| protocol.encoded_len().unwrap_or(0))
                    .sum::<usize>()
                    .to_string(),
            ),
        ]
    }
}

impl From<Vec<TlsAlpnProtocol>> for TlsAlpnProtocols {
    fn from(protocols: Vec<TlsAlpnProtocol>) -> Self {
        Self::new(protocols)
    }
}

impl<const N: usize> From<[TlsAlpnProtocol; N]> for TlsAlpnProtocols {
    fn from(protocols: [TlsAlpnProtocol; N]) -> Self {
        Self::new(Vec::from(protocols))
    }
}

impl TryFrom<&TlsRawExtension> for TlsAlpnProtocols {
    type Error = CrafterError;

    fn try_from(value: &TlsRawExtension) -> Result<Self> {
        Self::from_raw_extension(value)
    }
}

impl TryFrom<TlsAlpnProtocols> for TlsRawExtension {
    type Error = CrafterError;

    fn try_from(value: TlsAlpnProtocols) -> Result<Self> {
        value.to_raw_extension()
    }
}

fn validate_alpn_protocol(protocol: &TlsAlpnProtocol) -> Result<()> {
    let len = protocol.bytes().len();
    if len == 0 {
        return Err(CrafterError::invalid_field_value(
            "tls.alpn.protocol_name.length",
            "length must be at least one byte",
        ));
    }
    if len > u8::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.alpn.protocol_name.length",
            "length must fit in one byte",
        ));
    }
    Ok(())
}

fn validate_alpn_protocols(protocols: &[TlsAlpnProtocol]) -> Result<()> {
    for protocol in protocols {
        validate_alpn_protocol(protocol)?;
    }
    Ok(())
}

fn validate_alpn_protocol_name_list_len(len: usize) -> Result<()> {
    if len < TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN + 1 {
        return Err(CrafterError::invalid_field_value(
            "tls.alpn.protocol_name_list.length",
            "length must be at least two bytes",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.alpn.protocol_name_list.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

fn validate_server_name_entry(name: &TlsServerName) -> Result<()> {
    let body_len = name.body().len();
    if body_len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.server_name.name.length",
            "length must fit in two bytes",
        ));
    }

    if let TlsServerName::HostName(host_name) = name {
        if host_name.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "tls.server_name.host_name.length",
                "length must be at least one byte",
            ));
        }
        if !host_name.is_ascii() {
            return Err(CrafterError::invalid_field_value(
                "tls.server_name.host_name",
                "host_name must be ASCII",
            ));
        }
        if host_name.last() == Some(&b'.') {
            return Err(CrafterError::invalid_field_value(
                "tls.server_name.host_name",
                "host_name must not include trailing dot",
            ));
        }
    }

    Ok(())
}

fn validate_server_name_list_entries(names: &[TlsServerName]) -> Result<()> {
    let mut seen = [false; 256];
    for name in names {
        validate_server_name_entry(name)?;
        let name_type = name.name_type().raw() as usize;
        if seen[name_type] {
            return Err(CrafterError::invalid_field_value(
                "tls.server_name.name_type",
                "duplicate name_type in server_name list",
            ));
        }
        seen[name_type] = true;
    }
    Ok(())
}

fn validate_server_name_list_len(len: usize) -> Result<()> {
    if len == 0 {
        return Err(CrafterError::invalid_field_value(
            "tls.server_name_list.length",
            "length must be at least one byte",
        ));
    }
    if len > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            "tls.server_name_list.length",
            "length must fit in two bytes",
        ));
    }
    Ok(())
}

/// Error contexts used while encoding or decoding an extension list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsExtensionListContext {
    list: &'static str,
    list_length: &'static str,
    extension: &'static str,
    extension_type: &'static str,
    extension_length: &'static str,
    extension_body: &'static str,
}

impl TlsExtensionListContext {
    /// Create explicit labels for one extension-list context.
    pub const fn new(
        list: &'static str,
        list_length: &'static str,
        extension: &'static str,
        extension_type: &'static str,
        extension_length: &'static str,
        extension_body: &'static str,
    ) -> Self {
        Self {
            list,
            list_length,
            extension,
            extension_type,
            extension_length,
            extension_body,
        }
    }

    /// Generic `tls.extensions.*` context.
    pub const fn generic() -> Self {
        Self::new(
            "tls.extensions",
            "tls.extensions.length",
            "tls.extension",
            "tls.extension.type",
            "tls.extension.length",
            "tls.extension.body",
        )
    }

    /// ClientHello `tls.client_hello.extensions.*` context.
    pub const fn client_hello() -> Self {
        Self::new(
            "tls.client_hello.extensions",
            "tls.client_hello.extensions.length",
            "tls.client_hello.extension",
            "tls.client_hello.extension.type",
            "tls.client_hello.extension.length",
            "tls.client_hello.extension.body",
        )
    }

    /// ServerHello `tls.server_hello.extensions.*` context.
    pub const fn server_hello() -> Self {
        Self::new(
            "tls.server_hello.extensions",
            "tls.server_hello.extensions.length",
            "tls.server_hello.extension",
            "tls.server_hello.extension.type",
            "tls.server_hello.extension.length",
            "tls.server_hello.extension.body",
        )
    }

    /// EncryptedExtensions `tls.encrypted_extensions.extensions.*` context.
    pub const fn encrypted_extensions() -> Self {
        Self::new(
            "tls.encrypted_extensions.extensions",
            "tls.encrypted_extensions.extensions.length",
            "tls.encrypted_extensions.extension",
            "tls.encrypted_extensions.extension.type",
            "tls.encrypted_extensions.extension.length",
            "tls.encrypted_extensions.extension.body",
        )
    }

    /// CertificateRequest `tls.certificate_request.extensions.*` context.
    pub const fn certificate_request() -> Self {
        Self::new(
            "tls.certificate_request.extensions",
            "tls.certificate_request.extensions.length",
            "tls.certificate_request.extension",
            "tls.certificate_request.extension.type",
            "tls.certificate_request.extension.length",
            "tls.certificate_request.extension.body",
        )
    }

    /// NewSessionTicket `tls.new_session_ticket.extensions.*` context.
    pub const fn new_session_ticket() -> Self {
        Self::new(
            "tls.new_session_ticket.extensions",
            "tls.new_session_ticket.extensions.length",
            "tls.new_session_ticket.extension",
            "tls.new_session_ticket.extension.type",
            "tls.new_session_ticket.extension.length",
            "tls.new_session_ticket.extension.body",
        )
    }

    /// Certificate `tls.certificate.extensions.*` context.
    pub const fn certificate() -> Self {
        Self::new(
            "tls.certificate.extensions",
            "tls.certificate.extensions.length",
            "tls.certificate.extension",
            "tls.certificate.extension.type",
            "tls.certificate.extension.length",
            "tls.certificate.extension.body",
        )
    }

    /// CertificateEntry `tls.certificate_entry.extensions.*` context.
    pub const fn certificate_entry() -> Self {
        Self::new(
            "tls.certificate_entry.extensions",
            "tls.certificate_entry.extensions.length",
            "tls.certificate_entry.extension",
            "tls.certificate_entry.extension.type",
            "tls.certificate_entry.extension.length",
            "tls.certificate_entry.extension.body",
        )
    }

    /// Context for the aggregate extension-list body.
    pub const fn list(self) -> &'static str {
        self.list
    }

    /// Context for the aggregate extension-list length.
    pub const fn list_length(self) -> &'static str {
        self.list_length
    }

    /// Context for one complete extension entry.
    pub const fn extension(self) -> &'static str {
        self.extension
    }

    /// Context for one extension type field.
    pub const fn extension_type(self) -> &'static str {
        self.extension_type
    }

    /// Context for one extension body length field.
    pub const fn extension_length(self) -> &'static str {
        self.extension_length
    }

    /// Context for one extension body.
    pub const fn extension_body(self) -> &'static str {
        self.extension_body
    }
}

impl Default for TlsExtensionListContext {
    fn default() -> Self {
        Self::generic()
    }
}

/// Ordered TLS extension list with duplicate entries preserved visibly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TlsExtensions {
    extensions: Vec<TlsRawExtension>,
}

impl TlsExtensions {
    /// Create an ordered extension list.
    pub fn new(extensions: impl Into<Vec<TlsRawExtension>>) -> Self {
        Self {
            extensions: extensions.into(),
        }
    }

    /// Create an empty ordered extension list.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Create an ordered extension list from raw type/body pairs.
    pub fn from_raws<I, B>(extensions: I) -> Self
    where
        I: IntoIterator<Item = (u16, B)>,
        B: Into<Vec<u8>>,
    {
        Self::new(
            extensions
                .into_iter()
                .map(|(extension_type, body)| TlsRawExtension::from_raw(extension_type, body))
                .collect::<Vec<_>>(),
        )
    }

    /// Borrow the ordered raw extension entries.
    pub fn extensions(&self) -> &[TlsRawExtension] {
        &self.extensions
    }

    /// Compatibility alias for borrowing the ordered raw extension entries.
    pub fn as_slice(&self) -> &[TlsRawExtension] {
        self.extensions()
    }

    /// Return the ordered raw extension type values.
    pub fn raw_types(&self) -> Vec<u16> {
        self.extensions
            .iter()
            .map(TlsRawExtension::raw_type)
            .collect()
    }

    /// Return labels in wire order.
    pub fn labels(&self) -> Vec<String> {
        self.extensions
            .iter()
            .map(|extension| extension.extension_type().label())
            .collect()
    }

    /// Return every extension with this raw type in wire order, preserving duplicates.
    pub fn all_by_raw_type(&self, raw_type: u16) -> Vec<&TlsRawExtension> {
        self.extensions
            .iter()
            .filter(|extension| extension.raw_type() == raw_type)
            .collect()
    }

    /// Return every extension with this type in wire order, preserving duplicates.
    pub fn all_by_type(
        &self,
        extension_type: impl Into<TlsExtensionType>,
    ) -> Vec<&TlsRawExtension> {
        self.all_by_raw_type(extension_type.into().raw())
    }

    /// Consume the list and return the ordered raw extension entries.
    pub fn into_vec(self) -> Vec<TlsRawExtension> {
        self.extensions
    }

    /// Append one raw extension entry to the ordered list.
    pub fn push(&mut self, extension: TlsRawExtension) {
        self.extensions.push(extension);
    }

    /// Number of extension entries in the list.
    pub fn len(&self) -> usize {
        self.extensions.len()
    }

    /// Return true when the list carries no extension entries.
    pub fn is_empty(&self) -> bool {
        self.extensions.is_empty()
    }

    /// Number of bytes occupied by extension entries, excluding the list length prefix.
    pub fn byte_len(&self) -> Result<usize> {
        self.byte_len_with_context(TlsExtensionListContext::generic())
    }

    /// Number of bytes occupied by extension entries using context-specific labels.
    pub fn byte_len_with_context(&self, context: TlsExtensionListContext) -> Result<usize> {
        let mut len = 0usize;
        for extension in &self.extensions {
            len = len.checked_add(extension.encoded_len()?).ok_or_else(|| {
                CrafterError::invalid_field_value(context.list_length(), "length overflow")
            })?;
        }

        if len > u16::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                context.list_length(),
                "length must fit in two bytes",
            ));
        }

        Ok(len)
    }

    /// Number of bytes occupied by the complete encoded extension list.
    pub fn encoded_len(&self) -> Result<usize> {
        self.encoded_len_with_context(TlsExtensionListContext::generic())
    }

    /// Number of bytes occupied by the complete encoded list using context-specific labels.
    pub fn encoded_len_with_context(&self, context: TlsExtensionListContext) -> Result<usize> {
        TLS_EXTENSION_LIST_LENGTH_LEN
            .checked_add(self.byte_len_with_context(context)?)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.list_length(), "length overflow")
            })
    }

    /// Append the uint16 length-prefixed extension list.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.encode_with_context(TlsExtensionListContext::generic(), out)
    }

    /// Append the uint16 length-prefixed extension list with context-specific labels.
    pub fn encode_with_context(
        &self,
        context: TlsExtensionListContext,
        out: &mut Vec<u8>,
    ) -> Result<()> {
        let body_len = self.byte_len_with_context(context)?;
        let body_len = u16::try_from(body_len).map_err(|_| {
            CrafterError::invalid_field_value(context.list_length(), "length must fit in two bytes")
        })?;

        out.extend_from_slice(&body_len.to_be_bytes());
        for extension in &self.extensions {
            extension.encode(out)?;
        }
        Ok(())
    }

    /// Return the uint16 length-prefixed extension list encoding.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        self.encode_to_vec_with_context(TlsExtensionListContext::generic())
    }

    /// Return the uint16 length-prefixed extension list encoding with context-specific labels.
    pub fn encode_to_vec_with_context(&self, context: TlsExtensionListContext) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.encoded_len_with_context(context)?);
        self.encode_with_context(context, &mut out)?;
        Ok(out)
    }

    /// Decode a uint16 length-prefixed extension list.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let (extensions, _) = Self::decode_prefix(bytes.as_ref())?;
        Ok(extensions)
    }

    /// Decode a uint16 length-prefixed extension list using context-specific labels.
    pub fn decode_with_context(
        context: TlsExtensionListContext,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let (extensions, _) = Self::decode_prefix_with_context(context, bytes.as_ref())?;
        Ok(extensions)
    }

    /// Decode a uint16 length-prefixed extension list from the front of `bytes`.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8])> {
        Self::decode_prefix_with_context(TlsExtensionListContext::generic(), bytes)
    }

    /// Decode a uint16 length-prefixed extension list from the front of `bytes`
    /// using context-specific labels.
    pub fn decode_prefix_with_context(
        context: TlsExtensionListContext,
        bytes: &[u8],
    ) -> Result<(Self, &[u8])> {
        if bytes.len() < TLS_EXTENSION_LIST_LENGTH_LEN {
            return Err(CrafterError::buffer_too_short(
                context.list_length(),
                TLS_EXTENSION_LIST_LENGTH_LEN,
                bytes.len(),
            ));
        }

        let byte_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        let required = TLS_EXTENSION_LIST_LENGTH_LEN
            .checked_add(byte_len)
            .ok_or_else(|| {
                CrafterError::invalid_field_value(context.list_length(), "length overflow")
            })?;
        if bytes.len() < required {
            return Err(CrafterError::buffer_too_short(
                context.list(),
                required,
                bytes.len(),
            ));
        }

        let mut cursor = TLS_EXTENSION_LIST_LENGTH_LEN;
        let body_end = required;
        let mut extensions = Vec::new();

        while cursor < body_end {
            let remaining = body_end - cursor;
            if remaining < TLS_EXTENSION_HEADER_LEN {
                return Err(CrafterError::buffer_too_short(
                    context.extension(),
                    TLS_EXTENSION_HEADER_LEN,
                    remaining,
                ));
            }

            let extension_type =
                TlsExtensionType::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
            cursor += TLS_EXTENSION_TYPE_LEN;

            let body_len = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]) as usize;
            cursor += TLS_EXTENSION_LENGTH_LEN;

            if body_end - cursor < body_len {
                return Err(CrafterError::buffer_too_short(
                    context.extension_body(),
                    TLS_EXTENSION_HEADER_LEN + body_len,
                    remaining,
                ));
            }

            let extension_body = bytes[cursor..cursor + body_len].to_vec();
            cursor += body_len;
            extensions.push(TlsRawExtension::new(extension_type, extension_body));
        }

        Ok((Self::new(extensions), &bytes[required..]))
    }

    /// Stable one-line summary preserving order and duplicate entries.
    pub fn summary(&self) -> String {
        format!(
            "extensions count={} bytes={} values={}",
            self.len(),
            self.extensions
                .iter()
                .map(|extension| extension.encoded_len().unwrap_or(0))
                .sum::<usize>(),
            self.labels().join(",")
        )
    }

    /// Stable field/value pairs for packet inspection output.
    pub fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("extensions_count", self.len().to_string()),
            (
                "extensions_bytes",
                self.extensions
                    .iter()
                    .map(|extension| extension.encoded_len().unwrap_or(0))
                    .sum::<usize>()
                    .to_string(),
            ),
            ("extensions", self.labels().join(",")),
        ]
    }
}

impl From<Vec<TlsRawExtension>> for TlsExtensions {
    fn from(extensions: Vec<TlsRawExtension>) -> Self {
        Self::new(extensions)
    }
}

impl<const N: usize> From<[TlsRawExtension; N]> for TlsExtensions {
    fn from(extensions: [TlsRawExtension; N]) -> Self {
        Self::new(Vec::from(extensions))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_extension_type_known_constructors_expose_raw_values() {
        assert_eq!(
            TlsExtensionType::server_name().raw(),
            constants::TLS_EXTENSION_SERVER_NAME
        );
        assert_eq!(
            TlsExtensionType::status_request().raw(),
            constants::TLS_EXTENSION_STATUS_REQUEST
        );
        assert_eq!(
            TlsExtensionType::status_request_v2().raw(),
            constants::TLS_EXTENSION_STATUS_REQUEST_V2
        );
        assert_eq!(
            TlsExtensionType::supported_groups().raw(),
            constants::TLS_EXTENSION_SUPPORTED_GROUPS
        );
        assert_eq!(
            TlsExtensionType::signature_algorithms().raw(),
            constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS
        );
        assert_eq!(
            TlsExtensionType::signature_algorithms_cert().raw(),
            constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT
        );
        assert_eq!(
            TlsExtensionType::application_layer_protocol_negotiation().raw(),
            constants::TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        );
        assert_eq!(
            TlsExtensionType::supported_versions().raw(),
            constants::TLS_EXTENSION_SUPPORTED_VERSIONS
        );
        assert_eq!(
            TlsExtensionType::key_share().raw(),
            constants::TLS_EXTENSION_KEY_SHARE
        );
        assert_eq!(
            TlsExtensionType::from_be_bytes([0x00, 0x2b]),
            TlsExtensionType::SUPPORTED_VERSIONS
        );
        assert_eq!(
            TlsExtensionType::SUPPORTED_VERSIONS.to_be_bytes(),
            [0x00, 0x2b]
        );
    }

    #[test]
    fn tls_extension_type_labels_statuses_and_ranges_reuse_constants() {
        let sni = TlsExtensionType::SERVER_NAME;
        let legacy = TlsExtensionType::MAX_FRAGMENT_LENGTH;
        let status_request_v2 = TlsExtensionType::STATUS_REQUEST_V2;
        let deferred = TlsExtensionType::HEARTBEAT;
        let reserved = TlsExtensionType::RESERVED_46;
        let grease = TlsExtensionType::from_u16(0x0a0a);
        let private = TlsExtensionType::from_u16(0xff10);
        let renegotiation = TlsExtensionType::RENEGOTIATION_INFO;
        let ech = TlsExtensionType::ENCRYPTED_CLIENT_HELLO;
        let unknown = TlsExtensionType::from_u16(0xbeef);

        assert_eq!(sni.name(), Some("server_name"));
        assert_eq!(sni.status(), TlsCodepointStatus::DefaultEligible);
        assert_eq!(sni.label(), "server_name");
        assert_eq!(sni.to_string(), "server_name");
        assert!(sni.is_known());
        assert!(sni.is_default_eligible());

        assert_eq!(legacy.status(), TlsCodepointStatus::PreserveOnly);
        assert_eq!(legacy.label(), "max_fragment_length");
        assert!(!legacy.is_default_eligible());

        assert_eq!(
            status_request_v2.status(),
            TlsCodepointStatus::LabelEligible
        );
        assert_eq!(status_request_v2.label(), "status_request_v2");
        assert!(!status_request_v2.is_default_eligible());

        assert_eq!(deferred.status(), TlsCodepointStatus::Deferred);
        assert_eq!(deferred.label(), "heartbeat");

        assert_eq!(reserved.status(), TlsCodepointStatus::Reserved);
        assert_eq!(reserved.label(), "Reserved");

        assert_eq!(grease.name(), None);
        assert_eq!(grease.status(), TlsCodepointStatus::ReservedGrease);
        assert_eq!(grease.label(), "reserved grease extension 0x0a0a");
        assert!(grease.is_grease());

        assert_eq!(private.status(), TlsCodepointStatus::PrivateUse);
        assert_eq!(private.label(), "private-use extension 0xff10");
        assert!(private.is_private_use());

        assert_eq!(renegotiation.status(), TlsCodepointStatus::PreserveOnly);
        assert!(!renegotiation.is_private_use());

        assert_eq!(ech.status(), TlsCodepointStatus::PreserveOnly);
        assert!(ech.is_ech());

        assert_eq!(unknown.status(), TlsCodepointStatus::Unknown);
        assert_eq!(unknown.label(), "unknown extension 0xbeef");
        assert!(!unknown.is_known());
    }

    #[test]
    fn tls_extension_type_encode_decode_preserves_raw_values_and_tail() {
        let extension_type = TlsExtensionType::from_u16(0xbeef);
        let mut encoded = Vec::new();
        extension_type.encode(&mut encoded);

        assert_eq!(encoded, [0xbe, 0xef]);
        assert_eq!(extension_type.encode_to_vec(), vec![0xbe, 0xef]);
        assert_eq!(TlsExtensionType::decode(&encoded).unwrap(), extension_type);
        assert_eq!(
            TlsExtensionType::decode_prefix(&[0xbe, 0xef, 0xaa]).unwrap(),
            (extension_type, &[0xaa][..])
        );
        assert_eq!(u16::from(extension_type), 0xbeef);
        assert_eq!(TlsExtensionType::from(0xbeef).as_u16(), 0xbeef);
    }

    #[test]
    fn tls_extension_type_inspection_includes_raw_status_and_ranges() {
        let grease = TlsExtensionType::from_u16(0x1a1a);

        assert_eq!(
            grease.summary(),
            "reserved grease extension 0x1a1a raw=0x1a1a status=reserved-grease"
        );

        let fields = grease.inspection_fields();
        assert!(fields.contains(&(
            "extension_type",
            "reserved grease extension 0x1a1a".to_string()
        )));
        assert!(fields.contains(&("extension_type_raw", "0x1a1a".to_string())));
        assert!(fields.contains(&("extension_type_status", "reserved-grease".to_string())));
        assert!(fields.contains(&("grease", "true".to_string())));
        assert!(fields.contains(&("private_use", "false".to_string())));
        assert!(fields.contains(&("ech", "false".to_string())));
    }

    #[test]
    fn tls_extension_type_raw_extension_preserves_unknown_type_and_body_bytes() {
        let extension = TlsRawExtension::from_raw(0xbeef, [0xde, 0xad, 0xfa, 0xce]);
        let encoded = extension.encode_to_vec().unwrap();

        assert_eq!(encoded, [0xbe, 0xef, 0x00, 0x04, 0xde, 0xad, 0xfa, 0xce]);
        assert_eq!(extension.body_len(), 4);
        assert_eq!(
            extension.encoded_len().unwrap(),
            TLS_EXTENSION_HEADER_LEN + 4
        );

        let encoded_with_tail = [encoded.as_slice(), &[0xaa][..]].concat();
        let (decoded, tail) = TlsRawExtension::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded.extension_type(), TlsExtensionType::from_u16(0xbeef));
        assert_eq!(decoded.raw_type(), 0xbeef);
        assert_eq!(decoded.body(), &[0xde, 0xad, 0xfa, 0xce]);
        assert_eq!(decoded.encode_to_vec().unwrap(), encoded);
        assert_eq!(
            decoded.summary(),
            "extension type=unknown extension 0xbeef raw=0xbeef body_bytes=4"
        );

        let fields = decoded.inspection_fields();
        assert!(fields.contains(&("extension_type", "unknown extension 0xbeef".to_string())));
        assert!(fields.contains(&("extension_type_raw", "0xbeef".to_string())));
        assert!(fields.contains(&("extension_type_status", "unknown".to_string())));
        assert!(fields.contains(&("extension_body_bytes", "4".to_string())));
        assert_eq!(decoded.into_body(), vec![0xde, 0xad, 0xfa, 0xce]);
    }

    #[test]
    fn tls_extension_type_raw_extension_supports_known_and_empty_bodies() {
        let extension =
            TlsRawExtension::new(TlsExtensionType::SUPPORTED_VERSIONS, Vec::<u8>::new());

        assert_eq!(extension.body(), &[]);
        assert_eq!(extension.encode_to_vec().unwrap(), [0x00, 0x2b, 0x00, 0x00]);
        assert_eq!(
            TlsRawExtension::decode([0x00, 0x2b, 0x00, 0x00]).unwrap(),
            extension
        );
    }

    #[test]
    fn tls_extension_type_decode_reports_structured_errors() {
        assert_eq!(
            TlsExtensionType::decode([0xbe]).unwrap_err(),
            CrafterError::buffer_too_short("tls.extension.type", TLS_EXTENSION_TYPE_LEN, 1)
        );
        assert_eq!(
            TlsRawExtension::decode([0xbe, 0xef, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.extension", TLS_EXTENSION_HEADER_LEN, 3)
        );
        assert_eq!(
            TlsRawExtension::decode([0xbe, 0xef, 0x00, 0x04, 0xde]).unwrap_err(),
            CrafterError::buffer_too_short("tls.extension.body", 8, 5)
        );
    }

    #[test]
    fn tls_extension_type_encode_rejects_oversized_raw_body() {
        let extension = TlsRawExtension::from_raw(0xbeef, vec![0; u16::MAX as usize + 1]);

        assert_eq!(
            extension.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_status_request_builders_encode_and_inspect() {
        // RFC 6066 Section 8 defines CertificateStatusRequest with the OCSPStatusRequest body.
        assert_eq!(
            TlsExtensionType::status_request(),
            TlsExtensionType::STATUS_REQUEST
        );
        assert_eq!(
            TlsExtensionType::status_request_v2(),
            TlsExtensionType::STATUS_REQUEST_V2
        );

        let status_type = TlsCertificateStatusType::ocsp();
        assert_eq!(
            TlsCertificateStatusType::reserved().raw(),
            TLS_CERTIFICATE_STATUS_TYPE_RESERVED
        );
        assert!(TlsCertificateStatusType::reserved().is_reserved());
        assert_eq!(status_type.raw(), TLS_CERTIFICATE_STATUS_TYPE_OCSP);
        assert_eq!(status_type.as_u8(), TLS_CERTIFICATE_STATUS_TYPE_OCSP);
        assert_eq!(status_type.to_be_bytes(), [0x01]);
        assert_eq!(
            TlsCertificateStatusType::decode([0x01]).unwrap(),
            status_type
        );
        assert_eq!(status_type.name(), Some("ocsp"));
        assert_eq!(status_type.status(), TlsCodepointStatus::DefaultEligible);
        assert!(status_type.is_ocsp());
        assert!(status_type.uses_ocsp_status_request());
        assert_eq!(
            status_type.summary(),
            "ocsp raw=0x01 status=default-eligible"
        );
        assert!(status_type
            .inspection_fields()
            .contains(&("certificate_status_type", "ocsp".to_string())));
        assert_eq!(status_type.to_string(), "ocsp");
        assert_eq!(u8::from(status_type), 1);

        let responder_id = TlsOcspResponderId::new([0xaa, 0xbb]);
        assert_eq!(responder_id.len(), 2);
        assert_eq!(responder_id.bytes(), &[0xaa, 0xbb]);
        assert_eq!(
            responder_id.encode_to_vec().unwrap(),
            [0x00, 0x02, 0xaa, 0xbb]
        );
        assert_eq!(
            TlsOcspResponderId::decode_prefix(&[0x00, 0x02, 0xaa, 0xbb, 0xcc]).unwrap(),
            (responder_id.clone(), &[0xcc][..])
        );
        assert_eq!(responder_id.summary(), "ocsp_responder_id bytes=2");

        let responder_ids = TlsOcspResponderIds::new([responder_id.clone()]);
        assert_eq!(responder_ids.len(), 1);
        assert!(!responder_ids.is_empty());
        assert_eq!(responder_ids.byte_lengths(), vec![2]);
        assert_eq!(
            responder_ids.encode_to_vec().unwrap(),
            [0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb]
        );
        assert_eq!(
            responder_ids.summary(),
            "ocsp_responder_ids count=1 bytes=2 responder_lengths=2"
        );

        let ocsp = TlsOcspStatusRequest::new(responder_ids.clone(), [0x30, 0x00]);
        assert_eq!(ocsp.responder_id_count(), 1);
        assert_eq!(ocsp.responder_ids(), &[responder_id]);
        assert_eq!(ocsp.request_extensions(), &[0x30, 0x00]);
        assert_eq!(ocsp.request_extensions_len(), 2);
        assert_eq!(ocsp.encoded_len().unwrap(), 10);
        assert_eq!(
            ocsp.encode_to_vec().unwrap(),
            [0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x02, 0x30, 0x00]
        );
        assert_eq!(
            TlsOcspStatusRequest::decode(ocsp.encode_to_vec().unwrap()).unwrap(),
            ocsp
        );
        assert_eq!(
            ocsp.summary(),
            "ocsp_status_request responders=1 responder_bytes=2 request_extensions_bytes=2"
        );
        assert!(ocsp
            .inspection_fields()
            .contains(&("ocsp_request_extensions", "30 00".to_string())));

        let request = TlsStatusRequest::ocsp(ocsp.clone());
        assert_eq!(request.status_type(), TlsCertificateStatusType::OCSP);
        assert!(request.ocsp_request().is_some());
        assert_eq!(
            request.encode_to_vec().unwrap(),
            [0x01, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x02, 0x30, 0x00]
        );
        assert_eq!(
            TlsStatusRequest::decode(request.encode_to_vec().unwrap()).unwrap(),
            request
        );
        assert_eq!(
            request.summary(),
            "status_request status_type=ocsp raw=0x01 request=ocsp request_bytes=10"
        );
        assert!(request
            .inspection_fields()
            .contains(&("status_request_status_type", "ocsp".to_string())));

        let raw = request.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::STATUS_REQUEST);
        assert_eq!(raw.raw_type(), constants::TLS_EXTENSION_STATUS_REQUEST);
        let mut expected_raw = vec![0x00, 0x05, 0x00, 0x0b];
        expected_raw.extend_from_slice(&request.encode_to_vec().unwrap());
        assert_eq!(raw.encode_to_vec().unwrap(), expected_raw);
        assert_eq!(raw.as_status_request().unwrap(), request);
        assert_eq!(TlsStatusRequest::from_raw_extension(&raw).unwrap(), request);
        assert_eq!(TlsRawExtension::try_from(request.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::status_request(request.clone()).unwrap(),
            raw
        );
        assert_eq!(
            TlsRawExtension::status_request_ocsp(ocsp.clone()).unwrap(),
            raw
        );

        // RFC 6961 Section 2.2 wraps one or more status request items in a vector.
        let item = TlsStatusRequestV2Item::ocsp(ocsp);
        assert_eq!(item.status_type(), TlsCertificateStatusType::OCSP);
        assert_eq!(item.request_len().unwrap(), 10);
        assert_eq!(
            item.encode_to_vec().unwrap(),
            [0x01, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x02, 0x30, 0x00]
        );
        assert_eq!(
            item.summary(),
            "status_request_v2_item status_type=ocsp raw=0x01 request=ocsp request_bytes=10"
        );
        assert!(item
            .inspection_fields()
            .contains(&("status_request_v2_item_request_bytes", "10".to_string())));

        let request_v2 = TlsStatusRequestV2::new([item]);
        assert_eq!(request_v2.len(), 1);
        assert_eq!(request_v2.byte_len().unwrap(), 13);
        assert_eq!(
            request_v2.encode_to_vec().unwrap(),
            [
                0x00, 0x0d, 0x01, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x02, 0x30,
                0x00
            ]
        );
        assert_eq!(
            TlsStatusRequestV2::decode(request_v2.encode_to_vec().unwrap()).unwrap(),
            request_v2
        );
        assert_eq!(
            request_v2.summary(),
            "status_request_v2 items=1 bytes=13 status_types=ocsp"
        );

        let raw_v2 = request_v2.to_raw_extension().unwrap();
        assert_eq!(raw_v2.extension_type(), TlsExtensionType::STATUS_REQUEST_V2);
        assert_eq!(
            raw_v2.raw_type(),
            constants::TLS_EXTENSION_STATUS_REQUEST_V2
        );
        let mut expected_raw_v2 = vec![0x00, 0x11, 0x00, 0x0f];
        expected_raw_v2.extend_from_slice(&request_v2.encode_to_vec().unwrap());
        assert_eq!(raw_v2.encode_to_vec().unwrap(), expected_raw_v2);
        assert_eq!(raw_v2.as_status_request_v2().unwrap(), request_v2);
        assert_eq!(
            TlsStatusRequestV2::from_raw_extension(&raw_v2).unwrap(),
            request_v2
        );
        assert_eq!(
            TlsRawExtension::try_from(request_v2.clone()).unwrap(),
            raw_v2
        );
        assert_eq!(
            TlsRawExtension::status_request_v2(request_v2).unwrap(),
            raw_v2
        );
    }

    #[test]
    fn tls_extension_status_request_preserves_unknown_and_explicit_values() {
        let unknown_type = TlsCertificateStatusType::from_u8(0x7a);
        assert_eq!(unknown_type.status(), TlsCodepointStatus::Unassigned);
        assert!(unknown_type.is_unassigned());
        assert_eq!(
            unknown_type.label(),
            "unassigned certificate status type 0x7a"
        );
        assert_eq!(
            TlsCertificateStatusType::decode_prefix(&[0x7a, 0xaa]).unwrap(),
            (unknown_type, &[0xaa][..])
        );

        let request = TlsStatusRequest::decode([0x7a, 0xde, 0xad]).unwrap();
        assert_eq!(request.status_type(), unknown_type);
        assert_eq!(request.request().opaque_bytes(), Some(&[0xde, 0xad][..]));
        assert_eq!(request.encode_to_vec().unwrap(), [0x7a, 0xde, 0xad]);
        assert_eq!(
            request.summary(),
            "status_request status_type=unassigned certificate status type 0x7a raw=0x7a request=opaque request_bytes=2"
        );
        assert!(request
            .inspection_fields()
            .contains(&("status_request_opaque", "de ad".to_string())));

        let request_v2 =
            TlsStatusRequestV2::decode([0x00, 0x05, 0x7a, 0x00, 0x02, 0xde, 0xad]).unwrap();
        assert_eq!(request_v2.items()[0].status_type(), unknown_type);
        assert_eq!(
            request_v2.items()[0].request().opaque_bytes(),
            Some(&[0xde, 0xad][..])
        );
        assert_eq!(
            request_v2.encode_to_vec().unwrap(),
            [0x00, 0x05, 0x7a, 0x00, 0x02, 0xde, 0xad]
        );

        let ocsp_multi = TlsCertificateStatusType::ocsp_multi_reserved();
        assert_eq!(
            ocsp_multi.raw(),
            TLS_CERTIFICATE_STATUS_TYPE_OCSP_MULTI_RESERVED
        );
        assert_eq!(ocsp_multi.status(), TlsCodepointStatus::PreserveOnly);
        assert!(ocsp_multi.is_ocsp_multi_reserved());
        assert!(ocsp_multi.uses_ocsp_status_request());
        assert_eq!(ocsp_multi.label(), "ocsp_multi_RESERVED");

        let item = TlsStatusRequestV2Item::ocsp_multi(TlsOcspStatusRequest::empty());
        assert_eq!(item.status_type(), ocsp_multi);
        assert!(item.ocsp_request().is_some());
        assert_eq!(
            item.encode_to_vec().unwrap(),
            [0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            TlsStatusRequestV2Item::decode(item.encode_to_vec().unwrap()).unwrap(),
            item
        );
    }

    #[test]
    fn tls_extension_status_request_reports_structured_errors() {
        assert_eq!(
            TlsCertificateStatusType::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.certificate_status_type",
                TLS_CERTIFICATE_STATUS_TYPE_LEN,
                0
            )
        );
        assert_eq!(
            TlsStatusRequest::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.status_request.status_type",
                TLS_CERTIFICATE_STATUS_TYPE_LEN,
                0
            )
        );
        assert_eq!(
            TlsOcspResponderId::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.status_request.ocsp.responder_id.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsOcspResponderId::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.status_request.ocsp.responder_id.length",
                TLS_OCSP_RESPONDER_ID_LENGTH_LEN,
                1
            )
        );
        assert_eq!(
            TlsOcspResponderIds::decode([0x00, 0x03, 0x00, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.status_request.ocsp.responder_id", 4, 3)
        );
        assert_eq!(
            TlsOcspStatusRequest::decode([0x00, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.status_request.ocsp.request_extensions.length",
                TLS_OCSP_REQUEST_EXTENSIONS_LENGTH_LEN,
                1
            )
        );
        assert_eq!(
            TlsOcspStatusRequest::decode([0x00, 0x00, 0x00, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.status_request.ocsp.request_extensions", 4, 3)
        );
        assert_eq!(
            TlsStatusRequest::decode([0x01, 0x00, 0x00, 0x00, 0x00, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.status_request.length",
                "length must match extension body"
            )
        );
        assert_eq!(
            TlsStatusRequest::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be status_request"
            )
        );
        assert_eq!(
            TlsOcspResponderId::new(Vec::<u8>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.status_request.ocsp.responder_id.length",
                "length must be at least one byte"
            )
        );

        assert_eq!(
            TlsStatusRequestV2::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.status_request_v2.length",
                TLS_STATUS_REQUEST_V2_LIST_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsStatusRequestV2::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.status_request_v2.length",
                "length must be at least three bytes"
            )
        );
        assert_eq!(
            TlsStatusRequestV2::decode([0x00, 0x03, 0x01, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.status_request_v2", 5, 4)
        );
        assert_eq!(
            TlsStatusRequestV2::decode([0x00, 0x03, 0x01, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.status_request.ocsp.responder_id_list.length",
                TLS_OCSP_RESPONDER_ID_LIST_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsStatusRequestV2::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be status_request_v2"
            )
        );
        assert_eq!(
            TlsStatusRequestV2::default().encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.status_request_v2.length",
                "length must be at least three bytes"
            )
        );
    }

    #[test]
    fn tls_extension_certificate_authorities_builders_encode_and_inspect() {
        assert_eq!(
            TlsExtensionType::certificate_authorities(),
            TlsExtensionType::CERTIFICATE_AUTHORITIES
        );
        assert_eq!(
            TlsExtensionType::oid_filters(),
            TlsExtensionType::OID_FILTERS
        );

        let dn1 = TlsDistinguishedName::new([0x30, 0x03, 0x31]);
        let dn2 = TlsDistinguishedName::new([0xaa, 0xbb]);
        assert_eq!(dn1.len(), 3);
        assert!(!dn1.is_empty());
        assert_eq!(dn1.bytes(), &[0x30, 0x03, 0x31]);
        assert_eq!(dn1.encode_to_vec().unwrap(), [0x00, 0x03, 0x30, 0x03, 0x31]);
        assert_eq!(
            TlsDistinguishedName::decode(dn1.encode_to_vec().unwrap()).unwrap(),
            dn1
        );
        assert_eq!(dn1.summary(), "distinguished_name bytes=3");
        assert!(dn1
            .inspection_fields()
            .contains(&("distinguished_name", "30 03 31".to_string())));

        let authorities = TlsCertificateAuthorities::new([dn1.clone(), dn2.clone()]);
        assert_eq!(authorities.len(), 2);
        assert!(!authorities.is_empty());
        assert_eq!(
            authorities.distinguished_names(),
            &[dn1.clone(), dn2.clone()]
        );
        assert_eq!(authorities.byte_lengths(), vec![3, 2]);
        assert_eq!(
            authorities.raw_values(),
            vec![vec![0x30, 0x03, 0x31], vec![0xaa, 0xbb]]
        );
        assert_eq!(authorities.byte_len().unwrap(), 9);
        assert_eq!(authorities.encoded_len().unwrap(), 11);
        assert_eq!(
            authorities.encode_to_vec().unwrap(),
            [0x00, 0x09, 0x00, 0x03, 0x30, 0x03, 0x31, 0x00, 0x02, 0xaa, 0xbb]
        );
        assert_eq!(
            TlsCertificateAuthorities::decode(authorities.encode_to_vec().unwrap()).unwrap(),
            authorities
        );
        assert_eq!(
            authorities.summary(),
            "certificate_authorities count=2 bytes=9"
        );
        assert!(authorities
            .inspection_fields()
            .contains(&("certificate_authorities_lengths", "3,2".to_string())));

        let raw = authorities.to_raw_extension().unwrap();
        assert_eq!(
            raw.extension_type(),
            TlsExtensionType::CERTIFICATE_AUTHORITIES
        );
        assert_eq!(
            raw.raw_type(),
            constants::TLS_EXTENSION_CERTIFICATE_AUTHORITIES
        );
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [
                0x00, 0x2f, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x03, 0x30, 0x03, 0x31, 0x00, 0x02, 0xaa,
                0xbb
            ]
        );
        assert_eq!(raw.as_certificate_authorities().unwrap(), authorities);
        assert_eq!(
            TlsCertificateAuthorities::try_from(&raw).unwrap(),
            authorities
        );
        assert_eq!(TlsRawExtension::try_from(authorities.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::certificate_authorities(authorities.clone()).unwrap(),
            raw
        );
        assert_eq!(
            TlsCertificateAuthorities::from_raws([&[0x30, 0x03, 0x31][..], &[0xaa, 0xbb][..]]),
            authorities
        );

        let filter = TlsOidFilter::new([0x55, 0x1d, 0x25], [0x30, 0x00]);
        assert_eq!(filter.oid(), &[0x55, 0x1d, 0x25]);
        assert_eq!(filter.values(), &[0x30, 0x00]);
        assert_eq!(filter.oid_len(), 3);
        assert_eq!(filter.values_len(), 2);
        assert_eq!(
            filter.encode_to_vec().unwrap(),
            [0x03, 0x55, 0x1d, 0x25, 0x00, 0x02, 0x30, 0x00]
        );
        assert_eq!(
            TlsOidFilter::decode(filter.encode_to_vec().unwrap()).unwrap(),
            filter
        );
        assert_eq!(filter.summary(), "oid_filter oid_bytes=3 values_bytes=2");
        assert!(filter
            .inspection_fields()
            .contains(&("oid_filter_oid", "55 1d 25".to_string())));

        let empty_values = TlsOidFilter::new([0x55, 0x1d, 0x13], Vec::<u8>::new());
        let filters = TlsOidFilters::new([filter.clone(), empty_values.clone()]);
        assert_eq!(filters.len(), 2);
        assert_eq!(filters.filters(), &[filter.clone(), empty_values.clone()]);
        assert_eq!(filters.byte_lengths(), vec![8, 6]);
        assert_eq!(filters.byte_len().unwrap(), 14);
        assert_eq!(filters.encoded_len().unwrap(), 16);
        assert_eq!(
            filters.encode_to_vec().unwrap(),
            [
                0x00, 0x0e, 0x03, 0x55, 0x1d, 0x25, 0x00, 0x02, 0x30, 0x00, 0x03, 0x55, 0x1d, 0x13,
                0x00, 0x00
            ]
        );
        assert_eq!(
            TlsOidFilters::decode(filters.encode_to_vec().unwrap()).unwrap(),
            filters
        );
        assert_eq!(filters.summary(), "oid_filters count=2 bytes=14");
        assert!(filters
            .inspection_fields()
            .contains(&("oid_filters_lengths", "8,6".to_string())));

        let raw_filters = filters.to_raw_extension().unwrap();
        assert_eq!(raw_filters.extension_type(), TlsExtensionType::OID_FILTERS);
        assert_eq!(raw_filters.raw_type(), constants::TLS_EXTENSION_OID_FILTERS);
        assert_eq!(
            raw_filters.encode_to_vec().unwrap(),
            [
                0x00, 0x30, 0x00, 0x10, 0x00, 0x0e, 0x03, 0x55, 0x1d, 0x25, 0x00, 0x02, 0x30, 0x00,
                0x03, 0x55, 0x1d, 0x13, 0x00, 0x00
            ]
        );
        assert_eq!(raw_filters.as_oid_filters().unwrap(), filters);
        assert_eq!(TlsOidFilters::try_from(&raw_filters).unwrap(), filters);
        assert_eq!(
            TlsRawExtension::try_from(filters.clone()).unwrap(),
            raw_filters
        );
        assert_eq!(
            TlsRawExtension::oid_filters(filters.clone()).unwrap(),
            raw_filters
        );
        assert_eq!(
            TlsOidFilters::from_pairs([
                (&[0x55, 0x1d, 0x25][..], &[0x30, 0x00][..]),
                (&[0x55, 0x1d, 0x13][..], &[][..]),
            ]),
            filters
        );
        assert_eq!(
            TlsOidFilters::empty().encode_to_vec().unwrap(),
            [0x00, 0x00]
        );
    }

    #[test]
    fn tls_extension_certificate_authorities_preserves_explicit_bytes() {
        let authorities =
            TlsCertificateAuthorities::decode([0x00, 0x05, 0x00, 0x03, 0xff, 0x00, 0x7a]).unwrap();
        assert_eq!(authorities.raw_values(), vec![vec![0xff, 0x00, 0x7a]]);
        assert_eq!(
            authorities.encode_to_vec().unwrap(),
            [0x00, 0x05, 0x00, 0x03, 0xff, 0x00, 0x7a]
        );

        let mut built = TlsCertificateAuthorities::from_raws([&[0xde, 0xad][..]]);
        built.push([0xfa, 0xce, 0x00]);
        assert_eq!(built.byte_lengths(), vec![2, 3]);
        assert_eq!(
            built.clone().into_vec(),
            vec![
                TlsDistinguishedName::new([0xde, 0xad]),
                TlsDistinguishedName::new([0xfa, 0xce, 0x00])
            ]
        );
        assert_eq!(
            TlsDistinguishedName::new([0xde, 0xad]).clone().into_bytes(),
            vec![0xde, 0xad]
        );

        let filters =
            TlsOidFilters::decode([0x00, 0x08, 0x02, 0xff, 0x00, 0x00, 0x03, 0xaa, 0x00, 0xbb])
                .unwrap();
        assert_eq!(filters.byte_lengths(), vec![8]);
        assert_eq!(filters.filters()[0].oid(), &[0xff, 0x00]);
        assert_eq!(filters.filters()[0].values(), &[0xaa, 0x00, 0xbb]);
        assert_eq!(
            filters.encode_to_vec().unwrap(),
            [0x00, 0x08, 0x02, 0xff, 0x00, 0x00, 0x03, 0xaa, 0x00, 0xbb]
        );

        let mut built_filters = TlsOidFilters::empty();
        built_filters.push(([0x01], [0x02, 0x03]));
        assert_eq!(built_filters.filters()[0].oid(), &[0x01]);
        assert_eq!(built_filters.filters()[0].values(), &[0x02, 0x03]);
        assert_eq!(
            TlsOidFilter::new([0x01], [0x02, 0x03]).into_pair(),
            (vec![0x01], vec![0x02, 0x03])
        );
    }

    #[test]
    fn tls_extension_certificate_authorities_reports_structured_errors() {
        assert_eq!(
            TlsDistinguishedName::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.distinguished_name.length",
                TLS_DISTINGUISHED_NAME_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsDistinguishedName::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.distinguished_name.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsDistinguishedName::decode([0x00, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.distinguished_name", 4, 3)
        );
        assert_eq!(
            TlsDistinguishedName::decode([0x00, 0x01, 0xaa, 0xbb]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.distinguished_name.length",
                "length must match item body"
            )
        );
        assert_eq!(
            TlsDistinguishedName::new(Vec::<u8>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.distinguished_name.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsDistinguishedName::new(vec![0; TLS_DISTINGUISHED_NAME_MAX_LEN + 1])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.distinguished_name.length",
                "length must fit in two bytes"
            )
        );
        assert_eq!(
            TlsCertificateAuthorities::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.certificate_authorities.length",
                TLS_CERTIFICATE_AUTHORITIES_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsCertificateAuthorities::decode([0x00, 0x02, 0xaa, 0xbb]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.certificate_authorities.length",
                "length must be at least three bytes"
            )
        );
        assert_eq!(
            TlsCertificateAuthorities::decode([0x00, 0x04, 0x00, 0x03, 0xaa, 0xbb]).unwrap_err(),
            CrafterError::buffer_too_short("tls.distinguished_name", 5, 4)
        );
        assert_eq!(
            TlsCertificateAuthorities::decode([0x00, 0x03, 0x00, 0x00, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.distinguished_name.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsCertificateAuthorities::new(Vec::<TlsDistinguishedName>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.certificate_authorities.length",
                "length must be at least three bytes"
            )
        );
        assert_eq!(
            TlsCertificateAuthorities::new([TlsDistinguishedName::new(vec![
                0;
                TLS_DISTINGUISHED_NAME_MAX_LEN
            ])])
            .encode_to_vec()
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.certificate_authorities.length",
                "length must fit in two bytes"
            )
        );
        assert_eq!(
            TlsCertificateAuthorities::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be certificate_authorities"
            )
        );

        assert_eq!(
            TlsOidFilter::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.oid_filter.oid.length",
                TLS_OID_FILTER_OID_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsOidFilter::decode([0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.oid_filter.oid.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsOidFilter::decode([0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.oid_filter.oid", 3, 2)
        );
        assert_eq!(
            TlsOidFilter::decode([0x01, 0xaa, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.oid_filter.values.length", 4, 3)
        );
        assert_eq!(
            TlsOidFilter::decode([0x01, 0xaa, 0x00, 0x02, 0xbb]).unwrap_err(),
            CrafterError::buffer_too_short("tls.oid_filter.values", 6, 5)
        );
        assert_eq!(
            TlsOidFilter::decode([0x01, 0xaa, 0x00, 0x00, 0xcc]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.oid_filter.length",
                "length must match item body"
            )
        );
        assert_eq!(
            TlsOidFilter::new(Vec::<u8>::new(), Vec::<u8>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.oid_filter.oid.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsOidFilter::new(vec![0; TLS_OID_FILTER_OID_MAX_LEN + 1], Vec::<u8>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.oid_filter.oid.length",
                "length must fit in one byte"
            )
        );
        assert_eq!(
            TlsOidFilter::new([0xaa], vec![0; TLS_OID_FILTER_VALUES_MAX_LEN + 1])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.oid_filter.values.length",
                "length must fit in two bytes"
            )
        );
        assert_eq!(
            TlsOidFilters::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.oid_filters.length", TLS_OID_FILTERS_LENGTH_LEN, 0)
        );
        assert_eq!(
            TlsOidFilters::decode([0x00, 0x04, 0x01, 0xaa, 0x00, 0x02]).unwrap_err(),
            CrafterError::buffer_too_short("tls.oid_filter.values", 6, 4)
        );
        assert_eq!(
            TlsOidFilters::new([TlsOidFilter::new(
                [0xaa],
                vec![0; TLS_OID_FILTER_VALUES_MAX_LEN]
            )])
            .encode_to_vec()
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.oid_filters.length",
                "length must fit in two bytes"
            )
        );
        assert_eq!(
            TlsOidFilters::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, [])).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be oid_filters"
            )
        );
    }

    #[test]
    fn tls_extension_ec_point_formats_builders_encode_and_inspect() {
        assert_eq!(
            TlsExtensionType::ec_point_formats(),
            TlsExtensionType::EC_POINT_FORMATS
        );

        let uncompressed = TlsEcPointFormat::uncompressed();
        assert_eq!(uncompressed.raw(), TLS_EC_POINT_FORMAT_UNCOMPRESSED);
        assert_eq!(uncompressed.as_u8(), TLS_EC_POINT_FORMAT_UNCOMPRESSED);
        assert_eq!(uncompressed.to_be_bytes(), [0x00]);
        assert_eq!(uncompressed.encode_to_vec(), [0x00]);
        assert_eq!(TlsEcPointFormat::decode([0x00]).unwrap(), uncompressed);
        assert_eq!(uncompressed.name(), Some("uncompressed"));
        assert_eq!(uncompressed.status(), TlsCodepointStatus::DefaultEligible);
        assert!(uncompressed.is_uncompressed());
        assert!(uncompressed.is_default_eligible());
        assert_eq!(
            uncompressed.summary(),
            "uncompressed raw=0x00 status=default-eligible"
        );
        assert!(uncompressed
            .inspection_fields()
            .contains(&("ec_point_format", "uncompressed".to_string())));
        assert_eq!(uncompressed.to_string(), "uncompressed");
        assert_eq!(u8::from(uncompressed), 0);

        let compressed_prime = TlsEcPointFormat::ansi_x962_compressed_prime();
        assert_eq!(
            compressed_prime.raw(),
            TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME
        );
        assert_eq!(compressed_prime.name(), Some("ansiX962_compressed_prime"));
        assert_eq!(compressed_prime.status(), TlsCodepointStatus::PreserveOnly);
        assert!(compressed_prime.is_deprecated_compressed());
        assert_eq!(
            TlsEcPointFormat::ansi_x962_compressed_char2().raw(),
            TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2
        );

        let formats = TlsEcPointFormats::uncompressed_only();
        assert_eq!(formats.len(), 1);
        assert!(!formats.is_empty());
        assert!(formats.is_uncompressed_only());
        assert_eq!(formats.formats(), &[TlsEcPointFormat::UNCOMPRESSED]);
        assert_eq!(formats.raw_values(), vec![0x00]);
        assert_eq!(formats.labels(), vec!["uncompressed".to_string()]);
        assert_eq!(formats.byte_len().unwrap(), 1);
        assert_eq!(formats.encoded_len().unwrap(), 2);
        assert_eq!(formats.encode_to_vec().unwrap(), [0x01, 0x00]);
        assert_eq!(TlsEcPointFormats::decode([0x01, 0x00]).unwrap(), formats);
        assert_eq!(
            formats.summary(),
            "ec_point_formats count=1 bytes=1 values=uncompressed"
        );
        assert!(formats
            .inspection_fields()
            .contains(&("ec_point_formats_raw", "0x00".to_string())));
        assert!(formats
            .inspection_fields()
            .contains(&("ec_point_formats_uncompressed_only", "true".to_string())));

        let raw = formats.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::EC_POINT_FORMATS);
        assert_eq!(raw.raw_type(), constants::TLS_EXTENSION_EC_POINT_FORMATS);
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]
        );
        assert_eq!(raw.as_ec_point_formats().unwrap(), formats);
        assert_eq!(TlsEcPointFormats::try_from(&raw).unwrap(), formats);
        assert_eq!(TlsRawExtension::try_from(formats.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::ec_point_formats([TlsEcPointFormat::UNCOMPRESSED]).unwrap(),
            raw
        );
        assert_eq!(
            TlsRawExtension::ec_point_formats_uncompressed_only().unwrap(),
            raw
        );
    }

    #[test]
    fn tls_extension_ec_point_formats_preserves_unknown_and_explicit_values() {
        let decoded = TlsEcPointFormats::decode([0x04, 0x00, 0x01, 0x7a, 0xf8]).unwrap();
        assert_eq!(decoded.raw_values(), vec![0x00, 0x01, 0x7a, 0xf8]);
        assert_eq!(
            decoded.labels(),
            vec![
                "uncompressed".to_string(),
                "ansiX962_compressed_prime".to_string(),
                "unassigned ec point format 0x7a".to_string(),
                "private-use ec point format 0xf8".to_string(),
            ]
        );
        assert_eq!(
            decoded.encode_to_vec().unwrap(),
            [0x04, 0x00, 0x01, 0x7a, 0xf8]
        );
        assert_eq!(
            TlsEcPointFormats::from_raws([0x00, 0x01, 0x7a, 0xf8]),
            decoded
        );

        let mut built = TlsEcPointFormats::new([TlsEcPointFormat::UNCOMPRESSED]);
        built.push(TlsEcPointFormat::from_u8(0x7a));
        assert_eq!(built.raw_values(), vec![0x00, 0x7a]);
        assert_eq!(
            built.clone().into_vec(),
            vec![
                TlsEcPointFormat::UNCOMPRESSED,
                TlsEcPointFormat::from_u8(0x7a)
            ]
        );

        let unassigned = TlsEcPointFormat::from_u8(0x7a);
        assert_eq!(unassigned.status(), TlsCodepointStatus::Unassigned);
        assert_eq!(unassigned.label(), "unassigned ec point format 0x7a");
        assert_eq!(
            unassigned.summary(),
            "unassigned ec point format 0x7a raw=0x7a status=unassigned"
        );

        let private = TlsEcPointFormat::from_u8(0xf8);
        assert_eq!(private.status(), TlsCodepointStatus::PrivateUse);
        assert!(private.is_private_use());
        assert_eq!(private.label(), "private-use ec point format 0xf8");
        assert_eq!(
            TlsEcPointFormat::decode_prefix(&[0xf8, 0xaa]).unwrap(),
            (private, &[0xaa][..])
        );
    }

    #[test]
    fn tls_extension_ec_point_formats_reports_structured_errors() {
        assert_eq!(
            TlsEcPointFormat::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.ec_point_format", TLS_EC_POINT_FORMAT_LEN, 0)
        );
        assert_eq!(
            TlsEcPointFormats::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.ec_point_formats.length",
                TLS_EC_POINT_FORMATS_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsEcPointFormats::decode([0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.ec_point_formats.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsEcPointFormats::decode([0x02, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.ec_point_formats", 3, 2)
        );
        assert_eq!(
            TlsEcPointFormats::decode([0x01, 0x00, 0xbb]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.ec_point_formats.length",
                "length must match extension body"
            )
        );
        assert_eq!(
            TlsEcPointFormats::new(Vec::<TlsEcPointFormat>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.ec_point_formats.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsEcPointFormats::new(vec![TlsEcPointFormat::UNCOMPRESSED; u8::MAX as usize + 1])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.ec_point_formats.length",
                "length must fit in one byte"
            )
        );
        assert_eq!(
            TlsEcPointFormats::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be ec_point_formats"
            )
        );
    }

    #[test]
    fn tls_extension_cookie_padding_record_size_builders_encode_and_inspect() {
        assert_eq!(TlsExtensionType::cookie(), TlsExtensionType::COOKIE);
        assert_eq!(TlsExtensionType::padding(), TlsExtensionType::PADDING);
        assert_eq!(
            TlsExtensionType::record_size_limit(),
            TlsExtensionType::RECORD_SIZE_LIMIT
        );

        let cookie = TlsCookie::new([0xde, 0xad, 0xfa, 0xce]);
        assert_eq!(cookie.len(), 4);
        assert!(!cookie.is_empty());
        assert_eq!(cookie.bytes(), &[0xde, 0xad, 0xfa, 0xce]);
        assert_eq!(
            cookie.encode_to_vec().unwrap(),
            [0x00, 0x04, 0xde, 0xad, 0xfa, 0xce]
        );
        assert_eq!(
            TlsCookie::decode(cookie.encode_to_vec().unwrap()).unwrap(),
            cookie
        );
        assert_eq!(cookie.summary(), "cookie bytes=4");
        assert!(cookie
            .inspection_fields()
            .contains(&("cookie", "de ad fa ce".to_string())));

        let raw_cookie = cookie.to_raw_extension().unwrap();
        assert_eq!(raw_cookie.extension_type(), TlsExtensionType::COOKIE);
        assert_eq!(raw_cookie.raw_type(), constants::TLS_EXTENSION_COOKIE);
        assert_eq!(
            raw_cookie.encode_to_vec().unwrap(),
            [0x00, 0x2c, 0x00, 0x06, 0x00, 0x04, 0xde, 0xad, 0xfa, 0xce]
        );
        assert_eq!(raw_cookie.as_cookie().unwrap(), cookie);
        assert_eq!(TlsCookie::try_from(&raw_cookie).unwrap(), cookie);
        assert_eq!(
            TlsRawExtension::try_from(cookie.clone()).unwrap(),
            raw_cookie
        );
        assert_eq!(
            TlsRawExtension::cookie([0xde, 0xad, 0xfa, 0xce]).unwrap(),
            raw_cookie
        );

        let padding = TlsPadding::zeros(6);
        assert_eq!(padding.len(), 6);
        assert!(padding.is_zero_filled());
        assert_eq!(padding.encode_to_vec().unwrap(), vec![0; 6]);
        assert_eq!(padding.summary(), "padding bytes=6 zero_filled=true");
        assert!(padding
            .inspection_fields()
            .contains(&("padding_zero_filled", "true".to_string())));

        let raw_padding = padding.to_raw_extension().unwrap();
        assert_eq!(raw_padding.extension_type(), TlsExtensionType::PADDING);
        assert_eq!(raw_padding.raw_type(), constants::TLS_EXTENSION_PADDING);
        assert_eq!(
            raw_padding.encode_to_vec().unwrap(),
            [0x00, 0x15, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(raw_padding.as_padding().unwrap(), padding);
        assert_eq!(TlsPadding::try_from(&raw_padding).unwrap(), padding);
        assert_eq!(
            TlsRawExtension::try_from(padding.clone()).unwrap(),
            raw_padding
        );
        assert_eq!(TlsRawExtension::padding(6).unwrap(), raw_padding);

        let record_size_limit = TlsRecordSizeLimit::new(512);
        assert_eq!(record_size_limit.limit(), 512);
        assert_eq!(record_size_limit.as_u16(), 512);
        assert!(record_size_limit.is_valid());
        assert!(record_size_limit.is_valid_for_tls_1_2());
        assert!(record_size_limit.is_valid_for_tls_1_3());
        record_size_limit.validate().unwrap();
        assert_eq!(record_size_limit.encoded_len(), TLS_RECORD_SIZE_LIMIT_LEN);
        assert_eq!(record_size_limit.encode_to_vec(), [0x02, 0x00]);
        assert_eq!(
            TlsRecordSizeLimit::decode([0x02, 0x00]).unwrap(),
            record_size_limit
        );
        assert_eq!(
            record_size_limit.summary(),
            "record_size_limit limit=512 valid=true"
        );
        assert!(record_size_limit
            .inspection_fields()
            .contains(&("record_size_limit", "512".to_string())));

        let raw_record_size_limit = record_size_limit.to_raw_extension().unwrap();
        assert_eq!(
            raw_record_size_limit.extension_type(),
            TlsExtensionType::RECORD_SIZE_LIMIT
        );
        assert_eq!(
            raw_record_size_limit.raw_type(),
            constants::TLS_EXTENSION_RECORD_SIZE_LIMIT
        );
        assert_eq!(
            raw_record_size_limit.encode_to_vec().unwrap(),
            [0x00, 0x1c, 0x00, 0x02, 0x02, 0x00]
        );
        assert_eq!(
            raw_record_size_limit.as_record_size_limit().unwrap(),
            record_size_limit
        );
        assert_eq!(
            TlsRecordSizeLimit::try_from(&raw_record_size_limit).unwrap(),
            record_size_limit
        );
        assert_eq!(
            TlsRawExtension::try_from(record_size_limit).unwrap(),
            raw_record_size_limit
        );
        assert_eq!(
            TlsRawExtension::record_size_limit(512).unwrap(),
            raw_record_size_limit
        );
    }

    #[test]
    fn tls_extension_cookie_padding_record_size_preserves_explicit_bytes_and_values() {
        let cookie = TlsCookie::decode([0x00, 0x03, 0x00, 0xff, 0x7a]).unwrap();
        assert_eq!(cookie.bytes(), &[0x00, 0xff, 0x7a]);
        assert_eq!(
            cookie.encode_to_vec().unwrap(),
            [0x00, 0x03, 0x00, 0xff, 0x7a]
        );
        assert_eq!(cookie.clone().into_bytes(), vec![0x00, 0xff, 0x7a]);

        let padding = TlsPadding::new([0xaa, 0x00, 0xbb]);
        assert!(!padding.is_zero_filled());
        assert_eq!(padding.bytes(), &[0xaa, 0x00, 0xbb]);
        assert_eq!(padding.encode_to_vec().unwrap(), [0xaa, 0x00, 0xbb]);
        assert_eq!(TlsPadding::decode([0xaa, 0x00, 0xbb]).unwrap(), padding);
        assert_eq!(
            TlsRawExtension::padding_bytes([0xaa, 0x00, 0xbb])
                .unwrap()
                .as_padding()
                .unwrap()
                .bytes(),
            &[0xaa, 0x00, 0xbb]
        );

        let malformed = TlsRecordSizeLimit::new(TLS_RECORD_SIZE_LIMIT_MIN - 1);
        assert_eq!(malformed.limit(), 63);
        assert!(!malformed.is_valid());
        assert_eq!(malformed.encode_to_vec(), [0x00, 0x3f]);
        assert_eq!(TlsRecordSizeLimit::decode([0x00, 0x3f]).unwrap(), malformed);
        assert_eq!(
            malformed.validate().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.record_size_limit",
                "limit must be at least 64 bytes"
            )
        );
        assert_eq!(
            malformed
                .to_raw_extension()
                .unwrap()
                .encode_to_vec()
                .unwrap(),
            [0x00, 0x1c, 0x00, 0x02, 0x00, 0x3f]
        );

        let future = TlsRecordSizeLimit::new(TLS_RECORD_SIZE_LIMIT_TLS13_MAX + 1);
        assert!(future.is_valid());
        assert!(!future.is_valid_for_tls_1_3());
        assert_eq!(
            future.validate_for_tls_1_3().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.record_size_limit",
                "limit exceeds protocol-defined maximum"
            )
        );
        assert_eq!(
            TlsRecordSizeLimit::tls_1_2_max().limit(),
            TLS_RECORD_SIZE_LIMIT_TLS12_MAX
        );
        assert_eq!(
            TlsRecordSizeLimit::tls_1_3_max().limit(),
            TLS_RECORD_SIZE_LIMIT_TLS13_MAX
        );
    }

    #[test]
    fn tls_extension_cookie_padding_record_size_reports_structured_errors() {
        assert_eq!(
            TlsCookie::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.cookie.length", TLS_COOKIE_LENGTH_LEN, 0)
        );
        assert_eq!(
            TlsCookie::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.cookie.length", TLS_COOKIE_LENGTH_LEN, 1)
        );
        assert_eq!(
            TlsCookie::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.cookie.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsCookie::decode([0x00, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.cookie", 4, 3)
        );
        assert_eq!(
            TlsCookie::decode([0x00, 0x01, 0xaa, 0xbb]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.cookie.length",
                "length must match extension body"
            )
        );
        assert_eq!(
            TlsCookie::new(Vec::<u8>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.cookie.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsCookie::new(vec![0; TLS_COOKIE_MAX_LEN + 1])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value("tls.cookie.length", "length must fit in two bytes")
        );
        assert_eq!(
            TlsCookie::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, [])).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be cookie"
            )
        );

        assert_eq!(
            TlsPadding::new(vec![0; u16::MAX as usize + 1])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value("tls.padding.length", "length must fit in two bytes")
        );
        assert_eq!(
            TlsPadding::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, [])).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be padding"
            )
        );

        assert_eq!(
            TlsRecordSizeLimit::decode([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.record_size_limit", TLS_RECORD_SIZE_LIMIT_LEN, 0)
        );
        assert_eq!(
            TlsRecordSizeLimit::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.record_size_limit", TLS_RECORD_SIZE_LIMIT_LEN, 1)
        );
        assert_eq!(
            TlsRecordSizeLimit::decode([0x00, 0x40, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.record_size_limit.length",
                "length must be exactly two bytes"
            )
        );
        assert_eq!(
            TlsRecordSizeLimit::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be record_size_limit"
            )
        );
    }

    #[test]
    fn tls_extension_sni_host_name_builder_encodes_rfc6066_vector() {
        let name = TlsServerName::host_name("example.com");
        assert_eq!(name.name_type(), TlsServerNameType::HOST_NAME);
        assert_eq!(name.host_name_value(), Some("example.com"));
        assert_eq!(name.body(), b"example.com");
        assert_eq!(
            name.encode_to_vec().unwrap(),
            [0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',]
        );
        assert_eq!(
            name.summary(),
            "server_name type=host_name host_name=example.com bytes=11"
        );
        assert!(name
            .inspection_fields()
            .contains(&("server_name_host_name", "example.com".to_string())));

        let names = TlsServerNameList::from_host_name("example.com");
        assert_eq!(names.len(), 1);
        assert!(!names.is_empty());
        assert_eq!(names.host_names(), vec!["example.com"]);
        assert_eq!(names.byte_len().unwrap(), 14);
        assert_eq!(names.encoded_len().unwrap(), 16);
        assert_eq!(
            names.encode_to_vec().unwrap(),
            [
                0x00, 0x0e, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
                b'o', b'm',
            ]
        );

        let encoded_with_tail = [names.encode_to_vec().unwrap(), vec![0xaa]].concat();
        let (decoded, tail) = TlsServerNameList::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, names);
        assert_eq!(decoded.as_slice(), decoded.names());
        assert_eq!(
            decoded.summary(),
            "server_name list count=1 bytes=14 values=host_name:example.com"
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("server_name_host_names", "example.com".to_string())));
        assert_eq!(
            decoded.clone().into_vec(),
            vec![TlsServerName::host_name("example.com")]
        );
    }

    #[test]
    fn tls_extension_sni_preserves_unknown_name_types() {
        let name_type = TlsServerNameType::from_u8(0x7b);
        assert_eq!(name_type.raw(), 0x7b);
        assert_eq!(name_type.as_u8(), 0x7b);
        assert_eq!(name_type.name(), None);
        assert_eq!(name_type.label(), "unknown server name type 0x7b");
        assert_eq!(
            name_type.summary(),
            "unknown server name type 0x7b raw=0x7b"
        );
        assert_eq!(u8::from(name_type), 0x7b);
        assert_eq!(TlsServerNameType::from(0x7b).to_string(), name_type.label());

        let name = TlsServerName::unknown(name_type, [0xde, 0xad]);
        assert_eq!(name.name_type(), name_type);
        assert_eq!(name.body(), &[0xde, 0xad]);
        assert_eq!(name.host_name_value(), None);
        assert_eq!(
            name.encode_to_vec().unwrap(),
            [0x7b, 0x00, 0x02, 0xde, 0xad]
        );

        let list = TlsServerNameList::new(vec![name.clone()]);
        assert_eq!(
            list.encode_to_vec().unwrap(),
            [0x00, 0x05, 0x7b, 0x00, 0x02, 0xde, 0xad]
        );
        assert_eq!(
            TlsServerNameList::decode(list.encode_to_vec().unwrap()).unwrap(),
            list
        );
        assert_eq!(
            name.summary(),
            "server_name type=unknown server name type 0x7b raw=0x7b body_bytes=2"
        );
    }

    #[test]
    fn tls_extension_sni_converts_to_and_from_raw_extension() {
        let names = TlsServerNameList::from_host_name("www.example.test");
        let raw = names.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::SERVER_NAME);
        assert_eq!(raw.raw_type(), constants::TLS_EXTENSION_SERVER_NAME);
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [
                0x00, 0x00, 0x00, 0x15, 0x00, 0x13, 0x00, 0x00, 0x10, b'w', b'w', b'w', b'.', b'e',
                b'x', b'a', b'm', b'p', b'l', b'e', b'.', b't', b'e', b's', b't',
            ]
        );

        assert_eq!(raw.as_server_name_list().unwrap(), names);
        assert_eq!(TlsServerNameList::try_from(&raw).unwrap(), names);
        assert_eq!(TlsRawExtension::try_from(names.clone()).unwrap(), raw);
        assert_eq!(TlsRawExtension::server_name(names.clone()).unwrap(), raw);

        assert_eq!(
            TlsServerNameList::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be server_name"
            )
        );
    }

    #[test]
    fn tls_extension_sni_reports_structured_decode_errors() {
        assert_eq!(
            TlsServerName::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.server_name.name_type",
                TLS_SERVER_NAME_TYPE_LEN,
                0
            )
        );
        assert_eq!(
            TlsServerName::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.server_name.name.length",
                TLS_SERVER_NAME_HEADER_LEN,
                1
            )
        );
        assert_eq!(
            TlsServerName::decode([0x00, 0x00, 0x02, b'e']).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.server_name.name",
                TLS_SERVER_NAME_HEADER_LEN + 2,
                4
            )
        );
        assert_eq!(
            TlsServerName::decode([0x00, 0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name.host_name.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsServerName::host_name_bytes([0xff])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name.host_name",
                "host_name must be ASCII"
            )
        );
        assert_eq!(
            TlsServerName::host_name("example.com.")
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name.host_name",
                "host_name must not include trailing dot"
            )
        );
        assert_eq!(
            TlsServerName::host_name_bytes(vec![b'a'; u16::MAX as usize + 1])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name.name.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_sni_reports_structured_list_errors() {
        assert_eq!(
            TlsServerNameList::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.server_name_list.length",
                TLS_SERVER_NAME_LIST_LENGTH_LEN,
                1
            )
        );
        assert_eq!(
            TlsServerNameList::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name_list.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsServerNameList::decode([0x00, 0x04, 0x00, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.server_name_list", 6, 4)
        );

        let duplicate = TlsServerNameList::new(vec![
            TlsServerName::host_name("example.com"),
            TlsServerName::host_name("www.example.test"),
        ]);
        assert_eq!(
            duplicate.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name.name_type",
                "duplicate name_type in server_name list"
            )
        );

        let duplicate_bytes = [
            0x00, 0x21, 0x00, 0x00, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x00, 0x00, 0x10, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b't', b'e', b's', b't',
        ];
        assert_eq!(
            TlsServerNameList::decode(duplicate_bytes).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name.name_type",
                "duplicate name_type in server_name list"
            )
        );

        let oversized = TlsServerNameList::new(vec![
            TlsServerName::unknown(0x01, vec![0; u16::MAX as usize]),
            TlsServerName::unknown(0x02, [0x00]),
        ]);
        assert_eq!(
            oversized.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_name_list.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_alpn_protocol_builders_encode_rfc7301_vector() {
        let h2 = TlsAlpnProtocol::h2();
        assert_eq!(h2.bytes(), b"h2");
        assert_eq!(h2.as_bytes(), b"h2");
        assert_eq!(h2.encode_to_vec().unwrap(), [0x02, b'h', b'2']);
        assert_eq!(h2.clone().into_bytes(), b"h2".to_vec());
        assert_eq!(h2.summary(), "alpn protocol=h2 bytes=2");
        assert!(h2
            .inspection_fields()
            .contains(&("alpn_protocol", "h2".to_string())));

        let http_1_1 = TlsAlpnProtocol::http_1_1();
        assert_eq!(http_1_1.bytes(), b"http/1.1");
        assert_eq!(
            http_1_1.encode_to_vec().unwrap(),
            [0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );

        let protocols = TlsAlpnProtocols::h2_then_http_1_1();
        assert_eq!(protocols.len(), 2);
        assert!(!protocols.is_empty());
        assert_eq!(
            protocols.protocol_bytes(),
            vec![b"h2".as_slice(), b"http/1.1".as_slice()]
        );
        assert_eq!(protocols.byte_len().unwrap(), 12);
        assert_eq!(protocols.encoded_len().unwrap(), 14);
        assert_eq!(
            protocols.encode_to_vec().unwrap(),
            [0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',]
        );

        let encoded_with_tail = [protocols.encode_to_vec().unwrap(), vec![0xaa]].concat();
        let (decoded, tail) = TlsAlpnProtocols::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, protocols);
        assert_eq!(decoded.as_slice(), decoded.protocols());
        assert_eq!(decoded.clone().into_vec(), protocols.clone().into_vec());
        assert_eq!(
            decoded.summary(),
            "alpn protocols count=2 bytes=12 values=h2,http/1.1"
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("alpn_protocols", "h2,http/1.1".to_string())));

        let mut pushed = TlsAlpnProtocols::h2();
        pushed.push("http/1.1");
        assert_eq!(pushed, protocols);
        assert_eq!(
            TlsAlpnProtocols::http_1_1().protocol_bytes(),
            vec![b"http/1.1".as_slice()]
        );
        assert_eq!(
            TlsAlpnProtocols::from_protocol("h2").protocol_bytes(),
            vec![b"h2".as_slice()]
        );
    }

    #[test]
    fn tls_extension_alpn_converts_to_and_from_raw_extension() {
        let protocols = TlsAlpnProtocols::h2_then_http_1_1();
        let raw = protocols.to_raw_extension().unwrap();
        assert_eq!(
            raw.extension_type(),
            TlsExtensionType::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        );
        assert_eq!(
            raw.raw_type(),
            constants::TLS_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION
        );
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [
                0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p',
                b'/', b'1', b'.', b'1',
            ]
        );

        assert_eq!(raw.as_alpn_protocols().unwrap(), protocols);
        assert_eq!(TlsAlpnProtocols::try_from(&raw).unwrap(), protocols);
        assert_eq!(TlsRawExtension::try_from(protocols.clone()).unwrap(), raw);
        assert_eq!(TlsRawExtension::alpn(protocols.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::application_layer_protocol_negotiation(protocols).unwrap(),
            raw
        );

        assert_eq!(
            TlsAlpnProtocols::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be application_layer_protocol_negotiation"
            )
        );
    }

    #[test]
    fn tls_extension_alpn_preserves_opaque_protocol_bytes() {
        let protocol = TlsAlpnProtocol::new([0xff, 0x00, 0x80]);
        assert_eq!(protocol.bytes(), &[0xff, 0x00, 0x80]);
        assert_eq!(
            TlsAlpnProtocol::decode(protocol.encode_to_vec().unwrap()).unwrap(),
            protocol
        );

        let protocols = TlsAlpnProtocols::new([protocol.clone()]);
        let decoded = TlsAlpnProtocols::decode(protocols.encode_to_vec().unwrap()).unwrap();
        assert_eq!(decoded.protocols()[0].bytes(), &[0xff, 0x00, 0x80]);
    }

    #[test]
    fn tls_extension_alpn_reports_structured_decode_errors() {
        assert_eq!(
            TlsAlpnProtocol::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.alpn.protocol_name.length",
                TLS_ALPN_PROTOCOL_NAME_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsAlpnProtocol::decode([0x03, b'h']).unwrap_err(),
            CrafterError::buffer_too_short("tls.alpn.protocol_name", 4, 2)
        );
        assert_eq!(
            TlsAlpnProtocol::decode([0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsAlpnProtocols::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.alpn.protocol_name_list.length",
                TLS_ALPN_PROTOCOL_NAME_LIST_LENGTH_LEN,
                1
            )
        );
        assert_eq!(
            TlsAlpnProtocols::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name_list.length",
                "length must be at least two bytes"
            )
        );
        assert_eq!(
            TlsAlpnProtocols::decode([0x00, 0x01, 0x01]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name_list.length",
                "length must be at least two bytes"
            )
        );
        assert_eq!(
            TlsAlpnProtocols::decode([0x00, 0x03, 0x02, b'h']).unwrap_err(),
            CrafterError::buffer_too_short("tls.alpn.protocol_name_list", 5, 4)
        );
        assert_eq!(
            TlsAlpnProtocols::decode([0x00, 0x02, 0x00, b'h']).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name.length",
                "length must be at least one byte"
            )
        );
    }

    #[test]
    fn tls_extension_alpn_reports_structured_encode_errors() {
        assert_eq!(
            TlsAlpnProtocol::new(Vec::<u8>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsAlpnProtocol::new(vec![0; u8::MAX as usize + 1])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name.length",
                "length must fit in one byte"
            )
        );
        assert_eq!(
            TlsAlpnProtocols::new(Vec::<TlsAlpnProtocol>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name_list.length",
                "length must be at least two bytes"
            )
        );

        let oversized =
            TlsAlpnProtocols::new(vec![
                TlsAlpnProtocol::new(vec![0xaa; u8::MAX as usize]);
                258
            ]);
        assert_eq!(
            oversized.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.alpn.protocol_name_list.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_supported_groups_builders_encode_rfc8446_vector() {
        // RFC 8446 Section 4.2.7 defines NamedGroupList as NamedGroup<2..2^16-1>.
        let groups = TlsSupportedGroups::from_groups(vec![
            TlsNamedGroup::X25519,
            TlsNamedGroup::SECP256R1,
            TlsNamedGroup::FFDHE2048,
        ]);
        assert_eq!(groups.len(), 3);
        assert!(!groups.is_empty());
        assert_eq!(
            groups.groups(),
            &[
                TlsNamedGroup::X25519,
                TlsNamedGroup::SECP256R1,
                TlsNamedGroup::FFDHE2048,
            ]
        );
        assert_eq!(groups.raw_values(), vec![0x001d, 0x0017, 0x0100]);
        assert_eq!(groups.byte_len().unwrap(), 6);
        assert_eq!(groups.encoded_len().unwrap(), 8);
        assert_eq!(
            groups.encode_to_vec().unwrap(),
            [0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x01, 0x00]
        );

        let encoded_with_tail = [groups.encode_to_vec().unwrap(), vec![0xaa]].concat();
        let (decoded, tail) = TlsSupportedGroups::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, groups);
        assert_eq!(decoded.as_named_group_list(), decoded.named_group_list());
        assert_eq!(
            decoded.summary(),
            "supported_groups count=3 bytes=6 values=x25519,secp256r1,ffdhe2048"
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("supported_groups_raw", "0x001d,0x0017,0x0100".to_string())));
        assert_eq!(
            decoded.clone().into_vec(),
            vec![
                TlsNamedGroup::X25519,
                TlsNamedGroup::SECP256R1,
                TlsNamedGroup::FFDHE2048,
            ]
        );
        assert_eq!(
            decoded.into_named_group_list(),
            groups.named_group_list().clone()
        );

        let mut pushed = TlsSupportedGroups::from_groups(vec![TlsNamedGroup::X25519]);
        pushed.push(TlsNamedGroup::SECP256R1);
        assert_eq!(pushed.raw_values(), vec![0x001d, 0x0017]);
        assert_eq!(
            TlsSupportedGroups::from_raws([0x001d, 0xbeef]).raw_values(),
            vec![0x001d, 0xbeef]
        );
        assert_eq!(
            TlsSupportedGroups::from([TlsNamedGroup::X25519]).raw_values(),
            vec![0x001d]
        );
        assert_eq!(
            TlsSupportedGroups::new(TlsNamedGroupList::from_raws([0x001d])).raw_values(),
            vec![0x001d]
        );
    }

    #[test]
    fn tls_extension_supported_groups_converts_to_and_from_raw_extension() {
        let groups =
            TlsSupportedGroups::from_groups(vec![TlsNamedGroup::X25519, TlsNamedGroup::SECP256R1]);
        let raw = groups.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::SUPPORTED_GROUPS);
        assert_eq!(raw.raw_type(), constants::TLS_EXTENSION_SUPPORTED_GROUPS);
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]
        );

        assert_eq!(raw.as_supported_groups().unwrap(), groups);
        assert_eq!(TlsSupportedGroups::try_from(&raw).unwrap(), groups);
        assert_eq!(TlsRawExtension::try_from(groups.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::supported_groups(groups.clone()).unwrap(),
            raw
        );

        assert_eq!(
            TlsSupportedGroups::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be supported_groups"
            )
        );
    }

    #[test]
    fn tls_extension_supported_groups_preserves_unknown_raw_groups() {
        let groups = TlsSupportedGroups::from_raws([0x0a0a, 0xfe00, 0xbeef]);
        assert_eq!(
            groups.encode_to_vec().unwrap(),
            [0x00, 0x06, 0x0a, 0x0a, 0xfe, 0x00, 0xbe, 0xef]
        );

        let decoded =
            TlsSupportedGroups::decode([0x00, 0x06, 0x0a, 0x0a, 0xfe, 0x00, 0xbe, 0xef]).unwrap();
        assert_eq!(decoded, groups);
        assert_eq!(decoded.raw_values(), vec![0x0a0a, 0xfe00, 0xbeef]);
        assert_eq!(
            decoded.labels(),
            vec![
                "reserved grease named group 0x0a0a".to_string(),
                "private-use named group 0xfe00".to_string(),
                "unknown named group 0xbeef".to_string(),
            ]
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("supported_groups_raw", "0x0a0a,0xfe00,0xbeef".to_string())));
    }

    #[test]
    fn tls_extension_supported_groups_reports_structured_decode_errors() {
        assert_eq!(
            TlsSupportedGroups::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.supported_groups.length",
                TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsSupportedGroups::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.supported_groups.length",
                TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN,
                1
            )
        );
        assert_eq!(
            TlsSupportedGroups::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_groups.length",
                "length must be at least two bytes"
            )
        );
        assert_eq!(
            TlsSupportedGroups::decode([0x00, 0x03, 0x00, 0x1d, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_groups.length",
                "length must be a multiple of two bytes"
            )
        );
        assert_eq!(
            TlsSupportedGroups::decode([0x00, 0x04, 0x00, 0x1d]).unwrap_err(),
            CrafterError::buffer_too_short("tls.supported_groups", 6, 4)
        );
        assert_eq!(
            TlsSupportedGroups::decode([0x00, 0x02, 0x00, 0x1d, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_groups.length",
                "length must match extension body"
            )
        );
        assert_eq!(
            TlsSupportedGroups::from_raw_extension(&TlsRawExtension::new(
                TlsExtensionType::SUPPORTED_GROUPS,
                Vec::<u8>::new(),
            ))
            .unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.supported_groups.length",
                TLS_SUPPORTED_GROUPS_LIST_LENGTH_LEN,
                0
            )
        );
    }

    #[test]
    fn tls_extension_supported_groups_reports_structured_encode_errors() {
        assert_eq!(
            TlsSupportedGroups::default().encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_groups.length",
                "length must be at least two bytes"
            )
        );

        let oversized = TlsSupportedGroups::from_groups(vec![TlsNamedGroup::X25519; 32768]);
        assert_eq!(
            oversized.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_groups.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_signature_algorithms_builders_encode_rfc8446_vector() {
        // RFC 8446 Section 4.2.3 defines SignatureSchemeList as SignatureScheme<2..2^16-2>.
        let algorithms = TlsSignatureAlgorithms::from_schemes(vec![
            TlsSignatureScheme::ED25519,
            TlsSignatureScheme::RSA_PSS_RSAE_SHA256,
            TlsSignatureScheme::ECDSA_SECP256R1_SHA256,
        ]);
        assert_eq!(algorithms.len(), 3);
        assert!(!algorithms.is_empty());
        assert_eq!(
            algorithms.schemes(),
            &[
                TlsSignatureScheme::ED25519,
                TlsSignatureScheme::RSA_PSS_RSAE_SHA256,
                TlsSignatureScheme::ECDSA_SECP256R1_SHA256,
            ]
        );
        assert_eq!(algorithms.raw_values(), vec![0x0807, 0x0804, 0x0403]);
        assert_eq!(algorithms.byte_len().unwrap(), 6);
        assert_eq!(algorithms.encoded_len().unwrap(), 8);
        assert_eq!(
            algorithms.encode_to_vec().unwrap(),
            [0x00, 0x06, 0x08, 0x07, 0x08, 0x04, 0x04, 0x03]
        );

        let encoded_with_tail = [algorithms.encode_to_vec().unwrap(), vec![0xaa]].concat();
        let (decoded, tail) = TlsSignatureAlgorithms::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, algorithms);
        assert_eq!(
            decoded.as_signature_scheme_list(),
            decoded.signature_scheme_list()
        );
        assert_eq!(
            decoded.summary(),
            "signature_algorithms count=3 bytes=6 values=ed25519,rsa_pss_rsae_sha256,ecdsa_secp256r1_sha256"
        );
        assert!(decoded.inspection_fields().contains(&(
            "signature_algorithms_raw",
            "0x0807,0x0804,0x0403".to_string()
        )));
        assert_eq!(
            decoded.clone().into_vec(),
            vec![
                TlsSignatureScheme::ED25519,
                TlsSignatureScheme::RSA_PSS_RSAE_SHA256,
                TlsSignatureScheme::ECDSA_SECP256R1_SHA256,
            ]
        );
        assert_eq!(
            decoded.into_signature_scheme_list(),
            algorithms.signature_scheme_list().clone()
        );

        let mut pushed = TlsSignatureAlgorithms::from_schemes(vec![TlsSignatureScheme::ED25519]);
        pushed.push(TlsSignatureScheme::RSA_PSS_RSAE_SHA256);
        assert_eq!(pushed.raw_values(), vec![0x0807, 0x0804]);
        assert_eq!(
            TlsSignatureAlgorithms::from_raws([0x0807, 0xfe00]).raw_values(),
            vec![0x0807, 0xfe00]
        );
        assert_eq!(
            TlsSignatureAlgorithms::from([TlsSignatureScheme::ED25519]).raw_values(),
            vec![0x0807]
        );
        assert_eq!(
            TlsSignatureAlgorithms::new(TlsSignatureSchemeList::from_raws([0x0807])).raw_values(),
            vec![0x0807]
        );
    }

    #[test]
    fn tls_extension_signature_algorithms_cert_builders_encode_rfc8446_vector() {
        let cert = TlsSignatureAlgorithmsCert::from_schemes(vec![
            TlsSignatureScheme::RSA_PKCS1_SHA384,
            TlsSignatureScheme::ECDSA_SECP384R1_SHA384,
        ]);
        assert_eq!(cert.len(), 2);
        assert!(!cert.is_empty());
        assert_eq!(
            cert.schemes(),
            &[
                TlsSignatureScheme::RSA_PKCS1_SHA384,
                TlsSignatureScheme::ECDSA_SECP384R1_SHA384,
            ]
        );
        assert_eq!(cert.raw_values(), vec![0x0501, 0x0503]);
        assert_eq!(cert.byte_len().unwrap(), 4);
        assert_eq!(cert.encoded_len().unwrap(), 6);
        assert_eq!(
            cert.encode_to_vec().unwrap(),
            [0x00, 0x04, 0x05, 0x01, 0x05, 0x03]
        );

        let encoded_with_tail = [cert.encode_to_vec().unwrap(), vec![0xaa]].concat();
        let (decoded, tail) =
            TlsSignatureAlgorithmsCert::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, cert);
        assert_eq!(
            decoded.as_signature_scheme_list(),
            decoded.signature_scheme_list()
        );
        assert_eq!(
            decoded.summary(),
            "signature_algorithms_cert count=2 bytes=4 values=rsa_pkcs1_sha384,ecdsa_secp384r1_sha384"
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("signature_algorithms_cert_raw", "0x0501,0x0503".to_string())));
        assert_eq!(
            decoded.clone().into_vec(),
            vec![
                TlsSignatureScheme::RSA_PKCS1_SHA384,
                TlsSignatureScheme::ECDSA_SECP384R1_SHA384,
            ]
        );
        assert_eq!(
            decoded.into_signature_scheme_list(),
            cert.signature_scheme_list().clone()
        );

        let mut pushed =
            TlsSignatureAlgorithmsCert::from_schemes(vec![TlsSignatureScheme::RSA_PKCS1_SHA384]);
        pushed.push(TlsSignatureScheme::ECDSA_SECP384R1_SHA384);
        assert_eq!(pushed.raw_values(), vec![0x0501, 0x0503]);
        assert_eq!(
            TlsSignatureAlgorithmsCert::from_raws([0x0501, 0xfe00]).raw_values(),
            vec![0x0501, 0xfe00]
        );
        assert_eq!(
            TlsSignatureAlgorithmsCert::from([TlsSignatureScheme::RSA_PKCS1_SHA384]).raw_values(),
            vec![0x0501]
        );
    }

    #[test]
    fn tls_extension_signature_algorithms_converts_to_and_from_raw_extensions() {
        let algorithms = TlsSignatureAlgorithms::from_schemes(vec![
            TlsSignatureScheme::ED25519,
            TlsSignatureScheme::RSA_PSS_RSAE_SHA256,
        ]);
        let raw = algorithms.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::SIGNATURE_ALGORITHMS);
        assert_eq!(
            raw.raw_type(),
            constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS
        );
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x08, 0x07, 0x08, 0x04]
        );

        assert_eq!(raw.as_signature_algorithms().unwrap(), algorithms);
        assert_eq!(TlsSignatureAlgorithms::try_from(&raw).unwrap(), algorithms);
        assert_eq!(TlsRawExtension::try_from(algorithms.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::signature_algorithms(algorithms.clone()).unwrap(),
            raw
        );
        assert_eq!(
            TlsRawExtension::decode(raw.encode_to_vec().unwrap())
                .unwrap()
                .as_signature_algorithms()
                .unwrap(),
            algorithms
        );

        let cert = TlsSignatureAlgorithmsCert::from_schemes(vec![
            TlsSignatureScheme::RSA_PKCS1_SHA384,
            TlsSignatureScheme::ECDSA_SECP384R1_SHA384,
        ]);
        let raw = cert.to_raw_extension().unwrap();
        assert_eq!(
            raw.extension_type(),
            TlsExtensionType::SIGNATURE_ALGORITHMS_CERT
        );
        assert_eq!(
            raw.raw_type(),
            constants::TLS_EXTENSION_SIGNATURE_ALGORITHMS_CERT
        );
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x32, 0x00, 0x06, 0x00, 0x04, 0x05, 0x01, 0x05, 0x03]
        );

        assert_eq!(raw.as_signature_algorithms_cert().unwrap(), cert);
        assert_eq!(TlsSignatureAlgorithmsCert::try_from(&raw).unwrap(), cert);
        assert_eq!(TlsRawExtension::try_from(cert.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::signature_algorithms_cert(cert.clone()).unwrap(),
            raw
        );

        assert_eq!(
            TlsSignatureAlgorithms::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be signature_algorithms"
            )
        );
        assert_eq!(
            TlsSignatureAlgorithmsCert::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be signature_algorithms_cert"
            )
        );
    }

    #[test]
    fn tls_extension_signature_algorithms_preserves_unknown_raw_schemes() {
        let algorithms = TlsSignatureAlgorithms::from_raws([0x0a0a, 0xfe00, 0xbeef]);
        assert_eq!(
            algorithms.encode_to_vec().unwrap(),
            [0x00, 0x06, 0x0a, 0x0a, 0xfe, 0x00, 0xbe, 0xef]
        );

        let decoded =
            TlsSignatureAlgorithms::decode([0x00, 0x06, 0x0a, 0x0a, 0xfe, 0x00, 0xbe, 0xef])
                .unwrap();
        assert_eq!(decoded, algorithms);
        assert_eq!(decoded.raw_values(), vec![0x0a0a, 0xfe00, 0xbeef]);
        assert_eq!(
            decoded.labels(),
            vec![
                "reserved grease signature scheme 0x0a0a".to_string(),
                "private-use signature scheme 0xfe00".to_string(),
                "unknown signature scheme 0xbeef".to_string(),
            ]
        );
        assert!(decoded.inspection_fields().contains(&(
            "signature_algorithms_raw",
            "0x0a0a,0xfe00,0xbeef".to_string()
        )));

        let cert = TlsSignatureAlgorithmsCert::from_raws([0x0a0a, 0xbeef]);
        assert_eq!(
            TlsSignatureAlgorithmsCert::decode(cert.encode_to_vec().unwrap())
                .unwrap()
                .raw_values(),
            vec![0x0a0a, 0xbeef]
        );
    }

    #[test]
    fn tls_extension_signature_algorithms_reports_structured_decode_errors() {
        assert_eq!(
            TlsSignatureAlgorithms::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.signature_algorithms.length",
                TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsSignatureAlgorithms::decode([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.signature_algorithms.length",
                TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN,
                1
            )
        );
        assert_eq!(
            TlsSignatureAlgorithms::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms.length",
                "length must be at least two bytes"
            )
        );
        assert_eq!(
            TlsSignatureAlgorithms::decode([0x00, 0x03, 0x08, 0x07, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms.length",
                "length must be a multiple of two bytes"
            )
        );
        assert_eq!(
            TlsSignatureAlgorithms::decode([0x00, 0x04, 0x08, 0x07]).unwrap_err(),
            CrafterError::buffer_too_short("tls.signature_algorithms", 6, 4)
        );
        assert_eq!(
            TlsSignatureAlgorithms::decode([0x00, 0x02, 0x08, 0x07, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms.length",
                "length must match extension body"
            )
        );
        assert_eq!(
            TlsSignatureAlgorithms::from_raw_extension(&TlsRawExtension::new(
                TlsExtensionType::SIGNATURE_ALGORITHMS,
                Vec::<u8>::new(),
            ))
            .unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.signature_algorithms.length",
                TLS_SIGNATURE_ALGORITHMS_LIST_LENGTH_LEN,
                0
            )
        );

        assert_eq!(
            TlsSignatureAlgorithmsCert::decode([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms_cert.length",
                "length must be at least two bytes"
            )
        );
        assert_eq!(
            TlsSignatureAlgorithmsCert::decode([0x00, 0x03, 0x05, 0x01, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms_cert.length",
                "length must be a multiple of two bytes"
            )
        );
        assert_eq!(
            TlsSignatureAlgorithmsCert::decode([0x00, 0x04, 0x05, 0x01]).unwrap_err(),
            CrafterError::buffer_too_short("tls.signature_algorithms_cert", 6, 4)
        );
        assert_eq!(
            TlsSignatureAlgorithmsCert::decode([0x00, 0x02, 0x05, 0x01, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms_cert.length",
                "length must match extension body"
            )
        );
    }

    #[test]
    fn tls_extension_signature_algorithms_reports_structured_encode_errors() {
        assert_eq!(
            TlsSignatureAlgorithms::default()
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms.length",
                "length must be at least two bytes"
            )
        );
        assert_eq!(
            TlsSignatureAlgorithmsCert::default()
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms_cert.length",
                "length must be at least two bytes"
            )
        );

        let oversized =
            TlsSignatureAlgorithms::from_schemes(vec![TlsSignatureScheme::ED25519; 32768]);
        assert_eq!(
            oversized.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms.length",
                "length must fit in two bytes"
            )
        );

        let oversized_cert =
            TlsSignatureAlgorithmsCert::from_schemes(vec![TlsSignatureScheme::ED25519; 32768]);
        assert_eq!(
            oversized_cert.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.signature_algorithms_cert.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_supported_versions_builders_encode_client_and_server_forms() {
        let client = TlsSupportedVersions::client_tls_1_3_then_tls_1_2();
        assert!(client.is_client());
        assert!(!client.is_server());
        assert_eq!(
            client.versions().unwrap(),
            &[TlsVersion::tls_1_3(), TlsVersion::tls_1_2()]
        );
        assert_eq!(client.selected_version(), None);
        assert_eq!(client.encoded_len().unwrap(), 5);
        assert_eq!(
            client.encode_to_vec().unwrap(),
            [0x04, 0x03, 0x04, 0x03, 0x03]
        );

        let client_tls_1_2 = TlsSupportedVersions::client_tls_1_2();
        assert_eq!(client_tls_1_2.encode_to_vec().unwrap(), [0x02, 0x03, 0x03]);
        let client_tls_1_3 = TlsSupportedVersions::client_tls_1_3();
        assert_eq!(client_tls_1_3.encode_to_vec().unwrap(), [0x02, 0x03, 0x04]);

        let decoded = TlsSupportedVersions::decode_with_context(
            TlsSupportedVersionsContext::client_hello(),
            [0x04, 0x03, 0x04, 0x03, 0x03],
        )
        .unwrap();
        assert_eq!(decoded, client);
        assert_eq!(
            decoded.summary(),
            "supported_versions context=client count=2 values=TLS 1.3:0x0304,TLS 1.2:0x0303"
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("supported_versions_raw", "0x0304,0x0303".to_string())));

        let server = TlsSupportedVersions::server_tls_1_3();
        assert!(!server.is_client());
        assert!(server.is_server());
        assert_eq!(server.versions(), None);
        assert_eq!(server.selected_version(), Some(TlsVersion::tls_1_3()));
        assert_eq!(server.encoded_len().unwrap(), 2);
        assert_eq!(server.encode_to_vec().unwrap(), [0x03, 0x04]);
        assert_eq!(
            TlsSupportedVersions::server_tls_1_2()
                .encode_to_vec()
                .unwrap(),
            [0x03, 0x03]
        );
        assert_eq!(
            TlsSupportedVersions::decode_with_context(
                TlsSupportedVersionsContext::server_hello(),
                [0x03, 0x04],
            )
            .unwrap(),
            server
        );
        assert_eq!(
            TlsSupportedVersions::decode_hello_retry_request([0x03, 0x04]).unwrap(),
            server
        );
        assert_eq!(
            server.summary(),
            "supported_versions context=server selected=TLS 1.3:0x0304"
        );
        assert!(server
            .inspection_fields()
            .contains(&("supported_versions_selected_raw", "0x0304".to_string())));
    }

    #[test]
    fn tls_extension_supported_versions_converts_to_and_from_raw_extension_with_context() {
        let client = TlsSupportedVersions::client_tls_1_3_then_tls_1_2();
        let raw = client.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::SUPPORTED_VERSIONS);
        assert_eq!(raw.raw_type(), constants::TLS_EXTENSION_SUPPORTED_VERSIONS);
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]
        );
        assert_eq!(raw.as_supported_versions_client().unwrap(), client);
        assert_eq!(
            raw.as_supported_versions_with_context(TlsSupportedVersionsContext::ClientHello)
                .unwrap(),
            client
        );
        assert_eq!(
            TlsSupportedVersions::from_client_hello_raw_extension(&raw).unwrap(),
            client
        );
        assert_eq!(TlsRawExtension::try_from(client.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::supported_versions_client(vec![
                TlsVersion::tls_1_3(),
                TlsVersion::tls_1_2()
            ])
            .unwrap(),
            raw
        );

        let server = TlsSupportedVersions::server_tls_1_3();
        let raw = server.to_raw_extension().unwrap();
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
        );
        assert_eq!(raw.as_supported_versions_server().unwrap(), server);
        assert_eq!(
            TlsSupportedVersions::from_server_hello_raw_extension(&raw).unwrap(),
            server
        );
        assert_eq!(
            TlsSupportedVersions::from_hello_retry_request_raw_extension(&raw).unwrap(),
            server
        );
        assert_eq!(
            TlsRawExtension::supported_versions_server(TlsVersion::tls_1_3()).unwrap(),
            raw
        );

        assert_eq!(
            TlsSupportedVersions::from_client_hello_raw_extension(&TlsRawExtension::from_raw(
                0xbeef,
                []
            ))
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be supported_versions"
            )
        );
    }

    #[test]
    fn tls_extension_supported_versions_preserves_unknown_raw_versions() {
        let unknown = TlsVersion::from_u16(0x7a7a);
        let client = TlsSupportedVersions::client(vec![unknown, TlsVersion::tls_1_3()]);
        assert_eq!(
            client.encode_to_vec().unwrap(),
            [0x04, 0x7a, 0x7a, 0x03, 0x04]
        );
        let decoded = TlsSupportedVersions::decode_client([0x04, 0x7a, 0x7a, 0x03, 0x04]).unwrap();
        assert_eq!(decoded, client);
        assert_eq!(decoded.versions().unwrap()[0].raw(), 0x7a7a);
        assert!(decoded
            .inspection_fields()
            .contains(&("supported_versions_raw", "0x7a7a,0x0304".to_string())));

        let server = TlsSupportedVersions::decode_server([0x7a, 0x7a]).unwrap();
        assert_eq!(server.selected_version(), Some(unknown));
        assert_eq!(server.encode_to_vec().unwrap(), [0x7a, 0x7a]);
    }

    #[test]
    fn tls_extension_supported_versions_context_selects_client_or_server_body_shape() {
        let client_body = [0x02, 0x03, 0x04];
        assert_eq!(
            TlsSupportedVersions::decode_with_context(
                TlsSupportedVersionsContext::client_hello(),
                client_body,
            )
            .unwrap(),
            TlsSupportedVersions::client_tls_1_3()
        );
        assert_eq!(
            TlsSupportedVersions::decode_with_context(
                TlsSupportedVersionsContext::server_hello(),
                client_body,
            )
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.server.length",
                "length must be exactly two bytes"
            )
        );

        let server_body = [0x03, 0x04];
        assert_eq!(
            TlsSupportedVersions::decode_with_context(
                TlsSupportedVersionsContext::server_hello(),
                server_body,
            )
            .unwrap(),
            TlsSupportedVersions::server_tls_1_3()
        );
        assert_eq!(
            TlsSupportedVersions::decode_with_context(
                TlsSupportedVersionsContext::client_hello(),
                server_body,
            )
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length must be a multiple of two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_supported_versions_reports_structured_client_decode_errors() {
        assert_eq!(
            TlsSupportedVersions::decode_client([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.supported_versions.client.length",
                TLS_SUPPORTED_VERSIONS_CLIENT_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsSupportedVersions::decode_client([0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length must be at least two bytes"
            )
        );
        assert_eq!(
            TlsSupportedVersions::decode_client([0x01, 0x03]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length must be a multiple of two bytes"
            )
        );
        assert_eq!(
            TlsSupportedVersions::decode_client([0x04, 0x03, 0x04]).unwrap_err(),
            CrafterError::buffer_too_short("tls.supported_versions.client", 5, 3)
        );
        assert_eq!(
            TlsSupportedVersions::decode_client([0x02, 0x03, 0x04, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length must match extension body"
            )
        );
    }

    #[test]
    fn tls_extension_supported_versions_reports_structured_encode_and_server_decode_errors() {
        assert_eq!(
            TlsSupportedVersions::client(Vec::<TlsVersion>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length must be at least two bytes"
            )
        );

        let oversized = TlsSupportedVersions::client(vec![TlsVersion::tls_1_3(); 128]);
        assert_eq!(
            oversized.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.client.length",
                "length must fit in one byte"
            )
        );

        assert_eq!(
            TlsSupportedVersions::decode_server([0x03]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.supported_versions.server.version",
                TLS_SUPPORTED_VERSION_LEN,
                1
            )
        );
        assert_eq!(
            TlsSupportedVersions::decode_server([0x03, 0x04, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.supported_versions.server.length",
                "length must be exactly two bytes"
            )
        );
        assert_eq!(
            TlsSupportedVersions::decode_hello_retry_request([0x03]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.supported_versions.hello_retry_request.version",
                TLS_SUPPORTED_VERSION_LEN,
                1
            )
        );
    }

    #[test]
    fn tls_extension_psk_modes_known_codepoints_expose_raw_values() {
        assert_eq!(
            TlsPskKeyExchangeMode::psk_ke().raw(),
            TLS_PSK_KEY_EXCHANGE_MODE_PSK_KE
        );
        assert_eq!(
            TlsPskKeyExchangeMode::psk_dhe_ke().raw(),
            TLS_PSK_KEY_EXCHANGE_MODE_PSK_DHE_KE
        );
        assert_eq!(
            TlsPskKeyExchangeMode::from_be_bytes([0x01]),
            TlsPskKeyExchangeMode::PSK_DHE_KE
        );
        assert_eq!(TlsPskKeyExchangeMode::PSK_DHE_KE.to_be_bytes(), [0x01]);
        assert_eq!(TlsPskKeyExchangeMode::PSK_KE.name(), Some("psk_ke"));
        assert_eq!(TlsPskKeyExchangeMode::PSK_DHE_KE.name(), Some("psk_dhe_ke"));
        assert!(TlsPskKeyExchangeMode::PSK_KE.is_known());
        assert_eq!(
            TlsPskKeyExchangeMode::PSK_DHE_KE.status(),
            TlsCodepointStatus::DefaultEligible
        );
        assert!(TlsPskKeyExchangeMode::PSK_DHE_KE.is_default_eligible());

        let unknown = TlsPskKeyExchangeMode::from_u8(0x7a);
        assert_eq!(unknown.name(), None);
        assert_eq!(unknown.status(), TlsCodepointStatus::Unassigned);
        assert_eq!(unknown.label(), "unassigned psk mode 0x7a");
        assert_eq!(unknown.to_string(), "unassigned psk mode 0x7a");
        assert_eq!(unknown.encode_to_vec(), [0x7a]);
        assert_eq!(TlsPskKeyExchangeMode::decode([0x7a]).unwrap(), unknown);
        assert_eq!(
            TlsPskKeyExchangeMode::decode_prefix(&[0x7a, 0xaa]).unwrap(),
            (unknown, &[0xaa][..])
        );
        assert_eq!(u8::from(unknown), 0x7a);
        assert_eq!(TlsPskKeyExchangeMode::from(0x7a).as_u8(), 0x7a);

        let private = TlsPskKeyExchangeMode::from_u8(0xfe);
        assert!(private.is_private_use());
        assert_eq!(
            private.summary(),
            "private-use psk mode 0xfe raw=0xfe status=private-use"
        );
        assert!(private
            .inspection_fields()
            .contains(&("psk_key_exchange_mode_raw", "0xfe".to_string())));
        assert!(private
            .inspection_fields()
            .contains(&("psk_key_exchange_mode_status", "private-use".to_string())));

        let grease = TlsPskKeyExchangeMode::from_u8(0x2a);
        assert!(grease.is_grease());
        assert_eq!(grease.status(), TlsCodepointStatus::ReservedGrease);
        assert_eq!(grease.label(), "reserved grease psk mode 0x2a");
    }

    #[test]
    fn tls_extension_psk_modes_builders_encode_rfc8446_vector() {
        // RFC 8446 Section 4.2.9 defines PskKeyExchangeModes as PskKeyExchangeMode<1..255>.
        let modes = TlsPskKeyExchangeModes::from_modes(vec![
            TlsPskKeyExchangeMode::PSK_KE,
            TlsPskKeyExchangeMode::PSK_DHE_KE,
        ]);
        assert_eq!(modes.len(), 2);
        assert!(!modes.is_empty());
        assert_eq!(
            modes.modes(),
            &[
                TlsPskKeyExchangeMode::PSK_KE,
                TlsPskKeyExchangeMode::PSK_DHE_KE,
            ]
        );
        assert_eq!(modes.as_slice(), modes.modes());
        assert_eq!(modes.raw_values(), vec![0x00, 0x01]);
        assert_eq!(modes.byte_len().unwrap(), 2);
        assert_eq!(modes.encoded_len().unwrap(), 3);
        assert_eq!(modes.encode_to_vec().unwrap(), [0x02, 0x00, 0x01]);

        let encoded_with_tail = [modes.encode_to_vec().unwrap(), vec![0xaa]].concat();
        let (decoded, tail) = TlsPskKeyExchangeModes::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa]);
        assert_eq!(decoded, modes);
        assert_eq!(
            decoded.summary(),
            "psk_key_exchange_modes count=2 bytes=2 values=psk_ke,psk_dhe_ke"
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("psk_key_exchange_modes_raw", "0x00,0x01".to_string())));
        assert_eq!(
            decoded.clone().into_vec(),
            vec![
                TlsPskKeyExchangeMode::PSK_KE,
                TlsPskKeyExchangeMode::PSK_DHE_KE,
            ]
        );

        let mut pushed = TlsPskKeyExchangeModes::psk_ke();
        pushed.push(TlsPskKeyExchangeMode::PSK_DHE_KE);
        assert_eq!(pushed, modes);
        assert_eq!(
            TlsPskKeyExchangeModes::psk_dhe_ke()
                .encode_to_vec()
                .unwrap(),
            [0x01, 0x01]
        );
        assert_eq!(TlsPskKeyExchangeModes::psk_ke_then_psk_dhe_ke(), modes);
        assert_eq!(
            TlsPskKeyExchangeModes::from_raws([0x00, 0x7a]).raw_values(),
            vec![0x00, 0x7a]
        );
        assert_eq!(
            TlsPskKeyExchangeModes::from([TlsPskKeyExchangeMode::PSK_DHE_KE]).raw_values(),
            vec![0x01]
        );
    }

    #[test]
    fn tls_extension_psk_modes_converts_to_and_from_raw_extension() {
        let modes = TlsPskKeyExchangeModes::psk_ke_then_psk_dhe_ke();
        let raw = modes.to_raw_extension().unwrap();
        assert_eq!(
            raw.extension_type(),
            TlsExtensionType::PSK_KEY_EXCHANGE_MODES
        );
        assert_eq!(
            raw.raw_type(),
            constants::TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES
        );
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x2d, 0x00, 0x03, 0x02, 0x00, 0x01]
        );

        assert_eq!(raw.as_psk_key_exchange_modes().unwrap(), modes);
        assert_eq!(TlsPskKeyExchangeModes::try_from(&raw).unwrap(), modes);
        assert_eq!(TlsRawExtension::try_from(modes.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::psk_key_exchange_modes(modes.clone()).unwrap(),
            raw
        );
        assert_eq!(
            TlsRawExtension::decode(raw.encode_to_vec().unwrap())
                .unwrap()
                .as_psk_key_exchange_modes()
                .unwrap(),
            modes
        );

        assert_eq!(
            TlsPskKeyExchangeModes::from_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be psk_key_exchange_modes"
            )
        );
    }

    #[test]
    fn tls_extension_psk_modes_preserves_unknown_raw_modes() {
        let modes = TlsPskKeyExchangeModes::from_raws([0x7a, 0xfe, 0xff]);
        assert_eq!(modes.encode_to_vec().unwrap(), [0x03, 0x7a, 0xfe, 0xff]);

        let decoded = TlsPskKeyExchangeModes::decode([0x03, 0x7a, 0xfe, 0xff]).unwrap();
        assert_eq!(decoded, modes);
        assert_eq!(decoded.raw_values(), vec![0x7a, 0xfe, 0xff]);
        assert_eq!(
            decoded.labels(),
            vec![
                "unassigned psk mode 0x7a".to_string(),
                "private-use psk mode 0xfe".to_string(),
                "private-use psk mode 0xff".to_string(),
            ]
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("psk_key_exchange_modes_raw", "0x7a,0xfe,0xff".to_string())));
    }

    #[test]
    fn tls_extension_psk_modes_reports_structured_decode_and_encode_errors() {
        assert_eq!(
            TlsPskKeyExchangeMode::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.psk_key_exchange_mode",
                TLS_PSK_KEY_EXCHANGE_MODE_LEN,
                0
            )
        );
        assert_eq!(
            TlsPskKeyExchangeModes::decode([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.psk_key_exchange_modes.length",
                TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsPskKeyExchangeModes::decode([0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.psk_key_exchange_modes.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsPskKeyExchangeModes::decode([0x02, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.psk_key_exchange_modes", 3, 2)
        );
        assert_eq!(
            TlsPskKeyExchangeModes::decode([0x01, 0x00, 0xaa]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.psk_key_exchange_modes.length",
                "length must match extension body"
            )
        );
        assert_eq!(
            TlsPskKeyExchangeModes::from_raw_extension(&TlsRawExtension::new(
                TlsExtensionType::PSK_KEY_EXCHANGE_MODES,
                Vec::<u8>::new(),
            ))
            .unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.psk_key_exchange_modes.length",
                TLS_PSK_KEY_EXCHANGE_MODES_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsPskKeyExchangeModes::default()
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.psk_key_exchange_modes.length",
                "length must be at least one byte"
            )
        );

        let oversized =
            TlsPskKeyExchangeModes::from_modes(vec![TlsPskKeyExchangeMode::PSK_DHE_KE; 256]);
        assert_eq!(
            oversized.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.psk_key_exchange_modes.length",
                "length must fit in one byte"
            )
        );
    }

    #[test]
    fn tls_extension_pre_shared_key_builders_encode_client_and_server_forms() {
        // RFC 8446 Section 4.2.11 defines PskIdentity, PskBinderEntry, and
        // the context-selected PreSharedKeyExtension body.
        assert_eq!(
            TlsExtensionType::pre_shared_key().raw(),
            constants::TLS_EXTENSION_PRE_SHARED_KEY
        );

        let identity = TlsPskIdentity::new([0xde, 0xad, 0xbe, 0xef], 0x0102_0304);
        assert_eq!(identity.identity(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(identity.obfuscated_ticket_age(), 0x0102_0304);
        assert_eq!(identity.encoded_len().unwrap(), 10);
        assert_eq!(
            identity.encode_to_vec().unwrap(),
            [0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(
            TlsPskIdentity::decode_prefix(&[
                0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0xaa,
            ])
            .unwrap(),
            (identity.clone(), &[0xaa][..])
        );
        assert_eq!(
            identity.summary(),
            "psk_identity identity_bytes=4 obfuscated_ticket_age=16909060"
        );
        assert!(identity
            .inspection_fields()
            .contains(&("psk_identity", "de ad be ef".to_string())));

        let binder = TlsPskBinderEntry::new([0x11; 32]);
        assert_eq!(binder.bytes(), &[0x11; 32]);
        assert_eq!(binder.encoded_len().unwrap(), 33);
        let mut expected_binder = vec![0x20];
        expected_binder.extend_from_slice(&[0x11; 32]);
        assert_eq!(binder.encode_to_vec().unwrap(), expected_binder);
        assert_eq!(
            TlsPskBinderEntry::decode_prefix(&[expected_binder.clone(), vec![0xaa]].concat())
                .unwrap(),
            (binder.clone(), &[0xaa][..])
        );
        assert_eq!(binder.summary(), "psk_binder bytes=32");
        assert!(binder
            .inspection_fields()
            .contains(&("psk_binder_bytes", "32".to_string())));

        let identities = TlsPskIdentities::new(vec![identity.clone()]);
        assert_eq!(identities.len(), 1);
        assert!(!identities.is_empty());
        assert_eq!(identities.identities(), &[identity.clone()]);
        assert_eq!(identities.identity_lengths(), vec![4]);
        assert_eq!(identities.obfuscated_ticket_ages(), vec![0x0102_0304]);
        assert_eq!(identities.byte_len().unwrap(), 10);
        assert_eq!(identities.encoded_len().unwrap(), 12);
        assert_eq!(
            identities.encode_to_vec().unwrap(),
            [0x00, 0x0a, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(
            identities.summary(),
            "psk_identities count=1 bytes=10 identities=4 bytes age=16909060"
        );

        let binders = TlsPskBinders::new(vec![binder.clone()]);
        assert_eq!(binders.len(), 1);
        assert!(!binders.is_empty());
        assert_eq!(binders.binders(), &[binder.clone()]);
        assert_eq!(binders.binder_lengths(), vec![32]);
        assert_eq!(binders.byte_len().unwrap(), 33);
        assert_eq!(binders.encoded_len().unwrap(), 35);
        let mut expected_binders = vec![0x00, 0x21, 0x20];
        expected_binders.extend_from_slice(&[0x11; 32]);
        assert_eq!(binders.encode_to_vec().unwrap(), expected_binders);
        assert_eq!(
            binders.summary(),
            "psk_binders count=1 bytes=33 binders=32 bytes"
        );

        let client = TlsPreSharedKey::client(identities.clone(), binders.clone());
        assert!(client.is_client());
        assert!(!client.is_server());
        assert_eq!(client.identities(), Some(&identities));
        assert_eq!(client.binders(), Some(&binders));
        assert_eq!(client.selected_identity(), None);
        assert_eq!(client.binder_count_matches_identities(), Some(true));
        client.validate_binder_count_matches_identities().unwrap();
        assert_eq!(client.encoded_len().unwrap(), 47);

        let mut expected_client = identities.encode_to_vec().unwrap();
        expected_client.extend_from_slice(&binders.encode_to_vec().unwrap());
        assert_eq!(client.encode_to_vec().unwrap(), expected_client);
        assert_eq!(
            TlsPreSharedKey::decode_client(expected_client).unwrap(),
            client
        );
        assert_eq!(
            TlsPreSharedKey::decode_with_context(
                TlsPreSharedKeyContext::client_hello(),
                client.encode_to_vec().unwrap(),
            )
            .unwrap(),
            client
        );
        assert_eq!(
            client.summary(),
            "pre_shared_key context=client identities=1 identities_bytes=10 binders=1 binders_bytes=33"
        );
        assert!(client
            .inspection_fields()
            .contains(&("psk_identities", "de ad be ef".to_string())));
        assert!(client
            .inspection_fields()
            .contains(&("psk_binder_bytes", "32".to_string())));

        let server = TlsPreSharedKey::server(2);
        assert!(!server.is_client());
        assert!(server.is_server());
        assert_eq!(server.identities(), None);
        assert_eq!(server.binders(), None);
        assert_eq!(server.selected_identity(), Some(2));
        assert_eq!(server.binder_count_matches_identities(), None);
        assert_eq!(server.encoded_len().unwrap(), 2);
        assert_eq!(server.encode_to_vec().unwrap(), [0x00, 0x02]);
        assert_eq!(
            TlsPreSharedKey::decode_server([0x00, 0x02]).unwrap(),
            server
        );
        assert_eq!(
            TlsPreSharedKey::decode_with_context(
                TlsPreSharedKeyContext::server_hello(),
                [0x00, 0x02],
            )
            .unwrap(),
            server
        );
        assert_eq!(
            server.summary(),
            "pre_shared_key context=server selected_identity=2"
        );
        assert!(server
            .inspection_fields()
            .contains(&("pre_shared_key_selected_identity_raw", "0x0002".to_string())));
    }

    #[test]
    fn tls_extension_pre_shared_key_converts_to_and_from_raw_extension_with_context() {
        let identity = TlsPskIdentity::new([0xaa], 0);
        let binder = TlsPskBinderEntry::new([0xbb; 32]);
        let client = TlsPreSharedKey::client([identity], [binder]);
        let raw = client.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::PRE_SHARED_KEY);
        assert_eq!(raw.raw_type(), constants::TLS_EXTENSION_PRE_SHARED_KEY);

        let mut expected_raw = vec![0x00, 0x29, 0x00, 0x2c];
        expected_raw.extend_from_slice(&client.encode_to_vec().unwrap());
        assert_eq!(raw.encode_to_vec().unwrap(), expected_raw);
        assert_eq!(raw.as_pre_shared_key_client().unwrap(), client);
        assert_eq!(
            raw.as_pre_shared_key_with_context(TlsPreSharedKeyContext::client_hello())
                .unwrap(),
            client
        );
        assert_eq!(
            TlsPreSharedKey::from_client_hello_raw_extension(&raw).unwrap(),
            client
        );
        assert_eq!(TlsRawExtension::try_from(client.clone()).unwrap(), raw);
        assert_eq!(
            TlsRawExtension::pre_shared_key_client(
                client.identities().unwrap().clone(),
                client.binders().unwrap().clone(),
            )
            .unwrap(),
            raw
        );

        let server = TlsPreSharedKey::server(3);
        let raw = server.to_raw_extension().unwrap();
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x29, 0x00, 0x02, 0x00, 0x03]
        );
        assert_eq!(raw.as_pre_shared_key_server().unwrap(), server);
        assert_eq!(
            raw.as_pre_shared_key_with_context(TlsPreSharedKeyContext::server_hello())
                .unwrap(),
            server
        );
        assert_eq!(
            TlsPreSharedKey::from_server_hello_raw_extension(&raw).unwrap(),
            server
        );
        assert_eq!(TlsRawExtension::pre_shared_key_server(3).unwrap(), raw);

        assert_eq!(
            TlsPreSharedKey::from_client_hello_raw_extension(&TlsRawExtension::from_raw(
                0xbeef,
                []
            ))
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be pre_shared_key"
            )
        );
    }

    #[test]
    fn tls_extension_pre_shared_key_preserves_opaque_values_without_psk_semantics() {
        let first = TlsPskIdentity::new([0x00, 0xff, 0x00, 0x42], 7);
        let second = TlsPskIdentity::new([0xde, 0xad], u32::MAX);
        let binder = TlsPskBinderEntry::new([0xcc; 32]);
        let client = TlsPreSharedKey::client(
            TlsPskIdentities::new(vec![first.clone(), second.clone()]),
            TlsPskBinders::new(vec![binder.clone()]),
        );

        assert_eq!(client.binder_count_matches_identities(), Some(false));
        assert_eq!(
            client
                .validate_binder_count_matches_identities()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.binders.count",
                "binder count must match identity count"
            )
        );

        let decoded = TlsPreSharedKey::decode_client(client.encode_to_vec().unwrap()).unwrap();
        assert_eq!(decoded, client);
        let identities = decoded.identities().unwrap();
        assert_eq!(identities.identities()[0].identity(), first.identity());
        assert_eq!(identities.identities()[1].identity(), second.identity());
        assert_eq!(identities.obfuscated_ticket_ages(), vec![7, u32::MAX]);
        assert_eq!(
            decoded.binders().unwrap().binders()[0].bytes(),
            binder.bytes()
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("psk_identities", "00 ff 00 42|de ad".to_string())));
        assert!(decoded
            .inspection_fields()
            .contains(&("psk_binders_count", "1".to_string())));
    }

    #[test]
    fn tls_extension_pre_shared_key_reports_structured_client_decode_errors() {
        assert_eq!(
            TlsPreSharedKey::decode_client([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.pre_shared_key.client.identities.length",
                TLS_PSK_IDENTITIES_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsPreSharedKey::decode_client([0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.identities.length",
                "length must be at least seven bytes"
            )
        );
        assert_eq!(
            TlsPreSharedKey::decode_client([0x00, 0x07, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,])
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.identity.bytes.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsPreSharedKey::decode_client([0x00, 0x08, 0x00, 0x01, 0xaa, 0x00,]).unwrap_err(),
            CrafterError::buffer_too_short("tls.pre_shared_key.client.identities", 10, 6)
        );
        assert_eq!(
            TlsPreSharedKey::decode_client([0x00, 0x07, 0x00, 0x06, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,])
                .unwrap_err(),
            CrafterError::buffer_too_short("tls.pre_shared_key.client.identity.bytes", 8, 7)
        );
        assert_eq!(
            TlsPreSharedKey::decode_client([0x00, 0x07, 0x00, 0x02, 0xaa, 0xbb, 0x00, 0x00, 0x00,])
                .unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.pre_shared_key.client.identity.obfuscated_ticket_age",
                8,
                7
            )
        );

        let mut identity_then_empty_binders =
            vec![0x00, 0x07, 0x00, 0x01, 0xaa, 0x00, 0x00, 0x00, 0x00];
        identity_then_empty_binders.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            TlsPreSharedKey::decode_client(identity_then_empty_binders).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.binders.length",
                "length must be at least 33 bytes"
            )
        );

        let mut binder_zero_len = vec![
            0x00, 0x07, 0x00, 0x01, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00,
        ];
        binder_zero_len.extend_from_slice(&[0x00; 32]);
        assert_eq!(
            TlsPreSharedKey::decode_client(binder_zero_len).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.binder.length",
                "length must be at least 32 bytes"
            )
        );

        let mut binder_truncated = vec![
            0x00, 0x07, 0x00, 0x01, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x21,
        ];
        binder_truncated.extend_from_slice(&[0xbb; 32]);
        assert_eq!(
            TlsPreSharedKey::decode_client(binder_truncated).unwrap_err(),
            CrafterError::buffer_too_short("tls.pre_shared_key.client.binder", 34, 33)
        );

        let client = TlsPreSharedKey::client(
            [TlsPskIdentity::new([0xaa], 0)],
            [TlsPskBinderEntry::new([0xbb; 32])],
        );
        let mut with_tail = client.encode_to_vec().unwrap();
        with_tail.push(0xcc);
        assert_eq!(
            TlsPreSharedKey::decode_client(with_tail).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.length",
                "length must match extension body"
            )
        );
    }

    #[test]
    fn tls_extension_pre_shared_key_reports_structured_server_decode_errors() {
        assert_eq!(
            TlsPreSharedKey::decode_server([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.pre_shared_key.server.selected_identity", 2, 0)
        );
        assert_eq!(
            TlsPreSharedKey::decode_server([0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.pre_shared_key.server.selected_identity", 2, 1)
        );
        assert_eq!(
            TlsPreSharedKey::decode_server([0x00, 0x01, 0x02]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.server.length",
                "length must be exactly two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_pre_shared_key_reports_structured_encode_errors() {
        assert_eq!(
            TlsPskIdentity::new(Vec::<u8>::new(), 0)
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.identity.bytes.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsPreSharedKey::client(
                [TlsPskIdentity::new(Vec::<u8>::new(), 0)],
                [TlsPskBinderEntry::new([0xbb; 32])],
            )
            .encode_to_vec()
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.identity.bytes.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsPskIdentity::new(vec![0; u16::MAX as usize + 1], 0)
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.identity.bytes.length",
                "length must fit in two bytes"
            )
        );
        assert_eq!(
            TlsPskIdentities::default().encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.identities.length",
                "length must be at least seven bytes"
            )
        );

        let oversized_identities =
            TlsPskIdentities::new(vec![TlsPskIdentity::new([0xaa], 0); 9_363]);
        assert_eq!(
            oversized_identities.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.identities.length",
                "length must fit in two bytes"
            )
        );

        assert_eq!(
            TlsPskBinderEntry::new(vec![0xbb; 31])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.binder.length",
                "length must be at least 32 bytes"
            )
        );
        assert_eq!(
            TlsPreSharedKey::client(
                [TlsPskIdentity::new([0xaa], 0)],
                [TlsPskBinderEntry::new(vec![0xbb; 31])],
            )
            .encode_to_vec()
            .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.client.binder.length",
                "length must be at least 32 bytes"
            )
        );
        assert_eq!(
            TlsPskBinderEntry::new(vec![0xbb; 256])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.binder.length",
                "length must fit in one byte"
            )
        );
        assert_eq!(
            TlsPskBinders::default().encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.binders.length",
                "length must be at least 33 bytes"
            )
        );

        let oversized_binders = TlsPskBinders::new(vec![TlsPskBinderEntry::new([0xbb; 32]); 1_986]);
        assert_eq!(
            oversized_binders.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.pre_shared_key.binders.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_key_share_client_builders_encode_empty_single_and_multiple_lists() {
        let empty = TlsKeyShare::client_empty();
        assert!(empty.is_client());
        assert!(!empty.is_server());
        assert!(!empty.is_hello_retry_request());
        assert_eq!(empty.entries().unwrap(), &[]);
        assert_eq!(empty.encoded_len().unwrap(), 2);
        assert_eq!(empty.encode_to_vec().unwrap(), [0x00, 0x00]);
        assert_eq!(TlsKeyShare::decode_client([0x00, 0x00]).unwrap(), empty);
        assert_eq!(
            empty.summary(),
            "key_share context=client count=0 bytes=0 entries="
        );

        let entry = TlsKeyShareEntry::x25519([0xaa, 0xbb, 0xcc]);
        assert_eq!(entry.group(), TlsNamedGroup::X25519);
        assert_eq!(entry.raw_group(), 0x001d);
        assert_eq!(entry.key_exchange(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(entry.encoded_len().unwrap(), 7);
        assert_eq!(
            entry.encode_to_vec().unwrap(),
            [0x00, 0x1d, 0x00, 0x03, 0xaa, 0xbb, 0xcc]
        );
        assert_eq!(
            TlsKeyShareEntry::decode_prefix(&[0x00, 0x1d, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0xee,])
                .unwrap(),
            (entry.clone(), &[0xee][..])
        );
        assert_eq!(
            entry.summary(),
            "key_share_entry group=x25519:0x001d key_exchange_bytes=3"
        );
        assert!(entry
            .inspection_fields()
            .contains(&("key_share_key_exchange", "aa bb cc".to_string())));

        let secp256r1 = TlsKeyShareEntry::secp256r1([0x01, 0x02]);
        let client = TlsKeyShare::client(vec![entry.clone(), secp256r1.clone()]);
        assert_eq!(
            client.entries().unwrap(),
            &[entry.clone(), secp256r1.clone()]
        );
        assert_eq!(
            client.groups(),
            vec![TlsNamedGroup::X25519, TlsNamedGroup::SECP256R1]
        );
        assert_eq!(client.raw_groups(), vec![0x001d, 0x0017]);
        assert_eq!(
            client.labels(),
            vec!["x25519".to_string(), "secp256r1".to_string()]
        );
        assert_eq!(client.key_exchange_lengths(), vec![3, 2]);
        assert_eq!(client.encoded_len().unwrap(), 15);
        assert_eq!(
            client.encode_to_vec().unwrap(),
            [
                0x00, 0x0d, 0x00, 0x1d, 0x00, 0x03, 0xaa, 0xbb, 0xcc, 0x00, 0x17, 0x00, 0x02, 0x01,
                0x02,
            ]
        );

        let decoded = TlsKeyShare::decode_client(client.encode_to_vec().unwrap()).unwrap();
        assert_eq!(decoded, client);
        assert_eq!(
            decoded.summary(),
            "key_share context=client count=2 bytes=13 entries=x25519:3 bytes,secp256r1:2 bytes"
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("key_share_groups_raw", "0x001d,0x0017".to_string())));
        assert!(decoded
            .inspection_fields()
            .contains(&("key_share_key_exchange_bytes", "3,2".to_string())));
        assert!(decoded
            .inspection_fields()
            .contains(&("key_share_key_exchanges", "aa bb cc|01 02".to_string())));
        assert_eq!(
            decoded.entries().unwrap()[0].clone().into_key_exchange(),
            vec![0xaa, 0xbb, 0xcc]
        );
    }

    #[test]
    fn tls_extension_key_share_server_and_hrr_context_forms_encode_and_decode() {
        let server_entry = TlsKeyShareEntry::new(TlsNamedGroup::X25519, [0x11, 0x22]);
        let server = TlsKeyShare::server(server_entry.clone());
        assert!(!server.is_client());
        assert!(server.is_server());
        assert!(!server.is_hello_retry_request());
        assert_eq!(server.entries(), None);
        assert_eq!(server.selected_entry(), Some(&server_entry));
        assert_eq!(server.selected_group(), Some(TlsNamedGroup::X25519));
        assert_eq!(server.key_exchange_lengths(), vec![2]);
        assert_eq!(
            server.encode_to_vec().unwrap(),
            [0x00, 0x1d, 0x00, 0x02, 0x11, 0x22]
        );
        assert_eq!(
            TlsKeyShare::decode_with_context(
                TlsKeyShareContext::server_hello(),
                [0x00, 0x1d, 0x00, 0x02, 0x11, 0x22],
            )
            .unwrap(),
            server
        );
        assert_eq!(
            server.summary(),
            "key_share context=server selected=x25519:0x001d key_exchange_bytes=2"
        );
        assert!(server
            .inspection_fields()
            .contains(&("key_share_key_exchange", "11 22".to_string())));

        let hrr = TlsKeyShare::hello_retry_request(TlsNamedGroup::SECP384R1);
        assert!(!hrr.is_client());
        assert!(!hrr.is_server());
        assert!(hrr.is_hello_retry_request());
        assert_eq!(hrr.selected_entry(), None);
        assert_eq!(hrr.selected_group(), Some(TlsNamedGroup::SECP384R1));
        assert_eq!(hrr.key_exchange_lengths(), Vec::<usize>::new());
        assert_eq!(hrr.encoded_len().unwrap(), 2);
        assert_eq!(hrr.encode_to_vec().unwrap(), [0x00, 0x18]);
        assert_eq!(
            TlsKeyShare::decode_hello_retry_request([0x00, 0x18]).unwrap(),
            hrr
        );
        assert_eq!(
            TlsKeyShare::decode_with_context(
                TlsKeyShareContext::hello_retry_request(),
                [0x00, 0x18],
            )
            .unwrap(),
            hrr
        );
        assert_eq!(
            hrr.summary(),
            "key_share context=hello_retry_request selected_group=secp384r1:0x0018"
        );
        assert!(hrr
            .inspection_fields()
            .contains(&("key_share_selected_group_raw", "0x0018".to_string())));
    }

    #[test]
    fn tls_extension_key_share_converts_to_and_from_raw_extension_with_context() {
        let entry = TlsKeyShareEntry::x25519([0xaa]);
        let client = TlsKeyShare::client(vec![entry.clone()]);
        let raw = client.to_raw_extension().unwrap();
        assert_eq!(raw.extension_type(), TlsExtensionType::KEY_SHARE);
        assert_eq!(raw.raw_type(), constants::TLS_EXTENSION_KEY_SHARE);
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x33, 0x00, 0x07, 0x00, 0x05, 0x00, 0x1d, 0x00, 0x01, 0xaa]
        );
        assert_eq!(raw.as_key_share_client().unwrap(), client);
        assert_eq!(
            raw.as_key_share_with_context(TlsKeyShareContext::client_hello())
                .unwrap(),
            client
        );
        assert_eq!(
            TlsKeyShare::from_client_hello_raw_extension(&raw).unwrap(),
            client
        );
        assert_eq!(TlsRawExtension::try_from(client.clone()).unwrap(), raw);
        assert_eq!(TlsRawExtension::key_share_client(vec![entry]).unwrap(), raw);

        let server = TlsKeyShare::server((TlsNamedGroup::X25519, vec![0xbb, 0xcc]));
        let raw = server.to_raw_extension().unwrap();
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x33, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x02, 0xbb, 0xcc]
        );
        assert_eq!(raw.as_key_share_server().unwrap(), server);
        assert_eq!(
            TlsKeyShare::from_server_hello_raw_extension(&raw).unwrap(),
            server
        );
        assert_eq!(
            TlsRawExtension::key_share_server((TlsNamedGroup::X25519, vec![0xbb, 0xcc])).unwrap(),
            raw
        );

        let hrr = TlsKeyShare::hello_retry_request(TlsNamedGroup::SECP256R1);
        let raw = hrr.to_raw_extension().unwrap();
        assert_eq!(
            raw.encode_to_vec().unwrap(),
            [0x00, 0x33, 0x00, 0x02, 0x00, 0x17]
        );
        assert_eq!(raw.as_key_share_hello_retry_request().unwrap(), hrr);
        assert_eq!(
            TlsKeyShare::from_hello_retry_request_raw_extension(&raw).unwrap(),
            hrr
        );
        assert_eq!(
            TlsRawExtension::key_share_hello_retry_request(TlsNamedGroup::SECP256R1).unwrap(),
            raw
        );

        assert_eq!(
            TlsKeyShare::from_client_hello_raw_extension(&TlsRawExtension::from_raw(0xbeef, []))
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.extension.type",
                "extension type must be key_share"
            )
        );
    }

    #[test]
    fn tls_extension_key_share_preserves_unknown_groups_and_opaque_key_exchange() {
        let entry = TlsKeyShareEntry::from_raw_group(0xbeef, vec![0x00, 0xff, 0x00, 0x42]);
        let client = TlsKeyShare::client(vec![entry.clone()]);
        let encoded = client.encode_to_vec().unwrap();
        assert_eq!(
            encoded,
            [0x00, 0x08, 0xbe, 0xef, 0x00, 0x04, 0x00, 0xff, 0x00, 0x42]
        );

        let decoded = TlsKeyShare::decode_client(encoded).unwrap();
        assert_eq!(decoded, client);
        assert_eq!(decoded.raw_groups(), vec![0xbeef]);
        assert_eq!(
            decoded.labels(),
            vec!["unknown named group 0xbeef".to_string()]
        );
        assert_eq!(
            decoded.entries().unwrap()[0].key_exchange(),
            &[0x00, 0xff, 0x00, 0x42]
        );
        assert!(decoded
            .inspection_fields()
            .contains(&("key_share_groups_raw", "0xbeef".to_string())));
        assert!(decoded
            .inspection_fields()
            .contains(&("key_share_key_exchanges", "00 ff 00 42".to_string())));
        assert!(entry
            .inspection_fields()
            .contains(&("key_share_group", "unknown named group 0xbeef".to_string())));

        let hrr = TlsKeyShare::decode_hello_retry_request([0xbe, 0xef]).unwrap();
        assert_eq!(hrr.selected_group(), Some(TlsNamedGroup::from_u16(0xbeef)));
        assert_eq!(hrr.encode_to_vec().unwrap(), [0xbe, 0xef]);
    }

    #[test]
    fn tls_extension_key_share_reports_structured_client_decode_errors() {
        assert_eq!(
            TlsKeyShare::decode_client([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.key_share.client.length",
                TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN,
                0
            )
        );
        assert_eq!(
            TlsKeyShare::decode_client([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.key_share.client.length",
                TLS_KEY_SHARE_CLIENT_SHARES_LENGTH_LEN,
                1
            )
        );
        assert_eq!(
            TlsKeyShare::decode_client([0x00, 0x04, 0x00, 0x1d]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_share.client", 6, 4)
        );
        assert_eq!(
            TlsKeyShare::decode_client([0x00, 0x01, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_share.client.group", 2, 1)
        );
        assert_eq!(
            TlsKeyShare::decode_client([0x00, 0x04, 0x00, 0x1d, 0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.client.key_exchange.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsKeyShare::decode_client([0x00, 0x05, 0x00, 0x1d, 0x00, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_share.client.key_exchange", 6, 5)
        );
        assert_eq!(
            TlsKeyShare::decode_client([0x00, 0x05, 0x00, 0x1d, 0x00, 0x01, 0xaa, 0xbb,])
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.client.length",
                "length must match extension body"
            )
        );
    }

    #[test]
    fn tls_extension_key_share_reports_structured_server_and_hrr_decode_errors() {
        assert_eq!(
            TlsKeyShare::decode_server([]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_share.server.group", 2, 0)
        );
        assert_eq!(
            TlsKeyShare::decode_server([0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_share.server.group", 2, 1)
        );
        assert_eq!(
            TlsKeyShare::decode_server([0x00, 0x1d, 0x00]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_share.server.key_exchange.length", 4, 3)
        );
        assert_eq!(
            TlsKeyShare::decode_server([0x00, 0x1d, 0x00, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.server.key_exchange.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsKeyShare::decode_server([0x00, 0x1d, 0x00, 0x02, 0xaa]).unwrap_err(),
            CrafterError::buffer_too_short("tls.key_share.server.key_exchange", 6, 5)
        );
        assert_eq!(
            TlsKeyShare::decode_server([0x00, 0x1d, 0x00, 0x01, 0xaa, 0xbb]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.server.length",
                "length must match extension body"
            )
        );

        assert_eq!(
            TlsKeyShare::decode_hello_retry_request([]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.key_share.hello_retry_request.selected_group",
                2,
                0
            )
        );
        assert_eq!(
            TlsKeyShare::decode_hello_retry_request([0x00]).unwrap_err(),
            CrafterError::buffer_too_short(
                "tls.key_share.hello_retry_request.selected_group",
                2,
                1
            )
        );
        assert_eq!(
            TlsKeyShare::decode_hello_retry_request([0x00, 0x1d, 0x00]).unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.hello_retry_request.length",
                "length must be exactly two bytes"
            )
        );
    }

    #[test]
    fn tls_extension_key_share_reports_structured_encode_errors() {
        assert_eq!(
            TlsKeyShareEntry::x25519(Vec::<u8>::new())
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.entry.key_exchange.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsKeyShare::client(vec![TlsKeyShareEntry::x25519(Vec::<u8>::new())])
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.client.key_exchange.length",
                "length must be at least one byte"
            )
        );
        assert_eq!(
            TlsKeyShare::server(TlsKeyShareEntry::x25519(Vec::<u8>::new()))
                .encode_to_vec()
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.server.key_exchange.length",
                "length must be at least one byte"
            )
        );

        let oversized_key_exchange =
            TlsKeyShare::server(TlsKeyShareEntry::x25519(vec![0; u16::MAX as usize + 1]));
        assert_eq!(
            oversized_key_exchange.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.server.key_exchange.length",
                "length must fit in two bytes"
            )
        );

        let oversized_list =
            TlsKeyShare::client(vec![TlsKeyShareEntry::x25519(vec![0xaa]); 13_108]);
        assert_eq!(
            oversized_list.encode_to_vec().unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.key_share.client.length",
                "length must fit in two bytes"
            )
        );
    }

    #[test]
    fn tls_extensions_ordered_round_trip_preserves_duplicates_and_unknown_bodies() {
        let extensions = TlsExtensions::new(vec![
            TlsRawExtension::from_raw(0xbeef, [0xde, 0xad]),
            TlsRawExtension::from_raw(0x002b, [0x03, 0x04]),
            TlsRawExtension::from_raw(0xbeef, [0xfa, 0xce, 0x00]),
        ]);

        let encoded = extensions.encode_to_vec().unwrap();
        assert_eq!(
            encoded,
            [
                0x00, 0x13, 0xbe, 0xef, 0x00, 0x02, 0xde, 0xad, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
                0xbe, 0xef, 0x00, 0x03, 0xfa, 0xce, 0x00,
            ]
        );

        let encoded_with_tail = [encoded.as_slice(), &[0xaa, 0xbb][..]].concat();
        let (decoded, tail) = TlsExtensions::decode_prefix(&encoded_with_tail).unwrap();
        assert_eq!(tail, &[0xaa, 0xbb]);
        assert_eq!(decoded, extensions);
        assert_eq!(decoded.raw_types(), vec![0xbeef, 0x002b, 0xbeef]);
        assert_eq!(decoded.extensions()[0].body(), &[0xde, 0xad]);
        assert_eq!(decoded.extensions()[2].body(), &[0xfa, 0xce, 0x00]);
        assert_eq!(decoded.as_slice(), decoded.extensions());
        assert_eq!(decoded.clone().into_vec(), extensions.into_vec());
    }

    #[test]
    fn tls_unknown_extensions_preserve_order_duplicates_labels_and_query_all() {
        let extensions = TlsExtensions::from_raws([
            (0xbeef, vec![0xde, 0xad]),
            (
                constants::TLS_EXTENSION_SUPPORTED_VERSIONS,
                vec![0x03, 0x04],
            ),
            (0xbeef, vec![0xfa, 0xce, 0x00]),
            (0xff10, vec![0x7a]),
        ]);

        let encoded = extensions.encode_to_vec().unwrap();
        let decoded = TlsExtensions::decode(encoded).unwrap();
        assert_eq!(
            decoded.raw_types(),
            vec![
                0xbeef,
                constants::TLS_EXTENSION_SUPPORTED_VERSIONS,
                0xbeef,
                0xff10
            ]
        );
        assert_eq!(
            decoded.labels(),
            vec![
                "unknown extension 0xbeef".to_string(),
                "supported_versions".to_string(),
                "unknown extension 0xbeef".to_string(),
                "private-use extension 0xff10".to_string(),
            ]
        );
        assert_eq!(
            decoded.summary(),
            "extensions count=4 bytes=24 values=unknown extension 0xbeef,supported_versions,unknown extension 0xbeef,private-use extension 0xff10"
        );

        let unknowns = decoded.all_by_raw_type(0xbeef);
        assert_eq!(unknowns.len(), 2);
        assert_eq!(unknowns[0].body(), &[0xde, 0xad]);
        assert_eq!(unknowns[1].body(), &[0xfa, 0xce, 0x00]);
        assert_eq!(
            decoded
                .all_by_type(TlsExtensionType::supported_versions())
                .into_iter()
                .map(TlsRawExtension::body)
                .collect::<Vec<_>>(),
            vec![&[0x03, 0x04][..]]
        );
        assert!(decoded.all_by_raw_type(0x1234).is_empty());
        assert!(decoded
            .inspection_fields()
            .contains(&("extensions", decoded.labels().join(","))));
    }

    #[test]
    fn tls_extensions_empty_list_is_visible_and_round_trips() {
        let extensions = TlsExtensions::empty();

        assert!(extensions.is_empty());
        assert_eq!(extensions.len(), 0);
        assert_eq!(extensions.byte_len().unwrap(), 0);
        assert_eq!(extensions.encoded_len().unwrap(), 2);
        assert_eq!(extensions.encode_to_vec().unwrap(), [0x00, 0x00]);
        assert_eq!(
            TlsExtensions::decode([0x00, 0x00]).unwrap(),
            TlsExtensions::empty()
        );
    }

    #[test]
    fn tls_extensions_decode_reports_structured_short_list_header_and_body_errors() {
        assert_eq!(
            TlsExtensions::decode_with_context(TlsExtensionListContext::client_hello(), [0x00])
                .unwrap_err(),
            CrafterError::buffer_too_short("tls.client_hello.extensions.length", 2, 1)
        );
        assert_eq!(
            TlsExtensions::decode_with_context(
                TlsExtensionListContext::client_hello(),
                [0x00, 0x04, 0xbe]
            )
            .unwrap_err(),
            CrafterError::buffer_too_short("tls.client_hello.extensions", 6, 3)
        );
        assert_eq!(
            TlsExtensions::decode_with_context(
                TlsExtensionListContext::server_hello(),
                [0x00, 0x03, 0xbe, 0xef, 0x00]
            )
            .unwrap_err(),
            CrafterError::buffer_too_short("tls.server_hello.extension", 4, 3)
        );
        assert_eq!(
            TlsExtensions::decode_with_context(
                TlsExtensionListContext::certificate_entry(),
                [0x00, 0x05, 0xbe, 0xef, 0x00, 0x02, 0xaa]
            )
            .unwrap_err(),
            CrafterError::buffer_too_short("tls.certificate_entry.extension.body", 6, 5)
        );
    }

    #[test]
    fn tls_extensions_encode_rejects_oversized_aggregate_with_context() {
        let extensions = TlsExtensions::new(vec![
            TlsRawExtension::from_raw(
                0x0000,
                vec![0; u16::MAX as usize - TLS_EXTENSION_HEADER_LEN],
            ),
            TlsRawExtension::from_raw(0x0001, []),
        ]);

        assert_eq!(
            extensions
                .encode_to_vec_with_context(TlsExtensionListContext::server_hello())
                .unwrap_err(),
            CrafterError::invalid_field_value(
                "tls.server_hello.extensions.length",
                "length must fit in two bytes"
            )
        );
    }
}
