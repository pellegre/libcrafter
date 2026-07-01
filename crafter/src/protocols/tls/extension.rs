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

    /// TLS ExtensionType `supported_groups` constructor.
    pub const fn supported_groups() -> Self {
        Self::SUPPORTED_GROUPS
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

    /// TLS ExtensionType `supported_versions` constructor.
    pub const fn supported_versions() -> Self {
        Self::SUPPORTED_VERSIONS
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

    /// Create a raw `supported_groups` extension from a typed group list.
    pub fn supported_groups(groups: impl Into<TlsSupportedGroups>) -> Result<Self> {
        groups.into().to_raw_extension()
    }

    /// Decode this raw extension as a typed supported_groups NamedGroupList.
    pub fn as_supported_groups(&self) -> Result<TlsSupportedGroups> {
        TlsSupportedGroups::from_raw_extension(self)
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

    /// Create a raw ClientHello `supported_versions` extension.
    pub fn supported_versions_client(versions: impl Into<Vec<TlsVersion>>) -> Result<Self> {
        TlsSupportedVersions::client(versions).to_raw_extension()
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
