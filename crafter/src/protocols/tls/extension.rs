//! TLS extension type helpers.
//!
//! TLS extensions are length-prefixed entries keyed by a raw two-octet
//! `ExtensionType`. This module models the codepoint, a single raw extension
//! entry, and the ordered extension-list framing shared by hello and
//! certificate contexts so unknown or deferred extension bodies stay
//! round-trippable.

use core::fmt;

use super::constants::{self, TlsCodepointStatus};
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
