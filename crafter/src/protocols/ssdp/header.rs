//! SSDP header model.
//!
//! SSDP headers are ordered HTTP-like field lines. Names are case-insensitive
//! for lookup, while original spelling, duplicate order, unknown names, and raw
//! value bytes are preserved for serialization and inspection.

use core::fmt;
use core::str::FromStr;

const HEADER_HOST: &str = "HOST";
const HEADER_CACHE_CONTROL: &str = "CACHE-CONTROL";
const HEADER_LOCATION: &str = "LOCATION";
const HEADER_NT: &str = "NT";
const HEADER_NTS: &str = "NTS";
const HEADER_SERVER: &str = "SERVER";
const HEADER_USN: &str = "USN";
const HEADER_BOOTID: &str = "BOOTID.UPNP.ORG";
const HEADER_CONFIGID: &str = "CONFIGID.UPNP.ORG";
const HEADER_SEARCHPORT: &str = "SEARCHPORT.UPNP.ORG";
const HEADER_NEXTBOOTID: &str = "NEXTBOOTID.UPNP.ORG";
const HEADER_SECURELOCATION: &str = "SECURELOCATION.UPNP.ORG";
const HEADER_MAN: &str = "MAN";
const HEADER_MX: &str = "MX";
const HEADER_ST: &str = "ST";
const HEADER_USER_AGENT: &str = "USER-AGENT";
const HEADER_TCPPORT: &str = "TCPPORT.UPNP.ORG";
const HEADER_CPFN: &str = "CPFN.UPNP.ORG";
const HEADER_CPUUID: &str = "CPUUID.UPNP.ORG";
const HEADER_DATE: &str = "DATE";
const HEADER_EXT: &str = "EXT";
const HEADER_OPT: &str = "OPT";
const HEADER_NLS_TRAILER: &str = "-NLS";

const EXPECTED_HEADER_NAME: &str = "non-empty HTTP field-name token";

const KNOWN_HEADER_NAMES: &[(&str, SsdpHeaderNameKind)] = &[
    (HEADER_HOST, SsdpHeaderNameKind::Host),
    (HEADER_CACHE_CONTROL, SsdpHeaderNameKind::CacheControl),
    (HEADER_LOCATION, SsdpHeaderNameKind::Location),
    (HEADER_NT, SsdpHeaderNameKind::Nt),
    (HEADER_NTS, SsdpHeaderNameKind::Nts),
    (HEADER_SERVER, SsdpHeaderNameKind::Server),
    (HEADER_USN, SsdpHeaderNameKind::Usn),
    (HEADER_BOOTID, SsdpHeaderNameKind::BootId),
    (HEADER_CONFIGID, SsdpHeaderNameKind::ConfigId),
    (HEADER_SEARCHPORT, SsdpHeaderNameKind::SearchPort),
    (HEADER_NEXTBOOTID, SsdpHeaderNameKind::NextBootId),
    (HEADER_SECURELOCATION, SsdpHeaderNameKind::SecureLocation),
    (HEADER_MAN, SsdpHeaderNameKind::Man),
    (HEADER_MX, SsdpHeaderNameKind::Mx),
    (HEADER_ST, SsdpHeaderNameKind::St),
    (HEADER_USER_AGENT, SsdpHeaderNameKind::UserAgent),
    (HEADER_TCPPORT, SsdpHeaderNameKind::TcpPort),
    (HEADER_CPFN, SsdpHeaderNameKind::Cpfn),
    (HEADER_CPUUID, SsdpHeaderNameKind::Cpuuid),
    (HEADER_DATE, SsdpHeaderNameKind::Date),
    (HEADER_EXT, SsdpHeaderNameKind::Ext),
    (HEADER_OPT, SsdpHeaderNameKind::Opt),
];

/// SSDP header field name.
///
/// HTTP field names are case-insensitive for lookup, but SSDP preserves the
/// original spelling so decoded packets and explicit overrides can round-trip
/// without normalization.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpHeaderName {
    original: String,
    kind: SsdpHeaderNameKind,
}

impl SsdpHeaderName {
    /// Build a header name after validating HTTP field-name syntax.
    pub fn new(input: impl Into<String>) -> Result<Self, SsdpHeaderNameParseError> {
        Self::parse_owned(input.into())
    }

    /// Return the caller-supplied or decoded field-name spelling.
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Return the source-backed lookup kind for this field name.
    pub const fn kind(&self) -> SsdpHeaderNameKind {
        self.kind
    }

    /// Return the canonical source spelling for fixed SSDP headers.
    ///
    /// Namespace-prefixed NLS fields have a canonical suffix rather than a
    /// fixed full field name, so they return `Some("NLS")`.
    pub const fn canonical_name(&self) -> Option<&'static str> {
        self.kind.canonical_name()
    }

    /// Return the preserved namespace prefix for a `*-NLS` field name.
    pub fn nls_namespace(&self) -> Option<&str> {
        if self.kind == SsdpHeaderNameKind::NlsPrefixed {
            return nls_namespace_prefix(&self.original);
        }

        None
    }

    /// Consume the wrapper and return the preserved field-name spelling.
    pub fn into_string(self) -> String {
        self.original
    }

    fn parse_owned(input: String) -> Result<Self, SsdpHeaderNameParseError> {
        validate_header_name(&input)?;
        let kind = lookup_header_name_kind(&input);
        Ok(Self {
            original: input,
            kind,
        })
    }
}

impl fmt::Display for SsdpHeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.original())
    }
}

impl FromStr for SsdpHeaderName {
    type Err = SsdpHeaderNameParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        validate_header_name(input)?;
        Ok(Self {
            original: input.to_string(),
            kind: lookup_header_name_kind(input),
        })
    }
}

impl TryFrom<&str> for SsdpHeaderName {
    type Error = SsdpHeaderNameParseError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

impl TryFrom<String> for SsdpHeaderName {
    type Error = SsdpHeaderNameParseError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        Self::parse_owned(input)
    }
}

impl From<SsdpHeaderName> for String {
    fn from(name: SsdpHeaderName) -> Self {
        name.original
    }
}

/// Raw SSDP header field value bytes.
///
/// Values are intentionally byte-preserving. Empty values are valid, including
/// the UPnP-backed empty `EXT` response field.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct SsdpHeaderValue {
    raw: Vec<u8>,
}

impl SsdpHeaderValue {
    /// Build a value from raw field-value bytes.
    pub fn from_bytes(raw: impl Into<Vec<u8>>) -> Self {
        Self { raw: raw.into() }
    }

    /// Build an empty header value.
    pub fn empty() -> Self {
        Self { raw: Vec::new() }
    }

    /// Return the preserved field-value bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Return the number of preserved field-value bytes.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// Return true when this value has no bytes.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// Consume the wrapper and return the preserved bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.raw
    }
}

impl AsRef<[u8]> for SsdpHeaderValue {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<Vec<u8>> for SsdpHeaderValue {
    fn from(raw: Vec<u8>) -> Self {
        Self::from_bytes(raw)
    }
}

impl From<&[u8]> for SsdpHeaderValue {
    fn from(raw: &[u8]) -> Self {
        Self::from_bytes(raw.to_vec())
    }
}

impl<const N: usize> From<&[u8; N]> for SsdpHeaderValue {
    fn from(raw: &[u8; N]) -> Self {
        Self::from_bytes(raw.to_vec())
    }
}

impl From<String> for SsdpHeaderValue {
    fn from(raw: String) -> Self {
        Self::from_bytes(raw.into_bytes())
    }
}

impl From<&str> for SsdpHeaderValue {
    fn from(raw: &str) -> Self {
        Self::from_bytes(raw.as_bytes().to_vec())
    }
}

/// One ordered SSDP header field line.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpHeader {
    name: SsdpHeaderName,
    value: SsdpHeaderValue,
}

impl SsdpHeader {
    /// Build a header from a validated name and raw value bytes.
    pub fn new(name: SsdpHeaderName, value: impl Into<SsdpHeaderValue>) -> Self {
        Self {
            name,
            value: value.into(),
        }
    }

    /// Build a header after validating the field-name syntax.
    pub fn raw(
        name: impl Into<String>,
        value: impl Into<SsdpHeaderValue>,
    ) -> Result<Self, SsdpHeaderNameParseError> {
        Ok(Self::new(SsdpHeaderName::new(name)?, value))
    }

    /// Return the preserved header name.
    pub fn name(&self) -> &SsdpHeaderName {
        &self.name
    }

    /// Return the preserved header value.
    pub fn value(&self) -> &SsdpHeaderValue {
        &self.value
    }

    /// Consume the header and return its parts.
    pub fn into_parts(self) -> (SsdpHeaderName, SsdpHeaderValue) {
        (self.name, self.value)
    }

    /// Serialize this header as one SSDP field line.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.name.original().as_bytes());
        out.extend_from_slice(b":");
        if !self.value.is_empty() {
            out.extend_from_slice(b" ");
            out.extend_from_slice(self.value.as_bytes());
        }
        out.extend_from_slice(b"\r\n");
    }

    /// Return this header serialized as one SSDP field line.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize(&mut out);
        out
    }
}

/// Ordered SSDP header collection.
///
/// The collection preserves insertion order and duplicate fields. Lookups use
/// the canonical [`SsdpHeaderNameKind`] selected by the header-name parser.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SsdpHeaders {
    entries: Vec<SsdpHeader>,
}

impl SsdpHeaders {
    /// Build an empty header collection.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Build a header collection from already validated header entries.
    pub fn from_entries(entries: impl IntoIterator<Item = SsdpHeader>) -> Self {
        Self {
            entries: entries.into_iter().collect(),
        }
    }

    /// Return the number of stored header entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return true when no headers are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over every stored header in wire order.
    pub fn iter(&self) -> core::slice::Iter<'_, SsdpHeader> {
        self.entries.iter()
    }

    /// Append one already validated header, preserving insertion order.
    pub fn push(&mut self, header: SsdpHeader) {
        self.entries.push(header);
    }

    /// Validate and append one raw header field.
    pub fn push_raw(
        &mut self,
        name: impl Into<String>,
        value: impl Into<SsdpHeaderValue>,
    ) -> Result<(), SsdpHeaderNameParseError> {
        self.push(SsdpHeader::raw(name, value)?);
        Ok(())
    }

    /// Return the first value whose header name has the requested kind.
    pub fn get_first(&self, kind: SsdpHeaderNameKind) -> Option<&SsdpHeaderValue> {
        self.entries
            .iter()
            .find(|header| header.name.kind() == kind)
            .map(SsdpHeader::value)
    }

    /// Return every value whose header name has the requested kind, in wire order.
    pub fn get_all(&self, kind: SsdpHeaderNameKind) -> impl Iterator<Item = &SsdpHeaderValue> + '_ {
        self.entries
            .iter()
            .filter(move |header| header.name.kind() == kind)
            .map(SsdpHeader::value)
    }

    /// Serialize all headers as SSDP field lines in stored order.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        for header in &self.entries {
            header.serialize(out);
        }
    }

    /// Return all headers serialized as SSDP field lines in stored order.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize(&mut out);
        out
    }
}

impl IntoIterator for SsdpHeaders {
    type Item = SsdpHeader;
    type IntoIter = std::vec::IntoIter<SsdpHeader>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a SsdpHeaders {
    type Item = &'a SsdpHeader;
    type IntoIter = core::slice::Iter<'a, SsdpHeader>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Canonical lookup result for source-backed SSDP header names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SsdpHeaderNameKind {
    /// `HOST`.
    Host,
    /// `CACHE-CONTROL`.
    CacheControl,
    /// `LOCATION`.
    Location,
    /// `NT`.
    Nt,
    /// `NTS`.
    Nts,
    /// `SERVER`.
    Server,
    /// `USN`.
    Usn,
    /// `BOOTID.UPNP.ORG`.
    BootId,
    /// `CONFIGID.UPNP.ORG`.
    ConfigId,
    /// `SEARCHPORT.UPNP.ORG`.
    SearchPort,
    /// `NEXTBOOTID.UPNP.ORG`.
    NextBootId,
    /// `SECURELOCATION.UPNP.ORG`.
    SecureLocation,
    /// `MAN`.
    Man,
    /// `MX`.
    Mx,
    /// `ST`.
    St,
    /// `USER-AGENT`.
    UserAgent,
    /// `TCPPORT.UPNP.ORG`.
    TcpPort,
    /// `CPFN.UPNP.ORG`.
    Cpfn,
    /// `CPUUID.UPNP.ORG`.
    Cpuuid,
    /// `DATE`.
    Date,
    /// `EXT`.
    Ext,
    /// `OPT`.
    Opt,
    /// Any structurally valid namespace-prefixed `*-NLS` extension field.
    NlsPrefixed,
    /// Any structurally valid field name not named by the SSDP sources.
    Unknown,
}

impl SsdpHeaderNameKind {
    /// Return the source-backed canonical spelling for fixed known headers.
    pub const fn canonical_name(self) -> Option<&'static str> {
        match self {
            Self::Host => Some(HEADER_HOST),
            Self::CacheControl => Some(HEADER_CACHE_CONTROL),
            Self::Location => Some(HEADER_LOCATION),
            Self::Nt => Some(HEADER_NT),
            Self::Nts => Some(HEADER_NTS),
            Self::Server => Some(HEADER_SERVER),
            Self::Usn => Some(HEADER_USN),
            Self::BootId => Some(HEADER_BOOTID),
            Self::ConfigId => Some(HEADER_CONFIGID),
            Self::SearchPort => Some(HEADER_SEARCHPORT),
            Self::NextBootId => Some(HEADER_NEXTBOOTID),
            Self::SecureLocation => Some(HEADER_SECURELOCATION),
            Self::Man => Some(HEADER_MAN),
            Self::Mx => Some(HEADER_MX),
            Self::St => Some(HEADER_ST),
            Self::UserAgent => Some(HEADER_USER_AGENT),
            Self::TcpPort => Some(HEADER_TCPPORT),
            Self::Cpfn => Some(HEADER_CPFN),
            Self::Cpuuid => Some(HEADER_CPUUID),
            Self::Date => Some(HEADER_DATE),
            Self::Ext => Some(HEADER_EXT),
            Self::Opt => Some(HEADER_OPT),
            Self::NlsPrefixed => Some("NLS"),
            Self::Unknown => None,
        }
    }
}

/// Header field rejected by SSDP syntax validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SsdpHeaderField {
    /// HTTP field-name.
    Name,
}

impl SsdpHeaderField {
    const fn label(self) -> &'static str {
        match self {
            Self::Name => "field-name",
        }
    }
}

/// Error returned when a candidate SSDP header name is not an HTTP field-name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsdpHeaderNameParseError {
    field: SsdpHeaderField,
    value: String,
    expected: &'static str,
}

impl SsdpHeaderNameParseError {
    fn new(value: impl Into<String>) -> Self {
        Self {
            field: SsdpHeaderField::Name,
            value: value.into(),
            expected: EXPECTED_HEADER_NAME,
        }
    }

    /// The header field that failed validation.
    pub const fn field(&self) -> SsdpHeaderField {
        self.field
    }

    /// The rejected value.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Human-readable syntax expectation for the rejected field.
    pub const fn expected(&self) -> &'static str {
        self.expected
    }
}

impl fmt::Display for SsdpHeaderNameParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid SSDP header {}: {:?} (expected {})",
            self.field.label(),
            self.value,
            self.expected
        )
    }
}

impl std::error::Error for SsdpHeaderNameParseError {}

fn lookup_header_name_kind(input: &str) -> SsdpHeaderNameKind {
    if let Some((_, kind)) = KNOWN_HEADER_NAMES
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(input))
    {
        return *kind;
    }

    if nls_namespace_prefix(input).is_some() {
        return SsdpHeaderNameKind::NlsPrefixed;
    }

    SsdpHeaderNameKind::Unknown
}

fn nls_namespace_prefix(input: &str) -> Option<&str> {
    if input.len() > HEADER_NLS_TRAILER.len()
        && input[input.len() - HEADER_NLS_TRAILER.len()..].eq_ignore_ascii_case(HEADER_NLS_TRAILER)
    {
        return Some(&input[..input.len() - HEADER_NLS_TRAILER.len()]);
    }

    None
}

fn validate_header_name(input: &str) -> Result<(), SsdpHeaderNameParseError> {
    if is_http_token(input) {
        return Ok(());
    }

    Err(SsdpHeaderNameParseError::new(input))
}

fn is_http_token(input: &str) -> bool {
    !input.is_empty() && input.bytes().all(is_http_tchar)
}

fn is_http_tchar(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_header_name_known_names_are_case_insensitive() {
        for (wire, kind, canonical) in [
            ("host", SsdpHeaderNameKind::Host, "HOST"),
            (
                "cache-control",
                SsdpHeaderNameKind::CacheControl,
                "CACHE-CONTROL",
            ),
            ("LOCATION", SsdpHeaderNameKind::Location, "LOCATION"),
            ("nt", SsdpHeaderNameKind::Nt, "NT"),
            ("Nts", SsdpHeaderNameKind::Nts, "NTS"),
            ("SERVER", SsdpHeaderNameKind::Server, "SERVER"),
            ("usn", SsdpHeaderNameKind::Usn, "USN"),
            (
                "bootid.upnp.org",
                SsdpHeaderNameKind::BootId,
                "BOOTID.UPNP.ORG",
            ),
            (
                "configid.upnp.org",
                SsdpHeaderNameKind::ConfigId,
                "CONFIGID.UPNP.ORG",
            ),
            (
                "searchport.upnp.org",
                SsdpHeaderNameKind::SearchPort,
                "SEARCHPORT.UPNP.ORG",
            ),
            (
                "nextbootid.upnp.org",
                SsdpHeaderNameKind::NextBootId,
                "NEXTBOOTID.UPNP.ORG",
            ),
            (
                "securelocation.upnp.org",
                SsdpHeaderNameKind::SecureLocation,
                "SECURELOCATION.UPNP.ORG",
            ),
            ("man", SsdpHeaderNameKind::Man, "MAN"),
            ("mx", SsdpHeaderNameKind::Mx, "MX"),
            ("st", SsdpHeaderNameKind::St, "ST"),
            ("user-agent", SsdpHeaderNameKind::UserAgent, "USER-AGENT"),
            (
                "tcpport.upnp.org",
                SsdpHeaderNameKind::TcpPort,
                "TCPPORT.UPNP.ORG",
            ),
            ("cpfn.upnp.org", SsdpHeaderNameKind::Cpfn, "CPFN.UPNP.ORG"),
            (
                "cpuuid.upnp.org",
                SsdpHeaderNameKind::Cpuuid,
                "CPUUID.UPNP.ORG",
            ),
            ("date", SsdpHeaderNameKind::Date, "DATE"),
            ("ext", SsdpHeaderNameKind::Ext, "EXT"),
            ("opt", SsdpHeaderNameKind::Opt, "OPT"),
        ] {
            let name = SsdpHeaderName::try_from(wire).expect("known header name");

            assert_eq!(name.kind(), kind);
            assert_eq!(name.canonical_name(), Some(canonical));
        }
    }

    #[test]
    fn ssdp_header_name_known_names_preserve_original_spelling() {
        for wire in ["hOsT", "CaChE-CoNtRoL", "SeCuReLoCaTiOn.UpNp.OrG"] {
            let name = SsdpHeaderName::try_from(wire).expect("known header name");

            assert_eq!(name.original(), wire);
            assert_eq!(name.to_string(), wire);
            assert_eq!(String::from(name), wire);
        }
    }

    #[test]
    fn ssdp_header_name_unknown_valid_names_are_preserved() {
        for wire in ["X-DEVICE.UPNP.ORG", "X_VENDOR", "WORKGROUP.EXAMPLE.COM"] {
            let name = SsdpHeaderName::try_from(wire).expect("valid unknown header name");

            assert_eq!(name.kind(), SsdpHeaderNameKind::Unknown);
            assert_eq!(name.canonical_name(), None);
            assert_eq!(name.original(), wire);
            assert_eq!(String::from(name), wire);
        }
    }

    #[test]
    fn ssdp_header_name_namespace_prefixed_nls_is_recognized() {
        for (wire, namespace) in [("01-NLS", "01"), ("ns_2-nls", "ns_2")] {
            let name = SsdpHeaderName::try_from(wire).expect("valid NLS extension header");

            assert_eq!(name.kind(), SsdpHeaderNameKind::NlsPrefixed);
            assert_eq!(name.canonical_name(), Some("NLS"));
            assert_eq!(name.nls_namespace(), Some(namespace));
            assert_eq!(name.original(), wire);
        }

        for wire in ["NLS", "-NLS"] {
            let name = SsdpHeaderName::try_from(wire).expect("valid unknown header name");

            assert_eq!(name.kind(), SsdpHeaderNameKind::Unknown);
            assert_eq!(name.nls_namespace(), None);
        }
    }

    #[test]
    fn ssdp_header_name_invalid_names_are_structured_errors() {
        for invalid in [
            "",
            "bad name",
            "bad\tname",
            "bad:name",
            "bad/name",
            "bad\r",
            "bad\n",
            "caf\u{e9}",
        ] {
            let error = SsdpHeaderName::try_from(invalid).expect_err("invalid field-name");

            assert_eq!(error.field(), SsdpHeaderField::Name);
            assert_eq!(error.value(), invalid);
            assert_eq!(error.expected(), EXPECTED_HEADER_NAME);
        }
    }

    #[test]
    fn ssdp_header_collection_preserves_duplicate_order() {
        let mut headers = SsdpHeaders::new();
        headers.push_raw("ST", "ssdp:all").expect("first ST header");
        headers
            .push_raw("HOST", "239.255.255.250:1900")
            .expect("HOST header");
        headers
            .push_raw("st", "upnp:rootdevice")
            .expect("second ST header");

        let entries = headers.iter().collect::<Vec<_>>();

        assert_eq!(headers.len(), 3);
        assert_eq!(entries[0].name().original(), "ST");
        assert_eq!(entries[0].value().as_bytes(), b"ssdp:all");
        assert_eq!(entries[1].name().original(), "HOST");
        assert_eq!(entries[2].name().original(), "st");
        assert_eq!(entries[2].value().as_bytes(), b"upnp:rootdevice");
    }

    #[test]
    fn ssdp_header_collection_first_and_all_lookup_use_canonical_kind() {
        let mut headers = SsdpHeaders::new();
        headers
            .push_raw("st", "ssdp:all")
            .expect("lowercase ST header");
        headers
            .push_raw("HOST", "239.255.255.250:1900")
            .expect("HOST header");
        headers
            .push_raw("ST", "upnp:rootdevice")
            .expect("uppercase ST header");

        let first = headers
            .get_first(SsdpHeaderNameKind::St)
            .expect("first ST value");
        let all = headers
            .get_all(SsdpHeaderNameKind::St)
            .map(SsdpHeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert_eq!(first.as_bytes(), b"ssdp:all");
        assert_eq!(
            all,
            vec![b"ssdp:all".as_slice(), b"upnp:rootdevice".as_slice()]
        );
        assert!(headers.get_first(SsdpHeaderNameKind::Ext).is_none());
    }

    #[test]
    fn ssdp_header_collection_preserves_unknown_and_extension_headers() {
        let mut headers = SsdpHeaders::new();
        headers
            .push_raw("X-DEVICE.UPNP.ORG", "opaque")
            .expect("unknown extension header");
        headers
            .push_raw("01-NLS", "17")
            .expect("namespace-prefixed NLS header");

        let entries = headers.iter().collect::<Vec<_>>();

        assert_eq!(entries[0].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[0].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[0].value().as_bytes(), b"opaque");
        assert_eq!(entries[1].name().kind(), SsdpHeaderNameKind::NlsPrefixed);
        assert_eq!(entries[1].name().nls_namespace(), Some("01"));
        assert_eq!(
            headers.to_bytes(),
            b"X-DEVICE.UPNP.ORG: opaque\r\n01-NLS: 17\r\n"
        );
    }

    #[test]
    fn ssdp_header_collection_supports_empty_ext_value() {
        let mut headers = SsdpHeaders::new();
        headers
            .push_raw("EXT", SsdpHeaderValue::empty())
            .expect("empty EXT header");

        let ext = headers
            .get_first(SsdpHeaderNameKind::Ext)
            .expect("EXT value");

        assert!(ext.is_empty());
        assert_eq!(headers.to_bytes(), b"EXT:\r\n");
    }

    #[test]
    fn ssdp_header_collection_serializes_in_stored_order() {
        let mut headers = SsdpHeaders::new();
        headers
            .push_raw("HOST", "239.255.255.250:1900")
            .expect("HOST header");
        headers
            .push_raw("MAN", "\"ssdp:discover\"")
            .expect("MAN header");
        headers.push_raw("MX", "2").expect("MX header");
        headers.push_raw("ST", "ssdp:all").expect("ST header");

        assert_eq!(
            headers.to_bytes(),
            b"HOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n"
        );
    }

    #[test]
    fn ssdp_header_collection_invalid_raw_names_return_structured_errors() {
        let mut headers = SsdpHeaders::new();
        headers
            .push_raw("HOST", "239.255.255.250:1900")
            .expect("valid header");

        let error = headers
            .push_raw("bad name", "value")
            .expect_err("invalid raw header name");

        assert_eq!(error.field(), SsdpHeaderField::Name);
        assert_eq!(error.value(), "bad name");
        assert_eq!(error.expected(), EXPECTED_HEADER_NAME);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.to_bytes(), b"HOST: 239.255.255.250:1900\r\n");
    }

    #[test]
    fn ssdp_header_canonicalization_lookup_handles_lower_upper_mixed_and_canonical_case() {
        let mut headers = SsdpHeaders::new();
        headers
            .push_raw("host", "lower")
            .expect("lowercase HOST header");
        headers
            .push_raw("HOST", "upper")
            .expect("canonical HOST header");
        headers
            .push_raw("HoSt", "mixed")
            .expect("mixed-case HOST header");
        headers
            .push_raw("Host", "title")
            .expect("title-case HOST header");

        let entries = headers.iter().collect::<Vec<_>>();
        let values = headers
            .get_all(SsdpHeaderNameKind::Host)
            .map(SsdpHeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert!(entries
            .iter()
            .all(|header| header.name().kind() == SsdpHeaderNameKind::Host));
        assert!(entries
            .iter()
            .all(|header| header.name().canonical_name() == Some("HOST")));
        assert_eq!(
            values,
            vec![
                b"lower".as_slice(),
                b"upper".as_slice(),
                b"mixed".as_slice(),
                b"title".as_slice()
            ]
        );
        assert_eq!(
            headers
                .get_first(SsdpHeaderNameKind::Host)
                .expect("first HOST")
                .as_bytes(),
            b"lower"
        );
    }

    #[test]
    fn ssdp_header_canonicalization_serialization_preserves_original_spelling() {
        let mut headers = SsdpHeaders::new();
        headers
            .push_raw("st", "ssdp:all")
            .expect("lowercase ST header");
        headers
            .push_raw("ST", "upnp:rootdevice")
            .expect("canonical ST header");
        headers
            .push_raw("sT", "urn:schemas-upnp-org:service:ContentDirectory:1")
            .expect("mixed-case ST header");

        assert_eq!(
            headers.to_bytes(),
            b"st: ssdp:all\r\nST: upnp:rootdevice\r\nsT: urn:schemas-upnp-org:service:ContentDirectory:1\r\n"
        );
        assert_eq!(
            headers
                .iter()
                .map(|header| header.name().original())
                .collect::<Vec<_>>(),
            vec!["st", "ST", "sT"]
        );
    }
}
