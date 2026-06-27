//! SSDP message model scaffold.
//!
//! Request, response, unknown-value, and body-preserving message types are added
//! after the source-backed start line and header models exist.

use core::fmt;
use core::str::FromStr;

const METHOD_NOTIFY: &str = "NOTIFY";
const METHOD_M_SEARCH: &str = "M-SEARCH";
const REQUEST_TARGET_ASTERISK: &str = "*";
const HTTP_VERSION_1_1: &str = "HTTP/1.1";
const STATUS_OK: u16 = 200;
const REASON_OK: &str = "OK";

const EXPECTED_REQUEST_TARGET: &str =
    "non-empty HTTP request-target with visible ASCII bytes and no whitespace";
const EXPECTED_HTTP_VERSION: &str = "HTTP-version token formatted as HTTP/<DIGIT>.<DIGIT>";
const EXPECTED_STATUS_CODE: &str = "three decimal digits";
const EXPECTED_REASON_PHRASE: &str = "HTTP reason-phrase bytes: HTAB, SP, VCHAR, or obs-text";

/// SSDP request method token.
///
/// UPnP discovery defines `NOTIFY` and `M-SEARCH` as SSDP request methods.
/// Other syntactically valid HTTP method tokens are preserved verbatim instead
/// of being rejected or normalized.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SsdpMethod {
    /// UPnP discovery notification request.
    Notify,
    /// UPnP discovery search request.
    MSearch,
    /// Any structurally valid method token not named by UPnP discovery.
    Unknown(String),
}

impl SsdpMethod {
    /// Build a source-backed `NOTIFY` method.
    pub const fn notify() -> Self {
        Self::Notify
    }

    /// Build a source-backed `M-SEARCH` method.
    pub const fn m_search() -> Self {
        Self::MSearch
    }

    /// Return the wire method token.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Notify => METHOD_NOTIFY,
            Self::MSearch => METHOD_M_SEARCH,
            Self::Unknown(method) => method,
        }
    }
}

impl fmt::Display for SsdpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SsdpMethod {
    type Err = SsdpMethodParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if !is_http_token(input) {
            return Err(SsdpMethodParseError {
                token: input.to_string(),
            });
        }

        Ok(match input {
            METHOD_NOTIFY => Self::Notify,
            METHOD_M_SEARCH => Self::MSearch,
            _ => Self::Unknown(input.to_string()),
        })
    }
}

impl TryFrom<&str> for SsdpMethod {
    type Error = SsdpMethodParseError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

impl TryFrom<String> for SsdpMethod {
    type Error = SsdpMethodParseError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        if !is_http_token(&input) {
            return Err(SsdpMethodParseError { token: input });
        }

        Ok(match input.as_str() {
            METHOD_NOTIFY => Self::Notify,
            METHOD_M_SEARCH => Self::MSearch,
            _ => Self::Unknown(input),
        })
    }
}

impl From<SsdpMethod> for String {
    fn from(method: SsdpMethod) -> Self {
        match method {
            SsdpMethod::Notify => METHOD_NOTIFY.to_string(),
            SsdpMethod::MSearch => METHOD_M_SEARCH.to_string(),
            SsdpMethod::Unknown(method) => method,
        }
    }
}

/// Error returned when a candidate SSDP method is not an HTTP token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsdpMethodParseError {
    token: String,
}

impl SsdpMethodParseError {
    /// The rejected input.
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl fmt::Display for SsdpMethodParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid SSDP method token: {:?}", self.token)
    }
}

impl std::error::Error for SsdpMethodParseError {}

/// SSDP request-target token.
///
/// UPnP discovery uses the asterisk-form request target (`*`) for `NOTIFY` and
/// `M-SEARCH`. Other syntactically valid HTTP request targets are retained
/// verbatim so captures and explicit overrides are not normalized away.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpRequestTarget(String);

impl SsdpRequestTarget {
    /// Build the source-backed SSDP asterisk request target.
    pub fn asterisk() -> Self {
        Self(REQUEST_TARGET_ASTERISK.to_string())
    }

    /// Build a request target after validating HTTP start-line syntax.
    pub fn new(input: impl Into<String>) -> Result<Self, SsdpStartLineParseError> {
        let input = input.into();
        validate_request_target(&input)?;
        Ok(Self(input))
    }

    /// Return the wire request target.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return true when this is the UPnP-backed `*` request target.
    pub fn is_asterisk(&self) -> bool {
        self.0 == REQUEST_TARGET_ASTERISK
    }

    /// Consume the wrapper and return the preserved request-target string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SsdpRequestTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SsdpRequestTarget {
    type Err = SsdpStartLineParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        validate_request_target(input)?;
        Ok(Self(input.to_string()))
    }
}

impl TryFrom<&str> for SsdpRequestTarget {
    type Error = SsdpStartLineParseError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

impl TryFrom<String> for SsdpRequestTarget {
    type Error = SsdpStartLineParseError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        validate_request_target(&input)?;
        Ok(Self(input))
    }
}

impl From<SsdpRequestTarget> for String {
    fn from(target: SsdpRequestTarget) -> Self {
        target.0
    }
}

/// HTTP-version token used by SSDP start lines.
///
/// UPnP discovery uses `HTTP/1.1`; other syntactically valid HTTP-version
/// tokens are preserved as explicit or decoded values instead of being treated
/// as aliases.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpVersion(String);

impl SsdpVersion {
    /// Build the source-backed SSDP HTTP version token.
    pub fn http_1_1() -> Self {
        Self(HTTP_VERSION_1_1.to_string())
    }

    /// Build an HTTP-version token after validating RFC 9112 syntax.
    pub fn new(input: impl Into<String>) -> Result<Self, SsdpStartLineParseError> {
        let input = input.into();
        validate_http_version(&input)?;
        Ok(Self(input))
    }

    /// Return the wire HTTP-version token.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return true when this is the UPnP-backed `HTTP/1.1` version token.
    pub fn is_http_1_1(&self) -> bool {
        self.0 == HTTP_VERSION_1_1
    }

    /// Consume the wrapper and return the preserved HTTP-version string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SsdpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SsdpVersion {
    type Err = SsdpStartLineParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        validate_http_version(input)?;
        Ok(Self(input.to_string()))
    }
}

impl TryFrom<&str> for SsdpVersion {
    type Error = SsdpStartLineParseError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

impl TryFrom<String> for SsdpVersion {
    type Error = SsdpStartLineParseError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        validate_http_version(&input)?;
        Ok(Self(input))
    }
}

impl From<SsdpVersion> for String {
    fn from(version: SsdpVersion) -> Self {
        version.0
    }
}

/// SSDP status-line status code.
///
/// UPnP discovery names `200 OK` for search responses. Other three-digit HTTP
/// status codes are preserved as explicit or decoded values, including
/// unregistered or otherwise unusual codes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SsdpStatusCode(u16);

impl SsdpStatusCode {
    /// Build the source-backed SSDP OK status code.
    pub const fn ok() -> Self {
        Self(STATUS_OK)
    }

    /// Build a status code from a numeric value.
    pub fn new(code: u16) -> Result<Self, SsdpStartLineParseError> {
        validate_status_code_value(code)?;
        Ok(Self(code))
    }

    /// Return the numeric status code.
    pub const fn code(self) -> u16 {
        self.0
    }

    /// Return true when this is the UPnP-backed `200` response code.
    pub const fn is_ok(self) -> bool {
        self.0 == STATUS_OK
    }

    /// Return the UPnP-backed reason label for known SSDP status helpers.
    pub const fn default_reason(self) -> Option<&'static str> {
        match self.0 {
            STATUS_OK => Some(REASON_OK),
            _ => None,
        }
    }
}

impl fmt::Display for SsdpStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03}", self.0)
    }
}

impl FromStr for SsdpStatusCode {
    type Err = SsdpStartLineParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_status_code(input)
    }
}

impl TryFrom<&str> for SsdpStatusCode {
    type Error = SsdpStartLineParseError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

impl TryFrom<String> for SsdpStatusCode {
    type Error = SsdpStartLineParseError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        parse_status_code(&input)
    }
}

impl TryFrom<u16> for SsdpStatusCode {
    type Error = SsdpStartLineParseError;

    fn try_from(code: u16) -> Result<Self, Self::Error> {
        Self::new(code)
    }
}

impl From<SsdpStatusCode> for u16 {
    fn from(status: SsdpStatusCode) -> Self {
        status.0
    }
}

/// SSDP status-line reason phrase.
///
/// Reason phrases are display text in the HTTP status-line grammar. SSDP keeps
/// unusual but syntactically valid phrases verbatim rather than deriving
/// behavior from them.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpReasonPhrase(String);

impl SsdpReasonPhrase {
    /// Build the source-backed SSDP OK reason phrase.
    pub fn ok() -> Self {
        Self(REASON_OK.to_string())
    }

    /// Build an empty reason phrase.
    pub fn empty() -> Self {
        Self(String::new())
    }

    /// Build a reason phrase after validating HTTP status-line syntax.
    pub fn new(input: impl Into<String>) -> Result<Self, SsdpStartLineParseError> {
        let input = input.into();
        validate_reason_phrase(&input)?;
        Ok(Self(input))
    }

    /// Return the preserved reason phrase.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return true when this is the UPnP-backed `OK` reason phrase.
    pub fn is_ok(&self) -> bool {
        self.0 == REASON_OK
    }

    /// Consume the wrapper and return the preserved reason phrase string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SsdpReasonPhrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SsdpReasonPhrase {
    type Err = SsdpStartLineParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        validate_reason_phrase(input)?;
        Ok(Self(input.to_string()))
    }
}

impl TryFrom<&str> for SsdpReasonPhrase {
    type Error = SsdpStartLineParseError;

    fn try_from(input: &str) -> Result<Self, Self::Error> {
        input.parse()
    }
}

impl TryFrom<String> for SsdpReasonPhrase {
    type Error = SsdpStartLineParseError;

    fn try_from(input: String) -> Result<Self, Self::Error> {
        validate_reason_phrase(&input)?;
        Ok(Self(input))
    }
}

impl From<SsdpReasonPhrase> for String {
    fn from(reason: SsdpReasonPhrase) -> Self {
        reason.0
    }
}

/// Start-line field rejected by SSDP syntax validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SsdpStartLineField {
    /// HTTP request-target.
    RequestTarget,
    /// HTTP-version token.
    Version,
    /// Three-digit status code.
    StatusCode,
    /// Reason phrase.
    ReasonPhrase,
}

impl SsdpStartLineField {
    fn label(self) -> &'static str {
        match self {
            Self::RequestTarget => "request-target",
            Self::Version => "HTTP-version",
            Self::StatusCode => "status-code",
            Self::ReasonPhrase => "reason-phrase",
        }
    }
}

/// Error returned when an SSDP start-line wrapper receives invalid syntax.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsdpStartLineParseError {
    field: SsdpStartLineField,
    value: String,
    expected: &'static str,
}

impl SsdpStartLineParseError {
    fn new(field: SsdpStartLineField, value: impl Into<String>, expected: &'static str) -> Self {
        Self {
            field,
            value: value.into(),
            expected,
        }
    }

    /// The start-line field that failed validation.
    pub const fn field(&self) -> SsdpStartLineField {
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

impl fmt::Display for SsdpStartLineParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid SSDP {}: {:?} (expected {})",
            self.field.label(),
            self.value,
            self.expected
        )
    }
}

impl std::error::Error for SsdpStartLineParseError {}

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

fn validate_request_target(input: &str) -> Result<(), SsdpStartLineParseError> {
    if !input.is_empty() && input.bytes().all(is_request_target_byte) {
        return Ok(());
    }

    Err(SsdpStartLineParseError::new(
        SsdpStartLineField::RequestTarget,
        input,
        EXPECTED_REQUEST_TARGET,
    ))
}

fn is_request_target_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x7e)
}

fn validate_http_version(input: &str) -> Result<(), SsdpStartLineParseError> {
    let bytes = input.as_bytes();
    if bytes.len() == HTTP_VERSION_1_1.len()
        && bytes.starts_with(b"HTTP/")
        && bytes[5].is_ascii_digit()
        && bytes[6] == b'.'
        && bytes[7].is_ascii_digit()
    {
        return Ok(());
    }

    Err(SsdpStartLineParseError::new(
        SsdpStartLineField::Version,
        input,
        EXPECTED_HTTP_VERSION,
    ))
}

fn validate_status_code_value(code: u16) -> Result<(), SsdpStartLineParseError> {
    if code <= 999 {
        return Ok(());
    }

    Err(SsdpStartLineParseError::new(
        SsdpStartLineField::StatusCode,
        code.to_string(),
        EXPECTED_STATUS_CODE,
    ))
}

fn parse_status_code(input: &str) -> Result<SsdpStatusCode, SsdpStartLineParseError> {
    if input.len() != 3 || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SsdpStartLineParseError::new(
            SsdpStartLineField::StatusCode,
            input,
            EXPECTED_STATUS_CODE,
        ));
    }

    let code = input
        .bytes()
        .fold(0u16, |code, byte| code * 10 + u16::from(byte - b'0'));
    Ok(SsdpStatusCode(code))
}

fn validate_reason_phrase(input: &str) -> Result<(), SsdpStartLineParseError> {
    if input.bytes().all(is_reason_phrase_byte) {
        return Ok(());
    }

    Err(SsdpStartLineParseError::new(
        SsdpStartLineField::ReasonPhrase,
        input,
        EXPECTED_REASON_PHRASE,
    ))
}

fn is_reason_phrase_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | 0x21..=0x7e | 0x80..=0xff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssdp_method_known_tokens_map_to_named_variants() {
        assert_eq!("NOTIFY".parse::<SsdpMethod>(), Ok(SsdpMethod::Notify));
        assert_eq!("M-SEARCH".parse::<SsdpMethod>(), Ok(SsdpMethod::MSearch));
        assert_eq!(SsdpMethod::try_from("NOTIFY"), Ok(SsdpMethod::Notify));
        assert_eq!(SsdpMethod::try_from("M-SEARCH"), Ok(SsdpMethod::MSearch));
    }

    #[test]
    fn ssdp_method_unknown_tokens_preserve_original_spelling() {
        assert_eq!(
            "SEARCH".parse::<SsdpMethod>(),
            Ok(SsdpMethod::Unknown("SEARCH".to_string()))
        );
        assert_eq!(
            "m-search".parse::<SsdpMethod>(),
            Ok(SsdpMethod::Unknown("m-search".to_string()))
        );
        assert_eq!(
            "X_UPNP.EXPERIMENT".parse::<SsdpMethod>(),
            Ok(SsdpMethod::Unknown("X_UPNP.EXPERIMENT".to_string()))
        );
    }

    #[test]
    fn ssdp_method_invalid_syntax_is_rejected() {
        for invalid in [
            "",
            "M SEARCH",
            "M:SEARCH",
            "M/SEARCH",
            "NOTIFY\r",
            "m\u{e9}thod",
        ] {
            let error = SsdpMethod::try_from(invalid).expect_err("invalid method token");
            assert_eq!(error.token(), invalid);
        }
    }

    #[test]
    fn ssdp_method_display_uses_wire_token() {
        assert_eq!(SsdpMethod::notify().to_string(), "NOTIFY");
        assert_eq!(SsdpMethod::m_search().to_string(), "M-SEARCH");
        assert_eq!(
            SsdpMethod::Unknown("X-DEVICE".to_string()).to_string(),
            "X-DEVICE"
        );
    }

    #[test]
    fn ssdp_method_round_trip_conversion_preserves_valid_tokens() {
        for token in [
            "NOTIFY",
            "M-SEARCH",
            "SEARCH",
            "m-search",
            "X_UPNP.EXPERIMENT",
        ] {
            let method = SsdpMethod::try_from(token).expect("valid method token");
            let rendered = String::from(method.clone());

            assert_eq!(rendered, token);
            assert_eq!(SsdpMethod::try_from(rendered), Ok(method));
        }
    }

    #[test]
    fn ssdp_start_line_request_target_preserves_default_and_unknown_targets() {
        let asterisk = SsdpRequestTarget::asterisk();
        assert_eq!(asterisk.as_str(), "*");
        assert!(asterisk.is_asterisk());
        assert_eq!(asterisk.to_string(), "*");

        for target in [
            "/rootDesc.xml",
            "http://192.0.2.1/device.xml",
            "uuid:device-1",
        ] {
            let parsed = SsdpRequestTarget::try_from(target).expect("valid request-target");

            assert_eq!(parsed.as_str(), target);
            assert!(!parsed.is_asterisk());
            assert_eq!(String::from(parsed), target);
        }
    }

    #[test]
    fn ssdp_start_line_request_target_rejects_invalid_syntax() {
        for invalid in ["", "with space", "with\ttab", "bad\r", "bad\n", "caf\u{e9}"] {
            let error = SsdpRequestTarget::try_from(invalid).expect_err("invalid request-target");

            assert_eq!(error.field(), SsdpStartLineField::RequestTarget);
            assert_eq!(error.value(), invalid);
            assert_eq!(error.expected(), EXPECTED_REQUEST_TARGET);
        }
    }

    #[test]
    fn ssdp_start_line_http_version_preserves_unsupported_valid_versions() {
        let default = SsdpVersion::http_1_1();
        assert_eq!(default.as_str(), "HTTP/1.1");
        assert!(default.is_http_1_1());

        for version in ["HTTP/1.0", "HTTP/2.0", "HTTP/9.9"] {
            let parsed = SsdpVersion::try_from(version).expect("valid HTTP-version");

            assert_eq!(parsed.as_str(), version);
            assert!(!parsed.is_http_1_1());
            assert_eq!(String::from(parsed), version);
        }
    }

    #[test]
    fn ssdp_start_line_http_version_rejects_invalid_syntax() {
        for invalid in [
            "",
            "http/1.1",
            "HTTP/1",
            "HTTP/1.",
            "HTTP/1.10",
            "HTTP/10.1",
            "HTTP/1.A",
            "HTTP/1.1\r",
        ] {
            let error = SsdpVersion::try_from(invalid).expect_err("invalid HTTP-version");

            assert_eq!(error.field(), SsdpStartLineField::Version);
            assert_eq!(error.value(), invalid);
            assert_eq!(error.expected(), EXPECTED_HTTP_VERSION);
        }
    }

    #[test]
    fn ssdp_start_line_status_code_preserves_unknown_three_digit_codes() {
        let ok = SsdpStatusCode::ok();
        assert_eq!(ok.code(), 200);
        assert!(ok.is_ok());
        assert_eq!(ok.default_reason(), Some("OK"));
        assert_eq!(ok.to_string(), "200");

        for (wire, value) in [("000", 0), ("007", 7), ("599", 599), ("700", 700)] {
            let parsed = SsdpStatusCode::try_from(wire).expect("valid status-code");

            assert_eq!(parsed.code(), value);
            assert_eq!(u16::from(parsed), value);
            assert_eq!(parsed.to_string(), wire);
            assert_eq!(parsed.default_reason(), None);
        }
    }

    #[test]
    fn ssdp_start_line_status_code_rejects_invalid_syntax() {
        for invalid in ["", "20", "2000", "20A", " 200", "-01"] {
            let error = SsdpStatusCode::try_from(invalid).expect_err("invalid status-code");

            assert_eq!(error.field(), SsdpStartLineField::StatusCode);
            assert_eq!(error.value(), invalid);
            assert_eq!(error.expected(), EXPECTED_STATUS_CODE);
        }

        let error = SsdpStatusCode::try_from(1000u16).expect_err("invalid status-code");
        assert_eq!(error.field(), SsdpStartLineField::StatusCode);
        assert_eq!(error.value(), "1000");
        assert_eq!(error.expected(), EXPECTED_STATUS_CODE);
    }

    #[test]
    fn ssdp_start_line_reason_phrase_preserves_valid_text() {
        let ok = SsdpReasonPhrase::ok();
        assert_eq!(ok.as_str(), "OK");
        assert!(ok.is_ok());

        for phrase in ["", "OK", "I am a teapot", "tabs\tallowed", "caf\u{e9}"] {
            let parsed = SsdpReasonPhrase::try_from(phrase).expect("valid reason-phrase");

            assert_eq!(parsed.as_str(), phrase);
            assert_eq!(parsed.to_string(), phrase);
            assert_eq!(String::from(parsed), phrase);
        }
    }

    #[test]
    fn ssdp_start_line_reason_phrase_rejects_line_controls() {
        for invalid in ["bad\r", "bad\n", "bad\0", "bad\u{7f}"] {
            let error = SsdpReasonPhrase::try_from(invalid).expect_err("invalid reason-phrase");

            assert_eq!(error.field(), SsdpStartLineField::ReasonPhrase);
            assert_eq!(error.value(), invalid);
            assert_eq!(error.expected(), EXPECTED_REASON_PHRASE);
        }
    }
}
