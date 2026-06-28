//! SSDP message model.
//!
//! SSDP messages are HTTP-like UDP payloads with one start line, ordered
//! headers, and opaque body bytes.

use core::fmt;
use core::str::FromStr;

use crate::error::Result as CrafterResult;
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::protocols::transport::Udp;

use super::constants::{
    SSDP_HEADER_EXT, SSDP_HEADER_HOST, SSDP_HEADER_MAN, SSDP_HEADER_MX, SSDP_HEADER_NT,
    SSDP_HEADER_NTS, SSDP_HEADER_ST, SSDP_HEADER_USN, SSDP_HTTP_VERSION as HTTP_VERSION_1_1,
    SSDP_IPV4_MULTICAST_HOST, SSDP_MAN_DISCOVER, SSDP_METHOD_M_SEARCH as METHOD_M_SEARCH,
    SSDP_METHOD_NOTIFY as METHOD_NOTIFY, SSDP_NTS_ALIVE, SSDP_NTS_BYEBYE, SSDP_NTS_UPDATE,
    SSDP_REASON_OK as REASON_OK, SSDP_STATUS_OK as STATUS_OK, SSDP_ST_ALL, SSDP_TARGET_ROOTDEVICE,
    SSDP_UDP_PORT,
};
use super::header::{SsdpHeaderNameKind, SsdpHeaderNameParseError, SsdpHeaderValue, SsdpHeaders};

const REQUEST_TARGET_ASTERISK: &str = "*";
const CRLF: &[u8; 2] = b"\r\n";

const EXPECTED_REQUEST_TARGET: &str =
    "non-empty HTTP request-target with visible ASCII bytes and no whitespace";
const EXPECTED_HTTP_VERSION: &str = "HTTP-version token formatted as HTTP/<DIGIT>.<DIGIT>";
const EXPECTED_STATUS_CODE: &str = "three decimal digits";
const EXPECTED_REASON_PHRASE: &str = "HTTP reason-phrase bytes: HTAB, SP, VCHAR, or obs-text";

/// SSDP UDP application layer message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ssdp {
    message: SsdpMessage,
}

impl Ssdp {
    /// Build an SSDP layer from an already assembled message.
    pub fn new(message: SsdpMessage) -> Self {
        Self { message }
    }

    /// Build a source-backed `M-SEARCH * HTTP/1.1` request.
    pub fn m_search() -> Self {
        Self::new(SsdpMessage::m_search())
    }

    /// Build a source-backed `M-SEARCH` request for `ssdp:all`.
    pub fn m_search_all() -> Self {
        Self::m_search().with_search_defaults_for(SSDP_ST_ALL)
    }

    /// Build a source-backed `M-SEARCH` request for `upnp:rootdevice`.
    pub fn m_search_rootdevice() -> Self {
        Self::m_search().with_search_defaults_for(SSDP_TARGET_ROOTDEVICE)
    }

    /// Build a source-backed `NOTIFY * HTTP/1.1` request.
    pub fn notify() -> Self {
        Self::new(SsdpMessage::notify())
    }

    /// Build a source-backed `NOTIFY` request with `NTS: ssdp:alive`.
    pub fn notify_alive() -> Self {
        Self::notify().with_notify_defaults_for(SSDP_NTS_ALIVE)
    }

    /// Build a source-backed `NOTIFY` request with `NTS: ssdp:byebye`.
    pub fn notify_byebye() -> Self {
        Self::notify().with_notify_defaults_for(SSDP_NTS_BYEBYE)
    }

    /// Build a source-backed `NOTIFY` request with `NTS: ssdp:update`.
    pub fn notify_update() -> Self {
        Self::notify().with_notify_defaults_for(SSDP_NTS_UPDATE)
    }

    /// Build a source-backed `HTTP/1.1 200 OK` response.
    pub fn response_ok() -> Self {
        Self::new(SsdpMessage::response_ok())
    }

    /// Build a source-backed `HTTP/1.1 200 OK` response with an empty `EXT`.
    pub fn response_ok_with_ext() -> Self {
        Self::response_ok().with_source_header(SSDP_HEADER_EXT, SsdpHeaderValue::empty())
    }

    /// Build a response using a caller-supplied three-digit status and reason.
    pub fn response_with_status(
        code: u16,
        reason: impl Into<String>,
    ) -> Result<Self, SsdpStartLineParseError> {
        Ok(Self::response(
            SsdpVersion::http_1_1(),
            SsdpStatusCode::try_from(code)?,
            SsdpReasonPhrase::try_from(reason.into())?,
        ))
    }

    /// Build a UDP header for SSDP's source-backed `ssdp/udp` service port.
    ///
    /// The source and destination ports start at `1900`; callers can still
    /// override either value with `sport` or `dport` before composing a packet.
    pub fn udp() -> Udp {
        Udp::new()
            .source_port(SSDP_UDP_PORT)
            .destination_port(SSDP_UDP_PORT)
    }

    /// Build a request message from explicit start-line values.
    pub fn request(method: SsdpMethod, target: SsdpRequestTarget, version: SsdpVersion) -> Self {
        Self::new(SsdpMessage::request(method, target, version))
    }

    /// Build a response message from explicit status-line values.
    pub fn response(version: SsdpVersion, code: SsdpStatusCode, reason: SsdpReasonPhrase) -> Self {
        Self::new(SsdpMessage::response(version, code, reason))
    }

    /// Return the owned SSDP message.
    pub fn message(&self) -> &SsdpMessage {
        &self.message
    }

    /// Return the ordered SSDP headers.
    pub fn headers(&self) -> &SsdpHeaders {
        self.message.headers()
    }

    /// Return the opaque body bytes.
    pub fn body(&self) -> &[u8] {
        self.message.body()
    }

    /// Serialize this SSDP layer as one UDP payload.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        self.message.serialize(out);
    }

    /// Return this SSDP layer serialized as one UDP payload.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize(&mut out);
        out
    }

    /// Consume the layer and return the message.
    pub fn into_message(self) -> SsdpMessage {
        self.message
    }

    /// Append a raw header, preserving insertion order and caller spelling.
    pub fn with_raw_header(
        mut self,
        name: impl Into<String>,
        value: impl Into<SsdpHeaderValue>,
    ) -> Result<Self, SsdpHeaderNameParseError> {
        self.message.push_raw_header(name, value)?;
        Ok(self)
    }

    /// Fill missing source-backed M-SEARCH headers for `ssdp:all`.
    pub fn with_search_defaults(self) -> Self {
        self.with_search_defaults_for(SSDP_ST_ALL)
    }

    /// Append an explicit `HOST` header.
    pub fn host(self, value: impl Into<SsdpHeaderValue>) -> Self {
        self.with_source_header(SSDP_HEADER_HOST, value)
    }

    /// Append an explicit `MAN: "ssdp:discover"` header.
    pub fn man_discover(self) -> Self {
        self.with_source_header(SSDP_HEADER_MAN, SSDP_MAN_DISCOVER)
    }

    /// Append an explicit `MX` header.
    pub fn mx(self, seconds: u32) -> Self {
        self.with_source_header(SSDP_HEADER_MX, seconds.to_string())
    }

    /// Append an explicit `ST` search target header.
    pub fn search_target(self, value: impl Into<SsdpHeaderValue>) -> Self {
        self.with_source_header(SSDP_HEADER_ST, value)
    }

    /// Append an explicit `NT` notification type header.
    pub fn notification_type(self, value: impl Into<SsdpHeaderValue>) -> Self {
        self.with_source_header(SSDP_HEADER_NT, value)
    }

    /// Append an explicit `NTS` notification subtype header.
    pub fn notification_subtype(self, value: impl Into<SsdpHeaderValue>) -> Self {
        self.with_source_header(SSDP_HEADER_NTS, value)
    }

    /// Append an explicit `USN` unique service name header.
    pub fn unique_service_name(self, value: impl Into<SsdpHeaderValue>) -> Self {
        self.with_source_header(SSDP_HEADER_USN, value)
    }

    /// Replace the opaque body bytes with caller-supplied bytes.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.message = self.message.with_body(body);
        self
    }

    fn with_search_defaults_for(self, target: impl Into<SsdpHeaderValue>) -> Self {
        self.with_source_default_header(
            SsdpHeaderNameKind::Host,
            SSDP_HEADER_HOST,
            SSDP_IPV4_MULTICAST_HOST,
        )
        .with_source_default_header(SsdpHeaderNameKind::Man, SSDP_HEADER_MAN, SSDP_MAN_DISCOVER)
        .with_source_default_header(SsdpHeaderNameKind::Mx, SSDP_HEADER_MX, "1")
        .with_source_default_header(SsdpHeaderNameKind::St, SSDP_HEADER_ST, target)
    }

    fn with_notify_defaults_for(self, subtype: impl Into<SsdpHeaderValue>) -> Self {
        self.with_source_default_header(
            SsdpHeaderNameKind::Host,
            SSDP_HEADER_HOST,
            SSDP_IPV4_MULTICAST_HOST,
        )
        .with_source_default_header(SsdpHeaderNameKind::Nts, SSDP_HEADER_NTS, subtype)
    }

    fn with_source_default_header(
        self,
        kind: SsdpHeaderNameKind,
        name: &'static str,
        value: impl Into<SsdpHeaderValue>,
    ) -> Self {
        if self.headers().get_first(kind).is_some() {
            return self;
        }

        self.with_source_header(name, value)
    }

    fn with_source_header(mut self, name: &'static str, value: impl Into<SsdpHeaderValue>) -> Self {
        self.message
            .push_raw_header(name, value)
            .expect("source-backed SSDP header name is valid");
        self
    }
}

impl Layer for Ssdp {
    fn name(&self) -> &'static str {
        "SSDP"
    }

    fn summary(&self) -> String {
        format!(
            "SSDP({}=\"{}\", headers={}, body={} bytes)",
            self.message.start_line().kind_label(),
            self.message.start_line().display_line(),
            self.headers().len(),
            self.body().len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("kind", self.message.start_line().kind_label().to_string()),
            ("start_line", self.message.start_line().display_line()),
            ("header_count", self.headers().len().to_string()),
            ("header_names", header_names_summary(self.headers())),
            ("body_len", self.body().len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.to_bytes().len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> CrafterResult<()> {
        self.serialize(out);
        Ok(())
    }

    impl_layer_object!(Ssdp);
}

impl_layer_div!(Ssdp);

/// Complete SSDP message payload model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsdpMessage {
    start_line: SsdpStartLine,
    headers: SsdpHeaders,
    body: Vec<u8>,
}

impl SsdpMessage {
    /// Build a header-empty message with an empty body.
    pub fn new(start_line: SsdpStartLine) -> Self {
        Self {
            start_line,
            headers: SsdpHeaders::new(),
            body: Vec::new(),
        }
    }

    /// Build a source-backed `M-SEARCH * HTTP/1.1` request message.
    pub fn m_search() -> Self {
        Self::new(SsdpStartLine::m_search())
    }

    /// Build a source-backed `NOTIFY * HTTP/1.1` request message.
    pub fn notify() -> Self {
        Self::new(SsdpStartLine::notify())
    }

    /// Build a source-backed `HTTP/1.1 200 OK` response message.
    pub fn response_ok() -> Self {
        Self::new(SsdpStartLine::response_ok())
    }

    /// Build a request message from explicit start-line values.
    pub fn request(method: SsdpMethod, target: SsdpRequestTarget, version: SsdpVersion) -> Self {
        Self::new(SsdpStartLine::Request(SsdpRequestLine::new(
            method, target, version,
        )))
    }

    /// Build a response message from explicit status-line values.
    pub fn response(version: SsdpVersion, code: SsdpStatusCode, reason: SsdpReasonPhrase) -> Self {
        Self::new(SsdpStartLine::Response(SsdpStatusLine::new(
            version, code, reason,
        )))
    }

    /// Return the preserved start line.
    pub fn start_line(&self) -> &SsdpStartLine {
        &self.start_line
    }

    /// Return the ordered header collection.
    pub fn headers(&self) -> &SsdpHeaders {
        &self.headers
    }

    /// Return the opaque body bytes.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Serialize this message as an SSDP UDP payload.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        self.start_line.serialize(out);
        self.headers.serialize(out);
        out.extend_from_slice(CRLF);
        out.extend_from_slice(&self.body);
    }

    /// Consume the message and return its parts.
    pub fn into_parts(self) -> (SsdpStartLine, SsdpHeaders, Vec<u8>) {
        (self.start_line, self.headers, self.body)
    }

    /// Append a raw header, preserving order and duplicate entries.
    pub fn push_raw_header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<SsdpHeaderValue>,
    ) -> Result<(), SsdpHeaderNameParseError> {
        self.headers.push_raw(name, value)
    }

    /// Replace the opaque body bytes with caller-supplied bytes.
    pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
}

/// SSDP start line.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SsdpStartLine {
    /// Request-line form: `method SP request-target SP HTTP-version`.
    Request(SsdpRequestLine),
    /// Status-line form: `HTTP-version SP status-code SP reason-phrase`.
    Response(SsdpStatusLine),
}

impl SsdpStartLine {
    /// Build a source-backed `M-SEARCH * HTTP/1.1` request line.
    pub fn m_search() -> Self {
        Self::Request(SsdpRequestLine::m_search())
    }

    /// Build a source-backed `NOTIFY * HTTP/1.1` request line.
    pub fn notify() -> Self {
        Self::Request(SsdpRequestLine::notify())
    }

    /// Build a source-backed `HTTP/1.1 200 OK` status line.
    pub fn response_ok() -> Self {
        Self::Response(SsdpStatusLine::ok())
    }

    /// Return the request line when this is a request.
    pub fn as_request(&self) -> Option<&SsdpRequestLine> {
        match self {
            Self::Request(line) => Some(line),
            Self::Response(_) => None,
        }
    }

    /// Return the status line when this is a response.
    pub fn as_response(&self) -> Option<&SsdpStatusLine> {
        match self {
            Self::Request(_) => None,
            Self::Response(line) => Some(line),
        }
    }

    /// Serialize this start line and its trailing CRLF.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        match self {
            Self::Request(line) => line.serialize(out),
            Self::Response(line) => line.serialize(out),
        }
    }

    fn kind_label(&self) -> &'static str {
        match self {
            Self::Request(_) => "request",
            Self::Response(_) => "response",
        }
    }

    fn display_line(&self) -> String {
        match self {
            Self::Request(line) => {
                format!("{} {} {}", line.method(), line.target(), line.version())
            }
            Self::Response(line) => {
                format!("{} {} {}", line.version(), line.code(), line.reason())
            }
        }
    }
}

/// SSDP request-line values.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpRequestLine {
    method: SsdpMethod,
    target: SsdpRequestTarget,
    version: SsdpVersion,
}

impl SsdpRequestLine {
    /// Build a request line from explicit values.
    pub fn new(method: SsdpMethod, target: SsdpRequestTarget, version: SsdpVersion) -> Self {
        Self {
            method,
            target,
            version,
        }
    }

    /// Build a source-backed `M-SEARCH * HTTP/1.1` request line.
    pub fn m_search() -> Self {
        Self::new(
            SsdpMethod::m_search(),
            SsdpRequestTarget::asterisk(),
            SsdpVersion::http_1_1(),
        )
    }

    /// Build a source-backed `NOTIFY * HTTP/1.1` request line.
    pub fn notify() -> Self {
        Self::new(
            SsdpMethod::notify(),
            SsdpRequestTarget::asterisk(),
            SsdpVersion::http_1_1(),
        )
    }

    /// Return the method token.
    pub fn method(&self) -> &SsdpMethod {
        &self.method
    }

    /// Return the request target.
    pub fn target(&self) -> &SsdpRequestTarget {
        &self.target
    }

    /// Return the HTTP-version token.
    pub fn version(&self) -> &SsdpVersion {
        &self.version
    }

    /// Serialize this request line and its trailing CRLF.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.method.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.target.as_str().as_bytes());
        out.push(b' ');
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.extend_from_slice(CRLF);
    }
}

/// SSDP status-line values.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpStatusLine {
    version: SsdpVersion,
    code: SsdpStatusCode,
    reason: SsdpReasonPhrase,
}

impl SsdpStatusLine {
    /// Build a status line from explicit values.
    pub fn new(version: SsdpVersion, code: SsdpStatusCode, reason: SsdpReasonPhrase) -> Self {
        Self {
            version,
            code,
            reason,
        }
    }

    /// Build a source-backed `HTTP/1.1 200 OK` status line.
    pub fn ok() -> Self {
        Self::new(
            SsdpVersion::http_1_1(),
            SsdpStatusCode::ok(),
            SsdpReasonPhrase::ok(),
        )
    }

    /// Return the HTTP-version token.
    pub fn version(&self) -> &SsdpVersion {
        &self.version
    }

    /// Return the status code.
    pub const fn code(&self) -> SsdpStatusCode {
        self.code
    }

    /// Return the reason phrase.
    pub fn reason(&self) -> &SsdpReasonPhrase {
        &self.reason
    }

    /// Serialize this status line and its trailing CRLF.
    pub fn serialize(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.version.as_str().as_bytes());
        out.push(b' ');
        serialize_status_code(self.code, out);
        out.push(b' ');
        out.extend_from_slice(self.reason.as_str().as_bytes());
        out.extend_from_slice(CRLF);
    }
}

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

/// SSDP target value used by `ST` and `NT` headers.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpTarget(String);

impl SsdpTarget {
    /// Build the source-backed `ssdp:all` search target.
    pub fn all() -> Self {
        Self(SSDP_ST_ALL.to_string())
    }

    /// Build the source-backed `upnp:rootdevice` target.
    pub fn rootdevice() -> Self {
        Self(SSDP_TARGET_ROOTDEVICE.to_string())
    }

    /// Build a source-backed UUID target.
    pub fn uuid(device_uuid: impl Into<String>) -> Self {
        Self(format!("uuid:{}", device_uuid.into()))
    }

    /// Build a UPnP Forum device type target.
    pub fn upnp_device_type(device_type: impl Into<String>, version: u32) -> Self {
        source_target("schemas-upnp-org", "device", device_type, version)
    }

    /// Build a UPnP Forum service type target.
    pub fn upnp_service_type(service_type: impl Into<String>, version: u32) -> Self {
        source_target("schemas-upnp-org", "service", service_type, version)
    }

    /// Build a vendor device type target.
    pub fn vendor_device_type(
        domain: impl Into<String>,
        device_type: impl Into<String>,
        version: u32,
    ) -> Self {
        source_target(domain, "device", device_type, version)
    }

    /// Build a vendor service type target.
    pub fn vendor_service_type(
        domain: impl Into<String>,
        service_type: impl Into<String>,
        version: u32,
    ) -> Self {
        source_target(domain, "service", service_type, version)
    }

    /// Preserve a caller-supplied target value.
    pub fn raw(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return the preserved target bytes as UTF-8 text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the preserved target string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SsdpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for SsdpTarget {
    fn from(value: String) -> Self {
        Self::raw(value)
    }
}

impl From<&str> for SsdpTarget {
    fn from(value: &str) -> Self {
        Self::raw(value)
    }
}

impl From<SsdpTarget> for String {
    fn from(target: SsdpTarget) -> Self {
        target.0
    }
}

impl From<SsdpTarget> for SsdpHeaderValue {
    fn from(target: SsdpTarget) -> Self {
        Self::from(target.0)
    }
}

/// SSDP unique service name value used by the `USN` header.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SsdpUsn(String);

impl SsdpUsn {
    /// Build a UUID-only USN.
    pub fn uuid(device_uuid: impl Into<String>) -> Self {
        Self(format!("uuid:{}", device_uuid.into()))
    }

    /// Build a root-device USN.
    pub fn rootdevice(device_uuid: impl Into<String>) -> Self {
        Self::target(device_uuid, SsdpTarget::rootdevice())
    }

    /// Build a UUID plus target USN.
    pub fn target(device_uuid: impl Into<String>, target: impl Into<SsdpTarget>) -> Self {
        let target = target.into();
        Self(format!("uuid:{}::{}", device_uuid.into(), target.as_str()))
    }

    /// Preserve a caller-supplied USN value.
    pub fn raw(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Return the preserved USN bytes as UTF-8 text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume the wrapper and return the preserved USN string.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for SsdpUsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<String> for SsdpUsn {
    fn from(value: String) -> Self {
        Self::raw(value)
    }
}

impl From<&str> for SsdpUsn {
    fn from(value: &str) -> Self {
        Self::raw(value)
    }
}

impl From<SsdpUsn> for String {
    fn from(usn: SsdpUsn) -> Self {
        usn.0
    }
}

impl From<SsdpUsn> for SsdpHeaderValue {
    fn from(usn: SsdpUsn) -> Self {
        Self::from(usn.0)
    }
}

fn source_target(
    domain: impl Into<String>,
    kind: &'static str,
    type_name: impl Into<String>,
    version: u32,
) -> SsdpTarget {
    SsdpTarget(format!(
        "urn:{}:{kind}:{}:{version}",
        domain.into(),
        type_name.into()
    ))
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

fn serialize_status_code(code: SsdpStatusCode, out: &mut Vec<u8>) {
    let code = code.code();
    out.push(b'0' + ((code / 100) as u8));
    out.push(b'0' + (((code / 10) % 10) as u8));
    out.push(b'0' + ((code % 10) as u8));
}

fn header_names_summary(headers: &SsdpHeaders) -> String {
    const MAX_NAMES: usize = 8;

    let mut names = headers
        .iter()
        .take(MAX_NAMES)
        .map(|header| header.name().original())
        .collect::<Vec<_>>()
        .join(", ");

    let remaining = headers.len().saturating_sub(MAX_NAMES);
    if remaining > 0 {
        if !names.is_empty() {
            names.push_str(", ");
        }
        names.push_str(&format!("+{remaining} more"));
    }

    names
}

#[cfg(test)]
mod tests {
    use super::super::decode::decode_ssdp;
    use super::super::header::{SsdpHeaderField, SsdpHeaderNameKind, SsdpHeaderValue};
    use super::*;
    use crate::checksum::{ipv4_header_checksum, ipv4_pseudo_header_checksum};
    use crate::packet::{Layer, Packet};
    use crate::protocols::ip::shared::IPPROTO_UDP;
    use crate::protocols::ip::v4::Ipv4;
    use crate::protocols::transport::{Udp, UDP_HEADER_LEN};
    use core::net::Ipv4Addr;

    fn packet_composition_src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn packet_composition_dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn packet_composition_message() -> Ssdp {
        Ssdp::m_search()
            .with_raw_header("HOST", "239.255.255.250:1900")
            .expect("HOST header")
            .with_raw_header("MAN", "\"ssdp:discover\"")
            .expect("MAN header")
            .with_raw_header("MX", "1")
            .expect("MX header")
            .with_raw_header("ST", "ssdp:all")
            .expect("ST header")
    }

    fn packet_composition_udp_checksum(bytes: &[u8], payload_len: usize) -> u16 {
        let udp_start = 20;
        let udp_end = udp_start + UDP_HEADER_LEN + payload_len;
        let mut udp = bytes[udp_start..udp_end].to_vec();
        udp[6] = 0;
        udp[7] = 0;
        let checksum = ipv4_pseudo_header_checksum(
            packet_composition_src(),
            packet_composition_dst(),
            IPPROTO_UDP,
            &udp,
        );

        if checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    #[test]
    fn ssdp_packet_composition_udp_div_builds_typed_packet_and_payload() {
        let ssdp = packet_composition_message();
        let payload = ssdp.to_bytes();
        let packet = Udp::new().sport(49_152).dport(1_900) / ssdp.clone();

        assert_eq!(packet.layer::<Ssdp>(), Some(&ssdp));
        assert!(packet.layer::<Udp>().is_some());
        assert_eq!(packet.encoded_len(), UDP_HEADER_LEN + payload.len());

        let compiled = packet.compile().expect("udp/ssdp stack compiles");
        let bytes = compiled.as_bytes();

        assert_eq!(&bytes[0..2], &49_152u16.to_be_bytes());
        assert_eq!(&bytes[2..4], &1_900u16.to_be_bytes());
        assert_eq!(
            &bytes[4..6],
            &((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes()
        );
        assert_eq!(&bytes[6..8], &0u16.to_be_bytes());
        assert_eq!(&bytes[UDP_HEADER_LEN..], payload.as_slice());
    }

    #[test]
    fn ssdp_packet_composition_ipv4_udp_autofills_lengths_and_checksums() {
        let ssdp = packet_composition_message();
        let payload = ssdp.to_bytes();
        let packet = Ipv4::new()
            .src(packet_composition_src())
            .dst(packet_composition_dst())
            .id(0x5d50)
            / Udp::new().sport(49_152).dport(1_900)
            / ssdp.clone();

        assert_eq!(packet.layer::<Ssdp>(), Some(&ssdp));
        assert!(packet.layer::<Ipv4>().is_some());
        assert!(packet.layer::<Udp>().is_some());

        let compiled = packet.compile().expect("ipv4/udp/ssdp stack compiles");
        let bytes = compiled.as_bytes();
        let expected_total_len = 20 + UDP_HEADER_LEN + payload.len();

        assert_eq!(bytes.len(), expected_total_len);
        assert_eq!(&bytes[2..4], &(expected_total_len as u16).to_be_bytes());
        assert_eq!(bytes[9], IPPROTO_UDP);

        let mut ipv4_header = bytes[..20].to_vec();
        let transmitted_ip_checksum = u16::from_be_bytes([bytes[10], bytes[11]]);
        ipv4_header[10] = 0;
        ipv4_header[11] = 0;
        assert_eq!(transmitted_ip_checksum, ipv4_header_checksum(&ipv4_header));
        assert_eq!(ipv4_header_checksum(&bytes[..20]), 0);

        assert_eq!(&bytes[20..22], &49_152u16.to_be_bytes());
        assert_eq!(&bytes[22..24], &1_900u16.to_be_bytes());
        assert_eq!(
            &bytes[24..26],
            &((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes()
        );
        assert_eq!(
            u16::from_be_bytes([bytes[26], bytes[27]]),
            packet_composition_udp_checksum(bytes, payload.len())
        );
        assert_eq!(&bytes[20 + UDP_HEADER_LEN..], payload.as_slice());
    }

    #[test]
    fn ssdp_packet_composition_decode_compiled_udp_payload_explicitly() {
        let ssdp = packet_composition_message().with_body(b"opaque-body".to_vec());
        let packet = Ipv4::new()
            .src(packet_composition_src())
            .dst(packet_composition_dst())
            / Udp::new().sport(49_152).dport(1_900)
            / ssdp.clone();
        let compiled = packet.compile().expect("ipv4/udp/ssdp stack compiles");
        let payload = &compiled.as_bytes()[20 + UDP_HEADER_LEN..];

        assert_eq!(payload, ssdp.to_bytes().as_slice());
        assert_eq!(
            decode_ssdp(payload).expect("compiled SSDP payload decodes"),
            ssdp
        );
    }

    #[test]
    fn ssdp_udp_helpers_default_to_source_backed_service_port() {
        let udp = Ssdp::udp();

        assert_eq!(udp.source_port_value(), SSDP_UDP_PORT);
        assert_eq!(udp.destination_port_value(), SSDP_UDP_PORT);

        let ssdp = packet_composition_message();
        let packet = Ipv4::new()
            .src(packet_composition_src())
            .dst(packet_composition_dst())
            / Ssdp::udp()
            / ssdp.clone();

        assert_eq!(packet.layer::<Ssdp>(), Some(&ssdp));
        let packet_udp = packet.layer::<Udp>().expect("UDP layer");
        assert_eq!(packet_udp.source_port_value(), SSDP_UDP_PORT);
        assert_eq!(packet_udp.destination_port_value(), SSDP_UDP_PORT);

        let compiled = packet.compile().expect("ipv4/udp/ssdp stack compiles");
        let bytes = compiled.as_bytes();
        assert_eq!(&bytes[20..22], &SSDP_UDP_PORT.to_be_bytes());
        assert_eq!(&bytes[22..24], &SSDP_UDP_PORT.to_be_bytes());
    }

    #[test]
    fn ssdp_udp_helpers_preserve_explicit_source_and_destination_port_overrides() {
        let source_port = 49_153;
        let destination_port = 49_154;
        let udp = Ssdp::udp().sport(source_port).dport(destination_port);

        assert_eq!(udp.source_port_value(), source_port);
        assert_eq!(udp.destination_port_value(), destination_port);

        let ssdp = packet_composition_message();
        let packet = Ipv4::new()
            .src(packet_composition_src())
            .dst(packet_composition_dst())
            / udp
            / ssdp.clone();

        assert_eq!(packet.layer::<Ssdp>(), Some(&ssdp));
        let packet_udp = packet.layer::<Udp>().expect("UDP layer");
        assert_eq!(packet_udp.source_port_value(), source_port);
        assert_eq!(packet_udp.destination_port_value(), destination_port);

        let compiled = packet.compile().expect("ipv4/udp/ssdp stack compiles");
        let bytes = compiled.as_bytes();
        assert_eq!(&bytes[20..22], &source_port.to_be_bytes());
        assert_eq!(&bytes[22..24], &destination_port.to_be_bytes());
    }

    #[test]
    fn ssdp_message_builders_m_search_and_notify_request_defaults() {
        for (message, expected_method) in [
            (Ssdp::m_search(), SsdpMethod::MSearch),
            (Ssdp::notify(), SsdpMethod::Notify),
        ] {
            let request = message
                .message()
                .start_line()
                .as_request()
                .expect("request start line");

            assert_eq!(request.method(), &expected_method);
            assert_eq!(request.target().as_str(), "*");
            assert!(request.target().is_asterisk());
            assert_eq!(request.version().as_str(), "HTTP/1.1");
            assert!(request.version().is_http_1_1());
            assert!(message.headers().is_empty());
            assert!(message.body().is_empty());
        }
    }

    #[test]
    fn ssdp_message_builders_request_accepts_explicit_unknown_valid_values() {
        let method = SsdpMethod::try_from("X-SEARCH").expect("valid unknown method");
        let target = SsdpRequestTarget::try_from("/device.xml").expect("valid target");
        let version = SsdpVersion::try_from("HTTP/1.0").expect("valid version");

        let message = Ssdp::request(method.clone(), target.clone(), version.clone());
        let request = message
            .message()
            .start_line()
            .as_request()
            .expect("request start line");

        assert_eq!(request.method(), &method);
        assert_eq!(request.target(), &target);
        assert_eq!(request.version(), &version);
    }

    #[test]
    fn ssdp_message_builders_response_ok_defaults() {
        let response = Ssdp::response_ok();
        let status = response
            .message()
            .start_line()
            .as_response()
            .expect("response start line");

        assert_eq!(status.version().as_str(), "HTTP/1.1");
        assert!(status.version().is_http_1_1());
        assert_eq!(status.code(), SsdpStatusCode::ok());
        assert_eq!(status.code().code(), 200);
        assert_eq!(status.reason().as_str(), "OK");
        assert!(status.reason().is_ok());
        assert!(response.headers().is_empty());
        assert!(response.body().is_empty());
    }

    #[test]
    fn ssdp_message_builders_response_accepts_explicit_unknown_valid_values() {
        let version = SsdpVersion::try_from("HTTP/1.0").expect("valid version");
        let code = SsdpStatusCode::try_from("299").expect("valid status code");
        let reason = SsdpReasonPhrase::try_from("Odd Success").expect("valid reason");

        let message = Ssdp::response(version.clone(), code, reason.clone());
        let status = message
            .message()
            .start_line()
            .as_response()
            .expect("response start line");

        assert_eq!(status.version(), &version);
        assert_eq!(status.code(), code);
        assert_eq!(status.reason(), &reason);
    }

    #[test]
    fn ssdp_message_builders_raw_headers_preserve_order_and_unknown_names() {
        let message = Ssdp::m_search()
            .with_raw_header("X-DEVICE.UPNP.ORG", "opaque")
            .expect("unknown header")
            .with_raw_header("HOST", "239.255.255.250:1900")
            .expect("host header")
            .with_raw_header("x-device.upnp.org", b"second")
            .expect("second unknown header");

        let entries = message.headers().iter().collect::<Vec<_>>();

        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[0].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[0].value().as_bytes(), b"opaque");
        assert_eq!(entries[1].name().kind(), SsdpHeaderNameKind::Host);
        assert_eq!(entries[1].name().original(), "HOST");
        assert_eq!(entries[2].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[2].name().original(), "x-device.upnp.org");
        assert_eq!(entries[2].value().as_bytes(), b"second");
    }

    #[test]
    fn ssdp_message_builders_body_bytes_are_preserved() {
        let body = vec![0x00, b'\r', b'\n', 0xff, b':', b' '];
        let message = Ssdp::notify().with_body(body.clone());

        assert_eq!(message.body(), body.as_slice());

        let (_, _, preserved_body) = message.into_message().into_parts();
        assert_eq!(preserved_body, body);
    }

    #[test]
    fn ssdp_message_builders_invalid_raw_header_name_returns_header_parse_error() {
        let error = Ssdp::m_search()
            .with_raw_header("bad name", "value")
            .expect_err("invalid raw header name");

        assert_eq!(error.field(), SsdpHeaderField::Name);
        assert_eq!(error.value(), "bad name");
    }

    #[test]
    fn ssdp_search_builders_m_search_all_defaults_source_backed_headers() {
        let message = Ssdp::m_search_all();
        let request = message
            .message()
            .start_line()
            .as_request()
            .expect("M-SEARCH request line");
        let headers = message.headers().iter().collect::<Vec<_>>();

        assert_eq!(request.method(), &SsdpMethod::MSearch);
        assert_eq!(request.target().as_str(), "*");
        assert_eq!(request.version().as_str(), HTTP_VERSION_1_1);
        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].name().original(), SSDP_HEADER_HOST);
        assert_eq!(
            headers[0].value().as_bytes(),
            SSDP_IPV4_MULTICAST_HOST.as_bytes()
        );
        assert_eq!(headers[1].name().original(), SSDP_HEADER_MAN);
        assert_eq!(headers[1].value().as_bytes(), SSDP_MAN_DISCOVER.as_bytes());
        assert_eq!(headers[2].name().original(), SSDP_HEADER_MX);
        assert_eq!(headers[2].value().as_bytes(), b"1");
        assert_eq!(headers[3].name().original(), SSDP_HEADER_ST);
        assert_eq!(headers[3].value().as_bytes(), SSDP_ST_ALL.as_bytes());
        assert_eq!(
            message.to_bytes(),
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
        );
    }

    #[test]
    fn ssdp_search_builders_m_search_rootdevice_defaults_source_backed_target() {
        let message = Ssdp::m_search_rootdevice();
        let st = message
            .headers()
            .get_first(SsdpHeaderNameKind::St)
            .expect("ST header");

        assert_eq!(st.as_bytes(), SSDP_TARGET_ROOTDEVICE.as_bytes());
        assert_eq!(
            message.to_bytes(),
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n"
        );
    }

    #[test]
    fn ssdp_search_builders_typed_setters_preserve_raw_extension_order() {
        let message = Ssdp::m_search()
            .with_raw_header("X-DEVICE.UPNP.ORG", "opaque")
            .expect("extension header")
            .host("[ff02::c]:1900")
            .man_discover()
            .mx(3)
            .search_target("urn:schemas-upnp-org:device:MediaServer:1");
        let headers = message.headers().iter().collect::<Vec<_>>();

        assert_eq!(headers.len(), 5);
        assert_eq!(headers[0].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(headers[0].value().as_bytes(), b"opaque");
        assert_eq!(headers[1].name().original(), SSDP_HEADER_HOST);
        assert_eq!(headers[1].value().as_bytes(), b"[ff02::c]:1900");
        assert_eq!(headers[2].name().original(), SSDP_HEADER_MAN);
        assert_eq!(headers[3].name().original(), SSDP_HEADER_MX);
        assert_eq!(headers[3].value().as_bytes(), b"3");
        assert_eq!(headers[4].name().original(), SSDP_HEADER_ST);
        assert_eq!(
            headers[4].value().as_bytes(),
            b"urn:schemas-upnp-org:device:MediaServer:1"
        );
    }

    #[test]
    fn ssdp_search_builders_defaults_preserve_explicit_header_overrides() {
        let message = Ssdp::m_search()
            .with_raw_header("host", "[ff05::c]:1900")
            .expect("explicit HOST header")
            .with_raw_header("MAN", "\"custom:discover\"")
            .expect("explicit MAN header")
            .with_raw_header("MX", "9")
            .expect("explicit MX header")
            .with_raw_header("st", "urn:schemas-upnp-org:service:ContentDirectory:1")
            .expect("explicit ST header")
            .with_search_defaults();
        let headers = message.headers().iter().collect::<Vec<_>>();

        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].name().original(), "host");
        assert_eq!(headers[0].value().as_bytes(), b"[ff05::c]:1900");
        assert_eq!(headers[1].name().original(), "MAN");
        assert_eq!(headers[1].value().as_bytes(), b"\"custom:discover\"");
        assert_eq!(headers[2].name().original(), "MX");
        assert_eq!(headers[2].value().as_bytes(), b"9");
        assert_eq!(headers[3].name().original(), "st");
        assert_eq!(
            headers[3].value().as_bytes(),
            b"urn:schemas-upnp-org:service:ContentDirectory:1"
        );
    }

    #[test]
    fn ssdp_notify_builders_source_backed_subtypes() {
        for (message, expected_subtype) in [
            (Ssdp::notify_alive(), SSDP_NTS_ALIVE),
            (Ssdp::notify_byebye(), SSDP_NTS_BYEBYE),
            (Ssdp::notify_update(), SSDP_NTS_UPDATE),
        ] {
            let request = message
                .message()
                .start_line()
                .as_request()
                .expect("NOTIFY request line");
            let host = message
                .headers()
                .get_first(SsdpHeaderNameKind::Host)
                .expect("HOST header");
            let nts = message
                .headers()
                .get_first(SsdpHeaderNameKind::Nts)
                .expect("NTS header");

            assert_eq!(request.method(), &SsdpMethod::Notify);
            assert_eq!(request.target().as_str(), "*");
            assert_eq!(request.version().as_str(), HTTP_VERSION_1_1);
            assert_eq!(host.as_bytes(), SSDP_IPV4_MULTICAST_HOST.as_bytes());
            assert_eq!(nts.as_bytes(), expected_subtype.as_bytes());
        }
    }

    #[test]
    fn ssdp_notify_builders_typed_setters_preserve_unknown_notification_values() {
        let message = Ssdp::notify()
            .host("[ff05::c]:1900")
            .notification_type("urn:schemas-upnp-org:device:MediaServer:1")
            .notification_subtype("ssdp:custom")
            .unique_service_name("uuid:device-1::urn:schemas-upnp-org:device:MediaServer:1");
        let headers = message.headers().iter().collect::<Vec<_>>();

        assert_eq!(headers.len(), 4);
        assert_eq!(headers[0].name().original(), SSDP_HEADER_HOST);
        assert_eq!(headers[0].value().as_bytes(), b"[ff05::c]:1900");
        assert_eq!(headers[1].name().original(), SSDP_HEADER_NT);
        assert_eq!(
            headers[1].value().as_bytes(),
            b"urn:schemas-upnp-org:device:MediaServer:1"
        );
        assert_eq!(headers[2].name().original(), SSDP_HEADER_NTS);
        assert_eq!(headers[2].value().as_bytes(), b"ssdp:custom");
        assert_eq!(headers[3].name().original(), SSDP_HEADER_USN);
        assert_eq!(
            headers[3].value().as_bytes(),
            b"uuid:device-1::urn:schemas-upnp-org:device:MediaServer:1"
        );
    }

    #[test]
    fn ssdp_notify_builders_source_defaults_preserve_raw_extensions_and_overrides() {
        let message = Ssdp::notify()
            .with_raw_header("X-DEVICE.UPNP.ORG", "opaque")
            .expect("extension header")
            .with_raw_header("NTS", "ssdp:custom")
            .expect("explicit NTS header")
            .with_notify_defaults_for(SSDP_NTS_ALIVE);
        let headers = message.headers().iter().collect::<Vec<_>>();

        assert_eq!(headers.len(), 3);
        assert_eq!(headers[0].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(headers[0].value().as_bytes(), b"opaque");
        assert_eq!(headers[1].name().original(), "NTS");
        assert_eq!(headers[1].value().as_bytes(), b"ssdp:custom");
        assert_eq!(headers[2].name().original(), SSDP_HEADER_HOST);
        assert_eq!(
            headers[2].value().as_bytes(),
            SSDP_IPV4_MULTICAST_HOST.as_bytes()
        );
        assert_eq!(
            message
                .headers()
                .get_first(SsdpHeaderNameKind::Nts)
                .expect("NTS header")
                .as_bytes(),
            b"ssdp:custom"
        );
    }

    #[test]
    fn ssdp_response_builders_ok_with_ext_source_backed_success() {
        let message = Ssdp::response_ok_with_ext();
        let status = message
            .message()
            .start_line()
            .as_response()
            .expect("response status line");
        let ext = message
            .headers()
            .get_first(SsdpHeaderNameKind::Ext)
            .expect("EXT header");

        assert_eq!(status.version().as_str(), HTTP_VERSION_1_1);
        assert_eq!(status.code(), SsdpStatusCode::ok());
        assert_eq!(status.reason().as_str(), REASON_OK);
        assert!(ext.is_empty());
        assert_eq!(message.to_bytes(), b"HTTP/1.1 200 OK\r\nEXT:\r\n\r\n");
    }

    #[test]
    fn ssdp_response_builders_error_like_status_preserves_reason_phrase() {
        let message =
            Ssdp::response_with_status(404, "Not Found").expect("valid error-like response status");
        let status = message
            .message()
            .start_line()
            .as_response()
            .expect("response status line");

        assert_eq!(status.version().as_str(), HTTP_VERSION_1_1);
        assert_eq!(status.code().code(), 404);
        assert_eq!(status.reason().as_str(), "Not Found");
        assert_eq!(message.to_bytes(), b"HTTP/1.1 404 Not Found\r\n\r\n");
    }

    #[test]
    fn ssdp_response_builders_unknown_status_preserves_headers_and_reason() {
        let message = Ssdp::response_with_status(777, "Experimental Status")
            .expect("valid unknown response status")
            .with_raw_header("X-DEVICE.UPNP.ORG", "opaque")
            .expect("extension header");
        let decoded = decode_ssdp(&message.to_bytes()).expect("response should decode");
        let status = decoded
            .message()
            .start_line()
            .as_response()
            .expect("response status line");

        assert_eq!(status.code().code(), 777);
        assert_eq!(status.reason().as_str(), "Experimental Status");
        assert_eq!(
            decoded
                .headers()
                .iter()
                .next()
                .expect("extension header")
                .name()
                .original(),
            "X-DEVICE.UPNP.ORG"
        );
        assert_eq!(decoded, message);
    }

    #[test]
    fn ssdp_response_builders_invalid_status_or_reason_returns_structured_error() {
        let bad_status =
            Ssdp::response_with_status(1_000, "Invalid").expect_err("status is too large");

        assert_eq!(bad_status.field(), SsdpStartLineField::StatusCode);
        assert_eq!(bad_status.value(), "1000");

        let bad_reason =
            Ssdp::response_with_status(599, "Bad\rReason").expect_err("reason contains CR");

        assert_eq!(bad_reason.field(), SsdpStartLineField::ReasonPhrase);
        assert_eq!(bad_reason.value(), "Bad\rReason");
    }

    #[test]
    fn ssdp_target_headers_source_backed_target_constructors() {
        assert_eq!(SsdpTarget::all().as_str(), SSDP_ST_ALL);
        assert_eq!(SsdpTarget::rootdevice().as_str(), SSDP_TARGET_ROOTDEVICE);
        assert_eq!(SsdpTarget::uuid("device-1").as_str(), "uuid:device-1");
        assert_eq!(
            SsdpTarget::upnp_device_type("MediaServer", 1).as_str(),
            "urn:schemas-upnp-org:device:MediaServer:1"
        );
        assert_eq!(
            SsdpTarget::upnp_service_type("ContentDirectory", 2).as_str(),
            "urn:schemas-upnp-org:service:ContentDirectory:2"
        );
        assert_eq!(
            SsdpTarget::vendor_device_type("example.com", "Bridge", 3).as_str(),
            "urn:example.com:device:Bridge:3"
        );
        assert_eq!(
            SsdpTarget::vendor_service_type("example.com", "SwitchPower", 4).as_str(),
            "urn:example.com:service:SwitchPower:4"
        );
    }

    #[test]
    fn ssdp_target_headers_usn_constructors_compose_uuid_and_targets() {
        let target = SsdpTarget::upnp_service_type("ContentDirectory", 1);

        assert_eq!(SsdpUsn::uuid("device-1").as_str(), "uuid:device-1");
        assert_eq!(
            SsdpUsn::rootdevice("device-1").as_str(),
            "uuid:device-1::upnp:rootdevice"
        );
        assert_eq!(
            SsdpUsn::target("device-1", target).as_str(),
            "uuid:device-1::urn:schemas-upnp-org:service:ContentDirectory:1"
        );
    }

    #[test]
    fn ssdp_target_headers_setters_accept_typed_targets_and_usns() {
        let search_target = SsdpTarget::upnp_device_type("MediaServer", 1);
        let usn = SsdpUsn::target("device-1", search_target.clone());
        let search = Ssdp::m_search().search_target(search_target.clone());
        let notify = Ssdp::notify_alive()
            .notification_type(SsdpTarget::rootdevice())
            .unique_service_name(SsdpUsn::rootdevice("device-1"));
        let response = Ssdp::response_ok_with_ext()
            .search_target(search_target.clone())
            .unique_service_name(usn.clone());

        assert_eq!(
            search
                .headers()
                .get_first(SsdpHeaderNameKind::St)
                .expect("ST header")
                .as_bytes(),
            search_target.as_str().as_bytes()
        );
        assert_eq!(
            notify
                .headers()
                .get_first(SsdpHeaderNameKind::Nt)
                .expect("NT header")
                .as_bytes(),
            SSDP_TARGET_ROOTDEVICE.as_bytes()
        );
        assert_eq!(
            notify
                .headers()
                .get_first(SsdpHeaderNameKind::Usn)
                .expect("USN header")
                .as_bytes(),
            b"uuid:device-1::upnp:rootdevice"
        );
        assert_eq!(
            response
                .headers()
                .get_first(SsdpHeaderNameKind::Usn)
                .expect("USN header")
                .as_bytes(),
            usn.as_str().as_bytes()
        );
    }

    #[test]
    fn ssdp_target_headers_raw_unknown_values_are_preserved() {
        let target = SsdpTarget::raw("urn:example-com:device:OddDevice:99");
        let usn = SsdpUsn::raw("uuid:device-1::urn:example-com:device:OddDevice:99");
        let message = Ssdp::notify()
            .notification_type(target.clone())
            .unique_service_name(usn.clone());
        let decoded = decode_ssdp(&message.to_bytes()).expect("typed target headers decode");

        assert_eq!(String::from(target.clone()), target.as_str());
        assert_eq!(String::from(usn.clone()), usn.as_str());
        assert_eq!(decoded, message);
        assert_eq!(
            decoded
                .headers()
                .get_first(SsdpHeaderNameKind::Nt)
                .expect("NT header")
                .as_bytes(),
            target.as_str().as_bytes()
        );
        assert_eq!(
            decoded
                .headers()
                .get_first(SsdpHeaderNameKind::Usn)
                .expect("USN header")
                .as_bytes(),
            usn.as_str().as_bytes()
        );
    }

    #[test]
    fn ssdp_serialize_m_search_request_with_source_backed_headers() {
        let message = Ssdp::m_search()
            .with_raw_header("HOST", "239.255.255.250:1900")
            .expect("HOST header")
            .with_raw_header("MAN", "\"ssdp:discover\"")
            .expect("MAN header")
            .with_raw_header("MX", "2")
            .expect("MX header")
            .with_raw_header("ST", "ssdp:all")
            .expect("ST header");

        assert_eq!(
            message.to_bytes(),
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        );
    }

    #[test]
    fn ssdp_serialize_response_ok_with_empty_ext_header() {
        let message = Ssdp::response_ok()
            .with_raw_header("EXT", SsdpHeaderValue::empty())
            .expect("EXT header");

        assert_eq!(message.to_bytes(), b"HTTP/1.1 200 OK\r\nEXT:\r\n\r\n");
    }

    #[test]
    fn ssdp_serialize_unknown_request_start_line_values_are_preserved() {
        let method = SsdpMethod::try_from("X-SEARCH").expect("unknown method");
        let target = SsdpRequestTarget::try_from("/device.xml?x=1").expect("unknown target");
        let version = SsdpVersion::try_from("HTTP/9.9").expect("unknown version");
        let message = Ssdp::request(method, target, version);

        assert_eq!(
            message.to_bytes(),
            b"X-SEARCH /device.xml?x=1 HTTP/9.9\r\n\r\n"
        );
    }

    #[test]
    fn ssdp_serialize_unknown_status_reason_and_empty_reason_are_preserved() {
        let unknown = Ssdp::response(
            SsdpVersion::try_from("HTTP/1.0").expect("version"),
            SsdpStatusCode::try_from("299").expect("status"),
            SsdpReasonPhrase::try_from("Odd Success").expect("reason"),
        );
        let empty_reason = Ssdp::response(
            SsdpVersion::http_1_1(),
            SsdpStatusCode::try_from("204").expect("status"),
            SsdpReasonPhrase::empty(),
        );

        assert_eq!(unknown.to_bytes(), b"HTTP/1.0 299 Odd Success\r\n\r\n");
        assert_eq!(empty_reason.to_bytes(), b"HTTP/1.1 204 \r\n\r\n");
    }

    #[test]
    fn ssdp_serialize_duplicate_and_unknown_headers_preserve_order_and_spelling() {
        let message = Ssdp::response_ok()
            .with_raw_header("X-DEVICE.UPNP.ORG", "first")
            .expect("unknown header")
            .with_raw_header("ST", "ssdp:all")
            .expect("first ST header")
            .with_raw_header("x-device.upnp.org", "second")
            .expect("second unknown header")
            .with_raw_header("ST", "upnp:rootdevice")
            .expect("second ST header");

        assert_eq!(
            message.to_bytes(),
            b"HTTP/1.1 200 OK\r\nX-DEVICE.UPNP.ORG: first\r\nST: ssdp:all\r\nx-device.upnp.org: second\r\nST: upnp:rootdevice\r\n\r\n"
        );
    }

    #[test]
    fn ssdp_serialize_body_bytes_are_appended_exactly_after_delimiter() {
        let body = vec![0x00, b'\r', b'\n', 0xff, b':', b' '];
        let message = Ssdp::notify().with_body(body.clone());
        let mut expected = b"NOTIFY * HTTP/1.1\r\n\r\n".to_vec();
        expected.extend_from_slice(&body);

        assert_eq!(message.to_bytes(), expected);
    }

    #[test]
    fn ssdp_layer_encoded_len_and_compile_bytes_match_to_bytes() {
        let message = Ssdp::m_search()
            .with_raw_header("HOST", "239.255.255.250:1900")
            .expect("HOST header")
            .with_raw_header("MAN", "\"ssdp:discover\"")
            .expect("MAN header")
            .with_raw_header("ST", "ssdp:all")
            .expect("ST header")
            .with_body(b"opaque body".to_vec());
        let expected = message.to_bytes();
        let packet = Packet::from_layer(message.clone());
        let compiled = packet.compile().expect("SSDP compiles");

        assert_eq!(Layer::encoded_len(&message), expected.len());
        assert_eq!(packet.encoded_len(), expected.len());
        assert_eq!(compiled.as_bytes(), expected.as_slice());
    }

    #[test]
    fn ssdp_layer_packet_typed_access_retrieves_and_clones() {
        let message = Ssdp::notify()
            .with_raw_header("NT", "upnp:rootdevice")
            .expect("NT header")
            .with_raw_header("USN", "uuid:device-1::upnp:rootdevice")
            .expect("USN header");
        let packet = Packet::from_layer(message.clone());
        let cloned = packet.clone();

        assert_eq!(packet.layer::<Ssdp>(), Some(&message));
        assert_eq!(cloned.layer::<Ssdp>(), Some(&message));
    }

    #[test]
    fn ssdp_layer_summary_and_show_preserve_unknown_start_lines_and_counts() {
        let request = Ssdp::request(
            SsdpMethod::try_from("X-QUERY").expect("unknown method"),
            SsdpRequestTarget::try_from("/device.xml").expect("target"),
            SsdpVersion::try_from("HTTP/8.8").expect("version"),
        )
        .with_raw_header("X-DEVICE.UPNP.ORG", "opaque")
        .expect("unknown header")
        .with_raw_header("01-NLS", "17")
        .expect("NLS header")
        .with_body(b"abc".to_vec());

        let request_summary = request.summary();
        assert!(request_summary.contains("X-QUERY /device.xml HTTP/8.8"));
        assert!(request_summary.contains("headers=2"));
        assert!(request_summary.contains("body=3 bytes"));

        let request_show = Packet::from_layer(request).show();
        assert!(request_show.contains("[0] SSDP"));
        assert!(request_show.contains("kind: request"));
        assert!(request_show.contains("start_line: X-QUERY /device.xml HTTP/8.8"));
        assert!(request_show.contains("header_count: 2"));
        assert!(request_show.contains("header_names: X-DEVICE.UPNP.ORG, 01-NLS"));
        assert!(request_show.contains("body_len: 3"));

        let response = Ssdp::response(
            SsdpVersion::try_from("HTTP/9.9").expect("version"),
            SsdpStatusCode::try_from("777").expect("status"),
            SsdpReasonPhrase::try_from("Odd Status").expect("reason"),
        )
        .with_raw_header("EXT", SsdpHeaderValue::empty())
        .expect("EXT header");

        let response_summary = response.summary();
        assert!(response_summary.contains("HTTP/9.9 777 Odd Status"));
        assert!(response_summary.contains("headers=1"));
        assert!(response_summary.contains("body=0 bytes"));

        let response_show = Packet::from_layer(response).show();
        assert!(response_show.contains("kind: response"));
        assert!(response_show.contains("start_line: HTTP/9.9 777 Odd Status"));
        assert!(response_show.contains("header_count: 1"));
    }

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
