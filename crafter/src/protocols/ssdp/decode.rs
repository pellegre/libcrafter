//! SSDP decode scaffold.
//!
//! SSDP uses an HTTP-like message envelope carried in one UDP payload. This
//! parser is intentionally scoped to request lines for the current step:
//! response status-line parsing is added separately.

use core::fmt;
use core::str;

use super::header::{SsdpHeaderNameParseError, SsdpHeaderValue};
use super::message::{
    Ssdp, SsdpMessage, SsdpMethod, SsdpMethodParseError, SsdpRequestTarget,
    SsdpStartLineParseError, SsdpVersion,
};

const HEADER_DELIMITER: &[u8; 4] = b"\r\n\r\n";
const CRLF_LEN: usize = 2;

const CONTEXT_PAYLOAD: &str = "ssdp.payload";
const CONTEXT_LINE_DELIMITER: &str = "ssdp.line-delimiter";

const EXPECTED_REQUEST_LINE: &str =
    "request-line formatted as method SP request-target SP HTTP-version";
const EXPECTED_CRLF_DELIMITER: &str = "CRLF-delimited header section ending with CRLF CRLF";
const EXPECTED_HEADER_DELIMITER: &str = "header line delimiter ':' with no whitespace before it";

type ParseResult<T> = core::result::Result<T, SsdpParseError>;

/// Parse one SSDP request message from a UDP payload.
///
/// The parser preserves ordered headers and body bytes after the first
/// `\r\n\r\n` delimiter. It accepts unknown but structurally valid request
/// method, target, version, and header names through the SSDP message wrappers.
pub(crate) fn parse_ssdp_request(bytes: &[u8]) -> ParseResult<Ssdp> {
    let (header_section, body) = split_header_section(bytes)?;
    let mut lines = HeaderLineIter::new(header_section);
    let Some(start_line) = lines.next() else {
        return Err(SsdpParseError::invalid_request_start_line(
            0,
            "",
            "missing request start line",
        ));
    };

    let (method, target, version) = parse_request_start_line(start_line)?;
    let mut message = SsdpMessage::request(method, target, version);

    for (line_number, line) in lines.enumerate() {
        parse_header_line(&mut message, line_number + 2, line)?;
    }

    Ok(Ssdp::new(message.with_body(body.to_vec())))
}

fn split_header_section(bytes: &[u8]) -> ParseResult<(&[u8], &[u8])> {
    if bytes.is_empty() {
        return Err(SsdpParseError::truncated(CONTEXT_PAYLOAD, 1, 0));
    }

    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\r' => {
                let next = index + 1;
                if next >= bytes.len() {
                    return Err(SsdpParseError::truncated(
                        CONTEXT_LINE_DELIMITER,
                        index + CRLF_LEN,
                        bytes.len(),
                    ));
                }

                if bytes[next] != b'\n' {
                    return Err(SsdpParseError::bad_delimiter(
                        index,
                        "CR must be followed by LF",
                    ));
                }

                if bytes[index..].starts_with(HEADER_DELIMITER) {
                    return Ok((&bytes[..index], &bytes[index + HEADER_DELIMITER.len()..]));
                }

                index += CRLF_LEN;
            }
            b'\n' => {
                return Err(SsdpParseError::bad_delimiter(
                    index,
                    "bare LF is not a valid SSDP line delimiter",
                ));
            }
            _ => index += 1,
        }
    }

    Err(SsdpParseError::missing_header_delimiter(bytes.len()))
}

fn parse_request_start_line(
    line: &[u8],
) -> ParseResult<(SsdpMethod, SsdpRequestTarget, SsdpVersion)> {
    let line_text = str::from_utf8(line).map_err(|_| {
        SsdpParseError::invalid_request_start_line(0, lossy(line), "request-line must be ASCII")
    })?;

    if line_text.starts_with("HTTP/") {
        return Err(SsdpParseError::unsupported_start_line_form(
            0,
            line_text,
            "response status-line parsing is not implemented in this step",
        ));
    }

    let mut parts = line_text.split(' ');
    let method = parts.next();
    let target = parts.next();
    let version = parts.next();

    let (Some(method), Some(target), Some(version), None) = (method, target, version, parts.next())
    else {
        return Err(SsdpParseError::invalid_request_start_line(
            0,
            line_text,
            "request-line must contain exactly three SP-separated tokens",
        ));
    };

    if method.is_empty() || target.is_empty() || version.is_empty() {
        return Err(SsdpParseError::invalid_request_start_line(
            0,
            line_text,
            "request-line tokens must not be empty",
        ));
    }

    let method = SsdpMethod::try_from(method)
        .map_err(|err| SsdpParseError::invalid_request_method(0, line_text, err))?;
    let target = SsdpRequestTarget::try_from(target)
        .map_err(|err| SsdpParseError::invalid_request_target(0, line_text, err))?;
    let version = SsdpVersion::try_from(version)
        .map_err(|err| SsdpParseError::invalid_request_version(0, line_text, err))?;

    Ok((method, target, version))
}

fn parse_header_line(
    message: &mut SsdpMessage,
    line_number: usize,
    line: &[u8],
) -> ParseResult<()> {
    if line.starts_with(b" ") || line.starts_with(b"\t") {
        return Err(SsdpParseError::obsolete_folded_header(line_number));
    }

    let Some(colon) = line.iter().position(|byte| *byte == b':') else {
        return Err(SsdpParseError::bad_header_delimiter(line_number, line));
    };

    if line[..colon].ends_with(b" ") || line[..colon].ends_with(b"\t") {
        return Err(SsdpParseError::whitespace_before_colon(
            line_number,
            &line[..colon],
        ));
    }

    let name = str::from_utf8(&line[..colon]).map_err(|_| {
        SsdpParseError::invalid_header_name_bytes(
            line_number,
            &line[..colon],
            "field-name must contain ASCII token bytes",
        )
    })?;
    let value = trim_ows(&line[colon + 1..]);

    message
        .push_raw_header(name, SsdpHeaderValue::from_bytes(value.to_vec()))
        .map_err(|err| SsdpParseError::invalid_header_name(line_number, name, err))
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map(|index| index + 1)
        .unwrap_or(start);

    &bytes[start..end]
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

struct HeaderLineIter<'a> {
    remaining: Option<&'a [u8]>,
}

impl<'a> HeaderLineIter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: Some(bytes),
        }
    }
}

impl<'a> Iterator for HeaderLineIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let remaining = self.remaining?;
        if remaining.is_empty() {
            self.remaining = None;
            return None;
        }

        if let Some(crlf) = remaining
            .windows(CRLF_LEN)
            .position(|window| window == b"\r\n")
        {
            let line = &remaining[..crlf];
            self.remaining = Some(&remaining[crlf + CRLF_LEN..]);
            Some(line)
        } else {
            self.remaining = None;
            Some(remaining)
        }
    }
}

/// Field or boundary rejected by the SSDP request parser.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum SsdpParseField {
    /// CRLF line delimiter.
    LineDelimiter,
}

impl SsdpParseField {
    const fn label(self) -> &'static str {
        match self {
            Self::LineDelimiter => "line-delimiter",
        }
    }
}

/// Structured SSDP parser error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SsdpParseError {
    kind: SsdpParseErrorKind,
}

impl SsdpParseError {
    fn truncated(context: &'static str, required: usize, available: usize) -> Self {
        Self {
            kind: SsdpParseErrorKind::Truncated {
                context,
                required,
                available,
            },
        }
    }

    fn missing_header_delimiter(offset: usize) -> Self {
        Self {
            kind: SsdpParseErrorKind::MissingHeaderDelimiter {
                offset,
                expected: EXPECTED_CRLF_DELIMITER,
            },
        }
    }

    fn bad_delimiter(offset: usize, reason: &'static str) -> Self {
        Self {
            kind: SsdpParseErrorKind::BadDelimiter {
                field: SsdpParseField::LineDelimiter,
                offset,
                reason,
                expected: "CRLF",
            },
        }
    }

    fn unsupported_start_line_form(
        offset: usize,
        line: impl Into<String>,
        reason: &'static str,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidRequestStartLine {
                offset,
                line: line.into(),
                reason,
                expected: EXPECTED_REQUEST_LINE,
            },
        }
    }

    fn invalid_request_start_line(
        offset: usize,
        line: impl Into<String>,
        reason: &'static str,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidRequestStartLine {
                offset,
                line: line.into(),
                reason,
                expected: EXPECTED_REQUEST_LINE,
            },
        }
    }

    fn invalid_request_method(
        offset: usize,
        line: impl Into<String>,
        source: SsdpMethodParseError,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidRequestMethod {
                offset,
                line: line.into(),
                source,
                expected: "HTTP method token",
            },
        }
    }

    fn invalid_request_target(
        offset: usize,
        line: impl Into<String>,
        source: SsdpStartLineParseError,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidRequestTarget {
                offset,
                line: line.into(),
                source,
            },
        }
    }

    fn invalid_request_version(
        offset: usize,
        line: impl Into<String>,
        source: SsdpStartLineParseError,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidRequestVersion {
                offset,
                line: line.into(),
                source,
            },
        }
    }

    fn bad_header_delimiter(line_number: usize, line: &[u8]) -> Self {
        Self {
            kind: SsdpParseErrorKind::BadHeaderDelimiter {
                line_number,
                line: lossy(line),
                expected: EXPECTED_HEADER_DELIMITER,
            },
        }
    }

    fn whitespace_before_colon(line_number: usize, name: &[u8]) -> Self {
        Self {
            kind: SsdpParseErrorKind::WhitespaceBeforeColon {
                line_number,
                name: lossy(name),
                expected: "field-name followed immediately by ':'",
            },
        }
    }

    fn obsolete_folded_header(line_number: usize) -> Self {
        Self {
            kind: SsdpParseErrorKind::ObsoleteFoldedHeader {
                line_number,
                reason: "header line starts with SP or HTAB",
            },
        }
    }

    fn invalid_header_name(
        line_number: usize,
        name: impl Into<String>,
        source: SsdpHeaderNameParseError,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidHeaderName {
                line_number,
                name: name.into(),
                source,
            },
        }
    }

    fn invalid_header_name_bytes(line_number: usize, name: &[u8], reason: &'static str) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidHeaderNameBytes {
                line_number,
                name: lossy(name),
                reason,
                expected: "HTTP field-name token",
            },
        }
    }

    /// Return the structured parser error kind.
    pub(crate) const fn kind(&self) -> &SsdpParseErrorKind {
        &self.kind
    }
}

/// SSDP parser error categories.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SsdpParseErrorKind {
    /// Payload ended before a required parser boundary was complete.
    Truncated {
        /// Stable field context.
        context: &'static str,
        /// Required byte count.
        required: usize,
        /// Available byte count.
        available: usize,
    },
    /// The CRLF CRLF header terminator was not present before datagram end.
    MissingHeaderDelimiter {
        /// Datagram offset where parsing stopped.
        offset: usize,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// A line delimiter was not CRLF.
    BadDelimiter {
        /// Rejected delimiter field.
        field: SsdpParseField,
        /// Datagram offset of the bad delimiter byte.
        offset: usize,
        /// Stable rejection reason.
        reason: &'static str,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// The start line was not a request-line shape accepted in this step.
    InvalidRequestStartLine {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line text.
        line: String,
        /// Stable rejection reason.
        reason: &'static str,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// The request method failed HTTP token validation.
    InvalidRequestMethod {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line text.
        line: String,
        /// Source method parse error.
        source: SsdpMethodParseError,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// The request target failed wrapper validation.
    InvalidRequestTarget {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line text.
        line: String,
        /// Source start-line parse error.
        source: SsdpStartLineParseError,
    },
    /// The request HTTP-version failed wrapper validation.
    InvalidRequestVersion {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line text.
        line: String,
        /// Source start-line parse error.
        source: SsdpStartLineParseError,
    },
    /// Header line did not contain a valid colon delimiter.
    BadHeaderDelimiter {
        /// One-based message line number.
        line_number: usize,
        /// Rejected header line text.
        line: String,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// Header field-name was followed by whitespace before the colon.
    WhitespaceBeforeColon {
        /// One-based message line number.
        line_number: usize,
        /// Rejected name portion.
        name: String,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// Header line used obsolete folded syntax.
    ObsoleteFoldedHeader {
        /// One-based message line number.
        line_number: usize,
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// Header name failed HTTP field-name token validation.
    InvalidHeaderName {
        /// One-based message line number.
        line_number: usize,
        /// Rejected header name text.
        name: String,
        /// Source header-name parse error.
        source: SsdpHeaderNameParseError,
    },
    /// Header name bytes were not valid ASCII text.
    InvalidHeaderNameBytes {
        /// One-based message line number.
        line_number: usize,
        /// Rejected header name text, decoded lossily for diagnostics.
        name: String,
        /// Stable rejection reason.
        reason: &'static str,
        /// Human-readable expectation.
        expected: &'static str,
    },
}

impl fmt::Display for SsdpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            SsdpParseErrorKind::Truncated {
                context,
                required,
                available,
            } => write!(
                f,
                "{context} requires {required} bytes, but only {available} bytes are available"
            ),
            SsdpParseErrorKind::MissingHeaderDelimiter { expected, .. } => {
                write!(f, "invalid SSDP header-delimiter: missing {expected}")
            }
            SsdpParseErrorKind::BadDelimiter {
                field,
                reason,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP {}: {reason} (expected {expected})",
                field.label()
            ),
            SsdpParseErrorKind::InvalidRequestStartLine {
                line,
                reason,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP request-start-line: {line:?}: {reason} (expected {expected})"
            ),
            SsdpParseErrorKind::InvalidRequestMethod {
                line,
                source,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP request-start-line: {line:?}: {source} (expected {expected})"
            ),
            SsdpParseErrorKind::InvalidRequestTarget { line, source, .. }
            | SsdpParseErrorKind::InvalidRequestVersion { line, source, .. } => {
                write!(f, "invalid SSDP request-start-line: {line:?}: {source}")
            }
            SsdpParseErrorKind::BadHeaderDelimiter {
                line,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP header-line: {line:?} (expected {expected})"
            ),
            SsdpParseErrorKind::WhitespaceBeforeColon { name, expected, .. } => write!(
                f,
                "invalid SSDP header-line: whitespace before colon after {name:?} (expected {expected})"
            ),
            SsdpParseErrorKind::ObsoleteFoldedHeader { reason, .. } => {
                write!(f, "invalid SSDP header-line: {reason}")
            }
            SsdpParseErrorKind::InvalidHeaderName { source, .. } => {
                write!(f, "invalid SSDP header-name: {source}")
            }
            SsdpParseErrorKind::InvalidHeaderNameBytes {
                name,
                reason,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP header-name: {name:?}: {reason} (expected {expected})"
            ),
        }
    }
}

impl std::error::Error for SsdpParseError {}

#[cfg(test)]
mod tests {
    use super::super::header::SsdpHeaderNameKind;
    use super::super::message::SsdpMethod;
    use super::*;

    fn request_line(ssdp: &Ssdp) -> &super::super::message::SsdpRequestLine {
        ssdp.message()
            .start_line()
            .as_request()
            .expect("request start line")
    }

    #[test]
    fn ssdp_parse_request_m_search_with_headers_and_no_body() {
        let bytes = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n";
        let ssdp = parse_ssdp_request(bytes).expect("M-SEARCH request parses");
        let request = request_line(&ssdp);

        assert_eq!(request.method(), &SsdpMethod::MSearch);
        assert_eq!(request.target().as_str(), "*");
        assert_eq!(request.version().as_str(), "HTTP/1.1");
        assert_eq!(ssdp.headers().len(), 4);
        assert_eq!(
            ssdp.headers()
                .get_first(SsdpHeaderNameKind::Host)
                .expect("HOST")
                .as_bytes(),
            b"239.255.255.250:1900"
        );
        assert_eq!(
            ssdp.headers()
                .get_first(SsdpHeaderNameKind::Man)
                .expect("MAN")
                .as_bytes(),
            b"\"ssdp:discover\""
        );
        assert!(ssdp.body().is_empty());
    }

    #[test]
    fn ssdp_parse_request_notify_with_duplicate_and_unknown_headers() {
        let bytes = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nX-DEVICE.UPNP.ORG: first\r\nx-device.upnp.org: second\r\nNTS: ssdp:alive\r\n\r\n";
        let ssdp = parse_ssdp_request(bytes).expect("NOTIFY request parses");
        let request = request_line(&ssdp);
        let entries = ssdp.headers().iter().collect::<Vec<_>>();

        assert_eq!(request.method(), &SsdpMethod::Notify);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[1].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[1].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[1].value().as_bytes(), b"first");
        assert_eq!(entries[2].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[2].name().original(), "x-device.upnp.org");
        assert_eq!(entries[2].value().as_bytes(), b"second");
    }

    #[test]
    fn ssdp_parse_request_unknown_valid_method_is_preserved() {
        let ssdp = parse_ssdp_request(b"X-SEARCH /device.xml HTTP/1.0\r\nHOST: example\r\n\r\n")
            .expect("unknown request method parses");
        let request = request_line(&ssdp);

        assert_eq!(
            request.method(),
            &SsdpMethod::Unknown("X-SEARCH".to_string())
        );
        assert_eq!(request.target().as_str(), "/device.xml");
        assert_eq!(request.version().as_str(), "HTTP/1.0");
    }

    #[test]
    fn ssdp_parse_request_body_bytes_after_delimiter_are_preserved() {
        let body = b"\x00\r\nbody: bytes\n\xff";
        let mut bytes = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n".to_vec();
        bytes.extend_from_slice(body);

        let ssdp = parse_ssdp_request(&bytes).expect("body request parses");

        assert_eq!(ssdp.body(), body);
    }

    #[test]
    fn ssdp_parse_request_empty_payload_is_truncated_error() {
        let err = parse_ssdp_request(b"").expect_err("empty payload is malformed");

        assert_eq!(
            err.kind(),
            &SsdpParseErrorKind::Truncated {
                context: CONTEXT_PAYLOAD,
                required: 1,
                available: 0,
            }
        );
    }

    #[test]
    fn ssdp_parse_request_missing_crlf_delimiter_is_structured_error() {
        let err = parse_ssdp_request(b"M-SEARCH * HTTP/1.1\r\nHOST: example\r\n")
            .expect_err("missing empty CRLF line");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::MissingHeaderDelimiter { .. }
        ));
    }

    #[test]
    fn ssdp_parse_request_bare_lf_is_bad_delimiter_error() {
        let err = parse_ssdp_request(b"M-SEARCH * HTTP/1.1\nHOST: example\n\n")
            .expect_err("bare LF is malformed");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::BadDelimiter {
                field: SsdpParseField::LineDelimiter,
                ..
            }
        ));
    }

    #[test]
    fn ssdp_parse_request_bad_start_line_arity_is_structured_error() {
        let err = parse_ssdp_request(b"M-SEARCH * HTTP/1.1 extra\r\n\r\n")
            .expect_err("extra start-line token is malformed");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidRequestStartLine { .. }
        ));
    }

    #[test]
    fn ssdp_parse_request_response_shaped_start_line_is_form_error() {
        let err = parse_ssdp_request(b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n")
            .expect_err("response parsing is not in this step");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidRequestStartLine { .. }
        ));
    }

    #[test]
    fn ssdp_parse_request_invalid_header_name_is_structured_error() {
        let err = parse_ssdp_request(b"M-SEARCH * HTTP/1.1\r\nBad Name: value\r\n\r\n")
            .expect_err("invalid header name");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidHeaderName { .. }
        ));
    }

    #[test]
    fn ssdp_parse_request_whitespace_before_colon_is_structured_error() {
        let err = parse_ssdp_request(b"M-SEARCH * HTTP/1.1\r\nHOST : value\r\n\r\n")
            .expect_err("whitespace before colon is malformed");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::WhitespaceBeforeColon { .. }
        ));
    }

    #[test]
    fn ssdp_parse_request_folded_header_line_is_structured_error() {
        let err = parse_ssdp_request(b"M-SEARCH * HTTP/1.1\r\nHOST: value\r\n continued\r\n\r\n")
            .expect_err("folded header is malformed");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::ObsoleteFoldedHeader { .. }
        ));
    }
}
