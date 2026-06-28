//! SSDP decode scaffold.
//!
//! SSDP uses an HTTP-like message envelope carried in one UDP payload. This
//! parser preserves request and response start lines, ordered headers, and
//! opaque body bytes after the first header delimiter.

use core::fmt;
use core::str;

use super::header::{SsdpHeaderNameParseError, SsdpHeaderValue};
use super::message::{
    Ssdp, SsdpMessage, SsdpMethod, SsdpMethodParseError, SsdpReasonPhrase, SsdpRequestTarget,
    SsdpStartLineParseError, SsdpStatusCode, SsdpVersion,
};

const HEADER_DELIMITER: &[u8; 4] = b"\r\n\r\n";
const CRLF_LEN: usize = 2;

const CONTEXT_PAYLOAD: &str = "ssdp.payload";
const CONTEXT_LINE_DELIMITER: &str = "ssdp.line-delimiter";

const EXPECTED_REQUEST_LINE: &str =
    "request-line formatted as method SP request-target SP HTTP-version";
const EXPECTED_RESPONSE_LINE: &str =
    "status-line formatted as HTTP-version SP status-code SP [reason-phrase]";
const EXPECTED_CRLF_DELIMITER: &str = "CRLF-delimited header section ending with CRLF CRLF";
const EXPECTED_HEADER_DELIMITER: &str = "header line delimiter ':' with no whitespace before it";

type ParseResult<T> = core::result::Result<T, SsdpParseError>;

/// Parse one SSDP request message from a UDP payload.
///
/// The parser preserves ordered headers and body bytes after the first
/// `\r\n\r\n` delimiter. It accepts unknown but structurally valid request
/// method, target, version, and header names through the SSDP message wrappers.
pub(crate) fn parse_ssdp_request(bytes: &[u8]) -> ParseResult<Ssdp> {
    parse_ssdp_message(
        bytes,
        |line| {
            let (method, target, version) = parse_request_start_line(line)?;
            Ok(SsdpMessage::request(method, target, version))
        },
        || SsdpParseError::invalid_request_start_line(0, "", "missing request start line"),
    )
}

/// Parse one SSDP response message from a UDP payload.
///
/// The parser preserves unknown but structurally valid three-digit status codes,
/// reason phrases, ordered headers, and body bytes after the first `\r\n\r\n`
/// delimiter.
pub(crate) fn parse_ssdp_response(bytes: &[u8]) -> ParseResult<Ssdp> {
    parse_ssdp_message(
        bytes,
        |line| {
            let (version, code, reason) = parse_response_start_line(line)?;
            Ok(SsdpMessage::response(version, code, reason))
        },
        || SsdpParseError::invalid_response_start_line(0, "", "missing response status line"),
    )
}

/// Parse one SSDP request or response payload, using the start-line shape.
pub(crate) fn decode_ssdp(bytes: &[u8]) -> ParseResult<Ssdp> {
    if bytes.starts_with(b"HTTP/") {
        parse_ssdp_response(bytes)
    } else {
        parse_ssdp_request(bytes)
    }
}

fn parse_ssdp_message(
    bytes: &[u8],
    parse_start_line: impl FnOnce(&[u8]) -> ParseResult<SsdpMessage>,
    missing_start_line: impl FnOnce() -> SsdpParseError,
) -> ParseResult<Ssdp> {
    let (header_section, body) = split_header_section(bytes)?;
    let mut lines = HeaderLineIter::new(header_section);
    let Some(start_line) = lines.next() else {
        return Err(missing_start_line());
    };

    let mut message = parse_start_line(start_line)?;

    parse_header_lines(&mut message, lines)?;

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
    let line_text = str::from_utf8(line)
        .map_err(|err| SsdpParseError::invalid_request_start_line_bytes(0, line, err))?;

    if line_text.starts_with("HTTP/") {
        return Err(SsdpParseError::unsupported_start_line_form(
            0,
            line_text,
            "response status-line is not a request-line",
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

fn parse_response_start_line(
    line: &[u8],
) -> ParseResult<(SsdpVersion, SsdpStatusCode, SsdpReasonPhrase)> {
    let line_text = str::from_utf8(line)
        .map_err(|err| SsdpParseError::invalid_response_start_line_bytes(0, line, err))?;

    if !line_text.starts_with("HTTP/") {
        return Err(SsdpParseError::invalid_response_start_line(
            0,
            line_text,
            "response status-line must start with HTTP-version",
        ));
    }

    let Some(first_sp) = line_text.find(' ') else {
        return Err(SsdpParseError::invalid_response_start_line(
            0,
            line_text,
            "status-line must contain HTTP-version, status-code, and reason delimiter",
        ));
    };
    let version = &line_text[..first_sp];
    let remainder = &line_text[first_sp + 1..];

    let Some(second_sp) = remainder.find(' ') else {
        return Err(SsdpParseError::invalid_response_start_line(
            0,
            line_text,
            "status-line must include SP after status-code",
        ));
    };
    let code = &remainder[..second_sp];
    let reason = &remainder[second_sp + 1..];

    if version.is_empty() || code.is_empty() {
        return Err(SsdpParseError::invalid_response_start_line(
            0,
            line_text,
            "status-line version and status-code must not be empty",
        ));
    }

    let version = SsdpVersion::try_from(version)
        .map_err(|err| SsdpParseError::invalid_response_version(0, line_text, err))?;
    let code = SsdpStatusCode::try_from(code)
        .map_err(|err| SsdpParseError::invalid_response_status_code(0, line_text, err))?;
    let reason = SsdpReasonPhrase::try_from(reason)
        .map_err(|err| SsdpParseError::invalid_response_reason_phrase(0, line_text, err))?;

    Ok((version, code, reason))
}

fn parse_header_lines<'a>(
    message: &mut SsdpMessage,
    lines: impl Iterator<Item = &'a [u8]>,
) -> ParseResult<()> {
    for (line_number, line) in lines.enumerate() {
        parse_header_line(message, line_number + 2, line)?;
    }

    Ok(())
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

    let name = str::from_utf8(&line[..colon]).map_err(|err| {
        SsdpParseError::invalid_header_name_bytes(
            line_number,
            &line[..colon],
            err,
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

    fn invalid_request_start_line_bytes(
        offset: usize,
        line: &[u8],
        source: str::Utf8Error,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidRequestStartLineBytes {
                offset,
                line: line.to_vec(),
                valid_up_to: source.valid_up_to(),
                error_len: source.error_len(),
                reason: "request-line must be valid UTF-8 text for current SSDP wrappers",
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

    fn invalid_response_start_line(
        offset: usize,
        line: impl Into<String>,
        reason: &'static str,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidResponseStartLine {
                offset,
                line: line.into(),
                reason,
                expected: EXPECTED_RESPONSE_LINE,
            },
        }
    }

    fn invalid_response_start_line_bytes(
        offset: usize,
        line: &[u8],
        source: str::Utf8Error,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidResponseStartLineBytes {
                offset,
                line: line.to_vec(),
                valid_up_to: source.valid_up_to(),
                error_len: source.error_len(),
                reason: "status-line must be valid UTF-8 text for current SSDP wrappers",
                expected: EXPECTED_RESPONSE_LINE,
            },
        }
    }

    fn invalid_response_version(
        offset: usize,
        line: impl Into<String>,
        source: SsdpStartLineParseError,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidResponseVersion {
                offset,
                line: line.into(),
                source,
            },
        }
    }

    fn invalid_response_status_code(
        offset: usize,
        line: impl Into<String>,
        source: SsdpStartLineParseError,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidResponseStatusCode {
                offset,
                line: line.into(),
                source,
            },
        }
    }

    fn invalid_response_reason_phrase(
        offset: usize,
        line: impl Into<String>,
        source: SsdpStartLineParseError,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidResponseReasonPhrase {
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
                line: line.to_vec(),
                expected: EXPECTED_HEADER_DELIMITER,
            },
        }
    }

    fn whitespace_before_colon(line_number: usize, name: &[u8]) -> Self {
        Self {
            kind: SsdpParseErrorKind::WhitespaceBeforeColon {
                line_number,
                name: name.to_vec(),
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

    fn invalid_header_name_bytes(
        line_number: usize,
        name: &[u8],
        source: str::Utf8Error,
        reason: &'static str,
    ) -> Self {
        Self {
            kind: SsdpParseErrorKind::InvalidHeaderNameBytes {
                line_number,
                name: name.to_vec(),
                valid_up_to: source.valid_up_to(),
                error_len: source.error_len(),
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
    /// The request start line was not valid UTF-8 for the current wrappers.
    InvalidRequestStartLineBytes {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line bytes.
        line: Vec<u8>,
        /// Number of valid UTF-8 bytes before the first error.
        valid_up_to: usize,
        /// Length of the invalid byte sequence, or `None` for incomplete input.
        error_len: Option<usize>,
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
    /// The start line was not a response status-line shape.
    InvalidResponseStartLine {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line text.
        line: String,
        /// Stable rejection reason.
        reason: &'static str,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// The response status line was not valid UTF-8 for the current wrappers.
    InvalidResponseStartLineBytes {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line bytes.
        line: Vec<u8>,
        /// Number of valid UTF-8 bytes before the first error.
        valid_up_to: usize,
        /// Length of the invalid byte sequence, or `None` for incomplete input.
        error_len: Option<usize>,
        /// Stable rejection reason.
        reason: &'static str,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// The response HTTP-version failed wrapper validation.
    InvalidResponseVersion {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line text.
        line: String,
        /// Source start-line parse error.
        source: SsdpStartLineParseError,
    },
    /// The response status-code failed three-digit validation.
    InvalidResponseStatusCode {
        /// Datagram offset of the start line.
        offset: usize,
        /// Rejected start-line text.
        line: String,
        /// Source start-line parse error.
        source: SsdpStartLineParseError,
    },
    /// The response reason-phrase failed wrapper validation.
    InvalidResponseReasonPhrase {
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
        /// Rejected header line bytes.
        line: Vec<u8>,
        /// Human-readable expectation.
        expected: &'static str,
    },
    /// Header field-name was followed by whitespace before the colon.
    WhitespaceBeforeColon {
        /// One-based message line number.
        line_number: usize,
        /// Rejected name portion bytes.
        name: Vec<u8>,
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
        /// Rejected header name bytes.
        name: Vec<u8>,
        /// Number of valid UTF-8 bytes before the first error.
        valid_up_to: usize,
        /// Length of the invalid byte sequence, or `None` for incomplete input.
        error_len: Option<usize>,
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
            SsdpParseErrorKind::InvalidRequestStartLineBytes {
                line,
                valid_up_to,
                error_len,
                reason,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP request-start-line: {:?}: {reason} at byte {valid_up_to} len {error_len:?} (expected {expected})",
                String::from_utf8_lossy(line)
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
            SsdpParseErrorKind::InvalidResponseStartLine {
                line,
                reason,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP response-start-line: {line:?}: {reason} (expected {expected})"
            ),
            SsdpParseErrorKind::InvalidResponseStartLineBytes {
                line,
                valid_up_to,
                error_len,
                reason,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP response-start-line: {:?}: {reason} at byte {valid_up_to} len {error_len:?} (expected {expected})",
                String::from_utf8_lossy(line)
            ),
            SsdpParseErrorKind::InvalidResponseVersion { line, source, .. }
            | SsdpParseErrorKind::InvalidResponseStatusCode { line, source, .. }
            | SsdpParseErrorKind::InvalidResponseReasonPhrase { line, source, .. } => {
                write!(f, "invalid SSDP response-start-line: {line:?}: {source}")
            }
            SsdpParseErrorKind::BadHeaderDelimiter {
                line,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP header-line: {:?} (expected {expected})",
                String::from_utf8_lossy(line)
            ),
            SsdpParseErrorKind::WhitespaceBeforeColon { name, expected, .. } => write!(
                f,
                "invalid SSDP header-line: whitespace before colon after {:?} (expected {expected})",
                String::from_utf8_lossy(name)
            ),
            SsdpParseErrorKind::ObsoleteFoldedHeader { reason, .. } => {
                write!(f, "invalid SSDP header-line: {reason}")
            }
            SsdpParseErrorKind::InvalidHeaderName { source, .. } => {
                write!(f, "invalid SSDP header-name: {source}")
            }
            SsdpParseErrorKind::InvalidHeaderNameBytes {
                name,
                valid_up_to,
                error_len,
                reason,
                expected,
                ..
            } => write!(
                f,
                "invalid SSDP header-name: {:?}: {reason} at byte {valid_up_to} len {error_len:?} (expected {expected})",
                String::from_utf8_lossy(name)
            ),
        }
    }
}

impl std::error::Error for SsdpParseError {}

#[cfg(test)]
mod tests {
    use super::super::header::{SsdpHeaderField, SsdpHeaderNameKind};
    use super::super::message::{SsdpMethod, SsdpStartLineField};
    use super::*;

    fn request_line(ssdp: &Ssdp) -> &super::super::message::SsdpRequestLine {
        ssdp.message()
            .start_line()
            .as_request()
            .expect("request start line")
    }

    fn response_line(ssdp: &Ssdp) -> &super::super::message::SsdpStatusLine {
        ssdp.message()
            .start_line()
            .as_response()
            .expect("response start line")
    }

    fn assert_request_parse_serialize_body_round_trip(bytes: &[u8], expected_body: &[u8]) {
        let ssdp = parse_ssdp_request(bytes).expect("request parses");

        assert_eq!(ssdp.body(), expected_body);
        assert_eq!(ssdp.to_bytes().as_slice(), bytes);
    }

    fn assert_response_parse_serialize_body_round_trip(bytes: &[u8], expected_body: &[u8]) {
        let ssdp = parse_ssdp_response(bytes).expect("response parses");

        assert_eq!(ssdp.body(), expected_body);
        assert_eq!(ssdp.to_bytes().as_slice(), bytes);
    }

    fn assert_request_builder_serialize_parse_body_round_trip(ssdp: Ssdp, expected_body: &[u8]) {
        let bytes = ssdp.to_bytes();
        let parsed = parse_ssdp_request(&bytes).expect("serialized request parses");

        assert_eq!(parsed.body(), expected_body);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    fn assert_response_builder_serialize_parse_body_round_trip(ssdp: Ssdp, expected_body: &[u8]) {
        let bytes = ssdp.to_bytes();
        let parsed = parse_ssdp_response(&bytes).expect("serialized response parses");

        assert_eq!(parsed.body(), expected_body);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    fn expect_request_error(bytes: &[u8]) -> SsdpParseError {
        parse_ssdp_request(bytes).expect_err("request payload is malformed")
    }

    fn expect_response_error(bytes: &[u8]) -> SsdpParseError {
        parse_ssdp_response(bytes).expect_err("response payload is malformed")
    }

    #[test]
    fn ssdp_layer_decode_helper_returns_typed_request_and_response() {
        let request =
            decode_ssdp(b"X-QUERY /device.xml HTTP/1.0\r\nX-DEVICE.UPNP.ORG: opaque\r\n\r\nbody")
                .expect("request decodes");
        let request_line = request_line(&request);

        assert_eq!(
            request_line.method(),
            &SsdpMethod::Unknown("X-QUERY".to_string())
        );
        assert_eq!(request_line.target().as_str(), "/device.xml");
        assert_eq!(request_line.version().as_str(), "HTTP/1.0");
        assert_eq!(request.body(), b"body");

        let response =
            decode_ssdp(b"HTTP/9.9 777 Odd Status\r\nEXT:\r\n\r\n").expect("response decodes");
        let response_line = response_line(&response);

        assert_eq!(response_line.version().as_str(), "HTTP/9.9");
        assert_eq!(response_line.code().code(), 777);
        assert_eq!(response_line.reason().as_str(), "Odd Status");
        assert!(response.body().is_empty());
    }

    #[test]
    fn ssdp_malformed_empty_payload_is_truncated_for_requests_and_responses() {
        for error in [expect_request_error(b""), expect_response_error(b"")] {
            assert_eq!(
                error.kind(),
                &SsdpParseErrorKind::Truncated {
                    context: CONTEXT_PAYLOAD,
                    required: 1,
                    available: 0,
                }
            );
        }
    }

    #[test]
    fn ssdp_malformed_short_and_bad_line_delimiters_are_structured() {
        let lone_cr = expect_request_error(b"\r");
        assert_eq!(
            lone_cr.kind(),
            &SsdpParseErrorKind::Truncated {
                context: CONTEXT_LINE_DELIMITER,
                required: 2,
                available: 1,
            }
        );

        let short = expect_response_error(b"H");
        assert_eq!(
            short.kind(),
            &SsdpParseErrorKind::MissingHeaderDelimiter {
                offset: 1,
                expected: EXPECTED_CRLF_DELIMITER,
            }
        );

        let cr_without_lf = expect_request_error(b"M-SEARCH * HTTP/1.1\rHOST: value\r\n\r\n");
        assert_eq!(
            cr_without_lf.kind(),
            &SsdpParseErrorKind::BadDelimiter {
                field: SsdpParseField::LineDelimiter,
                offset: 19,
                reason: "CR must be followed by LF",
                expected: "CRLF",
            }
        );

        let bare_lf = expect_response_error(b"HTTP/1.1 200 OK\nST: ssdp:all\n\n");
        assert_eq!(
            bare_lf.kind(),
            &SsdpParseErrorKind::BadDelimiter {
                field: SsdpParseField::LineDelimiter,
                offset: 15,
                reason: "bare LF is not a valid SSDP line delimiter",
                expected: "CRLF",
            }
        );
    }

    #[test]
    fn ssdp_malformed_missing_delimiter_empty_start_line_and_header_only_are_structured() {
        let missing = expect_request_error(b"M-SEARCH * HTTP/1.1\r\nHOST: example\r\n");
        assert_eq!(
            missing.kind(),
            &SsdpParseErrorKind::MissingHeaderDelimiter {
                offset: 36,
                expected: EXPECTED_CRLF_DELIMITER,
            }
        );

        let empty_request_start = expect_request_error(b"\r\n\r\n");
        assert_eq!(
            empty_request_start.kind(),
            &SsdpParseErrorKind::InvalidRequestStartLine {
                offset: 0,
                line: String::new(),
                reason: "missing request start line",
                expected: EXPECTED_REQUEST_LINE,
            }
        );

        let empty_response_start = expect_response_error(b"\r\n\r\n");
        assert_eq!(
            empty_response_start.kind(),
            &SsdpParseErrorKind::InvalidResponseStartLine {
                offset: 0,
                line: String::new(),
                reason: "missing response status line",
                expected: EXPECTED_RESPONSE_LINE,
            }
        );

        let header_only_request = expect_request_error(b"HOST: example\r\n\r\n");
        assert_eq!(
            header_only_request.kind(),
            &SsdpParseErrorKind::InvalidRequestStartLine {
                offset: 0,
                line: "HOST: example".to_string(),
                reason: "request-line must contain exactly three SP-separated tokens",
                expected: EXPECTED_REQUEST_LINE,
            }
        );

        let header_only_response = expect_response_error(b"HOST: example\r\n\r\n");
        assert_eq!(
            header_only_response.kind(),
            &SsdpParseErrorKind::InvalidResponseStartLine {
                offset: 0,
                line: "HOST: example".to_string(),
                reason: "response status-line must start with HTTP-version",
                expected: EXPECTED_RESPONSE_LINE,
            }
        );
    }

    #[test]
    fn ssdp_malformed_request_start_line_variants_are_structured() {
        let bad_arity = expect_request_error(b"M-SEARCH * HTTP/1.1 extra\r\n\r\n");
        assert_eq!(
            bad_arity.kind(),
            &SsdpParseErrorKind::InvalidRequestStartLine {
                offset: 0,
                line: "M-SEARCH * HTTP/1.1 extra".to_string(),
                reason: "request-line must contain exactly three SP-separated tokens",
                expected: EXPECTED_REQUEST_LINE,
            }
        );

        let invalid_utf8 = expect_request_error(b"M-\xff * HTTP/1.1\r\n\r\n");
        assert_eq!(
            invalid_utf8.kind(),
            &SsdpParseErrorKind::InvalidRequestStartLineBytes {
                offset: 0,
                line: b"M-\xff * HTTP/1.1".to_vec(),
                valid_up_to: 2,
                error_len: Some(1),
                reason: "request-line must be valid UTF-8 text for current SSDP wrappers",
                expected: EXPECTED_REQUEST_LINE,
            }
        );

        let invalid_method = expect_request_error(b"M@SEARCH * HTTP/1.1\r\n\r\n");
        match invalid_method.kind() {
            SsdpParseErrorKind::InvalidRequestMethod {
                offset,
                line,
                source,
                expected,
            } => {
                assert_eq!(*offset, 0);
                assert_eq!(line, "M@SEARCH * HTTP/1.1");
                assert_eq!(source.token(), "M@SEARCH");
                assert_eq!(*expected, "HTTP method token");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let invalid_target = expect_request_error(b"M-SEARCH bad\ttarget HTTP/1.1\r\n\r\n");
        match invalid_target.kind() {
            SsdpParseErrorKind::InvalidRequestTarget {
                offset,
                line,
                source,
            } => {
                assert_eq!(*offset, 0);
                assert_eq!(line, "M-SEARCH bad\ttarget HTTP/1.1");
                assert_eq!(source.field(), SsdpStartLineField::RequestTarget);
                assert_eq!(source.value(), "bad\ttarget");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let invalid_version = expect_request_error(b"M-SEARCH * HTTP/1\r\n\r\n");
        match invalid_version.kind() {
            SsdpParseErrorKind::InvalidRequestVersion {
                offset,
                line,
                source,
            } => {
                assert_eq!(*offset, 0);
                assert_eq!(line, "M-SEARCH * HTTP/1");
                assert_eq!(source.field(), SsdpStartLineField::Version);
                assert_eq!(source.value(), "HTTP/1");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ssdp_malformed_response_start_line_variants_are_structured() {
        let bad_arity = expect_response_error(b"HTTP/1.1 200\r\n\r\n");
        assert_eq!(
            bad_arity.kind(),
            &SsdpParseErrorKind::InvalidResponseStartLine {
                offset: 0,
                line: "HTTP/1.1 200".to_string(),
                reason: "status-line must include SP after status-code",
                expected: EXPECTED_RESPONSE_LINE,
            }
        );

        let invalid_utf8 = expect_response_error(b"HTTP/1.1 200 O\xff\r\n\r\n");
        assert_eq!(
            invalid_utf8.kind(),
            &SsdpParseErrorKind::InvalidResponseStartLineBytes {
                offset: 0,
                line: b"HTTP/1.1 200 O\xff".to_vec(),
                valid_up_to: 14,
                error_len: Some(1),
                reason: "status-line must be valid UTF-8 text for current SSDP wrappers",
                expected: EXPECTED_RESPONSE_LINE,
            }
        );

        let invalid_version = expect_response_error(b"HTTP/1 200 OK\r\n\r\n");
        match invalid_version.kind() {
            SsdpParseErrorKind::InvalidResponseVersion {
                offset,
                line,
                source,
            } => {
                assert_eq!(*offset, 0);
                assert_eq!(line, "HTTP/1 200 OK");
                assert_eq!(source.field(), SsdpStartLineField::Version);
                assert_eq!(source.value(), "HTTP/1");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let invalid_status = expect_response_error(b"HTTP/1.1 20A OK\r\n\r\n");
        match invalid_status.kind() {
            SsdpParseErrorKind::InvalidResponseStatusCode {
                offset,
                line,
                source,
            } => {
                assert_eq!(*offset, 0);
                assert_eq!(line, "HTTP/1.1 20A OK");
                assert_eq!(source.field(), SsdpStartLineField::StatusCode);
                assert_eq!(source.value(), "20A");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let invalid_reason = expect_response_error(b"HTTP/1.1 200 Bad\0Reason\r\n\r\n");
        match invalid_reason.kind() {
            SsdpParseErrorKind::InvalidResponseReasonPhrase {
                offset,
                line,
                source,
            } => {
                assert_eq!(*offset, 0);
                assert_eq!(line, "HTTP/1.1 200 Bad\0Reason");
                assert_eq!(source.field(), SsdpStartLineField::ReasonPhrase);
                assert_eq!(source.value(), "Bad\0Reason");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ssdp_malformed_header_syntax_variants_are_structured() {
        let without_colon = expect_request_error(b"M-SEARCH * HTTP/1.1\r\nHOST value\r\n\r\n");
        assert_eq!(
            without_colon.kind(),
            &SsdpParseErrorKind::BadHeaderDelimiter {
                line_number: 2,
                line: b"HOST value".to_vec(),
                expected: EXPECTED_HEADER_DELIMITER,
            }
        );

        let whitespace_before_colon =
            expect_response_error(b"HTTP/1.1 200 OK\r\nHOST : value\r\n\r\n");
        assert_eq!(
            whitespace_before_colon.kind(),
            &SsdpParseErrorKind::WhitespaceBeforeColon {
                line_number: 2,
                name: b"HOST ".to_vec(),
                expected: "field-name followed immediately by ':'",
            }
        );

        let folded =
            expect_request_error(b"M-SEARCH * HTTP/1.1\r\nHOST: value\r\n continued\r\n\r\n");
        assert_eq!(
            folded.kind(),
            &SsdpParseErrorKind::ObsoleteFoldedHeader {
                line_number: 3,
                reason: "header line starts with SP or HTAB",
            }
        );

        let invalid_name_bytes =
            expect_response_error(b"HTTP/1.1 200 OK\r\nHO\xffST: value\r\n\r\n");
        assert_eq!(
            invalid_name_bytes.kind(),
            &SsdpParseErrorKind::InvalidHeaderNameBytes {
                line_number: 2,
                name: b"HO\xffST".to_vec(),
                valid_up_to: 2,
                error_len: Some(1),
                reason: "field-name must contain ASCII token bytes",
                expected: "HTTP field-name token",
            }
        );

        let invalid_name_token =
            expect_request_error(b"M-SEARCH * HTTP/1.1\r\nBad Name: value\r\n\r\n");
        match invalid_name_token.kind() {
            SsdpParseErrorKind::InvalidHeaderName {
                line_number,
                name,
                source,
            } => {
                assert_eq!(*line_number, 2);
                assert_eq!(name, "Bad Name");
                assert_eq!(source.field(), SsdpHeaderField::Name);
                assert_eq!(source.value(), "Bad Name");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn ssdp_malformed_unrelated_binary_and_text_payloads_are_structured() {
        let unrelated_text_request = expect_request_error(b"hello world\r\n\r\n");
        assert_eq!(
            unrelated_text_request.kind(),
            &SsdpParseErrorKind::InvalidRequestStartLine {
                offset: 0,
                line: "hello world".to_string(),
                reason: "request-line must contain exactly three SP-separated tokens",
                expected: EXPECTED_REQUEST_LINE,
            }
        );

        let unrelated_text_response = expect_response_error(b"hello world\r\n\r\n");
        assert_eq!(
            unrelated_text_response.kind(),
            &SsdpParseErrorKind::InvalidResponseStartLine {
                offset: 0,
                line: "hello world".to_string(),
                reason: "response status-line must start with HTTP-version",
                expected: EXPECTED_RESPONSE_LINE,
            }
        );

        let unrelated_binary_request = expect_request_error(b"\x00\xff\r\n\r\n");
        assert_eq!(
            unrelated_binary_request.kind(),
            &SsdpParseErrorKind::InvalidRequestStartLineBytes {
                offset: 0,
                line: b"\x00\xff".to_vec(),
                valid_up_to: 1,
                error_len: Some(1),
                reason: "request-line must be valid UTF-8 text for current SSDP wrappers",
                expected: EXPECTED_REQUEST_LINE,
            }
        );

        let unrelated_binary_response = expect_response_error(b"\x00\xff\r\n\r\n");
        assert_eq!(
            unrelated_binary_response.kind(),
            &SsdpParseErrorKind::InvalidResponseStartLineBytes {
                offset: 0,
                line: b"\x00\xff".to_vec(),
                valid_up_to: 1,
                error_len: Some(1),
                reason: "status-line must be valid UTF-8 text for current SSDP wrappers",
                expected: EXPECTED_RESPONSE_LINE,
            }
        );
    }

    #[test]
    fn ssdp_parse_response_200_ok_with_headers_and_no_body() {
        let bytes = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Sat, 27 Jun 2026 00:00:00 GMT\r\nEXT:\r\nST: ssdp:all\r\nUSN: uuid:device-1::upnp:rootdevice\r\n\r\n";
        let ssdp = parse_ssdp_response(bytes).expect("response parses");
        let response = response_line(&ssdp);

        assert_eq!(response.version().as_str(), "HTTP/1.1");
        assert_eq!(response.code().code(), 200);
        assert_eq!(response.reason().as_str(), "OK");
        assert_eq!(ssdp.headers().len(), 5);
        assert_eq!(
            ssdp.headers()
                .get_first(SsdpHeaderNameKind::CacheControl)
                .expect("CACHE-CONTROL")
                .as_bytes(),
            b"max-age=1800"
        );
        assert!(ssdp
            .headers()
            .get_first(SsdpHeaderNameKind::Ext)
            .expect("EXT")
            .is_empty());
        assert!(ssdp.body().is_empty());
    }

    #[test]
    fn ssdp_parse_response_unknown_valid_status_code_is_preserved() {
        let ssdp = parse_ssdp_response(b"HTTP/1.0 299 Odd Success\r\n\r\n")
            .expect("unknown response status parses");
        let response = response_line(&ssdp);

        assert_eq!(response.version().as_str(), "HTTP/1.0");
        assert_eq!(response.code().code(), 299);
        assert_eq!(response.reason().as_str(), "Odd Success");
    }

    #[test]
    fn ssdp_parse_response_empty_and_unusual_valid_reason_phrases_are_preserved() {
        let empty = parse_ssdp_response(b"HTTP/1.1 204 \r\n\r\n").expect("empty reason parses");
        let unusual = parse_ssdp_response(b"HTTP/1.1 218 Works\tFine / odd phrase\r\n\r\n")
            .expect("unusual reason parses");

        assert_eq!(response_line(&empty).reason().as_str(), "");
        assert_eq!(
            response_line(&unusual).reason().as_str(),
            "Works\tFine / odd phrase"
        );
    }

    #[test]
    fn ssdp_parse_response_duplicate_and_unknown_headers_are_preserved() {
        let bytes = b"HTTP/1.1 200 OK\r\nX-DEVICE.UPNP.ORG: first\r\nST: ssdp:all\r\nx-device.upnp.org: second\r\nST: upnp:rootdevice\r\n\r\n";
        let ssdp = parse_ssdp_response(bytes).expect("response parses");
        let entries = ssdp.headers().iter().collect::<Vec<_>>();
        let st_values = ssdp
            .headers()
            .get_all(SsdpHeaderNameKind::St)
            .map(SsdpHeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[0].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[0].value().as_bytes(), b"first");
        assert_eq!(entries[2].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[2].name().original(), "x-device.upnp.org");
        assert_eq!(entries[2].value().as_bytes(), b"second");
        assert_eq!(
            st_values,
            vec![b"ssdp:all".as_slice(), b"upnp:rootdevice".as_slice()]
        );
    }

    #[test]
    fn ssdp_parse_response_body_bytes_after_delimiter_are_preserved() {
        let body = b"\x00\r\nbody: bytes\n\xff";
        let mut bytes = b"HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n".to_vec();
        bytes.extend_from_slice(body);

        let ssdp = parse_ssdp_response(&bytes).expect("body response parses");

        assert_eq!(ssdp.body(), body);
    }

    #[test]
    fn ssdp_body_parse_serialize_round_trip_preserves_empty_request_and_response_bodies() {
        assert_request_parse_serialize_body_round_trip(b"NOTIFY * HTTP/1.1\r\n\r\n", b"");
        assert_response_parse_serialize_body_round_trip(b"HTTP/1.1 200 OK\r\n\r\n", b"");
    }

    #[test]
    fn ssdp_body_parse_serialize_round_trip_preserves_opaque_request_and_response_bodies() {
        let request_body = b"\x00\r\nHOST: body-only\r\n\r\n\xffrequest-tail";
        let mut request_bytes =
            b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n".to_vec();
        request_bytes.extend_from_slice(request_body);

        let response_body = b"\xff\r\nST: body-only\r\n\r\n\x00response-tail";
        let mut response_bytes = b"HTTP/1.1 200 OK\r\nEXT:\r\n\r\n".to_vec();
        response_bytes.extend_from_slice(response_body);

        assert_request_parse_serialize_body_round_trip(&request_bytes, request_body);
        assert_response_parse_serialize_body_round_trip(&response_bytes, response_body);
    }

    #[test]
    fn ssdp_body_builder_serialize_parse_round_trip_preserves_empty_request_and_response_bodies() {
        assert_request_builder_serialize_parse_body_round_trip(
            Ssdp::notify().with_body(Vec::<u8>::new()),
            b"",
        );
        assert_response_builder_serialize_parse_body_round_trip(
            Ssdp::response_ok().with_body(Vec::<u8>::new()),
            b"",
        );
    }

    #[test]
    fn ssdp_body_builder_serialize_parse_round_trip_preserves_opaque_request_and_response_bodies() {
        let request_body = b"\x00\r\nMAN: body-only\r\n\r\n\xffrequest-tail".to_vec();
        let request = Ssdp::m_search()
            .with_raw_header("HOST", "239.255.255.250:1900")
            .expect("HOST header")
            .with_body(request_body.clone());

        let response_body = b"\xff\r\nEXT: body-only\r\n\r\n\x00response-tail".to_vec();
        let response = Ssdp::response_ok()
            .with_raw_header("EXT", SsdpHeaderValue::empty())
            .expect("EXT header")
            .with_body(response_body.clone());

        assert_request_builder_serialize_parse_body_round_trip(request, &request_body);
        assert_response_builder_serialize_parse_body_round_trip(response, &response_body);
    }

    #[test]
    fn ssdp_unknown_preservation_request_parse_serialize_round_trip() {
        let bytes = b"X-QUERY /device.xml?probe=1 HTTP/9.9\r\nX-DEVICE.UPNP.ORG: alpha\r\n01-NLS: boot-17; opaque=\"yes\"\r\nx-device.upnp.org: beta\xfftail\r\nX-EXT.EXAMPLE.COM: value\twith\topaque spaces\r\n\r\n";
        let ssdp = parse_ssdp_request(bytes).expect("unknown request values parse");
        let request = request_line(&ssdp);
        let entries = ssdp.headers().iter().collect::<Vec<_>>();

        assert_eq!(
            request.method(),
            &SsdpMethod::Unknown("X-QUERY".to_string())
        );
        assert_eq!(request.target().as_str(), "/device.xml?probe=1");
        assert_eq!(request.version().as_str(), "HTTP/9.9");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[0].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[0].value().as_bytes(), b"alpha");
        assert_eq!(entries[1].name().kind(), SsdpHeaderNameKind::NlsPrefixed);
        assert_eq!(entries[1].name().original(), "01-NLS");
        assert_eq!(entries[1].name().nls_namespace(), Some("01"));
        assert_eq!(entries[1].value().as_bytes(), b"boot-17; opaque=\"yes\"");
        assert_eq!(entries[2].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[2].name().original(), "x-device.upnp.org");
        assert_eq!(entries[2].value().as_bytes(), b"beta\xfftail");
        assert_eq!(entries[3].value().as_bytes(), b"value\twith\topaque spaces");
        assert_eq!(ssdp.to_bytes().as_slice(), bytes);
    }

    #[test]
    fn ssdp_unknown_preservation_response_parse_serialize_round_trip() {
        let bytes = b"HTTP/9.9 777 Odd\tStatus / experimental\r\nST: ssdp:all\r\nX-DEVICE.UPNP.ORG: alpha\r\nst: urn:schemas-upnp-org:service:Odd:1\r\nOPT: \"http://example.com/ext/\"; ns=99\r\n99-NLS: opaque\xffnamespace\r\nX-EXT.EXAMPLE.COM: extension value\r\n\r\n";
        let ssdp = parse_ssdp_response(bytes).expect("unknown response values parse");
        let response = response_line(&ssdp);
        let entries = ssdp.headers().iter().collect::<Vec<_>>();
        let st_values = ssdp
            .headers()
            .get_all(SsdpHeaderNameKind::St)
            .map(SsdpHeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert_eq!(response.version().as_str(), "HTTP/9.9");
        assert_eq!(response.code().code(), 777);
        assert_eq!(response.reason().as_str(), "Odd\tStatus / experimental");
        assert_eq!(entries.len(), 6);
        assert_eq!(
            st_values,
            vec![
                b"ssdp:all".as_slice(),
                b"urn:schemas-upnp-org:service:Odd:1".as_slice()
            ]
        );
        assert_eq!(entries[1].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[1].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[1].value().as_bytes(), b"alpha");
        assert_eq!(entries[3].name().kind(), SsdpHeaderNameKind::Opt);
        assert_eq!(
            entries[3].value().as_bytes(),
            b"\"http://example.com/ext/\"; ns=99"
        );
        assert_eq!(entries[4].name().kind(), SsdpHeaderNameKind::NlsPrefixed);
        assert_eq!(entries[4].name().original(), "99-NLS");
        assert_eq!(entries[4].name().nls_namespace(), Some("99"));
        assert_eq!(entries[4].value().as_bytes(), b"opaque\xffnamespace");
        assert_eq!(entries[5].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(entries[5].name().original(), "X-EXT.EXAMPLE.COM");
        assert_eq!(entries[5].value().as_bytes(), b"extension value");
        assert_eq!(ssdp.to_bytes().as_slice(), bytes);
    }

    #[test]
    fn ssdp_unknown_preservation_request_builder_serialize_parse_round_trip() {
        let request = Ssdp::request(
            SsdpMethod::try_from("X-QUERY").expect("unknown method"),
            SsdpRequestTarget::try_from("/device.xml?probe=builder").expect("unknown target"),
            SsdpVersion::try_from("HTTP/8.8").expect("unknown version"),
        )
        .with_raw_header("X-DEVICE.UPNP.ORG", "alpha")
        .expect("unknown header")
        .with_raw_header("01-NLS", "boot-18; opaque=\"builder\"")
        .expect("NLS extension header")
        .with_raw_header("x-device.upnp.org", b"beta\xffbuilder")
        .expect("duplicate unknown header")
        .with_raw_header("X-EXT.EXAMPLE.COM", b"value\tbuilder")
        .expect("opaque extension value");

        let bytes = request.to_bytes();
        let parsed = parse_ssdp_request(&bytes).expect("serialized unknown request parses");
        let parsed_request = request_line(&parsed);
        let entries = parsed.headers().iter().collect::<Vec<_>>();

        assert_eq!(parsed_request.method().as_str(), "X-QUERY");
        assert_eq!(
            parsed_request.target().as_str(),
            "/device.xml?probe=builder"
        );
        assert_eq!(parsed_request.version().as_str(), "HTTP/8.8");
        assert_eq!(entries[0].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[1].name().kind(), SsdpHeaderNameKind::NlsPrefixed);
        assert_eq!(entries[1].name().nls_namespace(), Some("01"));
        assert_eq!(entries[2].name().original(), "x-device.upnp.org");
        assert_eq!(entries[2].value().as_bytes(), b"beta\xffbuilder");
        assert_eq!(entries[3].value().as_bytes(), b"value\tbuilder");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn ssdp_unknown_preservation_response_builder_serialize_parse_round_trip() {
        let response = Ssdp::response(
            SsdpVersion::try_from("HTTP/8.8").expect("unknown version"),
            SsdpStatusCode::try_from("777").expect("unknown status"),
            SsdpReasonPhrase::try_from("Odd\tStatus / builder").expect("unusual reason"),
        )
        .with_raw_header("ST", "ssdp:all")
        .expect("first ST")
        .with_raw_header("X-DEVICE.UPNP.ORG", "alpha")
        .expect("unknown header")
        .with_raw_header("st", "urn:schemas-upnp-org:service:Odd:1")
        .expect("duplicate ST")
        .with_raw_header("OPT", "\"http://example.com/ext/\"; ns=99")
        .expect("OPT extension")
        .with_raw_header("99-NLS", b"opaque\xffbuilder")
        .expect("NLS extension")
        .with_raw_header("X-EXT.EXAMPLE.COM", "extension value")
        .expect("unknown extension header");

        let bytes = response.to_bytes();
        let parsed = parse_ssdp_response(&bytes).expect("serialized unknown response parses");
        let parsed_response = response_line(&parsed);
        let entries = parsed.headers().iter().collect::<Vec<_>>();
        let st_values = parsed
            .headers()
            .get_all(SsdpHeaderNameKind::St)
            .map(SsdpHeaderValue::as_bytes)
            .collect::<Vec<_>>();

        assert_eq!(parsed_response.version().as_str(), "HTTP/8.8");
        assert_eq!(parsed_response.code().code(), 777);
        assert_eq!(parsed_response.reason().as_str(), "Odd\tStatus / builder");
        assert_eq!(
            st_values,
            vec![
                b"ssdp:all".as_slice(),
                b"urn:schemas-upnp-org:service:Odd:1".as_slice()
            ]
        );
        assert_eq!(entries[1].name().original(), "X-DEVICE.UPNP.ORG");
        assert_eq!(entries[3].name().kind(), SsdpHeaderNameKind::Opt);
        assert_eq!(entries[4].name().kind(), SsdpHeaderNameKind::NlsPrefixed);
        assert_eq!(entries[4].name().nls_namespace(), Some("99"));
        assert_eq!(entries[4].value().as_bytes(), b"opaque\xffbuilder");
        assert_eq!(entries[5].name().kind(), SsdpHeaderNameKind::Unknown);
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn ssdp_parse_response_request_shaped_start_line_is_form_error() {
        let err = parse_ssdp_response(b"M-SEARCH * HTTP/1.1\r\nHOST: example\r\n\r\n")
            .expect_err("request-line is not a response");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidResponseStartLine { .. }
        ));
    }

    #[test]
    fn ssdp_parse_response_bad_status_arity_is_structured_error() {
        let err = parse_ssdp_response(b"HTTP/1.1 200\r\n\r\n")
            .expect_err("missing reason delimiter is malformed");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidResponseStartLine { .. }
        ));
    }

    #[test]
    fn ssdp_parse_response_non_three_digit_status_is_structured_error() {
        let err = parse_ssdp_response(b"HTTP/1.1 20 OK\r\n\r\n").expect_err("bad status code");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidResponseStatusCode { .. }
        ));
    }

    #[test]
    fn ssdp_parse_response_invalid_version_is_structured_error() {
        let err = parse_ssdp_response(b"HTTP/1 200 OK\r\n\r\n").expect_err("bad HTTP-version");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidResponseVersion { .. }
        ));
    }

    #[test]
    fn ssdp_parse_response_invalid_reason_phrase_is_structured_error() {
        let err = parse_ssdp_response(b"HTTP/1.1 200 Bad\0Reason\r\n\r\n")
            .expect_err("bad reason phrase");

        assert!(matches!(
            err.kind(),
            SsdpParseErrorKind::InvalidResponseReasonPhrase { .. }
        ));
    }

    #[test]
    fn ssdp_parse_response_invalid_header_name_or_delimiter_is_structured_error() {
        let bad_name = parse_ssdp_response(b"HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n")
            .expect_err("invalid header name");
        let bare_lf = parse_ssdp_response(b"HTTP/1.1 200 OK\nST: ssdp:all\n\n")
            .expect_err("bare LF delimiter");

        assert!(matches!(
            bad_name.kind(),
            SsdpParseErrorKind::InvalidHeaderName { .. }
        ));
        assert!(matches!(
            bare_lf.kind(),
            SsdpParseErrorKind::BadDelimiter {
                field: SsdpParseField::LineDelimiter,
                ..
            }
        ));
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
