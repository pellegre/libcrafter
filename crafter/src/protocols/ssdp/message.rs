//! SSDP message model scaffold.
//!
//! Request, response, unknown-value, and body-preserving message types are added
//! after the source-backed start line and header models exist.

use core::fmt;
use core::str::FromStr;

const METHOD_NOTIFY: &str = "NOTIFY";
const METHOD_M_SEARCH: &str = "M-SEARCH";

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
        for invalid in ["", "M SEARCH", "M:SEARCH", "M/SEARCH", "NOTIFY\r", "méthod"] {
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
}
