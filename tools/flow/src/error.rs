//! Error types for the stateful flow engine.

use std::fmt;

/// Errors returned by flow construction and execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowError {
    /// Flow definition or validation failed.
    Build(String),
    /// The requested execution binding is invalid or unsupported.
    Binding(String),
    /// Sending a packet failed.
    Send(String),
    /// Sending an ordered output batch failed after zero or more earlier sends.
    BatchSend {
        /// Zero-based index of the output that failed within the batch.
        output_index: usize,
        /// Number of outputs successfully sent before the failure.
        sent_count: usize,
        /// Non-packet diagnostic from the underlying send failure.
        error: String,
    },
    /// Receiving or capturing packets failed.
    Capture(String),
    /// A flow step exceeded its deadline.
    Timeout,
    /// The requested flow feature is not supported.
    Unsupported(String),
    /// A private QUIC endpoint driver operation failed.
    QuicEndpoint {
        /// Stable failure category independent of the QUIC implementation.
        category: crate::QuicEndpointErrorCategory,
        /// Non-secret description of the operation that failed.
        context: String,
    },
    /// A lower-level `crafter` operation failed.
    Crafter(crafter::CrafterError),
}

/// Convenient result alias used by flow engine APIs.
pub type Result<T> = std::result::Result<T, FlowError>;

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(message) => write!(f, "flow build error: {message}"),
            Self::Binding(message) => write!(f, "flow binding error: {message}"),
            Self::Send(message) => write!(f, "flow send error: {message}"),
            Self::BatchSend {
                output_index,
                sent_count,
                error,
            } => write!(
                f,
                "flow batch send failed at output {output_index} after {sent_count} successful sends: {error}"
            ),
            Self::Capture(message) => write!(f, "flow capture error: {message}"),
            Self::Timeout => f.write_str("flow step timed out"),
            Self::Unsupported(message) => write!(f, "unsupported flow feature: {message}"),
            Self::QuicEndpoint { category, context } => {
                write!(f, "QUIC endpoint {category} error: {context}")
            }
            Self::Crafter(error) => write!(f, "crafter error: {error}"),
        }
    }
}

impl std::error::Error for FlowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crafter(error) => Some(error),
            _ => None,
        }
    }
}

impl From<crafter::CrafterError> for FlowError {
    fn from(error: crafter::CrafterError) -> Self {
        Self::Crafter(error)
    }
}

#[cfg(test)]
mod tests {
    use super::FlowError;

    #[test]
    fn flow_error_display_strings_are_non_empty() {
        let errors = [
            FlowError::Build("missing initial state".to_string()),
            FlowError::Binding("interface not selected".to_string()),
            FlowError::Send("packet sender failed".to_string()),
            FlowError::BatchSend {
                output_index: 1,
                sent_count: 1,
                error: "packet sender failed".to_string(),
            },
            FlowError::Capture("capture source closed".to_string()),
            FlowError::Timeout,
            FlowError::Unsupported("role is not implemented".to_string()),
            FlowError::QuicEndpoint {
                category: crate::QuicEndpointErrorCategory::Configuration,
                context: "missing peer name".to_string(),
            },
            FlowError::Crafter(crafter::CrafterError::buffer_too_short("packet", 4, 2)),
        ];

        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }
}
