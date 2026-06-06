//! Error types for packet wire sources, writers, transforms, and backends.

use std::fmt;
use std::io;

use crate::error::CrafterError;
use crate::net::NetError;
use crate::pcap::PcapError;

/// Convenient result alias used by wire packet I/O primitives.
pub type Result<T> = std::result::Result<T, WireError>;

/// Errors returned by packet wire sources, writers, transforms, and backends.
#[derive(Debug)]
pub enum WireError {
    /// A backend or opened wire does not support the requested operation.
    UnsupportedCapability {
        /// Stable capability name, such as `read`, `write`, or `split`.
        capability: &'static str,
        /// Backend or interface identifier when available.
        backend: Option<String>,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// A backend-specific operation failed before it became a packet, pcap, net, or I/O error.
    Backend {
        /// Backend name or identifier.
        backend: String,
        /// Stable operation name.
        operation: &'static str,
        /// Backend diagnostic reason.
        reason: String,
    },
    /// Packet compilation or decode failed.
    Packet(CrafterError),
    /// Pcap read, write, filter, or capture failed.
    Pcap(PcapError),
    /// Network interface, routing, send, or send/receive failed.
    Net(NetError),
    /// A file, stream, socket, or other I/O operation failed.
    Io {
        /// Stable operation name.
        operation: &'static str,
        /// Underlying I/O error.
        source: io::Error,
    },
    /// A packet transform failed.
    Transform {
        /// Transform name.
        transform: String,
        /// Transform diagnostic reason.
        reason: String,
    },
}

impl WireError {
    /// Build an unsupported capability error.
    pub fn unsupported_capability(
        capability: &'static str,
        backend: Option<impl Into<String>>,
        reason: &'static str,
    ) -> Self {
        Self::UnsupportedCapability {
            capability,
            backend: backend.map(Into::into),
            reason,
        }
    }

    /// Build a backend error.
    pub fn backend(
        backend: impl Into<String>,
        operation: &'static str,
        reason: impl Into<String>,
    ) -> Self {
        Self::Backend {
            backend: backend.into(),
            operation,
            reason: reason.into(),
        }
    }

    /// Build an I/O error with operation context.
    pub const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    /// Build a transform error.
    pub fn transform(transform: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Transform {
            transform: transform.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCapability {
                capability,
                backend,
                reason,
            } => {
                if let Some(backend) = backend {
                    write!(
                        f,
                        "wire backend '{backend}' does not support {capability}: {reason}"
                    )
                } else {
                    write!(f, "wire capability '{capability}' is unsupported: {reason}")
                }
            }
            Self::Backend {
                backend,
                operation,
                reason,
            } => write!(f, "wire backend '{backend}' {operation} failed: {reason}"),
            Self::Packet(err) => write!(f, "{err}"),
            Self::Pcap(err) => write!(f, "{err}"),
            Self::Net(err) => write!(f, "{err}"),
            Self::Io { operation, source } => write!(f, "{operation} failed: {source}"),
            Self::Transform { transform, reason } => {
                write!(f, "wire transform '{transform}' failed: {reason}")
            }
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Packet(err) => Some(err),
            Self::Pcap(err) => Some(err),
            Self::Net(err) => Some(err),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<CrafterError> for WireError {
    fn from(value: CrafterError) -> Self {
        Self::Packet(value)
    }
}

impl From<PcapError> for WireError {
    fn from(value: PcapError) -> Self {
        Self::Pcap(value)
    }
}

impl From<NetError> for WireError {
    fn from(value: NetError) -> Self {
        Self::Net(value)
    }
}

impl From<io::Error> for WireError {
    fn from(value: io::Error) -> Self {
        Self::Io {
            operation: "wire I/O",
            source: value,
        }
    }
}
