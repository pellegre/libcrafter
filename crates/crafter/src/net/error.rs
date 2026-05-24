use std::fmt;
use std::io;

use crate::pcap::PcapError;
use crate::CrafterError;

use super::send::{SendMode, SendTarget};

pub type Result<T> = std::result::Result<T, NetError>;

/// Errors returned by packet send helpers.
#[derive(Debug)]
pub enum NetError {
    /// Packet compilation failed before a send could be planned.
    Packet(CrafterError),
    /// A send plan or live send was requested without selecting an interface.
    InterfaceRequired,
    /// The selected interface name is structurally invalid.
    InvalidInterfaceName {
        /// Interface name supplied by the caller.
        name: String,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The selected interface was not present in the local interface table.
    InterfaceNotFound {
        /// Interface name supplied by the caller.
        name: String,
    },
    /// No non-loopback, up interface with an address was available.
    NoDefaultInterface,
    /// The selected interface has no MAC address in the local interface table.
    InterfaceMacNotFound {
        /// Interface name supplied by the caller or selected by default.
        name: String,
    },
    /// The selected interface has no address for the requested family.
    InterfaceAddressNotFound {
        /// Interface name supplied by the caller or selected by default.
        name: String,
        /// Requested address family.
        family: &'static str,
    },
    /// A target address, wildcard, CIDR, or number range could not be parsed safely.
    InvalidIpRange {
        /// User supplied range expression.
        input: String,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The packet stack cannot be sent with the requested mode.
    UnsupportedPacketShape {
        /// Requested send mode.
        mode: SendMode,
        /// One-line packet summary.
        summary: String,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The live backend cannot transmit the planned packet target.
    UnsupportedSendTarget {
        /// Planned send target.
        target: SendTarget,
        /// Stable diagnostic reason.
        reason: &'static str,
    },
    /// The datalink backend opened a channel type this crate does not send on.
    UnsupportedDatalinkChannel {
        /// Interface used for the channel.
        interface: String,
    },
    /// The datalink backend could not allocate a write buffer.
    SendBufferUnavailable {
        /// Interface selected for sending.
        interface: String,
        /// Packet byte length.
        len: usize,
    },
    /// A platform or permission error occurred while opening or writing a raw socket.
    PermissionDenied {
        /// Stable operation name.
        operation: &'static str,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// A platform error occurred while opening or writing a raw socket.
    Io {
        /// Stable operation name.
        operation: &'static str,
        /// Underlying operating-system error.
        source: io::Error,
    },
    /// Packet capture failed while waiting for a reply.
    Capture(PcapError),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packet(err) => write!(f, "{err}"),
            Self::InterfaceRequired => write!(f, "send interface is required"),
            Self::InvalidInterfaceName { name, reason } => {
                write!(f, "invalid interface name '{name}': {reason}")
            }
            Self::InterfaceNotFound { name } => write!(f, "interface '{name}' was not found"),
            Self::NoDefaultInterface => write!(
                f,
                "no usable default interface was found in the local interface table"
            ),
            Self::InterfaceMacNotFound { name } => {
                write!(f, "interface '{name}' does not have a MAC address")
            }
            Self::InterfaceAddressNotFound { name, family } => {
                write!(f, "interface '{name}' does not have a {family} address")
            }
            Self::InvalidIpRange { input, reason } => {
                write!(f, "invalid IP range '{input}': {reason}")
            }
            Self::UnsupportedPacketShape {
                mode,
                summary,
                reason,
            } => write!(
                f,
                "cannot build {mode:?} send plan for packet '{summary}': {reason}"
            ),
            Self::UnsupportedSendTarget { target, reason } => {
                write!(f, "cannot transmit {target:?}: {reason}")
            }
            Self::UnsupportedDatalinkChannel { interface } => {
                write!(
                    f,
                    "unsupported datalink channel for interface '{interface}'"
                )
            }
            Self::SendBufferUnavailable { interface, len } => write!(
                f,
                "send buffer for interface '{interface}' could not accept {len} bytes"
            ),
            Self::PermissionDenied { operation, source } => {
                write!(
                    f,
                    "{operation} failed due to missing platform permission: {source}"
                )
            }
            Self::Io { operation, source } => write!(f, "{operation} failed: {source}"),
            Self::Capture(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Packet(err) => Some(err),
            Self::PermissionDenied { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Capture(err) => Some(err),
            _ => None,
        }
    }
}

impl From<CrafterError> for NetError {
    fn from(value: CrafterError) -> Self {
        Self::Packet(value)
    }
}

impl From<PcapError> for NetError {
    fn from(value: PcapError) -> Self {
        Self::Capture(value)
    }
}
