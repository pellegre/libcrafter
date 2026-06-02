//! Typed ICMPv6 message-body model.
//!
//! ICMPv4 (`icmp/v4/`) classifies its messages by the `type` byte and dispatches
//! a type-specific interpretation of the four rest-of-header bytes (echo
//! identifier/sequence, RFC 4884 length, packet-too-big MTU, parameter-problem
//! pointer) plus any trailing typed body layers. ICMPv6 follows the same idiom:
//! the [`Icmpv6`](super::Icmpv6) header keeps its inline fields and proven
//! byte-exact serialization, and this module adds an explicit [`Icmpv6Body`]
//! enum that names the body family the `type` selects.
//!
//! Today the enum covers the existing surface — the RFC 4443 echo body, the four
//! RFC 4443 error bodies (destination-unreachable / packet-too-big /
//! time-exceeded / parameter-problem, each carrying a rest-of-header plus a
//! quoted packet), and an [`Icmpv6Body::Unknown`] catch-all for unrecognized
//! types whose rest-of-header stays raw. It is the first-class home into which
//! later steps slot the NDP, MLD, node-information, and extended-echo bodies
//! (see the `// extensible:` marker on the body classifier) without reshaping
//! the [`Icmpv6`](super::Icmpv6) header or its constructors.
//!
//! The enum is a *view* derived from the header's typed fields: it carries no
//! state the header does not already hold, so deriving it never changes emitted
//! bytes. `summary()` / `show()` render the body variant; serialization stays in
//! the header's `effective_rest_of_header` path.

use super::*;

/// The ICMPv6 message body selected by the [`Icmpv6`](super::Icmpv6) `type`
/// byte.
///
/// This is the typed-body seam that mirrors ICMPv4's type-dispatched body model.
/// It is derived from the [`Icmpv6`](super::Icmpv6) header (via
/// [`Icmpv6::body`](super::Icmpv6::body)); the header remains the source of
/// truth for the bytes on the wire. New ICMPv6 message families (NDP, MLD, node
/// information, extended echo) become new variants in later steps.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6Body {
    /// RFC 4443 echo request (128) / echo reply (129): a 16-bit identifier and a
    /// 16-bit sequence number in the rest-of-header, followed by an opaque data
    /// payload carried as a trailing [`Raw`] layer.
    Echo {
        /// Echo identifier (first half of the rest-of-header).
        identifier: u16,
        /// Echo sequence number (second half of the rest-of-header).
        sequence_number: u16,
    },
    /// RFC 4443 error message (destination-unreachable / packet-too-big /
    /// time-exceeded / parameter-problem): a four-byte rest-of-header whose
    /// type-specific fields are reported here, followed by the quoted packet
    /// that triggered the error (carried as trailing layers).
    Error(Icmpv6ErrorBody),
    /// Any ICMPv6 `type` not yet modeled with a typed body. The four
    /// rest-of-header bytes are preserved verbatim and any trailing bytes stay a
    /// [`Raw`] payload, so unknown messages round-trip unchanged.
    Unknown {
        /// The raw `type` byte, kept so callers can inspect the unrecognized
        /// message without re-reading the header.
        icmp_type: u8,
        /// The four rest-of-header bytes, preserved exactly.
        rest_of_header: [u8; 4],
    },
}

/// The typed fields an RFC 4443 error message exposes in its rest-of-header.
///
/// Every error type carries the same four rest-of-header bytes; the meaning of
/// those bytes is type-specific, so the relevant interpretation is surfaced per
/// variant while the raw bytes stay available through the header's
/// `rest_of_header_value`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6ErrorBody {
    /// Destination unreachable (1): the rest-of-header is unused (sent as zero).
    DestinationUnreachable,
    /// Packet too big (2): the rest-of-header is the 32-bit next-hop MTU.
    PacketTooBig {
        /// Next-hop MTU advertised by the message.
        mtu: u32,
    },
    /// Time exceeded (3): the rest-of-header is unused (sent as zero).
    TimeExceeded,
    /// Parameter problem (4): the rest-of-header is a 32-bit pointer to the
    /// offending octet in the original packet.
    ParameterProblem {
        /// Offset of the octet that triggered the error.
        pointer: u32,
    },
}

impl Icmpv6Body {
    /// Classify the body an [`Icmpv6`](super::Icmpv6) header carries, reading the
    /// type-specific fields the header already holds.
    pub(crate) fn from_header(header: &Icmpv6) -> Self {
        let icmp_type = header.icmp_type_value();
        let rest_of_header = header.rest_of_header_value();
        // extensible: NDP (133-137), MLD (130-132, 143), node information
        // (139/140), and extended echo (160/161) gain their own arms here in
        // later steps. Until then they fall through to `Unknown`, preserving the
        // raw rest-of-header so the messages still round-trip.
        match icmp_type {
            ICMPV6_ECHO_REQUEST | ICMPV6_ECHO_REPLY => {
                let identifier = u16::from_be_bytes([rest_of_header[0], rest_of_header[1]]);
                let sequence_number = u16::from_be_bytes([rest_of_header[2], rest_of_header[3]]);
                Icmpv6Body::Echo {
                    identifier,
                    sequence_number,
                }
            }
            ICMPV6_DESTINATION_UNREACHABLE => {
                Icmpv6Body::Error(Icmpv6ErrorBody::DestinationUnreachable)
            }
            ICMPV6_PACKET_TOO_BIG => Icmpv6Body::Error(Icmpv6ErrorBody::PacketTooBig {
                mtu: u32::from_be_bytes(rest_of_header),
            }),
            ICMPV6_TIME_EXCEEDED => Icmpv6Body::Error(Icmpv6ErrorBody::TimeExceeded),
            ICMPV6_PARAMETER_PROBLEM => Icmpv6Body::Error(Icmpv6ErrorBody::ParameterProblem {
                pointer: u32::from_be_bytes(rest_of_header),
            }),
            _ => Icmpv6Body::Unknown {
                icmp_type,
                rest_of_header,
            },
        }
    }

    /// Stable short label for the body family (`"echo"`, `"error"`,
    /// `"unknown"`), for inspection and dispatch in agent code.
    pub fn label(&self) -> &'static str {
        match self {
            Icmpv6Body::Echo { .. } => "echo",
            Icmpv6Body::Error(_) => "error",
            Icmpv6Body::Unknown { .. } => "unknown",
        }
    }

    /// A compact, body-specific description of the typed fields, for `show()`.
    pub(crate) fn detail(&self) -> String {
        match self {
            Icmpv6Body::Echo {
                identifier,
                sequence_number,
            } => format!("echo(id=0x{identifier:04x}, seq={sequence_number})"),
            Icmpv6Body::Error(error) => match error {
                Icmpv6ErrorBody::DestinationUnreachable => {
                    "error(destination-unreachable)".to_string()
                }
                Icmpv6ErrorBody::PacketTooBig { mtu } => {
                    format!("error(packet-too-big, mtu={mtu})")
                }
                Icmpv6ErrorBody::TimeExceeded => "error(time-exceeded)".to_string(),
                Icmpv6ErrorBody::ParameterProblem { pointer } => {
                    format!("error(parameter-problem, pointer={pointer})")
                }
            },
            Icmpv6Body::Unknown {
                icmp_type,
                rest_of_header,
            } => format!(
                "unknown(type={icmp_type}, rest_of_header={})",
                hex_bytes(rest_of_header)
            ),
        }
    }
}
