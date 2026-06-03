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
    /// RFC 4861 section 4.1 Router Solicitation (133): the four rest-of-header
    /// bytes are an unused, send-as-zero Reserved field; the message's NDP
    /// options ride in a trailing
    /// [`RouterSolicitation`](super::message::ndp::RouterSolicitation) layer (the
    /// way an echo body's data rides in a trailing [`Raw`]). This variant is the
    /// first NDP body; Router/Neighbor Advertisement, Neighbor Solicitation, and
    /// Redirect (133–137) join it in later steps.
    RouterSolicitation {
        /// The 32-bit Reserved field from the rest-of-header (RFC 4861 sec 4.1:
        /// sent as zero, preserved verbatim here so a non-zero value is visible).
        reserved: u32,
    },
    /// RFC 4861 section 4.2 Router Advertisement (134): the four rest-of-header
    /// bytes are the Cur Hop Limit, the M/O flags byte (with six Reserved bits),
    /// and the Router Lifetime; the Reachable-Time / Retrans-Timer words and the
    /// NDP options ride in a trailing
    /// [`RouterAdvertisement`](super::message::ndp::RouterAdvertisement) layer.
    /// RFC 4862 section 5.2 defines how the M and O flags drive host
    /// configuration.
    RouterAdvertisement {
        /// Cur Hop Limit (RFC 4861 sec 4.2: default hop limit for hosts using
        /// this router; 0 = unspecified).
        cur_hop_limit: u8,
        /// The M (Managed Address Configuration) flag — RFC 4861 sec 4.2 bit
        /// 0x80; RFC 4862 sec 5.2: select stateful (DHCPv6) address config.
        managed: bool,
        /// The O (Other Configuration) flag — RFC 4861 sec 4.2 bit 0x40;
        /// RFC 4862 sec 5.2: other configuration is available via DHCPv6.
        other: bool,
        /// The Default Router Preference (Prf) — RFC 4191 sec 2.2 bits 0x18 of
        /// the flags byte. RFC 4191 reassigned two of RFC 4861's send-as-zero
        /// Reserved bits to this 2-bit preference; it is decoded here rather than
        /// folded into [`reserved_flags`](Self::RouterAdvertisement::reserved_flags).
        preference: Prf,
        /// The remaining Reserved flag bits (RFC 4861 sec 4.2: send-as-zero),
        /// preserved verbatim so a non-zero value (or a later RFC 5175 "H"
        /// assignment at 0x20) is visible. This is the flags byte with M (0x80),
        /// O (0x40), and the RFC 4191 Prf bits (0x18) masked out — i.e. the bits
        /// 0x27 (the 0x20 "H" bit and the low three reserved bits).
        reserved_flags: u8,
        /// Router Lifetime in seconds (RFC 4861 sec 4.2: how long this router is
        /// a default router; 0 = not a default router).
        router_lifetime: u16,
    },
    /// RFC 4861 section 4.3 Neighbor Solicitation (135): the four rest-of-header
    /// bytes are an unused, send-as-zero Reserved field; the 128-bit Target
    /// Address (the IPv6 address being resolved) and the NDP options ride in a
    /// trailing
    /// [`NeighborSolicitation`](super::message::ndp::NeighborSolicitation) layer.
    /// Neighbor Solicitation is the IPv6 analogue of ARP "who-has" and, when sent
    /// from the unspecified source, a Duplicate Address Detection probe.
    NeighborSolicitation {
        /// The 32-bit Reserved field from the rest-of-header (RFC 4861 sec 4.3:
        /// sent as zero, preserved verbatim here so a non-zero value is visible).
        reserved: u32,
    },
    /// RFC 4861 section 4.4 Neighbor Advertisement (136): the four rest-of-header
    /// bytes are the R (Router) / S (Solicited) / O (Override) flags in the three
    /// most-significant bits plus 29 Reserved bits; the 128-bit Target Address (the
    /// address whose link-layer address is being reported) and the NDP options ride
    /// in a trailing
    /// [`NeighborAdvertisement`](super::message::ndp::NeighborAdvertisement) layer.
    /// Neighbor Advertisement is the IPv6 analogue of ARP "is-at" and answers a
    /// Neighbor Solicitation.
    NeighborAdvertisement {
        /// The R (Router) flag — RFC 4861 sec 4.4 bit 0x80000000: the sender is a
        /// router.
        router: bool,
        /// The S (Solicited) flag — RFC 4861 sec 4.4 bit 0x40000000: the
        /// advertisement was sent in response to a Neighbor Solicitation.
        solicited: bool,
        /// The O (Override) flag — RFC 4861 sec 4.4 bit 0x20000000: the
        /// advertisement should override an existing cache entry.
        override_flag: bool,
        /// The 29 Reserved bits (RFC 4861 sec 4.4: send-as-zero), preserved
        /// verbatim so a non-zero value is visible. These are the low 29 bits of
        /// the 32-bit flags word.
        reserved: u32,
    },
    /// RFC 4861 section 4.5 Redirect (137): the four rest-of-header bytes are an
    /// unused, send-as-zero Reserved field; the 128-bit Target Address (a better
    /// first hop), the 128-bit Destination Address (the destination being
    /// redirected), and the NDP options (commonly a Target Link-Layer Address and
    /// a Redirected Header carrying the packet that triggered the Redirect) ride in
    /// a trailing [`Redirect`](super::message::ndp::Redirect) layer. Redirect is
    /// the IPv6 analogue of the ICMPv4 Redirect: a router tells a host of a better
    /// first hop for a destination.
    Redirect {
        /// The 32-bit Reserved field from the rest-of-header (RFC 4861 sec 4.5:
        /// sent as zero, preserved verbatim here so a non-zero value is visible).
        reserved: u32,
    },
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
        // later steps. Router Solicitation (133) is classified below; the
        // remaining NDP types and the other families still fall through to
        // `Unknown`, preserving the raw rest-of-header so the messages still
        // round-trip.
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
            ICMPV6_ROUTER_SOLICITATION => Icmpv6Body::RouterSolicitation {
                // RFC 4861 sec 4.1: the rest-of-header is the 32-bit Reserved
                // field. The options live in the trailing RouterSolicitation
                // layer, not in this header-derived view.
                reserved: u32::from_be_bytes(rest_of_header),
            },
            ICMPV6_ROUTER_ADVERTISEMENT => {
                // RFC 4861 sec 4.2: rest-of-header = Cur Hop Limit (byte 0),
                // flags byte (byte 1: 0x80 M, 0x40 O, low six bits Reserved),
                // Router Lifetime (bytes 2..4). RFC 4191 sec 2.2 reassigns bits
                // 0x18 of the flags byte to the Default Router Preference (Prf);
                // it is decoded here, and the remaining bits (0x27) stay in
                // reserved_flags. The Reachable-Time / Retrans-Timer words and
                // options live in the trailing RouterAdvertisement layer, not in
                // this header-derived view.
                let flags = rest_of_header[1];
                Icmpv6Body::RouterAdvertisement {
                    cur_hop_limit: rest_of_header[0],
                    managed: flags & ICMPV6_RA_FLAG_MANAGED != 0,
                    other: flags & ICMPV6_RA_FLAG_OTHER != 0,
                    preference: Prf::from_flag_byte(flags),
                    reserved_flags: flags & ICMPV6_RA_FLAGS_RESERVED & !NDP_PRF_MASK,
                    router_lifetime: u16::from_be_bytes([rest_of_header[2], rest_of_header[3]]),
                }
            }
            ICMPV6_NEIGHBOR_SOLICITATION => Icmpv6Body::NeighborSolicitation {
                // RFC 4861 sec 4.3: the rest-of-header is the 32-bit Reserved
                // field. The Target Address and options live in the trailing
                // NeighborSolicitation layer, not in this header-derived view.
                reserved: u32::from_be_bytes(rest_of_header),
            },
            ICMPV6_NEIGHBOR_ADVERTISEMENT => {
                // RFC 4861 sec 4.4: rest-of-header = the 32-bit flags word. The
                // three most-significant bits are R (0x80000000), S (0x40000000),
                // O (0x20000000); the low 29 bits are Reserved (preserved). The
                // Target Address and options live in the trailing
                // NeighborAdvertisement layer, not in this header-derived view.
                let flags = rest_of_header[0];
                Icmpv6Body::NeighborAdvertisement {
                    router: flags & ICMPV6_NA_FLAG_ROUTER != 0,
                    solicited: flags & ICMPV6_NA_FLAG_SOLICITED != 0,
                    override_flag: flags & ICMPV6_NA_FLAG_OVERRIDE != 0,
                    reserved: u32::from_be_bytes(rest_of_header) & ICMPV6_NA_FLAGS_RESERVED,
                }
            }
            ICMPV6_REDIRECT => Icmpv6Body::Redirect {
                // RFC 4861 sec 4.5: the rest-of-header is the 32-bit Reserved
                // field. The Target Address, Destination Address, and options
                // live in the trailing Redirect layer, not in this
                // header-derived view.
                reserved: u32::from_be_bytes(rest_of_header),
            },
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
            Icmpv6Body::RouterSolicitation { .. } => "router-solicitation",
            Icmpv6Body::RouterAdvertisement { .. } => "router-advertisement",
            Icmpv6Body::NeighborSolicitation { .. } => "neighbor-solicitation",
            Icmpv6Body::NeighborAdvertisement { .. } => "neighbor-advertisement",
            Icmpv6Body::Redirect { .. } => "redirect",
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
            Icmpv6Body::RouterSolicitation { reserved } => {
                format!("router-solicitation(reserved=0x{reserved:08x})")
            }
            Icmpv6Body::RouterAdvertisement {
                cur_hop_limit,
                managed,
                other,
                preference,
                reserved_flags,
                router_lifetime,
            } => format!(
                "router-advertisement(cur_hop_limit={cur_hop_limit}, M={managed}, O={other}, \
                 prf={preference:?}, reserved_flags=0x{reserved_flags:02x}, \
                 router_lifetime={router_lifetime})"
            ),
            Icmpv6Body::NeighborSolicitation { reserved } => {
                format!("neighbor-solicitation(reserved=0x{reserved:08x})")
            }
            Icmpv6Body::NeighborAdvertisement {
                router,
                solicited,
                override_flag,
                reserved,
            } => format!(
                "neighbor-advertisement(R={router}, S={solicited}, O={override_flag}, \
                 reserved=0x{reserved:08x})"
            ),
            Icmpv6Body::Redirect { reserved } => {
                format!("redirect(reserved=0x{reserved:08x})")
            }
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
