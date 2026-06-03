//! TCP option types, encoding, decoding, and classification helpers.

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};

use super::constants::{
    MPTCP_SUBTYPE_TCPRST, TCP_EDO_HEADER_AND_SEGMENT_LEN, TCP_EDO_HEADER_LEN, TCP_EDO_REQUEST_LEN,
    TCP_OPTION_ACCURATE_ECN_MIN_LEN, TCP_OPTION_ACCURATE_ECN_ORDER_0,
    TCP_OPTION_ACCURATE_ECN_ORDER_1, TCP_OPTION_EDO, TCP_OPTION_EOL, TCP_OPTION_EXPERIMENTAL_1,
    TCP_OPTION_EXPERIMENTAL_2, TCP_OPTION_EXPERIMENTAL_MIN_LEN, TCP_OPTION_FAST_OPEN,
    TCP_OPTION_MD5_SIGNATURE, TCP_OPTION_MPTCP, TCP_OPTION_MSS, TCP_OPTION_NOP, TCP_OPTION_SACK,
    TCP_OPTION_SACK_PERMITTED, TCP_OPTION_TCP_AUTHENTICATION, TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN,
    TCP_OPTION_TCP_ENO, TCP_OPTION_TCP_ENO_MIN_LEN, TCP_OPTION_TIMESTAMP, TCP_OPTION_USER_TIMEOUT,
    TCP_OPTION_USER_TIMEOUT_LEN, TCP_OPTION_WINDOW_SCALE, TCP_WINDOW_SCALE_MAX_SHIFT,
};

/// IANA registry classification for a TCP option kind.
///
/// Backed by the IANA TCP Option Kind Numbers registry (under IANA TCP
/// Parameters) and `docs/tcp-rfc-manifest.md`. Unknown, obsolete, reserved,
/// and unassigned kinds stay inspectable through this classification rather
/// than being silently discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpOptionKindClass {
    /// Kind has a current IANA assignment (a name in the registry), whether or
    /// not `crafter` models its payload as a typed option.
    Assigned,
    /// RFC 6994 / RFC 3692-style experimental kind (253 or 254).
    Experimental,
    /// Kind is unassigned in the current IANA registry.
    Unassigned,
}

/// One SACK block carried by a TCP SACK option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpSackBlock {
    /// Left edge sequence number.
    pub left_edge: u32,
    /// Right edge sequence number.
    pub right_edge: u32,
}

impl TcpSackBlock {
    /// Create a SACK block.
    pub const fn new(left_edge: u32, right_edge: u32) -> Self {
        Self {
            left_edge,
            right_edge,
        }
    }
}

/// Parsed or constructible TCP Extended Data Offset value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpExtendedDataOffset {
    /// EDO request option with no payload.
    Request,
    /// EDO option carrying the extended TCP header length in 32-bit words.
    HeaderLength {
        /// Extended TCP header length in 32-bit words.
        header_length: u16,
    },
    /// EDO option carrying the extended TCP header length and TCP segment length.
    HeaderAndSegmentLength {
        /// Extended TCP header length in 32-bit words.
        header_length: u16,
        /// TCP segment length in bytes.
        segment_length: u16,
    },
}

impl TcpExtendedDataOffset {
    /// EDO option length byte.
    pub const fn option_len(self) -> u8 {
        match self {
            Self::Request => TCP_EDO_REQUEST_LEN,
            Self::HeaderLength { .. } => TCP_EDO_HEADER_LEN,
            Self::HeaderAndSegmentLength { .. } => TCP_EDO_HEADER_AND_SEGMENT_LEN,
        }
    }
}

/// Parsed or constructible TCP option.
///
/// Typed constructors build the standardized options ([`TcpOption::maximum_segment_size`],
/// [`TcpOption::window_scale`], [`TcpOption::sack_permitted`], [`TcpOption::timestamp`],
/// and others); attach them to a segment with [`Tcp::tcp_option`](crate::Tcp::tcp_option),
/// which appends the encoded bytes. Decoding preserves unknown and reserved kinds
/// as inspectable [`TcpOption::Generic`] data rather than discarding them.
///
/// ```rust
/// use crafter::prelude::*;
/// use std::net::Ipv4Addr;
///
/// # fn main() -> crafter::Result<()> {
/// let tcp = Tcp::new()
///     .sport(40000)
///     .dport(80)
///     .syn_segment()
///     .tcp_option(TcpOption::maximum_segment_size(1460))?
///     .tcp_option(TcpOption::window_scale(7))?
///     .tcp_option(TcpOption::sack_permitted())?;
///
/// let packet = Ipv4::new()
///     .src(Ipv4Addr::new(192, 0, 2, 10))
///     .dst(Ipv4Addr::new(198, 51, 100, 20))
///     / tcp;
///
/// let bytes = packet.compile()?;
/// let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes())?;
/// let tcp = decoded.layer::<Tcp>().expect("tcp header");
///
/// // The decoded options round-trip back to their typed values.
/// let options = tcp.parsed_options()?;
/// assert_eq!(options[0].maximum_segment_size_value(), Some(1460));
/// assert_eq!(options[1].window_scale_shift(), Some(7));
/// assert!(options[2].is_sack_permitted());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TcpOption {
    /// End of option list.
    EndOfList,
    /// One-byte no-operation padding.
    NoOperation,
    /// Maximum segment size.
    MaximumSegmentSize(u16),
    /// Window scale shift count.
    WindowScale(u8),
    /// SACK permitted.
    SackPermitted,
    /// SACK blocks.
    Sack(Vec<TcpSackBlock>),
    /// TCP timestamp.
    Timestamp {
        /// Timestamp value.
        value: u32,
        /// Timestamp echo reply value.
        echo_reply: u32,
    },
    /// MPTCP option preserving subtype-specific bytes.
    MultipathTcp {
        /// MPTCP subtype nibble.
        subtype: u8,
        /// Bytes after the kind/length header, including the subtype byte.
        data: Vec<u8>,
    },
    /// Extended Data Offset.
    ExtendedDataOffset(TcpExtendedDataOffset),
    /// TCP Fast Open cookie bytes.
    FastOpen(Vec<u8>),
    /// RFC 6994 experimental option carrying a 16-bit Experiment Identifier
    /// (ExID) followed by arbitrary experiment data, for experimental option
    /// kinds 253 and 254.
    Experimental {
        /// Experimental option kind (`TCP_OPTION_EXPERIMENTAL_1` = 253 or
        /// `TCP_OPTION_EXPERIMENTAL_2` = 254).
        kind: u8,
        /// 16-bit Experiment Identifier (ExID) that distinguishes co-existing
        /// experiments sharing the same option kind.
        experiment_id: u16,
        /// Experiment data bytes after the ExID, preserved verbatim.
        data: Vec<u8>,
    },
    /// RFC 5482 User Timeout (UTO) option carrying a 1-bit Granularity (G) flag
    /// and a 15-bit User Timeout value in a single 16-bit field.
    UserTimeout {
        /// Granularity (G) flag. `false` selects seconds, `true` selects
        /// minutes per RFC 5482 section 3.
        granularity: bool,
        /// 15-bit User Timeout value. Only the low 15 bits are wire-significant;
        /// the high bit holds the Granularity flag.
        value: u16,
    },
    /// RFC 5925 TCP Authentication Option (TCP-AO), byte-preserving.
    ///
    /// This option carries a per-segment Message Authentication Code (MAC). The
    /// MAC computation, master key tuples, traffic-key derivation, and key
    /// rollover described by RFC 5925 and RFC 5926 are *not* implemented here:
    /// authentication computation is out of scope for libcrafter's primitive
    /// packet layer. This variant only preserves the wire bytes (`key_id`,
    /// `rnext_key_id`, and the `mac` bytes) so a TCP-AO segment can be
    /// constructed and inspected verbatim. The MAC bytes are stored exactly as
    /// they appear on the wire and are never recomputed.
    AuthenticationOption {
        /// KeyID identifying the MAC key (and KDF) used to authenticate this
        /// segment for the send direction (RFC 5925 section 2.2).
        key_id: u8,
        /// RNextKeyID requesting the key the sender wishes to receive on
        /// subsequent segments (RFC 5925 section 2.2).
        rnext_key_id: u8,
        /// Message Authentication Code bytes, preserved verbatim. The wire
        /// length is `4 + mac.len()` (kind, length, KeyID, RNextKeyID, MAC).
        /// libcrafter never computes or validates these bytes.
        mac: Vec<u8>,
    },
    /// RFC 8547 TCP Encryption Negotiation Option (TCP-ENO), byte-preserving.
    ///
    /// TCP-ENO (kind 69) carries a sequence of suboption bytes after the
    /// kind/length header. Each suboption is one or more bytes encoding a
    /// negotiated TCP encryption spec (a "global" suboption byte plus optional
    /// non-global suboption data, per RFC 8547 section 4). The TCP-ENO
    /// negotiation handshake, the tcpcrypt session protocol of RFC 8548, and any
    /// negotiated encryption are *not* implemented here: session behavior is out
    /// of scope for libcrafter's primitive packet layer. This variant only
    /// preserves the raw suboption bytes so a TCP-ENO segment can be constructed
    /// and inspected verbatim. The suboption bytes are stored exactly as they
    /// appear on the wire and are never interpreted.
    TcpEno {
        /// Raw suboption bytes after the kind/length header, preserved verbatim.
        /// The wire length is `2 + suboptions.len()`. libcrafter never parses,
        /// negotiates, or validates these bytes.
        suboptions: Vec<u8>,
    },
    /// RFC 9768 Accurate ECN (AccECN) option, byte-preserving.
    ///
    /// AccECN defines two option kinds that differ only in the order in which
    /// the ECN byte-counter fields appear on the wire: AccECN0
    /// (`TCP_OPTION_ACCURATE_ECN_ORDER_0` = 172) and AccECN1
    /// (`TCP_OPTION_ACCURATE_ECN_ORDER_1` = 174). Each option carries zero to
    /// three 24-bit ECN byte counters after the kind/length header (RFC 9768
    /// section 3.2.3.3). The two kinds let an endpoint hedge against middleboxes
    /// that zero specific counter positions, so the *order* of the counters is
    /// itself wire-significant and must be preserved.
    ///
    /// libcrafter only preserves the option `kind` (which encodes the order) and
    /// the raw counter/payload bytes verbatim. The AccECN feedback algorithm,
    /// the codepoint state machine, and any congestion-control reaction described
    /// by RFC 9768 are *not* implemented: that behavior is out of scope for the
    /// primitive packet layer. This variant only lets an AccECN segment be
    /// constructed and inspected byte-for-byte; the counter bytes are stored
    /// exactly as they appear on the wire and are never interpreted.
    AccurateEcn {
        /// AccECN option kind encoding the counter order:
        /// `TCP_OPTION_ACCURATE_ECN_ORDER_0` (172, AccECN0) or
        /// `TCP_OPTION_ACCURATE_ECN_ORDER_1` (174, AccECN1).
        kind: u8,
        /// Order-specific ECN byte-counter / payload bytes after the kind/length
        /// header, preserved verbatim. The wire length is `2 + data.len()`.
        /// libcrafter never parses or interprets these bytes.
        data: Vec<u8>,
    },
    /// Unknown or caller-defined option with a standard length byte.
    Generic {
        /// Raw option kind byte.
        kind: u8,
        /// Option payload bytes after kind and length.
        data: Vec<u8>,
    },
}

impl TcpOption {
    /// Create an end-of-option-list marker.
    pub const fn end_of_list() -> Self {
        Self::EndOfList
    }

    /// Create a no-operation padding option.
    pub const fn no_operation() -> Self {
        Self::NoOperation
    }

    /// Create an MSS option.
    pub const fn maximum_segment_size(mss: u16) -> Self {
        Self::MaximumSegmentSize(mss)
    }

    /// Compatibility alias for MSS.
    pub const fn mss(mss: u16) -> Self {
        Self::MaximumSegmentSize(mss)
    }

    /// Create a window-scale option.
    pub const fn window_scale(shift: u8) -> Self {
        Self::WindowScale(shift)
    }

    /// Create a SACK-permitted option.
    pub const fn sack_permitted() -> Self {
        Self::SackPermitted
    }

    /// Create a SACK option.
    pub fn sack(blocks: impl Into<Vec<TcpSackBlock>>) -> Self {
        Self::Sack(blocks.into())
    }

    /// Create a timestamp option.
    pub const fn timestamp(value: u32, echo_reply: u32) -> Self {
        Self::Timestamp { value, echo_reply }
    }

    /// Create a generic MPTCP option, preserving subtype-specific bytes.
    pub fn multipath_tcp(subtype: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::MultipathTcp {
            subtype,
            data: data.into(),
        }
    }

    /// Create an EDO request option.
    pub const fn extended_data_offset_request() -> Self {
        Self::ExtendedDataOffset(TcpExtendedDataOffset::Request)
    }

    /// Create an EDO option with an extended header length.
    pub const fn extended_data_offset(header_length: u16) -> Self {
        Self::ExtendedDataOffset(TcpExtendedDataOffset::HeaderLength { header_length })
    }

    /// Create an EDO option with an extended header length and segment length.
    pub const fn extended_data_offset_ext(header_length: u16, segment_length: u16) -> Self {
        Self::ExtendedDataOffset(TcpExtendedDataOffset::HeaderAndSegmentLength {
            header_length,
            segment_length,
        })
    }

    /// Create a TCP Fast Open option carrying a cookie (RFC 7413 section 2).
    ///
    /// RFC 7413 defines the cookie as 4 to 16 bytes, even-length; the on-wire
    /// option length is `2 + cookie.len()`. `crafter` preserves the cookie bytes
    /// verbatim, including deliberately malformed lengths, so the cookie is not
    /// rewritten or rejected here. Use [`Self::fast_open_cookie_request`] for the
    /// empty cookie-request form sent on the initial SYN.
    pub fn fast_open(cookie: impl Into<Vec<u8>>) -> Self {
        Self::FastOpen(cookie.into())
    }

    /// Create a TCP Fast Open cookie REQUEST option (RFC 7413 section 3).
    ///
    /// The cookie-request form carries an empty cookie, so the on-wire option is
    /// just the kind and length bytes (length byte `2`). A client sends this on
    /// the initial SYN to ask the server for a Fast Open cookie.
    pub fn fast_open_cookie_request() -> Self {
        Self::FastOpen(Vec::new())
    }

    /// Create an RFC 6994 experimental option for a specific experimental kind.
    ///
    /// `kind` must be `TCP_OPTION_EXPERIMENTAL_1` (253) or
    /// `TCP_OPTION_EXPERIMENTAL_2` (254); other kinds round-trip but are not
    /// classified as experimental. The 16-bit `experiment_id` (ExID) is encoded
    /// immediately after the length byte, followed by `data` verbatim.
    pub fn experimental(kind: u8, experiment_id: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::Experimental {
            kind,
            experiment_id,
            data: data.into(),
        }
    }

    /// Create an RFC 6994 experimental option using experimental kind 253.
    pub fn experimental_1(experiment_id: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::experimental(TCP_OPTION_EXPERIMENTAL_1, experiment_id, data)
    }

    /// Create an RFC 6994 experimental option using experimental kind 254.
    pub fn experimental_2(experiment_id: u16, data: impl Into<Vec<u8>>) -> Self {
        Self::experimental(TCP_OPTION_EXPERIMENTAL_2, experiment_id, data)
    }

    /// Create an RFC 5482 User Timeout (UTO) option.
    ///
    /// `granularity` is the 1-bit Granularity (G) flag (`false` = seconds,
    /// `true` = minutes per RFC 5482 section 3); `value` is the 15-bit User
    /// Timeout value. Only the low 15 bits of `value` are wire-significant; any
    /// higher bits are masked off on encode so the Granularity flag is the sole
    /// occupant of the top bit.
    pub const fn user_timeout(granularity: bool, value: u16) -> Self {
        Self::UserTimeout { granularity, value }
    }

    /// Create an RFC 5925 TCP Authentication Option (TCP-AO), preserving the
    /// wire bytes only.
    ///
    /// `key_id` is the KeyID, `rnext_key_id` is the RNextKeyID, and `mac` is the
    /// Message Authentication Code carried verbatim. libcrafter does not compute
    /// or validate the MAC: authentication computation is out of scope for the
    /// primitive packet layer (see the [`TcpOption::AuthenticationOption`]
    /// documentation). The encoded option length is `4 + mac.len()`.
    pub fn tcp_authentication(key_id: u8, rnext_key_id: u8, mac: impl Into<Vec<u8>>) -> Self {
        Self::AuthenticationOption {
            key_id,
            rnext_key_id,
            mac: mac.into(),
        }
    }

    /// Create an RFC 8547 TCP Encryption Negotiation Option (TCP-ENO),
    /// preserving the raw suboption bytes only.
    ///
    /// `suboptions` is the sequence of suboption bytes carried after the
    /// kind/length header, preserved verbatim. libcrafter does not negotiate,
    /// parse, or validate the suboptions, and it implements no TCP-ENO handshake
    /// or tcpcrypt session behavior: encryption negotiation is out of scope for
    /// the primitive packet layer (see the [`TcpOption::TcpEno`] documentation).
    /// The encoded option length is `2 + suboptions.len()`.
    pub fn tcp_eno(suboptions: impl Into<Vec<u8>>) -> Self {
        Self::TcpEno {
            suboptions: suboptions.into(),
        }
    }

    /// Create an RFC 9768 Accurate ECN (AccECN) option for a specific AccECN
    /// kind, preserving the order-specific counter/payload bytes only.
    ///
    /// `kind` selects the counter order and must be
    /// `TCP_OPTION_ACCURATE_ECN_ORDER_0` (172, AccECN0) or
    /// `TCP_OPTION_ACCURATE_ECN_ORDER_1` (174, AccECN1); other kinds round-trip
    /// but are not classified as AccECN. `data` is the sequence of ECN
    /// byte-counter / payload bytes carried after the kind/length header,
    /// preserved verbatim. libcrafter does not parse, interpret, or react to the
    /// counters, and it implements no AccECN feedback or congestion-control
    /// behavior: that is out of scope for the primitive packet layer (see the
    /// [`TcpOption::AccurateEcn`] documentation). The encoded option length is
    /// `2 + data.len()`.
    pub fn accurate_ecn(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::AccurateEcn {
            kind,
            data: data.into(),
        }
    }

    /// Create an RFC 9768 Accurate ECN option using the AccECN0 kind (172,
    /// `TCP_OPTION_ACCURATE_ECN_ORDER_0`).
    pub fn accurate_ecn_order_0(data: impl Into<Vec<u8>>) -> Self {
        Self::accurate_ecn(TCP_OPTION_ACCURATE_ECN_ORDER_0, data)
    }

    /// Create an RFC 9768 Accurate ECN option using the AccECN1 kind (174,
    /// `TCP_OPTION_ACCURATE_ECN_ORDER_1`).
    pub fn accurate_ecn_order_1(data: impl Into<Vec<u8>>) -> Self {
        Self::accurate_ecn(TCP_OPTION_ACCURATE_ECN_ORDER_1, data)
    }

    /// Create a caller-defined option.
    pub fn generic(kind: u8, data: impl Into<Vec<u8>>) -> Self {
        Self::Generic {
            kind,
            data: data.into(),
        }
    }

    /// Raw option kind byte.
    pub const fn kind(&self) -> u8 {
        match self {
            Self::EndOfList => TCP_OPTION_EOL,
            Self::NoOperation => TCP_OPTION_NOP,
            Self::MaximumSegmentSize(_) => TCP_OPTION_MSS,
            Self::WindowScale(_) => TCP_OPTION_WINDOW_SCALE,
            Self::SackPermitted => TCP_OPTION_SACK_PERMITTED,
            Self::Sack(_) => TCP_OPTION_SACK,
            Self::Timestamp { .. } => TCP_OPTION_TIMESTAMP,
            Self::MultipathTcp { .. } => TCP_OPTION_MPTCP,
            Self::ExtendedDataOffset(_) => TCP_OPTION_EDO,
            Self::FastOpen(_) => TCP_OPTION_FAST_OPEN,
            Self::Experimental { kind, .. } => *kind,
            Self::UserTimeout { .. } => TCP_OPTION_USER_TIMEOUT,
            Self::AuthenticationOption { .. } => TCP_OPTION_TCP_AUTHENTICATION,
            Self::TcpEno { .. } => TCP_OPTION_TCP_ENO,
            Self::AccurateEcn { kind, .. } => *kind,
            Self::Generic { kind, .. } => *kind,
        }
    }

    /// Return the IANA registry classification for this option's kind.
    pub const fn kind_class(&self) -> TcpOptionKindClass {
        tcp_option_kind_class(self.kind())
    }

    /// Return a short, source-backed display name for this option's kind.
    ///
    /// This is the same registry-backed token used by TCP `summary()`/`show()`
    /// inspection; see [`tcp_option_kind_name`].
    pub const fn kind_name(&self) -> &'static str {
        tcp_option_kind_name(self.kind())
    }

    /// Return true when this option's kind is assigned by the IANA registry.
    pub const fn kind_is_assigned(&self) -> bool {
        tcp_option_kind_is_assigned(self.kind())
    }

    /// Return true when this option's kind is an RFC 6994 experimental kind.
    pub const fn kind_is_experimental(&self) -> bool {
        tcp_option_kind_is_experimental(self.kind())
    }

    /// Return the Maximum Segment Size value, if this option is MSS.
    ///
    /// Backed by RFC 9293 and `docs/tcp-rfc-manifest.md`.
    pub const fn maximum_segment_size_value(&self) -> Option<u16> {
        match self {
            Self::MaximumSegmentSize(mss) => Some(*mss),
            _ => None,
        }
    }

    /// Return the Window Scale shift count, if this option is Window Scale.
    ///
    /// Backed by RFC 7323 and `docs/tcp-rfc-manifest.md`.
    pub const fn window_scale_shift(&self) -> Option<u8> {
        match self {
            Self::WindowScale(shift) => Some(*shift),
            _ => None,
        }
    }

    /// Return whether this option is a Window Scale option whose shift count is
    /// within RFC 7323's valid range (`0..=14`).
    ///
    /// Returns `None` when this option is not a Window Scale option, `Some(true)`
    /// when the shift is RFC-valid, and `Some(false)` when the shift exceeds the
    /// RFC 7323 section 2.3 cap of 14. This is inspection-only guidance:
    /// out-of-range shifts are still constructible and encodable for stack
    /// testing (see [`valid_window_scale`]).
    ///
    /// Backed by RFC 7323 section 2.3 and `docs/tcp-rfc-manifest.md`.
    pub const fn window_scale_shift_is_valid(&self) -> Option<bool> {
        match self {
            Self::WindowScale(shift) => Some(valid_window_scale(*shift)),
            _ => None,
        }
    }

    /// Return true when this option is the SACK Permitted option.
    ///
    /// Backed by RFC 2018 and `docs/tcp-rfc-manifest.md`.
    pub const fn is_sack_permitted(&self) -> bool {
        matches!(self, Self::SackPermitted)
    }

    /// Return the SACK blocks, if this option is a SACK option.
    ///
    /// Backed by RFC 2018 / RFC 2883 and `docs/tcp-rfc-manifest.md`.
    pub fn sack_blocks(&self) -> Option<&[TcpSackBlock]> {
        match self {
            Self::Sack(blocks) => Some(blocks),
            _ => None,
        }
    }

    /// Return the number of SACK blocks, if this option is a SACK option.
    ///
    /// Backed by RFC 2018 and `docs/tcp-rfc-manifest.md`.
    pub fn sack_block_count(&self) -> Option<usize> {
        self.sack_blocks().map(<[TcpSackBlock]>::len)
    }

    /// Return the first SACK block, if this option is a SACK option with at
    /// least one block.
    ///
    /// Under RFC 2883 D-SACK semantics, the first block carries the
    /// duplicate-range report when one is present; see
    /// [`is_potential_dsack_first_block`](Self::is_potential_dsack_first_block).
    ///
    /// Backed by RFC 2018 / RFC 2883 and `docs/tcp-rfc-manifest.md`.
    pub fn first_sack_block(&self) -> Option<TcpSackBlock> {
        self.sack_blocks().and_then(|blocks| blocks.first().copied())
    }

    /// Return the SACK blocks after the first one, if this option is a SACK
    /// option. The slice is empty when there is one block or none.
    ///
    /// Under RFC 2883 D-SACK semantics, when the first block reports a
    /// duplicate range, these remaining blocks carry the ordinary (RFC 2018)
    /// SACK report.
    ///
    /// Backed by RFC 2018 / RFC 2883 and `docs/tcp-rfc-manifest.md`.
    pub fn remaining_sack_blocks(&self) -> Option<&[TcpSackBlock]> {
        self.sack_blocks()
            .map(|blocks| blocks.get(1..).unwrap_or(&[]))
    }

    /// Return whether the first SACK block looks like a D-SACK block per
    /// RFC 2883, given the cumulative acknowledgment number the receiver has
    /// already advanced past.
    ///
    /// RFC 2883 reuses the RFC 2018 SACK wire format: a D-SACK report is a
    /// reinterpretation of SACK block ordering, not a new option. The first
    /// SACK block reports a *duplicate* (already-received) range when either of
    /// the two D-SACK rules holds:
    ///
    /// * the first block is below the cumulative ACK (its right edge is at or
    ///   below the cumulative ACK the receiver has acknowledged), or
    /// * the first block is a subset of (contained within) the second SACK
    ///   block.
    ///
    /// This helper only inspects the supplied range context; it does not track
    /// connection state. It returns `None` when this option is not a SACK
    /// option or carries no blocks, and `Some(false)` when the first block does
    /// not match either D-SACK rule. Sequence comparisons use serial-number
    /// arithmetic (RFC 1982 / RFC 9293) so they are correct across the 32-bit
    /// wrap.
    ///
    /// Backed by RFC 2883 (section 4) and `docs/tcp-rfc-manifest.md`.
    pub fn is_potential_dsack_first_block(&self, cumulative_ack: u32) -> Option<bool> {
        let blocks = self.sack_blocks()?;
        let first = blocks.first()?;

        // Rule 1: the first block is at or below the cumulative ACK, i.e. it
        // covers data the receiver has already acknowledged. Serial comparison
        // (RFC 1982) keeps this correct across sequence-number wrap.
        let below_cumulative_ack = serial_le(first.right_edge, cumulative_ack);

        // Rule 2: the first block is a subset of the second SACK block, i.e.
        // the second block already covers everything the first block reports.
        let subset_of_second = blocks.get(1).is_some_and(|second| {
            serial_le(second.left_edge, first.left_edge)
                && serial_le(first.right_edge, second.right_edge)
        });

        Some(below_cumulative_ack || subset_of_second)
    }

    /// Return the Timestamp TSval and TSecr values, if this option is Timestamp.
    ///
    /// Backed by RFC 7323 and `docs/tcp-rfc-manifest.md`.
    pub const fn timestamp_values(&self) -> Option<(u32, u32)> {
        match self {
            Self::Timestamp { value, echo_reply } => Some((*value, *echo_reply)),
            _ => None,
        }
    }

    /// Return the Timestamp Value (TSval) alone, if this option is Timestamp.
    ///
    /// TSval is the sender's current timestamp clock value (RFC 7323 section
    /// 3.2). This is the first half of [`timestamp_values`](Self::timestamp_values).
    ///
    /// Backed by RFC 7323 section 3.2 and `docs/tcp-rfc-manifest.md`.
    pub const fn timestamp_value(&self) -> Option<u32> {
        match self {
            Self::Timestamp { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Return the Timestamp Echo Reply (TSecr) alone, if this option is
    /// Timestamp.
    ///
    /// TSecr echoes a TSval previously received from the peer; it is only valid
    /// when the ACK bit is set (RFC 7323 section 3.2). This is the second half
    /// of [`timestamp_values`](Self::timestamp_values). `crafter` exposes the
    /// echo value as inspectable data only; it does not perform PAWS or RTT
    /// estimation.
    ///
    /// Backed by RFC 7323 section 3.2 and `docs/tcp-rfc-manifest.md`.
    pub const fn timestamp_echo_reply(&self) -> Option<u32> {
        match self {
            Self::Timestamp { echo_reply, .. } => Some(*echo_reply),
            _ => None,
        }
    }

    /// Return the MPTCP subtype nibble, if this option is MPTCP.
    ///
    /// Backed by RFC 8684 and `docs/tcp-rfc-manifest.md`.
    pub const fn mptcp_subtype(&self) -> Option<u8> {
        match self {
            Self::MultipathTcp { subtype, .. } => Some(*subtype),
            _ => None,
        }
    }

    /// Return the MPTCP subtype-specific bytes (including the subtype byte), if
    /// this option is MPTCP.
    ///
    /// The first returned byte packs the subtype in its high nibble and a
    /// subtype-specific nibble (flags for several subtypes) in its low nibble;
    /// see [`mptcp_flags`](Self::mptcp_flags) and
    /// [`mptcp_subtype_data`](Self::mptcp_subtype_data) for the split views.
    ///
    /// Backed by RFC 8684 and `docs/tcp-rfc-manifest.md`.
    pub fn mptcp_data(&self) -> Option<&[u8]> {
        match self {
            Self::MultipathTcp { data, .. } => Some(data),
            _ => None,
        }
    }

    /// Return true when this option is a generic MPTCP option.
    ///
    /// Backed by RFC 8684 and `docs/tcp-rfc-manifest.md`.
    pub const fn is_multipath_tcp(&self) -> bool {
        matches!(self, Self::MultipathTcp { .. })
    }

    /// Return the MPTCP flags nibble (low four bits of the first subtype byte),
    /// if this option is MPTCP and carries at least the subtype byte.
    ///
    /// RFC 8684 packs the subtype in the high nibble of the byte after the
    /// option length and reserves the low nibble for subtype-specific use
    /// (flags for MP_CAPABLE, MP_JOIN, and others). This accessor exposes that
    /// nibble generically without interpreting any particular subtype layout.
    ///
    /// Backed by RFC 8684 and `docs/tcp-rfc-manifest.md`.
    pub fn mptcp_flags(&self) -> Option<u8> {
        match self {
            Self::MultipathTcp { data, .. } => data.first().map(|first| first & 0x0f),
            _ => None,
        }
    }

    /// Return the raw MPTCP subtype payload bytes that follow the first
    /// subtype/flags byte, if this option is MPTCP.
    ///
    /// This is [`mptcp_data`](Self::mptcp_data) with the leading subtype/flags
    /// byte stripped, leaving the subtype-specific payload verbatim. Returns an
    /// empty slice when the option carries only the subtype byte.
    ///
    /// Backed by RFC 8684 and `docs/tcp-rfc-manifest.md`.
    pub fn mptcp_subtype_data(&self) -> Option<&[u8]> {
        match self {
            Self::MultipathTcp { data, .. } => {
                Some(data.split_first().map_or(&[][..], |(_, rest)| rest))
            }
            _ => None,
        }
    }

    /// Return the raw MP_TCPRST Reason byte, if this option is an MPTCP
    /// `MP_TCPRST` (subtype [`MPTCP_SUBTYPE_TCPRST`]) carrying one.
    ///
    /// RFC 8684 section 3.6 lays out the `MP_TCPRST` option as the subtype/flags
    /// byte followed by an 8-bit Reason code. This accessor returns that Reason
    /// byte verbatim without interpreting it; compare it against the
    /// `MPTCP_TCPRST_REASON_*` constants for inspection. It returns `None` when
    /// the option is not MPTCP, is not the `MP_TCPRST` subtype, or is truncated
    /// before the Reason byte. `crafter` exposes the Reason code only as
    /// inspectable data; it implements no MPTCP connection recovery or subflow
    /// policy in response to it.
    ///
    /// Backed by RFC 8684 section 3.6 and `docs/tcp-rfc-manifest.md`.
    pub fn mptcp_tcprst_reason(&self) -> Option<u8> {
        match self {
            Self::MultipathTcp { subtype, data } if *subtype == MPTCP_SUBTYPE_TCPRST => {
                data.get(1).copied()
            }
            _ => None,
        }
    }

    /// Return the Extended Data Offset value, if this option is EDO.
    ///
    /// EDO is draft-status; see the EDO note in `docs/tcp-rfc-manifest.md`.
    pub const fn extended_data_offset_value(&self) -> Option<TcpExtendedDataOffset> {
        match self {
            Self::ExtendedDataOffset(edo) => Some(*edo),
            _ => None,
        }
    }

    /// Return the TCP Fast Open cookie bytes, if this option is Fast Open.
    ///
    /// Backed by RFC 7413 and `docs/tcp-rfc-manifest.md`.
    pub fn fast_open_cookie(&self) -> Option<&[u8]> {
        match self {
            Self::FastOpen(cookie) => Some(cookie),
            _ => None,
        }
    }

    /// Return `true` when this option is a TCP Fast Open cookie REQUEST: a Fast
    /// Open option carrying an empty (zero-length) cookie (RFC 7413 section 3).
    ///
    /// Backed by RFC 7413 and `docs/tcp-rfc-manifest.md`.
    pub fn is_fast_open_cookie_request(&self) -> bool {
        matches!(self, Self::FastOpen(cookie) if cookie.is_empty())
    }

    /// Return the RFC 6994 Experiment Identifier (ExID), if this option is an
    /// experimental option.
    ///
    /// Backed by RFC 6994 and `docs/tcp-rfc-manifest.md`.
    pub const fn experiment_id(&self) -> Option<u16> {
        match self {
            Self::Experimental { experiment_id, .. } => Some(*experiment_id),
            _ => None,
        }
    }

    /// Return the RFC 6994 experiment data bytes (after the 16-bit ExID), if
    /// this option is an experimental option.
    ///
    /// Backed by RFC 6994 and `docs/tcp-rfc-manifest.md`.
    pub fn experiment_data(&self) -> Option<&[u8]> {
        match self {
            Self::Experimental { data, .. } => Some(data),
            _ => None,
        }
    }

    /// Return true when this option is an RFC 6994 experimental option.
    ///
    /// Backed by RFC 6994 and `docs/tcp-rfc-manifest.md`.
    pub const fn is_experimental(&self) -> bool {
        matches!(self, Self::Experimental { .. })
    }

    /// Return the RFC 5482 User Timeout as a `(granularity, value)` pair, if
    /// this option is a User Timeout option.
    ///
    /// `granularity` is the Granularity (G) flag and `value` is the 15-bit User
    /// Timeout value. Backed by RFC 5482 and `docs/tcp-rfc-manifest.md`.
    pub const fn user_timeout_value(&self) -> Option<(bool, u16)> {
        match self {
            Self::UserTimeout { granularity, value } => Some((*granularity, *value)),
            _ => None,
        }
    }

    /// Return the RFC 5925 TCP Authentication Option fields as a
    /// `(key_id, rnext_key_id, mac)` tuple, if this option is a TCP-AO option.
    ///
    /// The MAC bytes are returned exactly as preserved on the wire; libcrafter
    /// never computes or validates them. Named with a `_value` suffix to avoid
    /// colliding with the [`TcpOption::tcp_authentication`] constructor. Backed
    /// by RFC 5925 and `docs/tcp-rfc-manifest.md`.
    pub fn tcp_authentication_value(&self) -> Option<(u8, u8, &[u8])> {
        match self {
            Self::AuthenticationOption {
                key_id,
                rnext_key_id,
                mac,
            } => Some((*key_id, *rnext_key_id, mac)),
            _ => None,
        }
    }

    /// Return the TCP-AO KeyID, if this option is a TCP Authentication Option.
    ///
    /// Backed by RFC 5925 and `docs/tcp-rfc-manifest.md`.
    pub const fn key_id(&self) -> Option<u8> {
        match self {
            Self::AuthenticationOption { key_id, .. } => Some(*key_id),
            _ => None,
        }
    }

    /// Return the TCP-AO RNextKeyID, if this option is a TCP Authentication
    /// Option.
    ///
    /// Backed by RFC 5925 and `docs/tcp-rfc-manifest.md`.
    pub const fn rnext_key_id(&self) -> Option<u8> {
        match self {
            Self::AuthenticationOption { rnext_key_id, .. } => Some(*rnext_key_id),
            _ => None,
        }
    }

    /// Return the preserved TCP-AO Message Authentication Code bytes, if this
    /// option is a TCP Authentication Option.
    ///
    /// The bytes are the verbatim wire MAC; libcrafter never computes or
    /// validates them. Backed by RFC 5925 and `docs/tcp-rfc-manifest.md`.
    pub fn authentication_mac(&self) -> Option<&[u8]> {
        match self {
            Self::AuthenticationOption { mac, .. } => Some(mac),
            _ => None,
        }
    }

    /// Return the preserved RFC 8547 TCP-ENO suboption bytes, if this option is
    /// a TCP-ENO option.
    ///
    /// The bytes are the verbatim wire suboption sequence; libcrafter never
    /// negotiates, parses, or validates them. Named with a `_suboptions` suffix
    /// to avoid colliding with the [`TcpOption::tcp_eno`] constructor. Backed by
    /// RFC 8547 and `docs/tcp-rfc-manifest.md`.
    pub fn tcp_eno_suboptions(&self) -> Option<&[u8]> {
        match self {
            Self::TcpEno { suboptions } => Some(suboptions),
            _ => None,
        }
    }

    /// Return the RFC 9768 Accurate ECN option kind encoding the counter order
    /// (`TCP_OPTION_ACCURATE_ECN_ORDER_0` = 172 or
    /// `TCP_OPTION_ACCURATE_ECN_ORDER_1` = 174), if this option is an AccECN
    /// option.
    ///
    /// The kind byte is wire-significant because it selects the order in which
    /// the ECN byte counters appear. Backed by RFC 9768 and
    /// `docs/tcp-rfc-manifest.md`.
    pub const fn accurate_ecn_order(&self) -> Option<u8> {
        match self {
            Self::AccurateEcn { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// Return the preserved RFC 9768 Accurate ECN counter/payload bytes (after
    /// the kind/length header), if this option is an AccECN option.
    ///
    /// The bytes are the verbatim wire counters; libcrafter never parses,
    /// interprets, or reacts to them. Backed by RFC 9768 and
    /// `docs/tcp-rfc-manifest.md`.
    pub fn accurate_ecn_data(&self) -> Option<&[u8]> {
        match self {
            Self::AccurateEcn { data, .. } => Some(data),
            _ => None,
        }
    }

    /// Return the RFC 9768 Accurate ECN option as an `(order_kind, data)` pair,
    /// if this option is an AccECN option.
    ///
    /// `order_kind` is the AccECN0/AccECN1 kind encoding the counter order and
    /// `data` is the verbatim counter/payload byte slice. Named with a `_value`
    /// suffix to avoid colliding with the [`TcpOption::accurate_ecn`]
    /// constructor. Backed by RFC 9768 and `docs/tcp-rfc-manifest.md`.
    pub fn accurate_ecn_value(&self) -> Option<(u8, &[u8])> {
        match self {
            Self::AccurateEcn { kind, data } => Some((*kind, data)),
            _ => None,
        }
    }

    /// Return true when this option is an RFC 9768 Accurate ECN (AccECN) option.
    ///
    /// Backed by RFC 9768 and `docs/tcp-rfc-manifest.md`.
    pub const fn is_accurate_ecn(&self) -> bool {
        matches!(self, Self::AccurateEcn { .. })
    }

    /// Return the kind byte of a generic (unknown or caller-defined) option, if
    /// this option is generic.
    pub const fn generic_kind(&self) -> Option<u8> {
        match self {
            Self::Generic { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// Return the payload bytes of a generic option, if this option is generic.
    pub fn generic_data(&self) -> Option<&[u8]> {
        match self {
            Self::Generic { data, .. } => Some(data),
            _ => None,
        }
    }

    /// Encoded option length in bytes.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::EndOfList | Self::NoOperation => 1,
            Self::MaximumSegmentSize(_) => 4,
            Self::WindowScale(_) => 3,
            Self::SackPermitted => 2,
            Self::Sack(blocks) => 2 + blocks.len() * 8,
            Self::Timestamp { .. } => 10,
            Self::MultipathTcp { data, .. } => 2 + data.len().max(1),
            Self::ExtendedDataOffset(edo) => edo.option_len() as usize,
            Self::FastOpen(cookie) => 2 + cookie.len(),
            Self::Experimental { data, .. } => 4 + data.len(),
            Self::UserTimeout { .. } => TCP_OPTION_USER_TIMEOUT_LEN as usize,
            // kind, length, KeyID, RNextKeyID, then the preserved MAC bytes.
            Self::AuthenticationOption { mac, .. } => {
                TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN as usize + mac.len()
            }
            // kind, length, then the preserved suboption bytes.
            Self::TcpEno { suboptions } => TCP_OPTION_TCP_ENO_MIN_LEN as usize + suboptions.len(),
            // kind, length, then the preserved order-specific counter bytes.
            Self::AccurateEcn { data, .. } => TCP_OPTION_ACCURATE_ECN_MIN_LEN as usize + data.len(),
            Self::Generic { data, .. } => 2 + data.len(),
        }
    }

    /// Encode this option to bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let len = self.encoded_len();
        if len > u8::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                "tcp.option.length",
                "TCP option length must fit in one byte",
            ));
        }

        let mut bytes = Vec::with_capacity(len);
        match self {
            Self::EndOfList => bytes.push(TCP_OPTION_EOL),
            Self::NoOperation => bytes.push(TCP_OPTION_NOP),
            Self::MaximumSegmentSize(mss) => {
                bytes.extend_from_slice(&[TCP_OPTION_MSS, 4]);
                bytes.extend_from_slice(&mss.to_be_bytes());
            }
            Self::WindowScale(shift) => {
                bytes.extend_from_slice(&[TCP_OPTION_WINDOW_SCALE, 3, *shift]);
            }
            Self::SackPermitted => {
                bytes.extend_from_slice(&[TCP_OPTION_SACK_PERMITTED, 2]);
            }
            Self::Sack(blocks) => {
                bytes.extend_from_slice(&[TCP_OPTION_SACK, len as u8]);
                for block in blocks {
                    bytes.extend_from_slice(&block.left_edge.to_be_bytes());
                    bytes.extend_from_slice(&block.right_edge.to_be_bytes());
                }
            }
            Self::Timestamp { value, echo_reply } => {
                bytes.extend_from_slice(&[TCP_OPTION_TIMESTAMP, 10]);
                bytes.extend_from_slice(&value.to_be_bytes());
                bytes.extend_from_slice(&echo_reply.to_be_bytes());
            }
            Self::MultipathTcp { subtype, data } => {
                if *subtype > 0x0f {
                    return Err(CrafterError::invalid_field_value(
                        "tcp.option.mptcp.subtype",
                        "MPTCP subtype must fit in four bits",
                    ));
                }
                bytes.extend_from_slice(&[TCP_OPTION_MPTCP, len as u8]);
                if let Some((first, rest)) = data.split_first() {
                    bytes.push((subtype << 4) | (first & 0x0f));
                    bytes.extend_from_slice(rest);
                } else {
                    bytes.push(subtype << 4);
                }
            }
            Self::ExtendedDataOffset(edo) => {
                bytes.extend_from_slice(&[TCP_OPTION_EDO, edo.option_len()]);
                match edo {
                    TcpExtendedDataOffset::Request => {}
                    TcpExtendedDataOffset::HeaderLength { header_length } => {
                        bytes.extend_from_slice(&header_length.to_be_bytes());
                    }
                    TcpExtendedDataOffset::HeaderAndSegmentLength {
                        header_length,
                        segment_length,
                    } => {
                        bytes.extend_from_slice(&header_length.to_be_bytes());
                        bytes.extend_from_slice(&segment_length.to_be_bytes());
                    }
                }
            }
            Self::FastOpen(cookie) => {
                bytes.extend_from_slice(&[TCP_OPTION_FAST_OPEN, len as u8]);
                bytes.extend_from_slice(cookie);
            }
            Self::Experimental {
                kind,
                experiment_id,
                data,
            } => {
                if *kind == TCP_OPTION_EOL || *kind == TCP_OPTION_NOP {
                    return Err(CrafterError::invalid_field_value(
                        "tcp.option.experimental.kind",
                        "experimental option kind must carry a length byte",
                    ));
                }
                bytes.extend_from_slice(&[*kind, len as u8]);
                bytes.extend_from_slice(&experiment_id.to_be_bytes());
                bytes.extend_from_slice(data);
            }
            Self::UserTimeout { granularity, value } => {
                // RFC 5482 section 3: 16-bit field with the Granularity (G) flag
                // in the most-significant bit and the 15-bit User Timeout value
                // in the remaining bits.
                let field = ((*granularity as u16) << 15) | (value & 0x7fff);
                bytes.extend_from_slice(&[TCP_OPTION_USER_TIMEOUT, TCP_OPTION_USER_TIMEOUT_LEN]);
                bytes.extend_from_slice(&field.to_be_bytes());
            }
            Self::AuthenticationOption {
                key_id,
                rnext_key_id,
                mac,
            } => {
                // RFC 5925 section 2.2: kind, length, KeyID, RNextKeyID, then the
                // MAC. The MAC bytes are preserved verbatim and never recomputed.
                bytes.extend_from_slice(&[
                    TCP_OPTION_TCP_AUTHENTICATION,
                    len as u8,
                    *key_id,
                    *rnext_key_id,
                ]);
                bytes.extend_from_slice(mac);
            }
            Self::TcpEno { suboptions } => {
                // RFC 8547 section 4: kind, length, then the suboption sequence.
                // The suboption bytes are preserved verbatim and never
                // interpreted or negotiated.
                bytes.extend_from_slice(&[TCP_OPTION_TCP_ENO, len as u8]);
                bytes.extend_from_slice(suboptions);
            }
            Self::AccurateEcn { kind, data } => {
                // RFC 9768 section 3.2.3.3: kind (172/174, encoding the counter
                // order), length, then the order-specific ECN byte counters. The
                // counter bytes are preserved verbatim and never interpreted; no
                // AccECN feedback or congestion-control reaction is performed.
                if *kind == TCP_OPTION_EOL || *kind == TCP_OPTION_NOP {
                    return Err(CrafterError::invalid_field_value(
                        "tcp.option.accurate_ecn.kind",
                        "AccECN option kind must carry a length byte",
                    ));
                }
                bytes.extend_from_slice(&[*kind, len as u8]);
                bytes.extend_from_slice(data);
            }
            Self::Generic { kind, data } => {
                if *kind == TCP_OPTION_EOL || *kind == TCP_OPTION_NOP {
                    return Err(CrafterError::invalid_field_value(
                        "tcp.option.kind",
                        "EOL and NOP options do not carry a length byte",
                    ));
                }
                bytes.extend_from_slice(&[*kind, len as u8]);
                bytes.extend_from_slice(data);
            }
        }

        Ok(bytes)
    }

    /// Decode all options from a raw TCP option byte slice.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>> {
        TcpOptionIter::new(bytes).collect()
    }
}

/// Iterator over encoded TCP options.
#[derive(Debug, Clone)]
pub struct TcpOptionIter<'a> {
    bytes: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> TcpOptionIter<'a> {
    /// Create an iterator over raw TCP option bytes.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            done: false,
        }
    }
}

impl Iterator for TcpOptionIter<'_> {
    type Item = Result<TcpOption>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.bytes.len() {
            return None;
        }

        let start = self.offset;
        let kind = self.bytes[start];
        match kind {
            TCP_OPTION_EOL => {
                self.done = true;
                self.offset = self.bytes.len();
                Some(Ok(TcpOption::EndOfList))
            }
            TCP_OPTION_NOP => {
                self.offset += 1;
                Some(Ok(TcpOption::NoOperation))
            }
            _ => {
                if start + 2 > self.bytes.len() {
                    self.done = true;
                    return Some(Err(CrafterError::buffer_too_short(
                        "tcp option",
                        start + 2,
                        self.bytes.len(),
                    )));
                }

                let len = self.bytes[start + 1] as usize;
                if len < 2 {
                    self.done = true;
                    return Some(Err(CrafterError::invalid_field_value(
                        "tcp.option.length",
                        "option length must be at least 2 bytes",
                    )));
                }
                if start + len > self.bytes.len() {
                    self.done = true;
                    return Some(Err(CrafterError::buffer_too_short(
                        "tcp option",
                        start + len,
                        self.bytes.len(),
                    )));
                }

                let option_bytes = &self.bytes[start..start + len];
                self.offset += len;
                Some(decode_tcp_option(option_bytes))
            }
        }
    }
}

pub(crate) fn validate_tcp_options(options: &[u8]) -> Result<()> {
    for option in TcpOptionIter::new(options) {
        option?;
    }
    Ok(())
}

fn decode_tcp_option(bytes: &[u8]) -> Result<TcpOption> {
    let kind = bytes[0];
    let data = &bytes[2..];
    match kind {
        TCP_OPTION_MSS => {
            validate_tcp_option_len("tcp.option.mss", bytes.len(), 4)?;
            Ok(TcpOption::MaximumSegmentSize(read_u16_be(data)?))
        }
        TCP_OPTION_WINDOW_SCALE => {
            validate_tcp_option_len("tcp.option.window_scale", bytes.len(), 3)?;
            Ok(TcpOption::WindowScale(data[0]))
        }
        TCP_OPTION_SACK_PERMITTED => {
            validate_tcp_option_len("tcp.option.sack_permitted", bytes.len(), 2)?;
            Ok(TcpOption::SackPermitted)
        }
        TCP_OPTION_SACK => decode_tcp_sack_option(data, bytes.len()),
        TCP_OPTION_TIMESTAMP => {
            validate_tcp_option_len("tcp.option.timestamp", bytes.len(), 10)?;
            Ok(TcpOption::Timestamp {
                value: read_u32_be(&data[0..4])?,
                echo_reply: read_u32_be(&data[4..8])?,
            })
        }
        TCP_OPTION_MPTCP => {
            if data.is_empty() {
                return Err(CrafterError::invalid_field_value(
                    "tcp.option.mptcp",
                    "MPTCP option must include a subtype byte",
                ));
            }
            Ok(TcpOption::MultipathTcp {
                subtype: data[0] >> 4,
                data: data.to_vec(),
            })
        }
        TCP_OPTION_USER_TIMEOUT => decode_tcp_user_timeout_option(data, bytes.len()),
        TCP_OPTION_TCP_AUTHENTICATION => decode_tcp_authentication_option(data, bytes.len()),
        TCP_OPTION_TCP_ENO => decode_tcp_eno_option(data, bytes.len()),
        TCP_OPTION_ACCURATE_ECN_ORDER_0 | TCP_OPTION_ACCURATE_ECN_ORDER_1 => {
            decode_tcp_accurate_ecn_option(kind, data, bytes.len())
        }
        TCP_OPTION_EDO => decode_tcp_edo_option(data, bytes.len()),
        TCP_OPTION_FAST_OPEN => Ok(TcpOption::FastOpen(data.to_vec())),
        TCP_OPTION_EXPERIMENTAL_1 | TCP_OPTION_EXPERIMENTAL_2 => {
            decode_tcp_experimental_option(kind, data, bytes.len())
        }
        _ => Ok(TcpOption::Generic {
            kind,
            data: data.to_vec(),
        }),
    }
}

fn decode_tcp_experimental_option(kind: u8, data: &[u8], len: usize) -> Result<TcpOption> {
    if (len as u8) < TCP_OPTION_EXPERIMENTAL_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tcp.option.experimental.length",
            "RFC 6994 experimental option must be at least 4 bytes (kind, length, 16-bit ExID)",
        ));
    }
    Ok(TcpOption::Experimental {
        kind,
        experiment_id: read_u16_be(&data[0..2])?,
        data: data[2..].to_vec(),
    })
}

fn decode_tcp_user_timeout_option(data: &[u8], len: usize) -> Result<TcpOption> {
    validate_tcp_option_len("tcp.option.user_timeout", len, TCP_OPTION_USER_TIMEOUT_LEN as usize)?;
    // RFC 5482 section 3: the 16-bit field's most-significant bit is the
    // Granularity (G) flag and the remaining 15 bits are the User Timeout value.
    let field = read_u16_be(&data[0..2])?;
    Ok(TcpOption::UserTimeout {
        granularity: field & 0x8000 != 0,
        value: field & 0x7fff,
    })
}

fn decode_tcp_authentication_option(data: &[u8], len: usize) -> Result<TcpOption> {
    // RFC 5925 section 2.2: kind, length, KeyID, RNextKeyID, then the MAC. The
    // minimum length is 4 bytes (the two id bytes plus the kind/length header)
    // for an empty MAC; libcrafter preserves the MAC bytes without computing or
    // validating them.
    if (len as u8) < TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tcp.option.authentication.length",
            "RFC 5925 TCP-AO option must be at least 4 bytes (kind, length, KeyID, RNextKeyID)",
        ));
    }
    Ok(TcpOption::AuthenticationOption {
        key_id: data[0],
        rnext_key_id: data[1],
        mac: data[2..].to_vec(),
    })
}

fn decode_tcp_eno_option(data: &[u8], len: usize) -> Result<TcpOption> {
    // RFC 8547 section 4: kind, length, then a sequence of suboption bytes. The
    // minimum length is 2 bytes (the kind/length header) for an empty suboption
    // sequence. libcrafter preserves the suboption bytes without negotiating,
    // parsing, or validating them; the TCP-ENO handshake and tcpcrypt session
    // behavior are out of scope.
    if (len as u8) < TCP_OPTION_TCP_ENO_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tcp.option.eno.length",
            "RFC 8547 TCP-ENO option must be at least 2 bytes (kind, length)",
        ));
    }
    Ok(TcpOption::TcpEno {
        suboptions: data.to_vec(),
    })
}

fn decode_tcp_accurate_ecn_option(kind: u8, data: &[u8], len: usize) -> Result<TcpOption> {
    // RFC 9768 section 3.2.3.3: kind (172/174, encoding the counter order),
    // length, then the order-specific ECN byte counters. The minimum length is 2
    // bytes (the kind/length header) with no counters. libcrafter preserves the
    // order (via the kind) and the counter bytes verbatim, without parsing,
    // interpreting, or reacting to them; the AccECN feedback algorithm and any
    // congestion-control reaction are out of scope.
    if (len as u8) < TCP_OPTION_ACCURATE_ECN_MIN_LEN {
        return Err(CrafterError::invalid_field_value(
            "tcp.option.accurate_ecn.length",
            "RFC 9768 AccECN option must be at least 2 bytes (kind, length)",
        ));
    }
    Ok(TcpOption::AccurateEcn {
        kind,
        data: data.to_vec(),
    })
}

/// Return `a <= b` under 32-bit serial-number arithmetic (RFC 1982 / RFC 9293).
///
/// Used by the D-SACK first-block heuristic so sequence-number comparisons stay
/// correct across the 32-bit wraparound.
fn serial_le(a: u32, b: u32) -> bool {
    // `a <= b` iff `b - a` (mod 2^32) is in the lower half of the number space.
    b.wrapping_sub(a) < 0x8000_0000
}

fn decode_tcp_sack_option(data: &[u8], len: usize) -> Result<TcpOption> {
    if len < 10 || (len - 2) % 8 != 0 {
        return Err(CrafterError::invalid_field_value(
            "tcp.option.sack",
            "SACK option payload must contain one or more 8-byte blocks",
        ));
    }

    let mut blocks = Vec::with_capacity((len - 2) / 8);
    for chunk in data.chunks_exact(8) {
        blocks.push(TcpSackBlock {
            left_edge: read_u32_be(&chunk[0..4])?,
            right_edge: read_u32_be(&chunk[4..8])?,
        });
    }
    Ok(TcpOption::Sack(blocks))
}

fn decode_tcp_edo_option(data: &[u8], len: usize) -> Result<TcpOption> {
    let edo = match len as u8 {
        TCP_EDO_REQUEST_LEN => TcpExtendedDataOffset::Request,
        TCP_EDO_HEADER_LEN => TcpExtendedDataOffset::HeaderLength {
            header_length: read_u16_be(&data[0..2])?,
        },
        TCP_EDO_HEADER_AND_SEGMENT_LEN => TcpExtendedDataOffset::HeaderAndSegmentLength {
            header_length: read_u16_be(&data[0..2])?,
            segment_length: read_u16_be(&data[2..4])?,
        },
        _ => {
            return Err(CrafterError::invalid_field_value(
                "tcp.option.edo.length",
                "EDO length must be 2, 4, or 6 bytes",
            ))
        }
    };
    Ok(TcpOption::ExtendedDataOffset(edo))
}

fn validate_tcp_option_len(field: &'static str, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(CrafterError::invalid_field_value(
            field,
            "TCP option has an invalid fixed length",
        ));
    }
    Ok(())
}

/// Return the IANA registry classification for a TCP option kind.
///
/// The assigned set follows the IANA TCP Option Kind Numbers registry (under
/// IANA TCP Parameters) and the kind table in `docs/tcp-rfc-manifest.md`:
/// kinds 0-15, 18, 19, 27-30, 34, 69, 172, and 174 carry current registry
/// names. Kinds 253 and 254 are the RFC 6994 / RFC 3692-style experimental
/// kinds. Every other kind (for example the draft-only EDO kind 237) is
/// unassigned in the current registry and stays inspectable as such.
///
/// Legacy security option: the MD5 Signature kind (`TCP_OPTION_MD5_SIGNATURE` =
/// 19, the `Md5` option of RFC 2385, obsoleted by RFC 5925/TCP-AO) is reported
/// as `Assigned` and preserved through the generic representation. `crafter`
/// performs no signing, key management, or signature validation for this legacy
/// option; it only classifies and round-trips its bytes (see the "Legacy
/// Security Options" note in `docs/tcp-rfc-manifest.md`).
///
/// ```rust
/// use crafter::prelude::*;
/// use crafter::protocols::transport::{tcp_option_kind_class, tcp_option_kind_name};
///
/// // A standardized option kind is Assigned and has a registry name.
/// assert_eq!(tcp_option_kind_class(TCP_OPTION_MSS), TcpOptionKindClass::Assigned);
/// assert_eq!(tcp_option_kind_name(TCP_OPTION_MSS), "MSS");
///
/// // Experimental kinds 253/254 classify separately from assigned kinds.
/// assert_eq!(tcp_option_kind_class(253), TcpOptionKindClass::Experimental);
///
/// // An unassigned kind stays inspectable with a generic name.
/// assert_eq!(tcp_option_kind_class(200), TcpOptionKindClass::Unassigned);
/// assert_eq!(tcp_option_kind_name(200), "opt");
/// ```
pub const fn tcp_option_kind_class(kind: u8) -> TcpOptionKindClass {
    match kind {
        TCP_OPTION_EXPERIMENTAL_1 | TCP_OPTION_EXPERIMENTAL_2 => TcpOptionKindClass::Experimental,
        TCP_OPTION_EOL
        | TCP_OPTION_NOP
        | TCP_OPTION_MSS
        | TCP_OPTION_WINDOW_SCALE
        | TCP_OPTION_SACK_PERMITTED
        | TCP_OPTION_SACK
        // Echo / Echo Reply (RFC 1072, obsoleted by RFC 7323).
        | 6
        | 7
        | TCP_OPTION_TIMESTAMP
        // Partial Order Connection options (RFC 1693, RFC 6247).
        | 9
        | 10
        // CC, CC.NEW, CC.ECHO (RFC 1644, RFC 6247).
        | 11
        | 12
        | 13
        // TCP Alternate Checksum Request / Data (RFC 1146, RFC 6247).
        | 14
        | 15
        // Trailer Checksum (historic, Stev Knowles).
        | 18
        | TCP_OPTION_MD5_SIGNATURE
        // Quick-Start Response (RFC 4782).
        | 27
        | TCP_OPTION_USER_TIMEOUT
        | TCP_OPTION_TCP_AUTHENTICATION
        | TCP_OPTION_MPTCP
        | TCP_OPTION_FAST_OPEN
        | TCP_OPTION_TCP_ENO
        | TCP_OPTION_ACCURATE_ECN_ORDER_0
        | TCP_OPTION_ACCURATE_ECN_ORDER_1 => TcpOptionKindClass::Assigned,
        _ => TcpOptionKindClass::Unassigned,
    }
}

/// Return a short, source-backed display name for a TCP option kind.
///
/// Names follow the IANA TCP Option Kind Numbers registry (under IANA TCP
/// Parameters) and `docs/tcp-rfc-manifest.md`. Assigned-but-unmodeled and
/// unassigned kinds return the generic `"opt"` token so the caller can still
/// pair the name with the numeric kind and registry class for inspection. This
/// is a display helper for `summary()`/`show()` only; it performs no
/// classification decision (use [`tcp_option_kind_class`] for that).
pub const fn tcp_option_kind_name(kind: u8) -> &'static str {
    match kind {
        TCP_OPTION_EOL => "EOL",
        TCP_OPTION_NOP => "NOP",
        TCP_OPTION_MSS => "MSS",
        TCP_OPTION_WINDOW_SCALE => "WScale",
        TCP_OPTION_SACK_PERMITTED => "SAckOK",
        TCP_OPTION_SACK => "SAck",
        TCP_OPTION_TIMESTAMP => "TS",
        TCP_OPTION_MD5_SIGNATURE => "Md5",
        TCP_OPTION_USER_TIMEOUT => "UTO",
        TCP_OPTION_TCP_AUTHENTICATION => "AO",
        TCP_OPTION_MPTCP => "MPTCP",
        TCP_OPTION_FAST_OPEN => "FastOpen",
        TCP_OPTION_TCP_ENO => "ENO",
        TCP_OPTION_ACCURATE_ECN_ORDER_0 | TCP_OPTION_ACCURATE_ECN_ORDER_1 => "AccECN",
        TCP_OPTION_EDO => "EDO",
        TCP_OPTION_EXPERIMENTAL_1 | TCP_OPTION_EXPERIMENTAL_2 => "Exp",
        _ => "opt",
    }
}

/// Return true when a TCP option kind has a current IANA registry assignment.
pub const fn tcp_option_kind_is_assigned(kind: u8) -> bool {
    matches!(
        tcp_option_kind_class(kind),
        TcpOptionKindClass::Assigned | TcpOptionKindClass::Experimental
    )
}

/// Return true when a TCP option kind is an RFC 6994 experimental kind.
pub const fn tcp_option_kind_is_experimental(kind: u8) -> bool {
    matches!(tcp_option_kind_class(kind), TcpOptionKindClass::Experimental)
}

/// Return whether a TCP Window Scale shift count is within RFC 7323's valid
/// range (`0..=14`).
///
/// RFC 7323 section 2.3 caps the shift exponent at 14
/// ([`TCP_WINDOW_SCALE_MAX_SHIFT`](super::constants::TCP_WINDOW_SCALE_MAX_SHIFT)),
/// keeping the largest scaled offered window below 2^32. A receiver that gets a
/// larger shift is required to use 14 instead, but the value still appears on
/// the wire verbatim.
///
/// This helper is validity *guidance* only. `crafter` never clamps or rejects a
/// shift on encode: deliberately out-of-range shifts (for example 15 or 255)
/// remain constructible via [`TcpOption::window_scale`] and round-trip
/// byte-for-byte, so generated tools can exercise a stack with malformed Window
/// Scale options. Use this function (or
/// [`TcpOption::window_scale_shift_is_valid`]) to check a shift, not to gate
/// construction.
///
/// Backed by RFC 7323 section 2.3 and `docs/tcp-rfc-manifest.md`.
pub const fn valid_window_scale(shift: u8) -> bool {
    shift <= TCP_WINDOW_SCALE_MAX_SHIFT
}
