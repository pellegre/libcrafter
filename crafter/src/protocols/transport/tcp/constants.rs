//! TCP wire and IANA option-kind constants.

/// TCP end-of-option-list kind.
pub const TCP_OPTION_EOL: u8 = 0;
/// TCP no-operation option kind.
pub const TCP_OPTION_NOP: u8 = 1;
/// TCP maximum segment size option kind.
pub const TCP_OPTION_MSS: u8 = 2;
/// TCP window scale option kind.
pub const TCP_OPTION_WINDOW_SCALE: u8 = 3;
/// Maximum valid TCP Window Scale shift count (RFC 7323 section 2.3).
///
/// RFC 7323 caps the shift at 14, limiting the largest advertised window to
/// 2^30 so the scaled offered window stays below 2^32 (RFC 7323 section 2.3,
/// "the maximum scale exponent is limited to 14"). `crafter` exposes this as a
/// validity reference only: deliberately out-of-range shifts can still be
/// constructed and encoded for stack testing (see
/// [`valid_window_scale`](super::option::valid_window_scale)).
pub const TCP_WINDOW_SCALE_MAX_SHIFT: u8 = 14;
/// TCP SACK-permitted option kind.
pub const TCP_OPTION_SACK_PERMITTED: u8 = 4;
/// TCP SACK option kind.
pub const TCP_OPTION_SACK: u8 = 5;
/// TCP timestamp option kind.
pub const TCP_OPTION_TIMESTAMP: u8 = 8;
/// TCP MD5 Signature option kind (RFC 2385, obsoleted by RFC 5925/TCP-AO).
///
/// This is a legacy security option. `crafter` preserves and classifies its
/// bytes for inspection and round-trip; it implements no signing, key
/// management, or signature validation. See the "Legacy Security Options" note
/// in `docs/tcp-rfc-manifest.md`.
pub const TCP_OPTION_MD5_SIGNATURE: u8 = 19;
/// TCP User Timeout (UTO) option kind (RFC 5482).
pub const TCP_OPTION_USER_TIMEOUT: u8 = 28;
/// Fixed length byte of an RFC 5482 User Timeout option: kind, length, and a
/// 16-bit field carrying the 1-bit Granularity flag and 15-bit timeout value.
pub const TCP_OPTION_USER_TIMEOUT_LEN: u8 = 4;
/// TCP Authentication Option (TCP-AO) kind (RFC 5925).
pub const TCP_OPTION_TCP_AUTHENTICATION: u8 = 29;
/// Minimum length byte of an RFC 5925 TCP Authentication Option: kind, length,
/// KeyID, and RNextKeyID with an empty MAC field. Real deployments carry a
/// non-empty MAC, but the wire format permits the 4-byte header alone.
pub const TCP_OPTION_TCP_AUTHENTICATION_MIN_LEN: u8 = 4;
/// TCP MPTCP option kind (RFC 8684).
pub const TCP_OPTION_MPTCP: u8 = 30;

// Multipath TCP (MPTCP) option subtypes.
//
// RFC 8684 section 3 encodes the MPTCP message type in the high 4 bits of the
// byte that follows the option kind and length. The IANA "MPTCP Option
// Subtypes" registry (defined by RFC 8684, obsoleting RFC 6824) assigns the
// 4-bit subtype values below. `crafter` preserves MPTCP subtype-specific bytes
// generically via `TcpOption::MultipathTcp`; these constants make the subtype
// nibble inspectable without modeling MPTCP connection state.

/// MPTCP subtype `MP_CAPABLE` (RFC 8684 section 3.1, IANA MPTCP Option
/// Subtypes registry).
pub const MPTCP_SUBTYPE_MP_CAPABLE: u8 = 0x0;
/// MPTCP subtype `MP_JOIN` (RFC 8684 section 3.2, IANA MPTCP Option Subtypes
/// registry).
pub const MPTCP_SUBTYPE_MP_JOIN: u8 = 0x1;
/// MPTCP subtype `DSS` (Data Sequence Signal) (RFC 8684 section 3.3, IANA MPTCP
/// Option Subtypes registry).
pub const MPTCP_SUBTYPE_DSS: u8 = 0x2;
/// MPTCP subtype `ADD_ADDR` (RFC 8684 section 3.4.1, IANA MPTCP Option Subtypes
/// registry).
pub const MPTCP_SUBTYPE_ADD_ADDR: u8 = 0x3;
/// MPTCP subtype `REMOVE_ADDR` (RFC 8684 section 3.4.2, IANA MPTCP Option
/// Subtypes registry).
pub const MPTCP_SUBTYPE_REMOVE_ADDR: u8 = 0x4;
/// MPTCP subtype `MP_PRIO` (RFC 8684 section 3.3.8, IANA MPTCP Option Subtypes
/// registry).
pub const MPTCP_SUBTYPE_MP_PRIO: u8 = 0x5;
/// MPTCP subtype `MP_FAIL` (RFC 8684 section 3.7, IANA MPTCP Option Subtypes
/// registry).
pub const MPTCP_SUBTYPE_MP_FAIL: u8 = 0x6;
/// MPTCP subtype `MP_FASTCLOSE` (RFC 8684 section 3.5, IANA MPTCP Option
/// Subtypes registry).
pub const MPTCP_SUBTYPE_MP_FASTCLOSE: u8 = 0x7;
/// MPTCP subtype `MP_TCPRST` (RFC 8684 section 3.6, IANA MPTCP Option Subtypes
/// registry).
///
/// The IANA registry spells this subtype `MP_TCPRST`; `crafter` exports it as
/// `MPTCP_SUBTYPE_TCPRST`.
pub const MPTCP_SUBTYPE_TCPRST: u8 = 0x8;
/// MPTCP subtype `0xf`, reserved for Private Use / experimentation by the IANA
/// MPTCP Option Subtypes registry (RFC 8684 section 8). No standardized message
/// is assigned to this value.
pub const MPTCP_SUBTYPE_MP_EXPERIMENTAL: u8 = 0xf;

// MP_TCPRST reason codes.
//
// RFC 8684 section 3.6 carries an 8-bit Reason code in the MP_TCPRST subtype
// option and defines the IANA "MPTCP MP_TCPRST Reason Codes" registry. These
// constants make that byte inspectable; `crafter` does not act on the reason.

/// MP_TCPRST reason `0x00`: unspecified error (RFC 8684 section 3.6).
pub const MPTCP_TCPRST_REASON_UNSPECIFIED: u8 = 0x00;
/// MP_TCPRST reason `0x01`: MPTCP-specific error (RFC 8684 section 3.6).
pub const MPTCP_TCPRST_REASON_MPTCP_SPECIFIC: u8 = 0x01;
/// MP_TCPRST reason `0x02`: lack of resources (RFC 8684 section 3.6).
pub const MPTCP_TCPRST_REASON_LACK_OF_RESOURCES: u8 = 0x02;
/// MP_TCPRST reason `0x03`: administratively prohibited (RFC 8684 section 3.6).
pub const MPTCP_TCPRST_REASON_ADMINISTRATIVELY_PROHIBITED: u8 = 0x03;
/// MP_TCPRST reason `0x04`: too much outstanding data (RFC 8684 section 3.6).
pub const MPTCP_TCPRST_REASON_TOO_MUCH_OUTSTANDING_DATA: u8 = 0x04;
/// MP_TCPRST reason `0x05`: unacceptable performance (RFC 8684 section 3.6).
pub const MPTCP_TCPRST_REASON_UNACCEPTABLE_PERFORMANCE: u8 = 0x05;
/// MP_TCPRST reason `0x06`: middlebox interference (RFC 8684 section 3.6).
pub const MPTCP_TCPRST_REASON_MIDDLEBOX_INTERFERENCE: u8 = 0x06;
/// TCP Fast Open Cookie option kind (RFC 7413).
pub const TCP_OPTION_FAST_OPEN: u8 = 34;
/// TCP Encryption Negotiation Option (TCP-ENO) kind (RFC 8547).
pub const TCP_OPTION_TCP_ENO: u8 = 69;
/// Minimum length byte of an RFC 8547 TCP-ENO option: the kind and length bytes
/// alone, with an empty suboption sequence. Real negotiations carry one or more
/// suboption bytes, but the option framing permits the 2-byte header alone.
pub const TCP_OPTION_TCP_ENO_MIN_LEN: u8 = 2;
/// TCP Accurate ECN Order 0 (AccECN0) option kind (RFC 9768).
pub const TCP_OPTION_ACCURATE_ECN_ORDER_0: u8 = 172;
/// TCP Accurate ECN Order 1 (AccECN1) option kind (RFC 9768).
pub const TCP_OPTION_ACCURATE_ECN_ORDER_1: u8 = 174;
/// Minimum length byte of an RFC 9768 Accurate ECN (AccECN) option: the kind and
/// length bytes alone, with no byte-counter fields. Real AccECN options carry
/// one to three 24-bit ECN byte counters (RFC 9768 section 3.2.3.3), but the
/// option framing permits the 2-byte header alone, and the counter fields are
/// preserved verbatim by `crafter` rather than being interpreted.
pub const TCP_OPTION_ACCURATE_ECN_MIN_LEN: u8 = 2;
/// TCP RFC 3692-style experimental option kind 1 (RFC 6994).
pub const TCP_OPTION_EXPERIMENTAL_1: u8 = 253;
/// TCP RFC 3692-style experimental option kind 2 (RFC 6994).
pub const TCP_OPTION_EXPERIMENTAL_2: u8 = 254;
/// Minimum length byte of an RFC 6994 experimental option: kind, length, and a
/// 16-bit Experiment Identifier (ExID) with no experiment data.
pub const TCP_OPTION_EXPERIMENTAL_MIN_LEN: u8 = 4;
/// TCP Extended Data Offset option kind.
pub const TCP_OPTION_EDO: u8 = 237;

/// EDO request length byte.
pub const TCP_EDO_REQUEST_LEN: u8 = 2;
/// EDO length byte carrying an extended TCP header length.
pub const TCP_EDO_HEADER_LEN: u8 = 4;
/// EDO length byte carrying an extended TCP header length and segment length.
pub const TCP_EDO_HEADER_AND_SEGMENT_LEN: u8 = 6;

pub(crate) const TCP_MIN_HEADER_LEN: usize = 20;
pub(crate) const TCP_MAX_HEADER_LEN: usize = 60;
pub(crate) const TCP_MAX_DATA_OFFSET: u8 = 15;
pub(crate) const TCP_MAX_RESERVED: u8 = 0x07;
pub(crate) const TCP_MAX_FLAGS: u16 = 0x01ff;
