//! TCP segment sizing and option-budget helpers.
//!
//! These are pure, inspectable helper functions for packet builders. They size
//! correct TCP segments and document fragmentation-adjacent facts (MSS, option
//! budgeting, effective payload sizing) without implementing fragmentation,
//! path-MTU probing, reassembly, or any state machine. Every constant is backed
//! by an RFC and `docs/tcp-rfc-manifest.md`, "Segment Sizing And
//! Fragmentation-Adjacent Guidance (Documentation Only)".
//!
//! Source anchors:
//! - RFC 9293 section 3.1 — TCP header layout and the 40-octet option budget
//!   (Data Offset 4 bits, max 15 32-bit words).
//! - RFC 9293 section 3.7.1, RFC 1122, RFC 879 — the IPv4 default send MSS of
//!   536 octets when the path MTU is unknown.
//! - RFC 8200 section 5 / RFC 8201 — the 1280-octet IPv6 minimum link MTU.
//! - RFC 1191 / RFC 8201 / RFC 8899 — PMTUD / PLPMTUD guidance only; `crafter`
//!   does not probe a path MTU. Callers supply `path_mtu`.

use super::constants::{
    IPV4_HEADER_LEN_FOR_MSS, IPV6_HEADER_LEN_FOR_MSS, IPV6_MINIMUM_MTU, TCP_DEFAULT_IPV4_MSS,
    TCP_FIXED_HEADER_LEN, TCP_MAX_OPTION_BYTES,
};

/// Round a raw TCP option-byte count up to the next 32-bit boundary.
///
/// TCP options are padded with zero/EOL bytes so the header length is a whole
/// number of 32-bit words (RFC 9293 section 3.1). Used when filling Data Offset
/// from unset option bytes during `compile()`.
pub(crate) fn padded_options_len(len: usize) -> usize {
    (len + 3) & !3
}

/// TCP header length in octets for a given raw option-byte count.
///
/// The fixed TCP header is 20 octets; options are padded to a 32-bit boundary
/// and added on top (RFC 9293 section 3.1). With no options this returns 20;
/// with the full 40-octet option budget it returns the 60-octet maximum.
///
/// This is a pure sizing helper. It does not validate that `option_bytes` fits
/// the 40-octet budget — deliberate over-budget values stay constructible for
/// stack testing; use [`option_budget`] to check the cap.
pub const fn tcp_header_len(option_bytes: usize) -> usize {
    // `const fn` cannot call the `pub(crate)` `padded_options_len`, so pad
    // inline with the same 32-bit-boundary rule.
    TCP_FIXED_HEADER_LEN + ((option_bytes + 3) & !3)
}

/// Maximum TCP option-byte budget: 40 octets (RFC 9293 section 3.1).
///
/// Data Offset is 4 bits, capping the TCP header at 15 32-bit words (60 octets);
/// after the 20-octet fixed header that leaves 40 octets for options. This is
/// the hard ceiling shared by MSS, Window Scale, SACK-Permitted, Timestamps, and
/// every other option on a SYN (see `docs/tcp-rfc-manifest.md`).
pub const fn option_budget() -> usize {
    TCP_MAX_OPTION_BYTES
}

/// Remaining TCP option-byte budget given `used` option bytes already consumed.
///
/// Returns how many more option octets fit under the 40-octet Data Offset cap
/// (RFC 9293 section 3.1). Saturates at zero: if `used` already meets or exceeds
/// the budget the result is 0, never a negative or wrapped value. This is the
/// inspectable form of "can another option still fit?" without modeling any
/// option layout.
pub const fn remaining_option_budget(used: usize) -> usize {
    TCP_MAX_OPTION_BYTES.saturating_sub(used)
}

/// Maximum TCP payload (user data) octets for a caller-provided path MTU.
///
/// Subtracts the IP header length and the TCP header length from the path MTU:
/// `path_mtu - ip_header_len - tcp_header_len`. `crafter` never discovers a path
/// MTU itself (RFC 1191 / RFC 8201 / RFC 8899 PMTUD/PLPMTUD are guidance only);
/// the caller supplies `path_mtu` from its own knowledge or a fixed assumption.
///
/// Saturating: if the headers meet or exceed the path MTU the result is 0, never
/// an underflow. This is a pure sizing helper and does not fragment, probe, or
/// emit a segment.
pub const fn max_tcp_payload(
    path_mtu: usize,
    ip_header_len: usize,
    tcp_header_len: usize,
) -> usize {
    path_mtu
        .saturating_sub(ip_header_len)
        .saturating_sub(tcp_header_len)
}

/// Source-backed effective TCP MSS guidance for IPv4.
///
/// Returns the largest TCP payload an IPv4 sender should offer for a given path
/// MTU, derived as `path_mtu - IPv4 header - TCP header` over the fixed 20-octet
/// IPv4 and TCP headers (RFC 9293 section 3.7.1). When `path_mtu` is `None` (the
/// path MTU is unknown) this falls back to the RFC 9293 / RFC 1122 / RFC 879
/// default send MSS of 536 octets. The derived value is also floored at 536 so
/// guidance never recommends a smaller-than-default MSS for an unusually small
/// (but still IPv4-legal) MTU; callers that want the raw derivation can use
/// [`max_tcp_payload`] directly.
///
/// Pure guidance: it never sizes below the default, never probes, and never
/// fragments. Backed by `docs/tcp-rfc-manifest.md`.
pub const fn effective_mss_ipv4(path_mtu: Option<usize>) -> u16 {
    match path_mtu {
        None => TCP_DEFAULT_IPV4_MSS,
        Some(mtu) => {
            let derived = max_tcp_payload(mtu, IPV4_HEADER_LEN_FOR_MSS, TCP_FIXED_HEADER_LEN);
            if derived < TCP_DEFAULT_IPV4_MSS as usize {
                TCP_DEFAULT_IPV4_MSS
            } else if derived > u16::MAX as usize {
                u16::MAX
            } else {
                derived as u16
            }
        }
    }
}

/// Source-backed effective TCP MSS guidance for IPv6.
///
/// Returns the largest TCP payload an IPv6 sender should offer for a given path
/// MTU, derived as `path_mtu - IPv6 header - TCP header` over the fixed 40-octet
/// IPv6 and 20-octet TCP headers (RFC 9293 section 3.7.1, RFC 8200). When
/// `path_mtu` is `None` (the path MTU is unknown) this uses the RFC 8200 / RFC
/// 8201 IPv6 minimum link MTU of 1280 octets, giving an effective MSS of
/// `1280 - 40 - 20 = 1220` octets. Any supplied MTU is also floored at the 1280
/// minimum before deriving, because IPv6 links must support at least 1280
/// octets, so guidance never drops below the minimum-MTU MSS.
///
/// Pure guidance: it never probes a path MTU and never fragments. Backed by
/// `docs/tcp-rfc-manifest.md`.
pub const fn effective_mss_ipv6(path_mtu: Option<usize>) -> u16 {
    let mtu = match path_mtu {
        None => IPV6_MINIMUM_MTU,
        Some(mtu) if mtu < IPV6_MINIMUM_MTU => IPV6_MINIMUM_MTU,
        Some(mtu) => mtu,
    };
    let derived = max_tcp_payload(mtu, IPV6_HEADER_LEN_FOR_MSS, TCP_FIXED_HEADER_LEN);
    if derived > u16::MAX as usize {
        u16::MAX
    } else {
        derived as u16
    }
}

/// Source-backed effective TCP MSS guidance for either IP version.
///
/// Dispatches to [`effective_mss_ipv4`] or [`effective_mss_ipv6`] based on
/// `is_ipv6`, applying the version-specific header sizes and unknown-`path_mtu`
/// defaults (IPv4 default MSS 536 per RFC 9293 / RFC 1122 / RFC 879; IPv6
/// derived from the 1280-octet minimum MTU per RFC 8200 / RFC 8201). This is the
/// single entry point a builder can call without branching on IP version
/// itself.
pub const fn effective_mss(is_ipv6: bool, path_mtu: Option<usize>) -> u16 {
    if is_ipv6 {
        effective_mss_ipv6(path_mtu)
    } else {
        effective_mss_ipv4(path_mtu)
    }
}
