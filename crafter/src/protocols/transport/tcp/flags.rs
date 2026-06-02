//! TCP control-bit constants and flag summaries.

/// TCP FIN flag.
pub const TCP_FLAG_FIN: u16 = 0x001;
/// TCP SYN flag.
pub const TCP_FLAG_SYN: u16 = 0x002;
/// TCP RST flag.
pub const TCP_FLAG_RST: u16 = 0x004;
/// TCP PSH flag.
pub const TCP_FLAG_PSH: u16 = 0x008;
/// TCP ACK flag.
pub const TCP_FLAG_ACK: u16 = 0x010;
/// TCP URG flag.
pub const TCP_FLAG_URG: u16 = 0x020;
/// TCP ECE flag.
pub const TCP_FLAG_ECE: u16 = 0x040;
/// TCP CWR flag.
pub const TCP_FLAG_CWR: u16 = 0x080;
/// TCP AE (Accurate ECN) flag.
///
/// The `0x100` control-bit position is assigned by IANA to AE (Accurate ECN)
/// per RFC 9768 (More Accurate ECN Feedback in TCP); see
/// `docs/tcp-rfc-manifest.md`. This bit was historically the ECN-nonce sum bit
/// exported as [`TCP_FLAG_NS`], which RFC 8311 deprecated. `TCP_FLAG_AE` is the
/// current source-backed name; `TCP_FLAG_NS` remains a compatibility alias for
/// the same bit value.
pub const TCP_FLAG_AE: u16 = 0x100;
/// TCP NS flag (compatibility alias for the AE / Accurate ECN bit).
///
/// Kept as a permanent compatibility alias for the `0x100` control bit. The
/// current IANA registry name for this bit is AE (Accurate ECN, RFC 9768);
/// prefer [`TCP_FLAG_AE`]. This alias has the same value so existing callers
/// keep working.
pub const TCP_FLAG_NS: u16 = TCP_FLAG_AE;

pub(crate) fn flags_summary(flags: u16) -> String {
    let mut names = Vec::new();
    if flags & TCP_FLAG_AE != 0 {
        // Current IANA name for the 0x100 bit is AE (Accurate ECN, RFC 9768).
        names.push("AE");
    }
    if flags & TCP_FLAG_CWR != 0 {
        names.push("CWR");
    }
    if flags & TCP_FLAG_ECE != 0 {
        names.push("ECE");
    }
    if flags & TCP_FLAG_URG != 0 {
        names.push("URG");
    }
    if flags & TCP_FLAG_ACK != 0 {
        names.push("ACK");
    }
    if flags & TCP_FLAG_PSH != 0 {
        names.push("PSH");
    }
    if flags & TCP_FLAG_RST != 0 {
        names.push("RST");
    }
    if flags & TCP_FLAG_SYN != 0 {
        names.push("SYN");
    }
    if flags & TCP_FLAG_FIN != 0 {
        names.push("FIN");
    }

    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("|")
    }
}

#[cfg(test)]
mod tests {
    use super::{TCP_FLAG_AE, TCP_FLAG_NS};

    #[test]
    fn tcp_flag_public_aliases() {
        // RFC 9768 (Accurate ECN) assigns the 0x100 control bit to AE; the
        // older `NS` name (ECN-nonce, deprecated by RFC 8311) stays as a
        // compatibility alias for the same bit. Both names must compile and
        // resolve to the same value. See docs/tcp-rfc-manifest.md.
        assert_eq!(TCP_FLAG_AE, 0x100);
        assert_eq!(TCP_FLAG_NS, 0x100);
        assert_eq!(TCP_FLAG_AE, TCP_FLAG_NS);
    }
}
