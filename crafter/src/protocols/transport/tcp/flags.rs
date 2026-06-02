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
/// TCP NS flag.
pub const TCP_FLAG_NS: u16 = 0x100;

pub(crate) fn flags_summary(flags: u16) -> String {
    let mut names = Vec::new();
    if flags & TCP_FLAG_NS != 0 {
        names.push("NS");
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
