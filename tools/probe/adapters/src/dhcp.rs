//! DHCP behavioral probe cases.
//!
//! Placeholder module. The DHCP/BOOTP client-message behavioral cases from the
//! spec are wired into the dispatcher by a later plan step. Until then DHCP
//! cases fall through to the shared `decode_failed` outcome in
//! [`crate::common`]. Keeping the module in place now anchors the per-protocol
//! layout so the later step only adds case functions here.

/// Stable identifier for the DHCP case module, used while wiring is pending.
pub const MODULE_NAME: &str = "dhcp";
