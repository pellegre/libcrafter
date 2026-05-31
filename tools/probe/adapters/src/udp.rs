//! UDP behavioral probe cases.
//!
//! Placeholder module. The UDP echo/transform and ICMP-port-unreachable
//! behavioral cases from the spec are wired into the dispatcher by a later
//! plan step. Until then UDP cases fall through to the shared `decode_failed`
//! outcome in [`crate::common`]. Keeping the module in place now anchors the
//! per-protocol layout so the later step only adds case functions here.

/// Stable identifier for the UDP case module, used while wiring is pending.
pub const MODULE_NAME: &str = "udp";
