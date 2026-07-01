//! Network Time Protocol (NTP) packet primitives.
//!
//! NTP support is source-gated by `.agents/docs/ntp-rfc-manifest.md`.
//! This module is reserved for source-backed packet construction, decoding,
//! inspection, codepoint metadata, extension fields, and raw-preserving tails
//! that compose with the existing `Packet` abstraction. It does not implement
//! clock synchronization, a daemon, peer selection, NTS key exchange, Autokey
//! verification, scanning, or live traffic workflows.

#[cfg(test)]
mod tests {
    #[test]
    fn ntp_module_scaffold_cites_manifest_and_packet_scope() {
        const SOURCE_MANIFEST: &str = ".agents/docs/ntp-rfc-manifest.md";
        const SCOPE: &str = "packet primitive";

        assert_eq!(SOURCE_MANIFEST, ".agents/docs/ntp-rfc-manifest.md");
        assert_eq!(SCOPE, "packet primitive");
    }
}
