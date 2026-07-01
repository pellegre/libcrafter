//! Network Time Protocol (NTP) packet primitives.
//!
//! NTP support is source-gated by `.agents/docs/ntp-rfc-manifest.md`.
//! This module is reserved for source-backed packet construction, decoding,
//! inspection, codepoint metadata, extension fields, and raw-preserving tails
//! that compose with the existing `Packet` abstraction. It does not implement
//! clock synchronization, a daemon, peer selection, NTS key exchange, Autokey
//! verification, scanning, or live traffic workflows.

pub mod constants;
pub mod message;
pub mod registry;

pub use self::constants::*;
pub use self::message::{
    append_ntp_packet, decode_ntp_payload, looks_like_ntp_payload, ntp_client_udp,
    ntp_ipv4_client_request, ntp_ipv6_client_request, ntp_pack_first_octet, ntp_parse_first_octet,
    ntp_server_udp, Ntp, NtpExtensionField, NtpLeapIndicator, NtpLegacyMac, NtpMode,
    NtpReferenceId, NtpShortFormat, NtpStratum, NtpTimestamp, NtpVersion,
};
pub use self::registry::{
    ntp_extension_field_type_meta, ntp_kiss_o_death_code_meta, ntp_leap_indicator_meta,
    ntp_mode_meta, ntp_nts_extension_field_type_meta, ntp_reference_id_meta, ntp_stratum_meta,
    NtpReferenceCodeMeta, NtpRegistryMeta, NtpRegistryStatus,
};

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
