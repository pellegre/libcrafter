//! Raw-preserving legacy NTP MAC tail model.
//!
//! This module only models the packet tail shape. It preserves the digest
//! bytes exactly as packet material and does not compute, verify, upgrade, or
//! reject authentication material based on cryptographic semantics.

use core::fmt;

use super::constants::NTP_LEGACY_MAC_KEY_ID_LEN;
use crate::error::{CrafterError, Result};

const NTP_MAC_CONTEXT: &str = "ntp.mac";
const NTP_MAC_CRYPTO_NAK_LEN: usize = NTP_LEGACY_MAC_KEY_ID_LEN;
const NTP_MAC_20_OCTET_LEN: usize = 20;
const NTP_MAC_24_OCTET_LEN: usize = 24;

pub(super) const fn ntp_legacy_mac_tail_len_is_plausible(len: usize) -> bool {
    matches!(
        len,
        NTP_MAC_CRYPTO_NAK_LEN | NTP_MAC_20_OCTET_LEN | NTP_MAC_24_OCTET_LEN
    )
}

/// Structural length class for a legacy NTP MAC tail.
///
/// These labels are packet-shape descriptions only. They do not imply that
/// authentication material was computed, verified, accepted, or rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NtpMacLengthClass {
    /// Four-octet tail shape used for a crypto-NAK.
    CryptoNakLength,
    /// Twenty-octet legacy MAC tail shape.
    Legacy20Octet,
    /// Twenty-four-octet legacy MAC tail shape.
    Legacy24Octet,
    /// Any other preserved legacy MAC tail length.
    Other,
}

impl NtpMacLengthClass {
    /// Stable inspection label for this structural length class.
    pub const fn label(self) -> &'static str {
        match self {
            Self::CryptoNakLength => "crypto-nak-length",
            Self::Legacy20Octet => "legacy-mac-20-octet",
            Self::Legacy24Octet => "legacy-mac-24-octet",
            Self::Other => "legacy-mac-other-length",
        }
    }
}

impl fmt::Display for NtpMacLengthClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Raw-preserving legacy NTP MAC tail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtpMac {
    key_id: u32,
    digest: Vec<u8>,
}

impl NtpMac {
    /// Build a legacy MAC tail from a key identifier and raw digest bytes.
    pub fn new(key_id: u32, digest: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id,
            digest: digest.into(),
        }
    }

    /// Build a legacy MAC tail from a key identifier and raw digest bytes.
    pub fn from_key_id_and_digest(key_id: u32, digest: impl AsRef<[u8]>) -> Self {
        Self::new(key_id, digest.as_ref().to_vec())
    }

    /// Decode a legacy MAC tail from raw packet bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < NTP_LEGACY_MAC_KEY_ID_LEN {
            return Err(CrafterError::buffer_too_short(
                NTP_MAC_CONTEXT,
                NTP_LEGACY_MAC_KEY_ID_LEN,
                bytes.len(),
            ));
        }

        let key_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok(Self::new(
            key_id,
            bytes[NTP_LEGACY_MAC_KEY_ID_LEN..].to_vec(),
        ))
    }

    /// Key identifier from the packet tail.
    pub const fn key_id(&self) -> u32 {
        self.key_id
    }

    /// Borrow the raw digest bytes after the key identifier.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Raw digest length in octets.
    pub fn digest_len(&self) -> usize {
        self.digest.len()
    }

    /// Encoded tail length in octets, including the key identifier.
    pub fn encoded_len(&self) -> usize {
        NTP_LEGACY_MAC_KEY_ID_LEN + self.digest.len()
    }

    /// Structural length class for summaries and inspection.
    pub fn length_class(&self) -> NtpMacLengthClass {
        match self.encoded_len() {
            NTP_MAC_CRYPTO_NAK_LEN => NtpMacLengthClass::CryptoNakLength,
            NTP_MAC_20_OCTET_LEN => NtpMacLengthClass::Legacy20Octet,
            NTP_MAC_24_OCTET_LEN => NtpMacLengthClass::Legacy24Octet,
            _ => NtpMacLengthClass::Other,
        }
    }

    /// Stable structural label for this tail.
    pub fn label(&self) -> &'static str {
        self.length_class().label()
    }

    /// Return true when the tail has the four-octet crypto-NAK shape.
    pub fn is_crypto_nak_length(&self) -> bool {
        self.length_class() == NtpMacLengthClass::CryptoNakLength
    }

    /// Encode the key identifier followed by the raw digest bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.key_id.to_be_bytes());
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    /// Inspection summary that omits key identifier values and digest bytes.
    pub fn summary(&self) -> String {
        format!(
            "ntp legacy-mac label={} key_id_len={} digest_len={} total_len={}",
            self.label(),
            NTP_LEGACY_MAC_KEY_ID_LEN,
            self.digest_len(),
            self.encoded_len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_legacy_mac_preserves_raw_digest_material() {
        let digest = [0xde, 0xad, 0xbe, 0xef, 0xaa, 0x55];
        let mac = NtpMac::from_key_id_and_digest(0x0102_0304, digest);

        assert_eq!(mac.key_id(), 0x0102_0304);
        assert_eq!(mac.digest(), &digest);
        assert_eq!(mac.digest_len(), digest.len());

        let bytes = mac.to_bytes();
        assert_eq!(
            &bytes[..NTP_LEGACY_MAC_KEY_ID_LEN],
            &[0x01, 0x02, 0x03, 0x04]
        );
        assert_eq!(&bytes[NTP_LEGACY_MAC_KEY_ID_LEN..], &digest);
        assert_eq!(NtpMac::from_bytes(&bytes).expect("decode NTP MAC"), mac);
    }

    #[test]
    fn ntp_legacy_mac_classifies_lengths_without_validation() {
        assert_eq!(
            NtpMac::from_key_id_and_digest(0, []).length_class(),
            NtpMacLengthClass::CryptoNakLength
        );
        assert_eq!(
            NtpMac::from_key_id_and_digest(0, [0u8; 16]).length_class(),
            NtpMacLengthClass::Legacy20Octet
        );
        assert_eq!(
            NtpMac::from_key_id_and_digest(0, [0u8; 20]).length_class(),
            NtpMacLengthClass::Legacy24Octet
        );
        assert_eq!(
            NtpMac::from_key_id_and_digest(0, [0u8; 7]).length_class(),
            NtpMacLengthClass::Other
        );
    }

    #[test]
    fn ntp_tail_parser_mac_length_helper_covers_source_backed_shapes() {
        assert!(ntp_legacy_mac_tail_len_is_plausible(4));
        assert!(ntp_legacy_mac_tail_len_is_plausible(20));
        assert!(ntp_legacy_mac_tail_len_is_plausible(24));

        assert!(!ntp_legacy_mac_tail_len_is_plausible(0));
        assert!(!ntp_legacy_mac_tail_len_is_plausible(8));
        assert!(!ntp_legacy_mac_tail_len_is_plausible(28));
    }

    #[test]
    fn ntp_legacy_mac_summary_omits_key_id_and_digest_bytes() {
        let mac = NtpMac::from_key_id_and_digest(0x0102_0304, [0xab; 16]);
        let summary = mac.summary();

        assert_eq!(
            summary,
            "ntp legacy-mac label=legacy-mac-20-octet key_id_len=4 digest_len=16 total_len=20"
        );
        assert!(!summary.contains("01020304"));
        assert!(!summary.contains("abababab"));
    }

    #[test]
    fn ntp_legacy_mac_decode_requires_key_id_bytes_only() {
        let err = NtpMac::from_bytes([0x01, 0x02]).expect_err("short NTP MAC tail");

        assert_eq!(
            err,
            CrafterError::buffer_too_short(NTP_MAC_CONTEXT, NTP_LEGACY_MAC_KEY_ID_LEN, 2)
        );
    }
}
