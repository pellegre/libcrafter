//! WPA key derivation and verification helpers.
//!
//! This module isolates secret-bearing WPA material from transform and state
//! code. Later steps will add PTK derivation, EAPOL-Key MIC verification, AES
//! key unwrap, and CCMP authentication here.

use core::fmt;

use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha1::Sha1;

use super::config::{WPA_PASSPHRASE_MAX_LEN, WPA_PASSPHRASE_MIN_LEN, WPA_SSID_MAX_LEN};
use crate::{CrafterError, Result};

/// WPA/WPA2-Personal PMK length in octets.
pub const WPA_PMK_LEN: usize = 32;

/// WPA/WPA2-Personal PBKDF2 iteration count.
pub const WPA_PBKDF2_ITERATIONS: u32 = 4096;

type HmacSha1 = Hmac<Sha1>;

/// WPA/WPA2-Personal pairwise master key material.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Pmk([u8; WPA_PMK_LEN]);

impl Pmk {
    /// Wrap raw 32-octet PMK material.
    pub const fn new(bytes: [u8; WPA_PMK_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the PMK octets.
    pub const fn as_bytes(&self) -> &[u8; WPA_PMK_LEN] {
        &self.0
    }

    /// Copy the PMK octets.
    pub const fn to_bytes(&self) -> [u8; WPA_PMK_LEN] {
        self.0
    }
}

impl From<[u8; WPA_PMK_LEN]> for Pmk {
    fn from(bytes: [u8; WPA_PMK_LEN]) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for Pmk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Pmk(<redacted>)")
    }
}

/// Derive a WPA/WPA2-Personal PMK from a passphrase and SSID bytes.
pub fn derive_pmk(passphrase: &str, ssid: &[u8]) -> Result<Pmk> {
    validate_pmk_inputs(passphrase, ssid)?;

    let mut pmk = [0u8; WPA_PMK_LEN];
    pbkdf2::<HmacSha1>(passphrase.as_bytes(), ssid, WPA_PBKDF2_ITERATIONS, &mut pmk).map_err(
        |_| CrafterError::invalid_field_value("wpa.passphrase", "could not derive WPA PMK"),
    )?;

    Ok(Pmk::new(pmk))
}

fn validate_pmk_inputs(passphrase: &str, ssid: &[u8]) -> Result<()> {
    let passphrase_len = passphrase.len();
    if !(WPA_PASSPHRASE_MIN_LEN..=WPA_PASSPHRASE_MAX_LEN).contains(&passphrase_len) {
        return Err(CrafterError::invalid_field_value(
            "wpa.passphrase",
            "must be 8 to 63 octets",
        ));
    }

    if ssid.len() > WPA_SSID_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "wpa.ssid",
            "must be at most 32 bytes",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmk_derives_wpa2_psk_vector() {
        let pmk = derive_pmk("password", b"IEEE").unwrap();

        assert_eq!(
            pmk.as_bytes(),
            &[
                0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef, 0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a,
                0x5f, 0x90, 0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2, 0x3a, 0xed, 0x76, 0x2e,
                0x97, 0x10, 0xa1, 0x2e,
            ]
        );
    }

    #[test]
    fn pmk_debug_redacts_secret_material() {
        let pmk = Pmk::new([0x11; WPA_PMK_LEN]);
        let debug = format!("{pmk:?}");

        assert_eq!(debug, "Pmk(<redacted>)");
        assert!(!debug.contains("17"));
    }

    #[test]
    fn pmk_derivation_validates_inputs() {
        let short = derive_pmk("short", b"IEEE").unwrap_err();
        assert_eq!(
            short,
            CrafterError::InvalidFieldValue {
                field: "wpa.passphrase",
                reason: "must be 8 to 63 octets"
            }
        );

        let long_ssid = [0u8; WPA_SSID_MAX_LEN + 1];
        let bad_ssid = derive_pmk("password", &long_ssid).unwrap_err();
        assert_eq!(
            bad_ssid,
            CrafterError::InvalidFieldValue {
                field: "wpa.ssid",
                reason: "must be at most 32 bytes"
            }
        );
    }
}
