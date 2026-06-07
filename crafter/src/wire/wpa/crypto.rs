//! WPA key derivation and verification helpers.
//!
//! This module isolates secret-bearing WPA material from transform and state
//! code. Later steps will add EAPOL-Key MIC verification, AES key unwrap, and
//! CCMP authentication here.

use core::fmt;

use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha1::Sha1;

use super::config::{WPA_PASSPHRASE_MAX_LEN, WPA_PASSPHRASE_MIN_LEN, WPA_SSID_MAX_LEN};
use crate::{CrafterError, Result};

/// WPA/WPA2-Personal PMK length in octets.
pub const WPA_PMK_LEN: usize = 32;

/// WPA/WPA2-Personal PBKDF2 iteration count.
pub const WPA_PBKDF2_ITERATIONS: u32 = 4096;

/// IEEE 802 MAC address length in octets.
pub const WPA_MAC_ADDR_LEN: usize = 6;

/// WPA/WPA2 nonce length in octets.
pub const WPA_NONCE_LEN: usize = 32;

/// WPA2-PSK CCMP-128 PTK length in octets.
pub const WPA_PTK_CCMP128_LEN: usize = 48;

/// WPA2-PSK CCMP-128 key confirmation key length in octets.
pub const WPA_PTK_KCK_LEN: usize = 16;

/// WPA2-PSK CCMP-128 key encryption key length in octets.
pub const WPA_PTK_KEK_LEN: usize = 16;

/// WPA2-PSK CCMP-128 temporal key length in octets.
pub const WPA_PTK_TEMPORAL_KEY_LEN: usize = 16;

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

/// WPA2-PSK CCMP-128 pairwise transient key material.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PairwiseTransientKey([u8; WPA_PTK_CCMP128_LEN]);

impl PairwiseTransientKey {
    /// Wrap raw 48-octet WPA2-PSK CCMP-128 PTK material.
    pub const fn new(bytes: [u8; WPA_PTK_CCMP128_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the complete PTK octets.
    pub const fn as_bytes(&self) -> &[u8; WPA_PTK_CCMP128_LEN] {
        &self.0
    }

    /// Copy the complete PTK octets.
    pub const fn to_bytes(&self) -> [u8; WPA_PTK_CCMP128_LEN] {
        self.0
    }

    /// Borrow the key confirmation key slice.
    pub fn kck(&self) -> &[u8; WPA_PTK_KCK_LEN] {
        self.0[..WPA_PTK_KCK_LEN]
            .try_into()
            .expect("WPA KCK slice length is fixed")
    }

    /// Borrow the key encryption key slice.
    pub fn kek(&self) -> &[u8; WPA_PTK_KEK_LEN] {
        self.0[WPA_PTK_KCK_LEN..WPA_PTK_KCK_LEN + WPA_PTK_KEK_LEN]
            .try_into()
            .expect("WPA KEK slice length is fixed")
    }

    /// Borrow the CCMP temporal key slice.
    pub fn temporal_key(&self) -> &[u8; WPA_PTK_TEMPORAL_KEY_LEN] {
        self.0[WPA_PTK_KCK_LEN + WPA_PTK_KEK_LEN..]
            .try_into()
            .expect("WPA temporal key slice length is fixed")
    }
}

impl From<[u8; WPA_PTK_CCMP128_LEN]> for PairwiseTransientKey {
    fn from(bytes: [u8; WPA_PTK_CCMP128_LEN]) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for PairwiseTransientKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PairwiseTransientKey(<redacted>)")
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

/// Derive a WPA2-PSK CCMP-128 PTK from a PMK, two MAC addresses, and two nonces.
///
/// IEEE 802.11's pairwise key expansion canonicalizes the two MAC addresses
/// and the two nonces independently by lexicographic byte order:
/// `min(addr) || max(addr) || min(nonce) || max(nonce)`. Callers may pass
/// authenticator/supplicant values in either order and get the same PTK.
pub fn derive_ptk(
    pmk: &Pmk,
    address_a: &[u8; WPA_MAC_ADDR_LEN],
    address_b: &[u8; WPA_MAC_ADDR_LEN],
    nonce_a: &[u8; WPA_NONCE_LEN],
    nonce_b: &[u8; WPA_NONCE_LEN],
) -> PairwiseTransientKey {
    let mut data = [0u8; 2 * WPA_MAC_ADDR_LEN + 2 * WPA_NONCE_LEN];

    let (low_address, high_address) = canonical_pair(address_a, address_b);
    data[..WPA_MAC_ADDR_LEN].copy_from_slice(low_address);
    data[WPA_MAC_ADDR_LEN..2 * WPA_MAC_ADDR_LEN].copy_from_slice(high_address);

    let (low_nonce, high_nonce) = canonical_pair(nonce_a, nonce_b);
    let nonce_offset = 2 * WPA_MAC_ADDR_LEN;
    data[nonce_offset..nonce_offset + WPA_NONCE_LEN].copy_from_slice(low_nonce);
    data[nonce_offset + WPA_NONCE_LEN..].copy_from_slice(high_nonce);

    let mut ptk = [0u8; WPA_PTK_CCMP128_LEN];
    wpa_prf_sha1(pmk.as_bytes(), b"Pairwise key expansion", &data, &mut ptk);
    PairwiseTransientKey::new(ptk)
}

fn canonical_pair<'a, const N: usize>(
    first: &'a [u8; N],
    second: &'a [u8; N],
) -> (&'a [u8; N], &'a [u8; N]) {
    if first.as_slice() <= second.as_slice() {
        (first, second)
    } else {
        (second, first)
    }
}

fn wpa_prf_sha1(key: &[u8], label: &[u8], data: &[u8], output: &mut [u8]) {
    let mut written = 0usize;
    let mut counter = 0u8;

    while written < output.len() {
        let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts WPA key material");
        mac.update(label);
        mac.update(&[0]);
        mac.update(data);
        mac.update(&[counter]);

        let block = mac.finalize().into_bytes();
        let remaining = output.len() - written;
        let take = remaining.min(block.len());
        output[written..written + take].copy_from_slice(&block[..take]);
        written += take;
        counter = counter
            .checked_add(1)
            .expect("WPA PRF output length fits one-octet counter");
    }
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

    #[test]
    fn ptk_derives_wpa2_psk_ccmp_vector() {
        let pmk = derive_pmk("password", b"IEEE").unwrap();
        let ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let station_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let ap_nonce = increasing_nonce(0x00);
        let station_nonce = increasing_nonce(0x20);

        let ptk = derive_ptk(&pmk, &ap_mac, &station_mac, &ap_nonce, &station_nonce);

        assert_eq!(
            ptk.as_bytes(),
            &[
                0x85, 0xc9, 0x8e, 0xca, 0x56, 0x14, 0x56, 0x29, 0x35, 0x9a, 0xc8, 0x83, 0x0b, 0xb6,
                0x6a, 0x59, 0xc5, 0x56, 0x2d, 0x47, 0x3f, 0xdd, 0xcb, 0x4e, 0xee, 0x9c, 0xe4, 0xde,
                0x54, 0xe1, 0xcb, 0x1a, 0x12, 0xcd, 0xd4, 0x44, 0x83, 0x25, 0xc8, 0x40, 0x79, 0xab,
                0xcd, 0x76, 0xb1, 0xb8, 0x9f, 0x8f,
            ]
        );
        assert_eq!(
            ptk.kck(),
            &[
                0x85, 0xc9, 0x8e, 0xca, 0x56, 0x14, 0x56, 0x29, 0x35, 0x9a, 0xc8, 0x83, 0x0b, 0xb6,
                0x6a, 0x59,
            ]
        );
        assert_eq!(
            ptk.kek(),
            &[
                0xc5, 0x56, 0x2d, 0x47, 0x3f, 0xdd, 0xcb, 0x4e, 0xee, 0x9c, 0xe4, 0xde, 0x54, 0xe1,
                0xcb, 0x1a,
            ]
        );
        assert_eq!(
            ptk.temporal_key(),
            &[
                0x12, 0xcd, 0xd4, 0x44, 0x83, 0x25, 0xc8, 0x40, 0x79, 0xab, 0xcd, 0x76, 0xb1, 0xb8,
                0x9f, 0x8f,
            ]
        );
    }

    #[test]
    fn ptk_derivation_canonicalizes_mac_and_nonce_order() {
        let pmk = Pmk::new([0x42; WPA_PMK_LEN]);
        let low_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let high_mac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let low_nonce = [0x10; WPA_NONCE_LEN];
        let high_nonce = [0x90; WPA_NONCE_LEN];

        let high_first = derive_ptk(&pmk, &high_mac, &low_mac, &high_nonce, &low_nonce);
        let low_first = derive_ptk(&pmk, &low_mac, &high_mac, &low_nonce, &high_nonce);

        assert_eq!(high_first, low_first);
    }

    #[test]
    fn ptk_debug_redacts_secret_material() {
        let ptk = PairwiseTransientKey::new([0xab; WPA_PTK_CCMP128_LEN]);
        let debug = format!("{ptk:?}");

        assert_eq!(debug, "PairwiseTransientKey(<redacted>)");
        assert!(!debug.contains("ab"));
        assert!(!debug.contains("171"));
    }

    fn increasing_nonce(first: u8) -> [u8; WPA_NONCE_LEN] {
        let mut nonce = [0u8; WPA_NONCE_LEN];
        for (offset, byte) in nonce.iter_mut().enumerate() {
            *byte = first + offset as u8;
        }
        nonce
    }
}
