//! WPA decryptor configuration types.

use core::fmt;

use super::crypto::{derive_pmk, Pmk};
use super::metadata::WpaCipher;
use crate::{CrafterError, Result};

/// Maximum SSID length defined by IEEE 802.11.
pub const WPA_SSID_MAX_LEN: usize = 32;

/// Minimum WPA/WPA2-Personal passphrase length in octets.
pub const WPA_PASSPHRASE_MIN_LEN: usize = 8;

/// Maximum WPA/WPA2-Personal passphrase length in octets.
pub const WPA_PASSPHRASE_MAX_LEN: usize = 63;

/// Configuration for the passive WPA decrypt transform.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WpaDecryptConfig {
    pass_originals: bool,
    supported_ciphers: Vec<WpaCipher>,
}

impl WpaDecryptConfig {
    /// Create the default WPA decryptor configuration.
    pub fn new() -> Self {
        Self {
            pass_originals: false,
            supported_ciphers: vec![WpaCipher::Ccmp128],
        }
    }

    /// Configure whether original records should be passed through.
    ///
    /// When disabled, the transform still passes non-Wi-Fi and unprotected
    /// non-handshake records. Handshake records and undecryptable protected
    /// records are retained as state but do not produce output.
    pub const fn pass_originals(mut self, pass_originals: bool) -> Self {
        self.pass_originals = pass_originals;
        self
    }

    /// Whether original records are configured for pass-through.
    pub const fn emits_originals(&self) -> bool {
        self.pass_originals
    }

    /// Replace the supported cipher list.
    ///
    /// Duplicate cipher entries are collapsed while preserving the caller's
    /// first-seen order. An empty list is allowed and means no protected frames
    /// are eligible for decryption.
    pub fn only_ciphers(mut self, ciphers: impl IntoIterator<Item = WpaCipher>) -> Self {
        self.supported_ciphers.clear();
        for cipher in ciphers {
            push_unique_cipher(&mut self.supported_ciphers, cipher);
        }
        self
    }

    /// Add one supported cipher to the current selection.
    pub fn allow_cipher(mut self, cipher: WpaCipher) -> Self {
        push_unique_cipher(&mut self.supported_ciphers, cipher);
        self
    }

    /// Configured cipher suites in priority order.
    pub fn supported_ciphers(&self) -> &[WpaCipher] {
        &self.supported_ciphers
    }

    /// Whether a cipher suite is currently eligible for decryption.
    pub fn supports_cipher(&self, cipher: WpaCipher) -> bool {
        self.supported_ciphers.contains(&cipher)
    }
}

impl Default for WpaDecryptConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// One configured WPA/WPA2-Personal network.
///
/// SSIDs are bytes on the wire and are not guaranteed to be UTF-8. This
/// configuration stores caller-provided passphrase material with a cached PMK,
/// or caller-supplied pre-derived PMK material.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct WpaNetwork {
    ssid: Vec<u8>,
    credential: WpaCredential,
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum WpaCredential {
    Passphrase { passphrase: String, pmk: Pmk },
    Pmk(Pmk),
}

impl WpaNetwork {
    /// Configure a network from a UTF-8 SSID and passphrase.
    pub fn passphrase(ssid: impl AsRef<str>, passphrase: impl Into<String>) -> Result<Self> {
        Self::passphrase_bytes(ssid.as_ref().as_bytes(), passphrase)
    }

    /// Configure a network from raw SSID bytes and passphrase.
    pub fn passphrase_bytes(ssid: impl AsRef<[u8]>, passphrase: impl Into<String>) -> Result<Self> {
        let ssid = validate_ssid(ssid.as_ref())?;
        let passphrase = passphrase.into();
        validate_passphrase(&passphrase)?;
        let pmk = derive_pmk(&passphrase, &ssid)?;

        Ok(Self {
            ssid,
            credential: WpaCredential::Passphrase { passphrase, pmk },
        })
    }

    /// Configure a network from a UTF-8 SSID and a pre-derived PMK.
    pub fn pmk(ssid: impl AsRef<str>, pmk: impl Into<Pmk>) -> Result<Self> {
        Self::pmk_bytes(ssid.as_ref().as_bytes(), pmk)
    }

    /// Configure a network from raw SSID bytes and a pre-derived PMK.
    pub fn pmk_bytes(ssid: impl AsRef<[u8]>, pmk: impl Into<Pmk>) -> Result<Self> {
        Ok(Self {
            ssid: validate_ssid(ssid.as_ref())?,
            credential: WpaCredential::Pmk(pmk.into()),
        })
    }

    /// Configured SSID bytes.
    pub fn ssid(&self) -> &[u8] {
        &self.ssid
    }

    /// Configured SSID as UTF-8 when valid.
    pub fn ssid_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.ssid).ok()
    }

    /// Configured passphrase, when this network was configured with one.
    pub fn passphrase_value(&self) -> Option<&str> {
        match &self.credential {
            WpaCredential::Passphrase { passphrase, .. } => Some(passphrase),
            WpaCredential::Pmk(_) => None,
        }
    }

    /// Cached PMK material for this configured network.
    pub fn cached_pmk(&self) -> &Pmk {
        match &self.credential {
            WpaCredential::Passphrase { pmk, .. } | WpaCredential::Pmk(pmk) => pmk,
        }
    }

    /// Configured pre-derived PMK bytes, when supplied by the caller.
    pub fn pmk_value(&self) -> Option<[u8; 32]> {
        match &self.credential {
            WpaCredential::Passphrase { .. } => None,
            WpaCredential::Pmk(pmk) => Some(pmk.to_bytes()),
        }
    }

    /// Whether this network was configured from a passphrase.
    pub fn uses_passphrase(&self) -> bool {
        matches!(&self.credential, WpaCredential::Passphrase { .. })
    }

    /// Whether this network was configured from pre-derived PMK material.
    pub fn uses_pmk(&self) -> bool {
        matches!(&self.credential, WpaCredential::Pmk(_))
    }
}

impl fmt::Debug for WpaNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WpaNetwork")
            .field("ssid", &self.ssid)
            .field("ssid_utf8", &self.ssid_str())
            .field("credential", &self.credential)
            .finish()
    }
}

impl fmt::Debug for WpaCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passphrase { .. } => f.write_str("Passphrase(<redacted>)"),
            Self::Pmk(_) => f.write_str("Pmk(<redacted>)"),
        }
    }
}

fn push_unique_cipher(ciphers: &mut Vec<WpaCipher>, cipher: WpaCipher) {
    if !ciphers.contains(&cipher) {
        ciphers.push(cipher);
    }
}

fn validate_ssid(ssid: &[u8]) -> Result<Vec<u8>> {
    if ssid.len() > WPA_SSID_MAX_LEN {
        return Err(CrafterError::invalid_field_value(
            "wpa.ssid",
            "must be at most 32 bytes",
        ));
    }

    Ok(ssid.to_vec())
}

fn validate_passphrase(passphrase: &str) -> Result<()> {
    let len = passphrase.len();
    if !(WPA_PASSPHRASE_MIN_LEN..=WPA_PASSPHRASE_MAX_LEN).contains(&len) {
        return Err(CrafterError::invalid_field_value(
            "wpa.passphrase",
            "must be 8 to 63 octets",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults_to_decrypting_output_and_ccmp128() {
        let config = WpaDecryptConfig::new();

        assert!(!config.emits_originals());
        assert_eq!(config.supported_ciphers(), &[WpaCipher::Ccmp128]);
        assert!(config.supports_cipher(WpaCipher::Ccmp128));
        assert!(!config.supports_cipher(WpaCipher::Tkip));
    }

    #[test]
    fn config_selects_supported_ciphers_without_duplicates() {
        let config = WpaDecryptConfig::new()
            .pass_originals(false)
            .only_ciphers([WpaCipher::Tkip, WpaCipher::Ccmp128, WpaCipher::Tkip])
            .allow_cipher(WpaCipher::Gcmp128)
            .allow_cipher(WpaCipher::Ccmp128);

        assert!(!config.emits_originals());
        assert_eq!(
            config.supported_ciphers(),
            &[WpaCipher::Tkip, WpaCipher::Ccmp128, WpaCipher::Gcmp128]
        );
        assert!(config.supports_cipher(WpaCipher::Gcmp128));
    }

    #[test]
    fn passphrase_network_accepts_text_and_non_utf8_ssid_bytes() {
        let text = WpaNetwork::passphrase("lab", "12345678").unwrap();
        let bytes = WpaNetwork::passphrase_bytes(b"\xfflab".as_slice(), "abcdefgh").unwrap();
        let expected_pmk = derive_pmk("12345678", b"lab").unwrap();

        assert_eq!(text.ssid(), b"lab");
        assert_eq!(text.ssid_str(), Some("lab"));
        assert_eq!(text.passphrase_value(), Some("12345678"));
        assert_eq!(text.cached_pmk(), &expected_pmk);
        assert!(text.uses_passphrase());
        assert!(!text.uses_pmk());
        assert_eq!(bytes.ssid(), b"\xfflab");
        assert_eq!(bytes.ssid_str(), None);
    }

    #[test]
    fn pmk_network_accepts_text_and_non_utf8_ssid_bytes() {
        let pmk = [0x42; 32];
        let text = WpaNetwork::pmk("lab", pmk).unwrap();
        let bytes = WpaNetwork::pmk_bytes(b"\xfflab".as_slice(), pmk).unwrap();

        assert_eq!(text.ssid(), b"lab");
        assert_eq!(text.passphrase_value(), None);
        assert_eq!(text.pmk_value(), Some(pmk));
        assert_eq!(text.cached_pmk().as_bytes(), &pmk);
        assert!(!text.uses_passphrase());
        assert!(text.uses_pmk());
        assert_eq!(bytes.ssid(), b"\xfflab");
        assert_eq!(bytes.ssid_str(), None);
    }

    #[test]
    fn passphrase_length_is_validated() {
        for passphrase in [
            "1234567",
            "1234567890123456789012345678901234567890123456789012345678901234",
        ] {
            let err = WpaNetwork::passphrase("lab", passphrase).unwrap_err();
            assert_eq!(
                err,
                CrafterError::InvalidFieldValue {
                    field: "wpa.passphrase",
                    reason: "must be 8 to 63 octets"
                }
            );
        }
    }

    #[test]
    fn ssid_length_is_validated() {
        let ssid = [0u8; WPA_SSID_MAX_LEN + 1];
        let err = WpaNetwork::passphrase_bytes(ssid, "12345678").unwrap_err();

        assert_eq!(
            err,
            CrafterError::InvalidFieldValue {
                field: "wpa.ssid",
                reason: "must be at most 32 bytes"
            }
        );
    }

    #[test]
    fn debug_redacts_secret_material() {
        let passphrase = WpaNetwork::passphrase("lab", "do-not-print").unwrap();
        let pmk = WpaNetwork::pmk("lab", [0x11; 32]).unwrap();

        let passphrase_debug = format!("{passphrase:?}");
        let pmk_debug = format!("{pmk:?}");

        assert!(passphrase_debug.contains("<redacted>"));
        assert!(!passphrase_debug.contains("do-not-print"));
        assert!(pmk_debug.contains("<redacted>"));
        assert!(!pmk_debug.contains("17, 17, 17"));
    }
}
