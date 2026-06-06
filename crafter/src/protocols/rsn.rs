//! RSN information element scaffolding.

use std::fmt;

/// Robust Security Network information element version 1.
pub const RSN_VERSION_1: u16 = 1;

/// Octets in an RSN cipher or AKM suite selector.
pub const RSN_SUITE_SELECTOR_LEN: usize = 4;

/// IEEE 802.11 RSN suite selector OUI.
pub const RSN_SUITE_SELECTOR_OUI: [u8; 3] = [0x00, 0x0f, 0xac];

/// RSN cipher suite selector: use the group cipher suite.
pub const RSN_CIPHER_SUITE_USE_GROUP: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 0);
/// RSN cipher suite selector: TKIP.
pub const RSN_CIPHER_SUITE_TKIP: RsnCipherSuite = RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 2);
/// RSN cipher suite selector: CCMP-128.
pub const RSN_CIPHER_SUITE_CCMP_128: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 4);
/// RSN cipher suite selector: AES-128-CMAC.
pub const RSN_CIPHER_SUITE_AES_128_CMAC: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 6);
/// RSN cipher suite selector: group addressed traffic not allowed.
pub const RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 7);
/// RSN cipher suite selector: GCMP-128.
pub const RSN_CIPHER_SUITE_GCMP_128: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 8);
/// RSN cipher suite selector: GCMP-256.
pub const RSN_CIPHER_SUITE_GCMP_256: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 9);
/// RSN cipher suite selector: CCMP-256.
pub const RSN_CIPHER_SUITE_CCMP_256: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 10);
/// RSN cipher suite selector: BIP-GMAC-128.
pub const RSN_CIPHER_SUITE_BIP_GMAC_128: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 11);
/// RSN cipher suite selector: BIP-GMAC-256.
pub const RSN_CIPHER_SUITE_BIP_GMAC_256: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 12);
/// RSN cipher suite selector: BIP-CMAC-256.
pub const RSN_CIPHER_SUITE_BIP_CMAC_256: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 13);
/// RSN cipher suite selector: CCM*.
pub const RSN_CIPHER_SUITE_CCM_STAR: RsnCipherSuite =
    RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 18);

/// RSN AKM suite selector: IEEE 802.1X.
pub const RSN_AKM_SUITE_8021X: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 1);
/// RSN AKM suite selector: PSK.
pub const RSN_AKM_SUITE_PSK: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 2);
/// RSN AKM suite selector: Fast BSS Transition over IEEE 802.1X.
pub const RSN_AKM_SUITE_FT_8021X: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 3);
/// RSN AKM suite selector: Fast BSS Transition using PSK.
pub const RSN_AKM_SUITE_FT_PSK: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 4);
/// RSN AKM suite selector: IEEE 802.1X with SHA-256.
pub const RSN_AKM_SUITE_8021X_SHA256: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 5);
/// RSN AKM suite selector: PSK with SHA-256.
pub const RSN_AKM_SUITE_PSK_SHA256: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 6);
/// RSN AKM suite selector: TDLS.
pub const RSN_AKM_SUITE_TDLS: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 7);
/// RSN AKM suite selector: SAE.
pub const RSN_AKM_SUITE_SAE: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 8);
/// RSN AKM suite selector: Fast BSS Transition over SAE.
pub const RSN_AKM_SUITE_FT_SAE: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 9);
/// RSN AKM suite selector: APPeerKey.
pub const RSN_AKM_SUITE_AP_PEER_KEY: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 10);
/// RSN AKM suite selector: IEEE 802.1X Suite B.
pub const RSN_AKM_SUITE_8021X_SUITE_B: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 11);
/// RSN AKM suite selector: IEEE 802.1X Suite B 192-bit.
pub const RSN_AKM_SUITE_8021X_SUITE_B_192: RsnAkmSuite =
    RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 12);
/// RSN AKM suite selector: Fast BSS Transition over IEEE 802.1X with SHA-384.
pub const RSN_AKM_SUITE_FT_8021X_SHA384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 13);
/// RSN AKM suite selector: Fast BSS Transition over IEEE 802.1X with SHA-384 and 256-bit pairwise ciphers.
pub const RSN_AKM_SUITE_FT_8021X_SHA384_CMP_256: RsnAkmSuite =
    RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 13);
/// RSN AKM suite selector: FILS with SHA-256.
pub const RSN_AKM_SUITE_FILS_SHA256: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 14);
/// RSN AKM suite selector: FILS with SHA-384.
pub const RSN_AKM_SUITE_FILS_SHA384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 15);
/// RSN AKM suite selector: Fast BSS Transition over FILS with SHA-256.
pub const RSN_AKM_SUITE_FT_FILS_SHA256: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 16);
/// RSN AKM suite selector: Fast BSS Transition over FILS with SHA-384.
pub const RSN_AKM_SUITE_FT_FILS_SHA384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 17);
/// RSN AKM suite selector: Opportunistic Wireless Encryption.
pub const RSN_AKM_SUITE_OWE: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 18);
/// RSN AKM suite selector: Fast BSS Transition using PSK with SHA-384.
pub const RSN_AKM_SUITE_FT_PSK_SHA384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 19);
/// RSN AKM suite selector: PSK with SHA-384.
pub const RSN_AKM_SUITE_PSK_SHA384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 20);
/// RSN AKM suite selector: PASN.
pub const RSN_AKM_SUITE_PASN: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 21);
/// RSN AKM suite selector: Fast BSS Transition over IEEE 802.1X with SHA-384.
pub const RSN_AKM_SUITE_FT_8021X_SHA384_BASIC: RsnAkmSuite =
    RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 22);
/// RSN AKM suite selector: IEEE 802.1X with SHA-384.
pub const RSN_AKM_SUITE_8021X_SHA384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 23);
/// RSN AKM suite selector: SAE with a 384-bit PMK.
pub const RSN_AKM_SUITE_SAE_PMK384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 24);
/// RSN AKM suite selector: Fast BSS Transition over SAE with a 384-bit PMK.
pub const RSN_AKM_SUITE_FT_SAE_PMK384: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 25);
/// RSN AKM suite selector: PASN with defined key wrap.
pub const RSN_AKM_SUITE_PASN_DEFINED_KEY_WRAP: RsnAkmSuite =
    RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 26);
/// RSN AKM suite selector: EDPKE.
pub const RSN_AKM_SUITE_EDPKE: RsnAkmSuite = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 29);

/// Raw RSN suite selector shape: a three-octet OUI plus one-octet suite type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RsnSuiteSelector {
    oui: [u8; 3],
    suite_type: u8,
}

impl RsnSuiteSelector {
    /// Create an RSN suite selector while preserving OUI and suite type verbatim.
    pub const fn new(oui: [u8; 3], suite_type: u8) -> Self {
        Self { oui, suite_type }
    }

    /// Create an RSN suite selector from its four wire octets.
    pub const fn from_bytes(bytes: [u8; RSN_SUITE_SELECTOR_LEN]) -> Self {
        Self {
            oui: [bytes[0], bytes[1], bytes[2]],
            suite_type: bytes[3],
        }
    }

    /// The selector OUI.
    pub const fn oui(&self) -> [u8; 3] {
        self.oui
    }

    /// The selector suite type octet.
    pub const fn suite_type(&self) -> u8 {
        self.suite_type
    }

    /// Return true when this selector uses the IEEE 802.11 RSN suite OUI.
    pub const fn is_rsn_oui(&self) -> bool {
        self.oui[0] == RSN_SUITE_SELECTOR_OUI[0]
            && self.oui[1] == RSN_SUITE_SELECTOR_OUI[1]
            && self.oui[2] == RSN_SUITE_SELECTOR_OUI[2]
    }

    /// Encode this selector as its four wire octets.
    pub const fn to_bytes(&self) -> [u8; RSN_SUITE_SELECTOR_LEN] {
        [self.oui[0], self.oui[1], self.oui[2], self.suite_type]
    }
}

impl From<[u8; RSN_SUITE_SELECTOR_LEN]> for RsnSuiteSelector {
    fn from(bytes: [u8; RSN_SUITE_SELECTOR_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<RsnSuiteSelector> for [u8; RSN_SUITE_SELECTOR_LEN] {
    fn from(selector: RsnSuiteSelector) -> Self {
        selector.to_bytes()
    }
}

impl fmt::Display for RsnSuiteSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}-{:02x}-{:02x}:{}",
            self.oui[0], self.oui[1], self.oui[2], self.suite_type
        )
    }
}

/// RSN cipher suite selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RsnCipherSuite {
    selector: RsnSuiteSelector,
}

impl RsnCipherSuite {
    /// Create an RSN cipher suite selector.
    pub const fn new(oui: [u8; 3], suite_type: u8) -> Self {
        Self {
            selector: RsnSuiteSelector::new(oui, suite_type),
        }
    }

    /// Create an RSN cipher suite selector from a raw selector.
    pub const fn from_selector(selector: RsnSuiteSelector) -> Self {
        Self { selector }
    }

    /// Create an RSN cipher suite selector from its four wire octets.
    pub const fn from_bytes(bytes: [u8; RSN_SUITE_SELECTOR_LEN]) -> Self {
        Self::from_selector(RsnSuiteSelector::from_bytes(bytes))
    }

    /// The raw OUI plus suite type selector.
    pub const fn selector(&self) -> RsnSuiteSelector {
        self.selector
    }

    /// The selector OUI.
    pub const fn oui(&self) -> [u8; 3] {
        self.selector.oui()
    }

    /// The selector suite type octet.
    pub const fn suite_type(&self) -> u8 {
        self.selector.suite_type()
    }

    /// Return a stable label for a source-backed IEEE 802.11 RSN cipher suite.
    pub const fn label(&self) -> Option<&'static str> {
        rsn_cipher_suite_label(*self)
    }

    /// Encode this selector as its four wire octets.
    pub const fn to_bytes(&self) -> [u8; RSN_SUITE_SELECTOR_LEN] {
        self.selector.to_bytes()
    }
}

impl From<RsnSuiteSelector> for RsnCipherSuite {
    fn from(selector: RsnSuiteSelector) -> Self {
        Self::from_selector(selector)
    }
}

impl From<[u8; RSN_SUITE_SELECTOR_LEN]> for RsnCipherSuite {
    fn from(bytes: [u8; RSN_SUITE_SELECTOR_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<RsnCipherSuite> for RsnSuiteSelector {
    fn from(suite: RsnCipherSuite) -> Self {
        suite.selector()
    }
}

impl From<RsnCipherSuite> for [u8; RSN_SUITE_SELECTOR_LEN] {
    fn from(suite: RsnCipherSuite) -> Self {
        suite.to_bytes()
    }
}

impl fmt::Display for RsnCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.label() {
            Some(label) => write!(f, "{label}({})", self.selector),
            None => write!(f, "unknown-cipher-suite({})", self.selector),
        }
    }
}

/// RSN AKM suite selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RsnAkmSuite {
    selector: RsnSuiteSelector,
}

impl RsnAkmSuite {
    /// Create an RSN AKM suite selector.
    pub const fn new(oui: [u8; 3], suite_type: u8) -> Self {
        Self {
            selector: RsnSuiteSelector::new(oui, suite_type),
        }
    }

    /// Create an RSN AKM suite selector from a raw selector.
    pub const fn from_selector(selector: RsnSuiteSelector) -> Self {
        Self { selector }
    }

    /// Create an RSN AKM suite selector from its four wire octets.
    pub const fn from_bytes(bytes: [u8; RSN_SUITE_SELECTOR_LEN]) -> Self {
        Self::from_selector(RsnSuiteSelector::from_bytes(bytes))
    }

    /// The raw OUI plus suite type selector.
    pub const fn selector(&self) -> RsnSuiteSelector {
        self.selector
    }

    /// The selector OUI.
    pub const fn oui(&self) -> [u8; 3] {
        self.selector.oui()
    }

    /// The selector suite type octet.
    pub const fn suite_type(&self) -> u8 {
        self.selector.suite_type()
    }

    /// Return a stable label for a source-backed IEEE 802.11 RSN AKM suite.
    pub const fn label(&self) -> Option<&'static str> {
        rsn_akm_suite_label(*self)
    }

    /// Encode this selector as its four wire octets.
    pub const fn to_bytes(&self) -> [u8; RSN_SUITE_SELECTOR_LEN] {
        self.selector.to_bytes()
    }
}

impl From<RsnSuiteSelector> for RsnAkmSuite {
    fn from(selector: RsnSuiteSelector) -> Self {
        Self::from_selector(selector)
    }
}

impl From<[u8; RSN_SUITE_SELECTOR_LEN]> for RsnAkmSuite {
    fn from(bytes: [u8; RSN_SUITE_SELECTOR_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<RsnAkmSuite> for RsnSuiteSelector {
    fn from(suite: RsnAkmSuite) -> Self {
        suite.selector()
    }
}

impl From<RsnAkmSuite> for [u8; RSN_SUITE_SELECTOR_LEN] {
    fn from(suite: RsnAkmSuite) -> Self {
        suite.to_bytes()
    }
}

impl fmt::Display for RsnAkmSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.label() {
            Some(label) => write!(f, "{label}({})", self.selector),
            None => write!(f, "unknown-akm-suite({})", self.selector),
        }
    }
}

/// Return a stable label for a source-backed IEEE 802.11 RSN cipher suite.
pub const fn rsn_cipher_suite_label(suite: RsnCipherSuite) -> Option<&'static str> {
    let selector = suite.selector();
    if !selector.is_rsn_oui() {
        return None;
    }

    match selector.suite_type() {
        0 => Some("use-group"),
        2 => Some("tkip"),
        4 => Some("ccmp-128"),
        6 => Some("aes-128-cmac"),
        7 => Some("no-group-addressed"),
        8 => Some("gcmp-128"),
        9 => Some("gcmp-256"),
        10 => Some("ccmp-256"),
        11 => Some("bip-gmac-128"),
        12 => Some("bip-gmac-256"),
        13 => Some("bip-cmac-256"),
        18 => Some("ccm-star"),
        _ => None,
    }
}

/// Return a stable label for a source-backed IEEE 802.11 RSN AKM suite.
pub const fn rsn_akm_suite_label(suite: RsnAkmSuite) -> Option<&'static str> {
    let selector = suite.selector();
    if !selector.is_rsn_oui() {
        return None;
    }

    match selector.suite_type() {
        1 => Some("802.1x"),
        2 => Some("psk"),
        3 => Some("ft-802.1x"),
        4 => Some("ft-psk"),
        5 => Some("802.1x-sha256"),
        6 => Some("psk-sha256"),
        7 => Some("tdls"),
        8 => Some("sae"),
        9 => Some("ft-sae"),
        10 => Some("ap-peer-key"),
        11 => Some("802.1x-suite-b"),
        12 => Some("802.1x-suite-b-192"),
        13 => Some("ft-802.1x-sha384-cmp-256"),
        14 => Some("fils-sha256"),
        15 => Some("fils-sha384"),
        16 => Some("ft-fils-sha256"),
        17 => Some("ft-fils-sha384"),
        18 => Some("owe"),
        19 => Some("ft-psk-sha384"),
        20 => Some("psk-sha384"),
        21 => Some("pasn"),
        22 => Some("ft-802.1x-sha384"),
        23 => Some("802.1x-sha384"),
        24 => Some("sae-pmk384"),
        25 => Some("ft-sae-pmk384"),
        26 => Some("pasn-defined-key-wrap"),
        29 => Some("edpke"),
        _ => None,
    }
}

/// Placeholder for Robust Security Network information elements.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RsnInformation {
    _private: (),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsn_suite_selectors_preserve_raw_oui_and_suite_type() {
        let selector = RsnSuiteSelector::from_bytes([0x02, 0x00, 0x5e, 0x99]);

        assert_eq!(selector.oui(), [0x02, 0x00, 0x5e]);
        assert_eq!(selector.suite_type(), 0x99);
        assert!(!selector.is_rsn_oui());
        assert_eq!(selector.to_bytes(), [0x02, 0x00, 0x5e, 0x99]);
        assert_eq!(selector.to_string(), "02-00-5e:153");
    }

    #[test]
    fn rsn_suite_selectors_cipher_known_labels_are_source_backed() {
        let ccmp = RsnCipherSuite::from_bytes([0x00, 0x0f, 0xac, 0x04]);
        let gcmp_256 = RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 9);

        assert_eq!(ccmp, RSN_CIPHER_SUITE_CCMP_128);
        assert_eq!(ccmp.oui(), RSN_SUITE_SELECTOR_OUI);
        assert_eq!(ccmp.suite_type(), 4);
        assert_eq!(ccmp.label(), Some("ccmp-128"));
        assert_eq!(ccmp.to_bytes(), [0x00, 0x0f, 0xac, 0x04]);
        assert_eq!(gcmp_256.label(), Some("gcmp-256"));
    }

    #[test]
    fn rsn_suite_selectors_akm_known_labels_are_source_backed() {
        let psk = RsnAkmSuite::from_bytes([0x00, 0x0f, 0xac, 0x02]);
        let sae = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 8);
        let owe = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 18);

        assert_eq!(psk, RSN_AKM_SUITE_PSK);
        assert_eq!(psk.oui(), RSN_SUITE_SELECTOR_OUI);
        assert_eq!(psk.suite_type(), 2);
        assert_eq!(psk.label(), Some("psk"));
        assert_eq!(psk.to_bytes(), [0x00, 0x0f, 0xac, 0x02]);
        assert_eq!(sae.label(), Some("sae"));
        assert_eq!(owe.label(), Some("owe"));
        assert_eq!(
            RSN_AKM_SUITE_FT_8021X_SHA384_CMP_256.label(),
            Some("ft-802.1x-sha384-cmp-256")
        );
        assert_eq!(RSN_AKM_SUITE_FT_PSK_SHA384.label(), Some("ft-psk-sha384"));
        assert_eq!(RSN_AKM_SUITE_PSK_SHA384.label(), Some("psk-sha384"));
        assert_eq!(
            RSN_AKM_SUITE_FT_8021X_SHA384_BASIC.label(),
            Some("ft-802.1x-sha384")
        );
        assert_eq!(RSN_AKM_SUITE_8021X_SHA384.label(), Some("802.1x-sha384"));
        assert_eq!(RSN_AKM_SUITE_SAE_PMK384.label(), Some("sae-pmk384"));
        assert_eq!(RSN_AKM_SUITE_FT_SAE_PMK384.label(), Some("ft-sae-pmk384"));
    }

    #[test]
    fn rsn_suite_selectors_unknown_oui_and_unknown_type_have_no_known_label() {
        let vendor_cipher = RsnCipherSuite::new([0x02, 0x00, 0x5e], 4);
        let unknown_cipher = RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 0xfe);
        let vendor_akm = RsnAkmSuite::new([0x02, 0x00, 0x5e], 2);
        let unknown_akm = RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 0xfe);

        assert_eq!(vendor_cipher.oui(), [0x02, 0x00, 0x5e]);
        assert_eq!(vendor_cipher.suite_type(), 4);
        assert_eq!(vendor_cipher.label(), None);
        assert_eq!(unknown_cipher.to_bytes(), [0x00, 0x0f, 0xac, 0xfe]);
        assert_eq!(unknown_cipher.label(), None);
        assert_eq!(vendor_akm.oui(), [0x02, 0x00, 0x5e]);
        assert_eq!(vendor_akm.suite_type(), 2);
        assert_eq!(vendor_akm.label(), None);
        assert_eq!(unknown_akm.to_bytes(), [0x00, 0x0f, 0xac, 0xfe]);
        assert_eq!(unknown_akm.label(), None);
    }

    #[test]
    fn rsn_suite_selectors_public_exports_resolve() {
        use crate::core::{RsnAkmSuite as CoreAkm, RSN_AKM_SUITE_PSK as CORE_PSK};
        use crate::prelude::{
            RsnCipherSuite as PreludeCipher, RSN_CIPHER_SUITE_CCMP_128 as PRELUDE_CCMP,
        };
        use crate::protocols::{
            rsn_akm_suite_label as protocols_akm_label, RsnSuiteSelector as ProtocolsSelector,
        };

        assert_eq!(CoreAkm::from(CORE_PSK).label(), Some("psk"));
        assert_eq!(PreludeCipher::from(PRELUDE_CCMP).label(), Some("ccmp-128"));
        assert_eq!(
            protocols_akm_label(RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 8)),
            Some("sae")
        );
        assert_eq!(
            ProtocolsSelector::from([0x00, 0x0f, 0xac, 0x04]).to_bytes(),
            [0x00, 0x0f, 0xac, 0x04]
        );
    }
}
