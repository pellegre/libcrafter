//! RSN information element helpers.

use std::fmt;

use crate::error::{CrafterError, Result};

/// Robust Security Network information element version 1.
pub const RSN_VERSION_1: u16 = 1;

/// Octets in an RSN Capabilities field.
pub const RSN_CAPABILITIES_LEN: usize = 2;

/// Octets in an RSN cipher or AKM suite selector.
pub const RSN_SUITE_SELECTOR_LEN: usize = 4;

const RSN_PMKID_LEN: usize = 16;

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

const RSN_CAP_PRE_AUTHENTICATION: u16 = 0x0001;
const RSN_CAP_NO_PAIRWISE: u16 = 0x0002;
const RSN_CAP_PTKSA_REPLAY_COUNTER_MASK: u16 = 0x000c;
const RSN_CAP_PTKSA_REPLAY_COUNTER_SHIFT: u8 = 2;
const RSN_CAP_GTKSA_REPLAY_COUNTER_MASK: u16 = 0x0030;
const RSN_CAP_GTKSA_REPLAY_COUNTER_SHIFT: u8 = 4;
const RSN_CAP_MFP_REQUIRED: u16 = 0x0040;
const RSN_CAP_MFP_CAPABLE: u16 = 0x0080;
const RSN_CAP_JOINT_MULTI_BAND_RSNA: u16 = 0x0100;
const RSN_CAP_PEERKEY_ENABLED: u16 = 0x0200;
const RSN_CAP_SPP_A_MSDU_CAPABLE: u16 = 0x0400;
const RSN_CAP_SPP_A_MSDU_REQUIRED: u16 = 0x0800;
const RSN_CAP_PBAC: u16 = 0x1000;
const RSN_CAP_EXTENDED_KEY_ID: u16 = 0x2000;
const RSN_CAP_RESERVED_MASK: u16 = 0xc000;

/// RSN Capabilities field.
///
/// The field is encoded as a little-endian two-octet RSN information element
/// subfield. Accessors expose source-backed IEEE 802.11 capability bits while
/// the raw word remains available so reserved or future bits round-trip
/// unchanged.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct RsnCapabilities {
    bits: u16,
}

impl RsnCapabilities {
    /// Create an empty RSN Capabilities field.
    pub const fn new() -> Self {
        Self { bits: 0 }
    }

    /// Create an RSN Capabilities value from its raw host-endian bit word.
    pub const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Create an RSN Capabilities value from its raw host-endian bit word.
    pub const fn from_raw(bits: u16) -> Self {
        Self::from_bits(bits)
    }

    /// Decode an RSN Capabilities field from exactly two little-endian bytes.
    pub const fn from_le_bytes(bytes: [u8; RSN_CAPABILITIES_LEN]) -> Self {
        Self {
            bits: u16::from_le_bytes(bytes),
        }
    }

    /// Decode an RSN Capabilities field from a byte slice.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < RSN_CAPABILITIES_LEN {
            return Err(CrafterError::buffer_too_short(
                "rsn.capabilities",
                RSN_CAPABILITIES_LEN,
                bytes.len(),
            ));
        }

        Ok(Self::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Return the raw host-endian RSN Capabilities bit word.
    pub const fn bits(&self) -> u16 {
        self.bits
    }

    /// Return the raw host-endian RSN Capabilities bit word.
    pub const fn raw(&self) -> u16 {
        self.bits
    }

    /// Set the raw host-endian RSN Capabilities bit word.
    pub const fn raw_set(mut self, bits: u16) -> Self {
        self.bits = bits;
        self
    }

    /// Builder alias for [`Self::raw_set`].
    pub const fn with_raw(self, bits: u16) -> Self {
        self.raw_set(bits)
    }

    /// Compile the RSN Capabilities field to little-endian wire bytes.
    pub const fn to_le_bytes(self) -> [u8; RSN_CAPABILITIES_LEN] {
        self.bits.to_le_bytes()
    }

    /// Compile the RSN Capabilities field to little-endian wire bytes.
    pub const fn encode(self) -> [u8; RSN_CAPABILITIES_LEN] {
        self.to_le_bytes()
    }

    /// Return true when the Pre-Authentication bit is set.
    pub const fn pre_authentication(&self) -> bool {
        self.has_flag(RSN_CAP_PRE_AUTHENTICATION)
    }

    /// Return true when the No Pairwise bit is set.
    pub const fn no_pairwise(&self) -> bool {
        self.has_flag(RSN_CAP_NO_PAIRWISE)
    }

    /// Two-bit PTKSA Replay Counter selector as encoded on the wire.
    pub const fn ptksa_replay_counter(&self) -> u8 {
        ((self.bits & RSN_CAP_PTKSA_REPLAY_COUNTER_MASK) >> RSN_CAP_PTKSA_REPLAY_COUNTER_SHIFT)
            as u8
    }

    /// Number of PTKSA replay counters represented by the selector.
    pub const fn ptksa_replay_counter_count(&self) -> u8 {
        rsn_replay_counter_count(self.ptksa_replay_counter())
    }

    /// Two-bit GTKSA Replay Counter selector as encoded on the wire.
    pub const fn gtksa_replay_counter(&self) -> u8 {
        ((self.bits & RSN_CAP_GTKSA_REPLAY_COUNTER_MASK) >> RSN_CAP_GTKSA_REPLAY_COUNTER_SHIFT)
            as u8
    }

    /// Number of GTKSA replay counters represented by the selector.
    pub const fn gtksa_replay_counter_count(&self) -> u8 {
        rsn_replay_counter_count(self.gtksa_replay_counter())
    }

    /// Return true when Management Frame Protection Required is set.
    pub const fn management_frame_protection_required(&self) -> bool {
        self.has_flag(RSN_CAP_MFP_REQUIRED)
    }

    /// Compatibility alias for [`Self::management_frame_protection_required`].
    pub const fn mfp_required(&self) -> bool {
        self.management_frame_protection_required()
    }

    /// Return true when Management Frame Protection Capable is set.
    pub const fn management_frame_protection_capable(&self) -> bool {
        self.has_flag(RSN_CAP_MFP_CAPABLE)
    }

    /// Compatibility alias for [`Self::management_frame_protection_capable`].
    pub const fn mfp_capable(&self) -> bool {
        self.management_frame_protection_capable()
    }

    /// Return true when Joint Multi-band RSNA is set.
    pub const fn joint_multi_band_rsna(&self) -> bool {
        self.has_flag(RSN_CAP_JOINT_MULTI_BAND_RSNA)
    }

    /// Return true when PeerKey Enabled is set.
    pub const fn peerkey_enabled(&self) -> bool {
        self.has_flag(RSN_CAP_PEERKEY_ENABLED)
    }

    /// Return true when SPP A-MSDU Capable is set.
    pub const fn spp_a_msdu_capable(&self) -> bool {
        self.has_flag(RSN_CAP_SPP_A_MSDU_CAPABLE)
    }

    /// Return true when SPP A-MSDU Required is set.
    pub const fn spp_a_msdu_required(&self) -> bool {
        self.has_flag(RSN_CAP_SPP_A_MSDU_REQUIRED)
    }

    /// Return true when PBAC is set.
    pub const fn pbac(&self) -> bool {
        self.has_flag(RSN_CAP_PBAC)
    }

    /// Compatibility alias for [`Self::pbac`].
    pub const fn pbac_enabled(&self) -> bool {
        self.pbac()
    }

    /// Return true when Extended Key ID for individually addressed frames is set.
    pub const fn extended_key_id(&self) -> bool {
        self.has_flag(RSN_CAP_EXTENDED_KEY_ID)
    }

    /// Reserved bits as they appear in the raw 16-bit word.
    pub const fn reserved_bits(&self) -> u16 {
        self.bits & RSN_CAP_RESERVED_MASK
    }

    /// Set or clear the Pre-Authentication bit.
    pub const fn pre_authentication_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_PRE_AUTHENTICATION, enabled);
        self
    }

    /// Builder alias for [`Self::pre_authentication_set`].
    pub const fn with_pre_authentication(self, enabled: bool) -> Self {
        self.pre_authentication_set(enabled)
    }

    /// Set or clear the No Pairwise bit.
    pub const fn no_pairwise_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_NO_PAIRWISE, enabled);
        self
    }

    /// Builder alias for [`Self::no_pairwise_set`].
    pub const fn with_no_pairwise(self, enabled: bool) -> Self {
        self.no_pairwise_set(enabled)
    }

    /// Set the two-bit PTKSA Replay Counter selector.
    ///
    /// Only the low two bits of `replay_counter` are representable. Use
    /// [`Self::raw_set`] to set an exact 16-bit word.
    pub const fn ptksa_replay_counter_set(mut self, replay_counter: u8) -> Self {
        self.bits = set_rsn_capability_subfield(
            self.bits,
            RSN_CAP_PTKSA_REPLAY_COUNTER_MASK,
            RSN_CAP_PTKSA_REPLAY_COUNTER_SHIFT,
            replay_counter,
        );
        self
    }

    /// Builder alias for [`Self::ptksa_replay_counter_set`].
    pub const fn with_ptksa_replay_counter(self, replay_counter: u8) -> Self {
        self.ptksa_replay_counter_set(replay_counter)
    }

    /// Set the two-bit GTKSA Replay Counter selector.
    ///
    /// Only the low two bits of `replay_counter` are representable. Use
    /// [`Self::raw_set`] to set an exact 16-bit word.
    pub const fn gtksa_replay_counter_set(mut self, replay_counter: u8) -> Self {
        self.bits = set_rsn_capability_subfield(
            self.bits,
            RSN_CAP_GTKSA_REPLAY_COUNTER_MASK,
            RSN_CAP_GTKSA_REPLAY_COUNTER_SHIFT,
            replay_counter,
        );
        self
    }

    /// Builder alias for [`Self::gtksa_replay_counter_set`].
    pub const fn with_gtksa_replay_counter(self, replay_counter: u8) -> Self {
        self.gtksa_replay_counter_set(replay_counter)
    }

    /// Set or clear the Management Frame Protection Required bit.
    pub const fn management_frame_protection_required_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_MFP_REQUIRED, enabled);
        self
    }

    /// Builder alias for [`Self::management_frame_protection_required_set`].
    pub const fn with_management_frame_protection_required(self, enabled: bool) -> Self {
        self.management_frame_protection_required_set(enabled)
    }

    /// Set or clear the Management Frame Protection Capable bit.
    pub const fn management_frame_protection_capable_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_MFP_CAPABLE, enabled);
        self
    }

    /// Builder alias for [`Self::management_frame_protection_capable_set`].
    pub const fn with_management_frame_protection_capable(self, enabled: bool) -> Self {
        self.management_frame_protection_capable_set(enabled)
    }

    /// Set or clear the Joint Multi-band RSNA bit.
    pub const fn joint_multi_band_rsna_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_JOINT_MULTI_BAND_RSNA, enabled);
        self
    }

    /// Builder alias for [`Self::joint_multi_band_rsna_set`].
    pub const fn with_joint_multi_band_rsna(self, enabled: bool) -> Self {
        self.joint_multi_band_rsna_set(enabled)
    }

    /// Set or clear the PeerKey Enabled bit.
    pub const fn peerkey_enabled_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_PEERKEY_ENABLED, enabled);
        self
    }

    /// Builder alias for [`Self::peerkey_enabled_set`].
    pub const fn with_peerkey_enabled(self, enabled: bool) -> Self {
        self.peerkey_enabled_set(enabled)
    }

    /// Set or clear the SPP A-MSDU Capable bit.
    pub const fn spp_a_msdu_capable_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_SPP_A_MSDU_CAPABLE, enabled);
        self
    }

    /// Builder alias for [`Self::spp_a_msdu_capable_set`].
    pub const fn with_spp_a_msdu_capable(self, enabled: bool) -> Self {
        self.spp_a_msdu_capable_set(enabled)
    }

    /// Set or clear the SPP A-MSDU Required bit.
    pub const fn spp_a_msdu_required_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_SPP_A_MSDU_REQUIRED, enabled);
        self
    }

    /// Builder alias for [`Self::spp_a_msdu_required_set`].
    pub const fn with_spp_a_msdu_required(self, enabled: bool) -> Self {
        self.spp_a_msdu_required_set(enabled)
    }

    /// Set or clear the PBAC bit.
    pub const fn pbac_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_PBAC, enabled);
        self
    }

    /// Builder alias for [`Self::pbac_set`].
    pub const fn with_pbac(self, enabled: bool) -> Self {
        self.pbac_set(enabled)
    }

    /// Set or clear the Extended Key ID bit.
    pub const fn extended_key_id_set(mut self, enabled: bool) -> Self {
        self.bits = set_rsn_capability_flag(self.bits, RSN_CAP_EXTENDED_KEY_ID, enabled);
        self
    }

    /// Builder alias for [`Self::extended_key_id_set`].
    pub const fn with_extended_key_id(self, enabled: bool) -> Self {
        self.extended_key_id_set(enabled)
    }

    /// Set the reserved bits that this phase does not interpret.
    pub const fn reserved_bits_set(mut self, reserved_bits: u16) -> Self {
        self.bits = (self.bits & !RSN_CAP_RESERVED_MASK) | (reserved_bits & RSN_CAP_RESERVED_MASK);
        self
    }

    /// Builder alias for [`Self::reserved_bits_set`].
    pub const fn with_reserved_bits(self, reserved_bits: u16) -> Self {
        self.reserved_bits_set(reserved_bits)
    }

    const fn has_flag(&self, flag: u16) -> bool {
        self.bits & flag != 0
    }
}

impl From<u16> for RsnCapabilities {
    fn from(bits: u16) -> Self {
        Self::from_bits(bits)
    }
}

impl From<RsnCapabilities> for u16 {
    fn from(capabilities: RsnCapabilities) -> Self {
        capabilities.bits()
    }
}

impl From<[u8; RSN_CAPABILITIES_LEN]> for RsnCapabilities {
    fn from(bytes: [u8; RSN_CAPABILITIES_LEN]) -> Self {
        Self::from_le_bytes(bytes)
    }
}

impl From<RsnCapabilities> for [u8; RSN_CAPABILITIES_LEN] {
    fn from(capabilities: RsnCapabilities) -> Self {
        capabilities.to_le_bytes()
    }
}

const fn rsn_replay_counter_count(encoded: u8) -> u8 {
    match encoded & 0x03 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 16,
    }
}

const fn set_rsn_capability_flag(bits: u16, flag: u16, enabled: bool) -> u16 {
    if enabled {
        bits | flag
    } else {
        bits & !flag
    }
}

const fn set_rsn_capability_subfield(bits: u16, mask: u16, shift: u8, value: u8) -> u16 {
    (bits & !mask) | (((value as u16) << shift) & mask)
}

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

/// Robust Security Network information element value bytes.
///
/// This type represents only the RSN information element value: it does not
/// include the outer IEEE 802.11 tagged-parameter element ID or length octets.
/// Decode preserves unknown suite selectors and unsupported trailing bytes so
/// decoded values can be encoded back without losing source bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsnInformation {
    version: u16,
    group_cipher: RsnCipherSuite,
    pairwise_ciphers: Vec<RsnCipherSuite>,
    akm_suites: Vec<RsnAkmSuite>,
    capabilities: Option<RsnCapabilities>,
    pmkid_count_present: bool,
    pmkids: Vec<[u8; RSN_PMKID_LEN]>,
    group_management_cipher: Option<RsnCipherSuite>,
    trailing: Vec<u8>,
}

impl RsnInformation {
    /// Create a source-backed WPA2-PSK-style RSN value.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode RSN information element value bytes.
    pub fn decode(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Self::from_tagged_parameter_value(bytes)
    }

    /// Decode RSN information element value bytes.
    ///
    /// The input must not include the outer tagged-parameter element ID or
    /// length octets.
    pub fn from_tagged_parameter_value(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let mut offset = 0usize;

        ensure_rsn_len(bytes, offset + 2, "rsn_information_element.version")?;
        let version = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        offset += 2;

        ensure_rsn_len(
            bytes,
            offset + RSN_SUITE_SELECTOR_LEN,
            "rsn_information_element.group_cipher",
        )?;
        let group_cipher = RsnCipherSuite::from_bytes(copy_selector(bytes, offset));
        offset += RSN_SUITE_SELECTOR_LEN;

        ensure_rsn_len(bytes, offset + 2, "rsn_information_element.pairwise_count")?;
        let pairwise_count = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        let pairwise_end = checked_rsn_list_end(
            offset,
            pairwise_count,
            RSN_SUITE_SELECTOR_LEN,
            "rsn_information_element.pairwise_count",
        )?;
        ensure_rsn_len(
            bytes,
            pairwise_end,
            "rsn_information_element.pairwise_ciphers",
        )?;
        let mut pairwise_ciphers = Vec::with_capacity(pairwise_count);
        while offset < pairwise_end {
            pairwise_ciphers.push(RsnCipherSuite::from_bytes(copy_selector(bytes, offset)));
            offset += RSN_SUITE_SELECTOR_LEN;
        }

        ensure_rsn_len(bytes, offset + 2, "rsn_information_element.akm_count")?;
        let akm_count = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;
        let akm_end = checked_rsn_list_end(
            offset,
            akm_count,
            RSN_SUITE_SELECTOR_LEN,
            "rsn_information_element.akm_count",
        )?;
        ensure_rsn_len(bytes, akm_end, "rsn_information_element.akm_suites")?;
        let mut akm_suites = Vec::with_capacity(akm_count);
        while offset < akm_end {
            akm_suites.push(RsnAkmSuite::from_bytes(copy_selector(bytes, offset)));
            offset += RSN_SUITE_SELECTOR_LEN;
        }

        let mut trailing = Vec::new();
        let capabilities = if bytes.len().saturating_sub(offset) >= RSN_CAPABILITIES_LEN {
            let capabilities = RsnCapabilities::from_le_bytes([bytes[offset], bytes[offset + 1]]);
            offset += RSN_CAPABILITIES_LEN;
            Some(capabilities)
        } else {
            trailing.extend_from_slice(&bytes[offset..]);
            return Ok(Self {
                version,
                group_cipher,
                pairwise_ciphers,
                akm_suites,
                capabilities: None,
                pmkid_count_present: false,
                pmkids: Vec::new(),
                group_management_cipher: None,
                trailing,
            });
        };

        let mut pmkid_count_present = false;
        let mut pmkids = Vec::new();
        if bytes.len().saturating_sub(offset) >= 2 {
            pmkid_count_present = true;
            let pmkid_count = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;
            let pmkid_end = checked_rsn_list_end(
                offset,
                pmkid_count,
                RSN_PMKID_LEN,
                "rsn_information_element.pmkid_count",
            )?;
            ensure_rsn_len(bytes, pmkid_end, "rsn_information_element.pmkids")?;
            pmkids.reserve(pmkid_count);
            while offset < pmkid_end {
                pmkids.push(copy_pmkid(bytes, offset));
                offset += RSN_PMKID_LEN;
            }
        } else {
            trailing.extend_from_slice(&bytes[offset..]);
            return Ok(Self {
                version,
                group_cipher,
                pairwise_ciphers,
                akm_suites,
                capabilities,
                pmkid_count_present,
                pmkids,
                group_management_cipher: None,
                trailing,
            });
        }

        let group_management_cipher =
            if bytes.len().saturating_sub(offset) >= RSN_SUITE_SELECTOR_LEN {
                let cipher = RsnCipherSuite::from_bytes(copy_selector(bytes, offset));
                offset += RSN_SUITE_SELECTOR_LEN;
                Some(cipher)
            } else {
                None
            };
        trailing.extend_from_slice(&bytes[offset..]);

        Ok(Self {
            version,
            group_cipher,
            pairwise_ciphers,
            akm_suites,
            capabilities,
            pmkid_count_present,
            pmkids,
            group_management_cipher,
            trailing,
        })
    }

    /// Encode this RSN information element as tagged-parameter value bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.to_tagged_parameter_value()
    }

    /// Encode this RSN information element as tagged-parameter value bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.to_tagged_parameter_value()
    }

    /// Encode this RSN information element as tagged-parameter value bytes.
    ///
    /// The returned bytes do not include the outer tagged-parameter element ID
    /// or length octets.
    pub fn to_tagged_parameter_value(&self) -> Result<Vec<u8>> {
        let pairwise_count = u16::try_from(self.pairwise_ciphers.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "rsn_information_element.pairwise_count",
                "pairwise cipher count exceeds 65535",
            )
        })?;
        let akm_count = u16::try_from(self.akm_suites.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "rsn_information_element.akm_count",
                "AKM suite count exceeds 65535",
            )
        })?;
        let pmkid_count = u16::try_from(self.pmkids.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "rsn_information_element.pmkid_count",
                "PMKID count exceeds 65535",
            )
        })?;

        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.group_cipher.to_bytes());
        out.extend_from_slice(&pairwise_count.to_le_bytes());
        for cipher in &self.pairwise_ciphers {
            out.extend_from_slice(&cipher.to_bytes());
        }
        out.extend_from_slice(&akm_count.to_le_bytes());
        for akm in &self.akm_suites {
            out.extend_from_slice(&akm.to_bytes());
        }

        let needs_capabilities = self.capabilities.is_some()
            || self.pmkid_count_present
            || !self.pmkids.is_empty()
            || self.group_management_cipher.is_some();
        if needs_capabilities {
            out.extend_from_slice(&self.capabilities.unwrap_or_default().to_le_bytes());
        }

        let needs_pmkid_count = self.pmkid_count_present
            || !self.pmkids.is_empty()
            || self.group_management_cipher.is_some();
        if needs_pmkid_count {
            out.extend_from_slice(&pmkid_count.to_le_bytes());
            for pmkid in &self.pmkids {
                out.extend_from_slice(pmkid);
            }
        }

        if let Some(cipher) = self.group_management_cipher {
            out.extend_from_slice(&cipher.to_bytes());
        }
        out.extend_from_slice(&self.trailing);
        Ok(out)
    }

    /// RSN information element version.
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// RSN information element version.
    pub const fn version_value(&self) -> u16 {
        self.version
    }

    /// Group Data Cipher Suite selector.
    pub const fn group_cipher(&self) -> RsnCipherSuite {
        self.group_cipher
    }

    /// Group Data Cipher Suite selector.
    pub const fn group_cipher_suite(&self) -> RsnCipherSuite {
        self.group_cipher
    }

    /// Pairwise Cipher Suite List.
    pub fn pairwise_ciphers(&self) -> &[RsnCipherSuite] {
        &self.pairwise_ciphers
    }

    /// Pairwise Cipher Suite List.
    pub fn pairwise_cipher_list(&self) -> &[RsnCipherSuite] {
        &self.pairwise_ciphers
    }

    /// AKM Suite List.
    pub fn akm_suites(&self) -> &[RsnAkmSuite] {
        &self.akm_suites
    }

    /// AKM Suite List.
    pub fn akm_list(&self) -> &[RsnAkmSuite] {
        &self.akm_suites
    }

    /// RSN Capabilities field, when present in the value.
    pub const fn capabilities(&self) -> Option<RsnCapabilities> {
        self.capabilities
    }

    /// Return true when a PMKID Count field was present.
    pub const fn pmkid_count_present(&self) -> bool {
        self.pmkid_count_present
    }

    /// PMKID List.
    pub fn pmkids(&self) -> &[[u8; RSN_PMKID_LEN]] {
        &self.pmkids
    }

    /// PMKID List.
    pub fn pmkid_list(&self) -> &[[u8; RSN_PMKID_LEN]] {
        &self.pmkids
    }

    /// Group Management Cipher Suite selector, when present.
    pub const fn group_management_cipher(&self) -> Option<RsnCipherSuite> {
        self.group_management_cipher
    }

    /// Group Management Cipher Suite selector, when present.
    pub const fn group_management_cipher_suite(&self) -> Option<RsnCipherSuite> {
        self.group_management_cipher
    }

    /// Unsupported trailing bytes preserved from the value.
    pub fn trailing_bytes(&self) -> &[u8] {
        &self.trailing
    }

    /// Unsupported trailing bytes preserved from the value.
    pub fn extension_bytes(&self) -> &[u8] {
        &self.trailing
    }

    /// Set the RSN information element version.
    pub const fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    /// Set the Group Data Cipher Suite selector.
    pub const fn with_group_cipher(mut self, cipher: RsnCipherSuite) -> Self {
        self.group_cipher = cipher;
        self
    }

    /// Set the Group Data Cipher Suite selector.
    pub const fn with_group_cipher_suite(self, cipher: RsnCipherSuite) -> Self {
        self.with_group_cipher(cipher)
    }

    /// Replace the Pairwise Cipher Suite List.
    pub fn with_pairwise_ciphers(mut self, ciphers: impl Into<Vec<RsnCipherSuite>>) -> Self {
        self.pairwise_ciphers = ciphers.into();
        self
    }

    /// Replace the Pairwise Cipher Suite List.
    pub fn with_pairwise_cipher_list(self, ciphers: impl Into<Vec<RsnCipherSuite>>) -> Self {
        self.with_pairwise_ciphers(ciphers)
    }

    /// Append one Pairwise Cipher Suite selector.
    pub fn with_pairwise_cipher(mut self, cipher: RsnCipherSuite) -> Self {
        self.pairwise_ciphers.push(cipher);
        self
    }

    /// Replace the AKM Suite List.
    pub fn with_akm_suites(mut self, akms: impl Into<Vec<RsnAkmSuite>>) -> Self {
        self.akm_suites = akms.into();
        self
    }

    /// Replace the AKM Suite List.
    pub fn with_akm_list(self, akms: impl Into<Vec<RsnAkmSuite>>) -> Self {
        self.with_akm_suites(akms)
    }

    /// Append one AKM Suite selector.
    pub fn with_akm_suite(mut self, akm: RsnAkmSuite) -> Self {
        self.akm_suites.push(akm);
        self
    }

    /// Set the RSN Capabilities field.
    pub const fn with_capabilities(mut self, capabilities: RsnCapabilities) -> Self {
        self.capabilities = Some(capabilities);
        self
    }

    /// Omit the RSN Capabilities field during encoding unless later fields require it.
    pub fn without_capabilities(mut self) -> Self {
        self.capabilities = None;
        self
    }

    /// Replace the PMKID List and emit a PMKID Count field.
    pub fn with_pmkids(mut self, pmkids: impl Into<Vec<[u8; RSN_PMKID_LEN]>>) -> Self {
        self.pmkids = pmkids.into();
        self.pmkid_count_present = true;
        self
    }

    /// Replace the PMKID List and emit a PMKID Count field.
    pub fn with_pmkid_list(self, pmkids: impl Into<Vec<[u8; RSN_PMKID_LEN]>>) -> Self {
        self.with_pmkids(pmkids)
    }

    /// Control whether a zero PMKID Count field is encoded when the PMKID list is empty.
    pub const fn with_pmkid_count_present(mut self, present: bool) -> Self {
        self.pmkid_count_present = present;
        self
    }

    /// Clear the PMKID Count and PMKID List fields.
    pub fn without_pmkids(mut self) -> Self {
        self.pmkids.clear();
        self.pmkid_count_present = false;
        self
    }

    /// Set the Group Management Cipher Suite selector.
    pub const fn with_group_management_cipher(mut self, cipher: RsnCipherSuite) -> Self {
        self.group_management_cipher = Some(cipher);
        self
    }

    /// Set the Group Management Cipher Suite selector.
    pub const fn with_group_management_cipher_suite(self, cipher: RsnCipherSuite) -> Self {
        self.with_group_management_cipher(cipher)
    }

    /// Clear the Group Management Cipher Suite selector.
    pub const fn without_group_management_cipher(mut self) -> Self {
        self.group_management_cipher = None;
        self
    }

    /// Replace unsupported trailing bytes.
    pub fn with_trailing_bytes(mut self, trailing: impl Into<Vec<u8>>) -> Self {
        self.trailing = trailing.into();
        self
    }

    /// Replace unsupported trailing bytes.
    pub fn with_extension_bytes(self, trailing: impl Into<Vec<u8>>) -> Self {
        self.with_trailing_bytes(trailing)
    }
}

impl Default for RsnInformation {
    fn default() -> Self {
        Self {
            version: RSN_VERSION_1,
            group_cipher: RSN_CIPHER_SUITE_CCMP_128,
            pairwise_ciphers: vec![RSN_CIPHER_SUITE_CCMP_128],
            akm_suites: vec![RSN_AKM_SUITE_PSK],
            capabilities: Some(RsnCapabilities::new()),
            pmkid_count_present: false,
            pmkids: Vec::new(),
            group_management_cipher: None,
            trailing: Vec::new(),
        }
    }
}

fn ensure_rsn_len(bytes: &[u8], required: usize, context: &'static str) -> Result<()> {
    if bytes.len() < required {
        return Err(CrafterError::buffer_too_short(
            context,
            required,
            bytes.len(),
        ));
    }

    Ok(())
}

fn checked_rsn_list_end(
    offset: usize,
    count: usize,
    item_len: usize,
    field: &'static str,
) -> Result<usize> {
    let byte_len = count
        .checked_mul(item_len)
        .ok_or_else(|| CrafterError::invalid_field_value(field, "RSN list byte length overflow"))?;
    offset
        .checked_add(byte_len)
        .ok_or_else(|| CrafterError::invalid_field_value(field, "RSN list end offset overflow"))
}

fn copy_selector(bytes: &[u8], offset: usize) -> [u8; RSN_SUITE_SELECTOR_LEN] {
    [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]
}

fn copy_pmkid(bytes: &[u8], offset: usize) -> [u8; RSN_PMKID_LEN] {
    [
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
        bytes[offset + 8],
        bytes[offset + 9],
        bytes[offset + 10],
        bytes[offset + 11],
        bytes[offset + 12],
        bytes[offset + 13],
        bytes[offset + 14],
        bytes[offset + 15],
    ]
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
        use crate::core::{
            RsnAkmSuite as CoreAkm, RsnCapabilities as CoreCapabilities,
            RSN_AKM_SUITE_PSK as CORE_PSK,
        };
        use crate::prelude::{
            RsnCapabilities as PreludeCapabilities, RsnCipherSuite as PreludeCipher,
            RSN_CIPHER_SUITE_CCMP_128 as PRELUDE_CCMP,
        };
        use crate::protocols::{
            rsn_akm_suite_label as protocols_akm_label, RsnCapabilities as ProtocolsCapabilities,
            RsnSuiteSelector as ProtocolsSelector,
        };

        assert_eq!(CoreAkm::from(CORE_PSK).label(), Some("psk"));
        assert_eq!(PreludeCipher::from(PRELUDE_CCMP).label(), Some("ccmp-128"));
        assert!(CoreCapabilities::new()
            .with_pre_authentication(true)
            .pre_authentication());
        assert!(PreludeCapabilities::from_le_bytes([0x80, 0x00]).mfp_capable());
        assert!(ProtocolsCapabilities::from_raw(0x2000).extended_key_id());
        assert_eq!(
            protocols_akm_label(RsnAkmSuite::new(RSN_SUITE_SELECTOR_OUI, 8)),
            Some("sae")
        );
        assert_eq!(
            ProtocolsSelector::from([0x00, 0x0f, 0xac, 0x04]).to_bytes(),
            [0x00, 0x0f, 0xac, 0x04]
        );
    }

    #[test]
    fn rsn_capabilities_decode_encode_little_endian_and_raw_bits() {
        let capabilities = RsnCapabilities::from_le_bytes([0xca, 0x35]);

        assert_eq!(capabilities.bits(), 0x35ca);
        assert_eq!(capabilities.raw(), 0x35ca);
        assert_eq!(capabilities.to_le_bytes(), [0xca, 0x35]);
        assert_eq!(capabilities.encode(), [0xca, 0x35]);
        assert_eq!(RsnCapabilities::decode([0xca, 0x35]).unwrap(), capabilities);
        assert_eq!(
            RsnCapabilities::decode([0xff]).unwrap_err(),
            CrafterError::buffer_too_short("rsn.capabilities", RSN_CAPABILITIES_LEN, 1)
        );
    }

    #[test]
    fn rsn_capabilities_bit_accessors_cover_source_backed_flags() {
        let capabilities = RsnCapabilities::new()
            .with_pre_authentication(true)
            .with_no_pairwise(true)
            .with_management_frame_protection_required(true)
            .with_management_frame_protection_capable(true)
            .with_joint_multi_band_rsna(true)
            .with_peerkey_enabled(true)
            .with_spp_a_msdu_capable(true)
            .with_spp_a_msdu_required(true)
            .with_pbac(true)
            .with_extended_key_id(true);

        assert!(capabilities.pre_authentication());
        assert!(capabilities.no_pairwise());
        assert!(capabilities.management_frame_protection_required());
        assert!(capabilities.mfp_required());
        assert!(capabilities.management_frame_protection_capable());
        assert!(capabilities.mfp_capable());
        assert!(capabilities.joint_multi_band_rsna());
        assert!(capabilities.peerkey_enabled());
        assert!(capabilities.spp_a_msdu_capable());
        assert!(capabilities.spp_a_msdu_required());
        assert!(capabilities.pbac());
        assert!(capabilities.pbac_enabled());
        assert!(capabilities.extended_key_id());
        assert_eq!(capabilities.bits(), 0x3fc3);
        assert_eq!(capabilities.to_le_bytes(), [0xc3, 0x3f]);
    }

    #[test]
    fn rsn_capabilities_replay_counter_accessors_cover_encoded_counts() {
        let counts = [1, 2, 4, 16];

        for encoded in 0..=3 {
            let capabilities = RsnCapabilities::new()
                .with_ptksa_replay_counter(encoded)
                .with_gtksa_replay_counter(3 - encoded);

            assert_eq!(capabilities.ptksa_replay_counter(), encoded);
            assert_eq!(
                capabilities.ptksa_replay_counter_count(),
                counts[encoded as usize]
            );
            assert_eq!(capabilities.gtksa_replay_counter(), 3 - encoded);
            assert_eq!(
                capabilities.gtksa_replay_counter_count(),
                counts[(3 - encoded) as usize]
            );
        }

        let truncated = RsnCapabilities::new()
            .with_ptksa_replay_counter(0xff)
            .with_gtksa_replay_counter(0xfe);
        assert_eq!(truncated.ptksa_replay_counter(), 3);
        assert_eq!(truncated.gtksa_replay_counter(), 2);
    }

    #[test]
    fn rsn_capabilities_reserved_bits_are_lossless() {
        let decoded = RsnCapabilities::from_raw(0xffff);

        assert_eq!(decoded.reserved_bits(), 0xc000);
        assert_eq!(decoded.to_le_bytes(), [0xff, 0xff]);

        let capabilities = RsnCapabilities::new()
            .with_pre_authentication(true)
            .with_reserved_bits(0xffff);

        assert!(capabilities.pre_authentication());
        assert_eq!(capabilities.reserved_bits(), 0xc000);
        assert_eq!(capabilities.bits(), 0xc001);
        assert_eq!(u16::from(capabilities), 0xc001);
        assert_eq!(
            <[u8; RSN_CAPABILITIES_LEN]>::from(capabilities),
            [0x01, 0xc0]
        );
    }

    #[test]
    fn rsn_information_element_decodes_and_encodes_fixture_value_bytes() {
        let bytes = [
            0x01, 0x00, // version
            0x00, 0x0f, 0xac, 0x04, // group cipher: CCMP-128
            0x01, 0x00, // pairwise count
            0x00, 0x0f, 0xac, 0x04, // pairwise cipher: CCMP-128
            0x01, 0x00, // AKM count
            0x00, 0x0f, 0xac, 0x02, // AKM: PSK
            0x0c, 0x00, // RSN capabilities
        ];

        let rsn = RsnInformation::decode(bytes).unwrap();

        assert_eq!(rsn.version(), RSN_VERSION_1);
        assert_eq!(rsn.group_cipher(), RSN_CIPHER_SUITE_CCMP_128);
        assert_eq!(rsn.pairwise_ciphers(), &[RSN_CIPHER_SUITE_CCMP_128]);
        assert_eq!(rsn.akm_suites(), &[RSN_AKM_SUITE_PSK]);
        assert_eq!(rsn.capabilities().unwrap().bits(), 0x000c);
        assert!(!rsn.pmkid_count_present());
        assert!(rsn.pmkids().is_empty());
        assert_eq!(rsn.group_management_cipher(), None);
        assert!(rsn.trailing_bytes().is_empty());
        assert_eq!(rsn.to_tagged_parameter_value().unwrap(), bytes);
        assert_eq!(rsn.encode().unwrap(), bytes);
    }

    #[test]
    fn rsn_information_element_preserves_unknown_selectors_pmkids_group_management_and_extensions()
    {
        let pmkid = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let vendor_group = RsnCipherSuite::new([0x02, 0x00, 0x5e], 0x99);
        let unknown_pairwise = RsnCipherSuite::new(RSN_SUITE_SELECTOR_OUI, 0xfe);
        let vendor_akm = RsnAkmSuite::new([0x02, 0x00, 0x5e], 0x55);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&RSN_VERSION_1.to_le_bytes());
        bytes.extend_from_slice(&vendor_group.to_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&RSN_CIPHER_SUITE_CCMP_128.to_bytes());
        bytes.extend_from_slice(&unknown_pairwise.to_bytes());
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&RSN_AKM_SUITE_PSK.to_bytes());
        bytes.extend_from_slice(&vendor_akm.to_bytes());
        bytes.extend_from_slice(
            &RsnCapabilities::new()
                .with_management_frame_protection_required(true)
                .with_management_frame_protection_capable(true)
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&pmkid);
        bytes.extend_from_slice(&RSN_CIPHER_SUITE_AES_128_CMAC.to_bytes());
        bytes.extend_from_slice(&[0xee, 0xff]);

        let rsn = RsnInformation::decode(&bytes).unwrap();

        assert_eq!(rsn.group_cipher(), vendor_group);
        assert_eq!(
            rsn.pairwise_cipher_list(),
            &[RSN_CIPHER_SUITE_CCMP_128, unknown_pairwise]
        );
        assert_eq!(rsn.akm_list(), &[RSN_AKM_SUITE_PSK, vendor_akm]);
        assert!(rsn.capabilities().unwrap().mfp_required());
        assert!(rsn.capabilities().unwrap().mfp_capable());
        assert!(rsn.pmkid_count_present());
        assert_eq!(rsn.pmkid_list(), &[pmkid]);
        assert_eq!(
            rsn.group_management_cipher_suite(),
            Some(RSN_CIPHER_SUITE_AES_128_CMAC)
        );
        assert_eq!(rsn.extension_bytes(), &[0xee, 0xff]);
        assert_eq!(rsn.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn rsn_information_element_builder_encodes_value_bytes() {
        let pmkids = [[0x44; 16], [0x55; 16]];
        let rsn = RsnInformation::new()
            .with_version(2)
            .with_group_cipher_suite(RSN_CIPHER_SUITE_GCMP_256)
            .with_pairwise_cipher_list([RSN_CIPHER_SUITE_GCMP_256, RSN_CIPHER_SUITE_CCMP_128])
            .with_akm_list([RSN_AKM_SUITE_SAE])
            .with_capabilities(RsnCapabilities::new().with_extended_key_id(true))
            .with_pmkid_list(pmkids)
            .with_group_management_cipher_suite(RSN_CIPHER_SUITE_BIP_GMAC_128)
            .with_extension_bytes([0xaa]);
        let mut expected = Vec::new();
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(&RSN_CIPHER_SUITE_GCMP_256.to_bytes());
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(&RSN_CIPHER_SUITE_GCMP_256.to_bytes());
        expected.extend_from_slice(&RSN_CIPHER_SUITE_CCMP_128.to_bytes());
        expected.extend_from_slice(&1u16.to_le_bytes());
        expected.extend_from_slice(&RSN_AKM_SUITE_SAE.to_bytes());
        expected.extend_from_slice(&0x2000u16.to_le_bytes());
        expected.extend_from_slice(&2u16.to_le_bytes());
        expected.extend_from_slice(&[0x44; 16]);
        expected.extend_from_slice(&[0x55; 16]);
        expected.extend_from_slice(&RSN_CIPHER_SUITE_BIP_GMAC_128.to_bytes());
        expected.push(0xaa);

        assert_eq!(rsn.to_tagged_parameter_value().unwrap(), expected);
        assert_eq!(RsnInformation::decode(&expected).unwrap(), rsn);
    }

    #[test]
    fn rsn_information_element_optional_tails_round_trip_at_their_boundaries() {
        let without_capabilities = RsnInformation::new()
            .without_capabilities()
            .with_trailing_bytes([0xaa]);
        let without_pmkid_count = RsnInformation::new().with_trailing_bytes([0xbb]);
        let with_zero_pmkid_count = RsnInformation::new()
            .with_pmkid_count_present(true)
            .with_trailing_bytes([0xcc, 0xdd, 0xee]);

        for rsn in [
            without_capabilities,
            without_pmkid_count,
            with_zero_pmkid_count,
        ] {
            let encoded = rsn.encode().unwrap();
            assert_eq!(RsnInformation::decode(&encoded).unwrap(), rsn);
        }
    }

    #[test]
    fn rsn_information_element_pairwise_count_length_mismatch_is_structured_error() {
        let bytes = [
            0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x02, 0x00, 0x00, 0x0f, 0xac, 0x04,
        ];
        let error = RsnInformation::decode(bytes).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("rsn_information_element.pairwise_ciphers", 16, 12)
        );
    }

    #[test]
    fn rsn_information_element_akm_count_length_mismatch_is_structured_error() {
        let bytes = [
            0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x02, 0x00,
            0x00, 0x0f, 0xac, 0x02,
        ];
        let error = RsnInformation::decode(bytes).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("rsn_information_element.akm_suites", 22, 18)
        );
    }

    #[test]
    fn rsn_information_element_pmkid_count_length_mismatch_is_structured_error() {
        let mut bytes = RsnInformation::new()
            .with_pmkids([[0x10; 16]])
            .encode()
            .unwrap();
        let pmkid_count_offset = 20;
        bytes[pmkid_count_offset..pmkid_count_offset + 2].copy_from_slice(&2u16.to_le_bytes());
        let error = RsnInformation::decode(bytes).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("rsn_information_element.pmkids", 54, 38)
        );
    }

    #[test]
    fn rsn_information_element_short_mandatory_prefix_is_structured_error() {
        let error = RsnInformation::decode([0x01]).unwrap_err();

        assert_eq!(
            error,
            CrafterError::buffer_too_short("rsn_information_element.version", 2, 1)
        );
    }
}
