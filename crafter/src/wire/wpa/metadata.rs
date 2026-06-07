//! WPA metadata attached by decryptor stages.

use crate::MacAddr;

/// WPA/WPA2 cipher suite recognized by the decryptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WpaCipher {
    /// Cipher has not been learned yet.
    Unknown,
    /// AES-CCMP with a 128-bit temporal key.
    Ccmp128,
    /// TKIP, currently outside the first decrypt path.
    Tkip,
    /// AES-GCMP with a 128-bit temporal key.
    Gcmp128,
    /// AES-GCMP with a 256-bit temporal key.
    Gcmp256,
    /// AES-CCMP with a 256-bit temporal key.
    Ccmp256,
    /// A cipher suite selector not handled by this crate yet.
    Unsupported(u32),
}

/// WPA/WPA2 authentication and key management suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WpaAkm {
    /// AKM has not been learned yet.
    Unknown,
    /// WPA/WPA2-Personal pre-shared key authentication.
    Psk,
    /// WPA-Enterprise / 802.1X authentication.
    Enterprise,
    /// WPA3 SAE authentication.
    Sae,
    /// An AKM selector not handled by this crate yet.
    Unsupported(u32),
}

/// Key class used for a protected Wi-Fi frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WpaKeyKind {
    /// Key kind is not known yet.
    Unknown,
    /// Pairwise transient key material for unicast traffic.
    Pairwise,
    /// Group temporal key material for multicast or broadcast traffic.
    Group,
}

/// Whether configured credentials matched the observed WPA handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WpaCredentialStatus {
    /// Credential matching has not been attempted yet.
    Unknown,
    /// No configured network matched the observed record.
    NotConfigured,
    /// Configured credentials matched and produced usable key material.
    Matched,
    /// Configured credentials did not verify the observed handshake.
    Mismatch,
}

/// Passive 4-way-handshake state visible to callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WpaHandshakeStatus {
    /// No relevant handshake material has been observed.
    NotStarted,
    /// Some handshake material has been observed but key state is incomplete.
    Observing,
    /// The needed handshake fields have been observed.
    Complete,
    /// The EAPOL-Key MIC verified with configured credentials.
    MicVerified,
    /// Handshake processing failed.
    Failed,
}

/// Reason a WPA decrypt transform did or did not decrypt a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WpaDecryptReason {
    /// Decryption was not attempted for this record.
    NotAttempted,
    /// No configured network matched the observed record.
    NetworkNotConfigured,
    /// The transform is waiting for handshake material.
    WaitingForHandshake,
    /// The observed cipher is not supported by this decryptor.
    UnsupportedCipher,
    /// The observed authentication/key-management suite is not supported.
    UnsupportedAkm,
    /// Required pairwise or group key material is missing.
    MissingKeyMaterial,
    /// EAPOL-Key MIC verification failed.
    MicFailed,
    /// Protected payload authentication failed.
    AuthenticationFailed,
    /// The protected frame or handshake record was malformed.
    MalformedFrame,
    /// The record was successfully decrypted.
    Decrypted,
}

/// WPA-specific metadata produced by the decryptor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct WpaMetadata {
    bssid: Option<MacAddr>,
    station: Option<MacAddr>,
    cipher: Option<WpaCipher>,
    akm: Option<WpaAkm>,
    key_kind: Option<WpaKeyKind>,
    key_id: Option<u8>,
    packet_number: Option<u64>,
    handshake_status: Option<WpaHandshakeStatus>,
    decrypt_reason: Option<WpaDecryptReason>,
    credential_status: Option<WpaCredentialStatus>,
}

impl WpaMetadata {
    /// Create empty WPA metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// BSSID associated with this WPA observation when known.
    pub const fn bssid(&self) -> Option<MacAddr> {
        self.bssid
    }

    /// Station address associated with this WPA session when known.
    pub const fn station(&self) -> Option<MacAddr> {
        self.station
    }

    /// Cipher suite when known.
    pub const fn cipher(&self) -> Option<WpaCipher> {
        self.cipher
    }

    /// Authentication and key management suite when known.
    pub const fn akm(&self) -> Option<WpaAkm> {
        self.akm
    }

    /// Key kind when known.
    pub const fn key_kind(&self) -> Option<WpaKeyKind> {
        self.key_kind
    }

    /// Key identifier when known.
    pub const fn key_id(&self) -> Option<u8> {
        self.key_id
    }

    /// WPA packet number when known.
    pub const fn packet_number(&self) -> Option<u64> {
        self.packet_number
    }

    /// Handshake status when known.
    pub const fn handshake_status(&self) -> Option<WpaHandshakeStatus> {
        self.handshake_status
    }

    /// Decrypt reason when known.
    pub const fn decrypt_reason(&self) -> Option<WpaDecryptReason> {
        self.decrypt_reason
    }

    /// Credential-match status when known.
    pub const fn credential_status(&self) -> Option<WpaCredentialStatus> {
        self.credential_status
    }

    /// Whether configured credentials matched when that is known.
    pub const fn credentials_matched(&self) -> Option<bool> {
        match self.credential_status {
            Some(WpaCredentialStatus::Matched) => Some(true),
            Some(WpaCredentialStatus::Mismatch) => Some(false),
            _ => None,
        }
    }

    /// Set BSSID metadata.
    pub const fn with_bssid(mut self, bssid: MacAddr) -> Self {
        self.bssid = Some(bssid);
        self
    }

    /// Set station address metadata.
    pub const fn with_station(mut self, station: MacAddr) -> Self {
        self.station = Some(station);
        self
    }

    /// Set cipher suite metadata.
    pub const fn with_cipher(mut self, cipher: WpaCipher) -> Self {
        self.cipher = Some(cipher);
        self
    }

    /// Set AKM suite metadata.
    pub const fn with_akm(mut self, akm: WpaAkm) -> Self {
        self.akm = Some(akm);
        self
    }

    /// Set key kind metadata.
    pub const fn with_key_kind(mut self, key_kind: WpaKeyKind) -> Self {
        self.key_kind = Some(key_kind);
        self
    }

    /// Set key identifier metadata.
    pub const fn with_key_id(mut self, key_id: u8) -> Self {
        self.key_id = Some(key_id);
        self
    }

    /// Set WPA packet number metadata.
    pub const fn with_packet_number(mut self, packet_number: u64) -> Self {
        self.packet_number = Some(packet_number);
        self
    }

    /// Set handshake status metadata.
    pub const fn with_handshake_status(mut self, handshake_status: WpaHandshakeStatus) -> Self {
        self.handshake_status = Some(handshake_status);
        self
    }

    /// Set decrypt reason metadata.
    pub const fn with_decrypt_reason(mut self, decrypt_reason: WpaDecryptReason) -> Self {
        self.decrypt_reason = Some(decrypt_reason);
        self
    }

    /// Set credential-match status metadata.
    pub const fn with_credential_status(mut self, credential_status: WpaCredentialStatus) -> Self {
        self.credential_status = Some(credential_status);
        self
    }

    /// Set credential-match metadata as a boolean.
    pub const fn with_credentials_matched(mut self, matched: bool) -> Self {
        self.credential_status = Some(if matched {
            WpaCredentialStatus::Matched
        } else {
            WpaCredentialStatus::Mismatch
        });
        self
    }
}
