//! WPA decryptor configuration types.

/// Configuration for the passive WPA decrypt transform.
///
/// The current skeleton keeps behavior inert and passes records through
/// unchanged. Later steps will use this configuration to decide how original
/// frames, handshake records, diagnostics, and undecryptable protected frames
/// are emitted.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WpaDecryptConfig {
    pass_originals: bool,
}

impl WpaDecryptConfig {
    /// Create the default WPA decryptor configuration.
    pub const fn new() -> Self {
        Self {
            pass_originals: true,
        }
    }

    /// Configure whether original records should be passed through.
    pub const fn pass_originals(mut self, pass_originals: bool) -> Self {
        self.pass_originals = pass_originals;
        self
    }

    /// Whether original records are configured for pass-through.
    pub const fn emits_originals(&self) -> bool {
        self.pass_originals
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
/// placeholder stores passphrases only as caller-provided configuration; key
/// derivation is intentionally left to later implementation steps.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WpaNetwork {
    ssid: Vec<u8>,
    passphrase: Option<String>,
    pmk: Option<[u8; 32]>,
}

impl WpaNetwork {
    /// Configure a network from a UTF-8 SSID and passphrase.
    pub fn passphrase(ssid: impl Into<String>, passphrase: impl Into<String>) -> Self {
        Self::passphrase_bytes(ssid.into().into_bytes(), passphrase)
    }

    /// Configure a network from raw SSID bytes and passphrase.
    pub fn passphrase_bytes(ssid: impl Into<Vec<u8>>, passphrase: impl Into<String>) -> Self {
        Self {
            ssid: ssid.into(),
            passphrase: Some(passphrase.into()),
            pmk: None,
        }
    }

    /// Configure a network from raw SSID bytes and a pre-derived PMK.
    pub fn pmk(ssid: impl Into<Vec<u8>>, pmk: [u8; 32]) -> Self {
        Self {
            ssid: ssid.into(),
            passphrase: None,
            pmk: Some(pmk),
        }
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
        self.passphrase.as_deref()
    }

    /// Configured pre-derived PMK, when supplied by the caller.
    pub const fn pmk_value(&self) -> Option<[u8; 32]> {
        self.pmk
    }
}
