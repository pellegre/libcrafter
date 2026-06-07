//! WPA decryptor packet transform.

use super::{WpaDecryptConfig, WpaNetwork};
use crate::wire::record::PacketRecord;
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::Result;

/// Passive WPA/WPA2-Personal decryptor transform.
///
/// This skeleton implements the public transform shape without changing packet
/// behavior. It currently emits each input record unchanged and does not append
/// WPA metadata. Later steps will use the same `PacketTransform` contract to
/// observe handshakes and emit decrypted packet records.
#[derive(Debug, Clone, Default)]
pub struct WpaDecrypt {
    config: WpaDecryptConfig,
    networks: Vec<WpaNetwork>,
    input_count: usize,
    emitted_count: usize,
}

impl WpaDecrypt {
    /// Create a WPA decryptor transform with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the decryptor configuration.
    pub fn with_config(mut self, config: WpaDecryptConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a configured network from a UTF-8 SSID and passphrase.
    pub fn network(mut self, ssid: impl Into<String>, passphrase: impl Into<String>) -> Self {
        self.networks.push(WpaNetwork::passphrase(ssid, passphrase));
        self
    }

    /// Add a configured network from raw SSID bytes and passphrase.
    pub fn network_bytes(
        mut self,
        ssid: impl Into<Vec<u8>>,
        passphrase: impl Into<String>,
    ) -> Self {
        self.networks
            .push(WpaNetwork::passphrase_bytes(ssid, passphrase));
        self
    }

    /// Borrow the current configuration.
    pub const fn config(&self) -> &WpaDecryptConfig {
        &self.config
    }

    /// Configured networks in insertion order.
    pub fn networks(&self) -> &[WpaNetwork] {
        &self.networks
    }

    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records successfully emitted.
    pub const fn emitted_count(&self) -> usize {
        self.emitted_count
    }

    /// Run the transform and collect emitted records into a small buffer.
    pub fn decrypt_record(&mut self, record: PacketRecord) -> Result<TransformOutput> {
        self.transform_to_output(record)
    }
}

impl PacketTransform for WpaDecrypt {
    fn name(&self) -> &'static str {
        "wpa-decrypt"
    }

    fn transform(
        &mut self,
        record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.input_count += 1;
        emit(record)?;
        self.emitted_count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{BackendKind, PacketOrigin};
    use crate::Raw;

    fn record(payload: &'static str) -> PacketRecord {
        PacketRecord::new(Raw::from(payload))
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
    }

    #[test]
    fn wpa_decrypt_skeleton_passes_records_unchanged() {
        let input = record("payload");
        let mut transform = WpaDecrypt::new();

        let output = transform.decrypt_record(input).unwrap();

        assert_eq!(transform.name(), "wpa-decrypt");
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 1);
        assert_eq!(output.len(), 1);
        assert_eq!(output.records()[0].packet().summary(), "Raw(len=7)");
        assert_eq!(
            output.records()[0].metadata().origin(),
            PacketOrigin::Generated
        );
        assert_eq!(
            output.records()[0].metadata().backend(),
            &BackendKind::Memory
        );
    }

    #[test]
    fn wpa_decrypt_skeleton_keeps_configured_networks() {
        let transform = WpaDecrypt::new()
            .network("lab", "passphrase")
            .network_bytes(b"\xffssid".to_vec(), "other");

        assert_eq!(transform.networks().len(), 2);
        assert_eq!(transform.networks()[0].ssid(), b"lab");
        assert_eq!(
            transform.networks()[0].passphrase_value(),
            Some("passphrase")
        );
        assert_eq!(transform.networks()[1].ssid(), b"\xffssid");
    }
}
