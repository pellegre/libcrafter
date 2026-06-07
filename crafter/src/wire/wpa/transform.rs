//! WPA decryptor packet transform.

use std::collections::HashMap;

use super::metadata::{
    WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecryptReason, WpaHandshakeStatus, WpaMetadata,
};
use super::state::ObservedBss;
use super::{WpaDecryptConfig, WpaNetwork};
use crate::wire::record::{PacketRecord, TransformTrace, WifiDecryptState, WifiMetadata};
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::Result as WireResult;
use crate::Result as CrafterResult;
use crate::{
    Dot11, Eapol, EapolKey, LlcSnap, MacAddr, Packet, DOT11_TAG_DS_PARAMETER_SET, DOT11_TAG_RSN,
    DOT11_TAG_SSID,
};

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
    bsses: HashMap<MacAddr, ObservedBss>,
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

    /// Add a pre-built configured network.
    pub fn with_network(mut self, network: WpaNetwork) -> Self {
        self.networks.push(network);
        self
    }

    /// Add a configured network from a UTF-8 SSID and passphrase.
    pub fn network(
        self,
        ssid: impl AsRef<str>,
        passphrase: impl Into<String>,
    ) -> CrafterResult<Self> {
        Ok(self.with_network(WpaNetwork::passphrase(ssid, passphrase)?))
    }

    /// Add a configured network from raw SSID bytes and passphrase.
    pub fn network_bytes(
        self,
        ssid: impl AsRef<[u8]>,
        passphrase: impl Into<String>,
    ) -> CrafterResult<Self> {
        Ok(self.with_network(WpaNetwork::passphrase_bytes(ssid, passphrase)?))
    }

    /// Borrow the current configuration.
    pub const fn config(&self) -> &WpaDecryptConfig {
        &self.config
    }

    /// Configured networks in insertion order.
    pub fn networks(&self) -> &[WpaNetwork] {
        &self.networks
    }

    pub(crate) fn observed_bss(&self, bssid: MacAddr) -> Option<&ObservedBss> {
        self.bsses.get(&bssid)
    }

    pub(crate) fn observed_bsses(&self) -> &HashMap<MacAddr, ObservedBss> {
        &self.bsses
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
    pub fn decrypt_record(&mut self, record: PacketRecord) -> WireResult<TransformOutput> {
        self.transform_to_output(record)
    }

    fn observe_and_annotate(
        &mut self,
        packet: &Packet,
        existing: Option<WifiMetadata>,
    ) -> Option<WifiMetadata> {
        let dot11 = packet.layer::<Dot11>()?;
        let mut wifi = existing.unwrap_or_default();

        if let Some(bssid) = dot11.bssid() {
            wifi = wifi.with_bssid(bssid);
        }
        if let Some(transmitter) = dot11.transmitter() {
            wifi = wifi.with_transmitter(transmitter);
        }
        if let Some(receiver) = dot11.receiver() {
            wifi = wifi.with_receiver(receiver);
        }

        let protected = dot11.is_protected();
        wifi = wifi.with_protected(protected);

        let mut ssid = wifi.ssid().map(<[u8]>::to_vec);
        let mut channel = wifi.channel();
        let mut malformed_rsn = false;
        let mut rsn = None;

        for tag in dot11.tagged_parameters() {
            match tag.id() {
                DOT11_TAG_SSID => {
                    let value = tag.value().to_vec();
                    wifi = wifi.with_ssid(value.clone());
                    ssid = Some(value);
                }
                DOT11_TAG_DS_PARAMETER_SET => {
                    if let Some(value) = tag.value().first().copied() {
                        let value = u16::from(value);
                        wifi = wifi.with_channel(value);
                        channel = Some(value);
                    }
                }
                DOT11_TAG_RSN => match tag.rsn_information() {
                    Some(Ok(value)) => {
                        rsn = Some(value);
                    }
                    Some(Err(_)) => {
                        malformed_rsn = true;
                    }
                    None => {}
                },
                _ => {}
            }
        }

        let frequency_mhz = wifi.frequency_mhz();
        let bssid = dot11.bssid().or_else(|| wifi.bssid());
        let station = bssid.and_then(|bssid| station_from_dot11(dot11, bssid));
        let eapol_key = packet.layer::<EapolKey>();
        let has_eapol_stack =
            packet.layer::<LlcSnap>().is_some() && packet.layer::<Eapol>().is_some();

        let mut context = WpaObservationContext::default();
        context.bssid = bssid;
        context.station = station;

        if let Some(bssid) = bssid {
            let bss = self
                .bsses
                .entry(bssid)
                .or_insert_with(|| ObservedBss::new(bssid));

            if let Some(ssid) = ssid.as_deref() {
                bss.observe_ssid(ssid);
            }
            if let Some(channel) = channel {
                bss.observe_channel(channel);
            }
            if let Some(frequency_mhz) = frequency_mhz {
                bss.observe_frequency_mhz(frequency_mhz);
            }
            if let Some(rsn) = rsn {
                bss.observe_rsn(rsn);
            }
            if let Some(station) = station {
                bss.observe_station(station);
            }

            if has_eapol_stack {
                if let (Some(transmitter), Some(receiver), Some(key)) =
                    (dot11.transmitter(), dot11.receiver(), eapol_key)
                {
                    if bss.observe_eapol_key(transmitter, receiver, key).is_some() {
                        context.handshake_status = station.and_then(|station| {
                            bss.session(station).map(|session| session.status())
                        });
                    }
                }
            }

            context.ssid = bss.ssid().map(<[u8]>::to_vec);
            context.channel = bss.channel();
            context.frequency_mhz = bss.frequency_mhz();
            context.cipher = bss.cipher();
            context.akm = bss.akm();
            context.decrypt_reason = bss.decrypt_reason();
        }

        if malformed_rsn {
            context.decrypt_reason = Some(WpaDecryptReason::MalformedFrame);
        }
        if context.handshake_status.is_none() && eapol_key.is_some() {
            context.handshake_status = Some(WpaHandshakeStatus::Observing);
        }

        if wifi.ssid().is_none() {
            if let Some(ssid) = context.ssid.as_deref() {
                wifi = wifi.with_ssid(ssid.to_vec());
            }
        }
        if wifi.channel().is_none() {
            if let Some(channel) = context.channel {
                wifi = wifi.with_channel(channel);
            }
        }
        if wifi.frequency_mhz().is_none() {
            if let Some(frequency_mhz) = context.frequency_mhz {
                wifi = wifi.with_frequency_mhz(frequency_mhz);
            }
        }

        let decrypt_reason = context.decrypt_reason.or_else(|| {
            context
                .cipher
                .filter(|cipher| !self.config.supports_cipher(*cipher))
                .map(|_| WpaDecryptReason::UnsupportedCipher)
        });
        let decrypt_reason =
            decrypt_reason.or_else(|| protected.then_some(WpaDecryptReason::WaitingForHandshake));

        wifi = wifi.with_decrypt_state(wifi_decrypt_state(protected, decrypt_reason));
        wifi = wifi.with_wpa_metadata(self.wpa_metadata_from_context(context, decrypt_reason));

        Some(wifi)
    }

    fn wpa_metadata_from_context(
        &self,
        context: WpaObservationContext,
        decrypt_reason: Option<WpaDecryptReason>,
    ) -> WpaMetadata {
        let mut metadata = WpaMetadata::new();

        if let Some(bssid) = context.bssid {
            metadata = metadata.with_bssid(bssid);
        }
        if let Some(station) = context.station {
            metadata = metadata.with_station(station);
        }
        if let Some(cipher) = context.cipher {
            metadata = metadata.with_cipher(cipher);
        }
        if let Some(akm) = context.akm {
            metadata = metadata.with_akm(akm);
        }
        if let Some(handshake_status) = context.handshake_status {
            metadata = metadata.with_handshake_status(handshake_status);
        }
        if let Some(decrypt_reason) = decrypt_reason {
            metadata = metadata.with_decrypt_reason(decrypt_reason);
        } else {
            metadata = metadata.with_decrypt_reason(WpaDecryptReason::NotAttempted);
        }
        if let Some(credential_status) = self.credential_status(context.ssid.as_deref()) {
            metadata = metadata.with_credential_status(credential_status);
        }

        metadata
    }

    fn credential_status(&self, ssid: Option<&[u8]>) -> Option<WpaCredentialStatus> {
        let ssid = ssid?;
        if self.networks.iter().any(|network| network.ssid() == ssid) {
            Some(WpaCredentialStatus::Unknown)
        } else {
            Some(WpaCredentialStatus::NotConfigured)
        }
    }
}

impl PacketTransform for WpaDecrypt {
    fn name(&self) -> &'static str {
        "wpa-decrypt"
    }

    fn transform(
        &mut self,
        mut record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> WireResult<()>,
    ) -> WireResult<()> {
        self.input_count += 1;
        if let Some(wifi) =
            self.observe_and_annotate(record.packet(), record.metadata().wifi().cloned())
        {
            record = record.with_wifi_metadata(wifi);
            record
                .metadata_mut()
                .push_transform_trace(TransformTrace::new(self.name()).with_note("observed"));
        }
        emit(record)?;
        self.emitted_count += 1;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
struct WpaObservationContext {
    bssid: Option<MacAddr>,
    station: Option<MacAddr>,
    ssid: Option<Vec<u8>>,
    channel: Option<u16>,
    frequency_mhz: Option<u32>,
    cipher: Option<WpaCipher>,
    akm: Option<WpaAkm>,
    handshake_status: Option<WpaHandshakeStatus>,
    decrypt_reason: Option<WpaDecryptReason>,
}

fn wifi_decrypt_state(protected: bool, reason: Option<WpaDecryptReason>) -> WifiDecryptState {
    if !protected {
        return WifiDecryptState::NotRequired;
    }

    match reason {
        Some(
            WpaDecryptReason::UnsupportedCipher
            | WpaDecryptReason::UnsupportedAkm
            | WpaDecryptReason::MalformedFrame
            | WpaDecryptReason::MicFailed
            | WpaDecryptReason::AuthenticationFailed,
        ) => WifiDecryptState::Failed,
        Some(WpaDecryptReason::Decrypted) => WifiDecryptState::Decrypted,
        _ => WifiDecryptState::KeyMaterialMissing,
    }
}

fn station_from_dot11(dot11: &Dot11, bssid: MacAddr) -> Option<MacAddr> {
    [
        dot11.source(),
        dot11.destination(),
        dot11.transmitter(),
        dot11.receiver(),
        dot11.addr1_value(),
        dot11.addr2_value(),
        dot11.addr3_value(),
        dot11.addr4_value(),
    ]
    .into_iter()
    .flatten()
    .find(|candidate| is_station_candidate(*candidate, bssid))
}

fn is_station_candidate(candidate: MacAddr, bssid: MacAddr) -> bool {
    candidate != bssid
        && candidate != MacAddr::BROADCAST
        && candidate != MacAddr::ZERO
        && !candidate.is_multicast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{BackendKind, PacketOrigin};
    use crate::{
        Dot11, Eapol, EapolKey, EapolKeyInformation, LlcSnap, MacAddr, RsnInformation,
        RSN_AKM_SUITE_SAE, RSN_CIPHER_SUITE_GCMP_256,
    };
    use crate::{Raw, ETHERTYPE_EAPOL};

    fn record(payload: &'static str) -> PacketRecord {
        PacketRecord::new(Raw::from(payload))
            .with_origin(PacketOrigin::Generated)
            .with_backend(BackendKind::Memory)
    }

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x08, 0x00, last])
    }

    fn message_1(replay_counter: u64) -> EapolKey {
        EapolKey::new()
            .key_information(
                EapolKeyInformation::new()
                    .with_descriptor_version(2)
                    .with_key_type(true)
                    .with_key_ack(true),
            )
            .key_length(16)
            .replay_counter(replay_counter)
            .nonce([0x42; 32])
    }

    fn beacon_with_rsn(
        bssid: MacAddr,
        ssid: impl Into<Vec<u8>>,
        rsn: &RsnInformation,
    ) -> PacketRecord {
        let dot11 = Dot11::beacon()
            .addr1(MacAddr::BROADCAST)
            .addr2(bssid)
            .addr3(bssid)
            .ssid(ssid)
            .ds_parameter_set(11)
            .with_rsn_information(rsn)
            .unwrap();
        PacketRecord::new(dot11)
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
            .unwrap()
            .network_bytes(b"\xffssid".as_slice(), "otherpass")
            .unwrap();

        assert_eq!(transform.networks().len(), 2);
        assert_eq!(transform.networks()[0].ssid(), b"lab");
        assert_eq!(
            transform.networks()[0].passphrase_value(),
            Some("passphrase")
        );
        assert_eq!(transform.networks()[1].ssid(), b"\xffssid");
    }

    #[test]
    fn observes_rsn_bss_metadata_and_preserves_non_utf8_ssid() {
        let bssid = mac(1);
        let ssid = vec![0xff, b'l', b'a', b'b'];
        let mut transform = WpaDecrypt::new();

        let output = transform
            .decrypt_record(beacon_with_rsn(bssid, ssid.clone(), &RsnInformation::new()))
            .unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.observed_bsses().len(), 1);
        let bss = transform.observed_bss(bssid).unwrap();
        assert_eq!(bss.bssid(), bssid);
        assert_eq!(bss.ssid(), Some(ssid.as_slice()));
        assert!(bss.rsn().is_some());
        assert_eq!(bss.channel(), Some(11));
        assert_eq!(bss.cipher(), Some(WpaCipher::Ccmp128));
        assert_eq!(bss.akm(), Some(WpaAkm::Psk));
        assert_eq!(bss.decrypt_reason(), None);

        let record = &output.records()[0];
        assert_eq!(record.metadata().transforms()[0].name(), "wpa-decrypt");
        let wifi = record.metadata().wifi().unwrap();
        assert_eq!(wifi.ssid(), Some(ssid.as_slice()));
        assert_eq!(wifi.ssid_str(), None);
        assert_eq!(wifi.bssid(), Some(bssid));
        assert_eq!(wifi.channel(), Some(11));
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::NotRequired));

        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.bssid(), Some(bssid));
        assert_eq!(wpa.cipher(), Some(WpaCipher::Ccmp128));
        assert_eq!(wpa.akm(), Some(WpaAkm::Psk));
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::NotAttempted));
        assert_eq!(
            wpa.credential_status(),
            Some(WpaCredentialStatus::NotConfigured)
        );
    }

    #[test]
    fn observes_unsupported_akm_as_decrypt_reason() {
        let bssid = mac(2);
        let rsn = RsnInformation::new().with_akm_list([RSN_AKM_SUITE_SAE]);
        let mut transform = WpaDecrypt::new();

        let output = transform
            .decrypt_record(beacon_with_rsn(bssid, b"sae-net".as_slice(), &rsn))
            .unwrap();

        let bss = transform.observed_bss(bssid).unwrap();
        assert_eq!(bss.cipher(), Some(WpaCipher::Ccmp128));
        assert_eq!(bss.akm(), Some(WpaAkm::Sae));
        assert_eq!(bss.decrypt_reason(), Some(WpaDecryptReason::UnsupportedAkm));

        let wpa = output.records()[0]
            .metadata()
            .wifi()
            .unwrap()
            .wpa_metadata()
            .unwrap();
        assert_eq!(wpa.akm(), Some(WpaAkm::Sae));
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::UnsupportedAkm));
    }

    #[test]
    fn observes_unsupported_cipher_as_decrypt_reason() {
        let bssid = mac(3);
        let rsn = RsnInformation::new().with_pairwise_cipher_list([RSN_CIPHER_SUITE_GCMP_256]);
        let mut transform = WpaDecrypt::new();

        let output = transform
            .decrypt_record(beacon_with_rsn(bssid, b"gcmp-net".as_slice(), &rsn))
            .unwrap();

        let bss = transform.observed_bss(bssid).unwrap();
        assert_eq!(bss.cipher(), Some(WpaCipher::Gcmp256));
        assert_eq!(bss.akm(), Some(WpaAkm::Psk));
        assert_eq!(
            bss.decrypt_reason(),
            Some(WpaDecryptReason::UnsupportedCipher)
        );

        let wpa = output.records()[0]
            .metadata()
            .wifi()
            .unwrap()
            .wpa_metadata()
            .unwrap();
        assert_eq!(wpa.cipher(), Some(WpaCipher::Gcmp256));
        assert_eq!(
            wpa.decrypt_reason(),
            Some(WpaDecryptReason::UnsupportedCipher)
        );
    }

    #[test]
    fn observes_eapol_station_and_carries_learned_bss_metadata() {
        let bssid = mac(4);
        let station = mac(0x44);
        let mut transform = WpaDecrypt::new().network("lab", "12345678").unwrap();
        transform
            .decrypt_record(beacon_with_rsn(
                bssid,
                b"lab".as_slice(),
                &RsnInformation::new(),
            ))
            .unwrap();

        let packet = Dot11::data().addr1(station).addr2(bssid).addr3(bssid)
            / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
            / Eapol::key()
            / message_1(7);
        let output = transform.decrypt_record(PacketRecord::new(packet)).unwrap();

        let bss = transform.observed_bss(bssid).unwrap();
        assert!(bss.stations().contains(&station));
        let session = bss.session(station).unwrap();
        assert_eq!(session.message_1().replay_counter(), Some(7));
        assert_eq!(session.status(), WpaHandshakeStatus::Observing);

        let wifi = output.records()[0].metadata().wifi().unwrap();
        assert_eq!(wifi.ssid(), Some(b"lab".as_slice()));
        assert_eq!(wifi.bssid(), Some(bssid));
        assert_eq!(wifi.transmitter(), Some(bssid));
        assert_eq!(wifi.receiver(), Some(station));

        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.bssid(), Some(bssid));
        assert_eq!(wpa.station(), Some(station));
        assert_eq!(wpa.cipher(), Some(WpaCipher::Ccmp128));
        assert_eq!(wpa.akm(), Some(WpaAkm::Psk));
        assert_eq!(wpa.handshake_status(), Some(WpaHandshakeStatus::Observing));
        assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Unknown));
    }
}
