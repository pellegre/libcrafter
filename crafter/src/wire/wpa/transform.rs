//! WPA decryptor packet transform.

use std::collections::HashMap;

use super::ccmp::{decrypt_group, decrypt_unicast, CcmpDecryptResult, CcmpHeader};
use super::crypto::Pmk;
use super::metadata::{
    WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecryptReason, WpaHandshakeStatus, WpaKeyKind,
    WpaMetadata,
};
use super::state::{GroupKeyReadiness, ObservedBss, PairwiseSession};
use super::{WpaDecryptConfig, WpaNetwork};
use crate::wire::record::{
    PacketMetadata, PacketOrigin, PacketRecord, TransformTrace, WifiDecryptState, WifiMetadata,
};
use crate::wire::transform::{PacketTransform, TransformOutput};
use crate::wire::Result as WireResult;
use crate::Result as CrafterResult;
use crate::{
    Dot11, Eapol, EapolKey, Ethernet, LinkType, LlcSnap, MacAddr, Packet, Raw,
    DOT11_TAG_DS_PARAMETER_SET, DOT11_TAG_RSN, DOT11_TAG_SSID,
};

/// Passive WPA/WPA2-Personal decryptor transform.
#[derive(Debug, Clone, Default)]
pub struct WpaDecrypt {
    config: WpaDecryptConfig,
    networks: Vec<WpaNetwork>,
    bsses: HashMap<MacAddr, ObservedBss>,
    pairwise_packet_numbers: HashMap<PairwiseReplayKey, u64>,
    group_packet_numbers: HashMap<GroupReplayKey, u64>,
    input_count: usize,
    emitted_count: usize,
    observed_handshake_count: usize,
    decrypted_count: usize,
    failed_count: usize,
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

    #[cfg(test)]
    pub(crate) fn observed_bss(&self, bssid: MacAddr) -> Option<&ObservedBss> {
        self.bsses.get(&bssid)
    }

    #[cfg(test)]
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

    /// Number of accepted EAPOL-Key handshake records observed.
    pub const fn observed_handshake_count(&self) -> usize {
        self.observed_handshake_count
    }

    /// Number of pairwise sessions with verified key material.
    pub fn verified_session_count(&self) -> usize {
        self.bsses
            .values()
            .flat_map(|bss| bss.pairwise_sessions().values())
            .filter(|session| session.is_ready())
            .count()
    }

    /// Number of protected records successfully decrypted.
    pub const fn decrypted_count(&self) -> usize {
        self.decrypted_count
    }

    /// Number of protected records that could not be decrypted.
    pub const fn failed_count(&self) -> usize {
        self.failed_count
    }

    /// Run the transform and collect emitted records into a small buffer.
    pub fn decrypt_record(&mut self, record: PacketRecord) -> WireResult<TransformOutput> {
        self.transform_to_output(record)
    }

    fn matching_pmks_for_ssid(&self, ssid: Option<&[u8]>) -> Vec<Pmk> {
        let Some(ssid) = ssid else {
            return Vec::new();
        };

        self.networks
            .iter()
            .filter(|network| network.ssid() == ssid)
            .map(|network| network.cached_pmk().clone())
            .collect()
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
        let matching_pmks =
            self.matching_pmks_for_ssid(ssid.as_deref().or_else(|| {
                bssid.and_then(|bssid| self.bsses.get(&bssid).and_then(|bss| bss.ssid()))
            }));
        let eapol_frame = has_eapol_stack
            .then(|| compile_eapol_frame(packet))
            .flatten();

        let mut context = WpaObservationContext {
            bssid,
            station,
            ..Default::default()
        };

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
                    if let Some(observation) = bss.observe_eapol_key(transmitter, receiver, key) {
                        if observation.accepted() && observation.message().is_known() {
                            self.observed_handshake_count += 1;
                        }

                        if let (Some(station), Some(eapol_frame)) =
                            (station, eapol_frame.as_deref())
                        {
                            for pmk in &matching_pmks {
                                if bss
                                    .verify_pairwise_key_mic(station, key, eapol_frame, pmk)
                                    .is_err()
                                {
                                    context.decrypt_reason = Some(WpaDecryptReason::MalformedFrame);
                                    break;
                                }
                                if bss
                                    .session(station)
                                    .map(PairwiseSession::is_ready)
                                    .unwrap_or(false)
                                {
                                    break;
                                }
                            }
                        }

                        if let Some(session) = station.and_then(|station| bss.session(station)) {
                            apply_pairwise_session_context(&mut context, session);
                        }
                    }
                }
            }

            if let Some(session) = station.and_then(|station| bss.session(station)) {
                apply_pairwise_session_context(&mut context, session);
            }

            context.ssid = bss.ssid().map(<[u8]>::to_vec);
            context.channel = bss.channel();
            context.frequency_mhz = bss.frequency_mhz();
            context.cipher = bss.cipher();
            context.akm = bss.akm();
            context.decrypt_reason = context.decrypt_reason.or_else(|| bss.decrypt_reason());
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
            metadata = metadata
                .with_credential_status(context.credential_status.unwrap_or(credential_status));
        } else if let Some(credential_status) = context.credential_status {
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

    fn try_decrypt_unicast(&mut self, record: &PacketRecord) -> Option<WpaDecryptAttempt> {
        let dot11 = record.packet().layer::<Dot11>()?;
        if !dot11.is_protected() {
            return None;
        }

        let encrypted_body = record.packet().layer::<Raw>()?.as_bytes();
        let bssid = dot11.bssid()?;
        let station = station_from_dot11(dot11, bssid)?;
        let bss = self.bsses.get(&bssid)?;
        let session = bss.session(station)?;
        let ptk = session.pairwise_transient_key()?;

        let header = CcmpHeader::parse(encrypted_body).ok();
        let last_packet_number = header.as_ref().and_then(|header| {
            self.pairwise_packet_numbers
                .get(&PairwiseReplayKey::new(bssid, station, header.key_id()))
                .copied()
        });
        let result = decrypt_unicast(
            dot11,
            encrypted_body,
            ptk.temporal_key(),
            last_packet_number,
        );

        let decrypted_packet = result
            .plaintext()
            .map(|plaintext| decode_decrypted_plaintext(dot11, plaintext));
        if result.is_decrypted() {
            if let (Some(packet_number), Some(key_id)) = (result.packet_number(), result.key_id()) {
                self.pairwise_packet_numbers.insert(
                    PairwiseReplayKey::new(bssid, station, key_id),
                    packet_number,
                );
            }
        }

        Some(WpaDecryptAttempt {
            result,
            decrypted_packet,
            credential_status: session.credential_status(),
            handshake_status: if session.is_ready() {
                WpaHandshakeStatus::MicVerified
            } else {
                session.status()
            },
        })
    }

    fn try_decrypt_group(&mut self, record: &PacketRecord) -> Option<WpaDecryptAttempt> {
        let dot11 = record.packet().layer::<Dot11>()?;
        if !dot11.is_protected() {
            return None;
        }

        let encrypted_body = record.packet().layer::<Raw>()?.as_bytes();
        let bssid = dot11.bssid()?;
        let header = CcmpHeader::parse(encrypted_body).ok()?;
        let key_kind = header
            .key_kind_for_dot11(dot11)
            .unwrap_or(WpaKeyKind::Unknown);
        if key_kind != WpaKeyKind::Group {
            return None;
        }

        let packet_number = header.packet_number();
        let key_id = header.key_id();
        let last_packet_number = self
            .group_packet_numbers
            .get(&GroupReplayKey::new(bssid, key_id))
            .copied();

        let bss = self.bsses.get(&bssid)?;
        let (credential_status, handshake_status) = bss_pairwise_status(bss);
        let result = if bss
            .group_cipher()
            .map(|cipher| cipher != WpaCipher::Ccmp128)
            .unwrap_or(false)
        {
            CcmpDecryptResult::failed(
                Some(packet_number),
                Some(key_id),
                Some(key_kind),
                WpaDecryptReason::UnsupportedCipher,
            )
        } else if let Some(gtk) = bss.gtk(key_id) {
            decrypt_group(dot11, encrypted_body, gtk.bytes(), last_packet_number)
        } else {
            CcmpDecryptResult::failed(
                Some(packet_number),
                Some(key_id),
                Some(key_kind),
                group_key_missing_reason(bss),
            )
        };

        let decrypted_packet = result
            .plaintext()
            .map(|plaintext| decode_decrypted_plaintext(dot11, plaintext));
        if result.is_decrypted() {
            if let (Some(packet_number), Some(key_id)) = (result.packet_number(), result.key_id()) {
                self.group_packet_numbers
                    .insert(GroupReplayKey::new(bssid, key_id), packet_number);
            }
        }

        Some(WpaDecryptAttempt {
            result,
            decrypted_packet,
            credential_status,
            handshake_status,
        })
    }

    fn record_with_attempt_metadata(
        &self,
        mut record: PacketRecord,
        attempt: &WpaDecryptAttempt,
    ) -> PacketRecord {
        let wifi = record.metadata().wifi().cloned().unwrap_or_default();
        record = record.with_wifi_metadata(wifi_with_decrypt_result(
            wifi,
            &attempt.result,
            attempt.credential_status,
            attempt.handshake_status,
        ));
        record
    }

    fn decrypted_record(
        &self,
        source_metadata: &PacketMetadata,
        decrypted_packet: Packet,
        attempt: &WpaDecryptAttempt,
    ) -> PacketRecord {
        let wifi = source_metadata.wifi().cloned().unwrap_or_default();
        let metadata = source_metadata
            .clone()
            .with_origin(PacketOrigin::Transformed)
            .with_link_type(LinkType::Ethernet)
            .with_wifi_metadata(wifi_with_decrypt_result(
                wifi,
                &attempt.result,
                attempt.credential_status,
                attempt.handshake_status,
            ))
            .with_transform_trace(TransformTrace::new(self.name()).with_note("decrypted"));

        PacketRecord::from_packet_metadata(decrypted_packet, metadata)
    }

    fn should_emit_original(&self, record: &PacketRecord) -> bool {
        if self.config.emits_originals() {
            return true;
        }

        let Some(dot11) = record.packet().layer::<Dot11>() else {
            return true;
        };

        !dot11.is_protected() && !is_eapol_key_record(record)
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

        let attempt = self
            .try_decrypt_group(&record)
            .or_else(|| self.try_decrypt_unicast(&record));
        if let Some(attempt) = attempt {
            record = self.record_with_attempt_metadata(record, &attempt);
            if let Some(decrypted_packet) = attempt.decrypted_packet.clone() {
                let decrypted =
                    self.decrypted_record(record.metadata(), decrypted_packet, &attempt);
                emit(decrypted)?;
                self.emitted_count += 1;
                self.decrypted_count += 1;
            } else {
                self.failed_count += 1;
            }
            if self.should_emit_original(&record) {
                emit(record)?;
                self.emitted_count += 1;
            }
            return Ok(());
        }

        if is_protected_dot11_record(&record) {
            self.failed_count += 1;
        }

        if self.should_emit_original(&record) {
            emit(record)?;
            self.emitted_count += 1;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct WpaDecryptAttempt {
    result: CcmpDecryptResult,
    decrypted_packet: Option<Packet>,
    credential_status: WpaCredentialStatus,
    handshake_status: WpaHandshakeStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PairwiseReplayKey {
    bssid: MacAddr,
    station: MacAddr,
    key_id: u8,
}

impl PairwiseReplayKey {
    const fn new(bssid: MacAddr, station: MacAddr, key_id: u8) -> Self {
        Self {
            bssid,
            station,
            key_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GroupReplayKey {
    bssid: MacAddr,
    key_id: u8,
}

impl GroupReplayKey {
    const fn new(bssid: MacAddr, key_id: u8) -> Self {
        Self { bssid, key_id }
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
    credential_status: Option<WpaCredentialStatus>,
    decrypt_reason: Option<WpaDecryptReason>,
}

fn visible_handshake_status(session: &PairwiseSession) -> WpaHandshakeStatus {
    if session.is_ready() {
        WpaHandshakeStatus::MicVerified
    } else if session.credential_status() == WpaCredentialStatus::Mismatch {
        WpaHandshakeStatus::Failed
    } else {
        session.status()
    }
}

fn apply_pairwise_session_context(context: &mut WpaObservationContext, session: &PairwiseSession) {
    context.handshake_status = Some(visible_handshake_status(session));
    context.credential_status = Some(session.credential_status());
    if session.credential_status() == WpaCredentialStatus::Mismatch {
        context.decrypt_reason = Some(WpaDecryptReason::MicFailed);
    }
}

fn compile_eapol_frame(packet: &Packet) -> Option<Vec<u8>> {
    let eapol = packet.layer::<Eapol>()?;
    let key = packet.layer::<EapolKey>()?;

    (eapol.clone() / key.clone())
        .compile()
        .ok()
        .map(|compiled| compiled.into_bytes())
}

fn is_protected_dot11_record(record: &PacketRecord) -> bool {
    record
        .packet()
        .layer::<Dot11>()
        .map(Dot11::is_protected)
        .unwrap_or(false)
}

fn is_eapol_key_record(record: &PacketRecord) -> bool {
    record.packet().layer::<EapolKey>().is_some()
}

fn group_key_missing_reason(bss: &ObservedBss) -> WpaDecryptReason {
    match bss.group_key_state().readiness() {
        GroupKeyReadiness::Unavailable(reason) => reason,
        GroupKeyReadiness::Unknown | GroupKeyReadiness::Available => {
            WpaDecryptReason::MissingKeyMaterial
        }
    }
}

fn bss_pairwise_status(bss: &ObservedBss) -> (WpaCredentialStatus, WpaHandshakeStatus) {
    let mut saw_observing = false;
    let mut saw_complete = false;
    let mut saw_mismatch = false;

    for session in bss.pairwise_sessions().values() {
        if session.is_ready() {
            return (
                WpaCredentialStatus::Matched,
                WpaHandshakeStatus::MicVerified,
            );
        }

        if session.credential_status() == WpaCredentialStatus::Mismatch {
            saw_mismatch = true;
        }
        match session.status() {
            WpaHandshakeStatus::Complete => saw_complete = true,
            WpaHandshakeStatus::Observing => saw_observing = true,
            _ => {}
        }
    }

    if saw_mismatch {
        (WpaCredentialStatus::Mismatch, WpaHandshakeStatus::Failed)
    } else if saw_complete {
        (WpaCredentialStatus::Unknown, WpaHandshakeStatus::Complete)
    } else if saw_observing {
        (WpaCredentialStatus::Unknown, WpaHandshakeStatus::Observing)
    } else {
        (WpaCredentialStatus::Unknown, WpaHandshakeStatus::NotStarted)
    }
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
            | WpaDecryptReason::AuthenticationFailed
            | WpaDecryptReason::ReplayDetected,
        ) => WifiDecryptState::Failed,
        Some(WpaDecryptReason::Decrypted) => WifiDecryptState::Decrypted,
        _ => WifiDecryptState::KeyMaterialMissing,
    }
}

fn wifi_with_decrypt_result(
    mut wifi: WifiMetadata,
    result: &CcmpDecryptResult,
    credential_status: WpaCredentialStatus,
    handshake_status: WpaHandshakeStatus,
) -> WifiMetadata {
    if let Some(key_id) = result.key_id() {
        wifi = wifi.with_key_id(key_id);
    }

    let reason = result
        .failure_reason()
        .unwrap_or(WpaDecryptReason::Decrypted);
    wifi = wifi.with_decrypt_state(wifi_decrypt_state(true, Some(reason)));

    let mut metadata = wifi.wpa_metadata().cloned().unwrap_or_default();
    metadata = metadata
        .with_decrypt_reason(reason)
        .with_credential_status(credential_status)
        .with_handshake_status(handshake_status);
    if let Some(key_kind) = result.key_kind() {
        metadata = metadata.with_key_kind(key_kind);
    }
    if let Some(key_id) = result.key_id() {
        metadata = metadata.with_key_id(key_id);
    }
    if let Some(packet_number) = result.packet_number() {
        metadata = metadata.with_packet_number(packet_number);
    }

    wifi.with_wpa_metadata(metadata)
}

fn decode_decrypted_plaintext(dot11: &Dot11, plaintext: &[u8]) -> Packet {
    if let Some((ethertype, payload)) = plaintext_llc_snap(plaintext) {
        if let (Some(source), Some(destination)) = (dot11.source(), dot11.destination()) {
            let mut ethernet_bytes = Vec::with_capacity(14 + payload.len());
            ethernet_bytes.extend_from_slice(&destination.octets());
            ethernet_bytes.extend_from_slice(&source.octets());
            ethernet_bytes.extend_from_slice(&ethertype.to_be_bytes());
            ethernet_bytes.extend_from_slice(payload);

            return Packet::decode_from_link(LinkType::Ethernet, &ethernet_bytes).unwrap_or_else(
                |_| {
                    Ethernet::with_addresses(source, destination).ethertype(ethertype)
                        / Raw::from_bytes(payload)
                },
            );
        }
    }

    Packet::decode_raw(plaintext).expect("raw packet decode is infallible")
}

fn plaintext_llc_snap(plaintext: &[u8]) -> Option<(u16, &[u8])> {
    if plaintext.len() < 8 {
        return None;
    }

    let snap = LlcSnap::new();
    let is_rfc1042 = plaintext[0] == snap.dsap_value()
        && plaintext[1] == snap.ssap_value()
        && plaintext[2] == snap.control_value()
        && plaintext[3..6] == snap.oui_value();
    if !is_rfc1042 {
        return None;
    }

    Some((
        u16::from_be_bytes([plaintext[6], plaintext[7]]),
        &plaintext[8..],
    ))
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
    use super::super::ccmp::encrypt_unicast_for_tests;
    use super::super::crypto::{
        derive_pmk, derive_ptk, wrap_key_data_for_tests, PairwiseTransientKey, Pmk, WPA_PMK_LEN,
        WPA_PTK_TEMPORAL_KEY_LEN,
    };
    use super::*;
    use core::net::Ipv4Addr;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    use std::path::{Path, PathBuf};

    use crate::wire::{BackendKind, Dot11Metadata, PacketOrigin, PacketWire, Sniffer};
    use crate::{
        Dot11, Dot11SequenceControl, Eapol, EapolKey, EapolKeyInformation, Ethernet, Ipv4,
        LinkType, LlcSnap, MacAddr, RsnInformation, RSN_AKM_SUITE_SAE, RSN_CIPHER_SUITE_GCMP_256,
        RSN_CIPHER_SUITE_TKIP,
    };
    use crate::{Raw, WpaKeyKind, EAPOL_HEADER_LEN, ETHERTYPE_EAPOL, ETHERTYPE_IPV4};

    type HmacSha1 = Hmac<Sha1>;

    const EAPOL_KEY_MIC_OFFSET_FROM_EAPOL: usize = EAPOL_HEADER_LEN + 77;
    const EAPOL_KEY_MIC_LEN: usize = 16;
    const WPA_KEY_DATA_VENDOR_SPECIFIC_ELEMENT_ID: u8 = 0xdd;
    const WPA_KEY_DATA_RSN_OUI: [u8; 3] = [0x00, 0x0f, 0xac];
    const WPA_KEY_DATA_GTK_KDE_TYPE: u8 = 1;
    const WPA_GTK_KEY_ID_MASK: u8 = 0x03;

    #[derive(Debug, Clone, Copy)]
    struct MultiNetworkFixture {
        ssid: &'static [u8],
        passphrase: &'static str,
        bssid: MacAddr,
        station: MacAddr,
        peer: MacAddr,
        ap_nonce: [u8; 32],
        station_nonce: [u8; 32],
        replay_counter: u64,
    }

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

    fn pairwise_message_1(replay_counter: u64, nonce: [u8; 32]) -> EapolKey {
        EapolKey::new()
            .key_information(
                EapolKeyInformation::new()
                    .with_descriptor_version(2)
                    .with_key_type(true)
                    .with_key_ack(true),
            )
            .key_length(16)
            .replay_counter(replay_counter)
            .nonce(nonce)
    }

    fn pairwise_message_2(replay_counter: u64, nonce: [u8; 32]) -> EapolKey {
        EapolKey::new()
            .key_information(
                EapolKeyInformation::new()
                    .with_descriptor_version(2)
                    .with_key_type(true)
                    .with_key_mic(true),
            )
            .key_length(16)
            .replay_counter(replay_counter)
            .nonce(nonce)
            .mic([0; EAPOL_KEY_MIC_LEN])
            .key_data([0x30, 0x14])
    }

    fn pairwise_message_3(
        replay_counter: u64,
        nonce: [u8; 32],
        encrypted_key_data: impl Into<Vec<u8>>,
    ) -> EapolKey {
        EapolKey::new()
            .key_information(
                EapolKeyInformation::new()
                    .with_descriptor_version(2)
                    .with_key_type(true)
                    .with_key_ack(true)
                    .with_key_mic(true)
                    .with_install(true)
                    .with_secure(true)
                    .with_encrypted_key_data(true),
            )
            .key_length(16)
            .replay_counter(replay_counter)
            .nonce(nonce)
            .mic([0; EAPOL_KEY_MIC_LEN])
            .key_data(encrypted_key_data)
    }

    fn signed_eapol_key(
        key: EapolKey,
        pairwise_transient_key: &PairwiseTransientKey,
    ) -> (EapolKey, Vec<u8>) {
        let zeroed_key = key.clone().mic([0; EAPOL_KEY_MIC_LEN]);
        let zeroed_frame = compile_eapol_key(&zeroed_key);
        let mic = eapol_mic(pairwise_transient_key.kck(), &zeroed_frame);
        let signed_key = key.mic(mic);
        let signed_frame = compile_eapol_key(&signed_key);
        (signed_key, signed_frame)
    }

    fn compile_eapol_key(key: &EapolKey) -> Vec<u8> {
        (Eapol::key() / key.clone())
            .compile()
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn eapol_mic(kck: &[u8; 16], frame: &[u8]) -> [u8; EAPOL_KEY_MIC_LEN] {
        let mut input = frame.to_vec();
        input[EAPOL_KEY_MIC_OFFSET_FROM_EAPOL..EAPOL_KEY_MIC_OFFSET_FROM_EAPOL + EAPOL_KEY_MIC_LEN]
            .fill(0);

        let mut mac = HmacSha1::new_from_slice(kck).unwrap();
        mac.update(&input);
        let digest = mac.finalize().into_bytes();
        let mut mic = [0u8; EAPOL_KEY_MIC_LEN];
        mic.copy_from_slice(&digest[..EAPOL_KEY_MIC_LEN]);
        mic
    }

    fn verified_unicast_transform() -> (WpaDecrypt, MacAddr, MacAddr, MacAddr, PairwiseTransientKey)
    {
        verified_unicast_transform_with_originals(false)
    }

    fn verified_unicast_transform_with_originals(
        pass_originals: bool,
    ) -> (WpaDecrypt, MacAddr, MacAddr, MacAddr, PairwiseTransientKey) {
        let bssid = mac(0x70);
        let station = mac(0x71);
        let peer = mac(0x72);
        let pmk = Pmk::new([0x61; WPA_PMK_LEN]);
        let ap_nonce = [0x10; 32];
        let station_nonce = [0x20; 32];
        let mut bss = ObservedBss::new(bssid);
        bss.observe_ssid(b"lab");
        bss.observe_rsn(RsnInformation::new());
        bss.observe_pairwise_key(station, bssid, station, &pairwise_message_1(1, ap_nonce));

        let ptk = derive_ptk(
            &pmk,
            &bssid.octets(),
            &station.octets(),
            &ap_nonce,
            &station_nonce,
        );
        let (message_2, eapol_frame) = signed_eapol_key(pairwise_message_2(1, station_nonce), &ptk);
        bss.observe_pairwise_key_with_mic(station, station, bssid, &message_2, &eapol_frame, &pmk)
            .unwrap();
        assert!(bss.session(station).unwrap().is_ready());

        let mut transform =
            WpaDecrypt::new().with_config(WpaDecryptConfig::new().pass_originals(pass_originals));
        transform.bsses.insert(bssid, bss);
        (transform, bssid, station, peer, ptk)
    }

    fn verified_group_transform(
        pass_originals: bool,
        gtk: Option<(u8, [u8; WPA_PTK_TEMPORAL_KEY_LEN])>,
    ) -> (
        WpaDecrypt,
        MacAddr,
        MacAddr,
        MacAddr,
        Pmk,
        PairwiseTransientKey,
    ) {
        let bssid = mac(0x80);
        let station = mac(0x81);
        let source = mac(0x82);
        let pmk = Pmk::new([0x62; WPA_PMK_LEN]);
        let ap_nonce = [0x30; 32];
        let station_nonce = [0x40; 32];
        let mut bss = ObservedBss::new(bssid);
        bss.observe_ssid(b"group-lab");
        bss.observe_rsn(RsnInformation::new());
        bss.observe_pairwise_key(station, bssid, station, &pairwise_message_1(1, ap_nonce));

        let ptk = derive_ptk(
            &pmk,
            &bssid.octets(),
            &station.octets(),
            &ap_nonce,
            &station_nonce,
        );
        let (message_2, eapol_frame) = signed_eapol_key(pairwise_message_2(1, station_nonce), &ptk);
        bss.observe_pairwise_key_with_mic(station, station, bssid, &message_2, &eapol_frame, &pmk)
            .unwrap();

        if let Some((key_id, gtk)) = gtk {
            install_group_key_data(&mut bss, bssid, station, &pmk, &ptk, gtk_kde(key_id, gtk));
        }

        let mut transform =
            WpaDecrypt::new().with_config(WpaDecryptConfig::new().pass_originals(pass_originals));
        transform.bsses.insert(bssid, bss);
        (transform, bssid, station, source, pmk, ptk)
    }

    fn install_group_key_data(
        bss: &mut ObservedBss,
        bssid: MacAddr,
        station: MacAddr,
        pmk: &Pmk,
        ptk: &PairwiseTransientKey,
        key_data: impl Into<Vec<u8>>,
    ) {
        let encrypted_key_data = wrap_key_data_for_tests(ptk.kek(), pad_key_data(key_data));
        let (message_3, eapol_frame) =
            signed_eapol_key(pairwise_message_3(2, [0x30; 32], encrypted_key_data), ptk);
        bss.observe_pairwise_key_with_mic(station, bssid, station, &message_3, &eapol_frame, pmk)
            .unwrap();
    }

    fn pad_key_data(key_data: impl Into<Vec<u8>>) -> Vec<u8> {
        let mut key_data = key_data.into();
        while key_data.len() % 8 != 0 {
            key_data.push(0);
        }
        key_data
    }

    fn gtk_kde(key_id: u8, gtk: impl AsRef<[u8]>) -> Vec<u8> {
        let gtk = gtk.as_ref();
        let kde_len = 5 + gtk.len();
        assert!(kde_len <= u8::MAX as usize);

        let mut key_data = Vec::with_capacity(2 + kde_len);
        key_data.push(WPA_KEY_DATA_VENDOR_SPECIFIC_ELEMENT_ID);
        key_data.push(kde_len as u8);
        key_data.extend_from_slice(&WPA_KEY_DATA_RSN_OUI);
        key_data.push(WPA_KEY_DATA_GTK_KDE_TYPE);
        key_data.push(key_id & WPA_GTK_KEY_ID_MASK);
        key_data.extend_from_slice(gtk);
        key_data
    }

    fn protected_to_ds_data(bssid: MacAddr, station: MacAddr, destination: MacAddr) -> Dot11 {
        let frame_control = Dot11::data()
            .frame_control_value()
            .with_to_ds(true)
            .with_protected(true);
        Dot11::data()
            .frame_control(frame_control)
            .addr1(bssid)
            .addr2(station)
            .addr3(destination)
            .sequence_control(Dot11SequenceControl::new().with_sequence_number(0x123))
    }

    fn protected_from_ds_group_data(
        bssid: MacAddr,
        source: MacAddr,
        destination: MacAddr,
    ) -> Dot11 {
        let frame_control = Dot11::data()
            .frame_control_value()
            .with_from_ds(true)
            .with_protected(true);
        Dot11::data()
            .frame_control(frame_control)
            .addr1(destination)
            .addr2(bssid)
            .addr3(source)
            .sequence_control(Dot11SequenceControl::new().with_sequence_number(0x456))
    }

    fn ipv4_plaintext(payload: impl Into<Vec<u8>>) -> Vec<u8> {
        (LlcSnap::new().ethertype(ETHERTYPE_IPV4)
            / Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Raw::from_bytes(payload.into()))
        .compile()
        .unwrap()
        .into_bytes()
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

    fn multi_network_fixture(
        ssid: &'static [u8],
        passphrase: &'static str,
        suffix: u8,
        nonce: u8,
        replay_counter: u64,
    ) -> MultiNetworkFixture {
        MultiNetworkFixture {
            ssid,
            passphrase,
            bssid: mac(suffix),
            station: mac(suffix + 1),
            peer: mac(suffix + 2),
            ap_nonce: [nonce; 32],
            station_nonce: [nonce.wrapping_add(0x40); 32],
            replay_counter,
        }
    }

    fn multi_network_ptk(fixture: &MultiNetworkFixture) -> PairwiseTransientKey {
        let pmk = derive_pmk(fixture.passphrase, fixture.ssid).unwrap();
        derive_ptk(
            &pmk,
            &fixture.bssid.octets(),
            &fixture.station.octets(),
            &fixture.ap_nonce,
            &fixture.station_nonce,
        )
    }

    fn observe_multi_network_beacon(transform: &mut WpaDecrypt, fixture: &MultiNetworkFixture) {
        transform
            .decrypt_record(beacon_with_rsn(
                fixture.bssid,
                fixture.ssid,
                &RsnInformation::new(),
            ))
            .unwrap();
    }

    fn observe_multi_network_message_1(transform: &mut WpaDecrypt, fixture: &MultiNetworkFixture) {
        let packet = Dot11::data()
            .addr1(fixture.station)
            .addr2(fixture.bssid)
            .addr3(fixture.bssid)
            / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
            / Eapol::key()
            / pairwise_message_1(fixture.replay_counter, fixture.ap_nonce);

        transform
            .decrypt_record(PacketRecord::new(packet).with_link_type(LinkType::Ieee80211))
            .unwrap();
    }

    fn observe_multi_network_message_2(
        transform: &mut WpaDecrypt,
        fixture: &MultiNetworkFixture,
        ptk: &PairwiseTransientKey,
    ) {
        let (message_2, _eapol_frame) = signed_eapol_key(
            pairwise_message_2(fixture.replay_counter, fixture.station_nonce),
            ptk,
        );
        let packet = Dot11::data()
            .addr1(fixture.bssid)
            .addr2(fixture.station)
            .addr3(fixture.bssid)
            / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
            / Eapol::key()
            / message_2;

        transform
            .decrypt_record(PacketRecord::new(packet).with_link_type(LinkType::Ieee80211))
            .unwrap();
    }

    fn encrypted_multi_network_record(
        fixture: &MultiNetworkFixture,
        ptk: &PairwiseTransientKey,
        key_id: u8,
        packet_number: u8,
        payload: &'static [u8],
    ) -> PacketRecord {
        let dot11 = protected_to_ds_data(fixture.bssid, fixture.station, fixture.peer);
        let encrypted_body = encrypt_unicast_for_tests(
            &dot11,
            ptk.temporal_key(),
            key_id,
            [packet_number, 0, 0, 0, 0, 0],
            &ipv4_plaintext(payload),
        );

        PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body))
            .with_origin(PacketOrigin::Captured)
            .with_link_type(LinkType::Ieee80211)
    }

    fn assert_multi_network_decrypted_record(
        record: &PacketRecord,
        fixture: &MultiNetworkFixture,
        key_id: u8,
        packet_number: u64,
        payload: &'static [u8],
    ) {
        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert_eq!(record.metadata().link_type(), Some(LinkType::Ethernet));
        assert_eq!(
            record.packet().layer::<Ethernet>().unwrap().source(),
            Some(fixture.station)
        );
        assert_eq!(
            record.packet().layer::<Ethernet>().unwrap().destination(),
            Some(fixture.peer)
        );
        assert_eq!(record.packet().layer::<Raw>().unwrap().as_bytes(), payload);

        let wifi = record.metadata().wifi().unwrap();
        assert_eq!(wifi.ssid(), Some(fixture.ssid));
        assert_eq!(wifi.bssid(), Some(fixture.bssid));
        assert_eq!(wifi.key_id(), Some(key_id));
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Decrypted));

        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.bssid(), Some(fixture.bssid));
        assert_eq!(wpa.station(), Some(fixture.station));
        assert_eq!(wpa.cipher(), Some(WpaCipher::Ccmp128));
        assert_eq!(wpa.akm(), Some(WpaAkm::Psk));
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Pairwise));
        assert_eq!(wpa.key_id(), Some(key_id));
        assert_eq!(wpa.packet_number(), Some(packet_number));
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::Decrypted));
        assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
        assert_eq!(
            wpa.handshake_status(),
            Some(WpaHandshakeStatus::MicVerified)
        );
    }

    fn wpa_pcap_fixture_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pcaps/wpa2-psk-ccmp-unicast.pcap")
    }

    fn wpa_pcap_fixture_mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x20, last])
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
        let mut transform = WpaDecrypt::new()
            .with_config(WpaDecryptConfig::new().pass_originals(true))
            .network("lab", "12345678")
            .unwrap();
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
        assert_eq!(transform.observed_handshake_count(), 1);
        assert_eq!(transform.verified_session_count(), 0);
        assert_eq!(transform.decrypted_count(), 0);
        assert_eq!(transform.failed_count(), 0);
    }

    #[test]
    fn configured_network_verifies_handshake_and_decrypts_default_output() {
        let bssid = mac(5);
        let station = mac(0x55);
        let peer = mac(0x56);
        let ap_nonce = [0x12; 32];
        let station_nonce = [0x34; 32];
        let mut transform = WpaDecrypt::new().network("lab", "12345678").unwrap();
        let pmk = transform.networks()[0].cached_pmk().clone();
        let ptk = derive_ptk(
            &pmk,
            &bssid.octets(),
            &station.octets(),
            &ap_nonce,
            &station_nonce,
        );

        assert_eq!(
            transform
                .decrypt_record(beacon_with_rsn(
                    bssid,
                    b"lab".as_slice(),
                    &RsnInformation::new(),
                ))
                .unwrap()
                .len(),
            1
        );

        let message_1_packet = Dot11::data().addr1(station).addr2(bssid).addr3(bssid)
            / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
            / Eapol::key()
            / pairwise_message_1(1, ap_nonce);
        assert!(transform
            .decrypt_record(PacketRecord::new(message_1_packet))
            .unwrap()
            .is_empty());

        let (message_2, _eapol_frame) =
            signed_eapol_key(pairwise_message_2(1, station_nonce), &ptk);
        let message_2_packet = Dot11::data().addr1(bssid).addr2(station).addr3(bssid)
            / LlcSnap::new().ethertype(ETHERTYPE_EAPOL)
            / Eapol::key()
            / message_2;
        assert!(transform
            .decrypt_record(PacketRecord::new(message_2_packet))
            .unwrap()
            .is_empty());

        assert_eq!(transform.observed_handshake_count(), 2);
        assert_eq!(transform.verified_session_count(), 1);

        let dot11 = protected_to_ds_data(bssid, station, peer);
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, ptk.temporal_key(), 0, [13, 0, 0, 0, 0, 0], b"plain");
        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(
            output.records()[0].metadata().origin(),
            PacketOrigin::Transformed
        );
        assert_eq!(
            output.records()[0]
                .metadata()
                .wifi()
                .unwrap()
                .decrypt_state(),
            Some(WifiDecryptState::Decrypted)
        );
        assert_eq!(transform.decrypted_count(), 1);
        assert_eq!(transform.failed_count(), 0);
    }

    #[test]
    fn pcap_fixture_decrypts_packet_wire_sniffer_pipeline() {
        let path = wpa_pcap_fixture_path();
        let source = PacketWire::pcap_file(path.clone())
            .open()
            .unwrap()
            .source()
            .unwrap();
        let records = Sniffer::new(source)
            .with(Dot11Metadata::new())
            .with(
                WpaDecrypt::new()
                    .network("libcrafter-wpa", "libcrafter-pass")
                    .unwrap(),
            )
            .collect_records()
            .unwrap();

        assert_eq!(records.len(), 2);
        let decrypted = records
            .iter()
            .find(|record| record.metadata().origin() == PacketOrigin::Transformed)
            .expect("fixture should emit one decrypted record");
        assert_eq!(decrypted.metadata().backend(), &BackendKind::PcapFile);
        assert_eq!(decrypted.metadata().file(), Some(path.as_path()));
        assert_eq!(decrypted.metadata().link_type(), Some(LinkType::Ethernet));
        assert!(decrypted.packet().layer::<Ethernet>().is_some());
        assert!(decrypted.packet().layer::<Ipv4>().is_some());
        assert_eq!(
            decrypted.packet().layer::<Raw>().unwrap().as_bytes(),
            b"libcrafter wpa"
        );

        let wifi = decrypted.metadata().wifi().unwrap();
        assert_eq!(wifi.ssid(), Some(b"libcrafter-wpa".as_slice()));
        assert_eq!(wifi.bssid(), Some(wpa_pcap_fixture_mac(0x01)));
        assert_eq!(wifi.transmitter(), Some(wpa_pcap_fixture_mac(0x02)));
        assert_eq!(wifi.receiver(), Some(wpa_pcap_fixture_mac(0x01)));
        assert_eq!(wifi.key_id(), Some(1));
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Decrypted));

        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.cipher(), Some(WpaCipher::Ccmp128));
        assert_eq!(wpa.akm(), Some(WpaAkm::Psk));
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Pairwise));
        assert_eq!(wpa.key_id(), Some(1));
        assert_eq!(wpa.packet_number(), Some(0x33));
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::Decrypted));
        assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
        assert_eq!(
            wpa.handshake_status(),
            Some(WpaHandshakeStatus::MicVerified)
        );
    }

    #[test]
    fn multi_network_decrypts_interleaved_sessions_with_independent_metadata() {
        let alpha = multi_network_fixture(b"multi-alpha", "alpha-pass", 0xa0, 0x11, 10);
        let beta = multi_network_fixture(b"multi-beta", "beta-pass", 0xb0, 0x21, 20);
        let alpha_ptk = multi_network_ptk(&alpha);
        let beta_ptk = multi_network_ptk(&beta);
        let mut transform = WpaDecrypt::new()
            .network("multi-alpha", "alpha-pass")
            .unwrap()
            .network("multi-beta", "beta-pass")
            .unwrap();

        observe_multi_network_beacon(&mut transform, &alpha);
        observe_multi_network_beacon(&mut transform, &beta);
        observe_multi_network_message_1(&mut transform, &alpha);
        observe_multi_network_message_1(&mut transform, &beta);
        observe_multi_network_message_2(&mut transform, &beta, &beta_ptk);
        observe_multi_network_message_2(&mut transform, &alpha, &alpha_ptk);

        assert_eq!(transform.networks().len(), 2);
        assert_eq!(transform.observed_handshake_count(), 4);
        assert_eq!(transform.verified_session_count(), 2);
        assert!(transform
            .observed_bss(alpha.bssid)
            .unwrap()
            .session(alpha.station)
            .unwrap()
            .is_ready());
        assert!(transform
            .observed_bss(beta.bssid)
            .unwrap()
            .session(beta.station)
            .unwrap()
            .is_ready());

        let alpha_output = transform
            .decrypt_record(
                encrypted_multi_network_record(&alpha, &alpha_ptk, 1, 31, b"alpha")
                    .with_backend(BackendKind::PcapInterface)
                    .with_interface("wlan0mon"),
            )
            .unwrap();
        let beta_output = transform
            .decrypt_record(
                encrypted_multi_network_record(&beta, &beta_ptk, 2, 41, b"beta")
                    .with_backend(BackendKind::PcapFile)
                    .with_file("fixtures/multi-beta.pcap"),
            )
            .unwrap();

        assert_eq!(alpha_output.len(), 1);
        assert_eq!(beta_output.len(), 1);
        assert_multi_network_decrypted_record(&alpha_output.records()[0], &alpha, 1, 31, b"alpha");
        assert_multi_network_decrypted_record(&beta_output.records()[0], &beta, 2, 41, b"beta");
        assert_eq!(
            alpha_output.records()[0].metadata().backend(),
            &BackendKind::PcapInterface
        );
        assert_eq!(
            alpha_output.records()[0].metadata().interface(),
            Some("wlan0mon")
        );
        assert_eq!(
            beta_output.records()[0].metadata().backend(),
            &BackendKind::PcapFile
        );
        assert_eq!(
            beta_output.records()[0].metadata().file(),
            Some(Path::new("fixtures/multi-beta.pcap"))
        );
        assert_eq!(transform.decrypted_count(), 2);
        assert_eq!(transform.failed_count(), 0);
    }

    #[test]
    fn multi_network_wrong_passphrase_does_not_poison_successful_network() {
        let good = multi_network_fixture(b"multi-good", "good-pass", 0xc0, 0x31, 30);
        let bad = multi_network_fixture(b"multi-bad", "right-pass", 0xd0, 0x41, 40);
        let good_ptk = multi_network_ptk(&good);
        let bad_actual_ptk = multi_network_ptk(&bad);
        let mut transform = WpaDecrypt::new()
            .with_config(WpaDecryptConfig::new().pass_originals(true))
            .network("multi-good", "good-pass")
            .unwrap()
            .network("multi-bad", "wrong-pass")
            .unwrap();

        observe_multi_network_beacon(&mut transform, &good);
        observe_multi_network_beacon(&mut transform, &bad);
        observe_multi_network_message_1(&mut transform, &bad);
        observe_multi_network_message_1(&mut transform, &good);
        observe_multi_network_message_2(&mut transform, &bad, &bad_actual_ptk);
        observe_multi_network_message_2(&mut transform, &good, &good_ptk);

        let good_session = transform
            .observed_bss(good.bssid)
            .unwrap()
            .session(good.station)
            .unwrap();
        let bad_session = transform
            .observed_bss(bad.bssid)
            .unwrap()
            .session(bad.station)
            .unwrap();
        assert!(good_session.is_ready());
        assert_eq!(
            good_session.credential_status(),
            WpaCredentialStatus::Matched
        );
        assert!(!bad_session.is_ready());
        assert_eq!(
            bad_session.credential_status(),
            WpaCredentialStatus::Mismatch
        );
        assert_eq!(transform.verified_session_count(), 1);

        let bad_output = transform
            .decrypt_record(
                encrypted_multi_network_record(&bad, &bad_actual_ptk, 0, 51, b"bad")
                    .with_backend(BackendKind::PcapInterface)
                    .with_interface("wlan1mon"),
            )
            .unwrap();
        let good_output = transform
            .decrypt_record(
                encrypted_multi_network_record(&good, &good_ptk, 0, 61, b"good")
                    .with_backend(BackendKind::PcapInterface)
                    .with_interface("wlan0mon"),
            )
            .unwrap();

        assert_eq!(bad_output.len(), 1);
        assert_eq!(
            bad_output.records()[0].metadata().origin(),
            PacketOrigin::Captured
        );
        let bad_wifi = bad_output.records()[0].metadata().wifi().unwrap();
        assert_eq!(bad_wifi.ssid(), Some(bad.ssid));
        assert_eq!(bad_wifi.bssid(), Some(bad.bssid));
        assert_ne!(bad_wifi.decrypt_state(), Some(WifiDecryptState::Decrypted));
        let bad_wpa = bad_wifi.wpa_metadata().unwrap();
        assert_eq!(
            bad_wpa.credential_status(),
            Some(WpaCredentialStatus::Mismatch)
        );
        assert_eq!(bad_wpa.handshake_status(), Some(WpaHandshakeStatus::Failed));

        assert_eq!(good_output.len(), 2);
        let decrypted_good = good_output
            .records()
            .iter()
            .find(|record| record.metadata().origin() == PacketOrigin::Transformed)
            .unwrap();
        assert_multi_network_decrypted_record(decrypted_good, &good, 0, 61, b"good");
        assert_eq!(decrypted_good.metadata().interface(), Some("wlan0mon"));
        assert_eq!(transform.decrypted_count(), 1);
        assert_eq!(transform.failed_count(), 1);
    }

    #[test]
    fn unicast_decrypts_llc_snap_to_ethernet_equivalent_packet() {
        let (mut transform, bssid, station, peer, ptk) = verified_unicast_transform();
        let dot11 = protected_to_ds_data(bssid, station, peer);
        let plaintext = (LlcSnap::new().ethertype(ETHERTYPE_IPV4)
            / Ipv4::new()
                .src(Ipv4Addr::new(192, 0, 2, 10))
                .dst(Ipv4Addr::new(198, 51, 100, 20))
            / Raw::from("hello"))
        .compile()
        .unwrap()
        .into_bytes();
        let encrypted_body = encrypt_unicast_for_tests(
            &dot11,
            ptk.temporal_key(),
            2,
            [5, 0, 0, 0, 0, 0],
            &plaintext,
        );

        let output = transform
            .decrypt_record(
                PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body))
                    .with_origin(PacketOrigin::Captured)
                    .with_backend(BackendKind::Memory),
            )
            .unwrap();

        assert_eq!(output.len(), 1);
        let record = &output.records()[0];
        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert_eq!(record.metadata().link_type(), Some(LinkType::Ethernet));
        assert_eq!(record.metadata().backend(), &BackendKind::Memory);

        let ethernet = record.packet().layer::<Ethernet>().unwrap();
        assert_eq!(ethernet.source(), Some(station));
        assert_eq!(ethernet.destination(), Some(peer));
        assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));
        assert!(record.packet().layer::<Ipv4>().is_some());
        assert_eq!(record.packet().layer::<Raw>().unwrap().as_bytes(), b"hello");

        let wifi = record.metadata().wifi().unwrap();
        assert_eq!(wifi.ssid(), Some(b"lab".as_slice()));
        assert_eq!(wifi.bssid(), Some(bssid));
        assert_eq!(wifi.key_id(), Some(2));
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Decrypted));

        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Pairwise));
        assert_eq!(wpa.key_id(), Some(2));
        assert_eq!(wpa.packet_number(), Some(5));
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::Decrypted));
        assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
        assert_eq!(
            wpa.handshake_status(),
            Some(WpaHandshakeStatus::MicVerified)
        );
        assert_eq!(transform.decrypted_count(), 1);
        assert_eq!(transform.failed_count(), 0);
    }

    #[test]
    fn unicast_preserves_unknown_decrypted_plaintext_as_raw_packet() {
        let (mut transform, bssid, station, peer, ptk) = verified_unicast_transform();
        let dot11 = protected_to_ds_data(bssid, station, peer);
        let plaintext = b"opaque application bytes";
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, ptk.temporal_key(), 0, [6, 0, 0, 0, 0, 0], plaintext);

        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        let packet = output.records()[0].packet();
        assert!(packet.layer::<Ethernet>().is_none());
        assert_eq!(packet.layer::<Raw>().unwrap().as_bytes(), plaintext);
        let wpa = output.records()[0]
            .metadata()
            .wifi()
            .unwrap()
            .wpa_metadata()
            .unwrap();
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::Decrypted));
        assert_eq!(wpa.packet_number(), Some(6));
    }

    #[test]
    fn group_decrypts_llc_snap_to_ethernet_equivalent_packet() {
        let gtk = [0x91; WPA_PTK_TEMPORAL_KEY_LEN];
        let (mut transform, bssid, _station, source, _pmk, _ptk) =
            verified_group_transform(false, Some((1, gtk)));
        let destination = MacAddr::new([0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
        let dot11 = protected_from_ds_group_data(bssid, source, destination);
        let plaintext = ipv4_plaintext(b"group");
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, &gtk, 1, [7, 0, 0, 0, 0, 0], &plaintext);

        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        let record = &output.records()[0];
        assert_eq!(record.metadata().origin(), PacketOrigin::Transformed);
        assert_eq!(record.metadata().link_type(), Some(LinkType::Ethernet));

        let ethernet = record.packet().layer::<Ethernet>().unwrap();
        assert_eq!(ethernet.source(), Some(source));
        assert_eq!(ethernet.destination(), Some(destination));
        assert_eq!(ethernet.ethertype_value(), Some(ETHERTYPE_IPV4));
        assert!(record.packet().layer::<Ipv4>().is_some());
        assert_eq!(record.packet().layer::<Raw>().unwrap().as_bytes(), b"group");

        let wifi = record.metadata().wifi().unwrap();
        assert_eq!(wifi.ssid(), Some(b"group-lab".as_slice()));
        assert_eq!(wifi.bssid(), Some(bssid));
        assert_eq!(wifi.key_id(), Some(1));
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Decrypted));

        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Group));
        assert_eq!(wpa.key_id(), Some(1));
        assert_eq!(wpa.packet_number(), Some(7));
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::Decrypted));
        assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
        assert_eq!(
            wpa.handshake_status(),
            Some(WpaHandshakeStatus::MicVerified)
        );
    }

    #[test]
    fn group_missing_gtk_marks_original_key_material_missing() {
        let bssid = mac(0x90);
        let source = mac(0x91);
        let mut bss = ObservedBss::new(bssid);
        bss.observe_ssid(b"group-missing");
        bss.observe_rsn(RsnInformation::new());

        let mut transform =
            WpaDecrypt::new().with_config(WpaDecryptConfig::new().pass_originals(true));
        transform.bsses.insert(bssid, bss);

        let gtk = [0xa1; WPA_PTK_TEMPORAL_KEY_LEN];
        let dot11 = protected_from_ds_group_data(bssid, source, MacAddr::BROADCAST);
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, &gtk, 0, [8, 0, 0, 0, 0, 0], b"payload");

        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        let wifi = output.records()[0].metadata().wifi().unwrap();
        assert_eq!(
            wifi.decrypt_state(),
            Some(WifiDecryptState::KeyMaterialMissing)
        );
        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Group));
        assert_eq!(wpa.key_id(), Some(0));
        assert_eq!(
            wpa.decrypt_reason(),
            Some(WpaDecryptReason::MissingKeyMaterial)
        );
        assert_eq!(wpa.handshake_status(), Some(WpaHandshakeStatus::NotStarted));
    }

    #[test]
    fn group_wrong_key_id_marks_original_key_material_missing() {
        let gtk = [0xb1; WPA_PTK_TEMPORAL_KEY_LEN];
        let (mut transform, bssid, _station, source, _pmk, _ptk) =
            verified_group_transform(true, Some((2, gtk)));
        let dot11 = protected_from_ds_group_data(bssid, source, MacAddr::BROADCAST);
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, &gtk, 1, [9, 0, 0, 0, 0, 0], b"payload");

        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        let wifi = output.records()[0].metadata().wifi().unwrap();
        assert_eq!(
            wifi.decrypt_state(),
            Some(WifiDecryptState::KeyMaterialMissing)
        );
        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Group));
        assert_eq!(wpa.key_id(), Some(1));
        assert_eq!(
            wpa.decrypt_reason(),
            Some(WpaDecryptReason::MissingKeyMaterial)
        );
        assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
    }

    #[test]
    fn group_malformed_gtk_kde_marks_original_failed() {
        let (mut transform, bssid, station, source, pmk, ptk) =
            verified_group_transform(true, None);
        let malformed_kde = [
            WPA_KEY_DATA_VENDOR_SPECIFIC_ELEMENT_ID,
            0x20,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        install_group_key_data(
            transform.bsses.get_mut(&bssid).unwrap(),
            bssid,
            station,
            &pmk,
            &ptk,
            malformed_kde,
        );

        let gtk = [0xc1; WPA_PTK_TEMPORAL_KEY_LEN];
        let dot11 = protected_from_ds_group_data(bssid, source, MacAddr::BROADCAST);
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, &gtk, 0, [10, 0, 0, 0, 0, 0], b"payload");

        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        let wifi = output.records()[0].metadata().wifi().unwrap();
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Failed));
        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Group));
        assert_eq!(wpa.decrypt_reason(), Some(WpaDecryptReason::MalformedFrame));
    }

    #[test]
    fn group_unsupported_cipher_marks_original_failed() {
        let gtk = [0xd1; WPA_PTK_TEMPORAL_KEY_LEN];
        let (mut transform, bssid, _station, source, _pmk, _ptk) =
            verified_group_transform(true, Some((0, gtk)));
        transform
            .bsses
            .get_mut(&bssid)
            .unwrap()
            .observe_rsn(RsnInformation::new().with_group_cipher_suite(RSN_CIPHER_SUITE_TKIP));

        let dot11 = protected_from_ds_group_data(bssid, source, MacAddr::BROADCAST);
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, &gtk, 0, [11, 0, 0, 0, 0, 0], b"payload");

        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        let wifi = output.records()[0].metadata().wifi().unwrap();
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::Failed));
        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Group));
        assert_eq!(
            wpa.decrypt_reason(),
            Some(WpaDecryptReason::UnsupportedCipher)
        );
    }

    #[test]
    fn group_before_gtk_is_known_marks_key_material_missing() {
        let (mut transform, bssid, _station, source, _pmk, _ptk) =
            verified_group_transform(true, None);
        let gtk = [0xe1; WPA_PTK_TEMPORAL_KEY_LEN];
        let dot11 = protected_from_ds_group_data(bssid, source, MacAddr::BROADCAST);
        let encrypted_body =
            encrypt_unicast_for_tests(&dot11, &gtk, 0, [12, 0, 0, 0, 0, 0], b"payload");

        let output = transform
            .decrypt_record(PacketRecord::new(dot11 / Raw::from_bytes(encrypted_body)))
            .unwrap();

        assert_eq!(output.len(), 1);
        let wifi = output.records()[0].metadata().wifi().unwrap();
        assert_eq!(
            wifi.decrypt_state(),
            Some(WifiDecryptState::KeyMaterialMissing)
        );
        let wpa = wifi.wpa_metadata().unwrap();
        assert_eq!(wpa.key_kind(), Some(WpaKeyKind::Group));
        assert_eq!(
            wpa.decrypt_reason(),
            Some(WpaDecryptReason::MissingKeyMaterial)
        );
        assert_eq!(wpa.credential_status(), Some(WpaCredentialStatus::Matched));
        assert_eq!(
            wpa.handshake_status(),
            Some(WpaHandshakeStatus::MicVerified)
        );
    }
}
