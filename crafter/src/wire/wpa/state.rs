//! WPA passive observation state machines.

use core::fmt;
use std::collections::{HashMap, HashSet};

use super::crypto::{derive_ptk, unwrap_key_data, verify_eapol_mic, PairwiseTransientKey, Pmk};
use super::metadata::{
    WpaAkm, WpaCipher, WpaCredentialStatus, WpaDecryptReason, WpaHandshakeStatus,
};
use crate::{
    CrafterError, EapolKey, MacAddr, RsnAkmSuite, RsnCipherSuite, RsnEapolKeyHandshakeMessage,
    RsnInformation, RSN_AKM_SUITE_8021X, RSN_AKM_SUITE_PSK, RSN_AKM_SUITE_SAE,
    RSN_CIPHER_SUITE_CCMP_128, RSN_CIPHER_SUITE_CCMP_256, RSN_CIPHER_SUITE_GCMP_128,
    RSN_CIPHER_SUITE_GCMP_256, RSN_CIPHER_SUITE_TKIP,
};

const WPA_KEY_DATA_VENDOR_SPECIFIC_ELEMENT_ID: u8 = 0xdd;
const WPA_KEY_DATA_RSN_OUI: [u8; 3] = [0x00, 0x0f, 0xac];
const WPA_KEY_DATA_GTK_KDE_TYPE: u8 = 1;
const WPA_GTK_KEY_ID_MASK: u8 = 0x03;

/// Group temporal key material extracted from WPA2 encrypted key data.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Gtk {
    key_id: u8,
    bytes: Vec<u8>,
}

impl Gtk {
    /// Create a GTK with its two-bit key identifier.
    pub(crate) fn new(key_id: u8, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            key_id: key_id & WPA_GTK_KEY_ID_MASK,
            bytes: bytes.into(),
        }
    }

    /// WPA key identifier carried by the GTK KDE.
    pub(crate) const fn key_id(&self) -> u8 {
        self.key_id
    }

    /// Borrow raw GTK bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Gtk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gtk")
            .field("key_id", &self.key_id)
            .field("bytes", &"<redacted>")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Group-key readiness state for one observed BSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GroupKeyReadiness {
    /// No encrypted key-data frame has been processed yet.
    Unknown,
    /// At least one GTK is available.
    Available,
    /// Key data was seen but no usable GTK is currently available.
    Unavailable(WpaDecryptReason),
}

impl Default for GroupKeyReadiness {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Group-key state for one observed BSS, keyed by GTK key id.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GroupKeyState {
    gtks: HashMap<u8, Gtk>,
    readiness: GroupKeyReadiness,
    unsupported_kde_count: usize,
}

impl GroupKeyState {
    /// GTKs keyed by key id.
    pub(crate) fn gtks(&self) -> &HashMap<u8, Gtk> {
        &self.gtks
    }

    /// Borrow one GTK by key id.
    pub(crate) fn gtk(&self, key_id: u8) -> Option<&Gtk> {
        self.gtks.get(&(key_id & WPA_GTK_KEY_ID_MASK))
    }

    /// Current group-key readiness.
    pub(crate) const fn readiness(&self) -> GroupKeyReadiness {
        self.readiness
    }

    /// Number of valid but unsupported KDEs seen while parsing key data.
    pub(crate) const fn unsupported_kde_count(&self) -> usize {
        self.unsupported_kde_count
    }

    fn apply_update(&mut self, update: &GroupKeyUpdate) {
        self.unsupported_kde_count += update.unsupported_kde_count;
        for gtk in &update.gtks {
            self.gtks.insert(gtk.key_id(), gtk.clone());
        }

        self.readiness = if self.gtks.is_empty() {
            GroupKeyReadiness::Unavailable(
                update
                    .reason
                    .unwrap_or(WpaDecryptReason::MissingKeyMaterial),
            )
        } else {
            GroupKeyReadiness::Available
        };
    }
}

/// Result of trying to decrypt and parse one EAPOL-Key key-data field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GroupKeyUpdate {
    gtks: Vec<Gtk>,
    reason: Option<WpaDecryptReason>,
    unsupported_kde_count: usize,
}

impl GroupKeyUpdate {
    fn available(gtks: Vec<Gtk>, unsupported_kde_count: usize) -> Self {
        Self {
            gtks,
            reason: None,
            unsupported_kde_count,
        }
    }

    fn unavailable(reason: WpaDecryptReason, unsupported_kde_count: usize) -> Self {
        Self {
            gtks: Vec::new(),
            reason: Some(reason),
            unsupported_kde_count,
        }
    }
}

/// WPA/WPA2-Personal four-way handshake message classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HandshakeMessage {
    /// Message 1 from authenticator to supplicant.
    Message1,
    /// Message 2 from supplicant to authenticator.
    Message2,
    /// Message 3 from authenticator to supplicant.
    Message3,
    /// Message 4 from supplicant to authenticator.
    Message4,
    /// A frame that does not match a supported four-way handshake shape.
    Unknown,
}

impl HandshakeMessage {
    /// Classify an EAPOL-Key layer into a passive four-way handshake shape.
    pub(crate) fn classify(key: &EapolKey) -> Self {
        key.rsn_handshake_message().into()
    }

    /// Return true for one of the four known handshake messages.
    pub(crate) const fn is_known(self) -> bool {
        match self {
            Self::Message1 | Self::Message2 | Self::Message3 | Self::Message4 => true,
            Self::Unknown => false,
        }
    }

    /// One-based message number.
    pub(crate) const fn number(self) -> Option<u8> {
        match self {
            Self::Message1 => Some(1),
            Self::Message2 => Some(2),
            Self::Message3 => Some(3),
            Self::Message4 => Some(4),
            Self::Unknown => None,
        }
    }

    /// Stable lowercase label used by diagnostics.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Message1 => "message_1",
            Self::Message2 => "message_2",
            Self::Message3 => "message_3",
            Self::Message4 => "message_4",
            Self::Unknown => "unknown",
        }
    }

    const fn transmitter_role(self) -> Option<PairwiseRole> {
        match self {
            Self::Message1 | Self::Message3 => Some(PairwiseRole::Authenticator),
            Self::Message2 | Self::Message4 => Some(PairwiseRole::Supplicant),
            Self::Unknown => None,
        }
    }
}

impl From<RsnEapolKeyHandshakeMessage> for HandshakeMessage {
    fn from(value: RsnEapolKeyHandshakeMessage) -> Self {
        match value {
            RsnEapolKeyHandshakeMessage::Message1 => Self::Message1,
            RsnEapolKeyHandshakeMessage::Message2 => Self::Message2,
            RsnEapolKeyHandshakeMessage::Message3 => Self::Message3,
            RsnEapolKeyHandshakeMessage::Message4 => Self::Message4,
            RsnEapolKeyHandshakeMessage::Unknown => Self::Unknown,
        }
    }
}

/// Candidate pairwise role inferred from a handshake message direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PairwiseRole {
    /// Authenticator role, normally the AP/BSSID.
    Authenticator,
    /// Supplicant role, normally the associated station.
    Supplicant,
}

/// One observed EAPOL-Key handshake record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct HandshakeObservation {
    message: HandshakeMessage,
    replay_counter: u64,
    transmitter: MacAddr,
    receiver: MacAddr,
    transmitter_role: Option<PairwiseRole>,
    accepted: bool,
}

impl HandshakeObservation {
    /// Classified four-way handshake message.
    pub(crate) const fn message(&self) -> HandshakeMessage {
        self.message
    }

    /// EAPOL-Key replay counter.
    pub(crate) const fn replay_counter(&self) -> u64 {
        self.replay_counter
    }

    /// Transmitting MAC address observed for this EAPOL-Key frame.
    pub(crate) const fn transmitter(&self) -> MacAddr {
        self.transmitter
    }

    /// Receiving MAC address observed for this EAPOL-Key frame.
    pub(crate) const fn receiver(&self) -> MacAddr {
        self.receiver
    }

    /// Candidate role of the transmitting MAC when the message is known.
    pub(crate) const fn transmitter_role(&self) -> Option<PairwiseRole> {
        self.transmitter_role
    }

    /// Whether this record advanced or refreshed the stored session state.
    pub(crate) const fn accepted(&self) -> bool {
        self.accepted
    }
}

/// Stored replay-counter state for one four-way handshake message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct HandshakeStepState {
    replay_counter: Option<u64>,
    observation_count: usize,
}

impl HandshakeStepState {
    /// Latest accepted replay counter for this message.
    pub(crate) const fn replay_counter(&self) -> Option<u64> {
        self.replay_counter
    }

    /// Number of accepted observations, including duplicates.
    pub(crate) const fn observation_count(&self) -> usize {
        self.observation_count
    }

    /// Whether this message has been observed.
    pub(crate) const fn observed(&self) -> bool {
        self.replay_counter.is_some()
    }

    fn observe(&mut self, replay_counter: u64) -> bool {
        if let Some(current) = self.replay_counter {
            if replay_counter < current {
                return false;
            }
        }

        self.replay_counter = Some(replay_counter);
        self.observation_count += 1;
        true
    }
}

/// Pairwise WPA handshake state for one BSSID/station pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PairwiseSession {
    bssid: MacAddr,
    station: MacAddr,
    authenticator: Option<MacAddr>,
    supplicant: Option<MacAddr>,
    ap_nonce: Option<[u8; 32]>,
    ap_nonce_replay_counter: Option<u64>,
    station_nonce: Option<[u8; 32]>,
    station_nonce_replay_counter: Option<u64>,
    message_1: HandshakeStepState,
    message_2: HandshakeStepState,
    message_3: HandshakeStepState,
    message_4: HandshakeStepState,
    last_observation: Option<HandshakeObservation>,
    pairwise_transient_key: Option<PairwiseTransientKey>,
    credential_status: WpaCredentialStatus,
    mic_replay_counter: Option<u64>,
}

impl PairwiseSession {
    /// Create empty pairwise handshake state for a BSSID/station pair.
    pub(crate) fn new(bssid: MacAddr, station: MacAddr) -> Self {
        Self {
            bssid,
            station,
            authenticator: None,
            supplicant: None,
            ap_nonce: None,
            ap_nonce_replay_counter: None,
            station_nonce: None,
            station_nonce_replay_counter: None,
            message_1: HandshakeStepState::default(),
            message_2: HandshakeStepState::default(),
            message_3: HandshakeStepState::default(),
            message_4: HandshakeStepState::default(),
            last_observation: None,
            pairwise_transient_key: None,
            credential_status: WpaCredentialStatus::Unknown,
            mic_replay_counter: None,
        }
    }

    /// BSSID/AP address for this session.
    pub(crate) const fn bssid(&self) -> MacAddr {
        self.bssid
    }

    /// Station address for this session.
    pub(crate) const fn station(&self) -> MacAddr {
        self.station
    }

    /// Candidate authenticator address observed from message direction.
    pub(crate) const fn authenticator(&self) -> Option<MacAddr> {
        self.authenticator
    }

    /// Candidate supplicant address observed from message direction.
    pub(crate) const fn supplicant(&self) -> Option<MacAddr> {
        self.supplicant
    }

    /// Latest accepted AP nonce.
    pub(crate) const fn ap_nonce(&self) -> Option<[u8; 32]> {
        self.ap_nonce
    }

    /// Replay counter associated with the stored AP nonce.
    pub(crate) const fn ap_nonce_replay_counter(&self) -> Option<u64> {
        self.ap_nonce_replay_counter
    }

    /// Latest accepted station nonce.
    pub(crate) const fn station_nonce(&self) -> Option<[u8; 32]> {
        self.station_nonce
    }

    /// Replay counter associated with the stored station nonce.
    pub(crate) const fn station_nonce_replay_counter(&self) -> Option<u64> {
        self.station_nonce_replay_counter
    }

    /// Stored state for message 1.
    pub(crate) const fn message_1(&self) -> &HandshakeStepState {
        &self.message_1
    }

    /// Stored state for message 2.
    pub(crate) const fn message_2(&self) -> &HandshakeStepState {
        &self.message_2
    }

    /// Stored state for message 3.
    pub(crate) const fn message_3(&self) -> &HandshakeStepState {
        &self.message_3
    }

    /// Stored state for message 4.
    pub(crate) const fn message_4(&self) -> &HandshakeStepState {
        &self.message_4
    }

    /// Last classified handshake observation.
    pub(crate) const fn last_observation(&self) -> Option<HandshakeObservation> {
        self.last_observation
    }

    /// Verified PTK material, available only after a matching EAPOL MIC.
    pub(crate) const fn pairwise_transient_key(&self) -> Option<&PairwiseTransientKey> {
        self.pairwise_transient_key.as_ref()
    }

    /// Credential status inferred from EAPOL-Key MIC verification.
    pub(crate) const fn credential_status(&self) -> WpaCredentialStatus {
        self.credential_status
    }

    /// Replay counter for the MIC-bearing frame that last set credential state.
    pub(crate) const fn mic_replay_counter(&self) -> Option<u64> {
        self.mic_replay_counter
    }

    /// Whether credentials match the observed pairwise handshake.
    pub(crate) const fn credentials_match(&self) -> bool {
        matches!(self.credential_status, WpaCredentialStatus::Matched)
    }

    /// Whether this session has verified pairwise key material ready to use.
    pub(crate) fn is_ready(&self) -> bool {
        self.credentials_match() && self.pairwise_transient_key.is_some()
    }

    /// Passive handshake status derived from currently stored state.
    pub(crate) fn status(&self) -> WpaHandshakeStatus {
        if !self.message_1.observed()
            && !self.message_2.observed()
            && !self.message_3.observed()
            && !self.message_4.observed()
        {
            return WpaHandshakeStatus::NotStarted;
        }

        if self.is_complete() {
            WpaHandshakeStatus::Complete
        } else {
            WpaHandshakeStatus::Observing
        }
    }

    /// Whether all four messages and both pairwise nonces have been observed.
    pub(crate) fn is_complete(&self) -> bool {
        self.message_1.observed()
            && self.message_2.observed()
            && self.message_3.observed()
            && self.message_4.observed()
            && self.ap_nonce.is_some()
            && self.station_nonce.is_some()
    }

    /// Observe one EAPOL-Key record for this BSSID/station pair.
    pub(crate) fn observe_key(
        &mut self,
        transmitter: MacAddr,
        receiver: MacAddr,
        key: &EapolKey,
    ) -> HandshakeObservation {
        let message = HandshakeMessage::classify(key);
        let replay_counter = key.replay_counter_value();
        let transmitter_role = message.transmitter_role();
        let accepted = match message {
            HandshakeMessage::Message1 => {
                let accepted = self.message_1.observe(replay_counter);
                if accepted {
                    self.note_roles(transmitter_role, transmitter, receiver);
                    self.update_ap_nonce(replay_counter, key.nonce_value());
                }
                accepted
            }
            HandshakeMessage::Message2 => {
                let accepted = self.message_2.observe(replay_counter);
                if accepted {
                    self.note_roles(transmitter_role, transmitter, receiver);
                    self.update_station_nonce(replay_counter, key.nonce_value());
                }
                accepted
            }
            HandshakeMessage::Message3 => {
                let accepted = self.message_3.observe(replay_counter);
                if accepted {
                    self.note_roles(transmitter_role, transmitter, receiver);
                    self.update_ap_nonce(replay_counter, key.nonce_value());
                }
                accepted
            }
            HandshakeMessage::Message4 => {
                let accepted = self.message_4.observe(replay_counter);
                if accepted {
                    self.note_roles(transmitter_role, transmitter, receiver);
                }
                accepted
            }
            HandshakeMessage::Unknown => false,
        };

        let observation = HandshakeObservation {
            message,
            replay_counter,
            transmitter,
            receiver,
            transmitter_role,
            accepted,
        };
        self.last_observation = Some(observation);
        observation
    }

    /// Verify one MIC-bearing EAPOL-Key frame against a configured PMK.
    ///
    /// This derives a candidate PTK once MAC roles and both nonces are known,
    /// then stores usable key material only when credentials match the frame
    /// MIC. Once a session has verified successfully, later duplicate or bad
    /// observations do not regress it.
    pub(crate) fn verify_key_mic(
        &mut self,
        pmk: &Pmk,
        key: &EapolKey,
        eapol_frame: &[u8],
    ) -> crate::Result<Option<bool>> {
        if !key.key_information_value().key_mic() {
            return Ok(None);
        }

        let Some(pairwise_transient_key) = self.derive_pairwise_transient_key(pmk) else {
            return Ok(None);
        };

        let credentials_match = verify_eapol_mic(&pairwise_transient_key, eapol_frame)?;
        if credentials_match {
            self.pairwise_transient_key = Some(pairwise_transient_key);
            self.credential_status = WpaCredentialStatus::Matched;
            self.mic_replay_counter = Some(key.replay_counter_value());
            return Ok(Some(true));
        }

        if !self.credentials_match() {
            self.pairwise_transient_key = None;
            self.credential_status = WpaCredentialStatus::Mismatch;
            self.mic_replay_counter = Some(key.replay_counter_value());
        }

        Ok(Some(false))
    }

    /// Decrypt and parse encrypted key data for GTK material when the PTK is ready.
    pub(crate) fn decrypt_group_key_data(&self, key: &EapolKey) -> GroupKeyUpdate {
        if !key.key_information_value().encrypted_key_data() || key.key_data_bytes().is_empty() {
            return GroupKeyUpdate::unavailable(WpaDecryptReason::MissingKeyMaterial, 0);
        }

        let Some(pairwise_transient_key) = self.pairwise_transient_key.as_ref() else {
            return GroupKeyUpdate::unavailable(WpaDecryptReason::MissingKeyMaterial, 0);
        };

        let decrypted = match unwrap_key_data(pairwise_transient_key.kek(), key.key_data_bytes()) {
            Ok(decrypted) => decrypted,
            Err(error) => {
                return GroupKeyUpdate::unavailable(group_key_unwrap_reason(&error), 0);
            }
        };

        match parse_key_data_elements(&decrypted) {
            Ok(parsed) if parsed.gtks.is_empty() => GroupKeyUpdate::unavailable(
                WpaDecryptReason::MissingKeyMaterial,
                parsed.unsupported_kde_count,
            ),
            Ok(parsed) => GroupKeyUpdate::available(parsed.gtks, parsed.unsupported_kde_count),
            Err(_) => GroupKeyUpdate::unavailable(WpaDecryptReason::MalformedFrame, 0),
        }
    }

    fn note_roles(
        &mut self,
        transmitter_role: Option<PairwiseRole>,
        transmitter: MacAddr,
        receiver: MacAddr,
    ) {
        match transmitter_role {
            Some(PairwiseRole::Authenticator) => {
                if transmitter == self.bssid {
                    self.authenticator = Some(transmitter);
                }
                if receiver == self.station {
                    self.supplicant = Some(receiver);
                }
            }
            Some(PairwiseRole::Supplicant) => {
                if transmitter == self.station {
                    self.supplicant = Some(transmitter);
                }
                if receiver == self.bssid {
                    self.authenticator = Some(receiver);
                }
            }
            None => {}
        }
    }

    fn update_ap_nonce(&mut self, replay_counter: u64, nonce: [u8; 32]) {
        update_nonce(
            &mut self.ap_nonce,
            &mut self.ap_nonce_replay_counter,
            replay_counter,
            nonce,
        );
    }

    fn update_station_nonce(&mut self, replay_counter: u64, nonce: [u8; 32]) {
        update_nonce(
            &mut self.station_nonce,
            &mut self.station_nonce_replay_counter,
            replay_counter,
            nonce,
        );
    }

    fn derive_pairwise_transient_key(&self, pmk: &Pmk) -> Option<PairwiseTransientKey> {
        let authenticator = self.authenticator?.octets();
        let supplicant = self.supplicant?.octets();
        let ap_nonce = self.ap_nonce?;
        let station_nonce = self.station_nonce?;

        Some(derive_ptk(
            pmk,
            &authenticator,
            &supplicant,
            &ap_nonce,
            &station_nonce,
        ))
    }
}

/// Observed WPA BSS state keyed by station address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservedBss {
    bssid: MacAddr,
    ssid: Option<Vec<u8>>,
    channel: Option<u16>,
    frequency_mhz: Option<u32>,
    rsn: Option<RsnInformation>,
    cipher: Option<WpaCipher>,
    akm: Option<WpaAkm>,
    decrypt_reason: Option<WpaDecryptReason>,
    stations: HashSet<MacAddr>,
    pairwise_sessions: HashMap<MacAddr, PairwiseSession>,
    group_keys: GroupKeyState,
}

impl ObservedBss {
    /// Create an observed BSS entry for one BSSID.
    pub(crate) fn new(bssid: MacAddr) -> Self {
        Self {
            bssid,
            ssid: None,
            channel: None,
            frequency_mhz: None,
            rsn: None,
            cipher: None,
            akm: None,
            decrypt_reason: None,
            stations: HashSet::new(),
            pairwise_sessions: HashMap::new(),
            group_keys: GroupKeyState::default(),
        }
    }

    /// BSSID for this observed network.
    pub(crate) const fn bssid(&self) -> MacAddr {
        self.bssid
    }

    /// SSID bytes when learned.
    pub(crate) fn ssid(&self) -> Option<&[u8]> {
        self.ssid.as_deref()
    }

    /// Last observed channel number for this BSS.
    pub(crate) const fn channel(&self) -> Option<u16> {
        self.channel
    }

    /// Last observed center frequency in MHz for this BSS.
    pub(crate) const fn frequency_mhz(&self) -> Option<u32> {
        self.frequency_mhz
    }

    /// Last observed RSN information element.
    pub(crate) const fn rsn(&self) -> Option<&RsnInformation> {
        self.rsn.as_ref()
    }

    /// Selected pairwise cipher inferred from RSN information.
    pub(crate) const fn cipher(&self) -> Option<WpaCipher> {
        self.cipher
    }

    /// Selected AKM suite inferred from RSN information.
    pub(crate) const fn akm(&self) -> Option<WpaAkm> {
        self.akm
    }

    /// Current decrypt reason inferred while observing this BSS.
    pub(crate) const fn decrypt_reason(&self) -> Option<WpaDecryptReason> {
        self.decrypt_reason
    }

    /// Learn or refresh SSID bytes for this BSS.
    pub(crate) fn observe_ssid(&mut self, ssid: impl AsRef<[u8]>) {
        let ssid = ssid.as_ref();
        if self.ssid.is_none() || !ssid.is_empty() {
            self.ssid = Some(ssid.to_vec());
        }
    }

    /// Learn or refresh channel metadata for this BSS.
    pub(crate) fn observe_channel(&mut self, channel: u16) {
        self.channel = Some(channel);
    }

    /// Learn or refresh frequency metadata for this BSS.
    pub(crate) fn observe_frequency_mhz(&mut self, frequency_mhz: u32) {
        self.frequency_mhz = Some(frequency_mhz);
    }

    /// Learn or refresh RSN security metadata for this BSS.
    pub(crate) fn observe_rsn(&mut self, rsn: RsnInformation) {
        let (cipher, akm, reason) = classify_rsn_security(&rsn);
        self.rsn = Some(rsn);
        self.cipher = Some(cipher);
        self.akm = Some(akm);
        self.decrypt_reason = reason;
    }

    /// Learn that a station is associated with or talking to this BSS.
    pub(crate) fn observe_station(&mut self, station: MacAddr) -> bool {
        if station == self.bssid || station == MacAddr::BROADCAST || station == MacAddr::ZERO {
            return false;
        }

        self.stations.insert(station)
    }

    /// Observed stations associated with or talking to this BSS.
    pub(crate) fn stations(&self) -> &HashSet<MacAddr> {
        &self.stations
    }

    /// Borrow observed pairwise sessions keyed by station address.
    pub(crate) fn pairwise_sessions(&self) -> &HashMap<MacAddr, PairwiseSession> {
        &self.pairwise_sessions
    }

    /// Borrow group-key state for this BSS.
    pub(crate) const fn group_key_state(&self) -> &GroupKeyState {
        &self.group_keys
    }

    /// Borrow one stored GTK by key id.
    pub(crate) fn gtk(&self, key_id: u8) -> Option<&Gtk> {
        self.group_keys.gtk(key_id)
    }

    /// Borrow a pairwise session if it exists.
    pub(crate) fn session(&self, station: MacAddr) -> Option<&PairwiseSession> {
        self.pairwise_sessions.get(&station)
    }

    /// Borrow or create a pairwise session for a station.
    pub(crate) fn session_mut(&mut self, station: MacAddr) -> &mut PairwiseSession {
        self.observe_station(station);
        self.pairwise_sessions
            .entry(station)
            .or_insert_with(|| PairwiseSession::new(self.bssid, station))
    }

    /// Observe one EAPOL-Key record when the caller already knows the station.
    pub(crate) fn observe_pairwise_key(
        &mut self,
        station: MacAddr,
        transmitter: MacAddr,
        receiver: MacAddr,
        key: &EapolKey,
    ) -> HandshakeObservation {
        self.session_mut(station)
            .observe_key(transmitter, receiver, key)
    }

    /// Observe and verify one MIC-bearing EAPOL-Key record with known station.
    pub(crate) fn observe_pairwise_key_with_mic(
        &mut self,
        station: MacAddr,
        transmitter: MacAddr,
        receiver: MacAddr,
        key: &EapolKey,
        eapol_frame: &[u8],
        pmk: &Pmk,
    ) -> crate::Result<HandshakeObservation> {
        let (observation, group_key_update) = {
            let session = self.session_mut(station);
            let observation = session.observe_key(transmitter, receiver, key);
            session.verify_key_mic(pmk, key, eapol_frame)?;
            let group_key_update = session.decrypt_group_key_data(key);
            (observation, group_key_update)
        };
        if key.key_information_value().encrypted_key_data() && !key.key_data_bytes().is_empty() {
            self.group_keys.apply_update(&group_key_update);
        }
        Ok(observation)
    }

    /// Observe one EAPOL-Key record and infer the station from BSSID direction.
    pub(crate) fn observe_eapol_key(
        &mut self,
        transmitter: MacAddr,
        receiver: MacAddr,
        key: &EapolKey,
    ) -> Option<HandshakeObservation> {
        let station = if transmitter == self.bssid && receiver != MacAddr::BROADCAST {
            receiver
        } else if receiver == self.bssid && transmitter != MacAddr::BROADCAST {
            transmitter
        } else {
            return None;
        };

        Some(self.observe_pairwise_key(station, transmitter, receiver, key))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ParsedKeyData {
    gtks: Vec<Gtk>,
    unsupported_kde_count: usize,
}

fn parse_key_data_elements(key_data: &[u8]) -> crate::Result<ParsedKeyData> {
    let mut parsed = ParsedKeyData::default();
    let mut offset = 0usize;

    while offset < key_data.len() {
        if key_data[offset..].iter().all(|byte| *byte == 0) {
            break;
        }

        let header_end = offset + 2;
        if header_end > key_data.len() {
            return Err(CrafterError::buffer_too_short(
                "wpa.key_data.element.header",
                header_end,
                key_data.len(),
            ));
        }

        let element_id = key_data[offset];
        let element_len = usize::from(key_data[offset + 1]);
        let value_start = header_end;
        let value_end = value_start.checked_add(element_len).ok_or_else(|| {
            CrafterError::invalid_field_value("wpa.key_data.element.length", "length overflow")
        })?;
        if value_end > key_data.len() {
            return Err(CrafterError::buffer_too_short(
                "wpa.key_data.element.value",
                value_end,
                key_data.len(),
            ));
        }

        let value = &key_data[value_start..value_end];
        if element_id == WPA_KEY_DATA_VENDOR_SPECIFIC_ELEMENT_ID {
            match parse_vendor_specific_key_data_element(value)? {
                Some(gtk) => parsed.gtks.push(gtk),
                None => parsed.unsupported_kde_count += 1,
            }
        }

        offset = value_end;
    }

    Ok(parsed)
}

fn parse_vendor_specific_key_data_element(value: &[u8]) -> crate::Result<Option<Gtk>> {
    if value.len() < 4 {
        return Err(CrafterError::buffer_too_short(
            "wpa.key_data.kde.selector",
            4,
            value.len(),
        ));
    }

    let oui = [value[0], value[1], value[2]];
    let kde_type = value[3];
    if oui != WPA_KEY_DATA_RSN_OUI || kde_type != WPA_KEY_DATA_GTK_KDE_TYPE {
        return Ok(None);
    }

    if value.len() < 6 {
        return Err(CrafterError::buffer_too_short(
            "wpa.key_data.gtk",
            6,
            value.len(),
        ));
    }

    let key_id = value[4] & WPA_GTK_KEY_ID_MASK;
    let gtk = value[5..].to_vec();
    if gtk.is_empty() {
        return Ok(None);
    }

    Ok(Some(Gtk::new(key_id, gtk)))
}

fn group_key_unwrap_reason(error: &CrafterError) -> WpaDecryptReason {
    match error {
        CrafterError::InvalidFieldValue {
            field: "wpa.key_data.integrity",
            ..
        } => WpaDecryptReason::AuthenticationFailed,
        _ => WpaDecryptReason::MalformedFrame,
    }
}

pub(crate) fn classify_rsn_security(
    rsn: &RsnInformation,
) -> (WpaCipher, WpaAkm, Option<WpaDecryptReason>) {
    let cipher = select_pairwise_cipher(rsn);
    let akm = select_akm(rsn);
    let reason = if cipher != WpaCipher::Ccmp128 {
        Some(WpaDecryptReason::UnsupportedCipher)
    } else if akm != WpaAkm::Psk {
        Some(WpaDecryptReason::UnsupportedAkm)
    } else {
        None
    };

    (cipher, akm, reason)
}

fn select_pairwise_cipher(rsn: &RsnInformation) -> WpaCipher {
    if rsn.pairwise_ciphers().contains(&RSN_CIPHER_SUITE_CCMP_128) {
        return WpaCipher::Ccmp128;
    }

    rsn.pairwise_ciphers()
        .first()
        .copied()
        .map(rsn_cipher_to_wpa)
        .unwrap_or_else(|| rsn_cipher_to_wpa(rsn.group_cipher()))
}

fn select_akm(rsn: &RsnInformation) -> WpaAkm {
    if rsn.akm_suites().contains(&RSN_AKM_SUITE_PSK) {
        return WpaAkm::Psk;
    }

    rsn.akm_suites()
        .first()
        .copied()
        .map(rsn_akm_to_wpa)
        .unwrap_or(WpaAkm::Unknown)
}

fn rsn_cipher_to_wpa(suite: RsnCipherSuite) -> WpaCipher {
    if suite == RSN_CIPHER_SUITE_CCMP_128 {
        WpaCipher::Ccmp128
    } else if suite == RSN_CIPHER_SUITE_TKIP {
        WpaCipher::Tkip
    } else if suite == RSN_CIPHER_SUITE_GCMP_128 {
        WpaCipher::Gcmp128
    } else if suite == RSN_CIPHER_SUITE_GCMP_256 {
        WpaCipher::Gcmp256
    } else if suite == RSN_CIPHER_SUITE_CCMP_256 {
        WpaCipher::Ccmp256
    } else {
        WpaCipher::Unsupported(selector_code(suite.to_bytes()))
    }
}

fn rsn_akm_to_wpa(suite: RsnAkmSuite) -> WpaAkm {
    if suite == RSN_AKM_SUITE_PSK {
        WpaAkm::Psk
    } else if suite == RSN_AKM_SUITE_8021X {
        WpaAkm::Enterprise
    } else if suite == RSN_AKM_SUITE_SAE {
        WpaAkm::Sae
    } else {
        WpaAkm::Unsupported(selector_code(suite.to_bytes()))
    }
}

fn selector_code(bytes: [u8; 4]) -> u32 {
    u32::from_be_bytes(bytes)
}

fn update_nonce(
    stored_nonce: &mut Option<[u8; 32]>,
    stored_replay_counter: &mut Option<u64>,
    replay_counter: u64,
    nonce: [u8; 32],
) {
    if nonce.iter().all(|byte| *byte == 0) {
        return;
    }
    if let Some(current) = *stored_replay_counter {
        if replay_counter < current {
            return;
        }
    }

    *stored_nonce = Some(nonce);
    *stored_replay_counter = Some(replay_counter);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    use super::super::crypto::{wrap_key_data_for_tests, WPA_PMK_LEN};
    use crate::{Eapol, EapolKeyInformation, EAPOL_HEADER_LEN};

    type HmacSha1 = Hmac<Sha1>;

    const EAPOL_KEY_MIC_OFFSET_FROM_EAPOL: usize = EAPOL_HEADER_LEN + 77;
    const EAPOL_KEY_MIC_LEN: usize = 16;

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x5e, 0x10, 0x00, last])
    }

    fn bytes<const N: usize>(seed: u8) -> [u8; N] {
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        out
    }

    fn base_info() -> EapolKeyInformation {
        EapolKeyInformation::new()
            .with_descriptor_version(2)
            .with_key_type(true)
    }

    fn message_1(replay_counter: u64, nonce_seed: u8) -> EapolKey {
        EapolKey::new()
            .key_information(base_info().with_key_ack(true))
            .key_length(16)
            .replay_counter(replay_counter)
            .nonce(bytes::<32>(nonce_seed))
    }

    fn message_2(replay_counter: u64, nonce_seed: u8) -> EapolKey {
        EapolKey::new()
            .key_information(base_info().with_key_mic(true))
            .key_length(16)
            .replay_counter(replay_counter)
            .nonce(bytes::<32>(nonce_seed))
            .mic(bytes::<16>(0x80))
            .key_data([0x30, 0x14])
    }

    fn message_3(replay_counter: u64, nonce_seed: u8) -> EapolKey {
        EapolKey::new()
            .key_information(
                base_info()
                    .with_key_ack(true)
                    .with_key_mic(true)
                    .with_install(true)
                    .with_secure(true)
                    .with_encrypted_key_data(true),
            )
            .key_length(16)
            .replay_counter(replay_counter)
            .nonce(bytes::<32>(nonce_seed))
            .mic(bytes::<16>(0x90))
            .key_data([0xdd, 0x16, 0x01])
    }

    fn message_4(replay_counter: u64) -> EapolKey {
        EapolKey::new()
            .key_information(base_info().with_key_mic(true).with_secure(true))
            .key_length(16)
            .replay_counter(replay_counter)
            .mic(bytes::<16>(0xa0))
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

    fn verified_bss() -> (ObservedBss, MacAddr, MacAddr, Pmk, PairwiseTransientKey) {
        let bssid = mac(1);
        let station = mac(2);
        let mut bss = ObservedBss::new(bssid);
        let pmk = Pmk::new([0x61; WPA_PMK_LEN]);

        bss.observe_pairwise_key(station, bssid, station, &message_1(1, 0x10));
        let ptk = derive_ptk(
            &pmk,
            &bssid.octets(),
            &station.octets(),
            &bytes::<32>(0x10),
            &bytes::<32>(0x20),
        );
        let (signed_message_2, eapol_frame) = signed_eapol_key(message_2(1, 0x20), &ptk);
        bss.observe_pairwise_key_with_mic(
            station,
            station,
            bssid,
            &signed_message_2,
            &eapol_frame,
            &pmk,
        )
        .unwrap();

        (bss, bssid, station, pmk, ptk)
    }

    fn encrypted_message_3(
        ptk: &PairwiseTransientKey,
        key_data: impl Into<Vec<u8>>,
    ) -> (EapolKey, Vec<u8>) {
        let encrypted_key_data = wrap_key_data_for_tests(ptk.kek(), pad_key_data(key_data));
        signed_eapol_key(message_3(2, 0x10).key_data(encrypted_key_data), ptk)
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

    #[test]
    fn handshake_classifies_synthetic_eapol_key_messages() {
        assert_eq!(
            HandshakeMessage::classify(&message_1(1, 0x10)),
            HandshakeMessage::Message1
        );
        assert_eq!(
            HandshakeMessage::classify(&message_2(1, 0x20)),
            HandshakeMessage::Message2
        );
        assert_eq!(
            HandshakeMessage::classify(&message_3(2, 0x10)),
            HandshakeMessage::Message3
        );
        assert_eq!(
            HandshakeMessage::classify(&message_4(2)),
            HandshakeMessage::Message4
        );

        let unknown = EapolKey::new()
            .key_information(base_info().with_key_mic(true).with_request(true))
            .replay_counter(3)
            .nonce(bytes::<32>(0x30))
            .mic(bytes::<16>(0xb0))
            .key_data([0x01]);

        assert_eq!(
            HandshakeMessage::classify(&unknown),
            HandshakeMessage::Unknown
        );
        assert!(HandshakeMessage::Message1.is_known());
        assert_eq!(HandshakeMessage::Message4.number(), Some(4));
        assert_eq!(HandshakeMessage::Message4.label(), "message_4");
    }

    #[test]
    fn handshake_session_tracks_normal_sequence() {
        let bssid = mac(1);
        let station = mac(2);
        let mut bss = ObservedBss::new(bssid);

        bss.observe_ssid(b"lab");
        assert_eq!(bss.bssid(), bssid);
        assert_eq!(bss.ssid(), Some(b"lab".as_slice()));

        let observed_1 = bss
            .observe_eapol_key(bssid, station, &message_1(1, 0x10))
            .unwrap();
        let observed_2 = bss
            .observe_eapol_key(station, bssid, &message_2(1, 0x20))
            .unwrap();
        let observed_3 = bss
            .observe_eapol_key(bssid, station, &message_3(2, 0x10))
            .unwrap();
        let observed_4 = bss
            .observe_eapol_key(station, bssid, &message_4(2))
            .unwrap();

        assert_eq!(observed_1.message(), HandshakeMessage::Message1);
        assert_eq!(observed_2.message(), HandshakeMessage::Message2);
        assert_eq!(observed_3.message(), HandshakeMessage::Message3);
        assert_eq!(observed_4.message(), HandshakeMessage::Message4);
        assert_eq!(observed_1.replay_counter(), 1);
        assert_eq!(observed_1.transmitter(), bssid);
        assert_eq!(observed_2.receiver(), bssid);
        assert_eq!(
            observed_3.transmitter_role(),
            Some(PairwiseRole::Authenticator)
        );
        assert!(observed_4.accepted());

        let session = bss.session(station).unwrap();
        assert_eq!(session.bssid(), bssid);
        assert_eq!(session.station(), station);
        assert_eq!(session.authenticator(), Some(bssid));
        assert_eq!(session.supplicant(), Some(station));
        assert_eq!(session.message_1().replay_counter(), Some(1));
        assert_eq!(session.message_2().replay_counter(), Some(1));
        assert_eq!(session.message_3().replay_counter(), Some(2));
        assert_eq!(session.message_4().replay_counter(), Some(2));
        assert_eq!(session.message_1().observation_count(), 1);
        assert_eq!(session.ap_nonce(), Some(bytes::<32>(0x10)));
        assert_eq!(session.ap_nonce_replay_counter(), Some(2));
        assert_eq!(session.station_nonce(), Some(bytes::<32>(0x20)));
        assert_eq!(session.station_nonce_replay_counter(), Some(1));
        assert_eq!(session.status(), WpaHandshakeStatus::Complete);
        assert_eq!(
            session.last_observation().unwrap().message(),
            HandshakeMessage::Message4
        );
        assert_eq!(bss.pairwise_sessions().len(), 1);
    }

    #[test]
    fn handshake_session_tolerates_duplicate_messages() {
        let bssid = mac(1);
        let station = mac(2);
        let mut bss = ObservedBss::new(bssid);

        let first = bss.observe_pairwise_key(station, bssid, station, &message_1(5, 0x10));
        let duplicate = bss.observe_pairwise_key(station, bssid, station, &message_1(5, 0x10));
        bss.observe_pairwise_key(station, station, bssid, &message_2(5, 0x20));
        bss.observe_pairwise_key(station, station, bssid, &message_2(5, 0x20));

        assert!(first.accepted());
        assert!(duplicate.accepted());

        let session = bss.session(station).unwrap();
        assert_eq!(session.message_1().replay_counter(), Some(5));
        assert_eq!(session.message_1().observation_count(), 2);
        assert_eq!(session.message_2().observation_count(), 2);
        assert_eq!(session.ap_nonce(), Some(bytes::<32>(0x10)));
        assert_eq!(session.station_nonce(), Some(bytes::<32>(0x20)));
        assert_eq!(session.status(), WpaHandshakeStatus::Observing);
    }

    #[test]
    fn handshake_session_keeps_newer_nonce_after_out_of_order_frames() {
        let bssid = mac(1);
        let station = mac(2);
        let mut bss = ObservedBss::new(bssid);

        bss.observe_pairwise_key(station, bssid, station, &message_3(20, 0x30));
        bss.observe_pairwise_key(station, bssid, station, &message_1(10, 0x10));
        bss.observe_pairwise_key(station, station, bssid, &message_4(20));
        bss.observe_pairwise_key(station, station, bssid, &message_2(10, 0x40));

        let stale = bss.observe_pairwise_key(station, bssid, station, &message_3(19, 0x50));
        let session = bss.session(station).unwrap();

        assert!(!stale.accepted());
        assert_eq!(session.message_1().replay_counter(), Some(10));
        assert_eq!(session.message_3().replay_counter(), Some(20));
        assert_eq!(session.ap_nonce(), Some(bytes::<32>(0x30)));
        assert_eq!(session.ap_nonce_replay_counter(), Some(20));
        assert_eq!(session.station_nonce(), Some(bytes::<32>(0x40)));
        assert_eq!(session.message_4().replay_counter(), Some(20));
        assert!(session.is_complete());
        assert_eq!(session.status(), WpaHandshakeStatus::Complete);
    }

    #[test]
    fn mic_verification_marks_credentials_match_and_stores_ptk() {
        let bssid = mac(1);
        let station = mac(2);
        let mut bss = ObservedBss::new(bssid);
        let pmk = Pmk::new([0x61; WPA_PMK_LEN]);

        bss.observe_pairwise_key(station, bssid, station, &message_1(1, 0x10));
        let expected_ptk = derive_ptk(
            &pmk,
            &bssid.octets(),
            &station.octets(),
            &bytes::<32>(0x10),
            &bytes::<32>(0x20),
        );
        let (signed_message_2, eapol_frame) = signed_eapol_key(message_2(1, 0x20), &expected_ptk);

        let observation = bss
            .observe_pairwise_key_with_mic(
                station,
                station,
                bssid,
                &signed_message_2,
                &eapol_frame,
                &pmk,
            )
            .unwrap();

        assert_eq!(observation.message(), HandshakeMessage::Message2);
        let session = bss.session(station).unwrap();
        assert_eq!(session.credential_status(), WpaCredentialStatus::Matched);
        assert!(session.credentials_match());
        assert!(session.is_ready());
        assert_eq!(session.mic_replay_counter(), Some(1));
        assert_eq!(session.pairwise_transient_key(), Some(&expected_ptk));
    }

    #[test]
    fn mic_verification_marks_wrong_credentials_as_mismatch() {
        let bssid = mac(1);
        let station = mac(2);
        let mut bss = ObservedBss::new(bssid);
        let correct_pmk = Pmk::new([0x61; WPA_PMK_LEN]);
        let wrong_pmk = Pmk::new([0x62; WPA_PMK_LEN]);

        bss.observe_pairwise_key(station, bssid, station, &message_1(1, 0x10));
        let correct_ptk = derive_ptk(
            &correct_pmk,
            &bssid.octets(),
            &station.octets(),
            &bytes::<32>(0x10),
            &bytes::<32>(0x20),
        );
        let (signed_message_2, eapol_frame) = signed_eapol_key(message_2(1, 0x20), &correct_ptk);

        bss.observe_pairwise_key_with_mic(
            station,
            station,
            bssid,
            &signed_message_2,
            &eapol_frame,
            &wrong_pmk,
        )
        .unwrap();

        let session = bss.session(station).unwrap();
        assert_eq!(session.credential_status(), WpaCredentialStatus::Mismatch);
        assert!(!session.credentials_match());
        assert!(!session.is_ready());
        assert_eq!(session.mic_replay_counter(), Some(1));
        assert!(session.pairwise_transient_key().is_none());
    }

    #[test]
    fn mic_duplicate_eapol_records_do_not_regress_verified_session() {
        let bssid = mac(1);
        let station = mac(2);
        let mut bss = ObservedBss::new(bssid);
        let correct_pmk = Pmk::new([0x61; WPA_PMK_LEN]);
        let wrong_pmk = Pmk::new([0x62; WPA_PMK_LEN]);

        bss.observe_pairwise_key(station, bssid, station, &message_1(1, 0x10));
        let expected_ptk = derive_ptk(
            &correct_pmk,
            &bssid.octets(),
            &station.octets(),
            &bytes::<32>(0x10),
            &bytes::<32>(0x20),
        );
        let (signed_message_2, eapol_frame) = signed_eapol_key(message_2(1, 0x20), &expected_ptk);

        bss.observe_pairwise_key_with_mic(
            station,
            station,
            bssid,
            &signed_message_2,
            &eapol_frame,
            &correct_pmk,
        )
        .unwrap();
        bss.observe_pairwise_key_with_mic(
            station,
            station,
            bssid,
            &signed_message_2,
            &eapol_frame,
            &correct_pmk,
        )
        .unwrap();

        let session = bss.session_mut(station);
        assert_eq!(session.message_2().observation_count(), 2);
        assert_eq!(session.credential_status(), WpaCredentialStatus::Matched);
        assert_eq!(session.pairwise_transient_key(), Some(&expected_ptk));

        assert_eq!(
            session
                .verify_key_mic(&wrong_pmk, &signed_message_2, &eapol_frame)
                .unwrap(),
            Some(false)
        );
        assert_eq!(session.credential_status(), WpaCredentialStatus::Matched);
        assert_eq!(session.pairwise_transient_key(), Some(&expected_ptk));
        assert!(session.is_ready());
    }

    #[test]
    fn gtk_key_data_extracts_valid_group_key_by_key_id() {
        let (mut bss, bssid, station, pmk, ptk) = verified_bss();
        let gtk_bytes = bytes::<16>(0x44);
        let (message_3, eapol_frame) = encrypted_message_3(&ptk, gtk_kde(2, gtk_bytes));

        bss.observe_pairwise_key_with_mic(station, bssid, station, &message_3, &eapol_frame, &pmk)
            .unwrap();

        let stored_gtk = bss.gtk(2).unwrap();
        assert_eq!(stored_gtk.key_id(), 2);
        assert_eq!(stored_gtk.bytes(), &gtk_bytes);
        assert_eq!(
            bss.group_key_state().readiness(),
            GroupKeyReadiness::Available
        );
        assert_eq!(bss.group_key_state().gtks().len(), 1);
        assert_eq!(
            format!("{stored_gtk:?}"),
            "Gtk { key_id: 2, bytes: \"<redacted>\", len: 16 }"
        );
    }

    #[test]
    fn gtk_malformed_key_data_marks_group_key_unavailable_without_regressing_session() {
        let (mut bss, bssid, station, pmk, ptk) = verified_bss();
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
        let (message_3, eapol_frame) = encrypted_message_3(&ptk, malformed_kde);

        bss.observe_pairwise_key_with_mic(station, bssid, station, &message_3, &eapol_frame, &pmk)
            .unwrap();

        let session = bss.session(station).unwrap();
        assert_eq!(session.credential_status(), WpaCredentialStatus::Matched);
        assert!(session.is_ready());
        assert!(bss.gtk(0).is_none());
        assert_eq!(
            bss.group_key_state().readiness(),
            GroupKeyReadiness::Unavailable(WpaDecryptReason::MalformedFrame)
        );
    }

    #[test]
    fn gtk_unsupported_kdes_are_counted_without_claiming_group_key_readiness() {
        let (mut bss, bssid, station, pmk, ptk) = verified_bss();
        let unsupported_kde = [
            WPA_KEY_DATA_VENDOR_SPECIFIC_ELEMENT_ID,
            6,
            0x00,
            0x0f,
            0xac,
            0xff,
            0xaa,
            0xbb,
        ];
        let (message_3, eapol_frame) = encrypted_message_3(&ptk, unsupported_kde);

        bss.observe_pairwise_key_with_mic(station, bssid, station, &message_3, &eapol_frame, &pmk)
            .unwrap();

        assert_eq!(bss.group_key_state().unsupported_kde_count(), 1);
        assert_eq!(
            bss.group_key_state().readiness(),
            GroupKeyReadiness::Unavailable(WpaDecryptReason::MissingKeyMaterial)
        );
    }

    #[test]
    fn gtk_encrypted_key_data_with_no_usable_gtk_marks_missing_group_key_material() {
        let (mut bss, bssid, station, pmk, ptk) = verified_bss();
        let rsn_element_only = [0x30, 0x02, 0x01, 0x00, 0, 0, 0, 0];
        let (message_3, eapol_frame) = encrypted_message_3(&ptk, rsn_element_only);

        bss.observe_pairwise_key_with_mic(station, bssid, station, &message_3, &eapol_frame, &pmk)
            .unwrap();

        assert!(bss.group_key_state().gtks().is_empty());
        assert_eq!(
            bss.group_key_state().readiness(),
            GroupKeyReadiness::Unavailable(WpaDecryptReason::MissingKeyMaterial)
        );
    }
}
