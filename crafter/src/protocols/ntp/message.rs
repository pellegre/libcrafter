//! NTP fixed-header message field helpers.
//!
//! Source-gated by `.agents/docs/ntp-wire-grammar.md` and
//! `.agents/docs/ntp-codepoints.md`. This module only models packet field
//! values; it does not add synchronization or peer workflow behavior.

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

use super::constants::*;
pub use super::extension::NtpExtensionField;
use super::extension::{
    is_valid_extension_length, is_valid_final_extension_without_mac_length,
    validate_extension_length, validate_final_extension_without_mac_length, NTP_EXTENSION_CONTEXT,
};
use super::registry::{
    ntp_extension_field_type_meta, ntp_kiss_o_death_code_meta, ntp_leap_indicator_meta,
    ntp_mode_meta, ntp_reference_code_ascii_label, ntp_reference_id_meta, ntp_stratum_meta,
    NtpRegistryMeta, NtpRegistryStatus,
};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext, Packet};
use crate::protocols::ip::v4::Ipv4;
use crate::protocols::ip::v6::Ipv6;
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
use crate::protocols::transport::Udp;

const NTP_HEADER_CONTEXT: &str = "ntp.header";
const NTP_MAC_CONTEXT: &str = "ntp.mac";
const NTP_DOCUMENTATION_IPV4_CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const NTP_DOCUMENTATION_IPV4_SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 123);
const NTP_DOCUMENTATION_IPV6_CLIENT: Ipv6Addr =
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0010);
const NTP_DOCUMENTATION_IPV6_SERVER: Ipv6Addr =
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0123);

/// Source-backed NTP leap-indicator field value.
///
/// The leap indicator is the high two bits of the first NTP fixed-header
/// octet. RFC 5905 defines every two-bit value; `AlarmUnsynchronized` is a
/// valid packet state, not a malformed value. `Unknown` preserves
/// caller-supplied values outside the extracted two-bit field space for
/// boundary-packet construction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NtpLeapIndicator {
    /// No leap warning.
    #[default]
    NoWarning,
    /// Last minute of the day has 61 seconds.
    LastMinute61Seconds,
    /// Last minute of the day has 59 seconds.
    LastMinute59Seconds,
    /// Alarm condition / clock unsynchronized.
    AlarmUnsynchronized,
    /// Caller-supplied value outside the source-backed two-bit LI space.
    Unknown(u8),
}

impl NtpLeapIndicator {
    /// Build a leap indicator from an already-extracted wire integer.
    pub const fn from_wire(value: u8) -> Self {
        match value {
            NTP_LI_NO_WARNING => Self::NoWarning,
            NTP_LI_LAST_MINUTE_61_SECONDS => Self::LastMinute61Seconds,
            NTP_LI_LAST_MINUTE_59_SECONDS => Self::LastMinute59Seconds,
            NTP_LI_ALARM_UNSYNCHRONIZED => Self::AlarmUnsynchronized,
            value => Self::Unknown(value),
        }
    }

    /// Raw leap-indicator value.
    pub const fn value(self) -> u8 {
        match self {
            Self::NoWarning => NTP_LI_NO_WARNING,
            Self::LastMinute61Seconds => NTP_LI_LAST_MINUTE_61_SECONDS,
            Self::LastMinute59Seconds => NTP_LI_LAST_MINUTE_59_SECONDS,
            Self::AlarmUnsynchronized => NTP_LI_ALARM_UNSYNCHRONIZED,
            Self::Unknown(value) => value,
        }
    }

    /// Raw leap-indicator value for serialization.
    pub const fn wire_value(self) -> u8 {
        self.value()
    }

    /// Value masked to the two leap-indicator bits used in the first NTP octet.
    pub const fn first_octet_bits(self) -> u8 {
        self.value() & NTP_LI_VALUE_MASK
    }

    /// Source-backed registry metadata for this leap-indicator value.
    pub fn registry_meta(self) -> NtpRegistryMeta {
        ntp_leap_indicator_meta(self.value())
    }

    /// Stable summary and inspection label.
    pub fn label(self) -> String {
        self.registry_meta().label
    }

    /// Stable summary-safe label.
    pub fn summary_label(self) -> String {
        self.label()
    }

    /// Return true for the alarm condition / clock unsynchronized state.
    pub const fn is_alarm_unsynchronized(self) -> bool {
        matches!(self, Self::AlarmUnsynchronized)
    }
}

impl From<u8> for NtpLeapIndicator {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<NtpLeapIndicator> for u8 {
    fn from(value: NtpLeapIndicator) -> Self {
        value.wire_value()
    }
}

impl fmt::Display for NtpLeapIndicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Source-backed NTP version field value.
///
/// The version number is the middle three bits of the first NTP fixed-header
/// octet. Unknown or future three-bit values are valid packet data and are
/// preserved for inspection and round-trip construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NtpVersion(u8);

impl NtpVersion {
    /// Build a version value from an already-extracted wire integer.
    pub const fn from_wire(value: u8) -> Self {
        Self(value)
    }

    /// Current source-backed default NTP version.
    pub const fn current() -> Self {
        Self(NTP_VERSION_CURRENT)
    }

    /// Raw version value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Raw version value for serialization.
    pub const fn wire_value(self) -> u8 {
        self.value()
    }

    /// Value masked to the three version bits used in the first NTP octet.
    pub const fn first_octet_bits(self) -> u8 {
        self.value() & NTP_VERSION_VALUE_MASK
    }

    /// Stable summary and inspection label.
    pub fn label(self) -> String {
        match self.value() {
            NTP_VERSION_1 => "ntp-v1".to_string(),
            NTP_VERSION_2 => "ntp-v2".to_string(),
            NTP_VERSION_3 => "ntp-v3".to_string(),
            NTP_VERSION_4 => "ntp-v4".to_string(),
            value => format!("version-{value}"),
        }
    }

    /// Stable summary-safe label.
    pub fn summary_label(self) -> String {
        self.label()
    }

    /// Return true for the current default NTP version.
    pub const fn is_current(self) -> bool {
        self.value() == NTP_VERSION_CURRENT
    }
}

impl Default for NtpVersion {
    fn default() -> Self {
        Self::current()
    }
}

impl From<u8> for NtpVersion {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<NtpVersion> for u8 {
    fn from(value: NtpVersion) -> Self {
        value.wire_value()
    }
}

impl fmt::Display for NtpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Source-backed NTP mode field value.
///
/// RFC 5905 defines the complete three-bit mode space. The `Unknown` variant
/// preserves caller-supplied values outside that extracted field space for
/// boundary-packet construction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NtpMode {
    /// Reserved mode value 0.
    Reserved,
    /// Symmetric active mode value 1.
    SymmetricActive,
    /// Symmetric passive mode value 2.
    SymmetricPassive,
    /// Client mode value 3.
    #[default]
    Client,
    /// Server mode value 4.
    Server,
    /// Broadcast mode value 5.
    Broadcast,
    /// Control mode value 6.
    Control,
    /// Private-use mode value 7.
    PrivateUse,
    /// Caller-supplied value outside the source-backed three-bit mode space.
    Unknown(u8),
}

impl NtpMode {
    /// Build a mode from an already-extracted wire integer.
    pub const fn from_wire(value: u8) -> Self {
        match value {
            NTP_MODE_RESERVED => Self::Reserved,
            NTP_MODE_SYMMETRIC_ACTIVE => Self::SymmetricActive,
            NTP_MODE_SYMMETRIC_PASSIVE => Self::SymmetricPassive,
            NTP_MODE_CLIENT => Self::Client,
            NTP_MODE_SERVER => Self::Server,
            NTP_MODE_BROADCAST => Self::Broadcast,
            NTP_MODE_CONTROL => Self::Control,
            NTP_MODE_PRIVATE => Self::PrivateUse,
            value => Self::Unknown(value),
        }
    }

    /// Raw mode value.
    pub const fn value(self) -> u8 {
        match self {
            Self::Reserved => NTP_MODE_RESERVED,
            Self::SymmetricActive => NTP_MODE_SYMMETRIC_ACTIVE,
            Self::SymmetricPassive => NTP_MODE_SYMMETRIC_PASSIVE,
            Self::Client => NTP_MODE_CLIENT,
            Self::Server => NTP_MODE_SERVER,
            Self::Broadcast => NTP_MODE_BROADCAST,
            Self::Control => NTP_MODE_CONTROL,
            Self::PrivateUse => NTP_MODE_PRIVATE,
            Self::Unknown(value) => value,
        }
    }

    /// Raw mode value for serialization.
    pub const fn wire_value(self) -> u8 {
        self.value()
    }

    /// Value masked to the three mode bits used in the first NTP octet.
    pub const fn first_octet_bits(self) -> u8 {
        self.value() & NTP_MODE_VALUE_MASK
    }

    /// Source-backed registry metadata for this mode value.
    pub fn registry_meta(self) -> NtpRegistryMeta {
        ntp_mode_meta(self.value())
    }

    /// Stable summary and inspection label.
    pub fn label(self) -> String {
        self.registry_meta().label
    }

    /// Stable summary-safe label.
    pub fn summary_label(self) -> String {
        self.label()
    }
}

impl From<u8> for NtpMode {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<NtpMode> for u8 {
    fn from(value: NtpMode) -> Self {
        value.wire_value()
    }
}

impl fmt::Display for NtpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Source-backed NTP stratum field value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NtpStratum(u8);

impl NtpStratum {
    /// Build a stratum wrapper from a raw wire value.
    pub const fn from_wire(value: u8) -> Self {
        Self(value)
    }

    /// Raw stratum value.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Raw stratum value for serialization.
    pub const fn wire_value(self) -> u8 {
        self.value()
    }

    /// Source-backed registry metadata for this stratum category.
    pub fn registry_meta(self) -> NtpRegistryMeta {
        ntp_stratum_meta(self.value())
    }

    /// Stable summary label.
    pub fn label(self) -> String {
        self.registry_meta().label
    }

    /// True for stratum 0 packets, including Kiss-o'-Death responses.
    pub const fn is_unspecified_or_kod(self) -> bool {
        self.value() == NTP_STRATUM_UNSPECIFIED
    }

    /// True for stratum 1 primary-server/reference-clock packets.
    pub const fn is_primary(self) -> bool {
        self.value() == NTP_STRATUM_PRIMARY
    }

    /// True for secondary-server strata 2 through 15.
    pub const fn is_secondary(self) -> bool {
        matches!(
            self.value(),
            NTP_STRATUM_SECONDARY_FIRST..=NTP_STRATUM_SECONDARY_LAST
        )
    }

    /// True for the explicitly unsynchronized stratum 16 value.
    pub const fn is_unsynchronized(self) -> bool {
        self.value() == NTP_STRATUM_UNSYNCHRONIZED
    }
}

impl Default for NtpStratum {
    fn default() -> Self {
        Self(NTP_DEFAULT_STRATUM)
    }
}

impl From<u8> for NtpStratum {
    fn from(value: u8) -> Self {
        Self::from_wire(value)
    }
}

impl From<NtpStratum> for u8 {
    fn from(value: NtpStratum) -> Self {
        value.wire_value()
    }
}

impl fmt::Display for NtpStratum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Four-octet NTP Reference ID bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NtpReferenceId([u8; NTP_REFERENCE_ID_LEN]);

impl NtpReferenceId {
    /// Build a reference identifier from raw wire bytes.
    pub const fn from_bytes(bytes: [u8; NTP_REFERENCE_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Build a stratum-0 Kiss-o'-Death reference identifier from four ASCII bytes.
    pub const fn kiss_o_death(code: [u8; NTP_REFERENCE_ID_LEN]) -> Self {
        Self(code)
    }

    /// Borrow the raw wire bytes.
    pub const fn bytes(self) -> [u8; NTP_REFERENCE_ID_LEN] {
        self.0
    }

    /// Source-backed label using the packet stratum to select the reference-ID meaning.
    pub fn label_for_stratum(self, stratum: NtpStratum) -> String {
        if stratum.is_unspecified_or_kod() {
            return ntp_kiss_o_death_code_meta(self.bytes()).label;
        }
        if stratum.is_primary() {
            return ntp_reference_id_meta(self.bytes()).label;
        }
        format!("refid-0x{:08X}", u32::from_be_bytes(self.0))
    }

    /// ASCII registry code when the raw bytes are uppercase alphanumeric and
    /// right-padded with NUL bytes.
    pub fn ascii_label(self) -> Option<String> {
        ntp_reference_code_ascii_label(self.bytes())
    }

    /// ASCII view when all bytes are printable ASCII or NUL padding.
    pub fn ascii_lossy(self) -> String {
        self.0
            .iter()
            .copied()
            .filter(|byte| *byte != 0)
            .map(|byte| {
                if byte.is_ascii_graphic() || byte == b' ' {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect()
    }
}

impl From<[u8; NTP_REFERENCE_ID_LEN]> for NtpReferenceId {
    fn from(bytes: [u8; NTP_REFERENCE_ID_LEN]) -> Self {
        Self::from_bytes(bytes)
    }
}

/// NTP short-format 16.16 fixed-point field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NtpShortFormat(u32);

impl NtpShortFormat {
    /// Build from a raw 32-bit wire value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Build from integer and fractional halves.
    pub const fn from_parts(integer: u16, fraction: u16) -> Self {
        Self(((integer as u32) << 16) | fraction as u32)
    }

    /// Raw 32-bit wire value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Integer half.
    pub const fn integer(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// Fractional half.
    pub const fn fraction(self) -> u16 {
        self.0 as u16
    }

    /// Interpret the short-format value as seconds.
    pub fn as_seconds(self) -> f64 {
        f64::from(self.integer()) + f64::from(self.fraction()) / 65_536.0
    }
}

impl From<u32> for NtpShortFormat {
    fn from(raw: u32) -> Self {
        Self::from_raw(raw)
    }
}

/// NTP 64-bit timestamp field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NtpTimestamp(u64);

impl NtpTimestamp {
    /// Build from a raw 64-bit wire value.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Build from seconds and fractional halves.
    pub const fn from_parts(seconds: u32, fraction: u32) -> Self {
        Self(((seconds as u64) << 32) | fraction as u64)
    }

    /// Raw 64-bit wire value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Integer seconds half.
    pub const fn seconds(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// Fractional half.
    pub const fn fraction(self) -> u32 {
        self.0 as u32
    }

    /// True when the timestamp is the all-zero unspecified value.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Convert to seconds as a floating-point inspection helper.
    pub fn as_seconds(self) -> f64 {
        f64::from(self.seconds()) + f64::from(self.fraction()) / 4_294_967_296.0
    }
}

impl From<u64> for NtpTimestamp {
    fn from(raw: u64) -> Self {
        Self::from_raw(raw)
    }
}

/// Pack NTP Leap Indicator, Version, and Mode into the first header octet.
pub fn ntp_pack_first_octet(
    leap_indicator: NtpLeapIndicator,
    version: NtpVersion,
    mode: NtpMode,
) -> u8 {
    (leap_indicator.first_octet_bits() << NTP_FIRST_OCTET_LI_SHIFT)
        | (version.first_octet_bits() << NTP_FIRST_OCTET_VERSION_SHIFT)
        | (mode.first_octet_bits() << NTP_FIRST_OCTET_MODE_SHIFT)
}

/// Parse the first NTP header octet into Leap Indicator, Version, and Mode.
pub fn ntp_parse_first_octet(first_octet: u8) -> (NtpLeapIndicator, NtpVersion, NtpMode) {
    let leap_indicator = (first_octet & NTP_FIRST_OCTET_LI_MASK) >> NTP_FIRST_OCTET_LI_SHIFT;
    let version = (first_octet & NTP_FIRST_OCTET_VERSION_MASK) >> NTP_FIRST_OCTET_VERSION_SHIFT;
    let mode = (first_octet & NTP_FIRST_OCTET_MODE_MASK) >> NTP_FIRST_OCTET_MODE_SHIFT;

    (
        NtpLeapIndicator::from_wire(leap_indicator),
        NtpVersion::from_wire(version),
        NtpMode::from_wire(mode),
    )
}

/// Raw-preserving legacy NTP MAC tail.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NtpLegacyMac {
    bytes: Vec<u8>,
}

impl NtpLegacyMac {
    /// Build from raw tail bytes.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }

    /// Build from a key identifier and raw digest bytes.
    pub fn from_key_id_and_digest(key_id: u32, digest: impl AsRef<[u8]>) -> Self {
        let mut bytes = Vec::with_capacity(NTP_LEGACY_MAC_KEY_ID_LEN + digest.as_ref().len());
        bytes.extend_from_slice(&key_id.to_be_bytes());
        bytes.extend_from_slice(digest.as_ref());
        Self { bytes }
    }

    /// Borrow the raw MAC bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the key identifier when the tail is at least four octets.
    pub fn key_id(&self) -> Option<u32> {
        if self.bytes.len() < NTP_LEGACY_MAC_KEY_ID_LEN {
            return None;
        }
        Some(u32::from_be_bytes([
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
        ]))
    }

    /// Return the digest bytes after the key identifier.
    pub fn digest(&self) -> &[u8] {
        if self.bytes.len() <= NTP_LEGACY_MAC_KEY_ID_LEN {
            &[]
        } else {
            &self.bytes[NTP_LEGACY_MAC_KEY_ID_LEN..]
        }
    }

    /// Tail length in octets.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the tail is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// NTP packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ntp {
    leap_indicator: Field<NtpLeapIndicator>,
    version: Field<NtpVersion>,
    mode: Field<NtpMode>,
    stratum: Field<NtpStratum>,
    poll: Field<i8>,
    precision: Field<i8>,
    root_delay: Field<NtpShortFormat>,
    root_dispersion: Field<NtpShortFormat>,
    reference_id: Field<NtpReferenceId>,
    reference_timestamp: Field<NtpTimestamp>,
    origin_timestamp: Field<NtpTimestamp>,
    receive_timestamp: Field<NtpTimestamp>,
    transmit_timestamp: Field<NtpTimestamp>,
    extension_fields: Vec<NtpExtensionField>,
    legacy_mac: Option<NtpLegacyMac>,
}

impl Ntp {
    /// Create a documentation-safe NTP client-shaped packet.
    pub fn new() -> Self {
        Self {
            leap_indicator: Field::defaulted(NtpLeapIndicator::default()),
            version: Field::defaulted(NtpVersion::default()),
            mode: Field::defaulted(NtpMode::default()),
            stratum: Field::defaulted(NtpStratum::default()),
            poll: Field::defaulted(NTP_DEFAULT_POLL),
            precision: Field::defaulted(NTP_DEFAULT_PRECISION),
            root_delay: Field::defaulted(NtpShortFormat::from_raw(NTP_DEFAULT_ROOT_DELAY)),
            root_dispersion: Field::defaulted(NtpShortFormat::from_raw(
                NTP_DEFAULT_ROOT_DISPERSION,
            )),
            reference_id: Field::defaulted(NtpReferenceId::from_bytes(NTP_DEFAULT_REFERENCE_ID)),
            reference_timestamp: Field::defaulted(NtpTimestamp::from_raw(
                NTP_DEFAULT_REFERENCE_TIMESTAMP,
            )),
            origin_timestamp: Field::defaulted(NtpTimestamp::from_raw(
                NTP_DEFAULT_ORIGIN_TIMESTAMP,
            )),
            receive_timestamp: Field::defaulted(NtpTimestamp::from_raw(
                NTP_DEFAULT_RECEIVE_TIMESTAMP,
            )),
            transmit_timestamp: Field::defaulted(NtpTimestamp::from_raw(
                NTP_DEFAULT_TRANSMIT_TIMESTAMP,
            )),
            extension_fields: Vec::new(),
            legacy_mac: None,
        }
    }

    /// Build a client-mode NTP request shape.
    pub fn client_request() -> Self {
        Self::new().mode(NtpMode::Client)
    }

    /// Build a client-mode NTP request shape.
    pub fn client() -> Self {
        Self::client_request()
    }

    /// Build a server-mode NTP response shape.
    pub fn server_response() -> Self {
        Self::new()
            .mode(NtpMode::Server)
            .stratum(NTP_STRATUM_PRIMARY)
    }

    /// Build a server-mode NTP response shape.
    pub fn server() -> Self {
        Self::server_response()
    }

    /// UDP header for the NTP service port.
    pub fn udp() -> Udp {
        Udp::ntp()
    }

    /// Build a symmetric-active NTP packet shape.
    pub fn symmetric_active() -> Self {
        Self::new().mode(NtpMode::SymmetricActive)
    }

    /// Build a broadcast-mode NTP packet shape.
    pub fn broadcast() -> Self {
        Self::new().mode(NtpMode::Broadcast)
    }

    /// Build a stratum-0 Kiss-o'-Death server response.
    pub fn kiss_o_death(code: [u8; NTP_REFERENCE_ID_LEN]) -> Self {
        Self::new()
            .mode(NtpMode::Server)
            .stratum(NTP_STRATUM_UNSPECIFIED)
            .reference_id(NtpReferenceId::kiss_o_death(code))
    }

    /// Decode a standalone NTP UDP payload.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        decode_ntp_payload(bytes)
    }

    /// Set the Leap Indicator.
    pub fn leap_indicator(mut self, value: impl Into<NtpLeapIndicator>) -> Self {
        self.leap_indicator.set_user(value.into());
        self
    }

    /// Set the version wrapper.
    pub fn version(mut self, value: impl Into<NtpVersion>) -> Self {
        self.version.set_user(value.into());
        self
    }

    /// Set the version from a raw wire value.
    pub fn version_value(self, value: u8) -> Self {
        self.version(NtpVersion::from_wire(value))
    }

    /// Set the mode wrapper.
    pub fn mode(mut self, value: impl Into<NtpMode>) -> Self {
        self.mode.set_user(value.into());
        self
    }

    /// Set the stratum from a raw wire value.
    pub fn stratum(mut self, value: u8) -> Self {
        self.stratum.set_user(NtpStratum::from_wire(value));
        self
    }

    /// Set the signed poll exponent.
    pub fn poll(mut self, value: i8) -> Self {
        self.poll.set_user(value);
        self
    }

    /// Set the signed precision exponent.
    pub fn precision(mut self, value: i8) -> Self {
        self.precision.set_user(value);
        self
    }

    /// Set the root delay fixed-point value.
    pub fn root_delay(mut self, value: impl Into<NtpShortFormat>) -> Self {
        self.root_delay.set_user(value.into());
        self
    }

    /// Set the root delay raw value.
    pub fn root_delay_raw(self, value: u32) -> Self {
        self.root_delay(NtpShortFormat::from_raw(value))
    }

    /// Set the root dispersion fixed-point value.
    pub fn root_dispersion(mut self, value: impl Into<NtpShortFormat>) -> Self {
        self.root_dispersion.set_user(value.into());
        self
    }

    /// Set the root dispersion raw value.
    pub fn root_dispersion_raw(self, value: u32) -> Self {
        self.root_dispersion(NtpShortFormat::from_raw(value))
    }

    /// Set the reference identifier.
    pub fn reference_id(mut self, value: impl Into<NtpReferenceId>) -> Self {
        self.reference_id.set_user(value.into());
        self
    }

    /// Set the reference timestamp.
    pub fn reference_timestamp(mut self, value: impl Into<NtpTimestamp>) -> Self {
        self.reference_timestamp.set_user(value.into());
        self
    }

    /// Set the origin timestamp.
    pub fn origin_timestamp(mut self, value: impl Into<NtpTimestamp>) -> Self {
        self.origin_timestamp.set_user(value.into());
        self
    }

    /// Set the receive timestamp.
    pub fn receive_timestamp(mut self, value: impl Into<NtpTimestamp>) -> Self {
        self.receive_timestamp.set_user(value.into());
        self
    }

    /// Set the transmit timestamp.
    pub fn transmit_timestamp(mut self, value: impl Into<NtpTimestamp>) -> Self {
        self.transmit_timestamp.set_user(value.into());
        self
    }

    /// Append one extension field.
    pub fn extension_field(mut self, field: NtpExtensionField) -> Self {
        self.extension_fields.push(field);
        self
    }

    /// Replace extension fields.
    pub fn extension_fields(mut self, fields: impl Into<Vec<NtpExtensionField>>) -> Self {
        self.extension_fields = fields.into();
        self
    }

    /// Set a raw legacy MAC tail.
    pub fn legacy_mac(mut self, mac: NtpLegacyMac) -> Self {
        self.legacy_mac = Some(mac);
        self
    }

    /// Remove the legacy MAC tail.
    pub fn without_legacy_mac(mut self) -> Self {
        self.legacy_mac = None;
        self
    }

    /// Effective Leap Indicator value.
    pub fn leap_indicator_value(&self) -> NtpLeapIndicator {
        field_value(&self.leap_indicator, NtpLeapIndicator::default())
    }

    /// Effective version value.
    pub fn version_value_effective(&self) -> NtpVersion {
        field_value(&self.version, NtpVersion::default())
    }

    /// Effective mode value.
    pub fn mode_value(&self) -> NtpMode {
        field_value(&self.mode, NtpMode::default())
    }

    /// Effective stratum value.
    pub fn stratum_value(&self) -> NtpStratum {
        field_value(&self.stratum, NtpStratum::default())
    }

    /// Effective poll exponent.
    pub fn poll_value(&self) -> i8 {
        field_value(&self.poll, NTP_DEFAULT_POLL)
    }

    /// Effective precision exponent.
    pub fn precision_value(&self) -> i8 {
        field_value(&self.precision, NTP_DEFAULT_PRECISION)
    }

    /// Effective root delay value.
    pub fn root_delay_value(&self) -> NtpShortFormat {
        field_value(
            &self.root_delay,
            NtpShortFormat::from_raw(NTP_DEFAULT_ROOT_DELAY),
        )
    }

    /// Effective root dispersion value.
    pub fn root_dispersion_value(&self) -> NtpShortFormat {
        field_value(
            &self.root_dispersion,
            NtpShortFormat::from_raw(NTP_DEFAULT_ROOT_DISPERSION),
        )
    }

    /// Effective reference identifier.
    pub fn reference_id_value(&self) -> NtpReferenceId {
        field_value(
            &self.reference_id,
            NtpReferenceId::from_bytes(NTP_DEFAULT_REFERENCE_ID),
        )
    }

    /// Effective reference timestamp.
    pub fn reference_timestamp_value(&self) -> NtpTimestamp {
        field_value(
            &self.reference_timestamp,
            NtpTimestamp::from_raw(NTP_DEFAULT_REFERENCE_TIMESTAMP),
        )
    }

    /// Effective origin timestamp.
    pub fn origin_timestamp_value(&self) -> NtpTimestamp {
        field_value(
            &self.origin_timestamp,
            NtpTimestamp::from_raw(NTP_DEFAULT_ORIGIN_TIMESTAMP),
        )
    }

    /// Effective receive timestamp.
    pub fn receive_timestamp_value(&self) -> NtpTimestamp {
        field_value(
            &self.receive_timestamp,
            NtpTimestamp::from_raw(NTP_DEFAULT_RECEIVE_TIMESTAMP),
        )
    }

    /// Effective transmit timestamp.
    pub fn transmit_timestamp_value(&self) -> NtpTimestamp {
        field_value(
            &self.transmit_timestamp,
            NtpTimestamp::from_raw(NTP_DEFAULT_TRANSMIT_TIMESTAMP),
        )
    }

    /// Borrow extension fields.
    pub fn extension_fields_value(&self) -> &[NtpExtensionField] {
        &self.extension_fields
    }

    /// Borrow the legacy MAC tail, when present.
    pub fn legacy_mac_value(&self) -> Option<&NtpLegacyMac> {
        self.legacy_mac.as_ref()
    }

    /// First-octet value that will be serialized.
    pub fn first_octet_value(&self) -> u8 {
        ntp_pack_first_octet(
            self.leap_indicator_value(),
            self.version_value_effective(),
            self.mode_value(),
        )
    }

    fn encoded_tail_len(&self) -> usize {
        let mut len = 0;
        for (index, field) in self.extension_fields.iter().enumerate() {
            let last_without_mac =
                index + 1 == self.extension_fields.len() && self.legacy_mac.is_none();
            len += field.encoded_len(last_without_mac);
        }
        if let Some(mac) = &self.legacy_mac {
            len += mac.len();
        }
        len
    }

    fn serialize_header(&self, out: &mut Vec<u8>) {
        out.push(self.first_octet_value());
        out.push(self.stratum_value().wire_value());
        out.push(self.poll_value() as u8);
        out.push(self.precision_value() as u8);
        out.extend_from_slice(&self.root_delay_value().raw().to_be_bytes());
        out.extend_from_slice(&self.root_dispersion_value().raw().to_be_bytes());
        out.extend_from_slice(&self.reference_id_value().bytes());
        out.extend_from_slice(&self.reference_timestamp_value().raw().to_be_bytes());
        out.extend_from_slice(&self.origin_timestamp_value().raw().to_be_bytes());
        out.extend_from_slice(&self.receive_timestamp_value().raw().to_be_bytes());
        out.extend_from_slice(&self.transmit_timestamp_value().raw().to_be_bytes());
    }
}

impl Default for Ntp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ntp {
    fn name(&self) -> &'static str {
        "Ntp"
    }

    fn summary(&self) -> String {
        let stratum = self.stratum_value();
        let reference_id = self.reference_id_value();
        format!(
            "Ntp(li={}, version={}, mode={}, stratum={}({}), refid={}, extensions={}, tail={})",
            self.leap_indicator_value().summary_label(),
            self.version_value_effective().summary_label(),
            self.mode_value().summary_label(),
            stratum.value(),
            stratum.label(),
            reference_id.label_for_stratum(stratum),
            self.extension_fields.len(),
            ntp_tail_status(self.extension_fields.len(), self.legacy_mac.is_some())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let stratum = self.stratum_value();
        let reference_id = self.reference_id_value();
        let mut fields = vec![
            ("first_octet", format!("0x{:02x}", self.first_octet_value())),
            ("leap_indicator", self.leap_indicator_value().label()),
            ("version", self.version_value_effective().label()),
            ("mode", self.mode_value().label()),
            (
                "stratum",
                format!("{} ({})", stratum.value(), stratum.label()),
            ),
            ("poll", self.poll_value().to_string()),
            ("precision", self.precision_value().to_string()),
            (
                "root_delay",
                format!("0x{:08x}", self.root_delay_value().raw()),
            ),
            (
                "root_dispersion",
                format!("0x{:08x}", self.root_dispersion_value().raw()),
            ),
            ("reference_id", reference_id.label_for_stratum(stratum)),
            (
                "reference_timestamp",
                format!("0x{:016x}", self.reference_timestamp_value().raw()),
            ),
            (
                "origin_timestamp",
                format!("0x{:016x}", self.origin_timestamp_value().raw()),
            ),
            (
                "receive_timestamp",
                format!("0x{:016x}", self.receive_timestamp_value().raw()),
            ),
            (
                "transmit_timestamp",
                format!("0x{:016x}", self.transmit_timestamp_value().raw()),
            ),
            ("extensions", self.extension_fields.len().to_string()),
            ("extension_count", self.extension_fields.len().to_string()),
            (
                "legacy_mac_len",
                self.legacy_mac
                    .as_ref()
                    .map_or(0, NtpLegacyMac::len)
                    .to_string(),
            ),
            (
                "mac_status",
                ntp_legacy_mac_status(self.legacy_mac.as_ref()),
            ),
        ];

        for (index, extension) in self.extension_fields.iter().enumerate() {
            let last_without_mac =
                index + 1 == self.extension_fields.len() && self.legacy_mac.is_none();
            fields.push((
                "extension",
                ntp_extension_inspection(extension, last_without_mac),
            ));
        }

        fields
    }

    fn encoded_len(&self) -> usize {
        NTP_FIXED_HEADER_LEN + self.encoded_tail_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.serialize_header(out);
        for (index, field) in self.extension_fields.iter().enumerate() {
            let last_without_mac =
                index + 1 == self.extension_fields.len() && self.legacy_mac.is_none();
            field.compile(last_without_mac, out)?;
        }
        if let Some(mac) = &self.legacy_mac {
            out.extend_from_slice(mac.bytes());
        }
        Ok(())
    }

    impl_layer_object!(Ntp);
}

impl_layer_div!(Ntp);

/// Decode a standalone NTP UDP payload.
pub fn decode_ntp_payload(bytes: &[u8]) -> Result<Ntp> {
    if bytes.len() < NTP_FIXED_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            NTP_HEADER_CONTEXT,
            NTP_FIXED_HEADER_LEN,
            bytes.len(),
        ));
    }

    let (leap_indicator, version, mode) = ntp_parse_first_octet(bytes[0]);
    let stratum = NtpStratum::from_wire(bytes[1]);
    let poll = bytes[2] as i8;
    let precision = bytes[3] as i8;
    let root_delay =
        NtpShortFormat::from_raw(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    let root_dispersion = NtpShortFormat::from_raw(u32::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11],
    ]));
    let reference_id = NtpReferenceId::from_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let reference_timestamp = read_timestamp(&bytes[16..24]);
    let origin_timestamp = read_timestamp(&bytes[24..32]);
    let receive_timestamp = read_timestamp(&bytes[32..40]);
    let transmit_timestamp = read_timestamp(&bytes[40..48]);
    let (extension_fields, legacy_mac) = parse_ntp_tail(&bytes[NTP_FIXED_HEADER_LEN..])?;

    Ok(Ntp {
        leap_indicator: Field::user(leap_indicator),
        version: Field::user(version),
        mode: Field::user(mode),
        stratum: Field::user(stratum),
        poll: Field::user(poll),
        precision: Field::user(precision),
        root_delay: Field::user(root_delay),
        root_dispersion: Field::user(root_dispersion),
        reference_id: Field::user(reference_id),
        reference_timestamp: Field::user(reference_timestamp),
        origin_timestamp: Field::user(origin_timestamp),
        receive_timestamp: Field::user(receive_timestamp),
        transmit_timestamp: Field::user(transmit_timestamp),
        extension_fields,
        legacy_mac,
    })
}

/// Conservative UDP/123 shape gate for built-in registry dispatch.
pub fn looks_like_ntp_payload(bytes: &[u8]) -> bool {
    if bytes.len() < NTP_FIXED_HEADER_LEN {
        return false;
    }

    let (_, version, mode) = ntp_parse_first_octet(bytes[0]);
    if !(NTP_VERSION_1..=NTP_VERSION_4).contains(&version.value()) {
        return false;
    }
    if mode.value() == NTP_MODE_RESERVED {
        return false;
    }

    ntp_tail_shape_is_plausible(&bytes[NTP_FIXED_HEADER_LEN..])
}

/// Append a decoded NTP layer to an existing packet.
pub fn append_ntp_packet(packet: Packet, payload: &[u8]) -> Result<Packet> {
    Ok(packet.push(Ntp::decode(payload)?))
}

/// UDP header for an NTP client request.
pub fn ntp_client_udp() -> Udp {
    Ntp::udp()
}

/// UDP header for an NTP server response.
pub fn ntp_server_udp() -> Udp {
    Ntp::udp()
}

/// Documentation-safe IPv4/UDP/NTP client request packet.
pub fn ntp_ipv4_client_request(source: Ipv4Addr, destination: Ipv4Addr) -> Packet {
    Ipv4::new().src(source).dst(destination) / ntp_client_udp() / Ntp::client()
}

/// Documentation-safe IPv4/UDP/NTP client request packet using documentation addresses.
pub fn ntp_ipv4_documentation_client_request() -> Packet {
    ntp_ipv4_client_request(NTP_DOCUMENTATION_IPV4_CLIENT, NTP_DOCUMENTATION_IPV4_SERVER)
}

/// Documentation-safe IPv6/UDP/NTP client request packet.
pub fn ntp_ipv6_client_request(source: Ipv6Addr, destination: Ipv6Addr) -> Packet {
    Ipv6::new().src(source).dst(destination) / ntp_client_udp() / Ntp::client()
}

/// Documentation-safe IPv6/UDP/NTP client request packet using documentation addresses.
pub fn ntp_ipv6_documentation_client_request() -> Packet {
    ntp_ipv6_client_request(NTP_DOCUMENTATION_IPV6_CLIENT, NTP_DOCUMENTATION_IPV6_SERVER)
}

fn field_value<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn ntp_tail_status(extension_count: usize, has_legacy_mac: bool) -> &'static str {
    match (extension_count == 0, has_legacy_mac) {
        (true, false) => "none",
        (false, false) => "extensions",
        (true, true) => "legacy-mac",
        (false, true) => "extensions+legacy-mac",
    }
}

fn ntp_extension_inspection(extension: &NtpExtensionField, last_without_mac: bool) -> String {
    let meta = extension.registry_meta();
    let declared_len = extension
        .declared_length_value()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "auto".to_string());

    format!(
        "type=0x{:04x} label={} status={} declared_len={} encoded_len={} value_len={}",
        extension.field_type(),
        meta.label,
        meta.status.label(),
        declared_len,
        extension.encoded_len(last_without_mac),
        extension.value().len()
    )
}

fn ntp_legacy_mac_status(mac: Option<&NtpLegacyMac>) -> String {
    match mac {
        Some(mac) => format!(
            "legacy-mac digest_len={} total_len={}",
            mac.digest().len(),
            mac.len()
        ),
        None => "none".to_string(),
    }
}

fn read_timestamp(bytes: &[u8]) -> NtpTimestamp {
    NtpTimestamp::from_raw(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn parse_ntp_tail(tail: &[u8]) -> Result<(Vec<NtpExtensionField>, Option<NtpLegacyMac>)> {
    let mut fields = Vec::new();
    let mut offset = 0;

    while offset < tail.len() {
        let remaining = &tail[offset..];
        if !fields.is_empty() && is_plausible_legacy_mac_len(remaining.len()) {
            return Ok((fields, Some(NtpLegacyMac::from_bytes(remaining))));
        }
        if remaining.len() < NTP_EXTENSION_FIELD_HEADER_LEN {
            let context = if fields.is_empty() {
                NTP_EXTENSION_CONTEXT
            } else {
                NTP_MAC_CONTEXT
            };
            let required = if fields.is_empty() {
                NTP_EXTENSION_FIELD_HEADER_LEN
            } else {
                NTP_LEGACY_MAC_KEY_ID_LEN
            };
            return Err(CrafterError::buffer_too_short(
                context,
                required,
                remaining.len(),
            ));
        }

        let field_type = u16::from_be_bytes([remaining[0], remaining[1]]);
        let declared_len = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;
        let meta = ntp_extension_field_type_meta(field_type);
        let known_extension = meta.status != NtpRegistryStatus::Unassigned;

        if let Err(err) = validate_extension_length(declared_len, remaining.len()) {
            if known_extension || !is_plausible_legacy_mac_len(remaining.len()) {
                return Err(err);
            }
            return Ok((fields, Some(NtpLegacyMac::from_bytes(remaining))));
        }

        let final_without_mac = offset + declared_len == tail.len();
        if final_without_mac {
            if let Err(err) = validate_final_extension_without_mac_length(declared_len) {
                if known_extension || !is_plausible_legacy_mac_len(remaining.len()) {
                    return Err(err);
                }
                return Ok((fields, Some(NtpLegacyMac::from_bytes(remaining))));
            }
        }

        let value = remaining[NTP_EXTENSION_FIELD_HEADER_LEN..declared_len].to_vec();
        fields.push(NtpExtensionField::from_decoded(
            field_type,
            declared_len as u16,
            value,
        ));
        offset += declared_len;
    }

    Ok((fields, None))
}

fn ntp_tail_shape_is_plausible(tail: &[u8]) -> bool {
    if tail.is_empty() {
        return true;
    }
    if matches!(tail.len(), 4 | 20 | 24) {
        return true;
    }

    let mut offset = 0;
    while offset < tail.len() {
        let remaining = &tail[offset..];
        if offset > 0 && is_plausible_legacy_mac_len(remaining.len()) {
            return true;
        }
        if remaining.len() < NTP_EXTENSION_FIELD_HEADER_LEN {
            return false;
        }
        let declared_len = u16::from_be_bytes([remaining[2], remaining[3]]) as usize;
        if !is_valid_extension_length(declared_len, remaining.len()) {
            return false;
        }
        if offset + declared_len == tail.len()
            && !is_valid_final_extension_without_mac_length(declared_len)
        {
            return false;
        }
        offset += declared_len;
    }
    true
}

fn is_plausible_legacy_mac_len(len: usize) -> bool {
    matches!(len, 4 | 20 | 24)
}

#[cfg(test)]
mod tests {
    use super::super::extension::NTP_EXTENSION_LENGTH_CONTEXT;
    use super::*;
    use crate::field::FieldState;
    use crate::protocols::ntp::NtpRegistryStatus;

    fn ntp_parse_error_base_header() -> Vec<u8> {
        let mut bytes = vec![NTP_DEFAULT_FIRST_OCTET];
        bytes.resize(NTP_FIXED_HEADER_LEN, 0);
        bytes
    }

    fn ntp_parse_error_with_tail(tail: &[u8]) -> Vec<u8> {
        let mut bytes = ntp_parse_error_base_header();
        bytes.extend_from_slice(tail);
        bytes
    }

    #[test]
    fn ntp_parse_errors_report_structured_fixed_header_and_tail_contexts() {
        match decode_ntp_payload(&[0u8; NTP_FIXED_HEADER_LEN - 1]).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, NTP_HEADER_CONTEXT);
                assert_eq!(required, NTP_FIXED_HEADER_LEN);
                assert_eq!(available, NTP_FIXED_HEADER_LEN - 1);
            }
            other => panic!("unexpected fixed header error: {other:?}"),
        }

        let truncated_extension_header = ntp_parse_error_with_tail(&[0x01, 0x04, 0x00]);
        match decode_ntp_payload(&truncated_extension_header).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, NTP_EXTENSION_CONTEXT);
                assert_eq!(required, NTP_EXTENSION_FIELD_HEADER_LEN);
                assert_eq!(available, 3);
            }
            other => panic!("unexpected extension header error: {other:?}"),
        }

        let short_extension_length = ntp_parse_error_with_tail(&[0x01, 0x04, 0x00, 0x0c]);
        match decode_ntp_payload(&short_extension_length).unwrap_err() {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, NTP_EXTENSION_LENGTH_CONTEXT);
            }
            other => panic!("unexpected extension length error: {other:?}"),
        }

        let truncated_extension_body =
            ntp_parse_error_with_tail(&[0x01, 0x04, 0x00, 0x10, 0xaa, 0xbb, 0xcc, 0xdd]);
        match decode_ntp_payload(&truncated_extension_body).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, NTP_EXTENSION_CONTEXT);
                assert_eq!(required, NTP_EXTENSION_FIELD_MIN_LEN);
                assert_eq!(available, 8);
            }
            other => panic!("unexpected extension body error: {other:?}"),
        }

        let mut extension_then_truncated_mac = vec![0x01, 0x04, 0x00, 0x10];
        extension_then_truncated_mac.resize(NTP_EXTENSION_FIELD_MIN_LEN, 0);
        extension_then_truncated_mac.extend_from_slice(&[0xaa, 0xbb]);
        let extension_then_truncated_mac = ntp_parse_error_with_tail(&extension_then_truncated_mac);
        match decode_ntp_payload(&extension_then_truncated_mac).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, NTP_MAC_CONTEXT);
                assert_eq!(required, NTP_LEGACY_MAC_KEY_ID_LEN);
                assert_eq!(available, 2);
            }
            other => panic!("unexpected MAC tail error: {other:?}"),
        }
    }

    #[test]
    fn ntp_standalone_decode_parses_extension_and_mac_tail() -> Result<()> {
        let extension = NtpExtensionField::nts_cookie([0xaa, 0xbb]);
        let mut decoded_extension_value = vec![0xaa, 0xbb];
        decoded_extension_value.resize(
            NTP_EXTENSION_FIELD_MIN_LEN - NTP_EXTENSION_FIELD_HEADER_LEN,
            0,
        );
        let decoded_extension = NtpExtensionField::nts_cookie(decoded_extension_value)
            .declared_length(NTP_EXTENSION_FIELD_MIN_LEN as u16);
        let legacy_mac = NtpLegacyMac::from_key_id_and_digest(0x0102_0304, [0xcc; 16]);
        let bytes = Packet::from_layer(
            Ntp::server()
                .poll(6)
                .precision(-20)
                .root_delay_raw(0x0001_8000)
                .root_dispersion_raw(0x0002_4000)
                .reference_id(NtpReferenceId::from_bytes(*b"GPS\0"))
                .reference_timestamp(0x0102_0304_0506_0708u64)
                .origin_timestamp(0x1112_1314_1516_1718u64)
                .receive_timestamp(0x2122_2324_2526_2728u64)
                .transmit_timestamp(0x3132_3334_3536_3738u64)
                .extension_field(extension.clone())
                .legacy_mac(legacy_mac.clone()),
        )
        .compile()?
        .into_bytes();

        let ntp = Ntp::decode(&bytes)?;

        assert_eq!(ntp.mode_value(), NtpMode::Server);
        assert_eq!(
            ntp.stratum_value(),
            NtpStratum::from_wire(NTP_STRATUM_PRIMARY)
        );
        assert_eq!(ntp.poll_value(), 6);
        assert_eq!(ntp.precision_value(), -20);
        assert_eq!(ntp.root_delay_value().raw(), 0x0001_8000);
        assert_eq!(ntp.root_dispersion_value().raw(), 0x0002_4000);
        assert_eq!(ntp.reference_id_value().bytes(), *b"GPS\0");
        assert_eq!(ntp.reference_timestamp_value().raw(), 0x0102_0304_0506_0708);
        assert_eq!(ntp.origin_timestamp_value().raw(), 0x1112_1314_1516_1718);
        assert_eq!(ntp.receive_timestamp_value().raw(), 0x2122_2324_2526_2728);
        assert_eq!(ntp.transmit_timestamp_value().raw(), 0x3132_3334_3536_3738);
        assert_eq!(ntp.extension_fields_value(), &[decoded_extension]);
        assert_eq!(ntp.legacy_mac_value(), Some(&legacy_mac));
        assert_eq!(decode_ntp_payload(&bytes)?, ntp);
        assert_eq!(crate::protocols::ntp::decode_ntp(&bytes)?, ntp);

        Ok(())
    }

    #[test]
    fn ntp_standalone_decode_reports_structured_errors() {
        match Ntp::decode(&[0u8; NTP_FIXED_HEADER_LEN - 1]).unwrap_err() {
            CrafterError::BufferTooShort {
                context,
                required,
                available,
            } => {
                assert_eq!(context, NTP_HEADER_CONTEXT);
                assert_eq!(required, NTP_FIXED_HEADER_LEN);
                assert_eq!(available, NTP_FIXED_HEADER_LEN - 1);
            }
            other => panic!("unexpected fixed header error: {other:?}"),
        }

        let short_known_extension = ntp_parse_error_with_tail(&[0x01, 0x04, 0x00, 0x0c]);
        match Ntp::decode(&short_known_extension).unwrap_err() {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, NTP_EXTENSION_LENGTH_CONTEXT);
            }
            other => panic!("unexpected extension length error: {other:?}"),
        }
    }

    #[test]
    fn ntp_leap_indicator_values_and_labels_match_source_backed_codepoints() {
        let cases = [
            (
                NtpLeapIndicator::NoWarning,
                0,
                "no-warning",
                NtpRegistryStatus::Assigned,
            ),
            (
                NtpLeapIndicator::LastMinute61Seconds,
                1,
                "last-minute-61-seconds",
                NtpRegistryStatus::Assigned,
            ),
            (
                NtpLeapIndicator::LastMinute59Seconds,
                2,
                "last-minute-59-seconds",
                NtpRegistryStatus::Assigned,
            ),
            (
                NtpLeapIndicator::AlarmUnsynchronized,
                3,
                "alarm-unsynchronized",
                NtpRegistryStatus::Assigned,
            ),
        ];

        for (leap_indicator, value, label, status) in cases {
            assert_eq!(NtpLeapIndicator::from_wire(value), leap_indicator);
            assert_eq!(leap_indicator.value(), value);
            assert_eq!(leap_indicator.wire_value(), value);
            assert_eq!(leap_indicator.first_octet_bits(), value);
            assert_eq!(u8::from(leap_indicator), value);
            assert_eq!(leap_indicator.label(), label);
            assert_eq!(leap_indicator.summary_label(), label);
            assert_eq!(leap_indicator.to_string(), label);

            let meta = leap_indicator.registry_meta();
            assert_eq!(meta.value, u32::from(value));
            assert_eq!(meta.label, label);
            assert_eq!(meta.status, status);
        }

        assert_eq!(NtpLeapIndicator::default(), NtpLeapIndicator::NoWarning);
        assert!(NtpLeapIndicator::AlarmUnsynchronized.is_alarm_unsynchronized());
        assert!(!NtpLeapIndicator::NoWarning.is_alarm_unsynchronized());
    }

    #[test]
    fn ntp_leap_indicator_unknown_caller_values_are_summary_safe() {
        let caller_value = NtpLeapIndicator::Unknown(0x2a);

        assert_eq!(caller_value.value(), 0x2a);
        assert_eq!(caller_value.wire_value(), 0x2a);
        assert_eq!(caller_value.first_octet_bits(), 0x2a & NTP_LI_VALUE_MASK);
        assert_eq!(u8::from(caller_value), 0x2a);
        assert_eq!(caller_value.label(), "leap-indicator-42");
        assert_eq!(caller_value.summary_label(), "leap-indicator-42");
        assert!(!caller_value.to_string().chars().any(char::is_whitespace));

        let meta = caller_value.registry_meta();
        assert_eq!(meta.value, 0x2a);
        assert_eq!(meta.status, NtpRegistryStatus::Unknown);
    }

    #[test]
    fn ntp_version_mode_version_values_and_labels_preserve_wire_values() {
        let cases = [
            (0, "version-0"),
            (1, "ntp-v1"),
            (2, "ntp-v2"),
            (3, "ntp-v3"),
            (4, "ntp-v4"),
            (5, "version-5"),
            (6, "version-6"),
            (7, "version-7"),
        ];

        for (value, label) in cases {
            let version = NtpVersion::from_wire(value);
            assert_eq!(version.value(), value);
            assert_eq!(version.wire_value(), value);
            assert_eq!(version.first_octet_bits(), value);
            assert_eq!(u8::from(version), value);
            assert_eq!(version.label(), label);
            assert_eq!(version.summary_label(), label);
            assert_eq!(version.to_string(), label);
        }

        assert_eq!(NtpVersion::default(), NtpVersion::current());
        assert!(NtpVersion::current().is_current());
    }

    #[test]
    fn ntp_version_mode_modes_match_source_backed_codepoints() {
        let cases = [
            (
                NtpMode::Reserved,
                0,
                "reserved",
                NtpRegistryStatus::Reserved,
            ),
            (
                NtpMode::SymmetricActive,
                1,
                "symmetric-active",
                NtpRegistryStatus::Assigned,
            ),
            (
                NtpMode::SymmetricPassive,
                2,
                "symmetric-passive",
                NtpRegistryStatus::Assigned,
            ),
            (NtpMode::Client, 3, "client", NtpRegistryStatus::Assigned),
            (NtpMode::Server, 4, "server", NtpRegistryStatus::Assigned),
            (
                NtpMode::Broadcast,
                5,
                "broadcast",
                NtpRegistryStatus::Assigned,
            ),
            (NtpMode::Control, 6, "control", NtpRegistryStatus::Assigned),
            (
                NtpMode::PrivateUse,
                7,
                "private-use",
                NtpRegistryStatus::PrivateOrExperimental,
            ),
        ];

        for (mode, value, label, status) in cases {
            assert_eq!(NtpMode::from_wire(value), mode);
            assert_eq!(mode.value(), value);
            assert_eq!(mode.wire_value(), value);
            assert_eq!(mode.first_octet_bits(), value);
            assert_eq!(u8::from(mode), value);
            assert_eq!(mode.label(), label);
            assert_eq!(mode.summary_label(), label);
            assert_eq!(mode.to_string(), label);

            let meta = mode.registry_meta();
            assert_eq!(meta.value, u32::from(value));
            assert_eq!(meta.label, label);
            assert_eq!(meta.status, status);
        }

        assert_eq!(NtpMode::default(), NtpMode::Client);
    }

    #[test]
    fn ntp_version_mode_unknown_or_future_values_are_summary_safe() {
        let future_version = NtpVersion::from_wire(7);
        assert_eq!(future_version.value(), 7);
        assert_eq!(future_version.label(), "version-7");
        assert!(!future_version.to_string().chars().any(char::is_whitespace));

        let caller_mode = NtpMode::Unknown(0x2a);
        assert_eq!(caller_mode.value(), 0x2a);
        assert_eq!(caller_mode.wire_value(), 0x2a);
        assert_eq!(caller_mode.first_octet_bits(), 0x2a & NTP_MODE_VALUE_MASK);
        assert_eq!(u8::from(caller_mode), 0x2a);
        assert_eq!(caller_mode.label(), "mode-42");
        assert_eq!(caller_mode.summary_label(), "mode-42");
        assert!(!caller_mode.to_string().chars().any(char::is_whitespace));
    }

    #[test]
    fn ntp_first_octet_packs_and_parses_default_client_shape() {
        let first_octet = ntp_pack_first_octet(
            NtpLeapIndicator::default(),
            NtpVersion::default(),
            NtpMode::default(),
        );

        assert_eq!(first_octet, NTP_DEFAULT_FIRST_OCTET);
        assert_eq!(first_octet, 0x23);

        let (leap_indicator, version, mode) = ntp_parse_first_octet(first_octet);
        assert_eq!(leap_indicator, NtpLeapIndicator::NoWarning);
        assert_eq!(version, NtpVersion::current());
        assert_eq!(mode, NtpMode::Client);
    }

    #[test]
    fn ntp_first_octet_round_trips_every_wire_combination() {
        for first_octet in u8::MIN..=u8::MAX {
            let (leap_indicator, version, mode) = ntp_parse_first_octet(first_octet);

            assert_eq!(
                ntp_pack_first_octet(leap_indicator, version, mode),
                first_octet
            );
            assert_eq!(
                leap_indicator.value(),
                (first_octet & NTP_FIRST_OCTET_LI_MASK) >> NTP_FIRST_OCTET_LI_SHIFT
            );
            assert_eq!(
                version.value(),
                (first_octet & NTP_FIRST_OCTET_VERSION_MASK) >> NTP_FIRST_OCTET_VERSION_SHIFT
            );
            assert_eq!(
                mode.value(),
                (first_octet & NTP_FIRST_OCTET_MODE_MASK) >> NTP_FIRST_OCTET_MODE_SHIFT
            );
        }
    }

    #[test]
    fn ntp_first_octet_masks_caller_values_to_field_widths() {
        let leap_indicator = NtpLeapIndicator::Unknown(0xaa);
        let version = NtpVersion::from_wire(0x0f);
        let mode = NtpMode::Unknown(0x2a);

        assert_eq!(
            ntp_pack_first_octet(leap_indicator, version, mode),
            ((0xaa & NTP_LI_VALUE_MASK) << NTP_FIRST_OCTET_LI_SHIFT)
                | ((0x0f & NTP_VERSION_VALUE_MASK) << NTP_FIRST_OCTET_VERSION_SHIFT)
                | ((0x2a & NTP_MODE_VALUE_MASK) << NTP_FIRST_OCTET_MODE_SHIFT)
        );
        assert_eq!(leap_indicator.wire_value(), 0xaa);
        assert_eq!(version.wire_value(), 0x0f);
        assert_eq!(mode.wire_value(), 0x2a);
    }

    #[test]
    fn ntp_summary_includes_core_fields_reference_id_and_tail_status() {
        let primary = Ntp::server()
            .leap_indicator(NtpLeapIndicator::AlarmUnsynchronized)
            .reference_id(NtpReferenceId::from_bytes([b'G', b'P', b'S', 0]));

        assert_eq!(
            primary.summary(),
            "Ntp(li=alarm-unsynchronized, version=ntp-v4, mode=server, stratum=1(primary), refid=Global Position System, extensions=0, tail=none)"
        );

        let secondary = Ntp::client()
            .stratum(2)
            .reference_id(NtpReferenceId::from_bytes([192, 0, 2, 44]))
            .extension_field(NtpExtensionField::udp_checksum_complement([0xaa, 0xbb]));

        assert_eq!(
            secondary.summary(),
            "Ntp(li=no-warning, version=ntp-v4, mode=client, stratum=2(secondary), refid=refid-0xC000022C, extensions=1, tail=extensions)"
        );
    }

    #[test]
    fn ntp_summary_hides_extension_cookie_and_mac_bytes() {
        let ntp = Ntp::kiss_o_death(*b"RATE")
            .extension_field(NtpExtensionField::nts_cookie([
                0xde, 0xad, 0xbe, 0xef, 0x13, 0x37,
            ]))
            .legacy_mac(NtpLegacyMac::from_key_id_and_digest(
                0x0102_0304,
                [0xcc; 16],
            ));

        let summary = ntp.summary();

        assert_eq!(
            summary,
            "Ntp(li=no-warning, version=ntp-v4, mode=server, stratum=0(unspecified-or-invalid), refid=Rate exceeded, extensions=1, tail=extensions+legacy-mac)"
        );
        assert!(!summary.contains("0x0204"), "{summary}");
        assert!(!summary.contains("deadbeef"), "{summary}");
        assert!(!summary.contains("1337"), "{summary}");
        assert!(!summary.contains("0x01020304"), "{summary}");
        assert!(!summary.contains("cccc"), "{summary}");
    }

    #[test]
    fn ntp_show_fields_include_fixed_header_extension_labels_and_mac_status() {
        let ntp = Ntp::server()
            .leap_indicator(NtpLeapIndicator::AlarmUnsynchronized)
            .version_value(3)
            .poll(6)
            .precision(-20)
            .root_delay_raw(0x0001_8000)
            .root_dispersion_raw(0x0002_4000)
            .reference_id(NtpReferenceId::from_bytes(*b"GPS\0"))
            .reference_timestamp(0xa1a2_a3a4_a5a6_a7a8u64)
            .origin_timestamp(0xb1b2_b3b4_b5b6_b7b8u64)
            .receive_timestamp(0xc1c2_c3c4_c5c6_c7c8u64)
            .transmit_timestamp(0xd1d2_d3d4_d5d6_d7d8u64)
            .extension_field(NtpExtensionField::nts_cookie([
                0xde, 0xad, 0xbe, 0xef, 0x13, 0x37,
            ]))
            .extension_field(NtpExtensionField::udp_checksum_complement([0xaa, 0xbb]))
            .legacy_mac(NtpLegacyMac::from_key_id_and_digest(
                0x0102_0304,
                [0xcc; 16],
            ));

        let show = Packet::from_layer(ntp).show();

        assert!(
            show.contains("leap_indicator: alarm-unsynchronized"),
            "{show}"
        );
        assert!(show.contains("version: ntp-v3"), "{show}");
        assert!(show.contains("mode: server"), "{show}");
        assert!(show.contains("stratum: 1 (primary)"), "{show}");
        assert!(show.contains("poll: 6"), "{show}");
        assert!(show.contains("precision: -20"), "{show}");
        assert!(show.contains("root_delay: 0x00018000"), "{show}");
        assert!(show.contains("root_dispersion: 0x00024000"), "{show}");
        assert!(
            show.contains("reference_id: Global Position System"),
            "{show}"
        );
        assert!(
            show.contains("reference_timestamp: 0xa1a2a3a4a5a6a7a8"),
            "{show}"
        );
        assert!(
            show.contains("origin_timestamp: 0xb1b2b3b4b5b6b7b8"),
            "{show}"
        );
        assert!(
            show.contains("receive_timestamp: 0xc1c2c3c4c5c6c7c8"),
            "{show}"
        );
        assert!(
            show.contains("transmit_timestamp: 0xd1d2d3d4d5d6d7d8"),
            "{show}"
        );
        assert!(show.contains("extension_count: 2"), "{show}");
        assert!(
            show.contains("extension: type=0x0204 label=Autokey Message Request / NTS Cookie status=assigned declared_len=auto encoded_len=16 value_len=6"),
            "{show}"
        );
        assert!(
            show.contains("extension: type=0x2005 label=UDP Checksum Complement status=assigned declared_len=auto encoded_len=16 value_len=2"),
            "{show}"
        );
        assert!(
            show.contains("mac_status: legacy-mac digest_len=16 total_len=20"),
            "{show}"
        );
        assert!(!show.contains("deadbeef"), "{show}");
        assert!(!show.contains("1337"), "{show}");
        assert!(!show.contains("cccc"), "{show}");
        assert!(!show.contains("0x01020304"), "{show}");
    }

    #[test]
    fn ntp_show_fields_report_empty_tail_without_opaque_bytes() {
        let show = Packet::from_layer(Ntp::client()).show();

        assert!(show.contains("extension_count: 0"), "{show}");
        assert!(show.contains("legacy_mac_len: 0"), "{show}");
        assert!(show.contains("mac_status: none"), "{show}");
        assert!(!show.contains("extension: type="), "{show}");
    }

    #[test]
    fn ntp_header_fields_default_constructor_tracks_default_state() {
        let ntp = Ntp::new();

        assert_eq!(ntp.leap_indicator.state(), FieldState::Defaulted);
        assert_eq!(ntp.version.state(), FieldState::Defaulted);
        assert_eq!(ntp.mode.state(), FieldState::Defaulted);
        assert_eq!(ntp.stratum.state(), FieldState::Defaulted);
        assert_eq!(ntp.poll.state(), FieldState::Defaulted);
        assert_eq!(ntp.precision.state(), FieldState::Defaulted);
        assert_eq!(ntp.root_delay.state(), FieldState::Defaulted);
        assert_eq!(ntp.root_dispersion.state(), FieldState::Defaulted);
        assert_eq!(ntp.reference_id.state(), FieldState::Defaulted);
        assert_eq!(ntp.reference_timestamp.state(), FieldState::Defaulted);
        assert_eq!(ntp.origin_timestamp.state(), FieldState::Defaulted);
        assert_eq!(ntp.receive_timestamp.state(), FieldState::Defaulted);
        assert_eq!(ntp.transmit_timestamp.state(), FieldState::Defaulted);

        assert_eq!(ntp.leap_indicator_value(), NtpLeapIndicator::NoWarning);
        assert_eq!(ntp.version_value_effective(), NtpVersion::current());
        assert_eq!(ntp.mode_value(), NtpMode::Client);
        assert_eq!(ntp.stratum_value(), NtpStratum::from_wire(0));
        assert_eq!(ntp.poll_value(), NTP_DEFAULT_POLL);
        assert_eq!(ntp.precision_value(), NTP_DEFAULT_PRECISION);
        assert_eq!(ntp.root_delay_value().raw(), NTP_DEFAULT_ROOT_DELAY);
        assert_eq!(
            ntp.root_dispersion_value().raw(),
            NTP_DEFAULT_ROOT_DISPERSION
        );
        assert_eq!(ntp.reference_id_value().bytes(), NTP_DEFAULT_REFERENCE_ID);
        assert_eq!(
            ntp.reference_timestamp_value().raw(),
            NTP_DEFAULT_REFERENCE_TIMESTAMP
        );
        assert_eq!(
            ntp.origin_timestamp_value().raw(),
            NTP_DEFAULT_ORIGIN_TIMESTAMP
        );
        assert_eq!(
            ntp.receive_timestamp_value().raw(),
            NTP_DEFAULT_RECEIVE_TIMESTAMP
        );
        assert_eq!(
            ntp.transmit_timestamp_value().raw(),
            NTP_DEFAULT_TRANSMIT_TIMESTAMP
        );
        assert!(ntp.extension_fields_value().is_empty());
        assert!(ntp.legacy_mac_value().is_none());
    }

    #[test]
    fn ntp_constructors_use_source_backed_packet_shapes() -> Result<()> {
        assert_eq!(Ntp::client(), Ntp::client_request());
        assert_eq!(Ntp::server(), Ntp::server_response());

        let cases = [
            (
                Ntp::client_request(),
                NtpMode::Client,
                NTP_STRATUM_UNSPECIFIED,
                FieldState::Defaulted,
                0x23,
            ),
            (
                Ntp::server_response(),
                NtpMode::Server,
                NTP_STRATUM_PRIMARY,
                FieldState::User,
                0x24,
            ),
            (
                Ntp::symmetric_active(),
                NtpMode::SymmetricActive,
                NTP_STRATUM_UNSPECIFIED,
                FieldState::Defaulted,
                0x21,
            ),
            (
                Ntp::broadcast(),
                NtpMode::Broadcast,
                NTP_STRATUM_UNSPECIFIED,
                FieldState::Defaulted,
                0x25,
            ),
        ];

        for (ntp, mode, stratum, stratum_state, first_octet) in cases {
            assert_eq!(ntp.leap_indicator.state(), FieldState::Defaulted);
            assert_eq!(ntp.version.state(), FieldState::Defaulted);
            assert_eq!(ntp.mode.state(), FieldState::User);
            assert_eq!(ntp.stratum.state(), stratum_state);
            assert_eq!(ntp.poll.state(), FieldState::Defaulted);
            assert_eq!(ntp.precision.state(), FieldState::Defaulted);
            assert_eq!(ntp.root_delay.state(), FieldState::Defaulted);
            assert_eq!(ntp.root_dispersion.state(), FieldState::Defaulted);
            assert_eq!(ntp.reference_id.state(), FieldState::Defaulted);
            assert_eq!(ntp.reference_timestamp.state(), FieldState::Defaulted);
            assert_eq!(ntp.origin_timestamp.state(), FieldState::Defaulted);
            assert_eq!(ntp.receive_timestamp.state(), FieldState::Defaulted);
            assert_eq!(ntp.transmit_timestamp.state(), FieldState::Defaulted);
            assert!(ntp.extension_fields_value().is_empty());
            assert!(ntp.legacy_mac_value().is_none());

            assert_eq!(ntp.leap_indicator_value(), NtpLeapIndicator::NoWarning);
            assert_eq!(ntp.version_value_effective(), NtpVersion::current());
            assert_eq!(ntp.mode_value(), mode);
            assert_eq!(ntp.stratum_value(), NtpStratum::from_wire(stratum));
            assert_eq!(ntp.first_octet_value(), first_octet);

            let bytes = Packet::from_layer(ntp).compile()?.into_bytes();
            assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN);
            assert_eq!(bytes[0], first_octet);
            assert_eq!(bytes[1], stratum);
        }

        Ok(())
    }

    #[test]
    fn ntp_udp_helper_uses_service_port_and_allows_overrides() {
        let udp = Ntp::udp();

        assert_eq!(udp.source_port_value(), NTP_PORT);
        assert_eq!(udp.destination_port_value(), NTP_PORT);
        assert_eq!(udp, ntp_client_udp());
        assert_eq!(udp, ntp_server_udp());

        let udp = Ntp::udp().source_port(49_152).destination_port(12_345);
        assert_eq!(udp.source_port_value(), 49_152);
        assert_eq!(udp.destination_port_value(), 12_345);
    }

    #[test]
    fn ntp_packet_helpers_build_documentation_safe_ipv4_client_request() -> Result<()> {
        let packet = ntp_ipv4_documentation_client_request();

        let ipv4 = packet.layer::<Ipv4>().expect("IPv4 layer");
        assert_eq!(ipv4.source(), NTP_DOCUMENTATION_IPV4_CLIENT);
        assert_eq!(ipv4.destination(), NTP_DOCUMENTATION_IPV4_SERVER);
        assert!(packet.layer::<Ipv6>().is_none());

        let udp = packet.layer::<Udp>().expect("UDP layer");
        assert_eq!(udp.source_port_value(), NTP_PORT);
        assert_eq!(udp.destination_port_value(), NTP_PORT);

        let ntp = packet.layer::<Ntp>().expect("NTP layer");
        assert_eq!(ntp.mode_value(), NtpMode::Client);
        assert_eq!(ntp.first_octet_value(), NTP_DEFAULT_FIRST_OCTET);

        let compiled = packet.compile()?;
        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, compiled.as_bytes())?;
        let decoded_ipv4 = decoded.layer::<Ipv4>().expect("decoded IPv4 layer");
        assert_eq!(decoded_ipv4.source(), NTP_DOCUMENTATION_IPV4_CLIENT);
        assert_eq!(decoded_ipv4.destination(), NTP_DOCUMENTATION_IPV4_SERVER);
        let decoded_ntp = decoded.layer::<Ntp>().expect("decoded NTP layer");
        assert_eq!(decoded_ntp.mode_value(), NtpMode::Client);

        Ok(())
    }

    #[test]
    fn ntp_packet_helpers_build_documentation_safe_ipv6_client_request() -> Result<()> {
        let packet = ntp_ipv6_documentation_client_request();

        let ipv6 = packet.layer::<Ipv6>().expect("IPv6 layer");
        assert_eq!(ipv6.source(), NTP_DOCUMENTATION_IPV6_CLIENT);
        assert_eq!(ipv6.destination(), NTP_DOCUMENTATION_IPV6_SERVER);
        assert!(packet.layer::<Ipv4>().is_none());

        let udp = packet.layer::<Udp>().expect("UDP layer");
        assert_eq!(udp.source_port_value(), NTP_PORT);
        assert_eq!(udp.destination_port_value(), NTP_PORT);

        let ntp = packet.layer::<Ntp>().expect("NTP layer");
        assert_eq!(ntp.mode_value(), NtpMode::Client);
        assert_eq!(ntp.first_octet_value(), NTP_DEFAULT_FIRST_OCTET);

        let compiled = packet.compile()?;
        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv6, compiled.as_bytes())?;
        let decoded_ipv6 = decoded.layer::<Ipv6>().expect("decoded IPv6 layer");
        assert_eq!(decoded_ipv6.source(), NTP_DOCUMENTATION_IPV6_CLIENT);
        assert_eq!(decoded_ipv6.destination(), NTP_DOCUMENTATION_IPV6_SERVER);
        let decoded_ntp = decoded.layer::<Ntp>().expect("decoded NTP layer");
        assert_eq!(decoded_ntp.mode_value(), NtpMode::Client);

        Ok(())
    }

    #[test]
    fn ntp_constructors_leave_every_field_overridable() {
        let constructors = [
            Ntp::client_request(),
            Ntp::server_response(),
            Ntp::symmetric_active(),
            Ntp::broadcast(),
        ];

        for ntp in constructors {
            let extension = NtpExtensionField::nts_cookie([0xaa, 0xbb]);
            let legacy_mac = NtpLegacyMac::from_key_id_and_digest(0x0102_0304, [0xcc; 16]);
            let ntp = ntp
                .leap_indicator(NtpLeapIndicator::AlarmUnsynchronized)
                .version_value(3)
                .mode(NtpMode::PrivateUse)
                .stratum(NTP_STRATUM_UNSYNCHRONIZED)
                .poll(6)
                .precision(-20)
                .root_delay_raw(0x0001_8000)
                .root_dispersion_raw(0x0002_4000)
                .reference_id(*b"TEST")
                .reference_timestamp(NtpTimestamp::from_raw(0x0102_0304_0506_0708))
                .origin_timestamp(NtpTimestamp::from_raw(0x1112_1314_1516_1718))
                .receive_timestamp(NtpTimestamp::from_raw(0x2122_2324_2526_2728))
                .transmit_timestamp(NtpTimestamp::from_raw(0x3132_3334_3536_3738))
                .extension_field(extension.clone())
                .legacy_mac(legacy_mac.clone());

            assert_eq!(ntp.leap_indicator.state(), FieldState::User);
            assert_eq!(ntp.version.state(), FieldState::User);
            assert_eq!(ntp.mode.state(), FieldState::User);
            assert_eq!(ntp.stratum.state(), FieldState::User);
            assert_eq!(ntp.poll.state(), FieldState::User);
            assert_eq!(ntp.precision.state(), FieldState::User);
            assert_eq!(ntp.root_delay.state(), FieldState::User);
            assert_eq!(ntp.root_dispersion.state(), FieldState::User);
            assert_eq!(ntp.reference_id.state(), FieldState::User);
            assert_eq!(ntp.reference_timestamp.state(), FieldState::User);
            assert_eq!(ntp.origin_timestamp.state(), FieldState::User);
            assert_eq!(ntp.receive_timestamp.state(), FieldState::User);
            assert_eq!(ntp.transmit_timestamp.state(), FieldState::User);

            assert_eq!(
                ntp.leap_indicator_value(),
                NtpLeapIndicator::AlarmUnsynchronized
            );
            assert_eq!(ntp.version_value_effective(), NtpVersion::from_wire(3));
            assert_eq!(ntp.mode_value(), NtpMode::PrivateUse);
            assert_eq!(
                ntp.stratum_value(),
                NtpStratum::from_wire(NTP_STRATUM_UNSYNCHRONIZED)
            );
            assert_eq!(ntp.poll_value(), 6);
            assert_eq!(ntp.precision_value(), -20);
            assert_eq!(ntp.root_delay_value().raw(), 0x0001_8000);
            assert_eq!(ntp.root_dispersion_value().raw(), 0x0002_4000);
            assert_eq!(ntp.reference_id_value().bytes(), *b"TEST");
            assert_eq!(ntp.reference_timestamp_value().raw(), 0x0102_0304_0506_0708);
            assert_eq!(ntp.origin_timestamp_value().raw(), 0x1112_1314_1516_1718);
            assert_eq!(ntp.receive_timestamp_value().raw(), 0x2122_2324_2526_2728);
            assert_eq!(ntp.transmit_timestamp_value().raw(), 0x3132_3334_3536_3738);
            assert_eq!(ntp.extension_fields_value(), &[extension]);
            assert_eq!(ntp.legacy_mac_value(), Some(&legacy_mac));
        }
    }

    #[test]
    fn ntp_accessors_expose_default_fixed_header_values() {
        let ntp = Ntp::new();

        assert_eq!(ntp.leap_indicator_value(), NtpLeapIndicator::NoWarning);
        assert_eq!(ntp.version_value_effective(), NtpVersion::current());
        assert_eq!(ntp.mode_value(), NtpMode::Client);
        assert_eq!(
            ntp.stratum_value(),
            NtpStratum::from_wire(NTP_DEFAULT_STRATUM)
        );
        assert_eq!(ntp.poll_value(), NTP_DEFAULT_POLL);
        assert_eq!(ntp.precision_value(), NTP_DEFAULT_PRECISION);
        assert_eq!(ntp.root_delay_value().raw(), NTP_DEFAULT_ROOT_DELAY);
        assert_eq!(
            ntp.root_dispersion_value().raw(),
            NTP_DEFAULT_ROOT_DISPERSION
        );
        assert_eq!(ntp.reference_id_value().bytes(), NTP_DEFAULT_REFERENCE_ID);
        assert_eq!(
            ntp.reference_timestamp_value().raw(),
            NTP_DEFAULT_REFERENCE_TIMESTAMP
        );
        assert_eq!(
            ntp.origin_timestamp_value().raw(),
            NTP_DEFAULT_ORIGIN_TIMESTAMP
        );
        assert_eq!(
            ntp.receive_timestamp_value().raw(),
            NTP_DEFAULT_RECEIVE_TIMESTAMP
        );
        assert_eq!(
            ntp.transmit_timestamp_value().raw(),
            NTP_DEFAULT_TRANSMIT_TIMESTAMP
        );
        assert_eq!(ntp.first_octet_value(), NTP_DEFAULT_FIRST_OCTET);
    }

    #[test]
    fn ntp_accessors_and_setters_preserve_explicit_fixed_header_values() -> Result<()> {
        let ntp = Ntp::new()
            .leap_indicator(0xaa)
            .version_value(0x0f)
            .mode(0x2a)
            .stratum(0xff)
            .poll(i8::MIN)
            .precision(i8::MAX)
            .root_delay(0xffff_0001u32)
            .root_dispersion_raw(0x8000_0002)
            .reference_id([0xde, 0xad, 0xbe, 0xef])
            .reference_timestamp(0x0102_0304_0506_0708u64)
            .origin_timestamp(NtpTimestamp::from_raw(0x1112_1314_1516_1718))
            .receive_timestamp(0x2122_2324_2526_2728u64)
            .transmit_timestamp(NtpTimestamp::from_parts(0x3132_3334, 0x3536_3738));

        assert_eq!(ntp.leap_indicator.state(), FieldState::User);
        assert_eq!(ntp.version.state(), FieldState::User);
        assert_eq!(ntp.mode.state(), FieldState::User);
        assert_eq!(ntp.stratum.state(), FieldState::User);
        assert_eq!(ntp.poll.state(), FieldState::User);
        assert_eq!(ntp.precision.state(), FieldState::User);
        assert_eq!(ntp.root_delay.state(), FieldState::User);
        assert_eq!(ntp.root_dispersion.state(), FieldState::User);
        assert_eq!(ntp.reference_id.state(), FieldState::User);
        assert_eq!(ntp.reference_timestamp.state(), FieldState::User);
        assert_eq!(ntp.origin_timestamp.state(), FieldState::User);
        assert_eq!(ntp.receive_timestamp.state(), FieldState::User);
        assert_eq!(ntp.transmit_timestamp.state(), FieldState::User);

        assert_eq!(ntp.leap_indicator_value(), NtpLeapIndicator::Unknown(0xaa));
        assert_eq!(ntp.version_value_effective(), NtpVersion::from_wire(0x0f));
        assert_eq!(ntp.mode_value(), NtpMode::Unknown(0x2a));
        assert_eq!(ntp.stratum_value(), NtpStratum::from_wire(0xff));
        assert_eq!(ntp.poll_value(), i8::MIN);
        assert_eq!(ntp.precision_value(), i8::MAX);
        assert_eq!(ntp.root_delay_value().raw(), 0xffff_0001);
        assert_eq!(ntp.root_dispersion_value().raw(), 0x8000_0002);
        assert_eq!(ntp.reference_id_value().bytes(), [0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(ntp.reference_timestamp_value().raw(), 0x0102_0304_0506_0708);
        assert_eq!(ntp.origin_timestamp_value().raw(), 0x1112_1314_1516_1718);
        assert_eq!(ntp.receive_timestamp_value().raw(), 0x2122_2324_2526_2728);
        assert_eq!(ntp.transmit_timestamp_value().raw(), 0x3132_3334_3536_3738);
        assert_eq!(
            ntp.first_octet_value(),
            ((0xaa & NTP_LI_VALUE_MASK) << NTP_FIRST_OCTET_LI_SHIFT)
                | ((0x0f & NTP_VERSION_VALUE_MASK) << NTP_FIRST_OCTET_VERSION_SHIFT)
                | (0x2a & NTP_MODE_VALUE_MASK)
        );

        let bytes = Packet::from_layer(ntp).compile()?.into_bytes();
        assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN);
        assert_eq!(bytes[0], 0xba);
        assert_eq!(bytes[1], 0xff);
        assert_eq!(bytes[2], 0x80);
        assert_eq!(bytes[3], 0x7f);
        assert_eq!(&bytes[4..8], &0xffff_0001u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &0x8000_0002u32.to_be_bytes());
        assert_eq!(&bytes[12..16], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&bytes[24..32], &0x1112_1314_1516_1718u64.to_be_bytes());
        assert_eq!(&bytes[32..40], &0x2122_2324_2526_2728u64.to_be_bytes());
        assert_eq!(&bytes[40..48], &0x3132_3334_3536_3738u64.to_be_bytes());

        Ok(())
    }

    #[test]
    fn ntp_serialize_header_writes_default_fixed_header() {
        let ntp = Ntp::new();
        let mut bytes = vec![0xaa];

        ntp.serialize_header(&mut bytes);

        assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN + 1);
        assert_eq!(bytes[0], 0xaa);

        let header = &bytes[1..];
        let mut expected = vec![
            NTP_DEFAULT_FIRST_OCTET,
            NTP_DEFAULT_STRATUM,
            NTP_DEFAULT_POLL as u8,
            NTP_DEFAULT_PRECISION as u8,
        ];
        expected.resize(NTP_FIXED_HEADER_LEN, 0);
        assert_eq!(header, expected.as_slice());
    }

    #[test]
    fn ntp_serialize_header_preserves_user_values_big_endian() {
        let ntp = Ntp::new()
            .leap_indicator(0xaa)
            .version_value(0x0f)
            .mode(0x2a)
            .stratum(0xff)
            .poll(i8::MIN)
            .precision(i8::MAX)
            .root_delay_raw(0xffff_0001)
            .root_dispersion_raw(0x8000_0002)
            .reference_id([0xde, 0xad, 0xbe, 0xef])
            .reference_timestamp(0x0102_0304_0506_0708u64)
            .origin_timestamp(0x1112_1314_1516_1718u64)
            .receive_timestamp(0x2122_2324_2526_2728u64)
            .transmit_timestamp(0x3132_3334_3536_3738u64);
        let mut bytes = Vec::new();

        ntp.serialize_header(&mut bytes);

        assert_eq!(bytes.len(), NTP_FIXED_HEADER_LEN);
        assert_eq!(bytes[0], 0xba);
        assert_eq!(bytes[1], 0xff);
        assert_eq!(bytes[2], 0x80);
        assert_eq!(bytes[3], 0x7f);
        assert_eq!(&bytes[4..8], &0xffff_0001u32.to_be_bytes());
        assert_eq!(&bytes[8..12], &0x8000_0002u32.to_be_bytes());
        assert_eq!(&bytes[12..16], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&bytes[24..32], &0x1112_1314_1516_1718u64.to_be_bytes());
        assert_eq!(&bytes[32..40], &0x2122_2324_2526_2728u64.to_be_bytes());
        assert_eq!(&bytes[40..48], &0x3132_3334_3536_3738u64.to_be_bytes());
    }

    #[test]
    fn ntp_serialize_header_excludes_extensions_and_mac() -> Result<()> {
        let ntp = Ntp::new()
            .transmit_timestamp(0x3132_3334_3536_3738u64)
            .extension_field(NtpExtensionField::nts_cookie([0xaa, 0xbb]))
            .legacy_mac(NtpLegacyMac::from_key_id_and_digest(
                0x0102_0304,
                [0xcc; 16],
            ));
        let mut header = Vec::new();

        ntp.serialize_header(&mut header);
        let compiled = Packet::from_layer(ntp).compile()?.into_bytes();

        assert_eq!(header.len(), NTP_FIXED_HEADER_LEN);
        assert!(compiled.len() > NTP_FIXED_HEADER_LEN);
        assert_eq!(&compiled[..NTP_FIXED_HEADER_LEN], header.as_slice());

        Ok(())
    }

    mod ntp_layer_impl {
        use super::*;
        use crate::packet::{Layer, Packet, Raw};
        use crate::protocols::transport::Udp;

        fn ntp_with_extension_and_mac() -> Ntp {
            Ntp::new()
                .extension_field(NtpExtensionField::nts_cookie([0xaa, 0xbb]))
                .legacy_mac(NtpLegacyMac::from_key_id_and_digest(
                    0x0102_0304,
                    [0xcc; 16],
                ))
        }

        #[test]
        fn encoded_len_includes_fixed_header_extension_and_mac() -> Result<()> {
            let ntp = ntp_with_extension_and_mac();
            let packet = Packet::from_layer(ntp.clone());

            assert_eq!(
                ntp.encoded_len(),
                NTP_FIXED_HEADER_LEN + NTP_EXTENSION_FIELD_MIN_LEN + 20
            );
            assert_eq!(packet.encoded_len(), ntp.encoded_len());

            let bytes = packet.compile()?.into_bytes();
            assert_eq!(bytes.len(), ntp.encoded_len());
            assert_eq!(
                &bytes[NTP_FIXED_HEADER_LEN..NTP_FIXED_HEADER_LEN + 2],
                &[0x02, 0x04]
            );
            assert_eq!(
                &bytes[NTP_FIXED_HEADER_LEN + 2..NTP_FIXED_HEADER_LEN + 4],
                &[0x00, 0x10]
            );
            assert_eq!(
                &bytes[NTP_FIXED_HEADER_LEN + 4..NTP_FIXED_HEADER_LEN + 6],
                &[0xaa, 0xbb]
            );
            assert!(bytes
                [NTP_FIXED_HEADER_LEN + 6..NTP_FIXED_HEADER_LEN + NTP_EXTENSION_FIELD_MIN_LEN]
                .iter()
                .all(|byte| *byte == 0));
            assert_eq!(
                &bytes[NTP_FIXED_HEADER_LEN + NTP_EXTENSION_FIELD_MIN_LEN
                    ..NTP_FIXED_HEADER_LEN + NTP_EXTENSION_FIELD_MIN_LEN + 4],
                &[0x01, 0x02, 0x03, 0x04]
            );
            assert_eq!(
                &bytes[NTP_FIXED_HEADER_LEN + NTP_EXTENSION_FIELD_MIN_LEN + 4..],
                &[0xcc; 16]
            );

            Ok(())
        }

        #[test]
        fn compile_emits_only_ntp_bytes_and_leaves_following_layers() -> Result<()> {
            let ntp = ntp_with_extension_and_mac();
            let ntp_len = ntp.encoded_len();
            let standalone = Packet::from_layer(ntp.clone()).compile()?.into_bytes();
            let packet = ntp / Raw::from_bytes([0xde, 0xad]);

            assert_eq!(packet.encoded_len(), ntp_len + 2);
            assert!(!packet
                .layer::<Ntp>()
                .expect("NTP layer")
                .consumes_following());

            let bytes = packet.compile()?.into_bytes();
            assert_eq!(&bytes[..ntp_len], standalone.as_slice());
            assert_eq!(&bytes[ntp_len..], &[0xde, 0xad]);

            Ok(())
        }

        #[test]
        fn clone_layer_and_any_downcasts_work() {
            let mut boxed: Box<dyn Layer> =
                Box::new(Ntp::client().transmit_timestamp(0x0102_0304_0506_0708u64));

            assert!(boxed.as_any().downcast_ref::<Ntp>().is_some());

            let ntp = boxed.as_any_mut().downcast_mut::<Ntp>().expect("boxed NTP");
            *ntp = ntp.clone().mode(NtpMode::Server);

            assert_eq!(
                boxed
                    .as_any()
                    .downcast_ref::<Ntp>()
                    .expect("boxed NTP")
                    .mode_value(),
                NtpMode::Server
            );

            let cloned = boxed.clone_layer();
            assert_eq!(
                cloned
                    .as_any()
                    .downcast_ref::<Ntp>()
                    .expect("cloned NTP")
                    .transmit_timestamp_value()
                    .raw(),
                0x0102_0304_0506_0708
            );

            let owned = cloned.into_any().downcast::<Ntp>().expect("owned NTP");
            assert_eq!(owned.mode_value(), NtpMode::Server);
        }

        #[test]
        fn div_composition_works_for_udp_application_layer_and_following_payload() {
            let udp_packet =
                Udp::new().source_port(49_152).destination_port(NTP_PORT) / Ntp::client();
            assert_eq!(udp_packet.len(), 2);
            assert!(udp_packet.layer::<Udp>().is_some());
            assert!(udp_packet.layer::<Ntp>().is_some());

            let ntp_packet = Ntp::client() / Raw::from_bytes([0xde, 0xad]);
            assert_eq!(ntp_packet.len(), 2);
            assert!(ntp_packet.layer::<Ntp>().is_some());
            assert!(ntp_packet.layer::<Raw>().is_some());
        }
    }

    #[test]
    fn ntp_header_fields_setters_track_user_state_and_tails() {
        let extension = NtpExtensionField::nts_unique_identifier([0xaa, 0xbb]);
        let legacy_mac = NtpLegacyMac::from_key_id_and_digest(0x0102_0304, [0xcc; 16]);
        let ntp = Ntp::new()
            .leap_indicator(NtpLeapIndicator::AlarmUnsynchronized)
            .version_value(3)
            .mode(NtpMode::Server)
            .stratum(1)
            .poll(6)
            .precision(-20)
            .root_delay_raw(0x0001_8000)
            .root_dispersion_raw(0x0002_4000)
            .reference_id(NtpReferenceId::from_bytes(*b"GPS\0"))
            .reference_timestamp(NtpTimestamp::from_raw(0x0102_0304_0506_0708))
            .origin_timestamp(NtpTimestamp::from_raw(0x1112_1314_1516_1718))
            .receive_timestamp(NtpTimestamp::from_raw(0x2122_2324_2526_2728))
            .transmit_timestamp(NtpTimestamp::from_raw(0x3132_3334_3536_3738))
            .extension_field(extension.clone())
            .legacy_mac(legacy_mac.clone());

        assert_eq!(ntp.leap_indicator.state(), FieldState::User);
        assert_eq!(ntp.version.state(), FieldState::User);
        assert_eq!(ntp.mode.state(), FieldState::User);
        assert_eq!(ntp.stratum.state(), FieldState::User);
        assert_eq!(ntp.poll.state(), FieldState::User);
        assert_eq!(ntp.precision.state(), FieldState::User);
        assert_eq!(ntp.root_delay.state(), FieldState::User);
        assert_eq!(ntp.root_dispersion.state(), FieldState::User);
        assert_eq!(ntp.reference_id.state(), FieldState::User);
        assert_eq!(ntp.reference_timestamp.state(), FieldState::User);
        assert_eq!(ntp.origin_timestamp.state(), FieldState::User);
        assert_eq!(ntp.receive_timestamp.state(), FieldState::User);
        assert_eq!(ntp.transmit_timestamp.state(), FieldState::User);

        assert_eq!(
            ntp.leap_indicator_value(),
            NtpLeapIndicator::AlarmUnsynchronized
        );
        assert_eq!(ntp.version_value_effective(), NtpVersion::from_wire(3));
        assert_eq!(ntp.mode_value(), NtpMode::Server);
        assert_eq!(ntp.stratum_value(), NtpStratum::from_wire(1));
        assert_eq!(ntp.poll_value(), 6);
        assert_eq!(ntp.precision_value(), -20);
        assert_eq!(ntp.root_delay_value().raw(), 0x0001_8000);
        assert_eq!(ntp.root_dispersion_value().raw(), 0x0002_4000);
        assert_eq!(ntp.reference_id_value().bytes(), *b"GPS\0");
        assert_eq!(ntp.reference_timestamp_value().raw(), 0x0102_0304_0506_0708);
        assert_eq!(ntp.origin_timestamp_value().raw(), 0x1112_1314_1516_1718);
        assert_eq!(ntp.receive_timestamp_value().raw(), 0x2122_2324_2526_2728);
        assert_eq!(ntp.transmit_timestamp_value().raw(), 0x3132_3334_3536_3738);
        assert_eq!(ntp.extension_fields_value(), &[extension]);
        assert_eq!(ntp.legacy_mac_value(), Some(&legacy_mac));
    }

    #[test]
    fn ntp_stratum_refid_strata_are_classified_without_rejecting_values() {
        let unspecified = NtpStratum::from_wire(0);
        assert_eq!(unspecified.value(), 0);
        assert_eq!(unspecified.wire_value(), 0);
        assert!(unspecified.is_unspecified_or_kod());
        assert!(!unspecified.is_primary());
        assert_eq!(unspecified.label(), "unspecified-or-invalid");

        let primary = NtpStratum::from_wire(1);
        assert!(primary.is_primary());
        assert_eq!(primary.label(), "primary");

        let secondary = NtpStratum::from_wire(15);
        assert!(secondary.is_secondary());
        assert_eq!(secondary.label(), "secondary");

        let unsynchronized = NtpStratum::from_wire(16);
        assert!(unsynchronized.is_unsynchronized());
        assert_eq!(unsynchronized.label(), "unsynchronized");

        let reserved = NtpStratum::from_wire(42);
        assert_eq!(reserved.value(), 42);
        assert_eq!(reserved.label(), "reserved");
        assert_eq!(reserved.registry_meta().status, NtpRegistryStatus::Reserved);
        assert_eq!(u8::from(reserved), 42);
        assert_eq!(reserved.to_string(), "reserved");
    }

    #[test]
    fn ntp_stratum_refid_reference_ids_preserve_bytes_and_expose_valid_ascii() {
        let rate = NtpReferenceId::from_bytes(*b"RATE");
        assert_eq!(rate.bytes(), *b"RATE");
        assert_eq!(rate.ascii_label().as_deref(), Some("RATE"));
        assert_eq!(
            rate.label_for_stratum(NtpStratum::from_wire(0)),
            "Rate exceeded"
        );

        let gps = NtpReferenceId::from_bytes([b'G', b'P', b'S', 0]);
        assert_eq!(gps.bytes(), [b'G', b'P', b'S', 0]);
        assert_eq!(gps.ascii_label().as_deref(), Some("GPS"));
        assert_eq!(
            gps.label_for_stratum(NtpStratum::from_wire(1)),
            "Global Position System"
        );

        let private = NtpReferenceId::from_bytes(*b"XLAB");
        assert_eq!(private.ascii_label().as_deref(), Some("XLAB"));
        assert_eq!(
            private.label_for_stratum(NtpStratum::from_wire(1)),
            "refid-0x584C4142 (private-or-experimental)"
        );

        let secondary = NtpReferenceId::from_bytes([192, 0, 2, 44]);
        assert_eq!(secondary.bytes(), [192, 0, 2, 44]);
        assert_eq!(secondary.ascii_label(), None);
        assert_eq!(
            secondary.label_for_stratum(NtpStratum::from_wire(2)),
            "refid-0xC000022C"
        );

        let invalid_padding = NtpReferenceId::from_bytes([b'G', 0, b'P', 0]);
        assert_eq!(invalid_padding.bytes(), [b'G', 0, b'P', 0]);
        assert_eq!(invalid_padding.ascii_label(), None);
        assert_eq!(
            invalid_padding.label_for_stratum(NtpStratum::from_wire(1)),
            "refid-0x47005000"
        );

        let non_ascii = NtpReferenceId::from_bytes([0x80, 0, 0, 1]);
        assert_eq!(non_ascii.bytes(), [0x80, 0, 0, 1]);
        assert_eq!(non_ascii.ascii_label(), None);
        assert_eq!(
            non_ascii.label_for_stratum(NtpStratum::from_wire(1)),
            "refid-0x80000001"
        );
    }
}
