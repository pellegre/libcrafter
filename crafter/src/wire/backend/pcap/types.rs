use std::time::Duration;

use crate::{LinkType, Packet, ProtocolRegistry};

use super::codec::{
    decode_raw_ip_with_registry, DEFAULT_SNAPLEN, PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR,
};
use super::{PcapError, Result};

/// BSD null/loopback pcap data-link type.
pub const DLT_NULL: u32 = 0;
/// Ethernet pcap data-link type.
pub const DLT_EN10MB: u32 = 1;
/// BSD loopback pcap data-link type.
pub const DLT_LOOP: u32 = 108;
/// Raw IPv4/IPv6 pcap data-link type.
pub const DLT_RAW: u32 = 101;
/// Bare IEEE 802.11 MAC frame pcap data-link type.
pub const DLT_IEEE802_11: u32 = 105;
/// Bare IEEE 802.11 MAC frame pcap link type.
pub const LINKTYPE_IEEE802_11: u32 = DLT_IEEE802_11;
/// Linux cooked capture v1 pcap data-link type.
pub const DLT_LINUX_SLL: u32 = 113;
/// Radiotap metadata followed by IEEE 802.11 MAC frame pcap data-link type.
pub const DLT_IEEE802_11_RADIO: u32 = 127;
/// Radiotap metadata followed by IEEE 802.11 MAC frame pcap link type.
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = DLT_IEEE802_11_RADIO;
/// Bluetooth LE Link Layer with pseudo-header pcap data-link type
/// (tcpdump LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR).
pub const DLT_BLUETOOTH_LE_LL_WITH_PHDR: u32 = 256;
/// Bluetooth LE Link Layer with pseudo-header pcap link type.
pub const LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR: u32 = DLT_BLUETOOTH_LE_LL_WITH_PHDR;
/// Bare IEEE 802.15.4 MAC frame with the FCS present pcap data-link type
/// (tcpdump LINKTYPE_IEEE802_15_4_WITHFCS).
pub const DLT_IEEE802_15_4_WITHFCS: u32 = 195;
/// Bare IEEE 802.15.4 MAC frame with the FCS present pcap link type.
pub const LINKTYPE_IEEE802_15_4_WITHFCS: u32 = DLT_IEEE802_15_4_WITHFCS;
/// Bare IEEE 802.15.4 MAC frame without the FCS pcap data-link type
/// (tcpdump LINKTYPE_IEEE802_15_4_NOFCS).
pub const DLT_IEEE802_15_4_NOFCS: u32 = 230;
/// Bare IEEE 802.15.4 MAC frame without the FCS pcap link type.
pub const LINKTYPE_IEEE802_15_4_NOFCS: u32 = DLT_IEEE802_15_4_NOFCS;
/// IEEE 802.15.4 TAP pseudo-header followed by a MAC frame pcap data-link type
/// (tcpdump LINKTYPE_IEEE802_15_4_TAP).
pub const DLT_IEEE802_15_4_TAP: u32 = 283;
/// IEEE 802.15.4 TAP pseudo-header followed by a MAC frame pcap link type.
pub const LINKTYPE_IEEE802_15_4_TAP: u32 = DLT_IEEE802_15_4_TAP;
const DLT_RAW_BSD: u32 = 12;
const DLT_IPV4: u32 = 228;
const DLT_IPV6: u32 = 229;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampPrecision {
    /// Classic pcap microsecond timestamps.
    Microseconds,
    /// Nanosecond-resolution pcap timestamps.
    Nanoseconds,
}

impl TimestampPrecision {
    fn units_per_second(self) -> u32 {
        match self {
            Self::Microseconds => 1_000_000,
            Self::Nanoseconds => 1_000_000_000,
        }
    }

    fn duration_factor(self) -> u32 {
        match self {
            Self::Microseconds => 1_000,
            Self::Nanoseconds => 1,
        }
    }
}

/// Timestamp attached to a pcap record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapTimestamp {
    seconds: u64,
    fractional: u32,
    pub(super) precision: TimestampPrecision,
}

impl PcapTimestamp {
    /// Create a zero timestamp.
    pub const fn zero() -> Self {
        Self {
            seconds: 0,
            fractional: 0,
            precision: TimestampPrecision::Microseconds,
        }
    }

    /// Create a microsecond-precision timestamp.
    pub fn micros(seconds: u64, micros: u32) -> Result<Self> {
        Self::new(seconds, micros, TimestampPrecision::Microseconds)
    }

    /// Create a nanosecond-precision timestamp.
    pub fn nanos(seconds: u64, nanos: u32) -> Result<Self> {
        Self::new(seconds, nanos, TimestampPrecision::Nanoseconds)
    }

    /// Create a timestamp in the supplied precision.
    pub fn new(seconds: u64, fractional: u32, precision: TimestampPrecision) -> Result<Self> {
        if fractional >= precision.units_per_second() {
            return Err(PcapError::InvalidRecord(
                "timestamp fractional field must be below one second",
            ));
        }

        Ok(Self {
            seconds,
            fractional,
            precision,
        })
    }

    /// Create a timestamp from a duration, truncating to the requested precision.
    pub fn from_duration(duration: Duration, precision: TimestampPrecision) -> Result<Self> {
        let seconds = duration.as_secs();
        let fractional = match precision {
            TimestampPrecision::Microseconds => duration.subsec_micros(),
            TimestampPrecision::Nanoseconds => duration.subsec_nanos(),
        };

        Self::new(seconds, fractional, precision)
    }

    /// Whole seconds since the epoch stored in the pcap record.
    pub const fn seconds(self) -> u64 {
        self.seconds
    }

    /// Fractional timestamp component in this timestamp's precision.
    pub const fn fractional(self) -> u32 {
        self.fractional
    }

    /// Precision used by the fractional component.
    pub const fn precision(self) -> TimestampPrecision {
        self.precision
    }

    /// Convert this timestamp to a [`Duration`].
    pub fn as_duration(self) -> Duration {
        Duration::new(
            self.seconds,
            self.fractional * self.precision.duration_factor(),
        )
    }

    /// Convert to a target pcap precision.
    pub fn to_precision(self, precision: TimestampPrecision) -> Result<Self> {
        if self.precision == precision {
            Ok(self)
        } else {
            Self::from_duration(self.as_duration(), precision)
        }
    }

    pub(super) fn pcap_fields(self, precision: TimestampPrecision) -> Result<(u32, u32)> {
        let timestamp = self.to_precision(precision)?;
        let seconds = u32::try_from(timestamp.seconds).map_err(|_| PcapError::RecordTooLarge {
            field: "timestamp seconds",
            max: u32::MAX as u64,
            actual: timestamp.seconds,
        })?;
        Ok((seconds, timestamp.fractional))
    }
}

impl Default for PcapTimestamp {
    fn default() -> Self {
        Self::zero()
    }
}

/// Pcap data-link type metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PcapLinkType {
    /// BSD null/loopback capture header.
    NullLoopback,
    /// Ethernet frames.
    Ethernet,
    /// Bare IEEE 802.11 MAC frames.
    Ieee80211,
    /// Radiotap metadata followed by IEEE 802.11 MAC frames.
    Ieee80211Radiotap,
    /// Bluetooth LE Link Layer with pseudo-header.
    BluetoothLeLl,
    /// Bare IEEE 802.15.4 MAC frames with the FCS present.
    Ieee802154WithFcs,
    /// Bare IEEE 802.15.4 MAC frames without the FCS.
    Ieee802154NoFcs,
    /// IEEE 802.15.4 TAP pseudo-header followed by a MAC frame.
    Ieee802154Tap,
    /// Raw IPv4/IPv6 packets without a link-layer header.
    RawIp,
    /// Linux cooked capture v1.
    LinuxSll,
    /// Unsupported or caller-defined pcap data-link type.
    Unknown(u32),
}

impl PcapLinkType {
    /// Convert a pcap numeric DLT value into a typed value.
    pub const fn from_datalink(datalink: u32) -> Self {
        match datalink {
            DLT_NULL | DLT_LOOP => Self::NullLoopback,
            DLT_EN10MB => Self::Ethernet,
            DLT_IEEE802_11 => Self::Ieee80211,
            DLT_RAW | DLT_RAW_BSD | DLT_IPV4 | DLT_IPV6 => Self::RawIp,
            DLT_LINUX_SLL => Self::LinuxSll,
            DLT_IEEE802_11_RADIO => Self::Ieee80211Radiotap,
            DLT_BLUETOOTH_LE_LL_WITH_PHDR => Self::BluetoothLeLl,
            DLT_IEEE802_15_4_WITHFCS => Self::Ieee802154WithFcs,
            DLT_IEEE802_15_4_NOFCS => Self::Ieee802154NoFcs,
            DLT_IEEE802_15_4_TAP => Self::Ieee802154Tap,
            value => Self::Unknown(value),
        }
    }

    /// Numeric pcap DLT value.
    pub const fn datalink(self) -> u32 {
        match self {
            Self::NullLoopback => DLT_NULL,
            Self::Ethernet => DLT_EN10MB,
            Self::Ieee80211 => DLT_IEEE802_11,
            Self::Ieee80211Radiotap => DLT_IEEE802_11_RADIO,
            Self::BluetoothLeLl => DLT_BLUETOOTH_LE_LL_WITH_PHDR,
            Self::Ieee802154WithFcs => DLT_IEEE802_15_4_WITHFCS,
            Self::Ieee802154NoFcs => DLT_IEEE802_15_4_NOFCS,
            Self::Ieee802154Tap => DLT_IEEE802_15_4_TAP,
            Self::RawIp => DLT_RAW,
            Self::LinuxSll => DLT_LINUX_SLL,
            Self::Unknown(value) => value,
        }
    }

    /// Best-effort core link-layer entrypoint.
    pub const fn link_type(self) -> LinkType {
        match self {
            Self::NullLoopback => LinkType::NullLoopback,
            Self::Ethernet => LinkType::Ethernet,
            Self::Ieee80211 => LinkType::Ieee80211,
            Self::Ieee80211Radiotap => LinkType::Radiotap,
            Self::LinuxSll => LinkType::LinuxSll,
            Self::BluetoothLeLl => LinkType::BluetoothLeLl,
            // Bare 802.15.4 captures (DLT 195 with-FCS / 230 no-FCS) start at the
            // MAC frame, so both map to the plain `Ieee802154` entrypoint; the TAP
            // form (DLT 283) prefixes the `Dot15d4Radio` pseudo-header.
            Self::Ieee802154WithFcs | Self::Ieee802154NoFcs => LinkType::Ieee802154,
            Self::Ieee802154Tap => LinkType::Ieee802154Tap,
            Self::RawIp | Self::Unknown(_) => LinkType::Raw,
        }
    }

    /// Decode bytes according to this pcap data-link type.
    pub fn decode(self, bytes: impl AsRef<[u8]>) -> crate::Result<Packet> {
        self.decode_with_registry(&ProtocolRegistry::new(), bytes)
    }

    /// Decode bytes using an explicit protocol registry.
    pub fn decode_with_registry(
        self,
        registry: &ProtocolRegistry,
        bytes: impl AsRef<[u8]>,
    ) -> crate::Result<Packet> {
        let bytes = bytes.as_ref();
        match self {
            Self::NullLoopback
            | Self::Ethernet
            | Self::Ieee80211
            | Self::Ieee80211Radiotap
            | Self::BluetoothLeLl
            // The bare 802.15.4 variants decode through `LinkType::Ieee802154`
            // and the TAP variant through `LinkType::Ieee802154Tap` (resolved by
            // `self.link_type()`), routing into `registry::decode_from_link`.
            | Self::Ieee802154WithFcs
            | Self::Ieee802154NoFcs
            | Self::Ieee802154Tap
            | Self::LinuxSll => {
                Packet::decode_from_link_with_registry(registry, self.link_type(), bytes)
            }
            Self::RawIp => decode_raw_ip_with_registry(registry, bytes),
            Self::Unknown(_) => Packet::decode_raw(bytes),
        }
    }
}

impl From<LinkType> for PcapLinkType {
    fn from(value: LinkType) -> Self {
        match value {
            LinkType::Raw => Self::RawIp,
            LinkType::Ethernet => Self::Ethernet,
            LinkType::Ieee80211 => Self::Ieee80211,
            LinkType::Radiotap => Self::Ieee80211Radiotap,
            LinkType::BluetoothLeLl => Self::BluetoothLeLl,
            // The bare 802.15.4 entrypoint defaults to the with-FCS DLT (195);
            // the TAP entrypoint maps to the TAP pseudo-header DLT (283).
            LinkType::Ieee802154 => Self::Ieee802154WithFcs,
            LinkType::Ieee802154Tap => Self::Ieee802154Tap,
            LinkType::LinuxCooked | LinkType::LinuxSll => Self::LinuxSll,
            LinkType::NullLoopback => Self::NullLoopback,
        }
    }
}

/// Parsed pcap global header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PcapHeader {
    pub(super) version_major: u16,
    pub(super) version_minor: u16,
    pub(super) thiszone: i32,
    pub(super) sigfigs: u32,
    pub(super) snaplen: u32,
    pub(super) link_type: PcapLinkType,
    pub(super) precision: TimestampPrecision,
}

impl PcapHeader {
    /// Create a standard pcap header.
    pub fn new(link_type: impl Into<PcapLinkType>) -> Self {
        Self {
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen: DEFAULT_SNAPLEN,
            link_type: link_type.into(),
            precision: TimestampPrecision::Microseconds,
        }
    }

    /// Pcap major version.
    pub const fn version_major(self) -> u16 {
        self.version_major
    }

    /// Pcap minor version.
    pub const fn version_minor(self) -> u16 {
        self.version_minor
    }

    /// Timezone correction field from the pcap header.
    pub const fn thiszone(self) -> i32 {
        self.thiszone
    }

    /// Timestamp accuracy field from the pcap header.
    pub const fn sigfigs(self) -> u32 {
        self.sigfigs
    }

    /// Snapshot length from the pcap header.
    pub const fn snaplen(self) -> u32 {
        self.snaplen
    }

    /// Best-effort core link-layer type.
    pub const fn link_type(self) -> LinkType {
        self.link_type.link_type()
    }

    /// Pcap data-link type metadata.
    pub const fn pcap_link_type(self) -> PcapLinkType {
        self.link_type
    }

    /// Timestamp precision used by the file.
    pub const fn precision(self) -> TimestampPrecision {
        self.precision
    }
}

/// Raw pcap record plus global link-type metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapRecord {
    timestamp: PcapTimestamp,
    original_len: u32,
    data: Vec<u8>,
    pub(super) link_type: PcapLinkType,
}

impl PcapRecord {
    /// Create a raw record.
    pub fn new(
        timestamp: PcapTimestamp,
        original_len: u32,
        data: impl Into<Vec<u8>>,
        link_type: impl Into<PcapLinkType>,
    ) -> Result<Self> {
        let data = data.into();
        if original_len < data.len() as u32 {
            return Err(PcapError::InvalidRecord(
                "original length must be at least captured length",
            ));
        }

        Ok(Self {
            timestamp,
            original_len,
            data,
            link_type: link_type.into(),
        })
    }

    /// Record timestamp.
    pub const fn timestamp(&self) -> PcapTimestamp {
        self.timestamp
    }

    /// Captured length.
    pub fn captured_len(&self) -> u32 {
        self.data.len() as u32
    }

    /// Original on-wire length.
    pub const fn original_len(&self) -> u32 {
        self.original_len
    }

    /// Captured bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume and return captured bytes.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Best-effort core link-layer type.
    pub const fn link_type(&self) -> LinkType {
        self.link_type.link_type()
    }

    /// Pcap data-link type metadata.
    pub const fn pcap_link_type(&self) -> PcapLinkType {
        self.link_type
    }

    /// Decode this record with the default protocol registry.
    pub fn decode(&self) -> crate::Result<Packet> {
        self.link_type.decode(&self.data)
    }

    /// Decode this record with an explicit protocol registry.
    pub fn decode_with_registry(&self, registry: &ProtocolRegistry) -> crate::Result<Packet> {
        self.link_type.decode_with_registry(registry, &self.data)
    }
}

/// Decoded packet with pcap record metadata preserved.
#[derive(Debug, Clone)]
pub struct PcapPacket {
    timestamp: PcapTimestamp,
    original_len: u32,
    data: Vec<u8>,
    pub(super) link_type: PcapLinkType,
    packet: Packet,
}

impl PcapPacket {
    /// Create a decoded pcap packet wrapper.
    pub fn new(
        timestamp: PcapTimestamp,
        original_len: u32,
        data: impl Into<Vec<u8>>,
        link_type: PcapLinkType,
        packet: Packet,
    ) -> Self {
        Self {
            timestamp,
            original_len,
            data: data.into(),
            link_type,
            packet,
        }
    }

    /// Metadata timestamp.
    pub const fn timestamp(&self) -> PcapTimestamp {
        self.timestamp
    }

    /// Original on-wire length.
    pub const fn original_len(&self) -> u32 {
        self.original_len
    }

    /// Captured bytes exactly as read from the pcap record.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Best-effort core link-layer type.
    pub const fn link_type(&self) -> LinkType {
        self.link_type.link_type()
    }

    /// Pcap data-link type metadata.
    pub const fn pcap_link_type(&self) -> PcapLinkType {
        self.link_type
    }

    /// Borrow the decoded packet.
    pub const fn packet(&self) -> &Packet {
        &self.packet
    }

    /// Consume and return the decoded packet.
    pub fn into_packet(self) -> Packet {
        self.packet
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PcapLinkType, PcapRecord, PcapTimestamp, DLT_BLUETOOTH_LE_LL_WITH_PHDR,
        DLT_IEEE802_15_4_NOFCS, DLT_IEEE802_15_4_TAP, DLT_IEEE802_15_4_WITHFCS,
    };
    use crate::packet::Layer;
    use crate::{BleRadio, Dot15d4, Dot15d4Radio, LinkType, Packet, ProtocolRegistry};

    #[test]
    fn pcap_linktype_ble_datalink() {
        assert_eq!(
            PcapLinkType::from_datalink(DLT_BLUETOOTH_LE_LL_WITH_PHDR),
            PcapLinkType::BluetoothLeLl
        );
        assert_eq!(
            PcapLinkType::BluetoothLeLl.datalink(),
            DLT_BLUETOOTH_LE_LL_WITH_PHDR
        );
    }

    #[test]
    fn pcap_dot15d4_datalink() {
        for (dlt, link_type) in [
            (DLT_IEEE802_15_4_WITHFCS, PcapLinkType::Ieee802154WithFcs),
            (DLT_IEEE802_15_4_NOFCS, PcapLinkType::Ieee802154NoFcs),
            (DLT_IEEE802_15_4_TAP, PcapLinkType::Ieee802154Tap),
        ] {
            assert_eq!(PcapLinkType::from_datalink(dlt), link_type);
            assert_eq!(link_type.datalink(), dlt);
        }
    }

    #[test]
    fn pcap_linktype_ble_bridge() {
        assert_eq!(
            PcapLinkType::BluetoothLeLl.link_type(),
            LinkType::BluetoothLeLl
        );
        assert_eq!(
            PcapLinkType::from(LinkType::BluetoothLeLl),
            PcapLinkType::BluetoothLeLl
        );
    }

    #[test]
    fn pcap_decode_ble() {
        let frame = [
            37, 0xc4, 0x00, 0x00, 0xd6, 0xbe, 0x89, 0x8e, 0x13, 0x0c, 0xd6, 0xbe, 0x89, 0x8e, 0x40,
            0x0f, 0x01, 0x53, 0x00, 0x5e, 0x00, 0x02, 0x02, 0x01, 0x06, 0x05, 0x09, b't', b'e',
            b's', b't',
        ];
        let record = PcapRecord::new(
            PcapTimestamp::zero(),
            frame.len() as u32,
            frame,
            PcapLinkType::BluetoothLeLl,
        )
        .unwrap();

        let packet = record.decode().unwrap();
        let first = packet.get(0).unwrap();

        assert!(first.as_any().is::<BleRadio>());
        assert_eq!(first.name(), "BleRadio");
    }

    #[test]
    fn pcap_dot15d4_bridge() {
        // The bare 802.15.4 link types resolve to the plain MAC entrypoint and
        // the TAP link type to the TAP entrypoint.
        assert_eq!(
            PcapLinkType::Ieee802154WithFcs.link_type(),
            LinkType::Ieee802154
        );
        assert_eq!(
            PcapLinkType::Ieee802154NoFcs.link_type(),
            LinkType::Ieee802154
        );
        assert_eq!(
            PcapLinkType::Ieee802154Tap.link_type(),
            LinkType::Ieee802154Tap
        );
        // The `From<LinkType>` round-trip uses the default with-FCS DLT for the
        // bare entrypoint and the TAP DLT for the TAP entrypoint.
        assert_eq!(
            PcapLinkType::from(LinkType::Ieee802154),
            PcapLinkType::Ieee802154WithFcs
        );
        assert_eq!(
            PcapLinkType::from(LinkType::Ieee802154Tap),
            PcapLinkType::Ieee802154Tap
        );
    }

    #[test]
    fn pcap_dot15d4_decode() {
        let registry = ProtocolRegistry::new();

        // TAP frame: a `Dot15d4Radio` pseudo-header over a MAC data frame. Decode
        // through `PcapLinkType::Ieee802154Tap` yields both typed layers.
        let tap_bytes = (Dot15d4Radio::on_channel(20).rssi(-55)
            / Dot15d4::data()
                .seq(9)
                .dest_short(0x1234, 0x0000)
                .src_short(0x1234, 0xABCD))
        .compile()
        .expect("compile TAP + MAC frame")
        .as_bytes()
        .to_vec();

        let tap_packet = PcapLinkType::Ieee802154Tap
            .decode_with_registry(&registry, &tap_bytes)
            .expect("decode TAP 802.15.4 frame");
        let tap_radio = tap_packet
            .layer::<Dot15d4Radio>()
            .expect("Dot15d4Radio layer present in TAP decode");
        assert!(
            tap_radio.summary().contains("ch=20"),
            "tap radio summary: {}",
            tap_radio.summary()
        );
        let tap_mac = tap_packet
            .layer::<Dot15d4>()
            .expect("Dot15d4 MAC layer present in TAP decode");
        let tap_mac_summary = tap_mac.summary();
        assert!(
            tap_mac_summary.contains("seq=9"),
            "tap mac summary: {tap_mac_summary}"
        );
        assert!(
            tap_mac_summary.contains("src=0xABCD"),
            "tap mac summary: {tap_mac_summary}"
        );

        // With-FCS frame: the bare MAC frame (no radio pseudo-header). Decode
        // through `PcapLinkType::Ieee802154WithFcs` yields the MAC layer and no
        // radio descriptor.
        let mac_bytes = Packet::new()
            .push(
                Dot15d4::data()
                    .seq(7)
                    .dest_short(0x1234, 0x0000)
                    .src_short(0x1234, 0xABCD),
            )
            .compile()
            .expect("compile bare MAC frame")
            .as_bytes()
            .to_vec();

        let mac_packet = PcapLinkType::Ieee802154WithFcs
            .decode_with_registry(&registry, &mac_bytes)
            .expect("decode with-FCS 802.15.4 frame");
        assert!(
            mac_packet.layer::<Dot15d4Radio>().is_none(),
            "bare MAC decode must not carry a radio pseudo-header"
        );
        let mac_mac = mac_packet
            .layer::<Dot15d4>()
            .expect("Dot15d4 MAC layer present in with-FCS decode");
        let mac_summary = mac_mac.summary();
        assert!(
            mac_summary.contains("seq=7"),
            "with-FCS mac summary: {mac_summary}"
        );
        assert!(
            mac_summary.contains("src=0xABCD"),
            "with-FCS mac summary: {mac_summary}"
        );
    }
}
