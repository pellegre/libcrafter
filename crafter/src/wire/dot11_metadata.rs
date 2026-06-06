//! Non-decrypting IEEE 802.11 metadata transform.

use crate::{Dot11, Packet, Radiotap, DOT11_TAG_DS_PARAMETER_SET, DOT11_TAG_SSID};

use super::record::{PacketRecord, TransformTrace, WifiDecryptState, WifiMetadata};
use super::transform::{PacketTransform, TransformOutput};
use super::Result;

/// Pass-through transform that annotates Radiotap/Dot11 records with Wi-Fi metadata.
///
/// This transform is intentionally best-effort: it only records fields already
/// decoded into existing Radiotap and Dot11 layers. It does not capture
/// handshakes, derive keys, decrypt protected payloads, or rewrite packets.
#[derive(Debug, Clone, Default)]
pub struct Dot11Metadata {
    input_count: usize,
    annotated_count: usize,
}

impl Dot11Metadata {
    /// Create a Dot11 metadata transform.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of input records seen.
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    /// Number of records annotated with Wi-Fi metadata.
    pub const fn annotated_count(&self) -> usize {
        self.annotated_count
    }

    /// Annotate one record and collect the pass-through output.
    pub fn annotate(&mut self, record: PacketRecord) -> Result<TransformOutput> {
        self.transform_to_output(record)
    }
}

impl PacketTransform for Dot11Metadata {
    fn name(&self) -> &'static str {
        "dot11-metadata"
    }

    fn transform(
        &mut self,
        mut record: PacketRecord,
        emit: &mut dyn FnMut(PacketRecord) -> Result<()>,
    ) -> Result<()> {
        self.input_count += 1;

        if let Some(wifi) = metadata_from_packet(record.packet(), record.metadata().wifi().cloned())
        {
            record = record.with_wifi_metadata(wifi);
            record
                .metadata_mut()
                .push_transform_trace(TransformTrace::new(self.name()).with_note("annotated"));
            self.annotated_count += 1;
        }

        emit(record)
    }
}

fn metadata_from_packet(packet: &Packet, existing: Option<WifiMetadata>) -> Option<WifiMetadata> {
    let mut wifi = existing.unwrap_or_default();
    let mut found = false;

    if let Some(radiotap) = packet.layer::<Radiotap>() {
        if let Some(channel) = radiotap.channel_value() {
            let frequency = channel.frequency();
            wifi = wifi.with_frequency_mhz(u32::from(frequency));
            if let Some(channel_number) = channel_number_from_frequency_mhz(frequency) {
                wifi = wifi.with_channel(channel_number);
            }
            found = true;
        }

        if let Some(signal) = radiotap.antenna_signal_value() {
            wifi = wifi.with_signal_dbm(i16::from(signal));
            found = true;
        }
    }

    if let Some(dot11) = packet.layer::<Dot11>() {
        wifi = wifi.with_dot11_frame_type(dot11.frame_type());
        found = true;

        if let Some(subtype) = dot11.management_subtype() {
            wifi = wifi.with_dot11_management_subtype(subtype);
        }
        if let Some(subtype) = dot11.control_subtype() {
            wifi = wifi.with_dot11_control_subtype(subtype);
        }
        if let Some(subtype) = dot11.data_subtype() {
            wifi = wifi.with_dot11_data_subtype(subtype);
        }
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
        wifi = wifi
            .with_protected(protected)
            .with_decrypt_state(if protected {
                WifiDecryptState::NotAttempted
            } else {
                WifiDecryptState::NotRequired
            });

        for tag in dot11.tagged_parameters() {
            match tag.id() {
                DOT11_TAG_SSID => {
                    wifi = wifi.with_ssid(tag.value().to_vec());
                }
                DOT11_TAG_DS_PARAMETER_SET => {
                    if let Some(channel) = tag.value().first().copied() {
                        wifi = wifi.with_channel(u16::from(channel));
                    }
                }
                _ => {}
            }
        }
    }

    found.then_some(wifi)
}

fn channel_number_from_frequency_mhz(frequency: u16) -> Option<u16> {
    match frequency {
        2412..=2472 if (frequency - 2407) % 5 == 0 => Some((frequency - 2407) / 5),
        2484 => Some(14),
        5005..=5895 if (frequency - 5000) % 5 == 0 => Some((frequency - 5000) / 5),
        5955..=7115 if (frequency - 5950) % 5 == 0 => Some((frequency - 5950) / 5),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dot11DataSubtype, Dot11FrameType, Dot11ManagementSubtype, LinkType, MacAddr, Raw};

    fn mac(last: u8) -> MacAddr {
        MacAddr::new([0x02, 0x00, 0x00, 0x00, 0x00, last])
    }

    #[test]
    fn dot11_metadata_annotates_radiotap_beacon() {
        let ap = mac(1);
        let packet = Radiotap::new().channel((2412, 0x00a0)).antenna_signal(-42)
            / Dot11::beacon()
                .addr1(MacAddr::BROADCAST)
                .addr2(ap)
                .addr3(ap)
                .ssid(b"mesh-a")
                .ds_parameter_set(6);
        let mut transform = Dot11Metadata::new();

        let output = transform
            .annotate(PacketRecord::new(packet).with_link_type(LinkType::Radiotap))
            .unwrap();

        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.annotated_count(), 1);
        assert_eq!(output.len(), 1);

        let record = &output.records()[0];
        assert_eq!(record.metadata().link_type(), Some(LinkType::Radiotap));
        assert_eq!(record.metadata().transforms()[0].name(), "dot11-metadata");

        let wifi = record.metadata().wifi().unwrap();
        assert_eq!(wifi.ssid(), Some(b"mesh-a".as_slice()));
        assert_eq!(wifi.ssid_str(), Some("mesh-a"));
        assert_eq!(wifi.bssid(), Some(ap));
        assert_eq!(wifi.transmitter(), Some(ap));
        assert_eq!(wifi.receiver(), Some(MacAddr::BROADCAST));
        assert_eq!(wifi.channel(), Some(6));
        assert_eq!(wifi.frequency_mhz(), Some(2412));
        assert_eq!(wifi.signal_dbm(), Some(-42));
        assert_eq!(wifi.dot11_frame_type(), Some(Dot11FrameType::Management));
        assert_eq!(
            wifi.dot11_management_subtype(),
            Some(Dot11ManagementSubtype::Beacon)
        );
        assert_eq!(wifi.protected(), Some(false));
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::NotRequired));
    }

    #[test]
    fn dot11_metadata_marks_protected_data_without_decrypting() {
        let ap = mac(2);
        let station = mac(3);
        let frame_control = Dot11::data().frame_control_value().with_protected(true);
        let packet = Radiotap::new()
            / Dot11::data()
                .frame_control(frame_control)
                .addr1(ap)
                .addr2(station)
                .addr3(ap)
            / Raw::from([0xaa, 0xbb, 0xcc, 0xdd]);
        let mut transform = Dot11Metadata::new();

        let output = transform.annotate(PacketRecord::new(packet)).unwrap();
        let wifi = output.records()[0].metadata().wifi().unwrap();

        assert_eq!(wifi.dot11_frame_type(), Some(Dot11FrameType::Data));
        assert_eq!(wifi.dot11_data_subtype(), Some(Dot11DataSubtype::Data));
        assert_eq!(wifi.bssid(), Some(ap));
        assert_eq!(wifi.transmitter(), Some(station));
        assert_eq!(wifi.receiver(), Some(ap));
        assert_eq!(wifi.protected(), Some(true));
        assert_eq!(wifi.decrypt_state(), Some(WifiDecryptState::NotAttempted));
        assert!(output.records()[0].packet().layer::<Raw>().is_some());
    }

    #[test]
    fn dot11_metadata_passes_non_dot11_records_unchanged() {
        let mut transform = Dot11Metadata::new();
        let record = PacketRecord::new(Raw::from("opaque"));

        let output = transform.annotate(record).unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.annotated_count(), 0);
        assert!(output.records()[0].metadata().wifi().is_none());
        assert!(output.records()[0].metadata().transforms().is_empty());
        assert_eq!(output.records()[0].packet().summary(), "Raw(len=6)");
    }

    #[test]
    fn dot11_metadata_derives_channel_from_radiotap_frequency() {
        let packet = Radiotap::new().channel((2437, 0x00a0)) / Dot11::probe_request();
        let mut transform = Dot11Metadata::new();

        let output = transform.annotate(PacketRecord::new(packet)).unwrap();
        let wifi = output.records()[0].metadata().wifi().unwrap();

        assert_eq!(wifi.frequency_mhz(), Some(2437));
        assert_eq!(wifi.channel(), Some(6));
        assert_eq!(
            wifi.dot11_management_subtype(),
            Some(Dot11ManagementSubtype::ProbeRequest)
        );
    }
}
