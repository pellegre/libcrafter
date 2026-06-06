use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crate::{Arp, Ethernet, Ipv4, LinkType, MacAddr, Packet, Raw, Tcp, Udp, ETHERTYPE_ARP};

use super::codec::PCAP_HEADER_LEN;
use super::{
    dump_pcap, CaptureControl, PcapLinkType, PcapReader, PcapTimestamp, PcapWriter,
    PcapWriterOptions, Sniffer, TimestampPrecision, DLT_EN10MB, DLT_IEEE802_11,
    DLT_IEEE802_11_RADIO, LINKTYPE_IEEE802_11, LINKTYPE_IEEE802_11_RADIOTAP,
};

const ARP_REQUEST: &[u8] = fixture_bytes!("bytes/arp-who-has.bin");
const ARP_REPLY_HEX: &str = fixture_str!("bytes/ethernet-arp-reply.hex");
const ARP_NONSTANDARD_HEX: &str =
    fixture_str!("bytes/ethernet-arp-infiniband-ipv6-nonstandard.hex");
static NEXT_TEMP_PCAP: AtomicUsize = AtomicUsize::new(0);

fn decode_hex(text: &str) -> Vec<u8> {
    let compact: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    assert!(compact.len() % 2 == 0, "hex fixture has an odd hex length");
    compact
        .as_bytes()
        .chunks(2)
        .map(|chunk| {
            let byte = std::str::from_utf8(chunk).expect("hex fixture is not valid UTF-8");
            u8::from_str_radix(byte, 16).expect("hex fixture has an invalid hex byte")
        })
        .collect()
}

fn ethernet_arp_packet() -> Packet {
    Packet::decode_from_link(LinkType::Ethernet, ARP_REQUEST).unwrap()
}

fn ethernet_arp_reply_bytes() -> Vec<u8> {
    decode_hex(ARP_REPLY_HEX)
}

fn ethernet_arp_nonstandard_bytes() -> Vec<u8> {
    decode_hex(ARP_NONSTANDARD_HEX)
}

fn tcp_packet(source_port: u16, destination_port: u16) -> Packet {
    Ethernet::new()
        .src(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
        .dst(MacAddr::BROADCAST)
        / Ipv4::new()
            .src_str("192.0.2.10")
            .unwrap()
            .dst_str("198.51.100.20")
            .unwrap()
        / Tcp::new().sport(source_port).dport(destination_port)
        / Raw::from("payload")
}

fn udp_packet(source_port: u16, destination_port: u16) -> Packet {
    Ethernet::new()
        .src(MacAddr::new([0x02, 0, 0, 0, 0, 2]))
        .dst(MacAddr::BROADCAST)
        / Ipv4::new()
            .src_str("203.0.113.30")
            .unwrap()
            .dst_str("198.51.100.20")
            .unwrap()
        / Udp::new().sport(source_port).dport(destination_port)
        / Raw::from("payload")
}

fn temp_pcap_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "pcap-crafter-{name}-{}.pcap",
        NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
    ))
}

fn write_temp_pcap(name: &str, packets: &[Packet]) -> PathBuf {
    let path = temp_pcap_path(name);
    {
        let mut writer = PcapWriter::create(&path, LinkType::Ethernet).unwrap();
        for packet in packets {
            writer.write_packet(packet).unwrap();
        }
        writer.flush().unwrap();
    }
    path
}

#[test]
fn pcap_write_emits_global_and_record_headers() {
    let packet = ethernet_arp_packet();
    let mut output = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
        writer
            .write_packet_with_timestamp(&packet, PcapTimestamp::micros(7, 42).unwrap())
            .unwrap();
        writer.flush().unwrap();
    }

    assert_eq!(&output[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    assert_eq!(
        u32::from_le_bytes(output[20..24].try_into().unwrap()),
        DLT_EN10MB
    );
    assert_eq!(
        u32::from_le_bytes(
            output[PCAP_HEADER_LEN..PCAP_HEADER_LEN + 4]
                .try_into()
                .unwrap()
        ),
        7
    );
    assert_eq!(
        u32::from_le_bytes(
            output[PCAP_HEADER_LEN + 4..PCAP_HEADER_LEN + 8]
                .try_into()
                .unwrap()
        ),
        42
    );
    assert_eq!(&output[PCAP_HEADER_LEN + 16..], ARP_REQUEST);
}

#[test]
fn pcap_write_supports_nanosecond_precision() {
    let mut output = Vec::new();
    let options =
        PcapWriterOptions::new(LinkType::Ethernet).precision(TimestampPrecision::Nanoseconds);
    {
        let mut writer = PcapWriter::from_writer_with_options(&mut output, options).unwrap();
        writer
            .write_packet_with_timestamp(
                &ethernet_arp_packet(),
                PcapTimestamp::nanos(11, 123).unwrap(),
            )
            .unwrap();
        writer.flush().unwrap();
    }

    assert_eq!(&output[..4], &[0x4d, 0x3c, 0xb2, 0xa1]);
    let reader = PcapReader::from_reader(Cursor::new(output))
        .unwrap()
        .collect_records()
        .unwrap();
    assert_eq!(
        reader[0].timestamp(),
        PcapTimestamp::nanos(11, 123).unwrap()
    );
}

#[test]
fn pcap_read_decodes_ethernet_fixture() {
    let mut output = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
        writer
            .write_packet_with_timestamp(
                &ethernet_arp_packet(),
                PcapTimestamp::micros(1, 500).unwrap(),
            )
            .unwrap();
    }

    let mut reader = PcapReader::from_reader(Cursor::new(output)).unwrap();
    assert_eq!(reader.link_type(), LinkType::Ethernet);

    let record = reader.next_record().unwrap().unwrap();
    assert_eq!(record.timestamp(), PcapTimestamp::micros(1, 500).unwrap());
    assert_eq!(record.link_type(), LinkType::Ethernet);
    assert_eq!(record.pcap_link_type(), PcapLinkType::Ethernet);
    assert_eq!(record.data(), ARP_REQUEST);

    let decoded = record.decode().unwrap();
    assert!(decoded.layer::<Arp>().is_some());
    assert_eq!(decoded.compile().unwrap().as_bytes(), ARP_REQUEST);
    assert!(reader.next_record().unwrap().is_none());
}

#[test]
fn pcap_dot11_link_types_numeric_round_trips() {
    assert_eq!(LINKTYPE_IEEE802_11, DLT_IEEE802_11);
    assert_eq!(LINKTYPE_IEEE802_11_RADIOTAP, DLT_IEEE802_11_RADIO);

    let cases = [
        (DLT_IEEE802_11, PcapLinkType::Ieee80211, LinkType::Ieee80211),
        (
            DLT_IEEE802_11_RADIO,
            PcapLinkType::Ieee80211Radiotap,
            LinkType::Radiotap,
        ),
    ];

    for (datalink, pcap_link_type, link_type) in cases {
        assert_eq!(PcapLinkType::from_datalink(datalink), pcap_link_type);
        assert_eq!(pcap_link_type.datalink(), datalink);
        assert_eq!(pcap_link_type.link_type(), link_type);
        assert_eq!(PcapLinkType::from(link_type), pcap_link_type);
    }
}

#[test]
fn pcap_read_filter_uses_libpcap_bpf() {
    let one = tcp_packet(10, 80);
    let two = tcp_packet(11, 443);
    let path = write_temp_pcap("read-filter", &[one, two]);

    let packets = super::read_pcap_filtered(&path, "tcp and port 10").unwrap();

    assert_eq!(packets.len(), 1);
    assert_eq!(
        packets[0]
            .packet()
            .layer::<Tcp>()
            .unwrap()
            .source_port_value(),
        10
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn pcap_read_filter_supports_bpf_host_and_ether_proto() {
    let packet = Ethernet::new()
        .src(MacAddr::new([0x02, 0, 0, 0, 0, 1]))
        .dst(MacAddr::BROADCAST)
        / Ipv4::new()
            .src_str("192.0.2.10")
            .unwrap()
            .dst_str("198.51.100.20")
            .unwrap()
        / Udp::new().sport(53).dport(53000);
    let path = write_temp_pcap("read-filter-host", &[packet]);

    let packets =
        super::read_pcap_filtered(&path, "ip and src host 192.0.2.10 and ether proto 0x0800")
            .unwrap();

    assert_eq!(packets.len(), 1);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn pcap_roundtrip_preserves_records_and_decoded_bytes() {
    let packet = ethernet_arp_packet();
    let mut first = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut first, LinkType::Ethernet).unwrap();
        writer
            .write_packet_with_timestamp(&packet, PcapTimestamp::micros(123, 456).unwrap())
            .unwrap();
    }

    let records = PcapReader::from_reader(Cursor::new(&first))
        .unwrap()
        .collect_records()
        .unwrap();
    let mut second = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut second, LinkType::Ethernet).unwrap();
        for record in &records {
            writer.write_record(record).unwrap();
        }
    }

    assert_eq!(first, second);
    let decoded = records[0].decode().unwrap();
    assert_eq!(
        decoded.compile().unwrap().as_bytes(),
        packet.compile().unwrap().as_bytes()
    );
}

#[test]
fn pcap_roundtrip_dump_and_read_helpers() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "pcap-crafter-roundtrip-{}.pcap",
        NEXT_TEMP_PCAP.fetch_add(1, Ordering::Relaxed)
    ));
    let packet = ethernet_arp_packet();

    dump_pcap(&path, [&packet], LinkType::Ethernet).unwrap();
    let packets = super::read_pcap(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    assert_eq!(packets.len(), 1);
    assert!(packets[0].packet().layer::<Arp>().is_some());
}

#[test]
fn pcap_write_rejects_link_type_mismatch() {
    let record = super::PcapRecord::new(
        PcapTimestamp::zero(),
        ARP_REQUEST.len() as u32,
        ARP_REQUEST,
        PcapLinkType::Ethernet,
    )
    .unwrap();
    let mut output = Vec::new();
    let mut writer = PcapWriter::from_writer(&mut output, PcapLinkType::RawIp).unwrap();

    assert!(writer.write_record(&record).is_err());
}

#[test]
fn pcap_read_null_loopback_link_type_is_preserved() {
    let packet = crate::NullLoopback::ipv4() / Raw::from("loopback");
    let mut output = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut output, LinkType::NullLoopback).unwrap();
        writer.write_packet(&packet).unwrap();
    }

    let record = PcapReader::from_reader(Cursor::new(output))
        .unwrap()
        .next_record()
        .unwrap()
        .unwrap();
    assert_eq!(record.link_type(), LinkType::NullLoopback);
    assert_eq!(
        record.decode().unwrap().summary(),
        "NullLoopback(family=2) / Raw(len=8)"
    );
}

#[test]
fn pcap_write_uses_autofilled_ether_type() {
    let packet = Ethernet::new() / Arp::new();
    let mut output = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
        writer.write_packet(&packet).unwrap();
    }

    let record = PcapReader::from_reader(Cursor::new(output))
        .unwrap()
        .next_record()
        .unwrap()
        .unwrap();
    let decoded = record.decode().unwrap();
    assert_eq!(
        decoded.layer::<Ethernet>().unwrap().ethertype_value(),
        Some(ETHERTYPE_ARP)
    );
}

#[test]
fn sniffer_offline_supports_iterator_callback_and_spawn() {
    let tcp = tcp_packet(10, 80);
    let udp = udp_packet(53000, 53001);
    let path = write_temp_pcap("sniffer-offline", &[tcp, udp]);

    let mut capture = Sniffer::offline(&path)
        .filter("tcp")
        .count(1)
        .open()
        .unwrap();
    let first = capture.next_packet().unwrap().unwrap();
    assert!(first.packet().layer::<Tcp>().is_some());
    assert!(capture.next_packet().unwrap().is_none());

    let mut summaries = Vec::new();
    let callback_count = Sniffer::offline(&path)
        .filter("udp")
        .capture(10, |packet| {
            summaries.push(packet.packet().summary());
            Ok(CaptureControl::Continue)
        })
        .unwrap();
    assert_eq!(callback_count, 1);
    assert!(summaries[0].contains("Udp"));

    let spawned_packets = Sniffer::offline(&path)
        .filter("tcp or udp")
        .spawn(2)
        .unwrap()
        .join()
        .unwrap();
    assert_eq!(spawned_packets.len(), 2);

    std::fs::remove_file(path).unwrap();
}

#[test]
fn bpf_filter_sniffer_offline_uses_libpcap() {
    let https = tcp_packet(12345, 443);
    let http = tcp_packet(12345, 80);
    let path = write_temp_pcap("bpf-filter", &[https, http]);

    let packets = Sniffer::offline(&path)
        .filter("tcp and dst port 443")
        .collect()
        .unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(
        packets[0]
            .packet()
            .layer::<Tcp>()
            .unwrap()
            .destination_port_value(),
        443
    );

    let packets = Sniffer::offline(&path)
        .filter("tcp and not dst port 443")
        .collect()
        .unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(
        packets[0]
            .packet()
            .layer::<Tcp>()
            .unwrap()
            .destination_port_value(),
        80
    );

    let mut callback_count = 0;
    let accepted = Sniffer::offline(&path)
        .filter("tcp")
        .capture(10, |_packet| {
            callback_count += 1;
            Ok(CaptureControl::Stop)
        })
        .unwrap();
    assert_eq!(accepted, 1);
    assert_eq!(callback_count, 1);

    std::fs::remove_file(path).unwrap();
}

#[test]
fn pcap_roundtrip_arp_request_and_reply_records() {
    let request = ethernet_arp_packet();
    let reply = Packet::decode_from_link(LinkType::Ethernet, ethernet_arp_reply_bytes()).unwrap();

    let mut output = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut output, LinkType::Ethernet).unwrap();
        writer
            .write_packet_with_timestamp(&request, PcapTimestamp::micros(1, 0).unwrap())
            .unwrap();
        writer
            .write_packet_with_timestamp(&reply, PcapTimestamp::micros(2, 0).unwrap())
            .unwrap();
        writer.flush().unwrap();
    }

    let records = PcapReader::from_reader(Cursor::new(output))
        .unwrap()
        .collect_records()
        .unwrap();
    assert_eq!(records.len(), 2);

    assert_eq!(records[0].data(), ARP_REQUEST);
    assert_eq!(records[1].data(), ethernet_arp_reply_bytes());

    let decoded_request = records[0].decode().unwrap();
    let decoded_reply = records[1].decode().unwrap();
    assert_eq!(
        decoded_request.layer::<Arp>().unwrap().opcode_value(),
        crate::ARP_OP_REQUEST
    );
    assert_eq!(
        decoded_reply.layer::<Arp>().unwrap().opcode_value(),
        crate::ARP_OP_REPLY
    );

    assert_eq!(decoded_request.compile().unwrap().as_bytes(), ARP_REQUEST);
    assert_eq!(
        decoded_reply.compile().unwrap().as_bytes(),
        ethernet_arp_reply_bytes()
    );
}

#[test]
fn pcap_roundtrip_nonstandard_arp_preserves_record_bytes() {
    let nonstandard = ethernet_arp_nonstandard_bytes();
    let packet = Packet::decode_from_link(LinkType::Ethernet, &nonstandard).unwrap();

    // Confirm the decode preserved the nonstandard codepoints and variable
    // address lengths before exercising the pcap round trip.
    let arp = packet.layer::<Arp>().unwrap();
    assert_eq!(arp.hardware_type_value(), crate::ARP_HRD_INFINIBAND);
    assert_eq!(arp.protocol_type_value(), crate::ETHERTYPE_IPV6);
    assert_eq!(arp.hardware_len_value(), 8);
    assert_eq!(arp.protocol_len_value(), 16);
    assert_eq!(arp.opcode_value(), 1024);
    assert_eq!(packet.compile().unwrap().as_bytes(), nonstandard);

    let mut first = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut first, LinkType::Ethernet).unwrap();
        writer
            .write_packet_with_timestamp(&packet, PcapTimestamp::micros(9, 9).unwrap())
            .unwrap();
        writer.flush().unwrap();
    }

    let records = PcapReader::from_reader(Cursor::new(&first))
        .unwrap()
        .collect_records()
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].data(), nonstandard);

    // Re-emit the read records: byte-exact pcap round trip for the nonstandard case.
    let mut second = Vec::new();
    {
        let mut writer = PcapWriter::from_writer(&mut second, LinkType::Ethernet).unwrap();
        for record in &records {
            writer.write_record(record).unwrap();
        }
        writer.flush().unwrap();
    }
    assert_eq!(first, second);

    // Decoding the read record reproduces the exact nonstandard bytes.
    let decoded = records[0].decode().unwrap();
    assert_eq!(decoded.compile().unwrap().as_bytes(), nonstandard);
    let decoded_arp = decoded.layer::<Arp>().unwrap();
    assert_eq!(decoded_arp.hardware_type_value(), crate::ARP_HRD_INFINIBAND);
    assert_eq!(decoded_arp.protocol_type_value(), crate::ETHERTYPE_IPV6);
    assert_eq!(decoded_arp.hardware_len_value(), 8);
    assert_eq!(decoded_arp.protocol_len_value(), 16);
    assert_eq!(decoded_arp.opcode_value(), 1024);
}

#[test]
fn pcap_read_filter_selects_arp_with_libpcap_bpf() {
    let tcp = tcp_packet(10, 80);
    let arp = ethernet_arp_packet();
    let path = write_temp_pcap("read-filter-arp", &[tcp, arp]);

    let packets = super::read_pcap_filtered(&path, "arp").unwrap();

    assert_eq!(packets.len(), 1);
    let decoded = packets[0].packet();
    assert!(decoded.layer::<Arp>().is_some());
    assert!(decoded.layer::<Tcp>().is_none());
    assert_eq!(decoded.compile().unwrap().as_bytes(), ARP_REQUEST);

    std::fs::remove_file(path).unwrap();
}

#[test]
#[ignore = "live capture is reserved for disposable wire endpoint execution"]
fn sniffer_live_capture_wire_endpoint_only() {
    let Some(iface) = std::env::var_os("LIBCRAFTER_LIVE_CAPTURE_IFACE") else {
        return;
    };
    let packets = Sniffer::interface(iface.to_string_lossy().into_owned())
        .filter("icmp or arp")
        .count(1)
        .timeout(Duration::from_secs(2))
        .collect()
        .unwrap();
    assert!(packets.len() <= 1);
}
