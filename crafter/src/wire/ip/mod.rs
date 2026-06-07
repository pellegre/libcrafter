//! IP fragmentation and defragmentation packet-stream transforms.
//!
//! This module is rooted in the existing wire transform pipeline. `IpDefrag`
//! will receive fragment records and emit reassembled packet records once a
//! datagram is complete. `IpFragment` will split one packet-shaped record into
//! packet-shaped fragments for transmission. The initial step keeps both
//! transforms as explicit pass-through stages while the receive and transmit
//! behavior is added in later implementation steps.

mod config;
mod defrag;
mod fragment;
mod fragmentation;
mod ipv4;
mod ipv6;
mod metadata;
mod range;

#[cfg(test)]
mod defrag_contract;
#[cfg(test)]
mod fragment_metadata;
#[cfg(test)]
mod tests;

#[cfg(test)]
mod ipv6_extension_scope {
    use super::ipv6::{
        extract_ipv6_fragment, Ipv6FragmentExtract, Ipv6FragmentPassThroughReason,
        IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE,
    };
    use super::{IpDefrag, IpFragment};
    use crate::pcap::PcapLinkType;
    use crate::wire::record::PacketRecord;
    use crate::{
        Ipv6, Ipv6DestinationOptionsHeader, Ipv6FragmentHeader, Ipv6HopByHopOptionsHeader,
        Ipv6RoutingHeader, Packet, Raw, IPPROTO_UDP,
    };
    use std::net::Ipv6Addr;

    const IDENTIFICATION: u32 = 0x1020_3040;

    fn source() -> Ipv6Addr {
        "2001:db8:17::1".parse().unwrap()
    }

    fn destination() -> Ipv6Addr {
        "2001:db8:17::2".parse().unwrap()
    }

    fn plain_fragment_packet() -> Packet {
        Ipv6::new().src(source()).dst(destination())
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .more_fragments(true)
            / Raw::from_bytes(b"abcdefgh")
    }

    fn scoped_extension_fragment_packet() -> Packet {
        Ipv6::new().src(source()).dst(destination())
            / Ipv6HopByHopOptionsHeader::new()
            / Ipv6DestinationOptionsHeader::new()
            / Ipv6RoutingHeader::new()
            / Ipv6FragmentHeader::new()
                .next_header(IPPROTO_UDP)
                .identification(IDENTIFICATION)
                .more_fragments(true)
            / Raw::from_bytes(b"abcdefgh")
    }

    fn unsupported_ah_fragment_record() -> PacketRecord {
        let mut bytes = (Ipv6::new()
            .src(source())
            .dst(destination())
            .next_header(crate::IPPROTO_IPV6_AH)
            / Raw::from_bytes([0u8; 8]))
        .compile()
        .unwrap()
        .as_bytes()
        .to_vec();
        bytes[40] = crate::IPPROTO_IPV6_FRAGMENT;

        PacketRecord::new(Raw::from_bytes(&bytes))
            .with_pcap_link_type(PcapLinkType::RawIp)
            .with_captured_bytes(bytes)
    }

    #[test]
    fn plain_ipv6_fragment_header_is_defrag_supported_scope() {
        let record = PacketRecord::new(plain_fragment_packet());
        let mut transform = IpDefrag::new();

        let output = transform.defrag_record(record).unwrap();

        assert!(output.is_empty());
        assert_eq!(transform.input_count(), 1);
        assert_eq!(transform.emitted_count(), 0);
    }

    #[test]
    fn existing_options_and_routing_before_fragment_header_are_supported_scope() {
        let record = PacketRecord::new(scoped_extension_fragment_packet());

        let view = match extract_ipv6_fragment(&record).unwrap() {
            Ipv6FragmentExtract::View(view) => view,
            Ipv6FragmentExtract::PassThrough(pass_through) => {
                panic!(
                    "expected supported Fragment Header scope, got {:?}",
                    pass_through.reason()
                )
            }
        };

        assert_eq!(view.ipv6_next_header(), crate::IPPROTO_IPV6_HOPOPTS);
        assert_eq!(view.fragment_next_header(), IPPROTO_UDP);
        assert_eq!(view.extension_chain().fragment_header_offset(), 64);
        assert_eq!(view.extension_chain().previous_next_header_offset(), 56);
        assert_eq!(view.extension_chain().unfragmentable().len(), 24);
    }

    #[test]
    fn unsupported_extension_chain_is_pass_through_with_defrag_trace() {
        let mut transform = IpDefrag::new();

        let output = transform
            .defrag_record(unsupported_ah_fragment_record())
            .unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let traces = output.records()[0].metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-defrag");
        assert_eq!(
            traces[0].note(),
            Some(IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE)
        );
    }

    #[test]
    fn unsupported_extension_chain_is_pass_through_with_fragment_trace() {
        let mut transform = IpFragment::new(1280);

        let output = transform
            .fragment_record(unsupported_ah_fragment_record())
            .unwrap();

        assert_eq!(output.len(), 1);
        assert_eq!(transform.emitted_count(), 1);
        let traces = output.records()[0].metadata().transforms();
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].name(), "ip-fragment");
        assert_eq!(
            traces[0].note(),
            Some(IPV6_FRAGMENT_UNSUPPORTED_EXTENSION_SCOPE_NOTE)
        );
    }

    #[test]
    fn unsupported_extension_chain_reason_remains_inspectable() {
        let extracted = extract_ipv6_fragment(&unsupported_ah_fragment_record()).unwrap();

        assert_eq!(
            extracted.pass_through().map(|pass| pass.reason()),
            Some(Ipv6FragmentPassThroughReason::UnsupportedExtensionChain)
        );
    }
}

pub use config::{
    IpDefragConfig, IpDefragOverlapPolicy, IpFragmentConfig, Ipv4DontFragmentPolicy,
    Ipv4FragmentIdentificationPolicy, Ipv6AtomicFragmentPolicy, Ipv6FragmentIdentificationPolicy,
    IP_DEFRAG_DEFAULT_MAX_AGE, IP_DEFRAG_DEFAULT_MAX_BYTES_PER_DATAGRAM,
    IP_DEFRAG_DEFAULT_MAX_DATAGRAMS, IP_FRAGMENT_MIN_MTU,
};
pub use defrag::IpDefrag;
pub use fragmentation::IpFragment;
pub use metadata::{
    IpDefragEvictionReason, IpDefragMetadata, IpDefragOverlapStatus, IpFragmentFamily,
    IpFragmentMetadata, IpFragmentRange, IpFragmentReason,
};
