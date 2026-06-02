//! UDP and TCP protocol implementations.

mod common;
mod tcp;
mod udp;

pub(crate) use self::tcp::append_tcp_packet_with_registry;
pub use self::tcp::{
    tcp_option_kind_class, tcp_option_kind_is_assigned, tcp_option_kind_is_experimental, Tcp,
    TcpExtendedDataOffset, TcpOption, TcpOptionIter, TcpOptionKindClass, TcpSackBlock,
    TCP_EDO_HEADER_AND_SEGMENT_LEN, TCP_EDO_HEADER_LEN, TCP_EDO_REQUEST_LEN, TCP_FLAG_ACK,
    TCP_FLAG_AE, TCP_FLAG_CWR, TCP_FLAG_ECE, TCP_FLAG_FIN, TCP_FLAG_NS, TCP_FLAG_PSH,
    TCP_FLAG_RST, TCP_FLAG_SYN, TCP_FLAG_URG, TCP_OPTION_ACCURATE_ECN_ORDER_0,
    TCP_OPTION_ACCURATE_ECN_ORDER_1, TCP_OPTION_EDO, TCP_OPTION_EOL, TCP_OPTION_EXPERIMENTAL_1,
    TCP_OPTION_EXPERIMENTAL_2, TCP_OPTION_FAST_OPEN, TCP_OPTION_MD5_SIGNATURE, TCP_OPTION_MPTCP,
    TCP_OPTION_MSS, TCP_OPTION_NOP, TCP_OPTION_SACK, TCP_OPTION_SACK_PERMITTED,
    TCP_OPTION_TCP_AUTHENTICATION, TCP_OPTION_TCP_ENO, TCP_OPTION_TIMESTAMP, TCP_OPTION_USER_TIMEOUT,
    TCP_OPTION_WINDOW_SCALE,
};
pub(crate) use self::udp::append_udp_packet_with_registry;
pub use self::udp::{
    udp_option_kind_class, udp_option_kind_is_unsafe, udp_option_kind_is_unsupported, Udp,
    UdpChecksumStatus, UdpOption, UdpOptionIter, UdpOptionKindClass, UdpOptionStatus, UdpOptions,
    UDP_HEADER_LEN, UDP_OPTION_APC, UDP_OPTION_AUTH, UDP_OPTION_EOL, UDP_OPTION_EXP,
    UDP_OPTION_FRAG, UDP_OPTION_MDS, UDP_OPTION_MRDS, UDP_OPTION_NOP, UDP_OPTION_REQ,
    UDP_OPTION_RES, UDP_OPTION_RESERVED_SAFE_END, UDP_OPTION_RESERVED_SAFE_START,
    UDP_OPTION_RESERVED_UNSAFE, UDP_OPTION_TIME, UDP_OPTION_UCMP, UDP_OPTION_UENC, UDP_OPTION_UEXP,
    UDP_OPTION_UNASSIGNED_SAFE_END, UDP_OPTION_UNASSIGNED_SAFE_START,
    UDP_OPTION_UNASSIGNED_UNSAFE_END, UDP_OPTION_UNASSIGNED_UNSAFE_START,
};

#[cfg(test)]
mod transport_checksums {
    use super::{Tcp, Udp};
    use crate::checksum::ipv6_pseudo_header_checksum;
    use crate::{
        Layer, LayerContext, Packet, Raw, TransportChecksumContext, IPPROTO_TCP, IPPROTO_UDP,
    };
    use core::any::Any;
    use core::net::Ipv6Addr;

    #[derive(Debug, Clone)]
    struct Ipv6PseudoHeader {
        source: Ipv6Addr,
        destination: Ipv6Addr,
    }

    impl Ipv6PseudoHeader {
        fn new() -> Self {
            Self {
                source: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                destination: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            }
        }
    }

    impl Layer for Ipv6PseudoHeader {
        fn name(&self) -> &'static str {
            "Ipv6PseudoHeader"
        }

        fn encoded_len(&self) -> usize {
            0
        }

        fn compile(&self, _ctx: &LayerContext<'_>, _out: &mut Vec<u8>) -> crate::Result<()> {
            Ok(())
        }

        fn transport_checksum_context(
            &self,
            transport_protocol: u8,
        ) -> Option<TransportChecksumContext> {
            Some(TransportChecksumContext::Ipv6 {
                source: self.source,
                destination: self.destination,
                next_header: transport_protocol,
            })
        }

        fn clone_layer(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }

    #[test]
    fn udp_uses_ipv6_checksum_context_when_previous_layer_provides_it() {
        let pseudo = Ipv6PseudoHeader::new();
        let source = pseudo.source;
        let destination = pseudo.destination;
        let bytes = (Packet::from_layer(pseudo)
            / Udp::new().sport(1).dport(2)
            / Raw::from_bytes([1, 2, 3]))
        .compile()
        .unwrap();

        let mut udp = bytes.as_bytes().to_vec();
        udp[6] = 0;
        udp[7] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[6], bytes.as_bytes()[7]]),
            ipv6_pseudo_header_checksum(source, destination, IPPROTO_UDP, &udp)
        );
    }

    #[test]
    fn tcp_uses_ipv6_checksum_context_when_previous_layer_provides_it() {
        let pseudo = Ipv6PseudoHeader::new();
        let source = pseudo.source;
        let destination = pseudo.destination;
        let bytes = (Packet::from_layer(pseudo)
            / Tcp::new().sport(10).dport(20)
            / Raw::from_bytes([1, 2, 3]))
        .compile()
        .unwrap();

        let mut tcp = bytes.as_bytes().to_vec();
        tcp[16] = 0;
        tcp[17] = 0;
        assert_eq!(
            u16::from_be_bytes([bytes.as_bytes()[16], bytes.as_bytes()[17]]),
            ipv6_pseudo_header_checksum(source, destination, IPPROTO_TCP, &tcp)
        );
    }

    #[test]
    fn transport_checksums_are_zero_without_network_context() {
        let udp = (Udp::new().sport(1).dport(2) / Raw::from("abc"))
            .compile()
            .unwrap();
        let tcp = (Tcp::new().sport(1).dport(2) / Raw::from("abc"))
            .compile()
            .unwrap();

        assert_eq!(&udp.as_bytes()[6..8], &[0, 0]);
        assert_eq!(&tcp.as_bytes()[16..18], &[0, 0]);
    }
}
