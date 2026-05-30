//! EDNS(0) OPT option types and OPT TTL packing helpers.

use crate::error::{CrafterError, Result};

use super::{
    DNS_EDNS_EXTENDED_RCODE_SHIFT, DNS_EDNS_FLAG_DO, DNS_EDNS_OPTION_CLIENT_SUBNET,
    DNS_EDNS_OPTION_COOKIE, DNS_EDNS_OPTION_DAU, DNS_EDNS_OPTION_DHU, DNS_EDNS_OPTION_EXPIRE,
    DNS_EDNS_OPTION_EXTENDED_ERROR, DNS_EDNS_OPTION_N3U, DNS_EDNS_OPTION_NSID,
    DNS_EDNS_OPTION_PADDING, DNS_EDNS_OPTION_TCP_KEEPALIVE, DNS_EDNS_VERSION_SHIFT,
};

/// One EDNS(0) option carried in the RDATA of an OPT pseudo-record.
///
/// Each option is an {OPTION-CODE, OPTION-LENGTH, OPTION-DATA} tuple
/// (RFC 6891 Section 6.1.2). The option data is kept as raw bytes: every
/// OPTION-DATA "MUST be treated as a bit field" and its layout varies per
/// OPTION-CODE, so this primitive preserves the exact wire bytes rather than
/// reinterpreting each option's internal structure. Source-backed option codes
/// have named constructors and a registry mnemonic; unknown codes round trip as
/// raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdnsOption {
    code: u16,
    data: Vec<u8>,
}

impl EdnsOption {
    /// Build an EDNS option from an explicit option code and data bytes.
    pub fn new(code: u16, data: impl Into<Vec<u8>>) -> Self {
        Self {
            code,
            data: data.into(),
        }
    }

    /// Build an NSID option (RFC 5001), carrying opaque identifier bytes.
    pub fn nsid(data: impl Into<Vec<u8>>) -> Self {
        Self::new(DNS_EDNS_OPTION_NSID, data)
    }

    /// Build a COOKIE option (RFC 7873), carrying the client/server cookie
    /// bytes verbatim.
    pub fn cookie(data: impl Into<Vec<u8>>) -> Self {
        Self::new(DNS_EDNS_OPTION_COOKIE, data)
    }

    /// Build a Padding option (RFC 7830) of `len` zero octets.
    pub fn padding(len: usize) -> Self {
        Self::new(DNS_EDNS_OPTION_PADDING, vec![0u8; len])
    }

    /// Option code value (an IANA DNS EDNS0 Option Code).
    pub const fn code(&self) -> u16 {
        self.code
    }

    /// Option data bytes, kept verbatim from the wire.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// IANA registry mnemonic for a source-backed EDNS option code, or `None`
    /// for codes this crate does not name (callers can fall back to the numeric
    /// value).
    pub fn option_code_name(&self) -> Option<&'static str> {
        edns_option_code_name(self.code)
    }

    pub(super) fn encoded_len(&self) -> usize {
        4 + self.data.len()
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let length = u16::try_from(self.data.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "dns.opt.option.length",
                "EDNS option data exceeds 65535 bytes",
            )
        })?;
        out.extend_from_slice(&self.code.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

/// Return the IANA registry mnemonic for a source-backed EDNS(0) option code,
/// or `None` when the code is not named by this crate.
pub fn edns_option_code_name(code: u16) -> Option<&'static str> {
    Some(match code {
        DNS_EDNS_OPTION_NSID => "NSID",
        DNS_EDNS_OPTION_DAU => "DAU",
        DNS_EDNS_OPTION_DHU => "DHU",
        DNS_EDNS_OPTION_N3U => "N3U",
        DNS_EDNS_OPTION_CLIENT_SUBNET => "edns-client-subnet",
        DNS_EDNS_OPTION_EXPIRE => "EDNS EXPIRE",
        DNS_EDNS_OPTION_COOKIE => "COOKIE",
        DNS_EDNS_OPTION_TCP_KEEPALIVE => "edns-tcp-keepalive",
        DNS_EDNS_OPTION_PADDING => "Padding",
        DNS_EDNS_OPTION_EXTENDED_ERROR => "Extended DNS Error",
        _ => return None,
    })
}

/// Pack the EDNS(0) OPT TTL field from its EXTENDED-RCODE, VERSION, DO flag,
/// and Z bits (RFC 6891 Section 6.1.3). `z` carries the reserved Z bits
/// alongside the DO bit in the lower 16-bit half; the DO bit is set or cleared
/// from `dnssec_ok` so callers do not have to encode it into `z` themselves.
pub(super) fn encode_edns_ttl(extended_rcode: u8, version: u8, dnssec_ok: bool, z: u16) -> u32 {
    let mut flags = z & !DNS_EDNS_FLAG_DO;
    if dnssec_ok {
        flags |= DNS_EDNS_FLAG_DO;
    }
    ((extended_rcode as u32) << DNS_EDNS_EXTENDED_RCODE_SHIFT)
        | ((version as u32) << DNS_EDNS_VERSION_SHIFT)
        | (flags as u32)
}

#[cfg(test)]
mod dns_edns {
    use super::super::{
        decode_record_data, Dns, DnsRecord, DnsRecordData, EdnsOption,
        DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE, DNS_EDNS_OPTION_COOKIE, DNS_EDNS_OPTION_NSID,
        DNS_TYPE_OPT,
    };
    use crate::{Ipv4, NetworkLayer, Packet, Udp};
    use core::net::Ipv4Addr;

    /// Build a DNS query carrying one OPT additional record, compile it through
    /// the packet stack, decode it back, and return the decoded additional
    /// record along with the original and recompiled bytes for byte-stable
    /// round-trip assertions.
    fn round_trip_opt(opt: DnsRecord) -> (DnsRecord, Vec<u8>, Vec<u8>) {
        let original = Dns::a_query("example.com.").id(0x4242).additional(opt);
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            / Udp::new().sport(53001).dport(53)
            / original)
            .compile()
            .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let record = decoded.layer::<Dns>().unwrap().additionals()[0].clone();
        let recompiled = decoded.compile().unwrap();
        (
            record,
            bytes.as_bytes().to_vec(),
            recompiled.as_bytes().to_vec(),
        )
    }

    #[test]
    fn dns_edns_opt_with_no_options_round_trips() {
        // A bare OPT record (RFC 6891 Section 6.1) advertises a UDP payload
        // size and the DO flag with an empty option list.
        let opt = DnsRecord::opt(DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE, 0, 0, true, Vec::new());
        let (record, original, recompiled) = round_trip_opt(opt);

        assert!(record.is_opt());
        // The OPT CLASS field carries the UDP payload size; the raw class
        // getter and the EDNS view agree.
        assert_eq!(record.class(), 4096);
        assert_eq!(record.edns_udp_payload_size(), 4096);
        assert_eq!(record.edns_extended_rcode(), 0);
        assert_eq!(record.edns_version(), 0);
        assert!(record.edns_dnssec_ok());
        // Empty RDATA decodes to an empty, non-None option list.
        assert_eq!(record.edns_options(), Some(&[][..]));
        assert_eq!(record.data(), &DnsRecordData::Opt(Vec::new()));
        // The OPT owner name is root and the bytes round trip unchanged.
        assert_eq!(record.name(), ".");
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dns_edns_opt_with_typed_option_round_trips() {
        // NSID (RFC 5001) is a source-backed option in the coverage map; its
        // data is opaque identifier bytes carried verbatim.
        let opt = DnsRecord::opt(1232, 0, 0, false, vec![EdnsOption::nsid(b"ns1".to_vec())]);
        let (record, original, recompiled) = round_trip_opt(opt);

        let options = record.edns_options().unwrap();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].code(), DNS_EDNS_OPTION_NSID);
        assert_eq!(options[0].data(), b"ns1");
        assert_eq!(options[0].option_code_name(), Some("NSID"));
        assert_eq!(record.edns_udp_payload_size(), 1232);
        assert!(!record.edns_dnssec_ok());
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dns_edns_opt_unknown_option_round_trips_as_raw_bytes() {
        // An option with a code this crate does not name keeps its exact data
        // bytes and surfaces no mnemonic, but still round trips.
        let unknown_code = 0xfffeu16;
        let opt = DnsRecord::opt(
            512,
            0,
            0,
            false,
            vec![
                EdnsOption::cookie(b"clientcookie".to_vec()),
                EdnsOption::new(unknown_code, vec![0xde, 0xad, 0xbe, 0xef]),
            ],
        );
        let (record, original, recompiled) = round_trip_opt(opt);

        let options = record.edns_options().unwrap();
        assert_eq!(options.len(), 2);
        assert_eq!(options[0].code(), DNS_EDNS_OPTION_COOKIE);
        assert_eq!(options[0].option_code_name(), Some("COOKIE"));
        assert_eq!(options[1].code(), unknown_code);
        assert_eq!(options[1].option_code_name(), None);
        assert_eq!(options[1].data(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dns_edns_unsupported_version_is_preserved_not_rejected() {
        // VERSION validation (RCODE=BADVERS) is resolver policy and out of
        // scope; the wire primitive must carry any version verbatim.
        let opt = DnsRecord::opt(4096, 0, 7, false, vec![EdnsOption::padding(4)]);
        let (record, original, recompiled) = round_trip_opt(opt);

        assert_eq!(record.edns_version(), 7);
        assert_eq!(record.edns_options().unwrap()[0].data(), &[0, 0, 0, 0]);
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dns_edns_extended_rcode_and_flags_fold_into_ttl() {
        // EXTENDED-RCODE and the DO flag share the OPT TTL field; reading the
        // typed getters must reflect the packed value exactly.
        let opt = DnsRecord::opt(4096, 0x12, 0, true, Vec::new());
        assert_eq!(opt.edns_extended_rcode(), 0x12);
        assert!(opt.edns_dnssec_ok());
        // The full lower-16 flags word carries only the DO bit here.
        assert_eq!(opt.edns_flags(), super::super::DNS_EDNS_FLAG_DO);
    }

    #[test]
    fn dns_edns_option_length_overrun_is_rejected() {
        // OPTION-LENGTH claims more data than the RDATA actually carries.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&DNS_EDNS_OPTION_NSID.to_be_bytes()); // code
        rdata.extend_from_slice(&8u16.to_be_bytes()); // length 8
        rdata.extend_from_slice(&[0u8; 2]); // only 2 data bytes present
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_OPT, &rdata, 0, end).is_err());
    }

    #[test]
    fn dns_edns_truncated_option_header_is_rejected() {
        // Fewer than the four fixed option-header bytes remain in the RDATA.
        let rdata = [0x00u8, 0x03, 0x00]; // code + half a length field
        assert!(decode_record_data(DNS_TYPE_OPT, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn dns_edns_option_data_too_large_is_rejected_on_encode() {
        // An option carrying more than 65535 data bytes cannot encode an
        // OPTION-LENGTH and must error rather than truncate.
        let oversized = EdnsOption::new(DNS_EDNS_OPTION_NSID, vec![0u8; 65_536]);
        let opt = DnsRecord::opt(4096, 0, 0, false, vec![oversized]);
        assert!(Packet::from_layer(Dns::new().additional(opt))
            .compile()
            .is_err());
    }
}
