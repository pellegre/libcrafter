//! SVCB/HTTPS service-binding SvcParam types shared by the SVCB and HTTPS
//! RDATA variants.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};

use super::{
    DNS_SVCB_KEY_ALPN, DNS_SVCB_KEY_DOHPATH, DNS_SVCB_KEY_ECH, DNS_SVCB_KEY_IPV4HINT,
    DNS_SVCB_KEY_IPV6HINT, DNS_SVCB_KEY_MANDATORY, DNS_SVCB_KEY_NO_DEFAULT_ALPN, DNS_SVCB_KEY_PORT,
};

/// One SvcParam carried in the RDATA of an SVCB or HTTPS service-binding
/// record.
///
/// Each SvcParam is a {SvcParamKey, length, SvcParamValue} tuple (RFC 9460
/// Section 2.2). The SvcParamValue is kept as raw bytes: its format is
/// "determined by the SvcParamKey", so this primitive preserves the exact wire
/// bytes rather than reinterpreting each key's internal structure. Source-backed
/// keys have named constructors and a registry mnemonic; unknown keys round trip
/// as raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SvcParam {
    key: u16,
    value: Vec<u8>,
}

impl SvcParam {
    /// Build a SvcParam from an explicit SvcParamKey and value bytes.
    pub fn new(key: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            key,
            value: value.into(),
        }
    }

    /// Build a "mandatory" SvcParam (RFC 9460 Section 8). The value bytes are
    /// the wire encoding of the mandatory key list, carried verbatim.
    pub fn mandatory(value: impl Into<Vec<u8>>) -> Self {
        Self::new(DNS_SVCB_KEY_MANDATORY, value)
    }

    /// Build an "alpn" SvcParam (RFC 9460 Section 7.1). The value bytes are the
    /// wire encoding of the ALPN id list, carried verbatim.
    pub fn alpn(value: impl Into<Vec<u8>>) -> Self {
        Self::new(DNS_SVCB_KEY_ALPN, value)
    }

    /// Build a "no-default-alpn" SvcParam (RFC 9460 Section 7.1). On the wire
    /// this key has an empty value.
    pub fn no_default_alpn() -> Self {
        Self::new(DNS_SVCB_KEY_NO_DEFAULT_ALPN, Vec::new())
    }

    /// Build a "port" SvcParam (RFC 9460 Section 7.2) carrying a 16-bit port in
    /// network byte order.
    pub fn port(port: u16) -> Self {
        Self::new(DNS_SVCB_KEY_PORT, port.to_be_bytes().to_vec())
    }

    /// Build an "ipv4hint" SvcParam (RFC 9460 Section 7.3) from a list of IPv4
    /// addresses, encoded as their concatenated 4-octet values.
    pub fn ipv4hint<I>(addresses: I) -> Self
    where
        I: IntoIterator<Item = Ipv4Addr>,
    {
        let mut value = Vec::new();
        for address in addresses {
            value.extend_from_slice(&address.octets());
        }
        Self::new(DNS_SVCB_KEY_IPV4HINT, value)
    }

    /// Build an "ipv6hint" SvcParam (RFC 9460 Section 7.3) from a list of IPv6
    /// addresses, encoded as their concatenated 16-octet values.
    pub fn ipv6hint<I>(addresses: I) -> Self
    where
        I: IntoIterator<Item = Ipv6Addr>,
    {
        let mut value = Vec::new();
        for address in addresses {
            value.extend_from_slice(&address.octets());
        }
        Self::new(DNS_SVCB_KEY_IPV6HINT, value)
    }

    /// SvcParamKey value (an IANA DNS SVCB SvcParamKey).
    pub const fn key(&self) -> u16 {
        self.key
    }

    /// SvcParamValue bytes, kept verbatim from the wire.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// IANA registry mnemonic for a source-backed SvcParamKey, or `None` for
    /// keys this crate does not name (callers can fall back to the numeric
    /// `keyNNNNN` form).
    pub fn key_name(&self) -> Option<&'static str> {
        svcb_param_key_name(self.key)
    }

    fn encoded_len(&self) -> usize {
        4 + self.value.len()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let length = u16::try_from(self.value.len()).map_err(|_| {
            CrafterError::invalid_field_value(
                "dns.svcb.param.length",
                "SvcParamValue exceeds 65535 bytes",
            )
        })?;
        out.extend_from_slice(&self.key.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.value);
        Ok(())
    }
}

/// Return the IANA registry mnemonic for a source-backed SVCB/HTTPS
/// SvcParamKey, or `None` when the key is not named by this crate.
pub fn svcb_param_key_name(key: u16) -> Option<&'static str> {
    Some(match key {
        DNS_SVCB_KEY_MANDATORY => "mandatory",
        DNS_SVCB_KEY_ALPN => "alpn",
        DNS_SVCB_KEY_NO_DEFAULT_ALPN => "no-default-alpn",
        DNS_SVCB_KEY_PORT => "port",
        DNS_SVCB_KEY_IPV4HINT => "ipv4hint",
        DNS_SVCB_KEY_ECH => "ech",
        DNS_SVCB_KEY_IPV6HINT => "ipv6hint",
        DNS_SVCB_KEY_DOHPATH => "dohpath",
        _ => return None,
    })
}

/// An ordered, key-unique list of SVCB/HTTPS SvcParams.
///
/// On the wire the SvcParams are a series of {SvcParamKey, length, value}
/// tuples that "SHALL appear in increasing numeric order" with no duplicate
/// keys (RFC 9460 Section 2.2). This type sorts the params by key and rejects
/// duplicates so encoding is deterministic and conformant, while preserving each
/// SvcParamValue verbatim, including unknown keys and unknown value formats.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SvcParams {
    /// Params kept sorted by ascending SvcParamKey so encoding is deterministic
    /// and conformant regardless of construction order.
    params: Vec<SvcParam>,
}

impl SvcParams {
    /// Build a SvcParams list from explicit params.
    ///
    /// Params are sorted by ascending SvcParamKey so the encoded order is
    /// deterministic and conformant (RFC 9460 Section 2.2). A duplicate
    /// SvcParamKey is rejected with a structured error, matching the wire rule
    /// that keys are strictly increasing.
    pub fn new<I>(params: I) -> Result<Self>
    where
        I: IntoIterator<Item = SvcParam>,
    {
        let mut params: Vec<SvcParam> = params.into_iter().collect();
        params.sort_by_key(|param| param.key);
        for window in params.windows(2) {
            if window[0].key == window[1].key {
                return Err(CrafterError::invalid_field_value(
                    "dns.svcb.params",
                    "duplicate SvcParamKey in SVCB/HTTPS SvcParams",
                ));
            }
        }
        Ok(Self { params })
    }

    /// An empty SvcParams list (AliasMode records carry no params).
    pub fn empty() -> Self {
        Self { params: Vec::new() }
    }

    /// The SvcParams, sorted by ascending SvcParamKey.
    pub fn params(&self) -> &[SvcParam] {
        &self.params
    }

    /// True when no SvcParams are present.
    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }

    /// The SvcParamValue for a given SvcParamKey, if present.
    pub fn get(&self, key: u16) -> Option<&[u8]> {
        self.params
            .iter()
            .find(|param| param.key == key)
            .map(SvcParam::value)
    }

    pub(super) fn encoded_len(&self) -> usize {
        self.params.iter().map(SvcParam::encoded_len).sum()
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        for param in &self.params {
            param.encode(out)?;
        }
        Ok(())
    }

    /// Parse the SvcParams that consume the remainder of an SVCB/HTTPS RDATA
    /// field, rejecting truncated params, out-of-order keys, and duplicate keys
    /// with structured errors (RFC 9460 Section 2.2).
    pub(super) fn decode(field: &'static str, rdata: &[u8]) -> Result<Self> {
        let mut params: Vec<SvcParam> = Vec::new();
        let mut offset = 0usize;
        let mut last_key: Option<u16> = None;

        while offset < rdata.len() {
            if offset + 4 > rdata.len() {
                // A partial SvcParam header (fewer than the four fixed bytes)
                // means the end of the RDATA occurs within a SvcParam.
                return Err(CrafterError::buffer_too_short(
                    field,
                    offset + 4,
                    rdata.len(),
                ));
            }
            let key = read_u16_be(&rdata[offset..offset + 2])?;
            let length = read_u16_be(&rdata[offset + 2..offset + 4])? as usize;
            // Keys SHALL appear in strictly increasing numeric order, which also
            // forbids duplicate keys (RFC 9460 Section 2.2).
            if let Some(previous) = last_key {
                if key <= previous {
                    return Err(CrafterError::invalid_field_value(
                        field,
                        "SVCB/HTTPS SvcParamKeys must be in strictly increasing order",
                    ));
                }
            }
            last_key = Some(key);

            let value_start = offset + 4;
            let value_end = value_start + length;
            if value_end > rdata.len() {
                // The declared length runs past the end of the RDATA.
                return Err(CrafterError::buffer_too_short(
                    field,
                    value_end,
                    rdata.len(),
                ));
            }
            params.push(SvcParam::new(key, rdata[value_start..value_end].to_vec()));
            offset = value_end;
        }

        // Keys are already validated as strictly increasing, so the list is
        // sorted and duplicate-free.
        Ok(Self { params })
    }
}

#[cfg(test)]
mod dns_service_rdata {
    use super::super::{
        decode_record_data, Dns, DnsName, DnsRecord, DnsRecordData, DNS_CLASS_IN,
        DNS_SVCB_KEY_ALPN, DNS_SVCB_KEY_IPV4HINT, DNS_SVCB_KEY_PORT, DNS_TYPE_HTTPS, DNS_TYPE_SVCB,
    };
    use super::{svcb_param_key_name, SvcParam, SvcParams};
    use crate::{Ipv4, NetworkLayer, Packet, Udp};
    use core::net::Ipv4Addr;

    /// Build a DNS response carrying one answer, compile it through the packet
    /// stack, decode it back, and return the decoded answer's record data along
    /// with the original compiled bytes and the recompiled bytes for byte-stable
    /// round-trip assertions.
    fn round_trip_answer(answer: DnsRecord) -> (DnsRecordData, Vec<u8>, Vec<u8>) {
        let original = Dns::new().id(0x4242).response(true).answer(answer);
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 53))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53001)
            / original)
            .compile()
            .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let data = decoded.layer::<Dns>().unwrap().answers()[0].data().clone();
        let recompiled = decoded.compile().unwrap();
        (
            data,
            bytes.as_bytes().to_vec(),
            recompiled.as_bytes().to_vec(),
        )
    }

    #[test]
    fn svcb_alias_mode_record_round_trips_through_packet_stack() {
        // AliasMode SVCB (SvcPriority 0, RFC 9460 Section 2.4.2) with a real
        // target name and no SvcParams.
        let record = DnsRecord::svcb(
            "example.com.",
            3600,
            0,
            "foo.example.com.",
            SvcParams::empty(),
        );
        let (data, original, recompiled) = round_trip_answer(record);
        match data {
            DnsRecordData::Svcb {
                priority,
                target,
                params,
            } => {
                assert_eq!(priority, 0);
                assert_eq!(target, DnsName::parse("foo.example.com.").unwrap());
                assert!(params.is_empty());
            }
            other => panic!("expected SVCB data, got {other:?}"),
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn svcb_root_target_round_trips() {
        // A "." TargetName is valid on the wire (RFC 9460 Section 2.5) and must
        // round trip as the root name.
        let record = DnsRecord::svcb("example.com.", 3600, 1, ".", SvcParams::empty());
        let (data, original, recompiled) = round_trip_answer(record);
        if let DnsRecordData::Svcb { target, .. } = &data {
            assert_eq!(target, &DnsName::root());
        } else {
            panic!("expected SVCB data, got {data:?}");
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn https_service_mode_record_with_params_round_trips() {
        // ServiceMode HTTPS (RFC 9460 Section 2.2) carrying ordered SvcParams:
        // alpn (1), port (3), ipv4hint (4). Builders supply them out of order to
        // prove deterministic key ordering on encode.
        let params = SvcParams::new([
            SvcParam::ipv4hint([Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]),
            SvcParam::port(8443),
            SvcParam::alpn(b"\x02h2\x05h3-29".to_vec()),
        ])
        .unwrap();
        let record = DnsRecord::https("example.com.", 7200, 1, ".", params);
        let (data, original, recompiled) = round_trip_answer(record);
        match data {
            DnsRecordData::Https {
                priority,
                target,
                params,
            } => {
                assert_eq!(priority, 1);
                assert_eq!(target, DnsName::root());
                // Params are sorted by SvcParamKey: alpn(1), port(3), ipv4hint(4).
                let keys: Vec<u16> = params.params().iter().map(SvcParam::key).collect();
                assert_eq!(
                    keys,
                    vec![DNS_SVCB_KEY_ALPN, DNS_SVCB_KEY_PORT, DNS_SVCB_KEY_IPV4HINT]
                );
                // The port value decodes to its big-endian 16-bit form.
                assert_eq!(
                    params.get(DNS_SVCB_KEY_PORT),
                    Some(&8443u16.to_be_bytes()[..])
                );
                // ipv4hint carries the two addresses as concatenated octets.
                assert_eq!(
                    params.get(DNS_SVCB_KEY_IPV4HINT),
                    Some(&[192, 0, 2, 1, 192, 0, 2, 2][..])
                );
            }
            other => panic!("expected HTTPS data, got {other:?}"),
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn svcb_unknown_param_key_round_trips_as_raw_bytes() {
        // A SvcParamKey this crate does not name keeps its exact value bytes and
        // surfaces no mnemonic, but still round trips.
        let unknown_key = 0xfffeu16;
        let params = SvcParams::new([
            SvcParam::no_default_alpn(),
            SvcParam::new(unknown_key, vec![0xde, 0xad, 0xbe, 0xef]),
        ])
        .unwrap();
        let record = DnsRecord::svcb("example.com.", 60, 5, "svc.example.com.", params);
        let (data, original, recompiled) = round_trip_answer(record);
        if let DnsRecordData::Svcb { params, .. } = &data {
            let entries = params.params();
            assert_eq!(entries.len(), 2);
            // no-default-alpn (key 2) has an empty value and a known mnemonic.
            assert_eq!(entries[0].key(), super::super::DNS_SVCB_KEY_NO_DEFAULT_ALPN);
            assert!(entries[0].value().is_empty());
            assert_eq!(entries[0].key_name(), Some("no-default-alpn"));
            // The unknown key keeps its bytes and surfaces no mnemonic.
            assert_eq!(entries[1].key(), unknown_key);
            assert_eq!(entries[1].value(), &[0xde, 0xad, 0xbe, 0xef]);
            assert_eq!(entries[1].key_name(), None);
        } else {
            panic!("expected SVCB data, got {data:?}");
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn https_service_mode_full_param_set_sorts_and_preserves_values() {
        // Mirror of the dns-svcb-https oracle case: an HTTPS ServiceMode answer
        // with a root target carrying the full named SvcParam set (RFC 9460 / RFC
        // 9461) supplied out of key order plus an unknown key, proving that the
        // params encode in strictly increasing SvcParamKey order while each
        // SvcParamValue is preserved verbatim as opaque bytes.
        use super::super::{
            DNS_SVCB_KEY_DOHPATH, DNS_SVCB_KEY_ECH, DNS_SVCB_KEY_IPV6HINT, DNS_SVCB_KEY_MANDATORY,
            DNS_SVCB_KEY_NO_DEFAULT_ALPN,
        };
        let unknown_key = 0xff00u16;
        let params = SvcParams::new([
            // Deliberately scrambled construction order: unknown key, ipv6hint,
            // ech, dohpath, mandatory, alpn, no-default-alpn, port, ipv4hint.
            SvcParam::new(unknown_key, vec![0xde, 0xad, 0xbe, 0xef]),
            SvcParam::new(
                DNS_SVCB_KEY_IPV6HINT,
                b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01".to_vec(),
            ),
            SvcParam::new(DNS_SVCB_KEY_ECH, vec![0x01, 0x02, 0x03]),
            SvcParam::new(DNS_SVCB_KEY_DOHPATH, b"/dns-query{?dns}".to_vec()),
            // mandatory lists alpn(1) and port(3) as two-octet keys.
            SvcParam::mandatory(b"\x00\x01\x00\x03".to_vec()),
            SvcParam::alpn(b"\x02h2\x05h3-29".to_vec()),
            SvcParam::no_default_alpn(),
            SvcParam::port(443),
            SvcParam::ipv4hint([Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 10)]),
        ])
        .unwrap();
        let record = DnsRecord::https("example.com.", 7200, 1, ".", params);
        let (data, original, recompiled) = round_trip_answer(record);
        let DnsRecordData::Https {
            priority,
            target,
            params,
        } = data
        else {
            panic!("expected HTTPS data");
        };
        assert_eq!(priority, 1);
        assert_eq!(target, DnsName::root());
        // Keys appear in strictly increasing numeric order with the unknown key
        // last (RFC 9460 Section 2.2).
        let keys: Vec<u16> = params.params().iter().map(SvcParam::key).collect();
        assert_eq!(
            keys,
            vec![
                DNS_SVCB_KEY_MANDATORY,
                DNS_SVCB_KEY_ALPN,
                DNS_SVCB_KEY_NO_DEFAULT_ALPN,
                DNS_SVCB_KEY_PORT,
                DNS_SVCB_KEY_IPV4HINT,
                DNS_SVCB_KEY_ECH,
                DNS_SVCB_KEY_IPV6HINT,
                DNS_SVCB_KEY_DOHPATH,
                unknown_key,
            ]
        );
        // Opaque values survive verbatim.
        assert_eq!(
            params.get(DNS_SVCB_KEY_MANDATORY),
            Some(&[0x00, 0x01, 0x00, 0x03][..])
        );
        assert_eq!(params.get(DNS_SVCB_KEY_ALPN), Some(&b"\x02h2\x05h3-29"[..]));
        assert_eq!(params.get(DNS_SVCB_KEY_NO_DEFAULT_ALPN), Some(&[][..]));
        assert_eq!(
            params.get(DNS_SVCB_KEY_PORT),
            Some(&443u16.to_be_bytes()[..])
        );
        assert_eq!(
            params.get(DNS_SVCB_KEY_IPV4HINT),
            Some(&[192, 0, 2, 1, 192, 0, 2, 10][..])
        );
        assert_eq!(
            params.get(DNS_SVCB_KEY_DOHPATH),
            Some(&b"/dns-query{?dns}"[..])
        );
        assert_eq!(params.get(unknown_key), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
        // The unknown key surfaces no mnemonic.
        assert_eq!(svcb_param_key_name(unknown_key), None);
        // Byte-stable round trip through the packet stack.
        assert_eq!(recompiled, original);
    }

    #[test]
    fn svcb_param_key_names_cover_source_backed_keys() {
        assert_eq!(
            svcb_param_key_name(super::super::DNS_SVCB_KEY_MANDATORY),
            Some("mandatory")
        );
        assert_eq!(svcb_param_key_name(DNS_SVCB_KEY_ALPN), Some("alpn"));
        assert_eq!(svcb_param_key_name(DNS_SVCB_KEY_PORT), Some("port"));
        assert_eq!(
            svcb_param_key_name(super::super::DNS_SVCB_KEY_DOHPATH),
            Some("dohpath")
        );
        // Unassigned keys stay numeric for callers to format.
        assert_eq!(svcb_param_key_name(60000), None);
    }

    #[test]
    fn svcparams_reject_duplicate_keys_on_construction() {
        // Strictly increasing keys forbid duplicates (RFC 9460 Section 2.2).
        let result = SvcParams::new([SvcParam::port(443), SvcParam::port(8443)]);
        assert!(result.is_err());
    }

    #[test]
    fn svcparams_construction_order_does_not_change_encoded_bytes() {
        // Two constructions with the same params in different orders must encode
        // identically because keys are sorted deterministically.
        let a = SvcParams::new([SvcParam::port(443), SvcParam::alpn(b"\x02h2".to_vec())]).unwrap();
        let b = SvcParams::new([SvcParam::alpn(b"\x02h2".to_vec()), SvcParam::port(443)]).unwrap();
        let mut encoded_a = Vec::new();
        let mut encoded_b = Vec::new();
        super::SvcParams::encode(&a, &mut encoded_a).unwrap();
        super::SvcParams::encode(&b, &mut encoded_b).unwrap();
        assert_eq!(encoded_a, encoded_b);
    }

    #[test]
    fn svcb_too_short_priority_is_rejected() {
        // Fewer than the two SvcPriority octets.
        let rdata = [0u8];
        assert!(decode_record_data(DNS_TYPE_SVCB, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn svcb_truncated_param_header_is_rejected() {
        // Priority + root target + a partial SvcParam header (RFC 9460 Section
        // 2.2: malformed if the end of the RDATA occurs within a SvcParam).
        let rdata = [0u8, 1, 0, 0x00, 0x03, 0x00]; // key 3 + half a length field
        assert!(decode_record_data(DNS_TYPE_SVCB, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn svcb_param_value_length_overrun_is_rejected() {
        // Priority + root target + a SvcParam whose declared length runs past the
        // RDATA.
        let mut rdata = vec![0u8, 1, 0]; // priority 1, root target
        rdata.extend_from_slice(&DNS_SVCB_KEY_PORT.to_be_bytes()); // key
        rdata.extend_from_slice(&8u16.to_be_bytes()); // length 8
        rdata.extend_from_slice(&[0u8; 2]); // only 2 value bytes present
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_SVCB, &rdata, 0, end).is_err());
    }

    #[test]
    fn svcb_out_of_order_param_keys_are_rejected() {
        // Keys must be in strictly increasing numeric order on the wire; a
        // decreasing pair is malformed (RFC 9460 Section 2.2).
        let mut rdata = vec![0u8, 1, 0]; // priority 1, root target
                                         // port (3) with empty value, then alpn (1) with empty value: decreasing.
        rdata.extend_from_slice(&DNS_SVCB_KEY_PORT.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&DNS_SVCB_KEY_ALPN.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_SVCB, &rdata, 0, end).is_err());
    }

    #[test]
    fn svcb_duplicate_param_keys_on_wire_are_rejected() {
        // The strictly-increasing rule also forbids duplicate keys.
        let mut rdata = vec![0u8, 1, 0]; // priority 1, root target
        rdata.extend_from_slice(&DNS_SVCB_KEY_ALPN.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        rdata.extend_from_slice(&DNS_SVCB_KEY_ALPN.to_be_bytes());
        rdata.extend_from_slice(&0u16.to_be_bytes());
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_SVCB, &rdata, 0, end).is_err());
    }

    #[test]
    fn svcb_oversized_param_value_returns_structured_error_on_encode() {
        // Each SvcParam length is a u16 field (RFC 9460 Section 2.2), so a
        // SvcParamValue longer than 65535 bytes cannot encode its length and must
        // surface a structured CrafterError carrying the dns.svcb.param.length
        // field rather than panic or silently truncate.
        use crate::error::CrafterError;

        let oversized = SvcParam::new(0xff00u16, vec![0u8; 65_536]);
        let params = SvcParams::new([oversized]).unwrap();
        let record = DnsRecord::svcb("example.com.", 3600, 1, "svc.example.com.", params);
        let error = Packet::from_layer(Dns::new().response(true).answer(record))
            .compile()
            .expect_err("oversized SvcParamValue must be rejected on encode");
        match error {
            CrafterError::InvalidFieldValue { field, .. } => {
                assert_eq!(field, "dns.svcb.param.length")
            }
            other => panic!("expected dns.svcb.param.length invalid-field-value, got {other:?}"),
        }
    }

    #[test]
    fn svcb_record_data_type_mismatch_is_rejected_on_compile() {
        // An SVCB payload under an HTTPS type must be refused at compile time.
        let record = DnsRecord::new(
            "example.com.",
            DNS_TYPE_HTTPS,
            DNS_CLASS_IN,
            60,
            DnsRecordData::Svcb {
                priority: 1,
                target: DnsName::root(),
                params: SvcParams::empty(),
            },
        );
        assert!(Packet::from_layer(Dns::new().answer(record))
            .compile()
            .is_err());
    }
}
