//! DNSSEC "Type Bit Maps" wire helper shared by NSEC and NSEC3 RDATA.

use crate::error::{CrafterError, Result};

/// A DNSSEC "Type Bit Maps" field: the set of RR types present at an owner
/// name, as carried by NSEC (RFC 4034 Section 4.1.2) and NSEC3 (RFC 5155
/// Section 3.2.1).
///
/// On the wire the field is a sequence of `(Window Block #, Bitmap Length,
/// Bitmap)` triples in increasing window order. Each window covers 256 RR
/// types (the low 8 bits of the type for that window block); a set bit means
/// the corresponding type is present.
///
/// This is a pure wire structure: it preserves the exact set of present type
/// values, including unknown or unassigned codepoints, and re-encodes them
/// deterministically. It performs no resolver, validation, or trust logic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DnsTypeBitmaps {
    /// Present RR type values, kept sorted and de-duplicated so encoding is
    /// deterministic regardless of construction order.
    types: Vec<u16>,
}

impl DnsTypeBitmaps {
    /// Build a type-bitmaps field from an explicit set of RR type values.
    ///
    /// Duplicate values are collapsed and the set is sorted so the encoded
    /// windows are deterministic. Unknown or unassigned type values are
    /// preserved verbatim; nothing is rejected here.
    pub fn from_types<I>(types: I) -> Self
    where
        I: IntoIterator<Item = u16>,
    {
        let mut types: Vec<u16> = types.into_iter().collect();
        types.sort_unstable();
        types.dedup();
        Self { types }
    }

    /// The present RR type values, sorted ascending.
    pub fn types(&self) -> &[u16] {
        &self.types
    }

    /// True when the given RR type value is marked present.
    pub fn contains(&self, record_type: u16) -> bool {
        self.types.binary_search(&record_type).is_ok()
    }

    pub(super) fn encoded_len(&self) -> usize {
        let mut len = 0usize;
        let mut window = None;
        let mut max_low = 0u16;
        for &record_type in &self.types {
            let block = (record_type >> 8) as u8;
            let low = record_type & 0xff;
            match window {
                Some(current) if current == block => {
                    max_low = max_low.max(low);
                }
                _ => {
                    if window.is_some() {
                        len += 2 + (max_low as usize / 8) + 1;
                    }
                    window = Some(block);
                    max_low = low;
                }
            }
        }
        if window.is_some() {
            len += 2 + (max_low as usize / 8) + 1;
        }
        len
    }

    /// Serialize the type-bitmaps field to wire form: windows in increasing
    /// order, each with the minimal bitmap length (no trailing zero octets),
    /// per RFC 4034 Section 4.1.2.
    pub(super) fn encode(&self, out: &mut Vec<u8>) {
        // Group present types by their high octet (window block), tracking the
        // highest low octet per window so the bitmap length is minimal.
        let mut window: Option<u8> = None;
        let mut bitmap = [0u8; 32];
        let mut max_low = 0u16;

        let flush = |window: u8, bitmap: &[u8; 32], max_low: u16, out: &mut Vec<u8>| {
            let length = (max_low as usize / 8) + 1;
            out.push(window);
            out.push(length as u8);
            out.extend_from_slice(&bitmap[..length]);
        };

        for &record_type in &self.types {
            let block = (record_type >> 8) as u8;
            let low = record_type & 0xff;
            match window {
                Some(current) if current == block => {}
                _ => {
                    if let Some(current) = window {
                        flush(current, &bitmap, max_low, out);
                    }
                    window = Some(block);
                    bitmap = [0u8; 32];
                    max_low = 0;
                }
            }
            bitmap[(low / 8) as usize] |= 0x80 >> (low % 8);
            max_low = max_low.max(low);
        }
        if let Some(current) = window {
            flush(current, &bitmap, max_low, out);
        }
    }

    /// Parse a type-bitmaps field from wire bytes (`rdata`), rejecting malformed
    /// window numbers, bitmap lengths, and truncated bitmaps with structured
    /// errors (RFC 4034 Section 4.1.2; RFC 5155 Section 3.2.1).
    pub(super) fn decode(field: &'static str, rdata: &[u8]) -> Result<Self> {
        let mut types: Vec<u16> = Vec::new();
        let mut offset = 0usize;
        let mut last_window: Option<u8> = None;

        while offset < rdata.len() {
            if offset + 2 > rdata.len() {
                // A window number with no bitmap-length octet is truncated.
                return Err(CrafterError::buffer_too_short(
                    field,
                    offset + 2,
                    rdata.len(),
                ));
            }
            let window = rdata[offset];
            let length = rdata[offset + 1] as usize;
            // Bitmap Length is "from 1 to 32" (RFC 4034 Section 4.1.2): a
            // zero-length or over-long window block is malformed.
            if length == 0 || length > 32 {
                return Err(CrafterError::invalid_field_value(
                    field,
                    "DNSSEC type bitmap window length must be 1..=32",
                ));
            }
            // Blocks are present in increasing numerical order; an out-of-order
            // or repeated window is malformed.
            if let Some(previous) = last_window {
                if window <= previous {
                    return Err(CrafterError::invalid_field_value(
                        field,
                        "DNSSEC type bitmap windows must be strictly increasing",
                    ));
                }
            }
            last_window = Some(window);

            let bitmap_start = offset + 2;
            let bitmap_end = bitmap_start + length;
            if bitmap_end > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    field,
                    bitmap_end,
                    rdata.len(),
                ));
            }
            let bitmap = &rdata[bitmap_start..bitmap_end];
            // A minimal encoding never carries a trailing all-zero octet; treat
            // a zero high octet as malformed so re-encoding stays deterministic.
            if let Some(&last) = bitmap.last() {
                if last == 0 {
                    return Err(CrafterError::invalid_field_value(
                        field,
                        "DNSSEC type bitmap has a trailing zero octet",
                    ));
                }
            }
            for (byte_index, &byte) in bitmap.iter().enumerate() {
                let mut bits = byte;
                while bits != 0 {
                    let bit = bits.leading_zeros() as u16;
                    let low = (byte_index as u16) * 8 + bit;
                    let record_type = ((window as u16) << 8) | low;
                    types.push(record_type);
                    bits &= !(0x80u8 >> bit);
                }
            }
            offset = bitmap_end;
        }

        // Types are produced in ascending order already; keep the invariant.
        Ok(Self { types })
    }
}

#[cfg(test)]
mod dns_dnssec {
    use super::super::{
        decode_record_data, Dns, DnsName, DnsRecord, DnsRecordData, DNS_CLASS_IN, DNS_TYPE_A,
        DNS_TYPE_DS, DNS_TYPE_MX, DNS_TYPE_NSEC, DNS_TYPE_NSEC3, DNS_TYPE_NSEC3PARAM,
        DNS_TYPE_RRSIG,
    };
    use super::DnsTypeBitmaps;
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
    fn dnssec_ds_record_round_trips_through_packet_stack() {
        // DS RDATA wire format: Key Tag (2), Algorithm (1), Digest Type (1),
        // Digest (rest) (RFC 4034 Section 5.1). Algorithm and digest type stay
        // raw numeric fields; the digest is opaque bytes.
        let digest = vec![0xab; 20]; // SHA-1-length digest, not validated.
        let (data, original, recompiled) = round_trip_answer(DnsRecord::ds(
            "example.com.",
            300,
            12345,
            8,
            2,
            digest.clone(),
        ));
        assert_eq!(
            data,
            DnsRecordData::Ds {
                key_tag: 12345,
                algorithm: 8,
                digest_type: 2,
                digest,
            }
        );
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_dnskey_record_round_trips_through_packet_stack() {
        // DNSKEY RDATA wire format: Flags (2), Protocol (1), Algorithm (1),
        // Public Key (rest) (RFC 4034 Section 2.1).
        let public_key = vec![0x03, 0x01, 0x00, 0x01, 0xde, 0xad, 0xbe, 0xef];
        let (data, original, recompiled) = round_trip_answer(DnsRecord::dnskey(
            "example.com.",
            3600,
            257, // Zone Key + SEP, carried verbatim.
            3,
            8,
            public_key.clone(),
        ));
        assert_eq!(
            data,
            DnsRecordData::Dnskey {
                flags: 257,
                protocol: 3,
                algorithm: 8,
                public_key,
            }
        );
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_rrsig_record_round_trips_through_packet_stack() {
        // RRSIG RDATA: 18 fixed octets, uncompressed Signer's Name, Signature
        // (RFC 4034 Section 3.1). The signature is opaque bytes.
        let signature = vec![0x5a; 32];
        let (data, original, recompiled) = round_trip_answer(DnsRecord::rrsig(
            "example.com.",
            3600,
            DNS_TYPE_A,
            8,
            2,
            3600,
            0x6500_0000,
            0x6400_0000,
            12345,
            "example.com.",
            signature.clone(),
        ));
        assert_eq!(
            data,
            DnsRecordData::Rrsig {
                type_covered: DNS_TYPE_A,
                algorithm: 8,
                labels: 2,
                original_ttl: 3600,
                signature_expiration: 0x6500_0000,
                signature_inception: 0x6400_0000,
                key_tag: 12345,
                signer_name: DnsName::parse("example.com.").unwrap(),
                signature,
            }
        );
        // Signer's Name is emitted uncompressed, so bytes round trip exactly.
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_nsec_record_matches_rfc4034_example_bitmap() {
        // RFC 4034 Section 4.3 NSEC example: next name host.example.com. with
        // the A, MX, RRSIG, NSEC, and TYPE1234 types present. Build the same
        // record and assert the exact RDATA wire bytes from the RFC.
        let record = DnsRecord::nsec(
            "alfa.example.com.",
            86400,
            "host.example.com.",
            [DNS_TYPE_A, DNS_TYPE_MX, DNS_TYPE_RRSIG, DNS_TYPE_NSEC, 1234],
        );

        // Encode just the RDATA by compiling the record into a buffer and
        // skipping the name/type/class/ttl/rdlength header.
        let mut wire = Vec::new();
        DnsRecord::encode(&record, &mut wire).unwrap();
        // The RDATA portion as printed in RFC 4034 Section 4.3: the next domain
        // name host.example.com., window 0 (A, MX, RRSIG, NSEC), and window 4
        // (TYPE1234) with a 27-octet bitmap.
        let expected_rdata: &[u8] = &[
            0x04, b'h', b'o', b's', b't', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03,
            b'c', b'o', b'm', 0x00, 0x00, 0x06, 0x40, 0x01, 0x00, 0x00, 0x00, 0x03, 0x04, 0x1b,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20,
        ];
        assert!(
            wire.ends_with(expected_rdata),
            "NSEC RDATA must match the RFC 4034 Section 4.3 example bytes"
        );
    }

    #[test]
    fn dnssec_nsec_record_round_trips_through_packet_stack() {
        let present = [DNS_TYPE_A, DNS_TYPE_MX, DNS_TYPE_RRSIG, DNS_TYPE_NSEC, 1234];
        let (data, original, recompiled) = round_trip_answer(DnsRecord::nsec(
            "alfa.example.com.",
            86400,
            "host.example.com.",
            present,
        ));
        match data {
            DnsRecordData::Nsec {
                next_domain_name,
                type_bitmaps,
            } => {
                assert_eq!(
                    next_domain_name,
                    DnsName::parse("host.example.com.").unwrap()
                );
                // Present types are recovered, sorted, including the unknown
                // TYPE1234 codepoint.
                assert_eq!(type_bitmaps.types(), &[1, 15, 46, 47, 1234]);
                assert!(type_bitmaps.contains(1234));
                assert!(!type_bitmaps.contains(2));
            }
            other => panic!("expected NSEC data, got {other:?}"),
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_nsec3_record_round_trips_through_packet_stack() {
        // NSEC3 RDATA: Hash Alg, Flags, Iterations, Salt Length+Salt, Hash
        // Length+Hash, Type Bit Maps (RFC 5155 Section 3.2).
        let salt = vec![0xaa, 0xbb, 0xcc, 0xdd];
        let next_hash = vec![0x11; 20];
        let (data, original, recompiled) = round_trip_answer(DnsRecord::nsec3(
            "example.com.",
            3600,
            1, // SHA-1
            1, // Opt-Out
            10,
            salt.clone(),
            next_hash.clone(),
            [DNS_TYPE_A, DNS_TYPE_RRSIG],
        ));
        match data {
            DnsRecordData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt: decoded_salt,
                next_hashed_owner_name,
                type_bitmaps,
            } => {
                assert_eq!(hash_algorithm, 1);
                assert_eq!(flags, 1);
                assert_eq!(iterations, 10);
                assert_eq!(decoded_salt, salt);
                assert_eq!(next_hashed_owner_name, next_hash);
                assert_eq!(type_bitmaps.types(), &[1, 46]);
            }
            other => panic!("expected NSEC3 data, got {other:?}"),
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_nsec3_empty_salt_round_trips() {
        // Salt Length zero omits the Salt field (RFC 5155 Section 3.2).
        let (data, original, recompiled) = round_trip_answer(DnsRecord::nsec3(
            "example.com.",
            3600,
            1,
            0,
            5,
            Vec::new(),
            vec![0x22; 20],
            [DNS_TYPE_A],
        ));
        if let DnsRecordData::Nsec3 { salt, .. } = &data {
            assert!(salt.is_empty());
        } else {
            panic!("expected NSEC3 data, got {data:?}");
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_nsec3_unknown_algorithm_and_bitmap_codepoints_round_trip() {
        // Hash Algorithm is a raw numeric field, so an unassigned value must
        // survive verbatim. The Type Bit Maps carry multiple entries spanning
        // several window blocks including an unknown high codepoint, and a
        // non-empty Salt and next hashed owner name (RFC 5155 Section 3.2). None
        // of this is cryptographically validated; it is wire data only.
        let salt = vec![0xde, 0xad, 0xbe, 0xef];
        let next_hash = vec![0x33; 20];
        let (data, original, recompiled) = round_trip_answer(DnsRecord::nsec3(
            "example.com.",
            3600,
            0xfe, // unassigned hash algorithm
            0x00,
            2500,
            salt.clone(),
            next_hash.clone(),
            // Unsorted input with a duplicate plus a high unknown codepoint
            // spanning multiple window blocks; construction sorts/dedups.
            [DNS_TYPE_RRSIG, DNS_TYPE_A, 1234u16, DNS_TYPE_A, 0xff10],
        ));
        match data {
            DnsRecordData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt: decoded_salt,
                next_hashed_owner_name,
                type_bitmaps,
            } => {
                assert_eq!(hash_algorithm, 0xfe);
                assert_eq!(flags, 0x00);
                assert_eq!(iterations, 2500);
                assert_eq!(decoded_salt, salt);
                assert_eq!(next_hashed_owner_name, next_hash);
                assert_eq!(type_bitmaps.types(), &[1, 46, 1234, 0xff10]);
            }
            other => panic!("expected NSEC3 data, got {other:?}"),
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_unknown_algorithm_and_digest_values_are_preserved() {
        // Algorithm and digest-type values stay raw numeric fields, so values
        // outside the named registry entries must round trip verbatim.
        let (data, original, recompiled) = round_trip_answer(DnsRecord::ds(
            "example.com.",
            300,
            0xffff,
            0xfe, // unassigned algorithm
            0xfd, // unassigned digest type
            vec![0x00, 0x01, 0x02],
        ));
        if let DnsRecordData::Ds {
            algorithm,
            digest_type,
            ..
        } = &data
        {
            assert_eq!(*algorithm, 0xfe);
            assert_eq!(*digest_type, 0xfd);
        } else {
            panic!("expected DS data, got {data:?}");
        }
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_type_bitmaps_dedup_and_sort_deterministically() {
        // Construction order and duplicates must not change the encoded windows.
        let a = DnsTypeBitmaps::from_types([47u16, 1, 15, 1, 46]);
        let b = DnsTypeBitmaps::from_types([1u16, 15, 46, 47]);
        assert_eq!(a.types(), &[1, 15, 46, 47]);

        let mut encoded_a = Vec::new();
        let mut encoded_b = Vec::new();
        DnsTypeBitmaps::encode(&a, &mut encoded_a);
        DnsTypeBitmaps::encode(&b, &mut encoded_b);
        assert_eq!(encoded_a, encoded_b);
    }

    #[test]
    fn dnssec_type_bitmaps_multiple_windows_round_trip() {
        // Types spanning several window blocks must encode in increasing window
        // order and decode back to the same set.
        let original = DnsTypeBitmaps::from_types([1u16, 300, 600, 0xff01]);
        let mut encoded = Vec::new();
        DnsTypeBitmaps::encode(&original, &mut encoded);
        let decoded = DnsTypeBitmaps::decode("test", &encoded).unwrap();
        assert_eq!(decoded.types(), original.types());
    }

    #[test]
    fn dnssec_ds_too_short_is_rejected() {
        // Fewer than the four fixed octets of a DS record.
        let rdata = [0u8; 3];
        assert!(decode_record_data(DNS_TYPE_DS, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn dnssec_rrsig_too_short_fixed_header_is_rejected() {
        // Fewer than the eighteen fixed octets before the signer's name.
        let rdata = [0u8; 17];
        assert!(decode_record_data(DNS_TYPE_RRSIG, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn dnssec_nsec3_salt_length_overrun_is_rejected() {
        // Salt Length claims more salt than the RDATA actually carries.
        let rdata = [1u8, 0, 0, 10, 8, 0xaa, 0xbb]; // salt length 8, only 2 present
        assert!(decode_record_data(DNS_TYPE_NSEC3, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn dnssec_nsec3_hash_length_overrun_is_rejected() {
        // Hash Length claims more hash bytes than remain after the salt.
        let rdata = [1u8, 0, 0, 10, 0, 20, 0x11, 0x22]; // hash length 20, only 2 present
        assert!(decode_record_data(DNS_TYPE_NSEC3, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn dnssec_type_bitmap_zero_window_length_is_rejected() {
        // A window with a zero bitmap length is malformed (length is 1..=32).
        let rdata = [0u8, 0]; // window 0, length 0
        assert!(DnsTypeBitmaps::decode("test", &rdata).is_err());
    }

    #[test]
    fn dnssec_type_bitmap_truncated_bitmap_is_rejected() {
        // Bitmap Length declares more bytes than are present.
        let rdata = [0u8, 4, 0x40]; // window 0, length 4, only one bitmap byte
        assert!(DnsTypeBitmaps::decode("test", &rdata).is_err());
    }

    #[test]
    fn dnssec_type_bitmap_out_of_order_window_is_rejected() {
        // Windows must be strictly increasing; a repeated/decreasing window is
        // malformed.
        let rdata = [1u8, 1, 0x40, 0u8, 1, 0x40]; // window 1 then window 0
        assert!(DnsTypeBitmaps::decode("test", &rdata).is_err());
    }

    #[test]
    fn dnssec_type_bitmap_trailing_zero_octet_is_rejected() {
        // A minimal encoding never carries a trailing all-zero octet.
        let rdata = [0u8, 2, 0x40, 0x00]; // window 0, length 2, trailing zero
        assert!(DnsTypeBitmaps::decode("test", &rdata).is_err());
    }

    #[test]
    fn dnssec_nsec3param_stays_raw_by_design() {
        // NSEC3PARAM is intentionally left as Raw in the coverage map; it must
        // not be silently lost and must round trip its exact bytes.
        let rdata = vec![1u8, 0, 0, 10, 4, 0xaa, 0xbb, 0xcc, 0xdd];
        let data = decode_record_data(DNS_TYPE_NSEC3PARAM, &rdata, 0, rdata.len()).unwrap();
        assert_eq!(data, DnsRecordData::Raw(rdata.clone()));

        // And it round trips byte-for-byte through the packet stack as Raw.
        let record = DnsRecord::new(
            "example.com.",
            DNS_TYPE_NSEC3PARAM,
            DNS_CLASS_IN,
            3600,
            DnsRecordData::Raw(rdata),
        );
        let (round_tripped, original, recompiled) = round_trip_answer(record);
        assert!(matches!(round_tripped, DnsRecordData::Raw(_)));
        assert_eq!(recompiled, original);
    }

    #[test]
    fn dnssec_related_key_type_stays_raw_by_design() {
        // KEY (type 25) is a cryptographic-key transport type kept as Raw in
        // the coverage map even though it neighbours the DNSSEC records.
        const DNS_TYPE_KEY: u16 = 25;
        let rdata = vec![0x01u8, 0x00, 0x03, 0x08, 0xde, 0xad];
        let data = decode_record_data(DNS_TYPE_KEY, &rdata, 0, rdata.len()).unwrap();
        assert_eq!(data, DnsRecordData::Raw(rdata));
    }

    #[test]
    fn unknown_and_deferred_record_types_stay_raw_round_trip() {
        // Mirrors the dns-raw-unknown-records oracle case: an unknown private-use
        // numeric TYPE plus the deferred NSEC3PARAM (51), TLSA (52), KEY (25), and
        // NAPTR (35) types must each decode to DnsRecordData::Raw (never a
        // mis-typed record) and recompile their exact RDATA bytes through the
        // packet stack. The numeric codepoints and opaque RDATA match the oracle
        // fixture so the crate test and the reference comparison stay in lockstep.
        const RAW_TYPE_CASES: &[(u16, &[u8])] = &[
            // Private-use unknown TYPE 65280 (RFC 6895 Section 3.1).
            (65280, &[0xde, 0xad, 0xbe, 0xef]),
            // NSEC3PARAM (51): deferred to Raw (docs/guide/dns.md).
            (51, &[0x01, 0x00, 0x00, 0x0a, 0x04, 0xaa, 0xbb, 0xcc, 0xdd]),
            // TLSA (52): deferred certificate-association record.
            (52, &[0x03, 0x01, 0x01, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]),
            // KEY (25): cryptographic-key transport type.
            (25, &[0x01, 0x00, 0x03, 0x08, 0x0a, 0x0b, 0x0c, 0x0d]),
            // NAPTR (35): deferred naming-authority-pointer record.
            (
                35,
                &[
                    0x00, 0x64, 0x00, 0x0a, 0x01, 0x53, 0x00, 0x04, 0x55, 0x52, 0x4c, 0x00,
                ],
            ),
        ];

        for &(record_type, rdata) in RAW_TYPE_CASES {
            // The decoder surfaces the RDATA verbatim rather than rejecting an
            // unknown/deferred type.
            let decoded = decode_record_data(record_type, rdata, 0, rdata.len()).unwrap();
            assert_eq!(
                decoded,
                DnsRecordData::Raw(rdata.to_vec()),
                "type {record_type} should decode as Raw"
            );

            // And it round trips byte-for-byte through the full packet stack.
            let record = DnsRecord::new(
                "example.com.",
                record_type,
                DNS_CLASS_IN,
                3600,
                DnsRecordData::Raw(rdata.to_vec()),
            );
            let (round_tripped, original, recompiled) = round_trip_answer(record);
            assert_eq!(
                round_tripped,
                DnsRecordData::Raw(rdata.to_vec()),
                "type {record_type} should round trip as Raw"
            );
            assert_eq!(
                recompiled, original,
                "type {record_type} should recompile to identical bytes"
            );
        }
    }
}
