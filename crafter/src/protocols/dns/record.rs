//! DNS question and resource-record types.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{CrafterError, Result};

use super::dnssec::DnsTypeBitmaps;
use super::edns::{encode_edns_ttl, EdnsOption};
use super::name::DnsName;
use super::rdata::DnsRecordData;
use super::svcb::SvcParams;
use super::{
    DNS_CLASS_IN, DNS_EDNS_EXTENDED_RCODE_SHIFT, DNS_EDNS_FLAGS_MASK, DNS_EDNS_FLAG_DO,
    DNS_EDNS_VERSION_SHIFT, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_DNSKEY,
    DNS_TYPE_DS, DNS_TYPE_HTTPS, DNS_TYPE_NSEC, DNS_TYPE_NSEC3, DNS_TYPE_OPT, DNS_TYPE_RRSIG,
    DNS_TYPE_SOA, DNS_TYPE_SRV, DNS_TYPE_SVCB,
};

/// Parsed or constructible DNS question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    pub(super) name: DnsName,
    pub(super) question_type: u16,
    pub(super) question_class: u16,
}

impl DnsQuestion {
    /// Create a DNS question with an explicit type and IN class.
    pub fn new(name: impl Into<DnsName>, question_type: u16) -> Self {
        Self {
            name: name.into(),
            question_type,
            question_class: DNS_CLASS_IN,
        }
    }

    /// Create an A question.
    pub fn a(name: impl Into<DnsName>) -> Self {
        Self::new(name, DNS_TYPE_A)
    }

    /// Create an AAAA question.
    pub fn aaaa(name: impl Into<DnsName>) -> Self {
        Self::new(name, DNS_TYPE_AAAA)
    }

    /// Set the question class.
    pub fn class(mut self, question_class: u16) -> Self {
        self.question_class = question_class;
        self
    }

    /// Compatibility alias for question type.
    pub fn qtype(mut self, question_type: u16) -> Self {
        self.question_type = question_type;
        self
    }

    /// Compatibility alias for question class.
    pub fn qclass(mut self, question_class: u16) -> Self {
        self.question_class = question_class;
        self
    }

    /// Question name in canonical trailing-dot presentation form.
    ///
    /// Non-text labels are rendered with `\DDD` escapes; use
    /// [`DnsQuestion::dns_name`] or [`DnsQuestion::name_labels`] for the exact
    /// wire bytes.
    pub fn name(&self) -> &str {
        self.name.presentation()
    }

    /// Typed owner name preserving the exact wire labels.
    pub fn dns_name(&self) -> &DnsName {
        &self.name
    }

    /// Exact wire-label bytes of the question name.
    pub fn name_labels(&self) -> &[Vec<u8>] {
        self.name.labels()
    }

    /// Question type value.
    pub const fn question_type(&self) -> u16 {
        self.question_type
    }

    /// Question class value.
    pub const fn question_class(&self) -> u16 {
        self.question_class
    }

    pub(super) fn encoded_len(&self) -> usize {
        self.name.encoded_len() + 4
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.name.encode(out)?;
        out.extend_from_slice(&self.question_type.to_be_bytes());
        out.extend_from_slice(&self.question_class.to_be_bytes());
        Ok(())
    }
}

/// DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsRecord {
    pub(super) name: DnsName,
    pub(super) record_type: u16,
    pub(super) class: u16,
    pub(super) ttl: u32,
    pub(super) data: DnsRecordData,
}

impl DnsRecord {
    /// Create a DNS resource record.
    pub fn new(
        name: impl Into<DnsName>,
        record_type: u16,
        class: u16,
        ttl: u32,
        data: DnsRecordData,
    ) -> Self {
        Self {
            name: name.into(),
            record_type,
            class,
            ttl,
            data,
        }
    }

    /// Create an A answer.
    pub fn a(name: impl Into<DnsName>, address: Ipv4Addr, ttl: u32) -> Self {
        Self::new(
            name,
            DNS_TYPE_A,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::A(address),
        )
    }

    /// Create an AAAA answer.
    pub fn aaaa(name: impl Into<DnsName>, address: Ipv6Addr, ttl: u32) -> Self {
        Self::new(
            name,
            DNS_TYPE_AAAA,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Aaaa(address),
        )
    }

    /// Create a CNAME answer.
    pub fn cname(name: impl Into<DnsName>, target: impl Into<DnsName>, ttl: u32) -> Self {
        Self::new(
            name,
            DNS_TYPE_CNAME,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::name(target),
        )
    }

    /// Create a SOA record (RFC 1035 Section 3.3.13).
    #[allow(clippy::too_many_arguments)]
    pub fn soa(
        name: impl Into<DnsName>,
        ttl: u32,
        mname: impl Into<DnsName>,
        rname: impl Into<DnsName>,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_SOA,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Soa {
                mname: mname.into(),
                rname: rname.into(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
        )
    }

    /// Create a SRV record (RFC 2782).
    pub fn srv(
        name: impl Into<DnsName>,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: impl Into<DnsName>,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_SRV,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Srv {
                priority,
                weight,
                port,
                target: target.into(),
            },
        )
    }

    /// Create a DS (Delegation Signer) record (RFC 4034 Section 5.1).
    ///
    /// The algorithm and digest type stay raw numeric fields and the digest is
    /// carried verbatim; no cryptographic validation is performed.
    pub fn ds(
        name: impl Into<DnsName>,
        ttl: u32,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_DS,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest: digest.into(),
            },
        )
    }

    /// Create a DNSKEY record (RFC 4034 Section 2.1).
    ///
    /// The flags and algorithm stay raw numeric fields and the public key is
    /// carried verbatim; no cryptographic validation is performed.
    pub fn dnskey(
        name: impl Into<DnsName>,
        ttl: u32,
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_DNSKEY,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key: public_key.into(),
            },
        )
    }

    /// Create an RRSIG record (RFC 4034 Section 3.1).
    ///
    /// The signer's name is emitted uncompressed and the signature is carried
    /// verbatim; no cryptographic validation is performed.
    #[allow(clippy::too_many_arguments)]
    pub fn rrsig(
        name: impl Into<DnsName>,
        ttl: u32,
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: impl Into<DnsName>,
        signature: impl Into<Vec<u8>>,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_RRSIG,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name: signer_name.into(),
                signature: signature.into(),
            },
        )
    }

    /// Create an NSEC record (RFC 4034 Section 4.1).
    ///
    /// The next domain name is emitted uncompressed and the type bitmaps carry
    /// the present RR type values verbatim.
    pub fn nsec(
        name: impl Into<DnsName>,
        ttl: u32,
        next_domain_name: impl Into<DnsName>,
        present_types: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_NSEC,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Nsec {
                next_domain_name: next_domain_name.into(),
                type_bitmaps: DnsTypeBitmaps::from_types(present_types),
            },
        )
    }

    /// Create an NSEC3 record (RFC 5155 Section 3.2).
    ///
    /// The hash algorithm and flags stay raw numeric fields; the salt, next
    /// hashed owner name, and type bitmaps carry their wire bytes verbatim.
    #[allow(clippy::too_many_arguments)]
    pub fn nsec3(
        name: impl Into<DnsName>,
        ttl: u32,
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: impl Into<Vec<u8>>,
        next_hashed_owner_name: impl Into<Vec<u8>>,
        present_types: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_NSEC3,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt: salt.into(),
                next_hashed_owner_name: next_hashed_owner_name.into(),
                type_bitmaps: DnsTypeBitmaps::from_types(present_types),
            },
        )
    }

    /// Create an SVCB service-binding record (RFC 9460 Section 2.2).
    ///
    /// The target name is emitted uncompressed (and may be the root `.`), and
    /// the SvcParams are sorted into strictly increasing SvcParamKey order. The
    /// SvcParam values are carried verbatim; no resolver or selection behavior is
    /// applied.
    pub fn svcb(
        name: impl Into<DnsName>,
        ttl: u32,
        priority: u16,
        target: impl Into<DnsName>,
        params: SvcParams,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_SVCB,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Svcb {
                priority,
                target: target.into(),
                params,
            },
        )
    }

    /// Create an HTTPS service-binding record (RFC 9460 Section 2.2).
    ///
    /// HTTPS shares the SVCB wire format; the target name is emitted
    /// uncompressed (and may be the root `.`), and the SvcParams are sorted into
    /// strictly increasing SvcParamKey order with their values carried verbatim.
    pub fn https(
        name: impl Into<DnsName>,
        ttl: u32,
        priority: u16,
        target: impl Into<DnsName>,
        params: SvcParams,
    ) -> Self {
        Self::new(
            name,
            DNS_TYPE_HTTPS,
            DNS_CLASS_IN,
            ttl,
            DnsRecordData::Https {
                priority,
                target: target.into(),
                params,
            },
        )
    }

    /// Create an EDNS(0) OPT pseudo-record (RFC 6891 Section 6.1).
    ///
    /// The OPT pseudo-record reuses ordinary resource-record fields with EDNS
    /// meanings: the owner name MUST be root, the CLASS field carries the
    /// requestor's UDP payload size, and the TTL field carries the extended
    /// RCODE, EDNS version, the DO flag, and the Z bits. This builder packs
    /// those EDNS fields into the underlying `class` and `ttl` so the record
    /// still encodes through the normal name/type/class/ttl/rdlength/RDATA path;
    /// inspect or override the raw fields with [`DnsRecord::class`],
    /// [`DnsRecord::ttl`], and the EDNS getters.
    pub fn opt(
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        options: Vec<EdnsOption>,
    ) -> Self {
        let ttl = encode_edns_ttl(extended_rcode, version, dnssec_ok, 0);
        Self::new(
            DnsName::root(),
            DNS_TYPE_OPT,
            udp_payload_size,
            ttl,
            DnsRecordData::Opt(options),
        )
    }

    /// Record name in canonical trailing-dot presentation form.
    ///
    /// Non-text labels are rendered with `\DDD` escapes; use
    /// [`DnsRecord::dns_name`] or [`DnsRecord::name_labels`] for the exact wire
    /// bytes.
    pub fn name(&self) -> &str {
        self.name.presentation()
    }

    /// Typed owner name preserving the exact wire labels.
    pub fn dns_name(&self) -> &DnsName {
        &self.name
    }

    /// Exact wire-label bytes of the record name.
    pub fn name_labels(&self) -> &[Vec<u8>] {
        self.name.labels()
    }

    /// Record type value.
    pub const fn record_type(&self) -> u16 {
        self.record_type
    }

    /// Record class value.
    pub const fn class(&self) -> u16 {
        self.class
    }

    /// Record TTL.
    pub const fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Record data.
    pub const fn data(&self) -> &DnsRecordData {
        &self.data
    }

    /// True when this record is an EDNS(0) OPT pseudo-record (TYPE 41).
    pub const fn is_opt(&self) -> bool {
        self.record_type == DNS_TYPE_OPT
    }

    /// EDNS(0) requestor UDP payload size, taken from the OPT CLASS field
    /// (RFC 6891 Section 6.1.2).
    ///
    /// This reads the raw CLASS field; it is only meaningful when
    /// [`DnsRecord::is_opt`] is true. The underlying value stays available
    /// through [`DnsRecord::class`].
    pub const fn edns_udp_payload_size(&self) -> u16 {
        self.class
    }

    /// EDNS(0) EXTENDED-RCODE: the upper 8 bits of the 12-bit extended RCODE,
    /// taken from the OPT TTL field (RFC 6891 Section 6.1.3).
    pub const fn edns_extended_rcode(&self) -> u8 {
        (self.ttl >> DNS_EDNS_EXTENDED_RCODE_SHIFT) as u8
    }

    /// EDNS(0) VERSION, taken from the OPT TTL field (RFC 6891 Section 6.1.3).
    pub const fn edns_version(&self) -> u8 {
        (self.ttl >> DNS_EDNS_VERSION_SHIFT) as u8
    }

    /// EDNS(0) DO ("DNSSEC OK") flag, taken from the OPT TTL field
    /// (RFC 6891 Section 6.1.3; IANA EDNS Header Flags bit 0).
    pub const fn edns_dnssec_ok(&self) -> bool {
        ((self.ttl as u16) & DNS_EDNS_FLAG_DO) != 0
    }

    /// EDNS(0) header flags word (the lower 16 bits of the OPT TTL field,
    /// including the DO bit and the Z bits) returned verbatim.
    pub const fn edns_flags(&self) -> u16 {
        (self.ttl & DNS_EDNS_FLAGS_MASK) as u16
    }

    /// EDNS(0) option list when this record's RDATA is typed as OPT, or `None`
    /// for any other record data (including an OPT type whose RDATA decoded as
    /// raw bytes).
    pub fn edns_options(&self) -> Option<&[EdnsOption]> {
        match &self.data {
            DnsRecordData::Opt(options) => Some(options),
            _ => None,
        }
    }

    pub(super) fn encoded_len(&self) -> usize {
        self.name.encoded_len() + 10 + self.data.encoded_len()
    }

    pub(super) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.name.encode(out)?;
        out.extend_from_slice(&self.record_type.to_be_bytes());
        out.extend_from_slice(&self.class.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());

        let mut rdata = Vec::with_capacity(self.data.encoded_len());
        self.data.encode(self.record_type, &mut rdata)?;
        let rdlength = u16::try_from(rdata.len()).map_err(|_| {
            CrafterError::invalid_field_value("dns.rdlength", "record data exceeds 65535 bytes")
        })?;
        out.extend_from_slice(&rdlength.to_be_bytes());
        out.extend_from_slice(&rdata);
        Ok(())
    }
}
