//! Domain Name System protocol implementation.

use core::any::Any;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ops::Div;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

mod constants;
mod dnssec;
mod edns;
mod name;

use edns::encode_edns_ttl;

pub use dnssec::DnsTypeBitmaps;
pub use edns::{edns_option_code_name, EdnsOption};
pub use name::{decode_dns_name, decode_dns_name_typed, DnsName};

pub use constants::{
    DNS_CLASS_ANY, DNS_CLASS_CH, DNS_CLASS_HS, DNS_CLASS_IN, DNS_CLASS_NONE,
    DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE, DNS_EDNS_FLAG_DO, DNS_EDNS_OPTION_CLIENT_SUBNET,
    DNS_EDNS_OPTION_COOKIE, DNS_EDNS_OPTION_DAU, DNS_EDNS_OPTION_DHU, DNS_EDNS_OPTION_EXPIRE,
    DNS_EDNS_OPTION_EXTENDED_ERROR, DNS_EDNS_OPTION_N3U, DNS_EDNS_OPTION_NSID,
    DNS_EDNS_OPTION_PADDING, DNS_EDNS_OPTION_TCP_KEEPALIVE, DNS_FLAG_AUTHENTIC_DATA,
    DNS_FLAG_AUTHORITATIVE, DNS_FLAG_CHECKING_DISABLED, DNS_FLAG_QR_RESPONSE,
    DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_TRUNCATED, DNS_HEADER_LEN,
    DNS_OPCODE_DSO, DNS_OPCODE_IQUERY, DNS_OPCODE_NOTIFY, DNS_OPCODE_QUERY, DNS_OPCODE_STATUS,
    DNS_OPCODE_UPDATE, DNS_PORT, DNS_RCODE_DSOTYPENI, DNS_RCODE_FORMERR, DNS_RCODE_NOERROR,
    DNS_RCODE_NOTAUTH, DNS_RCODE_NOTIMP, DNS_RCODE_NOTZONE, DNS_RCODE_NXDOMAIN, DNS_RCODE_NXRRSET,
    DNS_RCODE_REFUSED, DNS_RCODE_SERVFAIL, DNS_RCODE_YXDOMAIN, DNS_RCODE_YXRRSET,
    DNS_SVCB_KEY_ALPN, DNS_SVCB_KEY_DOHPATH, DNS_SVCB_KEY_ECH, DNS_SVCB_KEY_IPV4HINT,
    DNS_SVCB_KEY_IPV6HINT, DNS_SVCB_KEY_MANDATORY, DNS_SVCB_KEY_NO_DEFAULT_ALPN, DNS_SVCB_KEY_PORT,
    DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_DNSKEY, DNS_TYPE_DS, DNS_TYPE_HTTPS,
    DNS_TYPE_MX, DNS_TYPE_NS, DNS_TYPE_NSEC, DNS_TYPE_NSEC3, DNS_TYPE_NSEC3PARAM, DNS_TYPE_OPT,
    DNS_TYPE_PTR, DNS_TYPE_RRSIG, DNS_TYPE_SOA, DNS_TYPE_SRV, DNS_TYPE_SVCB, DNS_TYPE_TLSA,
    DNS_TYPE_TXT,
};

const DNS_NAME_POINTER_MASK: u8 = 0xc0;
const DNS_NAME_POINTER_TAG: u8 = 0xc0;
const DNS_MAX_LABEL_LEN: usize = 63;
const DNS_MAX_NAME_WIRE_LEN: usize = 255;

/// Mask for the four-bit OPCODE field within the DNS flags word (bits 11-14).
const DNS_OPCODE_MASK: u16 = 0x7800;
/// Bit shift for the OPCODE field within the DNS flags word.
const DNS_OPCODE_SHIFT: u16 = 11;
/// Mask for the four-bit RCODE field within the DNS flags word (bits 0-3).
const DNS_RCODE_MASK: u16 = 0x000f;

/// Bit shift for the EXTENDED-RCODE byte (upper 8 bits) of the OPT TTL field
/// (RFC 6891 Section 6.1.3).
const DNS_EDNS_EXTENDED_RCODE_SHIFT: u32 = 24;
/// Bit shift for the VERSION byte (bits 16-23) of the OPT TTL field
/// (RFC 6891 Section 6.1.3).
const DNS_EDNS_VERSION_SHIFT: u32 = 16;
/// Mask selecting the lower 16-bit DO/Z half of the OPT TTL field.
const DNS_EDNS_FLAGS_MASK: u32 = 0x0000_ffff;

macro_rules! impl_layer_object {
    ($type:ty) => {
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
    };
}

macro_rules! impl_layer_div {
    ($type:ty) => {
        impl<R> Div<R> for $type
        where
            R: IntoPacket,
        {
            type Output = Packet;

            fn div(self, rhs: R) -> Self::Output {
                Packet::from_layer(self).concat(rhs)
            }
        }
    };
}

/// Parsed or constructible DNS question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    name: DnsName,
    question_type: u16,
    question_class: u16,
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

    fn encoded_len(&self) -> usize {
        self.name.encoded_len() + 4
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        self.name.encode(out)?;
        out.extend_from_slice(&self.question_type.to_be_bytes());
        out.extend_from_slice(&self.question_class.to_be_bytes());
        Ok(())
    }
}

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

    fn encoded_len(&self) -> usize {
        self.params.iter().map(SvcParam::encoded_len).sum()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        for param in &self.params {
            param.encode(out)?;
        }
        Ok(())
    }

    /// Parse the SvcParams that consume the remainder of an SVCB/HTTPS RDATA
    /// field, rejecting truncated params, out-of-order keys, and duplicate keys
    /// with structured errors (RFC 9460 Section 2.2).
    fn decode(field: &'static str, rdata: &[u8]) -> Result<Self> {
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

/// DNS resource record data for common record types.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsRecordData {
    /// IPv4 address data for A records.
    A(Ipv4Addr),
    /// IPv6 address data for AAAA records.
    Aaaa(Ipv6Addr),
    /// Domain name data for NS, CNAME, and PTR records.
    Name(DnsName),
    /// Mail exchanger data.
    Mx {
        /// Preference value.
        preference: u16,
        /// Mail exchanger domain name.
        exchange: DnsName,
    },
    /// Start of authority data (RFC 1035 Section 3.3.13).
    Soa {
        /// MNAME: primary source domain name for this zone.
        mname: DnsName,
        /// RNAME: responsible-person mailbox domain name.
        rname: DnsName,
        /// SERIAL: 32-bit zone version number.
        serial: u32,
        /// REFRESH: 32-bit refresh interval, in seconds.
        refresh: u32,
        /// RETRY: 32-bit retry interval, in seconds.
        retry: u32,
        /// EXPIRE: 32-bit expiry interval, in seconds.
        expire: u32,
        /// MINIMUM: 32-bit minimum TTL, in seconds.
        minimum: u32,
    },
    /// Service location data (RFC 2782): priority, weight, port, target.
    Srv {
        /// Priority of this target host.
        priority: u16,
        /// Relative weight among entries with the same priority.
        weight: u16,
        /// Port of the service on the target host.
        port: u16,
        /// Target host domain name.
        target: DnsName,
    },
    /// TXT strings, each encoded as one DNS character-string.
    Txt(Vec<Vec<u8>>),
    /// EDNS(0) OPT pseudo-record RDATA: a list of {code, length, data} options
    /// (RFC 6891 Section 6.1.2). The OPT CLASS and TTL fields carry the UDP
    /// payload size and the extended RCODE/version/flags rather than ordinary
    /// class and TTL meaning; build with [`DnsRecord::opt`] and inspect with the
    /// `edns_*` accessors on [`DnsRecord`].
    Opt(Vec<EdnsOption>),
    /// Delegation Signer (DS) data (RFC 4034 Section 5.1). Algorithm and digest
    /// type stay raw numeric fields; the digest is opaque wire bytes and is not
    /// cryptographically validated.
    Ds {
        /// Key Tag of the referenced DNSKEY (network byte order).
        key_tag: u16,
        /// DNSSEC algorithm number of the referenced DNSKEY.
        algorithm: u8,
        /// Digest Type identifying the digest algorithm.
        digest_type: u8,
        /// Digest bytes, carried verbatim.
        digest: Vec<u8>,
    },
    /// DNSKEY public-key data (RFC 4034 Section 2.1). Flags and algorithm stay
    /// raw numeric fields; the public key is opaque wire bytes and is not
    /// cryptographically validated.
    Dnskey {
        /// 16-bit Flags field (for example the Zone Key and SEP bits).
        flags: u16,
        /// Protocol field (MUST be 3 per RFC 4034, but carried verbatim).
        protocol: u8,
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Public key bytes, carried verbatim.
        public_key: Vec<u8>,
    },
    /// Resource Record Signature (RRSIG) data (RFC 4034 Section 3.1). The
    /// signature bytes are opaque and are not cryptographically validated; the
    /// signer's name is emitted uncompressed (Section 3.1.7).
    Rrsig {
        /// RR type covered by this signature.
        type_covered: u16,
        /// DNSSEC algorithm number.
        algorithm: u8,
        /// Number of labels in the original owner name.
        labels: u8,
        /// Original TTL of the covered RRset, in seconds.
        original_ttl: u32,
        /// Signature expiration time (seconds since the Unix epoch).
        signature_expiration: u32,
        /// Signature inception time (seconds since the Unix epoch).
        signature_inception: u32,
        /// Key Tag of the DNSKEY that made the signature.
        key_tag: u16,
        /// Signer's Name (emitted uncompressed per RFC 4034 Section 3.1.7).
        signer_name: DnsName,
        /// Signature bytes, carried verbatim.
        signature: Vec<u8>,
    },
    /// Next Secure (NSEC) data (RFC 4034 Section 4.1). The next domain name is
    /// emitted uncompressed (Section 6.2).
    Nsec {
        /// Next owner name in canonical ordering (emitted uncompressed).
        next_domain_name: DnsName,
        /// Type Bit Maps: the RR types present at the owner name.
        type_bitmaps: DnsTypeBitmaps,
    },
    /// Next Secure v3 (NSEC3) data (RFC 5155 Section 3.2). Hash algorithm and
    /// flags stay raw numeric fields; the salt and next hashed owner name are
    /// opaque wire bytes.
    Nsec3 {
        /// Hash Algorithm number.
        hash_algorithm: u8,
        /// Flags field (the Opt-Out flag is the least significant bit).
        flags: u8,
        /// Iterations: additional hash rounds.
        iterations: u16,
        /// Salt bytes, carried verbatim (may be empty).
        salt: Vec<u8>,
        /// Next Hashed Owner Name: the unmodified binary hash value.
        next_hashed_owner_name: Vec<u8>,
        /// Type Bit Maps: the RR types present at the original owner name.
        type_bitmaps: DnsTypeBitmaps,
    },
    /// SVCB service-binding data (RFC 9460 Section 2.2): SvcPriority, an
    /// uncompressed target name, and an ordered list of SvcParams. SvcParam
    /// values stay opaque wire bytes (their format is determined by the
    /// SvcParamKey); unknown keys are preserved verbatim.
    Svcb {
        /// SvcPriority: 0 selects AliasMode, any other value ServiceMode.
        priority: u16,
        /// TargetName domain name (emitted uncompressed; may be the root `.`).
        target: DnsName,
        /// SvcParams in strictly increasing SvcParamKey order.
        params: SvcParams,
    },
    /// HTTPS service-binding data (RFC 9460 Section 2.2). Shares the SVCB wire
    /// format: SvcPriority, an uncompressed target name, and an ordered list of
    /// SvcParams.
    Https {
        /// SvcPriority: 0 selects AliasMode, any other value ServiceMode.
        priority: u16,
        /// TargetName domain name (emitted uncompressed; may be the root `.`).
        target: DnsName,
        /// SvcParams in strictly increasing SvcParamKey order.
        params: SvcParams,
    },
    /// Unknown or caller-defined record payload bytes.
    Raw(Vec<u8>),
}

impl DnsRecordData {
    /// Create name-like record data.
    pub fn name(name: impl Into<DnsName>) -> Self {
        Self::Name(name.into())
    }

    /// Create TXT record data from one string.
    pub fn txt(text: impl AsRef<[u8]>) -> Self {
        Self::Txt(vec![text.as_ref().to_vec()])
    }

    fn expected_type(&self) -> Option<u16> {
        match self {
            Self::A(_) => Some(DNS_TYPE_A),
            Self::Aaaa(_) => Some(DNS_TYPE_AAAA),
            Self::Mx { .. } => Some(DNS_TYPE_MX),
            Self::Soa { .. } => Some(DNS_TYPE_SOA),
            Self::Srv { .. } => Some(DNS_TYPE_SRV),
            Self::Txt(_) => Some(DNS_TYPE_TXT),
            Self::Opt(_) => Some(DNS_TYPE_OPT),
            Self::Ds { .. } => Some(DNS_TYPE_DS),
            Self::Dnskey { .. } => Some(DNS_TYPE_DNSKEY),
            Self::Rrsig { .. } => Some(DNS_TYPE_RRSIG),
            Self::Nsec { .. } => Some(DNS_TYPE_NSEC),
            Self::Nsec3 { .. } => Some(DNS_TYPE_NSEC3),
            Self::Svcb { .. } => Some(DNS_TYPE_SVCB),
            Self::Https { .. } => Some(DNS_TYPE_HTTPS),
            Self::Name(_) | Self::Raw(_) => None,
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::A(_) => 4,
            Self::Aaaa(_) => 16,
            Self::Name(name) => name.encoded_len(),
            Self::Mx { exchange, .. } => 2 + exchange.encoded_len(),
            Self::Soa { mname, rname, .. } => mname.encoded_len() + rname.encoded_len() + 20,
            Self::Srv { target, .. } => 6 + target.encoded_len(),
            Self::Txt(strings) => strings.iter().map(|value| 1 + value.len()).sum(),
            Self::Opt(options) => options.iter().map(EdnsOption::encoded_len).sum(),
            Self::Ds { digest, .. } => 4 + digest.len(),
            Self::Dnskey { public_key, .. } => 4 + public_key.len(),
            Self::Rrsig {
                signer_name,
                signature,
                ..
            } => 18 + signer_name.encoded_len() + signature.len(),
            Self::Nsec {
                next_domain_name,
                type_bitmaps,
            } => next_domain_name.encoded_len() + type_bitmaps.encoded_len(),
            Self::Nsec3 {
                salt,
                next_hashed_owner_name,
                type_bitmaps,
                ..
            } => 5 + salt.len() + 1 + next_hashed_owner_name.len() + type_bitmaps.encoded_len(),
            Self::Svcb { target, params, .. } | Self::Https { target, params, .. } => {
                2 + target.encoded_len() + params.encoded_len()
            }
            Self::Raw(bytes) => bytes.len(),
        }
    }

    fn encode(&self, record_type: u16, out: &mut Vec<u8>) -> Result<()> {
        if let Some(expected) = self.expected_type() {
            if expected != record_type {
                return Err(CrafterError::invalid_field_value(
                    "dns.record.type",
                    "record data does not match record type",
                ));
            }
        }

        match self {
            Self::A(address) => out.extend_from_slice(&address.octets()),
            Self::Aaaa(address) => out.extend_from_slice(&address.octets()),
            Self::Name(name) => name.encode(out)?,
            Self::Mx {
                preference,
                exchange,
            } => {
                out.extend_from_slice(&preference.to_be_bytes());
                exchange.encode(out)?;
            }
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                mname.encode(out)?;
                rname.encode(out)?;
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                target.encode(out)?;
            }
            Self::Txt(strings) => {
                for text in strings {
                    if text.len() > u8::MAX as usize {
                        return Err(CrafterError::invalid_field_value(
                            "dns.txt",
                            "TXT character-string exceeds 255 bytes",
                        ));
                    }
                    out.push(text.len() as u8);
                    out.extend_from_slice(text);
                }
            }
            Self::Opt(options) => {
                for option in options {
                    option.encode(out)?;
                }
            }
            Self::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.push(*algorithm);
                out.push(*digest_type);
                out.extend_from_slice(digest);
            }
            Self::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                out.extend_from_slice(&flags.to_be_bytes());
                out.push(*protocol);
                out.push(*algorithm);
                out.extend_from_slice(public_key);
            }
            Self::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
            } => {
                out.extend_from_slice(&type_covered.to_be_bytes());
                out.push(*algorithm);
                out.push(*labels);
                out.extend_from_slice(&original_ttl.to_be_bytes());
                out.extend_from_slice(&signature_expiration.to_be_bytes());
                out.extend_from_slice(&signature_inception.to_be_bytes());
                out.extend_from_slice(&key_tag.to_be_bytes());
                // RFC 4034 Section 3.1.7: the Signer's Name MUST NOT be
                // compressed, so the deterministic uncompressed encoder is used.
                signer_name.encode(out)?;
                out.extend_from_slice(signature);
            }
            Self::Nsec {
                next_domain_name,
                type_bitmaps,
            } => {
                // RFC 4034 Section 6.2: the Next Domain Name MUST NOT be
                // compressed.
                next_domain_name.encode(out)?;
                type_bitmaps.encode(out);
            }
            Self::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner_name,
                type_bitmaps,
            } => {
                let salt_len = u8::try_from(salt.len()).map_err(|_| {
                    CrafterError::invalid_field_value(
                        "dns.nsec3.salt",
                        "NSEC3 salt exceeds 255 bytes",
                    )
                })?;
                let hash_len = u8::try_from(next_hashed_owner_name.len()).map_err(|_| {
                    CrafterError::invalid_field_value(
                        "dns.nsec3.hash",
                        "NSEC3 next hashed owner name exceeds 255 bytes",
                    )
                })?;
                out.push(*hash_algorithm);
                out.push(*flags);
                out.extend_from_slice(&iterations.to_be_bytes());
                out.push(salt_len);
                out.extend_from_slice(salt);
                out.push(hash_len);
                out.extend_from_slice(next_hashed_owner_name);
                type_bitmaps.encode(out);
            }
            Self::Svcb {
                priority,
                target,
                params,
            }
            | Self::Https {
                priority,
                target,
                params,
            } => {
                out.extend_from_slice(&priority.to_be_bytes());
                // RFC 9460 Section 2.2: the TargetName is uncompressed, so the
                // deterministic uncompressed encoder is used.
                target.encode(out)?;
                params.encode(out)?;
            }
            Self::Raw(bytes) => out.extend_from_slice(bytes),
        }
        Ok(())
    }
}

/// DNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsRecord {
    name: DnsName,
    record_type: u16,
    class: u16,
    ttl: u32,
    data: DnsRecordData,
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

    fn encoded_len(&self) -> usize {
        self.name.encoded_len() + 10 + self.data.encoded_len()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
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

/// DNS message layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    id: Field<u16>,
    flags: Field<u16>,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
}

impl Dns {
    /// Create an empty DNS query with recursion desired enabled.
    pub fn new() -> Self {
        Self {
            id: Field::defaulted(0),
            flags: Field::defaulted(DNS_FLAG_RECURSION_DESIRED),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Create a DNS query for a single name and type.
    pub fn query(name: impl Into<DnsName>, question_type: u16) -> Self {
        Self::new().question(DnsQuestion::new(name, question_type))
    }

    /// Create an A query.
    pub fn a_query(name: impl Into<DnsName>) -> Self {
        Self::query(name, DNS_TYPE_A)
    }

    /// Create an AAAA query.
    pub fn aaaa_query(name: impl Into<DnsName>) -> Self {
        Self::query(name, DNS_TYPE_AAAA)
    }

    /// Set the DNS transaction ID.
    pub fn id(mut self, id: u16) -> Self {
        self.id.set_user(id);
        self
    }

    /// Set the raw DNS flags field.
    pub fn flags(mut self, flags: u16) -> Self {
        self.flags.set_user(flags);
        self
    }

    /// Set or clear the response flag.
    pub fn response(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_QR_RESPONSE, enabled)
    }

    /// Set or clear the authoritative-answer flag.
    pub fn authoritative(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_AUTHORITATIVE, enabled)
    }

    /// Set or clear the recursion-desired flag.
    pub fn recursion_desired(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_RECURSION_DESIRED, enabled)
    }

    /// Compatibility alias for recursion desired.
    pub fn rd(self, enabled: bool) -> Self {
        self.recursion_desired(enabled)
    }

    /// Set or clear the recursion-available flag.
    pub fn recursion_available(self, enabled: bool) -> Self {
        self.set_flag(DNS_FLAG_RECURSION_AVAILABLE, enabled)
    }

    /// Set the four-bit OPCODE field, preserving every other flag bit.
    ///
    /// Only the low four bits of `opcode` are used; the field cannot represent
    /// values above 15. Unrelated header bits are left untouched.
    pub fn opcode(mut self, opcode: u8) -> Self {
        let field = ((opcode as u16) << DNS_OPCODE_SHIFT) & DNS_OPCODE_MASK;
        let flags = (self.flags_value() & !DNS_OPCODE_MASK) | field;
        self.flags.set_user(flags);
        self
    }

    /// Set the four-bit RCODE field, preserving every other flag bit.
    ///
    /// Only the low four bits of `rcode` are used. Extended RCODE bits carried
    /// in an EDNS(0) OPT record are out of scope here.
    pub fn rcode(mut self, rcode: u8) -> Self {
        let flags = (self.flags_value() & !DNS_RCODE_MASK) | ((rcode as u16) & DNS_RCODE_MASK);
        self.flags.set_user(flags);
        self
    }

    /// Append one DNS question.
    pub fn question(mut self, question: DnsQuestion) -> Self {
        self.questions.push(question);
        self
    }

    /// Append one DNS answer record.
    pub fn answer(mut self, answer: DnsRecord) -> Self {
        self.answers.push(answer);
        self
    }

    /// Append one DNS authority record.
    pub fn authority(mut self, authority: DnsRecord) -> Self {
        self.authorities.push(authority);
        self
    }

    /// Append one DNS additional record.
    pub fn additional(mut self, additional: DnsRecord) -> Self {
        self.additionals.push(additional);
        self
    }

    /// DNS transaction ID.
    pub fn id_value(&self) -> u16 {
        value_or_copy(&self.id, 0)
    }

    /// Raw DNS flags.
    pub fn flags_value(&self) -> u16 {
        value_or_copy(&self.flags, DNS_FLAG_RECURSION_DESIRED)
    }

    /// Return true when this message is a response.
    pub fn is_response(&self) -> bool {
        self.flags_value() & DNS_FLAG_QR_RESPONSE != 0
    }

    /// Four-bit OPCODE field extracted from the raw flags word.
    ///
    /// The value is the registry codepoint (for example [`DNS_OPCODE_QUERY`]).
    /// Unknown opcodes are returned verbatim rather than rejected.
    pub fn opcode_value(&self) -> u8 {
        ((self.flags_value() & DNS_OPCODE_MASK) >> DNS_OPCODE_SHIFT) as u8
    }

    /// Four-bit RCODE field extracted from the raw flags word.
    ///
    /// The value is the registry codepoint (for example [`DNS_RCODE_NOERROR`]).
    /// Extended RCODE bits from an EDNS(0) OPT record are not folded in here.
    pub fn rcode_value(&self) -> u8 {
        (self.flags_value() & DNS_RCODE_MASK) as u8
    }

    /// DNS questions.
    pub fn questions(&self) -> &[DnsQuestion] {
        &self.questions
    }

    /// DNS answer records.
    pub fn answers(&self) -> &[DnsRecord] {
        &self.answers
    }

    /// DNS authority records.
    pub fn authorities(&self) -> &[DnsRecord] {
        &self.authorities
    }

    /// DNS additional records.
    pub fn additionals(&self) -> &[DnsRecord] {
        &self.additionals
    }

    fn set_flag(mut self, bit: u16, enabled: bool) -> Self {
        let mut flags = self.flags_value();
        if enabled {
            flags |= bit;
        } else {
            flags &= !bit;
        }
        self.flags.set_user(flags);
        self
    }

    fn encoded_message_len(&self) -> usize {
        DNS_HEADER_LEN
            + self
                .questions
                .iter()
                .map(DnsQuestion::encoded_len)
                .sum::<usize>()
            + self
                .answers
                .iter()
                .map(DnsRecord::encoded_len)
                .sum::<usize>()
            + self
                .authorities
                .iter()
                .map(DnsRecord::encoded_len)
                .sum::<usize>()
            + self
                .additionals
                .iter()
                .map(DnsRecord::encoded_len)
                .sum::<usize>()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        validate_count("dns.qdcount", self.questions.len())?;
        validate_count("dns.ancount", self.answers.len())?;
        validate_count("dns.nscount", self.authorities.len())?;
        validate_count("dns.arcount", self.additionals.len())?;

        out.extend_from_slice(&self.id_value().to_be_bytes());
        out.extend_from_slice(&self.flags_value().to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        for question in &self.questions {
            question.encode(out)?;
        }
        for answer in &self.answers {
            answer.encode(out)?;
        }
        for authority in &self.authorities {
            authority.encode(out)?;
        }
        for additional in &self.additionals {
            additional.encode(out)?;
        }
        Ok(())
    }
}

impl Default for Dns {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Dns {
    fn name(&self) -> &'static str {
        "Dns"
    }

    fn summary(&self) -> String {
        let direction = if self.is_response() {
            "response"
        } else {
            "query"
        };
        let question = self
            .questions
            .first()
            .map(|question| {
                format!(
                    " {} {}",
                    question.name(),
                    record_type_summary(question.question_type())
                )
            })
            .unwrap_or_default();

        format!(
            "Dns(id=0x{:04x}, {direction}{question}, answers={})",
            self.id_value(),
            self.answers.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("id", format!("0x{:04x}", self.id_value())),
            ("flags", format!("0x{:04x}", self.flags_value())),
            ("qdcount", self.questions.len().to_string()),
            ("ancount", self.answers.len().to_string()),
            ("nscount", self.authorities.len().to_string()),
            ("arcount", self.additionals.len().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.encoded_message_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.encode(out)
    }

    impl_layer_object!(Dns);
}

impl_layer_div!(Dns);

/// Append a decoded DNS message to an existing packet stack.
pub(crate) fn append_dns_packet(packet: Packet, bytes: &[u8]) -> Result<Packet> {
    Ok(packet.push(decode_dns(bytes)?))
}

fn decode_dns(bytes: &[u8]) -> Result<Dns> {
    if bytes.len() < DNS_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "dns header",
            DNS_HEADER_LEN,
            bytes.len(),
        ));
    }

    let qdcount = read_u16_be(&bytes[4..6])? as usize;
    let ancount = read_u16_be(&bytes[6..8])? as usize;
    let nscount = read_u16_be(&bytes[8..10])? as usize;
    let arcount = read_u16_be(&bytes[10..12])? as usize;

    let mut offset = DNS_HEADER_LEN;
    let mut questions = Vec::with_capacity(qdcount);
    let mut answers = Vec::with_capacity(ancount);
    let mut authorities = Vec::with_capacity(nscount);
    let mut additionals = Vec::with_capacity(arcount);

    for _ in 0..qdcount {
        let (question, next_offset) = decode_question(bytes, offset)?;
        questions.push(question);
        offset = next_offset;
    }
    for _ in 0..ancount {
        let (record, next_offset) = decode_record(bytes, offset)?;
        answers.push(record);
        offset = next_offset;
    }
    for _ in 0..nscount {
        let (record, next_offset) = decode_record(bytes, offset)?;
        authorities.push(record);
        offset = next_offset;
    }
    for _ in 0..arcount {
        let (record, next_offset) = decode_record(bytes, offset)?;
        additionals.push(record);
        offset = next_offset;
    }

    if offset != bytes.len() {
        return Err(CrafterError::invalid_field_value(
            "dns.length",
            "DNS message has trailing bytes after declared records",
        ));
    }

    Ok(Dns {
        id: Field::user(read_u16_be(&bytes[0..2])?),
        flags: Field::user(read_u16_be(&bytes[2..4])?),
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn decode_question(bytes: &[u8], offset: usize) -> Result<(DnsQuestion, usize)> {
    let (name, consumed) = decode_dns_name_typed(bytes, offset)?;
    let fields_offset = offset + consumed;
    if fields_offset + 4 > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            "dns question",
            fields_offset + 4,
            bytes.len(),
        ));
    }

    Ok((
        DnsQuestion {
            name,
            question_type: read_u16_be(&bytes[fields_offset..fields_offset + 2])?,
            question_class: read_u16_be(&bytes[fields_offset + 2..fields_offset + 4])?,
        },
        fields_offset + 4,
    ))
}

fn decode_record(bytes: &[u8], offset: usize) -> Result<(DnsRecord, usize)> {
    let (name, consumed) = decode_dns_name_typed(bytes, offset)?;
    let fields_offset = offset + consumed;
    if fields_offset + 10 > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            "dns record",
            fields_offset + 10,
            bytes.len(),
        ));
    }

    let record_type = read_u16_be(&bytes[fields_offset..fields_offset + 2])?;
    let class = read_u16_be(&bytes[fields_offset + 2..fields_offset + 4])?;
    let ttl = read_u32_be(&bytes[fields_offset + 4..fields_offset + 8])?;
    let rdlength = read_u16_be(&bytes[fields_offset + 8..fields_offset + 10])? as usize;
    let rdata_start = fields_offset + 10;
    let rdata_end = rdata_start + rdlength;
    if rdata_end > bytes.len() {
        return Err(CrafterError::buffer_too_short(
            "dns rdata",
            rdata_end,
            bytes.len(),
        ));
    }

    let data = decode_record_data(record_type, bytes, rdata_start, rdata_end)?;
    Ok((
        DnsRecord {
            name,
            record_type,
            class,
            ttl,
            data,
        },
        rdata_end,
    ))
}

fn decode_record_data(
    record_type: u16,
    message: &[u8],
    rdata_start: usize,
    rdata_end: usize,
) -> Result<DnsRecordData> {
    let rdata = &message[rdata_start..rdata_end];
    match record_type {
        DNS_TYPE_A => {
            if rdata.len() != 4 {
                return Err(CrafterError::invalid_field_value(
                    "dns.a.rdlength",
                    "A records must contain four bytes",
                ));
            }
            Ok(DnsRecordData::A(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )))
        }
        DNS_TYPE_AAAA => {
            if rdata.len() != 16 {
                return Err(CrafterError::invalid_field_value(
                    "dns.aaaa.rdlength",
                    "AAAA records must contain sixteen bytes",
                ));
            }
            Ok(DnsRecordData::Aaaa(Ipv6Addr::from(
                <[u8; 16]>::try_from(rdata).expect("slice length already checked"),
            )))
        }
        DNS_TYPE_CNAME | DNS_TYPE_NS | DNS_TYPE_PTR => {
            let (name, consumed) = decode_dns_name_typed(message, rdata_start)?;
            ensure_rdata_consumed("dns.name.rdata", consumed, rdata.len())?;
            Ok(DnsRecordData::Name(name))
        }
        DNS_TYPE_MX => {
            if rdata.len() < 3 {
                return Err(CrafterError::buffer_too_short("dns.mx", 3, rdata.len()));
            }
            let preference = read_u16_be(&rdata[0..2])?;
            let (exchange, consumed) = decode_dns_name_typed(message, rdata_start + 2)?;
            ensure_rdata_consumed("dns.mx.exchange", consumed + 2, rdata.len())?;
            Ok(DnsRecordData::Mx {
                preference,
                exchange,
            })
        }
        DNS_TYPE_SOA => {
            // MNAME and RNAME are <domain-name> fields (RFC 1035 Section
            // 3.3.13) followed by five fixed 32-bit fields (20 octets total).
            let (mname, mname_used) = decode_dns_name_typed(message, rdata_start)?;
            let (rname, rname_used) = decode_dns_name_typed(message, rdata_start + mname_used)?;
            let fixed_start = mname_used + rname_used;
            if fixed_start + 20 != rdata.len() {
                return Err(CrafterError::invalid_field_value(
                    "dns.soa.rdlength",
                    "SOA RDATA must end with exactly twenty bytes after MNAME and RNAME",
                ));
            }
            let fixed = &rdata[fixed_start..fixed_start + 20];
            Ok(DnsRecordData::Soa {
                mname,
                rname,
                serial: read_u32_be(&fixed[0..4])?,
                refresh: read_u32_be(&fixed[4..8])?,
                retry: read_u32_be(&fixed[8..12])?,
                expire: read_u32_be(&fixed[12..16])?,
                minimum: read_u32_be(&fixed[16..20])?,
            })
        }
        DNS_TYPE_SRV => {
            // Priority, weight, and port are 16-bit fields, followed by an
            // uncompressed target <domain-name> (RFC 2782).
            if rdata.len() < 7 {
                return Err(CrafterError::buffer_too_short("dns.srv", 7, rdata.len()));
            }
            let priority = read_u16_be(&rdata[0..2])?;
            let weight = read_u16_be(&rdata[2..4])?;
            let port = read_u16_be(&rdata[4..6])?;
            let (target, consumed) = decode_dns_name_typed(message, rdata_start + 6)?;
            ensure_rdata_consumed("dns.srv.target", consumed + 6, rdata.len())?;
            Ok(DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        DNS_TYPE_TXT => {
            let mut strings = Vec::new();
            let mut offset = 0;
            while offset < rdata.len() {
                let len = rdata[offset] as usize;
                let start = offset + 1;
                let end = start + len;
                if end > rdata.len() {
                    return Err(CrafterError::buffer_too_short("dns.txt", end, rdata.len()));
                }
                strings.push(rdata[start..end].to_vec());
                offset = end;
            }
            Ok(DnsRecordData::Txt(strings))
        }
        DNS_TYPE_OPT => {
            // OPT RDATA is a sequence of {OPTION-CODE (2), OPTION-LENGTH (2),
            // OPTION-DATA (OPTION-LENGTH)} tuples (RFC 6891 Section 6.1.2).
            let mut options = Vec::new();
            let mut offset = 0;
            while offset < rdata.len() {
                if offset + 4 > rdata.len() {
                    // A partial option header (fewer than the four fixed bytes)
                    // is a truncated option.
                    return Err(CrafterError::buffer_too_short(
                        "dns.opt.option",
                        offset + 4,
                        rdata.len(),
                    ));
                }
                let code = read_u16_be(&rdata[offset..offset + 2])?;
                let length = read_u16_be(&rdata[offset + 2..offset + 4])? as usize;
                let data_start = offset + 4;
                let data_end = data_start + length;
                if data_end > rdata.len() {
                    // The declared OPTION-LENGTH runs past the end of the RDATA.
                    return Err(CrafterError::buffer_too_short(
                        "dns.opt.option.data",
                        data_end,
                        rdata.len(),
                    ));
                }
                options.push(EdnsOption::new(code, rdata[data_start..data_end].to_vec()));
                offset = data_end;
            }
            Ok(DnsRecordData::Opt(options))
        }
        DNS_TYPE_DS => {
            // Key Tag (2), Algorithm (1), Digest Type (1), Digest (rest)
            // (RFC 4034 Section 5.1).
            if rdata.len() < 4 {
                return Err(CrafterError::buffer_too_short("dns.ds", 4, rdata.len()));
            }
            Ok(DnsRecordData::Ds {
                key_tag: read_u16_be(&rdata[0..2])?,
                algorithm: rdata[2],
                digest_type: rdata[3],
                digest: rdata[4..].to_vec(),
            })
        }
        DNS_TYPE_DNSKEY => {
            // Flags (2), Protocol (1), Algorithm (1), Public Key (rest)
            // (RFC 4034 Section 2.1).
            if rdata.len() < 4 {
                return Err(CrafterError::buffer_too_short("dns.dnskey", 4, rdata.len()));
            }
            Ok(DnsRecordData::Dnskey {
                flags: read_u16_be(&rdata[0..2])?,
                protocol: rdata[2],
                algorithm: rdata[3],
                public_key: rdata[4..].to_vec(),
            })
        }
        DNS_TYPE_RRSIG => {
            // Eighteen fixed octets, then the uncompressed Signer's Name, then
            // the Signature (RFC 4034 Section 3.1).
            if rdata.len() < 18 {
                return Err(CrafterError::buffer_too_short("dns.rrsig", 18, rdata.len()));
            }
            let type_covered = read_u16_be(&rdata[0..2])?;
            let algorithm = rdata[2];
            let labels = rdata[3];
            let original_ttl = read_u32_be(&rdata[4..8])?;
            let signature_expiration = read_u32_be(&rdata[8..12])?;
            let signature_inception = read_u32_be(&rdata[12..16])?;
            let key_tag = read_u16_be(&rdata[16..18])?;
            // The Signer's Name MUST NOT be compressed (RFC 4034 Section
            // 3.1.7); decode it relative to the RDATA so any stray pointer is
            // still bounds-checked, and require it to stay within the RDATA.
            let (signer_name, name_used) = decode_dns_name_typed(message, rdata_start + 18)?;
            let signature_start = 18 + name_used;
            if signature_start > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.rrsig.signer",
                    signature_start,
                    rdata.len(),
                ));
            }
            Ok(DnsRecordData::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature: rdata[signature_start..].to_vec(),
            })
        }
        DNS_TYPE_NSEC => {
            // Next Domain Name (uncompressed), then Type Bit Maps (RFC 4034
            // Section 4.1).
            let (next_domain_name, name_used) = decode_dns_name_typed(message, rdata_start)?;
            if name_used > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec.name",
                    name_used,
                    rdata.len(),
                ));
            }
            let type_bitmaps = DnsTypeBitmaps::decode("dns.nsec.bitmap", &rdata[name_used..])?;
            Ok(DnsRecordData::Nsec {
                next_domain_name,
                type_bitmaps,
            })
        }
        DNS_TYPE_NSEC3 => {
            // Hash Alg (1), Flags (1), Iterations (2), Salt Length (1), Salt,
            // Hash Length (1), Next Hashed Owner Name, Type Bit Maps (RFC 5155
            // Section 3.2).
            if rdata.len() < 5 {
                return Err(CrafterError::buffer_too_short("dns.nsec3", 5, rdata.len()));
            }
            let hash_algorithm = rdata[0];
            let flags = rdata[1];
            let iterations = read_u16_be(&rdata[2..4])?;
            let salt_len = rdata[4] as usize;
            let salt_start = 5;
            let salt_end = salt_start + salt_len;
            if salt_end > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec3.salt",
                    salt_end,
                    rdata.len(),
                ));
            }
            let salt = rdata[salt_start..salt_end].to_vec();
            if salt_end + 1 > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec3.hash.length",
                    salt_end + 1,
                    rdata.len(),
                ));
            }
            let hash_len = rdata[salt_end] as usize;
            let hash_start = salt_end + 1;
            let hash_end = hash_start + hash_len;
            if hash_end > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.nsec3.hash",
                    hash_end,
                    rdata.len(),
                ));
            }
            let next_hashed_owner_name = rdata[hash_start..hash_end].to_vec();
            let type_bitmaps = DnsTypeBitmaps::decode("dns.nsec3.bitmap", &rdata[hash_end..])?;
            Ok(DnsRecordData::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed_owner_name,
                type_bitmaps,
            })
        }
        DNS_TYPE_SVCB | DNS_TYPE_HTTPS => {
            // SvcPriority (2), uncompressed TargetName, then SvcParams that
            // consume the remainder of the RDATA (RFC 9460 Section 2.2).
            if rdata.len() < 2 {
                return Err(CrafterError::buffer_too_short("dns.svcb", 2, rdata.len()));
            }
            let priority = read_u16_be(&rdata[0..2])?;
            let (target, target_used) = decode_dns_name_typed(message, rdata_start + 2)?;
            let params_start = 2 + target_used;
            if params_start > rdata.len() {
                return Err(CrafterError::buffer_too_short(
                    "dns.svcb.target",
                    params_start,
                    rdata.len(),
                ));
            }
            let params = SvcParams::decode("dns.svcb.params", &rdata[params_start..])?;
            if record_type == DNS_TYPE_SVCB {
                Ok(DnsRecordData::Svcb {
                    priority,
                    target,
                    params,
                })
            } else {
                Ok(DnsRecordData::Https {
                    priority,
                    target,
                    params,
                })
            }
        }
        _ => Ok(DnsRecordData::Raw(rdata.to_vec())),
    }
}

fn ensure_rdata_consumed(field: &'static str, consumed: usize, available: usize) -> Result<()> {
    if consumed != available {
        return Err(CrafterError::invalid_field_value(
            field,
            "compressed name did not consume the full RDATA field",
        ));
    }
    Ok(())
}

fn validate_count(field: &'static str, count: usize) -> Result<()> {
    if count > u16::MAX as usize {
        return Err(CrafterError::invalid_field_value(
            field,
            "DNS section count exceeds 65535",
        ));
    }
    Ok(())
}

fn value_or_copy<T: Copy>(field: &Field<T>, default: T) -> T {
    field.value().copied().unwrap_or(default)
}

fn record_type_summary(record_type: u16) -> String {
    match dns_type_name(record_type) {
        Some(name) => name.to_string(),
        None => format!("TYPE{record_type}"),
    }
}

/// Return the IANA registry mnemonic for a source-backed DNS RR TYPE, or
/// `None` when the value is unknown to this crate so callers can fall back to
/// a numeric `TYPE<n>` form.
pub fn dns_type_name(record_type: u16) -> Option<&'static str> {
    Some(match record_type {
        DNS_TYPE_A => "A",
        DNS_TYPE_NS => "NS",
        DNS_TYPE_CNAME => "CNAME",
        DNS_TYPE_SOA => "SOA",
        DNS_TYPE_PTR => "PTR",
        DNS_TYPE_MX => "MX",
        DNS_TYPE_TXT => "TXT",
        DNS_TYPE_AAAA => "AAAA",
        DNS_TYPE_SRV => "SRV",
        DNS_TYPE_OPT => "OPT",
        DNS_TYPE_DS => "DS",
        DNS_TYPE_RRSIG => "RRSIG",
        DNS_TYPE_NSEC => "NSEC",
        DNS_TYPE_DNSKEY => "DNSKEY",
        DNS_TYPE_NSEC3 => "NSEC3",
        DNS_TYPE_NSEC3PARAM => "NSEC3PARAM",
        DNS_TYPE_TLSA => "TLSA",
        DNS_TYPE_SVCB => "SVCB",
        DNS_TYPE_HTTPS => "HTTPS",
        _ => return None,
    })
}

#[cfg(test)]
mod dns_tests {
    use super::{
        decode_dns_name, Dns, DnsName, DnsQuestion, DnsRecord, DnsRecordData, DNS_CLASS_IN,
        DNS_FLAG_AUTHORITATIVE, DNS_FLAG_QR_RESPONSE, DNS_FLAG_RECURSION_DESIRED, DNS_TYPE_A,
        DNS_TYPE_AAAA, DNS_TYPE_CNAME, DNS_TYPE_TXT,
    };
    use crate::{Ipv4, NetworkLayer, Packet, Udp};
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn dns_a_query_encodes_header_question_and_udp_payload() {
        let dns = Dns::a_query("example.com").id(0xbeef);
        let packet = Udp::new().sport(53001).dport(53) / dns;
        let compiled = packet.compile().unwrap();
        assert_eq!(&compiled.as_bytes()[8..10], &0xbeefu16.to_be_bytes());
        assert_eq!(
            &compiled.as_bytes()[10..12],
            &DNS_FLAG_RECURSION_DESIRED.to_be_bytes()
        );
        assert_eq!(&compiled.as_bytes()[12..14], &1u16.to_be_bytes());
        assert!(compiled.as_bytes().ends_with(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]));
    }

    #[test]
    fn dns_response_records_roundtrip() {
        let original = Dns::new()
            .id(0x1234)
            .response(true)
            .authoritative(true)
            .question(DnsQuestion::a("example.com."))
            .answer(DnsRecord::a(
                "example.com.",
                Ipv4Addr::new(203, 0, 113, 10),
                60,
            ))
            .answer(DnsRecord::aaaa(
                "example.com.",
                Ipv6Addr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                60,
            ))
            .answer(DnsRecord::cname("www.example.com.", "example.com.", 60));

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 53))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53001)
            / original.clone())
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();

        assert_eq!(dns.id_value(), 0x1234);
        assert_eq!(
            dns.flags_value() & (DNS_FLAG_QR_RESPONSE | DNS_FLAG_AUTHORITATIVE),
            DNS_FLAG_QR_RESPONSE | DNS_FLAG_AUTHORITATIVE
        );
        assert_eq!(dns.questions()[0].name(), "example.com.");
        assert_eq!(dns.answers().len(), 3);
        assert_eq!(
            dns.answers()[0].data(),
            &DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 10))
        );
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn dns_decode_uses_udp_port_context() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            / Udp::new().sport(53001).dport(53)
            / Dns::aaaa_query("example.com").id(0x5678))
        .compile()
        .unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();

        assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_AAAA);
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn dns_builders_keep_common_values_visible() {
        let query = Dns::new()
            .id(7)
            .rd(false)
            .question(DnsQuestion::new("example.org", DNS_TYPE_A).qclass(DNS_CLASS_IN));

        assert_eq!(query.id_value(), 7);
        assert_eq!(query.flags_value() & DNS_FLAG_RECURSION_DESIRED, 0);
        assert_eq!(query.questions()[0].name(), "example.org.");
        assert_eq!(query.questions()[0].question_class(), DNS_CLASS_IN);
    }

    #[test]
    fn dns_compressed_name_decode_is_exposed() {
        let message = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, 4, b'm', b'a', b'i', b'l', 0xc0, 4,
        ];

        assert_eq!(
            decode_dns_name(&message, 0).unwrap(),
            ("www.example.com.".to_string(), 17)
        );
        assert_eq!(
            decode_dns_name(&message, 17).unwrap(),
            ("mail.example.com.".to_string(), 7)
        );
    }

    #[test]
    fn non_text_owner_name_round_trips_through_a_compiled_packet() {
        // An owner name with a non-UTF-8 label must survive build -> compile ->
        // decode -> recompile with its exact wire bytes intact, exercising the
        // byte-preserving name path end to end through the packet stack.
        let owner = DnsName::from_labels([vec![0x00u8, 0xff], b"example".to_vec()]).unwrap();
        assert!(!owner.is_text());

        let record = DnsRecord::new(
            owner.clone(),
            DNS_TYPE_TXT,
            DNS_CLASS_IN,
            300,
            DnsRecordData::txt(b"v"),
        );
        let original = Dns::new().id(0x4242).response(true).answer(record);

        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(198, 51, 100, 53))
            .dst(Ipv4Addr::new(192, 0, 2, 10))
            / Udp::new().sport(53).dport(53001)
            / original)
            .compile()
            .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();
        let answer = &dns.answers()[0];

        // Exact wire-label bytes are preserved, and the presentation string uses
        // the documented \DDD escaping for the non-text octets.
        assert_eq!(answer.name_labels(), owner.labels());
        assert_eq!(answer.dns_name(), &owner);
        // Each label is escaped independently and dot-separated, so the
        // non-text first label and the text second label render as one name.
        assert_eq!(answer.name(), "\\000\\255.example.");
        assert_eq!(decoded.compile().unwrap(), bytes);
    }

    #[test]
    fn dns_type_mismatch_is_rejected() {
        let record = DnsRecord::new(
            "example.com.",
            DNS_TYPE_CNAME,
            DNS_CLASS_IN,
            60,
            DnsRecordData::A(Ipv4Addr::new(203, 0, 113, 1)),
        );
        assert!(Packet::from_layer(Dns::new().answer(record))
            .compile()
            .is_err());
    }
}

#[cfg(test)]
mod dns_header_codepoints {
    use super::{
        dns_type_name, Dns, DnsQuestion, DNS_FLAG_AUTHORITATIVE, DNS_FLAG_QR_RESPONSE,
        DNS_FLAG_RECURSION_DESIRED, DNS_OPCODE_QUERY, DNS_OPCODE_STATUS, DNS_OPCODE_UPDATE,
        DNS_RCODE_NOERROR, DNS_RCODE_NXDOMAIN, DNS_RCODE_REFUSED, DNS_TYPE_A, DNS_TYPE_HTTPS,
        DNS_TYPE_SOA, DNS_TYPE_SRV,
    };
    use crate::Udp;

    #[test]
    fn existing_flag_helpers_compile_identically() {
        // A response with AA set built through the existing helpers must produce
        // the same flags word it did before opcode/rcode helpers existed.
        let dns = Dns::new()
            .id(0xbeef)
            .response(true)
            .authoritative(true)
            .question(DnsQuestion::a("example.com."));
        let compiled = (Udp::new().sport(53001).dport(53) / dns).compile().unwrap();

        let expected_flags =
            DNS_FLAG_QR_RESPONSE | DNS_FLAG_AUTHORITATIVE | DNS_FLAG_RECURSION_DESIRED;
        assert_eq!(&compiled.as_bytes()[10..12], &expected_flags.to_be_bytes());
    }

    #[test]
    fn opcode_setter_preserves_unrelated_bits() {
        let dns = Dns::new()
            .response(true)
            .authoritative(true)
            .rcode(DNS_RCODE_NXDOMAIN)
            .opcode(DNS_OPCODE_UPDATE);

        // OPCODE is set without disturbing QR, AA, RD, or the RCODE nibble.
        assert_eq!(dns.opcode_value(), DNS_OPCODE_UPDATE);
        assert!(dns.is_response());
        assert_ne!(dns.flags_value() & DNS_FLAG_AUTHORITATIVE, 0);
        assert_ne!(dns.flags_value() & DNS_FLAG_RECURSION_DESIRED, 0);
        assert_eq!(dns.rcode_value(), DNS_RCODE_NXDOMAIN);
    }

    #[test]
    fn rcode_setter_preserves_unrelated_bits() {
        let dns = Dns::new()
            .opcode(DNS_OPCODE_STATUS)
            .response(true)
            .rcode(DNS_RCODE_REFUSED);

        assert_eq!(dns.rcode_value(), DNS_RCODE_REFUSED);
        assert_eq!(dns.opcode_value(), DNS_OPCODE_STATUS);
        assert!(dns.is_response());
    }

    #[test]
    fn opcode_and_rcode_defaults_are_query_noerror() {
        let dns = Dns::new();
        assert_eq!(dns.opcode_value(), DNS_OPCODE_QUERY);
        assert_eq!(dns.rcode_value(), DNS_RCODE_NOERROR);
    }

    #[test]
    fn unknown_opcode_and_rcode_values_round_trip() {
        // Values outside the named registry entries must remain representable.
        let dns = Dns::new().opcode(0xf).rcode(0xf);
        assert_eq!(dns.opcode_value(), 0xf);
        assert_eq!(dns.rcode_value(), 0xf);

        // Only the low four bits of each field are honored; higher bits are
        // masked off rather than corrupting neighbouring fields.
        let truncated = Dns::new().opcode(0xff).rcode(0xff);
        assert_eq!(truncated.opcode_value(), 0xf);
        assert_eq!(truncated.rcode_value(), 0xf);
    }

    #[test]
    fn raw_flags_remain_the_escape_hatch() {
        // flags() sets the whole word verbatim, including unusual combinations,
        // and flags_value() reflects it untouched.
        let dns = Dns::new().flags(0xabcd);
        assert_eq!(dns.flags_value(), 0xabcd);
        // Extracted fields reflect the raw word without rejecting it.
        assert_eq!(dns.opcode_value(), ((0xabcd & 0x7800) >> 11) as u8);
        assert_eq!(dns.rcode_value(), (0xabcd & 0x000f) as u8);
    }

    #[test]
    fn type_names_cover_source_backed_codepoints() {
        assert_eq!(dns_type_name(DNS_TYPE_A), Some("A"));
        assert_eq!(dns_type_name(DNS_TYPE_SOA), Some("SOA"));
        assert_eq!(dns_type_name(DNS_TYPE_SRV), Some("SRV"));
        assert_eq!(dns_type_name(DNS_TYPE_HTTPS), Some("HTTPS"));
        // Unknown values stay numeric for callers to format.
        assert_eq!(dns_type_name(60000), None);
    }
}

#[cfg(test)]
mod dns_base_rdata {
    use super::{
        decode_record_data, Dns, DnsName, DnsRecord, DnsRecordData, DNS_CLASS_IN, DNS_TYPE_SOA,
        DNS_TYPE_SRV,
    };
    use crate::{Ipv4, NetworkLayer, Packet, Udp};
    use core::net::Ipv4Addr;

    /// Build a DNS message carrying one answer, compile it through the packet
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
    fn soa_record_round_trips_through_packet_stack() {
        let (data, original, recompiled) = round_trip_answer(DnsRecord::soa(
            "example.com.",
            300,
            "ns1.example.com.",
            "hostmaster.example.com.",
            2024010101,
            7200,
            3600,
            1209600,
            300,
        ));
        assert_eq!(
            data,
            DnsRecordData::Soa {
                mname: DnsName::parse("ns1.example.com.").unwrap(),
                rname: DnsName::parse("hostmaster.example.com.").unwrap(),
                serial: 2024010101,
                refresh: 7200,
                retry: 3600,
                expire: 1209600,
                minimum: 300,
            }
        );
        // Stable wire bytes round trip (no compression emitted by default).
        assert_eq!(recompiled, original);
    }

    #[test]
    fn srv_record_round_trips_through_packet_stack() {
        let (data, original, recompiled) = round_trip_answer(DnsRecord::srv(
            "_sip._tcp.example.com.",
            60,
            10,
            60,
            5060,
            "sip.example.com.",
        ));
        assert_eq!(
            data,
            DnsRecordData::Srv {
                priority: 10,
                weight: 60,
                port: 5060,
                target: DnsName::parse("sip.example.com.").unwrap(),
            }
        );
        // Round-trip is byte-stable.
        assert_eq!(recompiled, original);
    }

    #[test]
    fn soa_too_short_fixed_tail_is_rejected() {
        // MNAME = "a.", RNAME = ".", then only 19 bytes where 20 are required.
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[1, b'a', 0]); // mname "a."
        rdata.push(0); // rname root
        rdata.extend_from_slice(&[0u8; 19]); // one byte short of the 20-byte tail
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_SOA, &rdata, 0, end).is_err());
    }

    #[test]
    fn soa_trailing_bytes_after_fixed_tail_are_rejected() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&[1, b'a', 0]); // mname "a."
        rdata.push(0); // rname root
        rdata.extend_from_slice(&[0u8; 21]); // one byte too many
        let end = rdata.len();
        assert!(decode_record_data(DNS_TYPE_SOA, &rdata, 0, end).is_err());
    }

    #[test]
    fn srv_too_short_fixed_header_is_rejected() {
        // Fewer than the six fixed bytes (priority/weight/port) plus a name.
        let rdata = [0u8; 5];
        assert!(decode_record_data(DNS_TYPE_SRV, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn srv_trailing_bytes_after_target_are_rejected() {
        // priority/weight/port + root target + one stray trailing byte.
        let rdata = [0u8, 1, 0, 2, 0x13, 0x88, 0, 0xff];
        assert!(decode_record_data(DNS_TYPE_SRV, &rdata, 0, rdata.len()).is_err());
    }

    #[test]
    fn record_data_type_mismatch_is_rejected_on_compile() {
        // A SOA payload under an SRV type must be refused at compile time.
        let record = DnsRecord::new(
            "example.com.",
            DNS_TYPE_SRV,
            DNS_CLASS_IN,
            60,
            DnsRecordData::Soa {
                mname: DnsName::parse("ns1.example.com.").unwrap(),
                rname: DnsName::parse("hostmaster.example.com.").unwrap(),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            },
        );
        assert!(Packet::from_layer(Dns::new().answer(record))
            .compile()
            .is_err());
    }
}

#[cfg(test)]
mod dns_service_rdata {
    use super::{
        decode_record_data, svcb_param_key_name, Dns, DnsName, DnsRecord, DnsRecordData, SvcParam,
        SvcParams, DNS_CLASS_IN, DNS_SVCB_KEY_ALPN, DNS_SVCB_KEY_IPV4HINT, DNS_SVCB_KEY_PORT,
        DNS_TYPE_HTTPS, DNS_TYPE_SVCB,
    };
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
            assert_eq!(entries[0].key(), super::DNS_SVCB_KEY_NO_DEFAULT_ALPN);
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
    fn svcb_param_key_names_cover_source_backed_keys() {
        assert_eq!(
            svcb_param_key_name(super::DNS_SVCB_KEY_MANDATORY),
            Some("mandatory")
        );
        assert_eq!(svcb_param_key_name(DNS_SVCB_KEY_ALPN), Some("alpn"));
        assert_eq!(svcb_param_key_name(DNS_SVCB_KEY_PORT), Some("port"));
        assert_eq!(
            svcb_param_key_name(super::DNS_SVCB_KEY_DOHPATH),
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

#[cfg(test)]
mod dns_malformed {
    //! Table-driven boundary coverage for the record-data and name parsers.
    //!
    //! These cases live as unit tests (rather than full packet fixtures in the
    //! resilience corpus) because they exercise a single RDATA or name decoder
    //! directly and assert the exact structured error field, which is clearer
    //! than reconstructing an entire DNS message. The resilience corpus carries
    //! the matching end-to-end packet rows.

    use super::{
        decode_dns_name_typed, decode_record_data, DnsRecordData, DNS_MAX_LABEL_LEN, DNS_TYPE_A,
        DNS_TYPE_AAAA, DNS_TYPE_DNSKEY, DNS_TYPE_DS, DNS_TYPE_NSEC, DNS_TYPE_NSEC3, DNS_TYPE_RRSIG,
        DNS_TYPE_SOA, DNS_TYPE_SRV, DNS_TYPE_SVCB,
    };
    use crate::error::CrafterError;

    /// Assert that decoding `rdata` for `record_type` fails with a
    /// `buffer-too-short` error whose context is exactly `field`.
    fn assert_too_short(record_type: u16, rdata: &[u8], field: &str) {
        match decode_record_data(record_type, rdata, 0, rdata.len()) {
            Err(CrafterError::BufferTooShort { context, .. }) => assert_eq!(
                context, field,
                "type {record_type:#x} expected buffer-too-short context {field}"
            ),
            other => {
                panic!("type {record_type:#x} expected buffer-too-short {field}, got {other:?}")
            }
        }
    }

    /// Assert that decoding `rdata` for `record_type` fails with an
    /// `invalid-field-value` error whose field is exactly `field`.
    fn assert_invalid(record_type: u16, rdata: &[u8], field: &str) {
        match decode_record_data(record_type, rdata, 0, rdata.len()) {
            Err(CrafterError::InvalidFieldValue { field: got, .. }) => assert_eq!(
                got, field,
                "type {record_type:#x} expected invalid-field-value {field}"
            ),
            other => {
                panic!("type {record_type:#x} expected invalid-field-value {field}, got {other:?}")
            }
        }
    }

    #[test]
    fn fixed_length_records_reject_wrong_rdlength() {
        // A and AAAA carry an exact fixed-length address; any other length is
        // structurally invalid rather than silently truncated.
        assert_invalid(DNS_TYPE_A, &[192, 0, 2], "dns.a.rdlength");
        assert_invalid(DNS_TYPE_A, &[192, 0, 2, 1, 9], "dns.a.rdlength");
        assert_invalid(DNS_TYPE_AAAA, &[0u8; 15], "dns.aaaa.rdlength");
        assert_invalid(DNS_TYPE_AAAA, &[0u8; 17], "dns.aaaa.rdlength");
    }

    #[test]
    fn dnssec_fixed_headers_reject_truncation() {
        // Each DNSSEC record has a fixed minimum header; fewer bytes must error
        // on the documented field rather than panic on a slice.
        assert_too_short(DNS_TYPE_DS, &[0u8; 3], "dns.ds");
        assert_too_short(DNS_TYPE_DNSKEY, &[0u8; 3], "dns.dnskey");
        assert_too_short(DNS_TYPE_RRSIG, &[0u8; 17], "dns.rrsig");
    }

    #[test]
    fn soa_rejects_wrong_fixed_tail_length() {
        // MNAME "a." + RNAME root, then a fixed tail that is one byte short and
        // one byte long: both are rejected on dns.soa.rdlength.
        let mut short = vec![1u8, b'a', 0, 0];
        short.extend_from_slice(&[0u8; 19]);
        assert_invalid(DNS_TYPE_SOA, &short, "dns.soa.rdlength");

        let mut long = vec![1u8, b'a', 0, 0];
        long.extend_from_slice(&[0u8; 21]);
        assert_invalid(DNS_TYPE_SOA, &long, "dns.soa.rdlength");
    }

    #[test]
    fn srv_rejects_short_header_and_trailing_bytes() {
        // Fewer than the six fixed octets plus a name.
        assert_too_short(DNS_TYPE_SRV, &[0u8; 5], "dns.srv");
        // priority/weight/port + root target + one stray trailing byte.
        assert_invalid(
            DNS_TYPE_SRV,
            &[0, 1, 0, 2, 0x13, 0x88, 0, 0xff],
            "dns.srv.target",
        );
    }

    #[test]
    fn nsec3_rejects_hash_length_overrun() {
        // Salt length 0, then Hash Length 20 with only two bytes present.
        assert_too_short(
            DNS_TYPE_NSEC3,
            &[1, 0, 0, 10, 0, 20, 0x11, 0x22],
            "dns.nsec3.hash",
        );
    }

    #[test]
    fn nsec_rejects_non_minimal_trailing_zero_bitmap() {
        // Next name root, then a window whose bitmap ends in a trailing zero
        // octet (a non-minimal encoding) is rejected on dns.nsec.bitmap.
        let rdata = [0u8, 0x00, 2, 0x40, 0x00];
        assert_invalid(DNS_TYPE_NSEC, &rdata, "dns.nsec.bitmap");
    }

    #[test]
    fn svcb_rejects_out_of_order_and_overrun_params() {
        // priority + root target + port(3) then alpn(1): a decreasing key pair.
        let out_of_order = [0u8, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0];
        assert_invalid(DNS_TYPE_SVCB, &out_of_order, "dns.svcb.params");

        // priority + root target + a SvcParam whose declared length runs past
        // the RDATA.
        let overrun = [0u8, 1, 0, 0, 3, 0, 8, 0, 0];
        assert_too_short(DNS_TYPE_SVCB, &overrun, "dns.svcb.params");
    }

    #[test]
    fn unknown_record_type_decodes_as_raw_not_rejected() {
        // A structurally valid record with a TYPE this crate does not model must
        // surface its RDATA verbatim rather than being rejected for being
        // unknown.
        let rdata = [0xde, 0xad, 0xbe, 0xef];
        let data = decode_record_data(0xfff0, &rdata, 0, rdata.len()).unwrap();
        assert_eq!(data, DnsRecordData::Raw(rdata.to_vec()));

        // Even a zero-length RDATA under an unknown type stays raw and empty.
        let empty = decode_record_data(0xfff0, &[], 0, 0).unwrap();
        assert_eq!(empty, DnsRecordData::Raw(Vec::new()));
    }

    #[test]
    fn name_decoder_rejects_reserved_marker_and_length_overrun() {
        // A reserved label-length marker (top two bits 0b10) is malformed.
        match decode_dns_name_typed(&[0x40], 0) {
            Err(CrafterError::InvalidFieldValue { field, .. }) => assert_eq!(field, "dns.name"),
            other => panic!("expected reserved-marker rejection, got {other:?}"),
        }

        // Four 63-octet labels exceed the 255-octet full-name limit.
        let mut overrun = Vec::new();
        for _ in 0..4 {
            overrun.push(DNS_MAX_LABEL_LEN as u8);
            overrun.extend_from_slice(&[b'a'; DNS_MAX_LABEL_LEN]);
        }
        overrun.push(0);
        match decode_dns_name_typed(&overrun, 0) {
            Err(CrafterError::InvalidFieldValue { field, .. }) => assert_eq!(field, "dns.name"),
            other => panic!("expected full-name overrun rejection, got {other:?}"),
        }
    }

    #[test]
    fn label_at_63_octet_boundary_is_accepted() {
        // The 63-octet label boundary is the largest valid label and must decode
        // successfully (the boundary itself is not an error).
        let mut wire = Vec::new();
        wire.push(DNS_MAX_LABEL_LEN as u8);
        wire.extend_from_slice(&[b'a'; DNS_MAX_LABEL_LEN]);
        wire.push(0);
        let (name, used) = decode_dns_name_typed(&wire, 0).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(name.labels(), &[vec![b'a'; DNS_MAX_LABEL_LEN]]);
    }
}

#[cfg(test)]
mod dns_golden_bytes {
    use super::{Dns, DnsQuestion, DNS_TYPE_A};
    use crate::{Ipv4, LinkType, Packet, Udp};
    use core::net::Ipv4Addr;

    const DNS_QUERY_FIXTURE: &[u8] = fixture_bytes!("bytes/ipv4-udp-dns-query-example-com.bin");

    #[test]
    fn dns_query_matches_golden_bytes() {
        let bytes = (Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 53))
            .id(0x1237)
            .ttl(61)
            / Udp::new().sport(53001).dport(53)
            / Dns::new()
                .id(0xbeef)
                .question(DnsQuestion::new("example.com.", DNS_TYPE_A)))
        .compile()
        .unwrap();

        assert_eq!(bytes.as_bytes(), DNS_QUERY_FIXTURE);
    }

    #[test]
    fn dns_query_fixture_decodes_to_typed_layer() {
        let decoded = Packet::decode_from_l3(crate::NetworkLayer::Ipv4, DNS_QUERY_FIXTURE).unwrap();
        let dns = decoded.layer::<Dns>().unwrap();

        assert_eq!(dns.id_value(), 0xbeef);
        assert_eq!(dns.questions()[0].name(), "example.com.");
        assert_eq!(dns.questions()[0].question_type(), DNS_TYPE_A);
        assert_eq!(decoded.compile().unwrap().as_bytes(), DNS_QUERY_FIXTURE);
    }

    #[test]
    fn non_dns_udp_payload_stays_raw_even_when_decoding_from_link() {
        let raw_fixture = fixture_bytes!("bytes/ethernet-vlan-ipv4-udp-raw.bin");
        let decoded = Packet::decode_from_link(LinkType::Ethernet, raw_fixture).unwrap();
        assert!(decoded.layer::<Dns>().is_none());
    }
}
