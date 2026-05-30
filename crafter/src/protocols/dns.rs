//! Domain Name System protocol implementation.

use core::any::Any;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ops::Div;
use core::str;

use crate::endian::{read_u16_be, read_u32_be};
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

/// DNS header length in bytes.
pub const DNS_HEADER_LEN: usize = 12;

/// DNS port.
pub const DNS_PORT: u16 = 53;

/// Standard Internet class (IN), IANA DNS CLASSes.
pub const DNS_CLASS_IN: u16 = 1;
/// Chaos class (CH), IANA DNS CLASSes.
pub const DNS_CLASS_CH: u16 = 3;
/// Hesiod class (HS), IANA DNS CLASSes.
pub const DNS_CLASS_HS: u16 = 4;
/// QCLASS NONE, IANA DNS CLASSes (RFC 2136).
pub const DNS_CLASS_NONE: u16 = 254;
/// QCLASS ANY (`*`), IANA DNS CLASSes.
pub const DNS_CLASS_ANY: u16 = 255;

/// DNS A record type.
pub const DNS_TYPE_A: u16 = 1;
/// DNS NS record type.
pub const DNS_TYPE_NS: u16 = 2;
/// DNS CNAME record type.
pub const DNS_TYPE_CNAME: u16 = 5;
/// DNS SOA record type.
pub const DNS_TYPE_SOA: u16 = 6;
/// DNS PTR record type.
pub const DNS_TYPE_PTR: u16 = 12;
/// DNS MX record type.
pub const DNS_TYPE_MX: u16 = 15;
/// DNS TXT record type.
pub const DNS_TYPE_TXT: u16 = 16;
/// DNS AAAA record type.
pub const DNS_TYPE_AAAA: u16 = 28;
/// DNS SRV record type (RFC 2782).
pub const DNS_TYPE_SRV: u16 = 33;
/// DNS OPT pseudo-record type for EDNS(0) (RFC 6891).
pub const DNS_TYPE_OPT: u16 = 41;
/// DNS DS record type (RFC 4034).
pub const DNS_TYPE_DS: u16 = 43;
/// DNS RRSIG record type (RFC 4034).
pub const DNS_TYPE_RRSIG: u16 = 46;
/// DNS NSEC record type (RFC 4034).
pub const DNS_TYPE_NSEC: u16 = 47;
/// DNS DNSKEY record type (RFC 4034).
pub const DNS_TYPE_DNSKEY: u16 = 48;
/// DNS NSEC3 record type (RFC 5155).
pub const DNS_TYPE_NSEC3: u16 = 50;
/// DNS NSEC3PARAM record type (RFC 5155).
pub const DNS_TYPE_NSEC3PARAM: u16 = 51;
/// DNS TLSA record type (RFC 6698).
pub const DNS_TYPE_TLSA: u16 = 52;
/// DNS SVCB service-binding record type (RFC 9460).
pub const DNS_TYPE_SVCB: u16 = 64;
/// DNS HTTPS service-binding record type (RFC 9460).
pub const DNS_TYPE_HTTPS: u16 = 65;

/// DNS QUERY opcode, IANA DNS OpCodes.
pub const DNS_OPCODE_QUERY: u8 = 0;
/// DNS IQUERY (inverse query) opcode, obsolete, IANA DNS OpCodes.
pub const DNS_OPCODE_IQUERY: u8 = 1;
/// DNS STATUS opcode, IANA DNS OpCodes.
pub const DNS_OPCODE_STATUS: u8 = 2;
/// DNS NOTIFY opcode, IANA DNS OpCodes (RFC 1996).
pub const DNS_OPCODE_NOTIFY: u8 = 4;
/// DNS UPDATE opcode, IANA DNS OpCodes (RFC 2136).
pub const DNS_OPCODE_UPDATE: u8 = 5;
/// DNS Stateful Operations (DSO) opcode, IANA DNS OpCodes (RFC 8490).
pub const DNS_OPCODE_DSO: u8 = 6;

/// DNS NOERROR response code, IANA DNS RCODEs.
pub const DNS_RCODE_NOERROR: u8 = 0;
/// DNS FORMERR (format error) response code, IANA DNS RCODEs.
pub const DNS_RCODE_FORMERR: u8 = 1;
/// DNS SERVFAIL (server failure) response code, IANA DNS RCODEs.
pub const DNS_RCODE_SERVFAIL: u8 = 2;
/// DNS NXDOMAIN (non-existent domain) response code, IANA DNS RCODEs.
pub const DNS_RCODE_NXDOMAIN: u8 = 3;
/// DNS NOTIMP (not implemented) response code, IANA DNS RCODEs.
pub const DNS_RCODE_NOTIMP: u8 = 4;
/// DNS REFUSED response code, IANA DNS RCODEs.
pub const DNS_RCODE_REFUSED: u8 = 5;
/// DNS YXDOMAIN (name exists when it should not) response code (RFC 2136).
pub const DNS_RCODE_YXDOMAIN: u8 = 6;
/// DNS YXRRSET (RR set exists when it should not) response code (RFC 2136).
pub const DNS_RCODE_YXRRSET: u8 = 7;
/// DNS NXRRSET (RR set that should exist does not) response code (RFC 2136).
pub const DNS_RCODE_NXRRSET: u8 = 8;
/// DNS NOTAUTH (server not authoritative / not authorized) response code
/// (RFC 2136, RFC 8945).
pub const DNS_RCODE_NOTAUTH: u8 = 9;
/// DNS NOTZONE (name not contained in zone) response code (RFC 2136).
pub const DNS_RCODE_NOTZONE: u8 = 10;
/// DNS DSOTYPENI (DSO-TYPE not implemented) response code (RFC 8490).
pub const DNS_RCODE_DSOTYPENI: u8 = 11;

/// EDNS(0) option code NSID (RFC 5001), IANA DNS EDNS0 Option Codes.
pub const DNS_EDNS_OPTION_NSID: u16 = 3;
/// EDNS(0) option code DAU (RFC 6975), IANA DNS EDNS0 Option Codes.
pub const DNS_EDNS_OPTION_DAU: u16 = 5;
/// EDNS(0) option code DHU (RFC 6975), IANA DNS EDNS0 Option Codes.
pub const DNS_EDNS_OPTION_DHU: u16 = 6;
/// EDNS(0) option code N3U (RFC 6975), IANA DNS EDNS0 Option Codes.
pub const DNS_EDNS_OPTION_N3U: u16 = 7;
/// EDNS(0) option code edns-client-subnet (RFC 7871), IANA DNS EDNS0 Option
/// Codes.
pub const DNS_EDNS_OPTION_CLIENT_SUBNET: u16 = 8;
/// EDNS(0) option code EDNS EXPIRE (RFC 7314), IANA DNS EDNS0 Option Codes.
pub const DNS_EDNS_OPTION_EXPIRE: u16 = 9;
/// EDNS(0) option code COOKIE (RFC 7873), IANA DNS EDNS0 Option Codes.
pub const DNS_EDNS_OPTION_COOKIE: u16 = 10;
/// EDNS(0) option code edns-tcp-keepalive (RFC 7828), IANA DNS EDNS0 Option
/// Codes.
pub const DNS_EDNS_OPTION_TCP_KEEPALIVE: u16 = 11;
/// EDNS(0) option code Padding (RFC 7830), IANA DNS EDNS0 Option Codes.
pub const DNS_EDNS_OPTION_PADDING: u16 = 12;
/// EDNS(0) option code Extended DNS Error (RFC 8914), IANA DNS EDNS0 Option
/// Codes.
pub const DNS_EDNS_OPTION_EXTENDED_ERROR: u16 = 15;

/// Default EDNS(0) requestor UDP payload size carried in the OPT CLASS field
/// (RFC 6891 Section 6.2.5 recommends 4096 as a sensible default).
pub const DNS_EDNS_DEFAULT_UDP_PAYLOAD_SIZE: u16 = 4096;

/// EDNS(0) DO ("DNSSEC OK") flag bit within the lower 16 bits of the OPT TTL
/// field (RFC 6891 Section 6.1.3; IANA EDNS Header Flags bit 0). In the full
/// 32-bit TTL word this is mask `0x0000_8000`.
pub const DNS_EDNS_FLAG_DO: u16 = 0x8000;

/// DNS response flag bit.
pub const DNS_FLAG_QR_RESPONSE: u16 = 0x8000;
/// DNS authoritative-answer flag bit.
pub const DNS_FLAG_AUTHORITATIVE: u16 = 0x0400;
/// DNS truncated flag bit.
pub const DNS_FLAG_TRUNCATED: u16 = 0x0200;
/// DNS recursion-desired flag bit.
pub const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
/// DNS recursion-available flag bit.
pub const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
/// DNS authentic-data flag bit.
pub const DNS_FLAG_AUTHENTIC_DATA: u16 = 0x0020;
/// DNS checking-disabled flag bit.
pub const DNS_FLAG_CHECKING_DISABLED: u16 = 0x0010;

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

/// A DNS owner or target name preserved as wire labels.
///
/// DNS labels are byte sequences, not text (RFC 1035 Section 3.1). Most names
/// are text-compatible and round trip through the ergonomic trailing-dot string
/// API, but the wire format permits arbitrary octets in a label. `DnsName`
/// keeps the exact label bytes so non-text names are not silently lost, while
/// still exposing a stable presentation string.
///
/// The presentation string uses the RFC 1035 Section 5.1 master-file escaping
/// convention so non-text and special bytes survive a string round trip:
///
/// - bytes outside the printable ASCII range, and `.` or `\` inside a label,
///   are written as `\DDD` (a backslash followed by exactly three decimal
///   digits, the octet value), matching RFC 1035 Section 5.1 and RFC 4343
///   Section 2.1.
/// - printable ASCII bytes are written verbatim.
/// - the trailing dot terminates the name; the root name is `"."`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
    presentation: String,
}

impl DnsName {
    /// Build a name from raw wire labels (each label is a byte slice, the root
    /// label is the empty list).
    ///
    /// Returns an error when a label exceeds 63 bytes or the encoded name would
    /// exceed the 255-octet wire limit (RFC 1035 Section 2.3.4).
    pub fn from_labels<I, L>(labels: I) -> Result<Self>
    where
        I: IntoIterator<Item = L>,
        L: AsRef<[u8]>,
    {
        let labels: Vec<Vec<u8>> = labels
            .into_iter()
            .map(|label| label.as_ref().to_vec())
            .collect();
        validate_labels(&labels)?;
        let presentation = labels_to_presentation(&labels);
        Ok(Self {
            labels,
            presentation,
        })
    }

    /// Parse a presentation-form name, honoring the RFC 1035 Section 5.1
    /// `\DDD` and `\X` escapes so non-text labels can be expressed as text.
    ///
    /// A trailing dot is accepted and canonical; a bare relative name is
    /// treated as fully qualified.
    pub fn parse(name: &str) -> Result<Self> {
        let labels = presentation_to_labels(name)?;
        validate_labels(&labels)?;
        let presentation = labels_to_presentation(&labels);
        Ok(Self {
            labels,
            presentation,
        })
    }

    /// The root name (`"."`).
    pub fn root() -> Self {
        Self {
            labels: Vec::new(),
            presentation: ".".to_string(),
        }
    }

    /// Stable presentation string in canonical trailing-dot form.
    ///
    /// Text-compatible names match the historical string form exactly;
    /// non-text labels use `\DDD` escapes.
    pub fn presentation(&self) -> &str {
        &self.presentation
    }

    /// Exact wire-label bytes, in order. The root name yields an empty slice.
    pub fn labels(&self) -> &[Vec<u8>] {
        &self.labels
    }

    /// True when every label is valid UTF-8 with no byte requiring an escape,
    /// so the presentation string is a faithful text rendering.
    pub fn is_text(&self) -> bool {
        self.labels.iter().all(|label| label_is_text(label))
    }

    fn encoded_len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| 1 + label.len())
            .sum::<usize>()
            + 1
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut wire_len = 1usize;
        for label in &self.labels {
            if label.is_empty() {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "empty label inside DNS name",
                ));
            }
            if label.len() > DNS_MAX_LABEL_LEN {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "label exceeds 63 bytes",
                ));
            }
            wire_len += 1 + label.len();
            if wire_len > DNS_MAX_NAME_WIRE_LEN {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "encoded name exceeds 255 bytes",
                ));
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        Ok(())
    }
}

impl From<&str> for DnsName {
    /// Lossy convenience conversion used by builders. Falls back to the root
    /// name when the input cannot be parsed so infallible builder call sites
    /// keep compiling; use [`DnsName::parse`] when an error is meaningful.
    fn from(name: &str) -> Self {
        DnsName::parse(name).unwrap_or_else(|_| DnsName::root())
    }
}

impl From<String> for DnsName {
    fn from(name: String) -> Self {
        DnsName::from(name.as_str())
    }
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

    fn encoded_len(&self) -> usize {
        4 + self.data.len()
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
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

    fn encoded_len(&self) -> usize {
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
    fn encode(&self, out: &mut Vec<u8>) {
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
    fn decode(field: &'static str, rdata: &[u8]) -> Result<Self> {
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

/// Decode a DNS name from a full DNS message and byte offset.
///
/// The returned offset is the number of bytes consumed at the original offset,
/// so compressed names return the two-byte pointer length. The name is returned
/// in canonical trailing-dot presentation form; non-text labels are rendered
/// with `\DDD` escapes (RFC 1035 Section 5.1). Use [`decode_dns_name_typed`] to
/// recover the exact wire-label bytes.
pub fn decode_dns_name(message: &[u8], offset: usize) -> Result<(String, usize)> {
    let (name, used) = decode_dns_name_typed(message, offset)?;
    Ok((name.presentation().to_string(), used))
}

/// Decode a DNS name into a byte-preserving [`DnsName`].
///
/// Behaves like [`decode_dns_name`] but keeps the exact wire-label bytes, so
/// labels that are not valid UTF-8 round trip without loss. Compression
/// pointers are followed; cycles, reserved markers, out-of-range pointers,
/// truncated pointers, label-length overrun, and full-name length overrun all
/// return structured [`CrafterError`] values rather than panicking.
pub fn decode_dns_name_typed(message: &[u8], offset: usize) -> Result<(DnsName, usize)> {
    if offset >= message.len() {
        return Err(CrafterError::buffer_too_short(
            "dns.name",
            offset + 1,
            message.len(),
        ));
    }

    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut wire_len = 1usize;
    let mut cursor = offset;
    let mut consumed = None;
    let mut visited = Vec::new();

    loop {
        if cursor >= message.len() {
            return Err(CrafterError::buffer_too_short(
                "dns.name",
                cursor + 1,
                message.len(),
            ));
        }
        if visited.contains(&cursor) {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "compressed name pointer cycle",
            ));
        }
        visited.push(cursor);

        let length = message[cursor];
        match length & DNS_NAME_POINTER_MASK {
            0x00 => {
                if length == 0 {
                    let used = match consumed {
                        Some(consumed) => consumed,
                        None => cursor
                            .checked_add(1)
                            .and_then(|end| end.checked_sub(offset))
                            .ok_or_else(|| {
                                CrafterError::invalid_field_value(
                                    "dns.name",
                                    "name cursor moved before original offset",
                                )
                            })?,
                    };
                    let presentation = labels_to_presentation(&labels);
                    return Ok((
                        DnsName {
                            labels,
                            presentation,
                        },
                        used,
                    ));
                }

                let label_len = length as usize;
                if label_len > DNS_MAX_LABEL_LEN {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name",
                        "label exceeds 63 bytes",
                    ));
                }
                let label_start = cursor + 1;
                let label_end = label_start + label_len;
                if label_end > message.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dns.name.label",
                        label_end,
                        message.len(),
                    ));
                }
                wire_len += 1 + label_len;
                if wire_len > DNS_MAX_NAME_WIRE_LEN {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name",
                        "decoded name exceeds 255 bytes",
                    ));
                }
                labels.push(message[label_start..label_end].to_vec());
                cursor = label_end;
            }
            DNS_NAME_POINTER_TAG => {
                if cursor + 1 >= message.len() {
                    return Err(CrafterError::buffer_too_short(
                        "dns.name.pointer",
                        cursor + 2,
                        message.len(),
                    ));
                }
                let pointer = (((length & 0x3f) as usize) << 8) | (message[cursor + 1] as usize);
                if pointer >= message.len() {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name.pointer",
                        "pointer offset is outside the DNS message",
                    ));
                }
                if consumed.is_none() {
                    consumed = Some(cursor + 2 - offset);
                }
                cursor = pointer;
            }
            _ => {
                return Err(CrafterError::invalid_field_value(
                    "dns.name",
                    "reserved label length marker",
                ))
            }
        }
    }
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

/// Validate decoded or constructed labels against the RFC 1035 length bounds:
/// each label is at most 63 octets (Section 2.3.4) and the encoded name is at
/// most 255 octets including the per-label length bytes and the root
/// terminator.
fn validate_labels(labels: &[Vec<u8>]) -> Result<()> {
    let mut wire_len = 1usize;
    for label in labels {
        if label.is_empty() {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "empty label inside DNS name",
            ));
        }
        if label.len() > DNS_MAX_LABEL_LEN {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "label exceeds 63 bytes",
            ));
        }
        wire_len += 1 + label.len();
        if wire_len > DNS_MAX_NAME_WIRE_LEN {
            return Err(CrafterError::invalid_field_value(
                "dns.name",
                "encoded name exceeds 255 bytes",
            ));
        }
    }
    Ok(())
}

/// True when a label is valid UTF-8 and contains only bytes that render
/// verbatim in presentation form (printable ASCII other than `.` and `\`).
fn label_is_text(label: &[u8]) -> bool {
    str::from_utf8(label).is_ok() && label.iter().all(|&byte| byte_renders_verbatim(byte))
}

/// True when a byte is printable ASCII and is neither `.` nor `\`, so it needs
/// no RFC 1035 Section 5.1 escaping.
fn byte_renders_verbatim(byte: u8) -> bool {
    byte > 0x20 && byte < 0x7f && byte != b'.' && byte != b'\\'
}

/// Render wire labels into a canonical trailing-dot presentation string using
/// the RFC 1035 Section 5.1 escaping convention (`\DDD` for octets that do not
/// render verbatim, including `.` and `\` inside a label). The root name is
/// `"."`.
fn labels_to_presentation(labels: &[Vec<u8>]) -> String {
    if labels.is_empty() {
        return ".".to_string();
    }
    let mut out = String::new();
    for label in labels {
        for &byte in label {
            if byte_renders_verbatim(byte) {
                out.push(byte as char);
            } else {
                out.push('\\');
                out.push_str(&format!("{byte:03}"));
            }
        }
        out.push('.');
    }
    out
}

/// Parse a presentation-form name into wire labels, honoring the RFC 1035
/// Section 5.1 `\DDD` (decimal octet) and `\X` (literal character) escapes. An
/// empty input or `"."` is the root name. A trailing dot is canonical and
/// stripped before splitting; a bare relative name is accepted as fully
/// qualified.
fn presentation_to_labels(name: &str) -> Result<Vec<Vec<u8>>> {
    if name.is_empty() || name == "." {
        return Ok(Vec::new());
    }

    let bytes = name.as_bytes();
    let mut labels: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut index = 0;
    let mut saw_label = false;

    while index < bytes.len() {
        let byte = bytes[index];
        match byte {
            b'.' => {
                if current.is_empty() {
                    return Err(CrafterError::invalid_field_value(
                        "dns.name",
                        "empty label inside DNS name",
                    ));
                }
                labels.push(core::mem::take(&mut current));
                saw_label = true;
                index += 1;
            }
            b'\\' => {
                let next = *bytes.get(index + 1).ok_or_else(|| {
                    CrafterError::invalid_field_value(
                        "dns.name",
                        "trailing backslash escape in DNS name",
                    )
                })?;
                if next.is_ascii_digit() {
                    if index + 3 >= bytes.len() {
                        return Err(CrafterError::invalid_field_value(
                            "dns.name",
                            "incomplete \\DDD escape in DNS name",
                        ));
                    }
                    let digits = &bytes[index + 1..index + 4];
                    if !digits.iter().all(u8::is_ascii_digit) {
                        return Err(CrafterError::invalid_field_value(
                            "dns.name",
                            "malformed \\DDD escape in DNS name",
                        ));
                    }
                    let value = (digits[0] - b'0') as u16 * 100
                        + (digits[1] - b'0') as u16 * 10
                        + (digits[2] - b'0') as u16;
                    let octet = u8::try_from(value).map_err(|_| {
                        CrafterError::invalid_field_value(
                            "dns.name",
                            "\\DDD escape exceeds 255 in DNS name",
                        )
                    })?;
                    current.push(octet);
                    index += 4;
                } else {
                    current.push(next);
                    index += 2;
                }
            }
            other => {
                current.push(other);
                index += 1;
            }
        }
    }

    if !current.is_empty() {
        labels.push(current);
    } else if !saw_label {
        // Input was non-empty but produced no labels (e.g. only a stray dot).
        return Err(CrafterError::invalid_field_value(
            "dns.name",
            "DNS name has no labels",
        ));
    }

    Ok(labels)
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

/// Pack the EDNS(0) OPT TTL field from its EXTENDED-RCODE, VERSION, DO flag,
/// and Z bits (RFC 6891 Section 6.1.3). `z` carries the reserved Z bits
/// alongside the DO bit in the lower 16-bit half; the DO bit is set or cleared
/// from `dnssec_ok` so callers do not have to encode it into `z` themselves.
fn encode_edns_ttl(extended_rcode: u8, version: u8, dnssec_ok: bool, z: u16) -> u32 {
    let mut flags = z & !DNS_EDNS_FLAG_DO;
    if dnssec_ok {
        flags |= DNS_EDNS_FLAG_DO;
    }
    ((extended_rcode as u32) << DNS_EDNS_EXTENDED_RCODE_SHIFT)
        | ((version as u32) << DNS_EDNS_VERSION_SHIFT)
        | (flags as u32)
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
mod dns_edns {
    use super::{
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
        assert_eq!(opt.edns_flags(), super::DNS_EDNS_FLAG_DO);
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

#[cfg(test)]
mod dns_dnssec {
    use super::{
        decode_record_data, Dns, DnsName, DnsRecord, DnsRecordData, DnsTypeBitmaps, DNS_CLASS_IN,
        DNS_TYPE_A, DNS_TYPE_DS, DNS_TYPE_MX, DNS_TYPE_NSEC, DNS_TYPE_NSEC3, DNS_TYPE_NSEC3PARAM,
        DNS_TYPE_RRSIG,
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
        super::DnsRecord::encode(&record, &mut wire).unwrap();
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
        super::DnsTypeBitmaps::encode(&a, &mut encoded_a);
        super::DnsTypeBitmaps::encode(&b, &mut encoded_b);
        assert_eq!(encoded_a, encoded_b);
    }

    #[test]
    fn dnssec_type_bitmaps_multiple_windows_round_trip() {
        // Types spanning several window blocks must encode in increasing window
        // order and decode back to the same set.
        let original = DnsTypeBitmaps::from_types([1u16, 300, 600, 0xff01]);
        let mut encoded = Vec::new();
        super::DnsTypeBitmaps::encode(&original, &mut encoded);
        let decoded = super::DnsTypeBitmaps::decode("test", &encoded).unwrap();
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
        assert!(super::DnsTypeBitmaps::decode("test", &rdata).is_err());
    }

    #[test]
    fn dnssec_type_bitmap_truncated_bitmap_is_rejected() {
        // Bitmap Length declares more bytes than are present.
        let rdata = [0u8, 4, 0x40]; // window 0, length 4, only one bitmap byte
        assert!(super::DnsTypeBitmaps::decode("test", &rdata).is_err());
    }

    #[test]
    fn dnssec_type_bitmap_out_of_order_window_is_rejected() {
        // Windows must be strictly increasing; a repeated/decreasing window is
        // malformed.
        let rdata = [1u8, 1, 0x40, 0u8, 1, 0x40]; // window 1 then window 0
        assert!(super::DnsTypeBitmaps::decode("test", &rdata).is_err());
    }

    #[test]
    fn dnssec_type_bitmap_trailing_zero_octet_is_rejected() {
        // A minimal encoding never carries a trailing all-zero octet.
        let rdata = [0u8, 2, 0x40, 0x00]; // window 0, length 2, trailing zero
        assert!(super::DnsTypeBitmaps::decode("test", &rdata).is_err());
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
}

#[cfg(test)]
mod dns_name_decode {
    use super::{decode_dns_name, decode_dns_name_typed, DnsName, DNS_MAX_LABEL_LEN};

    #[test]
    fn rejects_truncated_names_and_pointers() {
        assert!(decode_dns_name(&[3, b'w'], 0).is_err());
        assert!(decode_dns_name(&[0xc0], 0).is_err());
        assert!(decode_dns_name(&[0xc0, 0x10], 0).is_err());
    }

    #[test]
    fn rejects_pointer_cycles_and_reserved_markers() {
        assert!(decode_dns_name(&[0xc0, 0x00], 0).is_err());
        assert!(decode_dns_name(&[0x40], 0).is_err());
    }

    #[test]
    fn decodes_root_name() {
        assert_eq!(decode_dns_name(&[0], 0).unwrap(), (".".to_string(), 1));
    }

    #[test]
    fn non_text_label_decodes_and_preserves_wire_bytes() {
        // A two-byte label that is not valid UTF-8 (0xff is never a UTF-8 lead
        // byte) must decode into the byte-preserving DnsName instead of failing
        // the way a UTF-8-only decoder would.
        let message = [2u8, 0x00, 0xff, 0];
        let (name, used) = decode_dns_name_typed(&message, 0).unwrap();

        assert_eq!(used, 4);
        assert_eq!(name.labels(), &[vec![0x00, 0xff]]);
        assert!(!name.is_text());
        // RFC 1035 Section 5.1 \DDD escaping renders the exact octet values.
        assert_eq!(name.presentation(), "\\000\\255.");
    }

    #[test]
    fn non_text_presentation_round_trips_through_parse() {
        // Decoding a non-text name to its presentation string and parsing that
        // string back must recover the identical wire labels.
        let message = [3u8, 0x80, b'a', 0x2e, 0];
        let (decoded, _) = decode_dns_name_typed(&message, 0).unwrap();
        let reparsed = DnsName::parse(decoded.presentation()).unwrap();

        assert_eq!(reparsed.labels(), decoded.labels());
        assert_eq!(reparsed.presentation(), decoded.presentation());
    }

    #[test]
    fn non_text_name_decode_and_encode_preserves_original_label_bytes() {
        // The exact wire-label bytes survive a decode then re-encode cycle.
        let original = [4u8, 0x00, 0x01, 0xfe, 0xff, 0];
        let (name, _) = decode_dns_name_typed(&original, 0).unwrap();

        let mut encoded = Vec::new();
        name.encode(&mut encoded).unwrap();
        assert_eq!(encoded, original);
    }

    #[test]
    fn label_at_63_octet_boundary_round_trips() {
        let label = vec![b'a'; DNS_MAX_LABEL_LEN];
        let mut wire = Vec::new();
        wire.push(DNS_MAX_LABEL_LEN as u8);
        wire.extend_from_slice(&label);
        wire.push(0);

        let (name, used) = decode_dns_name_typed(&wire, 0).unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(name.labels(), &[label]);

        let mut encoded = Vec::new();
        name.encode(&mut encoded).unwrap();
        assert_eq!(encoded, wire);
    }

    #[test]
    fn full_name_length_overrun_is_rejected() {
        // Four 63-octet labels encode to 4 * 64 + 1 = 257 wire octets, past the
        // 255-octet full-name limit, and must error rather than panic.
        let label = vec![b'a'; DNS_MAX_LABEL_LEN];
        let mut wire = Vec::new();
        for _ in 0..4 {
            wire.push(DNS_MAX_LABEL_LEN as u8);
            wire.extend_from_slice(&label);
        }
        wire.push(0);

        assert!(decode_dns_name_typed(&wire, 0).is_err());
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
