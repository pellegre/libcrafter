//! DNS wire-level constants and codepoints.

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

/// SVCB/HTTPS SvcParamKey "mandatory" (RFC 9460 Section 8), IANA DNS SVCB
/// Service Parameter Keys (SvcParamKeys).
pub const DNS_SVCB_KEY_MANDATORY: u16 = 0;
/// SVCB/HTTPS SvcParamKey "alpn" (RFC 9460 Section 7.1), IANA DNS SVCB
/// SvcParamKeys.
pub const DNS_SVCB_KEY_ALPN: u16 = 1;
/// SVCB/HTTPS SvcParamKey "no-default-alpn" (RFC 9460 Section 7.1), IANA DNS
/// SVCB SvcParamKeys.
pub const DNS_SVCB_KEY_NO_DEFAULT_ALPN: u16 = 2;
/// SVCB/HTTPS SvcParamKey "port" (RFC 9460 Section 7.2), IANA DNS SVCB
/// SvcParamKeys.
pub const DNS_SVCB_KEY_PORT: u16 = 3;
/// SVCB/HTTPS SvcParamKey "ipv4hint" (RFC 9460 Section 7.3), IANA DNS SVCB
/// SvcParamKeys.
pub const DNS_SVCB_KEY_IPV4HINT: u16 = 4;
/// SVCB/HTTPS SvcParamKey "ech" (TLS Encrypted ClientHello Config), IANA DNS
/// SVCB SvcParamKeys.
pub const DNS_SVCB_KEY_ECH: u16 = 5;
/// SVCB/HTTPS SvcParamKey "ipv6hint" (RFC 9460 Section 7.3), IANA DNS SVCB
/// SvcParamKeys.
pub const DNS_SVCB_KEY_IPV6HINT: u16 = 6;
/// SVCB/HTTPS SvcParamKey "dohpath" (RFC 9461), IANA DNS SVCB SvcParamKeys.
pub const DNS_SVCB_KEY_DOHPATH: u16 = 7;

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
