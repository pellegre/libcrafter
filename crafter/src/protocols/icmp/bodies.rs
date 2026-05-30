//! Typed ICMPv4 body layers that follow the fixed eight-byte header.
//!
//! Extracted verbatim from the original `icmp.rs`; nothing here changes wire
//! behavior, defaults, or the public API surface. Shared compile/auto-fill
//! helpers and codepoints are reached through `use super::*;` and
//! `use super::constants::*;`.
use super::constants::*;
use super::*;

/// Quoted original IPv4 datagram carried by an ICMPv4 error message.
///
/// RFC 792 error messages (destination unreachable, source quench, redirect,
/// time exceeded, parameter problem) append the IPv4 header plus at least the
/// first 64 bits of the offending datagram so the originator can match the
/// error to the packet it sent. This layer holds that quoted datagram as a
/// nested [`Packet`] of typed layers, keeping the packet abstraction intact:
/// the quoted IPv4 header, transport header, and payload are inspectable just
/// like any other layer stack.
///
/// On decode the quote is parsed leniently: a valid IPv4 prefix is typed,
/// unknown quoted next protocols and truncated quotes remain raw-compatible,
/// and a non-IPv4 quote leaves the bytes as a plain `Raw` payload instead of
/// producing this layer.
#[derive(Debug, Clone)]
pub struct IcmpQuotedIpv4 {
    datagram: Packet,
}

impl IcmpQuotedIpv4 {
    /// Wrap a quoted original datagram built from typed packet layers.
    pub fn new(datagram: impl IntoPacket) -> Self {
        Self {
            datagram: datagram.into_packet(),
        }
    }

    /// Borrow the quoted datagram as a typed packet stack.
    pub fn datagram(&self) -> &Packet {
        &self.datagram
    }

    /// Mutably borrow the quoted datagram.
    pub fn datagram_mut(&mut self) -> &mut Packet {
        &mut self.datagram
    }

    /// First quoted layer of type `T`, when the quote was typed on decode.
    pub fn quoted_layer<T>(&self) -> Option<&T>
    where
        T: Layer,
    {
        self.datagram.layer::<T>()
    }
}

impl PartialEq for IcmpQuotedIpv4 {
    fn eq(&self, other: &Self) -> bool {
        // Layers are not directly comparable through trait objects, so compare
        // the compiled byte image. Quoted datagrams decode every field as
        // user-set, so this is a faithful structural comparison.
        match (self.datagram.compile(), other.datagram.compile()) {
            (Ok(left), Ok(right)) => left.as_bytes() == right.as_bytes(),
            _ => false,
        }
    }
}

impl Layer for IcmpQuotedIpv4 {
    fn name(&self) -> &'static str {
        "IcmpQuotedIpv4"
    }

    fn summary(&self) -> String {
        format!("IcmpQuotedIpv4({})", self.datagram.summary())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("quoted_len", self.datagram.encoded_len().to_string()),
            ("quoted", self.datagram.summary()),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.datagram.encoded_len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.datagram.compile_into(out)
    }

    impl_layer_object!(IcmpQuotedIpv4);
}

impl_layer_div!(IcmpQuotedIpv4);

/// RFC 792 timestamp message body.
///
/// Timestamp request (type 13) and timestamp reply (type 14) append three
/// 32-bit timestamps after the fixed ICMP header: the originate timestamp set
/// by the requester, the receive timestamp set when the responder received the
/// request, and the transmit timestamp set when the responder sent the reply.
/// RFC 792 defines each as milliseconds since midnight UT; a sender that cannot
/// supply a standard value may set the high-order bit, so the raw 32-bit values
/// are exposed verbatim rather than reinterpreted.
///
/// This layer always encodes exactly 12 bytes. Malformed timestamp lengths
/// (a short or oversized trailing region) are not forced into this layer on
/// decode; they remain a [`Raw`] payload so the bytes are never lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpTimestamp {
    originate: Field<u32>,
    receive: Field<u32>,
    transmit: Field<u32>,
}

impl IcmpTimestamp {
    /// Create a timestamp body with all three timestamps defaulted to zero.
    pub fn new() -> Self {
        Self {
            originate: Field::defaulted(0),
            receive: Field::defaulted(0),
            transmit: Field::defaulted(0),
        }
    }

    /// Set the originate timestamp.
    pub fn originate(mut self, originate: u32) -> Self {
        self.originate.set_user(originate);
        self
    }

    /// Set the receive timestamp.
    pub fn receive(mut self, receive: u32) -> Self {
        self.receive.set_user(receive);
        self
    }

    /// Set the transmit timestamp.
    pub fn transmit(mut self, transmit: u32) -> Self {
        self.transmit.set_user(transmit);
        self
    }

    /// Originate timestamp value.
    pub fn originate_value(&self) -> u32 {
        value_or_copy(&self.originate, 0)
    }

    /// Receive timestamp value.
    pub fn receive_value(&self) -> u32 {
        value_or_copy(&self.receive, 0)
    }

    /// Transmit timestamp value.
    pub fn transmit_value(&self) -> u32 {
        value_or_copy(&self.transmit, 0)
    }
}

impl Default for IcmpTimestamp {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpTimestamp {
    fn name(&self) -> &'static str {
        "IcmpTimestamp"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpTimestamp(originate={}, receive={}, transmit={})",
            self.originate_value(),
            self.receive_value(),
            self.transmit_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("originate", self.originate_value().to_string()),
            ("receive", self.receive_value().to_string()),
            ("transmit", self.transmit_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_TIMESTAMP_BODY_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.originate_value().to_be_bytes());
        out.extend_from_slice(&self.receive_value().to_be_bytes());
        out.extend_from_slice(&self.transmit_value().to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IcmpTimestamp);
}

impl_layer_div!(IcmpTimestamp);

/// RFC 950 address mask message body.
///
/// Address mask request (type 17) and address mask reply (type 18) append a
/// single 32-bit address mask after the fixed ICMP header. RFC 950 has the
/// requesting host set the mask to zero and the responding gateway return the
/// 32-bit subnet/network mask. The identifier and sequence number live in the
/// fixed header's rest-of-header, like an echo.
///
/// Both messages are deprecated by RFC 6918 but remain constructible and
/// decodable. The mask is modeled as an [`Ipv4Addr`] for convenience while the
/// raw four bytes stay inspectable through [`IcmpAddressMask::mask_octets`].
///
/// This layer always encodes exactly four bytes. A trailing region that is not
/// exactly four bytes is not forced into this layer on decode; it stays a
/// [`Raw`] payload so the bytes are never lost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpAddressMask {
    mask: Field<Ipv4Addr>,
}

impl IcmpAddressMask {
    /// Create an address mask body defaulting to the all-zero mask RFC 950
    /// specifies for a request.
    pub fn new() -> Self {
        Self {
            mask: Field::defaulted(Ipv4Addr::UNSPECIFIED),
        }
    }

    /// Set the 32-bit address mask.
    pub fn mask(mut self, mask: Ipv4Addr) -> Self {
        self.mask.set_user(mask);
        self
    }

    /// Set the address mask from dotted-quad text.
    pub fn mask_str(self, mask: &str) -> Result<Self> {
        Ok(self.mask(parse_ipv4(mask)?))
    }

    /// Set the address mask from a raw 32-bit value.
    pub fn mask_bits(self, mask: u32) -> Self {
        self.mask(Ipv4Addr::from(mask))
    }

    /// Address mask value as an [`Ipv4Addr`].
    pub fn mask_value(&self) -> Ipv4Addr {
        value_or_copy(&self.mask, Ipv4Addr::UNSPECIFIED)
    }

    /// Address mask as its raw four bytes.
    pub fn mask_octets(&self) -> [u8; 4] {
        self.mask_value().octets()
    }
}

impl Default for IcmpAddressMask {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpAddressMask {
    fn name(&self) -> &'static str {
        "IcmpAddressMask"
    }

    fn summary(&self) -> String {
        format!("IcmpAddressMask(mask={})", self.mask_value())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("mask", self.mask_value().to_string()),
            ("mask_bytes", hex_bytes(&self.mask_octets())),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_ADDRESS_MASK_BODY_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.mask_octets());
        Ok(())
    }

    impl_layer_object!(IcmpAddressMask);
}

impl_layer_div!(IcmpAddressMask);

/// RFC 1256 router advertisement entry.
///
/// A router advertisement (type 9) lists one entry per advertised router after
/// the fixed ICMP header. The standard entry format (Addr Entry Size of two
/// 32-bit words) is a 4-byte router address followed by a 4-byte signed
/// preference level: higher preference levels are preferred, and the reserved
/// value 0x8000_0000 means the address must not be used as a default router.
///
/// This layer always encodes exactly eight bytes. The router address is modeled
/// as an [`Ipv4Addr`] for convenience while the raw four address bytes stay
/// inspectable through [`IcmpRouterAdvertisementEntry::router_address_octets`].
/// The preference level is exposed as a raw `i32` so the full signed range,
/// including the reserved "do not use" value, survives untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpRouterAdvertisementEntry {
    router_address: Field<Ipv4Addr>,
    preference_level: Field<i32>,
}

impl IcmpRouterAdvertisementEntry {
    /// Create a router advertisement entry defaulting to the unspecified
    /// address and a zero preference level.
    pub fn new() -> Self {
        Self {
            router_address: Field::defaulted(Ipv4Addr::UNSPECIFIED),
            preference_level: Field::defaulted(0),
        }
    }

    /// Set the advertised router address.
    pub fn router_address(mut self, router_address: Ipv4Addr) -> Self {
        self.router_address.set_user(router_address);
        self
    }

    /// Set the advertised router address from dotted-quad text.
    pub fn router_address_str(self, router_address: &str) -> Result<Self> {
        Ok(self.router_address(parse_ipv4(router_address)?))
    }

    /// Set the signed preference level.
    pub fn preference_level(mut self, preference_level: i32) -> Self {
        self.preference_level.set_user(preference_level);
        self
    }

    /// Router address value as an [`Ipv4Addr`].
    pub fn router_address_value(&self) -> Ipv4Addr {
        value_or_copy(&self.router_address, Ipv4Addr::UNSPECIFIED)
    }

    /// Router address as its raw four bytes.
    pub fn router_address_octets(&self) -> [u8; 4] {
        self.router_address_value().octets()
    }

    /// Signed preference level value.
    pub fn preference_level_value(&self) -> i32 {
        value_or_copy(&self.preference_level, 0)
    }
}

impl Default for IcmpRouterAdvertisementEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpRouterAdvertisementEntry {
    fn name(&self) -> &'static str {
        "IcmpRouterAdvertisementEntry"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpRouterAdvertisementEntry(router={}, preference={})",
            self.router_address_value(),
            self.preference_level_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("router_address", self.router_address_value().to_string()),
            (
                "router_address_bytes",
                hex_bytes(&self.router_address_octets()),
            ),
            (
                "preference_level",
                self.preference_level_value().to_string(),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_ROUTER_ADVERTISEMENT_ENTRY_LEN
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.router_address_octets());
        out.extend_from_slice(&self.preference_level_value().to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IcmpRouterAdvertisementEntry);
}

impl_layer_div!(IcmpRouterAdvertisementEntry);

#[cfg(test)]
mod icmpv4_rfc792_queries {
    use super::{
        icmpv4_type_is_deprecated, icmpv4_type_summary, Icmp, IcmpTimestamp,
        ICMP_INFORMATION_REPLY, ICMP_INFORMATION_REQUEST, ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY,
    };
    use crate::checksum::internet_checksum;
    use crate::packet::Layer;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // A timestamp request compiles its fixed header (with identifier and
    // sequence) plus the three 32-bit timestamps, and the typed body survives a
    // full decode round-trip with its values intact.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_compile_decode_roundtrip() {
        for icmp_type in [ICMP_TIMESTAMP, ICMP_TIMESTAMP_REPLY] {
            let packet = Ipv4::new().src(src()).dst(dst())
                / Icmp::new().icmp_type(icmp_type).id(0x1234).seq(7)
                / IcmpTimestamp::new()
                    .originate(0x0a0b_0c0d)
                    .receive(0x11223344)
                    .transmit(0x55667788);
            let compiled = packet.compile().unwrap();

            // ICMP header begins at byte 20 (20-byte IPv4 header, no options).
            assert_eq!(compiled.as_bytes()[20], icmp_type);
            assert_eq!(compiled.as_bytes()[21], 0); // code
                                                    // Identifier (bytes 24..26) and sequence (bytes 26..28).
            assert_eq!(&compiled.as_bytes()[24..26], &0x1234u16.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[26..28], &7u16.to_be_bytes());
            // Timestamp body (bytes 28..40): originate, receive, transmit.
            assert_eq!(&compiled.as_bytes()[28..32], &0x0a0b_0c0du32.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[32..36], &0x11223344u32.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[36..40], &0x55667788u32.to_be_bytes());

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            let icmp = decoded.layer::<Icmp>().unwrap();
            assert_eq!(icmp.icmp_type_value(), icmp_type);
            // Identifier and sequence are inspectable for the timestamp family.
            assert_eq!(icmp.identifier_value(), Some(0x1234));
            assert_eq!(icmp.sequence_number_value(), Some(7));
            // Timestamp is not an echo, so it maps to no common ping kind.
            assert_eq!(icmp.kind_value(), None);

            let ts = decoded.layer::<IcmpTimestamp>().unwrap();
            assert_eq!(ts.originate_value(), 0x0a0b_0c0d);
            assert_eq!(ts.receive_value(), 0x11223344);
            assert_eq!(ts.transmit_value(), 0x55667788);
            // No leftover raw bytes when the body length is exactly 12.
            assert!(decoded.layer::<Raw>().is_none());
            assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
        }
    }

    // The timestamp constructors set the right types and default the body to
    // zero timestamps.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_constructors_set_types() {
        assert_eq!(Icmp::timestamp_request().icmp_type_value(), ICMP_TIMESTAMP);
        assert_eq!(
            Icmp::timestamp_reply().icmp_type_value(),
            ICMP_TIMESTAMP_REPLY
        );
        let ts = IcmpTimestamp::new();
        assert_eq!(ts.originate_value(), 0);
        assert_eq!(ts.receive_value(), 0);
        assert_eq!(ts.transmit_value(), 0);
    }

    // The ICMP checksum is auto-filled over the header plus the timestamp body
    // when the caller leaves it unset.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_checksum_autofill() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_request().id(0x4242).seq(3)
            / IcmpTimestamp::new().originate(1).receive(2).transmit(3);
        let compiled = packet.compile().unwrap();

        // Recompute the expected checksum over the full ICMP message (header +
        // 12-byte timestamp body) with the checksum field zeroed.
        let icmp_message = &compiled.as_bytes()[20..];
        let mut zeroed = icmp_message.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        let expected = internet_checksum(&zeroed);
        assert_ne!(expected, 0);
        assert_eq!(
            &compiled.as_bytes()[22..24],
            &expected.to_be_bytes(),
            "auto-filled checksum must cover the timestamp body"
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().checksum_value(),
            Some(expected)
        );
    }

    // An explicit (deliberately wrong) checksum on a timestamp message is
    // emitted verbatim instead of being recomputed over the body.
    #[test]
    fn icmpv4_rfc792_queries_timestamp_explicit_checksum_override() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_request().id(1).seq(1).checksum(0xbeef)
            / IcmpTimestamp::new().originate(9).receive(9).transmit(9);
        let compiled = packet.compile().unwrap();

        assert_eq!(&compiled.as_bytes()[22..24], &0xbeefu16.to_be_bytes());
    }

    // Information request and reply are constructible (RFC 792) and carry only
    // the identifier and sequence number with no body beyond the fixed header.
    #[test]
    fn icmpv4_rfc792_queries_information_request_reply_construction() {
        for icmp_type in [ICMP_INFORMATION_REQUEST, ICMP_INFORMATION_REPLY] {
            let packet = Ipv4::new().src(src()).dst(dst())
                / Icmp::new().icmp_type(icmp_type).id(0x0a0b).seq(0x0c0d);
            let compiled = packet.compile().unwrap();

            assert_eq!(compiled.as_bytes()[20], icmp_type);
            assert_eq!(compiled.as_bytes()[21], 0);
            assert_eq!(&compiled.as_bytes()[24..26], &0x0a0bu16.to_be_bytes());
            assert_eq!(&compiled.as_bytes()[26..28], &0x0c0du16.to_be_bytes());
            // No body bytes follow the fixed 8-byte ICMP header.
            assert_eq!(compiled.as_bytes().len(), 20 + 8);

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            let icmp = decoded.layer::<Icmp>().unwrap();
            assert_eq!(icmp.icmp_type_value(), icmp_type);
            assert_eq!(icmp.identifier_value(), Some(0x0a0b));
            assert_eq!(icmp.sequence_number_value(), Some(0x0c0d));
            // Information messages are not echoes, so they carry no ping kind.
            assert_eq!(icmp.kind_value(), None);
            assert!(decoded.layer::<Raw>().is_none());
            assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
        }

        // The dedicated constructors set the same types.
        assert_eq!(
            Icmp::information_request().icmp_type_value(),
            ICMP_INFORMATION_REQUEST
        );
        assert_eq!(
            Icmp::information_reply().icmp_type_value(),
            ICMP_INFORMATION_REPLY
        );
    }

    // Information messages are deprecated by RFC 6918 but keep their registry
    // identity in summaries and are flagged as deprecated. Naming them never
    // doubles as refusing them (construction above succeeds).
    #[test]
    fn icmpv4_rfc792_queries_deprecated_information_summaries() {
        assert_eq!(
            icmpv4_type_summary(ICMP_INFORMATION_REQUEST),
            "information-request(15)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_INFORMATION_REPLY),
            "information-reply(16)"
        );
        assert!(icmpv4_type_is_deprecated(ICMP_INFORMATION_REQUEST));
        assert!(icmpv4_type_is_deprecated(ICMP_INFORMATION_REPLY));

        // Timestamp messages are active (not deprecated) and keep their names.
        assert_eq!(icmpv4_type_summary(ICMP_TIMESTAMP), "timestamp(13)");
        assert_eq!(
            icmpv4_type_summary(ICMP_TIMESTAMP_REPLY),
            "timestamp-reply(14)"
        );
        assert!(!icmpv4_type_is_deprecated(ICMP_TIMESTAMP));

        // The body summary exposes the three typed timestamps.
        let summary = IcmpTimestamp::new()
            .originate(1)
            .receive(2)
            .transmit(3)
            .summary();
        assert_eq!(summary, "IcmpTimestamp(originate=1, receive=2, transmit=3)");
    }

    // A timestamp message whose trailing region is the wrong length (not exactly
    // 12 bytes) is malformed: the typed body parser declines it, the bytes
    // remain a Raw payload, decoding does not panic, and the message still
    // round-trips byte-for-byte.
    #[test]
    fn icmpv4_rfc792_queries_malformed_timestamp_stays_raw() {
        // Short body: only 8 of the 12 timestamp bytes are present.
        let short = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_request().id(1).seq(1)
            / Raw::from_bytes([0xaa; 8]);
        let compiled = short.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpTimestamp>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0xaa; 8]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());

        // Oversized body: 12 timestamp bytes plus trailing unknown data.
        let mut body = vec![0u8; 12];
        body.extend_from_slice(b"trailing");
        let long = Ipv4::new().src(src()).dst(dst())
            / Icmp::timestamp_reply().id(2).seq(2)
            / Raw::from_bytes(&body);
        let compiled = long.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpTimestamp>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &body[..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // True buffer truncation (fewer than 8 bytes of ICMP header) returns a
    // structured buffer error rather than panicking.
    #[test]
    fn icmpv4_rfc792_queries_truncated_header_is_structured_error() {
        let short = (Ipv4::new().proto(crate::IpProtocol::Icmp)
            / Raw::from_bytes([ICMP_TIMESTAMP; 5]))
        .compile()
        .unwrap();
        assert!(Packet::decode_from_l3(NetworkLayer::Ipv4, short.as_bytes()).is_err());
    }
}


#[cfg(test)]
mod icmpv4_address_mask {
    use super::{
        icmpv4_type_is_deprecated, icmpv4_type_summary, Icmp, IcmpAddressMask,
        ICMP_ADDRESS_MASK_REPLY, ICMP_ADDRESS_MASK_REQUEST,
    };
    use crate::checksum::internet_checksum;
    use crate::packet::Layer;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // An address mask request (RFC 950) compiles its fixed header (with
    // identifier and sequence) plus the 32-bit mask, with the mask defaulting to
    // all zeros per RFC 950, and round-trips through decode with its fields
    // intact.
    #[test]
    fn icmpv4_address_mask_request_compile_decode_roundtrip() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_request().id(0x1234).seq(7)
            / IcmpAddressMask::new();
        let compiled = packet.compile().unwrap();

        // ICMP header begins at byte 20 (20-byte IPv4 header, no options).
        assert_eq!(compiled.as_bytes()[20], ICMP_ADDRESS_MASK_REQUEST);
        assert_eq!(compiled.as_bytes()[21], 0); // code
                                                // Identifier (bytes 24..26) and sequence (bytes 26..28).
        assert_eq!(&compiled.as_bytes()[24..26], &0x1234u16.to_be_bytes());
        assert_eq!(&compiled.as_bytes()[26..28], &7u16.to_be_bytes());
        // RFC 950 request: the address mask body (bytes 28..32) is all zeros.
        assert_eq!(&compiled.as_bytes()[28..32], &[0, 0, 0, 0]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), ICMP_ADDRESS_MASK_REQUEST);
        // Identifier and sequence are inspectable for the address mask family.
        assert_eq!(icmp.identifier_value(), Some(0x1234));
        assert_eq!(icmp.sequence_number_value(), Some(7));
        // Address mask is not an echo, so it maps to no common ping kind.
        assert_eq!(icmp.kind_value(), None);

        let mask = decoded.layer::<IcmpAddressMask>().unwrap();
        assert_eq!(mask.mask_value(), Ipv4Addr::UNSPECIFIED);
        // No leftover raw bytes when the body length is exactly 4.
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An address mask reply carries the gateway's subnet/network mask, exposed
    // through both the typed Ipv4Addr accessor and the raw octets, and survives
    // a full decode round-trip.
    #[test]
    fn icmpv4_address_mask_reply_compile_decode_roundtrip_and_accessors() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_reply().id(0xabcd).seq(9)
            / IcmpAddressMask::new().mask(mask);
        let compiled = packet.compile().unwrap();

        assert_eq!(compiled.as_bytes()[20], ICMP_ADDRESS_MASK_REPLY);
        // The 32-bit mask body holds the subnet mask verbatim.
        assert_eq!(&compiled.as_bytes()[28..32], &mask.octets());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let body = decoded.layer::<IcmpAddressMask>().unwrap();
        assert_eq!(body.mask_value(), mask);
        assert_eq!(body.mask_octets(), [255, 255, 255, 0]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());

        // The mask escape hatches agree with the typed accessor.
        assert_eq!(
            IcmpAddressMask::new().mask_bits(0xffff_ff00).mask_value(),
            mask
        );
        assert_eq!(
            IcmpAddressMask::new()
                .mask_str("255.255.255.0")
                .unwrap()
                .mask_value(),
            mask
        );
    }

    // The address mask constructors set the right types and default the body to
    // the all-zero mask.
    #[test]
    fn icmpv4_address_mask_constructors_set_types() {
        assert_eq!(
            Icmp::address_mask_request().icmp_type_value(),
            ICMP_ADDRESS_MASK_REQUEST
        );
        assert_eq!(
            Icmp::address_mask_reply().icmp_type_value(),
            ICMP_ADDRESS_MASK_REPLY
        );
        assert_eq!(IcmpAddressMask::new().mask_value(), Ipv4Addr::UNSPECIFIED);
    }

    // The ICMP checksum is auto-filled over the header plus the address mask
    // body when the caller leaves it unset.
    #[test]
    fn icmpv4_address_mask_checksum_autofill() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_reply().id(0x4242).seq(3)
            / IcmpAddressMask::new().mask(Ipv4Addr::new(255, 255, 0, 0));
        let compiled = packet.compile().unwrap();

        // Recompute the expected checksum over the full ICMP message (header +
        // 4-byte mask body) with the checksum field zeroed.
        let icmp_message = &compiled.as_bytes()[20..];
        let mut zeroed = icmp_message.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        let expected = internet_checksum(&zeroed);
        assert_ne!(expected, 0);
        assert_eq!(
            &compiled.as_bytes()[22..24],
            &expected.to_be_bytes(),
            "auto-filled checksum must cover the address mask body"
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().checksum_value(),
            Some(expected)
        );
    }

    // An explicit (deliberately wrong) checksum on an address mask message is
    // emitted verbatim instead of being recomputed over the body.
    #[test]
    fn icmpv4_address_mask_explicit_checksum_override() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_request().id(1).seq(1).checksum(0xbeef)
            / IcmpAddressMask::new();
        let compiled = packet.compile().unwrap();

        assert_eq!(&compiled.as_bytes()[22..24], &0xbeefu16.to_be_bytes());
    }

    // Both address mask types are deprecated by RFC 6918 but keep their registry
    // identity in summaries and are flagged as deprecated. Naming them never
    // doubles as refusing them (construction above succeeds).
    #[test]
    fn icmpv4_address_mask_deprecated_summaries() {
        assert_eq!(
            icmpv4_type_summary(ICMP_ADDRESS_MASK_REQUEST),
            "address-mask-request(17)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_ADDRESS_MASK_REPLY),
            "address-mask-reply(18)"
        );
        assert!(icmpv4_type_is_deprecated(ICMP_ADDRESS_MASK_REQUEST));
        assert!(icmpv4_type_is_deprecated(ICMP_ADDRESS_MASK_REPLY));

        // The body summary exposes the typed mask.
        assert_eq!(
            IcmpAddressMask::new()
                .mask(Ipv4Addr::new(255, 255, 255, 0))
                .summary(),
            "IcmpAddressMask(mask=255.255.255.0)"
        );
    }

    // An address mask message whose trailing region is the wrong length (not
    // exactly 4 bytes) is malformed: the typed body parser declines it, the
    // bytes remain a Raw payload, decoding does not panic, and the message still
    // round-trips byte-for-byte.
    #[test]
    fn icmpv4_address_mask_malformed_body_stays_raw() {
        // Short body: only 3 of the 4 mask bytes are present.
        let short = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_request().id(1).seq(1)
            / Raw::from_bytes([0xaa; 3]);
        let compiled = short.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpAddressMask>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0xaa; 3]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());

        // Oversized body: 4 mask bytes plus trailing unknown data.
        let mut body = vec![0xffu8; 4];
        body.extend_from_slice(b"trailing");
        let long = Ipv4::new().src(src()).dst(dst())
            / Icmp::address_mask_reply().id(2).seq(2)
            / Raw::from_bytes(&body);
        let compiled = long.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpAddressMask>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &body[..]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }
}


#[cfg(test)]
mod icmpv4_router_discovery {
    use super::{
        icmpv4_type_summary, Icmp, IcmpRouterAdvertisementEntry,
        ICMP_CODE_ROUTER_ADVERTISEMENT_NORMAL, ICMP_ROUTER_ADVERTISEMENT,
        ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS, ICMP_ROUTER_SOLICITATION,
    };
    use crate::checksum::internet_checksum;
    use crate::packet::Layer;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // A router solicitation (RFC 1256, type 10) is the fixed 8-byte header with a
    // 32-bit reserved field that is sent as zero. It carries no body and round-
    // trips through decode with the reserved word intact.
    #[test]
    fn icmpv4_router_discovery_solicitation_compile_decode_roundtrip() {
        let packet = Ipv4::new().src(src()).dst(dst()) / Icmp::router_solicitation();
        let compiled = packet.compile().unwrap();

        // ICMP header begins at byte 20 (20-byte IPv4 header, no options).
        assert_eq!(compiled.as_bytes()[20], ICMP_ROUTER_SOLICITATION);
        assert_eq!(compiled.as_bytes()[21], 0); // code
                                                // The reserved 32-bit field (bytes 24..28) is sent as zero.
        assert_eq!(&compiled.as_bytes()[24..28], &[0, 0, 0, 0]);
        // No body follows the fixed 8-byte ICMP header.
        assert_eq!(compiled.as_bytes().len(), 20 + 8);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type_value(), ICMP_ROUTER_SOLICITATION);
        assert_eq!(icmp.rest_of_header_value(), [0, 0, 0, 0]);
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(
            Icmp::router_solicitation().icmp_type_value(),
            ICMP_ROUTER_SOLICITATION
        );
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A one-entry router advertisement compiles its fixed header (Num Addrs,
    // Addr Entry Size, Lifetime) plus a single router-address/preference entry,
    // and round-trips through decode with the typed entry intact.
    #[test]
    fn icmpv4_router_discovery_advertisement_one_entry_roundtrip() {
        let router = Ipv4Addr::new(192, 0, 2, 1);
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement().lifetime(1800)
            / IcmpRouterAdvertisementEntry::new()
                .router_address(router)
                .preference_level(5);
        let compiled = packet.compile().unwrap();

        assert_eq!(compiled.as_bytes()[20], ICMP_ROUTER_ADVERTISEMENT);
        assert_eq!(compiled.as_bytes()[21], 0); // code
                                                // Rest-of-header: Num Addrs (byte 24), Addr Entry Size (byte 25),
                                                // Lifetime (bytes 26..28).
        assert_eq!(compiled.as_bytes()[24], 1);
        assert_eq!(
            compiled.as_bytes()[25],
            ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS
        );
        assert_eq!(&compiled.as_bytes()[26..28], &1800u16.to_be_bytes());
        // Entry: router address (bytes 28..32) then signed preference (32..36).
        assert_eq!(&compiled.as_bytes()[28..32], &router.octets());
        assert_eq!(&compiled.as_bytes()[32..36], &5i32.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.num_addrs_value(), Some(1));
        assert_eq!(
            icmp.addr_entry_size_value(),
            Some(ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS)
        );
        assert_eq!(icmp.lifetime_value(), Some(1800));

        let entry = decoded.layer::<IcmpRouterAdvertisementEntry>().unwrap();
        assert_eq!(entry.router_address_value(), router);
        assert_eq!(entry.preference_level_value(), 5);
        // No leftover raw bytes when the body length matches Num Addrs entries.
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A multi-entry advertisement preserves every entry in order, including a
    // negative (signed) preference level, and round-trips through decode.
    #[test]
    fn icmpv4_router_discovery_advertisement_multi_entry_roundtrip() {
        let entries = [
            (Ipv4Addr::new(192, 0, 2, 1), 100i32),
            (Ipv4Addr::new(192, 0, 2, 2), -50i32),
            (Ipv4Addr::new(192, 0, 2, 3), 0i32),
        ];
        let mut packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement()
                .code(ICMP_CODE_ROUTER_ADVERTISEMENT_NORMAL)
                .lifetime(600);
        for (router, preference) in entries {
            packet = packet
                / IcmpRouterAdvertisementEntry::new()
                    .router_address(router)
                    .preference_level(preference);
        }
        let compiled = packet.compile().unwrap();

        // Num Addrs is auto-filled to the entry count.
        assert_eq!(compiled.as_bytes()[24], entries.len() as u8);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let decoded_entries: Vec<&IcmpRouterAdvertisementEntry> =
            decoded.layers::<IcmpRouterAdvertisementEntry>().collect();
        assert_eq!(decoded_entries.len(), entries.len());
        for (decoded_entry, (router, preference)) in decoded_entries.iter().zip(entries) {
            assert_eq!(decoded_entry.router_address_value(), router);
            assert_eq!(decoded_entry.preference_level_value(), preference);
        }
        assert!(decoded.layer::<Raw>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Compilation auto-fills Num Addrs from the following entry layers and
    // defaults Addr Entry Size to the standard format when the caller leaves
    // them unset, and the auto-filled ICMP checksum covers the whole message.
    #[test]
    fn icmpv4_router_discovery_advertisement_autofills_counts_and_checksum() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement().lifetime(900)
            / IcmpRouterAdvertisementEntry::new().router_address(Ipv4Addr::new(192, 0, 2, 1))
            / IcmpRouterAdvertisementEntry::new().router_address(Ipv4Addr::new(192, 0, 2, 2));
        let compiled = packet.compile().unwrap();

        // Num Addrs counts the two entries; Addr Entry Size defaults to 2 words.
        assert_eq!(compiled.as_bytes()[24], 2);
        assert_eq!(
            compiled.as_bytes()[25],
            ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS
        );

        // The auto-filled checksum covers the header plus both entries.
        let icmp_message = &compiled.as_bytes()[20..];
        let mut zeroed = icmp_message.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        let expected = internet_checksum(&zeroed);
        assert_ne!(expected, 0);
        assert_eq!(&compiled.as_bytes()[22..24], &expected.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert_eq!(
            decoded.layer::<Icmp>().unwrap().checksum_value(),
            Some(expected)
        );
    }

    // Explicit Num Addrs, Addr Entry Size, Lifetime, and checksum overrides are
    // preserved verbatim even when they are deliberately inconsistent with the
    // following entries. A mismatched Num Addrs / non-standard Addr Entry Size
    // means decode cannot defensibly type the entries, so the body stays Raw and
    // the message still round-trips byte-for-byte.
    #[test]
    fn icmpv4_router_discovery_advertisement_explicit_malformed_overrides() {
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement()
                .num_addrs(7) // deliberately wrong: only one entry follows
                .addr_entry_size(3) // non-standard entry size
                .lifetime(0xbeef)
                .checksum(0xdead)
            / IcmpRouterAdvertisementEntry::new().router_address(Ipv4Addr::new(192, 0, 2, 9));
        let compiled = packet.compile().unwrap();

        // Every pinned field is emitted verbatim.
        assert_eq!(compiled.as_bytes()[24], 7);
        assert_eq!(compiled.as_bytes()[25], 3);
        assert_eq!(&compiled.as_bytes()[26..28], &0xbeefu16.to_be_bytes());
        assert_eq!(&compiled.as_bytes()[22..24], &0xdeadu16.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmp>().unwrap();
        assert_eq!(icmp.num_addrs_value(), Some(7));
        assert_eq!(icmp.addr_entry_size_value(), Some(3));
        assert_eq!(icmp.lifetime_value(), Some(0xbeef));
        // The inconsistent header means the body cannot be typed as entries; the
        // bytes survive as Raw and nothing panics.
        assert!(decoded.layer::<IcmpRouterAdvertisementEntry>().is_none());
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A router advertisement whose body length does not match Num Addrs * entry
    // size is malformed: the entry parser declines it, the bytes remain Raw,
    // decoding does not panic, and the message still round-trips byte-for-byte.
    #[test]
    fn icmpv4_router_discovery_advertisement_length_mismatch_stays_raw() {
        // Standard entry size and Num Addrs of 1, but only 5 trailing bytes.
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmp::router_advertisement()
                .num_addrs(1)
                .addr_entry_size(ICMP_ROUTER_ADVERTISEMENT_ENTRY_WORDS)
            / Raw::from_bytes([0xaa; 5]);
        let compiled = packet.compile().unwrap();
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpRouterAdvertisementEntry>().is_none());
        assert_eq!(decoded.layer::<Raw>().unwrap().as_bytes(), &[0xaa; 5]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Summaries identify the router discovery types and the typed entry fields
    // while keeping numeric values visible.
    #[test]
    fn icmpv4_router_discovery_summary_output() {
        assert_eq!(
            icmpv4_type_summary(ICMP_ROUTER_ADVERTISEMENT),
            "router-advertisement(9)"
        );
        assert_eq!(
            icmpv4_type_summary(ICMP_ROUTER_SOLICITATION),
            "router-solicitation(10)"
        );
        assert_eq!(
            Icmp::router_advertisement().code(0).summary(),
            "Icmp(type=router-advertisement(9), code=normal(0), id=-, seq=-)"
        );
        assert_eq!(
            IcmpRouterAdvertisementEntry::new()
                .router_address(Ipv4Addr::new(192, 0, 2, 1))
                .preference_level(-7)
                .summary(),
            "IcmpRouterAdvertisementEntry(router=192.0.2.1, preference=-7)"
        );
    }
}

