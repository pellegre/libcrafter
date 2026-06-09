//! IKEv2 Traffic Selector payloads TSi (type 44) and TSr (type 45)
//! (RFC 7296 §3.13).
//!
//! A Traffic Selector (TS) payload narrows the set of packets an IPsec SA
//! carries: TSi names the source/destination ranges as seen by the initiator,
//! TSr the ranges as seen by the responder. The body that follows the 4-octet
//! generic payload header (emitted by [`write_generic_payload_header`]) is:
//!
//! ```text
//!  Number of TSs (1) | RESERVED (3) | <Traffic Selectors>
//! ```
//!
//! (RFC 7296 §3.13). Each Traffic Selector substructure (RFC 7296 §3.13.1) is:
//!
//! ```text
//!  TS Type (1) | IP Protocol ID (1) | Selector Length (2)
//!  | Start Port (2) | End Port (2) | Starting Address | Ending Address
//! ```
//!
//! The Selector Length counts the whole substructure including its 8-octet
//! fixed header, so it is `8 + 2 * addr_len`: 16 octets for an IPv4 address
//! range ([`TS_IPV4_ADDR_RANGE`], 4-byte addresses) and 40 octets for an IPv6
//! address range ([`TS_IPV6_ADDR_RANGE`], 16-byte addresses).
//!
//! TSi (Traffic Selector - Initiator, type 44) and TSr (Traffic Selector -
//! Responder, type 45) share this exact wire form and differ only in their
//! payload type. This module models both with one [`IkeTsPayload`] carrying a
//! [`TsRole`], with [`IkeTsPayload::initiator`] / [`IkeTsPayload::responder`]
//! constructors selecting the role and therefore the reported [`PayloadType`]
//! and [`Layer::name`].
//!
//! The Number of TSs and each Selector Length are auto-filled by `compile()`
//! from the data, while any caller-pinned value (Next Payload, Payload Length,
//! Critical, Number of TSs, Selector Length) is emitted verbatim so
//! deliberately malformed Traffic Selector payloads can be constructed for
//! testing.

use core::net::{Ipv4Addr, Ipv6Addr};

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::ipsec::ikev2::payload::{
    write_generic_payload_header, IkePayload, PayloadHeaderFields, PayloadType,
};
use crate::protocols::transport::common::{impl_layer_div, impl_layer_object};
#[cfg(test)]
use crate::CrafterError;
use crate::Result;

/// Layer name for the IKEv2 TSi (Traffic Selector - Initiator) payload,
/// registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_TSI_PAYLOAD_NAME: &str = "IkeTsiPayload";

/// Layer name for the IKEv2 TSr (Traffic Selector - Responder) payload,
/// registered in
/// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
pub const IKE_TSR_PAYLOAD_NAME: &str = "IkeTsrPayload";

/// Length of the fixed Traffic Selector payload body header (RFC 7296 §3.13):
/// Number of TSs (1) + RESERVED (3) = 4 octets, excluding the Traffic Selector
/// substructures that follow.
pub const TS_PAYLOAD_FIXED_LEN: usize = 4;

/// Length of the fixed Traffic Selector substructure header (RFC 7296 §3.13.1):
/// TS Type (1) + IP Protocol ID (1) + Selector Length (2) + Start Port (2) +
/// End Port (2) = 8 octets, excluding the Starting/Ending Address that follow.
pub const TS_FIXED_LEN: usize = 8;

// --- TS Types (RFC 7296 §3.13.1; IANA "IKEv2 Traffic Selector Types") -------

/// TS Type `7` — TS_IPV4_ADDR_RANGE (RFC 7296 §3.13.1): a range of IPv4
/// addresses, each a four-octet Starting/Ending Address.
pub const TS_IPV4_ADDR_RANGE: u8 = 7;

/// TS Type `8` — TS_IPV6_ADDR_RANGE (RFC 7296 §3.13.1): a range of IPv6
/// addresses, each a sixteen-octet Starting/Ending Address.
pub const TS_IPV6_ADDR_RANGE: u8 = 8;

/// One IKEv2 Traffic Selector substructure (RFC 7296 §3.13.1).
///
/// Names a single range of traffic: a TS Type ([`TS_IPV4_ADDR_RANGE`] or
/// [`TS_IPV6_ADDR_RANGE`]), an IP Protocol ID (`0` for any), a Start/End Port
/// range, and a Starting/Ending Address range. The Selector Length is
/// auto-filled by the enclosing payload `compile()` (`8 + 2 * addr_len`) unless
/// the caller pins it.
///
/// The Starting and Ending Address are stored as raw bytes so that any address
/// width round-trips byte-for-byte; the [`TrafficSelector::ipv4_range`] /
/// [`TrafficSelector::ipv6_range`] constructors fill them from typed addresses.
#[derive(Debug, Clone)]
pub struct TrafficSelector {
    /// TS Type (RFC 7296 §3.13.1; see `TS_*` constants).
    ts_type: u8,
    /// IP Protocol ID (RFC 7296 §3.13.1): the upper-layer protocol, or `0` for
    /// any protocol.
    ip_protocol: u8,
    /// Start Port (RFC 7296 §3.13.1): the first port of the allowed range (the
    /// ICMP type/code or low 16 bits otherwise).
    start_port: u16,
    /// End Port (RFC 7296 §3.13.1): the last port of the allowed range.
    end_port: u16,
    /// Starting Address (RFC 7296 §3.13.1): the low address of the range, as
    /// raw bytes (4 octets for IPv4, 16 for IPv6).
    start_addr: Vec<u8>,
    /// Ending Address (RFC 7296 §3.13.1): the high address of the range, as raw
    /// bytes (same width as `start_addr`).
    end_addr: Vec<u8>,
    /// Caller override for Selector Length; unset lets `compile()` fill it.
    selector_length: Field<u16>,
}

impl TrafficSelector {
    /// A Traffic Selector with the given TS Type, IP Protocol ID, port range,
    /// and raw Starting/Ending Address bytes (RFC 7296 §3.13.1).
    ///
    /// The address bytes are taken verbatim; use [`TrafficSelector::ipv4_range`]
    /// or [`TrafficSelector::ipv6_range`] for the common typed-address cases.
    pub fn new(
        ts_type: u8,
        ip_protocol: u8,
        start_port: u16,
        end_port: u16,
        start_addr: impl Into<Vec<u8>>,
        end_addr: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            ts_type,
            ip_protocol,
            start_port,
            end_port,
            start_addr: start_addr.into(),
            end_addr: end_addr.into(),
            selector_length: Field::unset(),
        }
    }

    /// A TS_IPV4_ADDR_RANGE selector (RFC 7296 §3.13.1) over the inclusive IPv4
    /// address range `start..=end` and port range `start_port..=end_port`.
    ///
    /// Use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`,
    /// `203.0.113.0/24`) in tests and examples. `ip_protocol` is `0` for any
    /// protocol.
    pub fn ipv4_range(
        ip_protocol: u8,
        start_port: u16,
        end_port: u16,
        start: Ipv4Addr,
        end: Ipv4Addr,
    ) -> Self {
        Self::new(
            TS_IPV4_ADDR_RANGE,
            ip_protocol,
            start_port,
            end_port,
            start.octets().to_vec(),
            end.octets().to_vec(),
        )
    }

    /// A TS_IPV6_ADDR_RANGE selector (RFC 7296 §3.13.1) over the inclusive IPv6
    /// address range `start..=end` and port range `start_port..=end_port`.
    ///
    /// Use documentation addresses (`2001:db8::/32`) in tests and examples.
    pub fn ipv6_range(
        ip_protocol: u8,
        start_port: u16,
        end_port: u16,
        start: Ipv6Addr,
        end: Ipv6Addr,
    ) -> Self {
        Self::new(
            TS_IPV6_ADDR_RANGE,
            ip_protocol,
            start_port,
            end_port,
            start.octets().to_vec(),
            end.octets().to_vec(),
        )
    }

    /// Pin the Selector Length explicitly (RFC 7296 §3.13.1). An override is
    /// emitted verbatim, including a deliberately wrong value for malformed
    /// testing.
    pub fn selector_length(mut self, selector_length: u16) -> Self {
        self.selector_length.set_user(selector_length);
        self
    }

    /// TS Type (RFC 7296 §3.13.1).
    pub fn ts_type(&self) -> u8 {
        self.ts_type
    }

    /// IP Protocol ID (RFC 7296 §3.13.1).
    pub fn ip_protocol(&self) -> u8 {
        self.ip_protocol
    }

    /// Start Port (RFC 7296 §3.13.1).
    pub fn start_port(&self) -> u16 {
        self.start_port
    }

    /// End Port (RFC 7296 §3.13.1).
    pub fn end_port(&self) -> u16 {
        self.end_port
    }

    /// Starting Address bytes (RFC 7296 §3.13.1).
    pub fn start_addr(&self) -> &[u8] {
        &self.start_addr
    }

    /// Ending Address bytes (RFC 7296 §3.13.1).
    pub fn end_addr(&self) -> &[u8] {
        &self.end_addr
    }

    /// On-wire length of this Traffic Selector in octets (RFC 7296 §3.13.1): the
    /// 8-octet fixed header plus the Starting and Ending Address.
    pub fn encoded_len(&self) -> usize {
        TS_FIXED_LEN + self.start_addr.len() + self.end_addr.len()
    }

    /// Append this Traffic Selector to `out` (RFC 7296 §3.13.1).
    ///
    /// The Selector Length is auto-filled from [`TrafficSelector::encoded_len`]
    /// unless the caller pinned it, in which case the pinned value is emitted
    /// verbatim.
    fn write(&self, out: &mut Vec<u8>) {
        let selector_length = self
            .selector_length
            .value()
            .copied()
            .unwrap_or(self.encoded_len() as u16);

        out.push(self.ts_type);
        out.push(self.ip_protocol);
        out.extend_from_slice(&selector_length.to_be_bytes());
        out.extend_from_slice(&self.start_port.to_be_bytes());
        out.extend_from_slice(&self.end_port.to_be_bytes());
        out.extend_from_slice(&self.start_addr);
        out.extend_from_slice(&self.end_addr);
    }
}

/// Which Traffic Selector payload an [`IkeTsPayload`] is: TSi (Initiator, type
/// 44) or TSr (Responder, type 45) (RFC 7296 §3.13).
///
/// The two share the identical wire form and differ only in payload type and
/// layer name. The role selects both: [`IkePayload::payload_type`] and
/// [`Layer::name`] report the TSi/TSr value for the chosen role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsRole {
    /// TSi — Traffic Selector - Initiator (payload type 44).
    Initiator,
    /// TSr — Traffic Selector - Responder (payload type 45).
    Responder,
}

impl TsRole {
    /// The [`PayloadType`] this role reports (RFC 7296 §3.13): TSi → 44,
    /// TSr → 45.
    fn payload_type(self) -> PayloadType {
        match self {
            Self::Initiator => PayloadType::TrafficSelectorInitiator,
            Self::Responder => PayloadType::TrafficSelectorResponder,
        }
    }

    /// The stable [`Layer::name`] for this role, registered in
    /// [`payload_type_for_layer_name`](super::payload_type_for_layer_name).
    fn layer_name(self) -> &'static str {
        match self {
            Self::Initiator => IKE_TSI_PAYLOAD_NAME,
            Self::Responder => IKE_TSR_PAYLOAD_NAME,
        }
    }
}

/// IKEv2 Traffic Selector payload — TSi (type 44) or TSr (type 45)
/// (RFC 7296 §3.13).
///
/// Carries an ordered list of [`TrafficSelector`]s plus a [`TsRole`] selecting
/// whether this is the Initiator (TSi) or Responder (TSr) payload. As a
/// [`Layer`] it emits the 4-octet generic payload header (via
/// [`write_generic_payload_header`]) followed by the body `Number of TSs (1) |
/// RESERVED (3) | <Traffic Selectors>`. The generic-header Next Payload,
/// Critical flag, and Payload Length are the shared overridable fields carried
/// in [`PayloadHeaderFields`]; the Number of TSs is auto-filled from the list
/// unless pinned.
#[derive(Debug, Clone)]
pub struct IkeTsPayload {
    /// Whether this is the TSi (Initiator) or TSr (Responder) payload.
    role: TsRole,
    /// The Traffic Selectors carried by this payload (RFC 7296 §3.13.1).
    selectors: Vec<TrafficSelector>,
    /// Caller override for Number of TSs; unset derives it from `selectors`.
    number_of_ts: Field<u8>,
    /// Shared generic-payload-header overrides (Next Payload, Length, Critical).
    header: PayloadHeaderFields,
}

impl IkeTsPayload {
    /// A Traffic Selector payload of the given role with no selectors
    /// (RFC 7296 §3.13).
    pub fn new(role: TsRole) -> Self {
        Self {
            role,
            selectors: Vec::new(),
            number_of_ts: Field::unset(),
            header: PayloadHeaderFields::new(),
        }
    }

    /// A TSi (Traffic Selector - Initiator, type 44) payload with no selectors
    /// (RFC 7296 §3.13).
    pub fn initiator() -> Self {
        Self::new(TsRole::Initiator)
    }

    /// A TSr (Traffic Selector - Responder, type 45) payload with no selectors
    /// (RFC 7296 §3.13).
    pub fn responder() -> Self {
        Self::new(TsRole::Responder)
    }

    /// A TSi payload carrying a single IPv4 address-range selector
    /// (RFC 7296 §3.13.1). Use documentation addresses (`192.0.2.0/24`) in
    /// tests and examples.
    pub fn initiator_ipv4_range(
        ip_protocol: u8,
        start_port: u16,
        end_port: u16,
        start: Ipv4Addr,
        end: Ipv4Addr,
    ) -> Self {
        Self::initiator().with_selector(TrafficSelector::ipv4_range(
            ip_protocol,
            start_port,
            end_port,
            start,
            end,
        ))
    }

    /// A TSr payload carrying a single IPv4 address-range selector
    /// (RFC 7296 §3.13.1).
    pub fn responder_ipv4_range(
        ip_protocol: u8,
        start_port: u16,
        end_port: u16,
        start: Ipv4Addr,
        end: Ipv4Addr,
    ) -> Self {
        Self::responder().with_selector(TrafficSelector::ipv4_range(
            ip_protocol,
            start_port,
            end_port,
            start,
            end,
        ))
    }

    /// Append a Traffic Selector (RFC 7296 §3.13.1), consuming-builder style.
    pub fn with_selector(mut self, selector: TrafficSelector) -> Self {
        self.selectors.push(selector);
        self
    }

    /// Append a Traffic Selector (RFC 7296 §3.13.1) in place.
    pub fn push_selector(&mut self, selector: TrafficSelector) {
        self.selectors.push(selector);
    }

    /// Pin the Number of TSs explicitly (RFC 7296 §3.13), independent of the
    /// actual selector count, for malformed-input testing.
    pub fn number_of_ts(mut self, number_of_ts: u8) -> Self {
        self.number_of_ts.set_user(number_of_ts);
        self
    }

    /// Pin the generic-header Next Payload explicitly (RFC 7296 §3.2).
    pub fn next_payload(mut self, next_payload: u8) -> Self {
        self.header.set_next_payload(next_payload);
        self
    }

    /// Pin the generic-header Payload Length explicitly (RFC 7296 §3.2).
    pub fn payload_length(mut self, length: u16) -> Self {
        self.header.set_length(length);
        self
    }

    /// Set the Critical (C) flag for this payload explicitly (RFC 7296 §3.2).
    pub fn critical(mut self, critical: bool) -> Self {
        self.header.set_critical(critical);
        self
    }

    /// Whether this is the TSi (Initiator) or TSr (Responder) payload.
    pub fn role(&self) -> TsRole {
        self.role
    }

    /// The Traffic Selectors carried by this payload (RFC 7296 §3.13.1).
    pub fn selectors(&self) -> &[TrafficSelector] {
        &self.selectors
    }

    /// The Traffic Selector body (everything after the 4-octet generic header),
    /// per RFC 7296 §3.13: Number of TSs (1) | RESERVED (3, zero) | the Traffic
    /// Selector substructures in order. The Number of TSs is auto-filled from
    /// the selector count unless pinned.
    fn ts_body(&self) -> Vec<u8> {
        let number_of_ts = self
            .number_of_ts
            .value()
            .copied()
            .unwrap_or(self.selectors.len() as u8);

        let mut out = Vec::with_capacity(TS_PAYLOAD_FIXED_LEN);
        out.push(number_of_ts);
        out.extend_from_slice(&[0u8, 0u8, 0u8]); // RESERVED (3 octets).
        for selector in &self.selectors {
            selector.write(&mut out);
        }
        out
    }
}

impl IkePayload for IkeTsPayload {
    fn payload_type(&self) -> PayloadType {
        self.role.payload_type()
    }

    fn payload_body(&self, _ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        Ok(self.ts_body())
    }

    fn next_payload_override(&self) -> Option<u8> {
        self.header.next_payload_override()
    }

    fn payload_length_override(&self) -> Option<u16> {
        self.header.payload_length_override()
    }

    fn critical(&self) -> bool {
        self.header.critical()
    }
}

impl Layer for IkeTsPayload {
    fn name(&self) -> &'static str {
        self.role.layer_name()
    }

    fn summary(&self) -> String {
        format!(
            "{}(traffic_selectors={})",
            self.role.layer_name(),
            self.selectors.len()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![("traffic_selectors", self.selectors.len().to_string())];
        for selector in &self.selectors {
            fields.push((
                "traffic_selector",
                format!(
                    "type={} protocol={} ports={}-{} addr_len={}",
                    selector.ts_type,
                    selector.ip_protocol,
                    selector.start_port,
                    selector.end_port,
                    selector.start_addr.len()
                ),
            ));
        }
        fields
    }

    fn encoded_len(&self) -> usize {
        let selectors: usize = self.selectors.iter().map(|s| s.encoded_len()).sum();
        super::GENERIC_PAYLOAD_HEADER_LEN + TS_PAYLOAD_FIXED_LEN + selectors
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        // Emit the 4-octet generic payload header (auto Next Payload from the
        // following payload and auto Payload Length unless overridden), then the
        // Traffic Selector body (Number of TSs | RESERVED | selectors).
        let body = self.payload_body(ctx)?;
        write_generic_payload_header(
            out,
            ctx,
            self.next_payload_override(),
            self.critical(),
            self.payload_length_override(),
            body.len(),
        )?;
        out.extend_from_slice(&body);
        Ok(())
    }

    impl_layer_object!(IkeTsPayload);
}

impl_layer_div!(IkeTsPayload);

// --- Local parse helpers (Step 45 closes the full registry decode) ----------

/// A parsed Traffic Selector and the number of octets it consumed
/// (RFC 7296 §3.13.1). Local to this step; the full payload-chain decode is
/// added by Step 45.
///
/// The Selector Length names the whole substructure; the address bytes are the
/// remainder after the 8-octet fixed header, split evenly into the Starting and
/// Ending Address. A truncated buffer or a length shorter than the fixed header
/// is a structured error rather than a panic.
#[cfg(test)]
fn parse_traffic_selector(bytes: &[u8]) -> Result<(TrafficSelector, usize)> {
    if bytes.len() < TS_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.ts.selector",
            TS_FIXED_LEN,
            bytes.len(),
        ));
    }
    let ts_type = bytes[0];
    let ip_protocol = bytes[1];
    let selector_length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let start_port = u16::from_be_bytes([bytes[4], bytes[5]]);
    let end_port = u16::from_be_bytes([bytes[6], bytes[7]]);
    if selector_length < TS_FIXED_LEN || bytes.len() < selector_length {
        return Err(CrafterError::buffer_too_short(
            "ikev2.ts.selector.length",
            selector_length.max(TS_FIXED_LEN),
            bytes.len(),
        ));
    }
    // The addresses fill the remainder of the substructure, split into equal
    // Starting and Ending Address halves.
    let addr_total = selector_length - TS_FIXED_LEN;
    let addr_len = addr_total / 2;
    let start_addr = bytes[TS_FIXED_LEN..TS_FIXED_LEN + addr_len].to_vec();
    let end_addr = bytes[TS_FIXED_LEN + addr_len..TS_FIXED_LEN + 2 * addr_len].to_vec();
    Ok((
        TrafficSelector::new(
            ts_type,
            ip_protocol,
            start_port,
            end_port,
            start_addr,
            end_addr,
        ),
        selector_length,
    ))
}

/// Parse a Traffic Selector payload **body** (the bytes after the 4-octet
/// generic header) per RFC 7296 §3.13, for the given [`TsRole`]. Local to this
/// step; the registry-driven chain decode lands in Step 45.
///
/// The Number of TSs is read from the first octet, the three RESERVED octets
/// are ignored, and that many Traffic Selector substructures are parsed. A
/// buffer shorter than the fixed body header is a structured error rather than
/// a panic.
#[cfg(test)]
fn parse_ts_payload_body(role: TsRole, bytes: &[u8]) -> Result<IkeTsPayload> {
    if bytes.len() < TS_PAYLOAD_FIXED_LEN {
        return Err(CrafterError::buffer_too_short(
            "ikev2.ts",
            TS_PAYLOAD_FIXED_LEN,
            bytes.len(),
        ));
    }
    let number_of_ts = bytes[0] as usize;
    // bytes[1..4] are RESERVED and ignored on decode.
    let mut payload = IkeTsPayload::new(role);
    let mut offset = TS_PAYLOAD_FIXED_LEN;
    for _ in 0..number_of_ts {
        let (selector, consumed) = parse_traffic_selector(&bytes[offset..])?;
        payload.push_selector(selector);
        offset += consumed;
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{LayerContext, Packet, Raw};
    use crate::protocols::ipsec::ikev2::payload::GENERIC_PAYLOAD_HEADER_LEN;

    /// Compile a standalone Traffic Selector payload and return its full bytes
    /// (generic header + body), gathered through a one-layer packet.
    fn compile_payload(payload: IkeTsPayload) -> Vec<u8> {
        let packet = Packet::from_layer(payload);
        let ctx = LayerContext::new(&packet, 0);
        let mut out = Vec::new();
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        out
    }

    /// A representative TSi over the documentation IPv4 range
    /// `192.0.2.1..=192.0.2.254` for TCP (protocol 6), ports 1024..=65535.
    fn tsi_ipv4_payload() -> IkeTsPayload {
        IkeTsPayload::initiator_ipv4_range(
            6,
            1024,
            65535,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 254),
        )
    }

    #[test]
    fn ts_constants_match_manifest() {
        // RFC 7296 §3.13.1 / IANA "IKEv2 Traffic Selector Types".
        assert_eq!(TS_PAYLOAD_FIXED_LEN, 4);
        assert_eq!(TS_FIXED_LEN, 8);
        assert_eq!(TS_IPV4_ADDR_RANGE, 7);
        assert_eq!(TS_IPV6_ADDR_RANGE, 8);
        // The TSi/TSr payload-type codepoints (RFC 7296 §3.2 / §3.13).
        assert_eq!(PayloadType::TrafficSelectorInitiator.codepoint(), 44);
        assert_eq!(PayloadType::TrafficSelectorResponder.codepoint(), 45);
    }

    #[test]
    fn role_selects_payload_type_and_name() {
        // TSi reports payload type 44 / the TSi name; TSr reports 45 / the TSr
        // name. Both register for the chain next-payload derivation.
        let tsi = IkeTsPayload::initiator();
        assert_eq!(tsi.role(), TsRole::Initiator);
        assert_eq!(tsi.payload_type(), PayloadType::TrafficSelectorInitiator);
        assert_eq!(tsi.name(), IKE_TSI_PAYLOAD_NAME);

        let tsr = IkeTsPayload::responder();
        assert_eq!(tsr.role(), TsRole::Responder);
        assert_eq!(tsr.payload_type(), PayloadType::TrafficSelectorResponder);
        assert_eq!(tsr.name(), IKE_TSR_PAYLOAD_NAME);
    }

    #[test]
    fn ipv4_selector_is_sixteen_octets_with_auto_length() {
        // RFC 7296 §3.13.1: an IPv4 selector is 8 (fixed) + 4 + 4 = 16 octets,
        // and the auto Selector Length matches.
        let selector = TrafficSelector::ipv4_range(
            6,
            1024,
            65535,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(192, 0, 2, 254),
        );
        assert_eq!(selector.ts_type(), TS_IPV4_ADDR_RANGE);
        assert_eq!(selector.encoded_len(), 16);

        let mut out = Vec::new();
        selector.write(&mut out);
        assert_eq!(out.len(), 16);
        assert_eq!(out[0], TS_IPV4_ADDR_RANGE);
        assert_eq!(out[1], 6); // IP Protocol ID (TCP).
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 16); // Selector Length.
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 1024); // Start Port.
        assert_eq!(u16::from_be_bytes([out[6], out[7]]), 65535); // End Port.
        assert_eq!(&out[8..12], &[192, 0, 2, 1]); // Starting Address.
        assert_eq!(&out[12..16], &[192, 0, 2, 254]); // Ending Address.
    }

    #[test]
    fn ipv6_selector_is_forty_octets() {
        // RFC 7296 §3.13.1: an IPv6 selector is 8 (fixed) + 16 + 16 = 40 octets.
        let start: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::ffff".parse().unwrap();
        let selector = TrafficSelector::ipv6_range(17, 53, 53, start, end);
        assert_eq!(selector.ts_type(), TS_IPV6_ADDR_RANGE);
        assert_eq!(selector.encoded_len(), 40);

        let mut out = Vec::new();
        selector.write(&mut out);
        assert_eq!(out.len(), 40);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 40); // Selector Length.
        assert_eq!(&out[8..24], &start.octets());
        assert_eq!(&out[24..40], &end.octets());
    }

    #[test]
    fn ts_body_lays_out_count_reserved_then_selectors() {
        // RFC 7296 §3.13: Number of TSs (1) | RESERVED (3, zero) | selectors.
        let payload = tsi_ipv4_payload();
        let body = payload.ts_body();
        assert_eq!(body[0], 1); // One Traffic Selector.
        assert_eq!(&body[1..4], &[0, 0, 0]); // RESERVED.
        assert_eq!(body.len(), TS_PAYLOAD_FIXED_LEN + 16);
        // The selector substructure begins immediately after the fixed header.
        assert_eq!(body[TS_PAYLOAD_FIXED_LEN], TS_IPV4_ADDR_RANGE);
    }

    #[test]
    fn payload_compiles_generic_header_then_body() {
        // The compiled payload is the 4-octet generic header (Next Payload 0
        // terminator, auto length) followed by the Traffic Selector body.
        let payload = tsi_ipv4_payload();
        let bytes = compile_payload(payload.clone());

        assert_eq!(bytes[0], 0); // Next Payload terminator.
        assert_eq!(bytes[1], 0); // Critical clear.
        let payload_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        assert_eq!(payload_len, bytes.len());
        assert_eq!(payload_len, payload.encoded_len());
        // The body after the generic header is the Traffic Selector body verbatim.
        assert_eq!(&bytes[GENERIC_PAYLOAD_HEADER_LEN..], &payload.ts_body()[..]);
    }

    #[test]
    fn payload_honors_generic_header_overrides() {
        // Caller-pinned Next Payload, Critical, and Payload Length survive.
        let payload = tsi_ipv4_payload()
            .next_payload(45)
            .critical(true)
            .payload_length(0xBEEF);
        let bytes = compile_payload(payload);
        assert_eq!(bytes[0], 45);
        assert_eq!(bytes[1], 0x80); // Critical bit set.
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 0xBEEF);
    }

    #[test]
    fn number_of_ts_and_selector_length_overrides_emit_verbatim() {
        // A pinned Number of TSs and a pinned Selector Length are emitted
        // verbatim, even when they disagree with the data (malformed testing).
        let payload = IkeTsPayload::initiator()
            .with_selector(
                TrafficSelector::ipv4_range(
                    0,
                    0,
                    65535,
                    Ipv4Addr::new(192, 0, 2, 0),
                    Ipv4Addr::new(192, 0, 2, 255),
                )
                .selector_length(0x00FF),
            )
            .number_of_ts(9);
        let bytes = compile_payload(payload);
        let body = &bytes[GENERIC_PAYLOAD_HEADER_LEN..];
        assert_eq!(body[0], 9); // Pinned Number of TSs.
                                // Pinned Selector Length in the substructure header.
        assert_eq!(u16::from_be_bytes([body[6], body[7]]), 0x00FF);
    }

    #[test]
    fn payload_chain_next_payload_points_at_tsi_and_tsr() {
        // A TSi/TSr payload following another layer derives the preceding
        // header's Next Payload through payload_type_for_layer_name (registered
        // this step) as the TSi (44) / TSr (45) codepoint.
        use crate::protocols::ipsec::ikev2::payload::{
            following_next_payload, payload_type_for_layer_name, PAYLOAD_TSI, PAYLOAD_TSR,
        };
        assert_eq!(
            payload_type_for_layer_name(IKE_TSI_PAYLOAD_NAME),
            Some(PayloadType::TrafficSelectorInitiator)
        );
        assert_eq!(
            payload_type_for_layer_name(IKE_TSR_PAYLOAD_NAME),
            Some(PayloadType::TrafficSelectorResponder)
        );

        let tsi_packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0])) / tsi_ipv4_payload();
        let tsi_ctx = LayerContext::new(&tsi_packet, 0);
        assert_eq!(following_next_payload(&tsi_ctx), PAYLOAD_TSI);

        let tsr_packet: Packet = Packet::from_layer(Raw::from_bytes([0u8; 0]))
            / IkeTsPayload::responder_ipv4_range(
                0,
                0,
                65535,
                Ipv4Addr::new(198, 51, 100, 1),
                Ipv4Addr::new(198, 51, 100, 254),
            );
        let tsr_ctx = LayerContext::new(&tsr_packet, 0);
        assert_eq!(following_next_payload(&tsr_ctx), PAYLOAD_TSR);
    }

    #[test]
    fn round_trip_tsi_ipv4_preserves_all_fields() {
        // Build a TSi from a documentation IPv4 address range with a port range,
        // compile to wire, parse the body back, and confirm every field
        // round-trips and re-compiles byte-exact (Step 45 closes the registry
        // decode; this is the local parse helper).
        let payload = tsi_ipv4_payload();
        let bytes = compile_payload(payload.clone());

        let parsed =
            parse_ts_payload_body(TsRole::Initiator, &bytes[GENERIC_PAYLOAD_HEADER_LEN..]).unwrap();
        assert_eq!(parsed.role(), TsRole::Initiator);
        assert_eq!(parsed.selectors().len(), 1);

        let selector = &parsed.selectors()[0];
        assert_eq!(selector.ts_type(), TS_IPV4_ADDR_RANGE);
        assert_eq!(selector.ip_protocol(), 6);
        assert_eq!(selector.start_port(), 1024);
        assert_eq!(selector.end_port(), 65535);
        assert_eq!(selector.start_addr(), &[192, 0, 2, 1]);
        assert_eq!(selector.end_addr(), &[192, 0, 2, 254]);

        // The parsed payload re-compiles byte-exact.
        let recompiled = compile_payload(parsed);
        assert_eq!(recompiled, bytes);
    }

    #[test]
    fn round_trip_multiple_selectors() {
        // A payload carrying both an IPv4 and an IPv6 selector round-trips both
        // substructures, with the auto Number of TSs reflecting the count.
        let payload = IkeTsPayload::responder()
            .with_selector(TrafficSelector::ipv4_range(
                0,
                0,
                65535,
                Ipv4Addr::new(203, 0, 113, 0),
                Ipv4Addr::new(203, 0, 113, 255),
            ))
            .with_selector(TrafficSelector::ipv6_range(
                0,
                0,
                65535,
                "2001:db8::".parse().unwrap(),
                "2001:db8::ffff".parse().unwrap(),
            ));
        let bytes = compile_payload(payload);
        let body = &bytes[GENERIC_PAYLOAD_HEADER_LEN..];
        assert_eq!(body[0], 2); // Number of TSs auto-filled to 2.

        let parsed = parse_ts_payload_body(TsRole::Responder, body).unwrap();
        assert_eq!(parsed.selectors().len(), 2);
        assert_eq!(parsed.selectors()[0].ts_type(), TS_IPV4_ADDR_RANGE);
        assert_eq!(parsed.selectors()[0].encoded_len(), 16);
        assert_eq!(parsed.selectors()[1].ts_type(), TS_IPV6_ADDR_RANGE);
        assert_eq!(parsed.selectors()[1].encoded_len(), 40);
        // Re-compile byte-exact.
        assert_eq!(compile_payload(parsed), bytes);
    }

    #[test]
    fn parse_rejects_truncated_body() {
        // A buffer shorter than the fixed Traffic Selector body header is a
        // structured error, not a panic.
        let err = parse_ts_payload_body(TsRole::Initiator, &[1u8, 0, 0]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }

    #[test]
    fn parse_rejects_truncated_selector() {
        // A Number of TSs of 1 but a selector shorter than the fixed header is a
        // structured error, not a panic.
        let err =
            parse_ts_payload_body(TsRole::Initiator, &[1u8, 0, 0, 0, 7, 6, 0, 16]).unwrap_err();
        assert!(matches!(err, CrafterError::BufferTooShort { .. }));
    }
}
