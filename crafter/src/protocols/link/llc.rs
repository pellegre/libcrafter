//! LLC/SNAP encapsulation over IEEE 802.11 data frames.

use core::any::Any;
use core::ops::Div;

use crate::endian::read_u16_be;
use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet, Raw};
use crate::registry::ProtocolRegistry;

use super::{hex_bytes, layer_ethertype, value_or_copy, ETHERTYPE_IPV4};

const LLC_SNAP_HEADER_LEN: usize = 8;
const LLC_SNAP_DSAP: u8 = 0xaa;
const LLC_SNAP_SSAP: u8 = 0xaa;
const LLC_SNAP_CONTROL_UNNUMBERED_INFORMATION: u8 = 0x03;
const LLC_SNAP_OUI_ENCAPSULATED_ETHERNET: [u8; 3] = [0x00, 0x00, 0x00];

/// LLC/SNAP header for EtherType-based payloads over IEEE 802.11 data frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlcSnap {
    dsap: Field<u8>,
    ssap: Field<u8>,
    control: Field<u8>,
    oui: Field<[u8; 3]>,
    ethertype: Field<u16>,
}

impl LlcSnap {
    /// Create an LLC/SNAP header with RFC 1042 SNAP defaults.
    pub fn new() -> Self {
        Self {
            dsap: Field::defaulted(LLC_SNAP_DSAP),
            ssap: Field::defaulted(LLC_SNAP_SSAP),
            control: Field::defaulted(LLC_SNAP_CONTROL_UNNUMBERED_INFORMATION),
            oui: Field::defaulted(LLC_SNAP_OUI_ENCAPSULATED_ETHERNET),
            ethertype: Field::defaulted(ETHERTYPE_IPV4),
        }
    }

    /// Set the destination service access point byte.
    pub fn dsap(mut self, dsap: u8) -> Self {
        self.dsap.set_user(dsap);
        self
    }

    /// Set the source service access point byte.
    pub fn ssap(mut self, ssap: u8) -> Self {
        self.ssap.set_user(ssap);
        self
    }

    /// Set the LLC control byte.
    pub fn control(mut self, control: u8) -> Self {
        self.control.set_user(control);
        self
    }

    /// Set the three-octet SNAP OUI.
    pub fn oui(mut self, oui: [u8; 3]) -> Self {
        self.oui.set_user(oui);
        self
    }

    /// Set the encapsulated EtherType.
    pub fn ethertype(mut self, ethertype: u16) -> Self {
        self.ethertype.set_user(ethertype);
        self
    }

    /// Destination service access point byte.
    pub fn dsap_value(&self) -> u8 {
        value_or_copy(&self.dsap, LLC_SNAP_DSAP)
    }

    /// Source service access point byte.
    pub fn ssap_value(&self) -> u8 {
        value_or_copy(&self.ssap, LLC_SNAP_SSAP)
    }

    /// LLC control byte.
    pub fn control_value(&self) -> u8 {
        value_or_copy(&self.control, LLC_SNAP_CONTROL_UNNUMBERED_INFORMATION)
    }

    /// Three-octet SNAP OUI.
    pub fn oui_value(&self) -> [u8; 3] {
        value_or_copy(&self.oui, LLC_SNAP_OUI_ENCAPSULATED_ETHERNET)
    }

    /// Encapsulated EtherType field value.
    pub fn ethertype_value(&self) -> u16 {
        value_or_copy(&self.ethertype, ETHERTYPE_IPV4)
    }

    fn effective_ethertype(&self, next: Option<&dyn Layer>) -> u16 {
        if self.ethertype.is_user_set() {
            return self.ethertype_value();
        }

        next.and_then(layer_ethertype)
            .or_else(|| self.ethertype.value().copied())
            .unwrap_or(0)
    }
}

/// Append an LLC/SNAP layer and dispatch RFC 1042 SNAP payloads by EtherType.
pub(crate) fn append_llc_snap_packet_with_registry(
    registry: &ProtocolRegistry,
    packet: Packet,
    bytes: &[u8],
) -> Result<Packet> {
    if bytes.is_empty() {
        return Ok(packet);
    }

    if bytes.len() < LLC_SNAP_HEADER_LEN {
        if is_truncated_snap_prefix(bytes) {
            return Err(CrafterError::buffer_too_short(
                "llc_snap.header",
                LLC_SNAP_HEADER_LEN,
                bytes.len(),
            ));
        }

        return Ok(packet.push(Raw::from_bytes(bytes)));
    }

    let llc = decode_llc_snap_header(bytes)?;
    if !llc.has_snap_llc_fields() {
        return Ok(packet.push(Raw::from_bytes(bytes)));
    }

    let is_rfc1042_snap = llc.oui_value() == LLC_SNAP_OUI_ENCAPSULATED_ETHERNET;
    let ethertype = llc.ethertype_value();
    let packet = packet.push(llc);
    let payload = &bytes[LLC_SNAP_HEADER_LEN..];

    if is_rfc1042_snap {
        registry.decode_ethertype(packet, ethertype, payload)
    } else if payload.is_empty() {
        Ok(packet)
    } else {
        Ok(packet.push(Raw::from_bytes(payload)))
    }
}

fn decode_llc_snap_header(bytes: &[u8]) -> Result<LlcSnap> {
    if bytes.len() < LLC_SNAP_HEADER_LEN {
        return Err(CrafterError::buffer_too_short(
            "llc_snap.header",
            LLC_SNAP_HEADER_LEN,
            bytes.len(),
        ));
    }

    Ok(LlcSnap {
        dsap: Field::user(bytes[0]),
        ssap: Field::user(bytes[1]),
        control: Field::user(bytes[2]),
        oui: Field::user([bytes[3], bytes[4], bytes[5]]),
        ethertype: Field::user(read_u16_be(&bytes[6..8])?),
    })
}

fn is_truncated_snap_prefix(bytes: &[u8]) -> bool {
    let snap_llc_prefix = [
        LLC_SNAP_DSAP,
        LLC_SNAP_SSAP,
        LLC_SNAP_CONTROL_UNNUMBERED_INFORMATION,
    ];
    (bytes.len() <= LLC_SNAP_HEADER_LEN
        && bytes.len() <= snap_llc_prefix.len()
        && bytes == &snap_llc_prefix[..bytes.len()])
        || (bytes.len() > snap_llc_prefix.len()
            && bytes[..snap_llc_prefix.len()] == snap_llc_prefix)
}

impl Default for LlcSnap {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for LlcSnap {
    fn name(&self) -> &'static str {
        "LlcSnap"
    }

    fn summary(&self) -> String {
        format!(
            "LlcSnap(dsap=0x{:02x}, ssap=0x{:02x}, control=0x{:02x}, oui={}, type=0x{:04x})",
            self.dsap_value(),
            self.ssap_value(),
            self.control_value(),
            hex_bytes(&self.oui_value()),
            self.ethertype_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("dsap", format!("0x{:02x}", self.dsap_value())),
            ("ssap", format!("0x{:02x}", self.ssap_value())),
            ("control", format!("0x{:02x}", self.control_value())),
            ("oui", hex_bytes(&self.oui_value())),
            ("ethertype", format!("0x{:04x}", self.ethertype_value())),
        ]
    }

    fn encoded_len(&self) -> usize {
        LLC_SNAP_HEADER_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.push(self.dsap_value());
        out.push(self.ssap_value());
        out.push(self.control_value());
        out.extend_from_slice(&self.oui_value());
        out.extend_from_slice(&self.effective_ethertype(ctx.next()).to_be_bytes());
        Ok(())
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

impl LlcSnap {
    fn has_snap_llc_fields(&self) -> bool {
        self.dsap_value() == LLC_SNAP_DSAP
            && self.ssap_value() == LLC_SNAP_SSAP
            && self.control_value() == LLC_SNAP_CONTROL_UNNUMBERED_INFORMATION
    }
}

impl<R> Div<R> for LlcSnap
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

#[cfg(test)]
mod tests {
    use super::LlcSnap;
    use crate::{
        Arp, CrafterError, Dot11, Ipv4, Ipv6, Layer, LinkType, Packet, ProtocolRegistry, Raw,
        ETHERTYPE_ARP, ETHERTYPE_IPV6,
    };
    use core::net::Ipv4Addr;

    fn compiled_header(packet: Packet) -> [u8; 8] {
        let bytes = packet.compile().unwrap();
        bytes.as_bytes()[..8].try_into().unwrap()
    }

    fn decode_dot11_packet(packet: Packet) -> Packet {
        let bytes = packet.compile().unwrap();
        Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes()).unwrap()
    }

    #[test]
    fn llc_snap_compile_uses_snap_defaults() {
        let packet = LlcSnap::new() / Raw::from("payload");

        assert_eq!(
            compiled_header(packet),
            [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]
        );
    }

    #[test]
    fn llc_snap_compile_infers_next_layer_ethertype() {
        let ipv6 = compiled_header(LlcSnap::new() / Ipv6::new());

        assert_eq!(ipv6[6..8], ETHERTYPE_IPV6.to_be_bytes());

        let arp = compiled_header(
            LlcSnap::new()
                / Arp::who_has(
                    Ipv4Addr::new(192, 0, 2, 10),
                    Ipv4Addr::new(192, 0, 2, 1),
                    "02:00:5e:00:53:01".parse().unwrap(),
                ),
        );

        assert_eq!(arp[6..8], ETHERTYPE_ARP.to_be_bytes());
    }

    #[test]
    fn llc_snap_compile_preserves_explicit_malformed_overrides() {
        let packet = LlcSnap::new()
            .dsap(0x01)
            .ssap(0x02)
            .control(0xff)
            .oui([0xde, 0xad, 0xbe])
            .ethertype(0x1234)
            / Ipv4::new();

        assert_eq!(
            compiled_header(packet),
            [0x01, 0x02, 0xff, 0xde, 0xad, 0xbe, 0x12, 0x34]
        );
    }

    #[test]
    fn llc_snap_compile_has_summary_and_inspection_fields() {
        let llc = LlcSnap::new().ethertype(0x86dd);

        assert_eq!(
            llc.summary(),
            "LlcSnap(dsap=0xaa, ssap=0xaa, control=0x03, oui=00 00 00, type=0x86dd)"
        );
        assert_eq!(
            llc.inspection_fields(),
            vec![
                ("dsap", "0xaa".to_string()),
                ("ssap", "0xaa".to_string()),
                ("control", "0x03".to_string()),
                ("oui", "00 00 00".to_string()),
                ("ethertype", "0x86dd".to_string()),
            ]
        );

        let show = (LlcSnap::new() / Raw::from("payload")).show();
        assert!(show.contains("[0] LlcSnap"));
        assert!(show.contains("ethertype: 0x0800"));
    }

    #[test]
    fn llc_snap_decode_dispatches_ipv4_ipv6_and_arp() {
        let ipv4 =
            decode_dot11_packet(Dot11::data() / LlcSnap::new() / Ipv4::new() / Raw::from("v4"));
        assert!(ipv4.layer::<Dot11>().is_some());
        assert!(ipv4.layer::<LlcSnap>().is_some());
        assert!(ipv4.layer::<Ipv4>().is_some());
        assert_eq!(ipv4.layer::<Raw>().unwrap().as_bytes(), b"v4");

        let ipv6 = decode_dot11_packet(
            Dot11::data() / LlcSnap::new() / Ipv6::new().next_header(59) / Raw::from("v6"),
        );
        assert!(ipv6.layer::<Dot11>().is_some());
        assert!(ipv6.layer::<LlcSnap>().is_some());
        assert!(ipv6.layer::<Ipv6>().is_some());
        assert_eq!(ipv6.layer::<Raw>().unwrap().as_bytes(), b"v6");

        let arp = decode_dot11_packet(
            Dot11::data()
                / LlcSnap::new()
                / Arp::who_has(
                    Ipv4Addr::new(192, 0, 2, 10),
                    Ipv4Addr::new(192, 0, 2, 1),
                    "02:00:5e:00:53:01".parse().unwrap(),
                ),
        );
        assert!(arp.layer::<Dot11>().is_some());
        assert!(arp.layer::<LlcSnap>().is_some());
        assert!(arp.layer::<Arp>().is_some());
        assert!(arp.layer::<Raw>().is_none());
    }

    #[test]
    fn llc_snap_decode_uses_custom_ethertype_registry_binding() {
        let packet = Dot11::data() / LlcSnap::new().ethertype(0x88b5) / Raw::from("wire");
        let bytes = packet.compile().unwrap();
        let mut registry = ProtocolRegistry::empty();
        registry.bind_ethertype(0x88b5, |packet, payload| {
            assert_eq!(payload, b"wire");
            Ok(packet.push(Raw::from("registry-bound")))
        });

        let decoded = Packet::decode_from_link_with_registry(
            &registry,
            LinkType::Ieee80211,
            bytes.as_bytes(),
        )
        .unwrap();

        assert!(decoded.layer::<Dot11>().is_some());
        assert_eq!(
            decoded.layer::<LlcSnap>().unwrap().ethertype_value(),
            0x88b5
        );
        assert_eq!(
            decoded.layer::<Raw>().unwrap().as_bytes(),
            b"registry-bound"
        );
    }

    #[test]
    fn llc_snap_decode_preserves_non_snap_llc_and_unknown_snap_payloads_as_raw() {
        let non_snap = decode_dot11_packet(
            Dot11::data() / Raw::from_bytes([0x42, 0x42, 0x03, 0xde, 0xad, 0xbe, 0x08, 0x00]),
        );
        assert!(non_snap.layer::<LlcSnap>().is_none());
        assert_eq!(
            non_snap.layer::<Raw>().unwrap().as_bytes(),
            &[0x42, 0x42, 0x03, 0xde, 0xad, 0xbe, 0x08, 0x00]
        );

        let unknown_oui = decode_dot11_packet(
            Dot11::data() / LlcSnap::new().oui([0x00, 0x00, 0x01]) / Raw::from("vendor"),
        );
        assert_eq!(
            unknown_oui.layer::<LlcSnap>().unwrap().oui_value(),
            [0x00, 0x00, 0x01]
        );
        assert_eq!(unknown_oui.layer::<Raw>().unwrap().as_bytes(), b"vendor");
        assert!(unknown_oui.layer::<Ipv4>().is_none());

        let unknown_ethertype = decode_dot11_packet(
            Dot11::data() / LlcSnap::new().ethertype(0x88b5) / Raw::from("unknown"),
        );
        assert_eq!(
            unknown_ethertype
                .layer::<LlcSnap>()
                .unwrap()
                .ethertype_value(),
            0x88b5
        );
        assert_eq!(
            unknown_ethertype.layer::<Raw>().unwrap().as_bytes(),
            b"unknown"
        );
    }

    #[test]
    fn llc_snap_decode_truncated_snap_header_returns_structured_error() {
        let mut bytes = (Dot11::data() / Raw::from_bytes([0xaa, 0xaa, 0x03, 0, 0, 0, 0x08]))
            .compile()
            .unwrap()
            .into_bytes();
        let available = bytes.len() - Dot11::data().encoded_len();

        let err = Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap_err();
        assert_eq!(
            err,
            CrafterError::buffer_too_short("llc_snap.header", 8, available)
        );

        bytes.truncate(Dot11::data().encoded_len() + 2);
        let err = Packet::decode_from_link(LinkType::Ieee80211, &bytes).unwrap_err();
        assert_eq!(err, CrafterError::buffer_too_short("llc_snap.header", 8, 2));
    }

    #[test]
    fn llc_snap_decode_protected_data_keeps_body_raw() {
        let frame_control = Dot11::data().frame_control_value().with_protected(true);
        let packet = Dot11::data().frame_control(frame_control) / LlcSnap::new() / Ipv4::new();
        let bytes = packet.compile().unwrap();
        let decoded = Packet::decode_from_link(LinkType::Ieee80211, bytes.as_bytes()).unwrap();

        assert!(decoded.layer::<LlcSnap>().is_none());
        assert!(decoded.layer::<Ipv4>().is_none());
        assert_eq!(
            decoded.layer::<Raw>().unwrap().as_bytes(),
            &bytes.as_bytes()[Dot11::data().encoded_len()..]
        );
    }
}
