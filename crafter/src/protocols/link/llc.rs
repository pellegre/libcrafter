//! LLC/SNAP encapsulation over IEEE 802.11 data frames.

use core::any::Any;
use core::ops::Div;

use crate::error::Result;
use crate::field::Field;
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};

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
    use crate::{Arp, Ipv4, Ipv6, Layer, Packet, Raw, ETHERTYPE_ARP, ETHERTYPE_IPV6};
    use core::net::Ipv4Addr;

    fn compiled_header(packet: Packet) -> [u8; 8] {
        let bytes = packet.compile().unwrap();
        bytes.as_bytes()[..8].try_into().unwrap()
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
}
