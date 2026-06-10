//! NAT Traversal: UDP-encapsulated ESP and the non-ESP marker (RFC 3948).
//!
//! When an IPSec peer sits behind a NAT, ESP (IP protocol 50) cannot traverse
//! the NAT — it has no ports for the NAT to rewrite — so RFC 3948 carries the
//! ESP datagram inside a UDP datagram on port 4500 (UDP-Encapsulated-ESP). The
//! same UDP/4500 flow also carries IKE messages once the peers have detected a
//! NAT (RFC 7296 §2.23), which creates an ambiguity: a receiver on UDP/4500
//! sees a UDP payload that could be either an ESP datagram or an IKE message.
//!
//! RFC 3948 §2.1–§2.2 resolves it with the **non-ESP marker**: an IKE message
//! sent on UDP/4500 is prefixed with four zero octets, while a UDP-encapsulated
//! ESP datagram is the ESP packet directly (its first four octets are the ESP
//! SPI). Because the SPI value `0` is reserved and never appears on the wire
//! (RFC 4303 §2.1, §2.4), a leading 32-bit word of all zeros can only be the
//! non-ESP marker — so the receiver disambiguates by inspecting the first four
//! octets:
//!
//! - **first four octets all zero** → strip the 4-octet marker, decode the rest
//!   as an IKEv2 message;
//! - **a nonzero leading word** → decode as a UDP-encapsulated ESP datagram (the
//!   leading word is a real ESP SPI).
//!
//! UDP/500 carries IKE only and never uses the marker (RFC 3948 §2.2); that
//! binding (Step 45) is unchanged. This module supplies the marker predicate
//! ([`is_non_esp_marker`]), a builder helper ([`non_esp_marker`]) and the small
//! [`NatTraversal`] marker layer that prepends the four zero octets to an IKE
//! message destined for UDP/4500 so the marker round-trips byte-exact.

use crate::field::Field;
use crate::packet::{Layer, LayerContext};
use crate::protocols::transport::common::{hex_bytes, impl_layer_div, impl_layer_object};
use crate::Result;

/// Length of the RFC 3948 non-ESP marker: four octets, all zero.
///
/// An IKE message on UDP/4500 is prefixed with this marker so its leading bytes
/// cannot be mistaken for an ESP SPI (RFC 3948 §2.2).
pub const NON_ESP_MARKER_LEN: usize = 4;

/// The four-octet non-ESP marker value (RFC 3948 §2.2): all zero.
pub const NON_ESP_MARKER: [u8; NON_ESP_MARKER_LEN] = [0, 0, 0, 0];

/// True when `bytes` begins with the RFC 3948 non-ESP marker.
///
/// On UDP/4500 a receiver disambiguates IKE from UDP-encapsulated ESP by the
/// first four octets (RFC 3948 §2.2): an IKE message carries the four-zero
/// non-ESP marker, while an ESP datagram leads with its (always nonzero) SPI.
/// This returns `true` only when at least four octets are present and all four
/// are zero, so a buffer too short to hold the marker — or one whose leading
/// word is a real ESP SPI — is reported as *not* a marker.
pub fn is_non_esp_marker(bytes: &[u8]) -> bool {
    bytes.len() >= NON_ESP_MARKER_LEN && bytes[..NON_ESP_MARKER_LEN] == NON_ESP_MARKER
}

/// The four-octet non-ESP marker to prepend to an IKE message on UDP/4500.
///
/// Builder helper mirroring the disambiguation rule (RFC 3948 §2.2): place this
/// marker before an IKE header when composing an IKE message destined for
/// UDP/4500 so the receiver routes it to the IKEv2 decoder rather than the
/// UDP-encapsulated ESP decoder. The returned [`NatTraversal`] layer composes
/// with `/` like any other layer:
///
/// ```ignore
/// let packet = Ipv4::new() / Udp::new().sport(4500).dport(4500)
///     / non_esp_marker() / IkeHeader::new().exchange(IKE_SA_INIT).initiator()
///     / sa / ke / ni;
/// ```
pub fn non_esp_marker() -> NatTraversal {
    NatTraversal::marker()
}

/// The RFC 3948 non-ESP marker as a composable layer.
///
/// `NatTraversal` carries the four-octet marker that prefixes an IKE message on
/// UDP/4500 (RFC 3948 §2.2). It compiles to exactly its stored marker octets and
/// consumes nothing, so it slots in front of an `IkeHeader` without disturbing
/// the IKE message that follows. The marker bytes are a caller-set field, so a
/// decoded marker re-compiles byte-for-byte — including a deliberately
/// non-canonical value built for malformed testing.
#[derive(Debug, Clone)]
pub struct NatTraversal {
    /// The non-ESP marker octets (RFC 3948 §2.2: four zero octets).
    marker: Field<Vec<u8>>,
}

impl NatTraversal {
    /// Create a `NatTraversal` carrying the canonical four-zero non-ESP marker.
    pub fn marker() -> Self {
        Self {
            marker: Field::defaulted(NON_ESP_MARKER.to_vec()),
        }
    }

    /// Override the marker octets verbatim.
    ///
    /// The canonical marker is four zero octets (RFC 3948 §2.2); this setter
    /// lets a caller pin a different value (including a deliberately wrong one)
    /// for malformed-packet construction. The bytes are emitted unchanged.
    pub fn bytes(mut self, marker: impl Into<Vec<u8>>) -> Self {
        self.marker.set_user(marker.into());
        self
    }

    /// The stored marker octets.
    pub fn marker_bytes(&self) -> &[u8] {
        self.marker.value().map(Vec::as_slice).unwrap_or(&[])
    }
}

impl Default for NatTraversal {
    fn default() -> Self {
        Self::marker()
    }
}

impl Layer for NatTraversal {
    fn name(&self) -> &'static str {
        "NatTraversal"
    }

    fn summary(&self) -> String {
        format!(
            "NatTraversal(non-esp-marker={})",
            hex_bytes(self.marker_bytes())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![("non_esp_marker", hex_bytes(self.marker_bytes()))]
    }

    fn encoded_len(&self) -> usize {
        self.marker_bytes().len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(self.marker_bytes());
        Ok(())
    }

    impl_layer_object!(NatTraversal);
}

impl_layer_div!(NatTraversal);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{NetworkLayer, Packet, Raw};
    use crate::protocols::ipsec::esp::Esp;
    use crate::protocols::ipsec::ikev2::header::{IkeHeader, IKE_SA_INIT};
    use crate::protocols::ipsec::ikev2::payload::ke::IkeKePayload;
    use crate::protocols::ipsec::ikev2::payload::nonce::IkeNoncePayload;
    use crate::protocols::ipsec::ikev2::payload::sa::{IkeSaPayload, Proposal, Transform};
    use crate::protocols::ipv4::{Ipv4, IPPROTO_UDP};
    use crate::protocols::transport::Udp;

    /// UDP port 4500, the IKE/ESP NAT-traversal port (RFC 3948 §2; IANA
    /// "ipsec-nat-t").
    const NATT_UDP_PORT: u16 = 4500;

    #[test]
    fn is_non_esp_marker_recognizes_four_zero_octets() {
        // The canonical marker plus any trailing IKE bytes is a marker.
        assert!(is_non_esp_marker(&[0, 0, 0, 0]));
        assert!(is_non_esp_marker(&[0, 0, 0, 0, 0x20, 0x22, 0x08, 0x00]));
        // A nonzero leading word (a real ESP SPI) is not a marker.
        assert!(!is_non_esp_marker(&[0x00, 0x00, 0x20, 0x00, 0xDE, 0xAD]));
        assert!(!is_non_esp_marker(&[0x01, 0x00, 0x00, 0x00]));
        // A buffer too short to hold the marker is not a marker.
        assert!(!is_non_esp_marker(&[0, 0, 0]));
        assert!(!is_non_esp_marker(&[]));
    }

    #[test]
    fn marker_layer_compiles_to_four_zero_octets() {
        let mut out = Vec::new();
        let natt = NatTraversal::marker();
        let packet = Packet::from_layer(natt);
        let ctx = LayerContext::new(&packet, 0);
        packet.get(0).unwrap().compile(&ctx, &mut out).unwrap();
        assert_eq!(out, NON_ESP_MARKER.to_vec());
    }

    #[test]
    fn marker_override_is_emitted_verbatim() {
        let natt = NatTraversal::marker().bytes(vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(natt.marker_bytes(), &[0x01, 0x02, 0x03, 0x04]);
    }

    /// Build an `IKE_SA_INIT` message (SA + KE + Ni payloads, RFC 7296 §1.2).
    fn ike_sa_init_payloads() -> (IkeSaPayload, IkeKePayload, IkeNoncePayload) {
        let proposal = Proposal::new(1, 3).with_transform(Transform::new(1, 20));
        let sa = IkeSaPayload::new().with_proposal(proposal);
        let ke = IkeKePayload::new(14, vec![0xAB; 32]);
        let ni = IkeNoncePayload::new(vec![0x5A; 16]);
        (sa, ke, ni)
    }

    #[test]
    fn udp_4500_zero_marker_then_ike_decodes_to_ikev2_and_round_trips() {
        // RFC 3948 §2.2: an IKE message on UDP/4500 is prefixed with the four-zero
        // non-ESP marker. The registry must strip the marker and decode IKEv2.
        let (sa, ke, ni) = ike_sa_init_payloads();
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_UDP)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        let udp = Udp::new().sport(NATT_UDP_PORT).dport(NATT_UDP_PORT);
        let header = IkeHeader::new().exchange(IKE_SA_INIT).initiator();
        let packet = Packet::from_layer(ipv4) / udp / non_esp_marker() / header / sa / ke / ni;
        let wire = packet.compile().expect("compile NAT-T IKE").into_bytes();

        let decoded =
            Packet::decode_from_l3(NetworkLayer::Ipv4, &wire).expect("decode NAT-T IKE from L3");

        // The NAT-T marker layer survives as a typed layer, and the IKE message
        // decodes to its typed payload layers (not opaque ESP).
        assert!(
            decoded.layer::<NatTraversal>().is_some(),
            "non-ESP marker present"
        );
        assert_eq!(
            decoded.layer::<NatTraversal>().unwrap().marker_bytes(),
            &NON_ESP_MARKER
        );
        assert!(decoded.layer::<IkeHeader>().is_some(), "IkeHeader present");
        assert!(decoded.layer::<IkeSaPayload>().is_some(), "SA present");
        assert!(decoded.layer::<IkeKePayload>().is_some(), "KE present");
        assert!(decoded.layer::<IkeNoncePayload>().is_some(), "Ni present");
        // It must NOT have decoded as ESP.
        assert!(
            decoded.layer::<Esp>().is_none(),
            "must not decode the marker+IKE as ESP"
        );

        // The decoded packet re-compiles byte-for-byte.
        let recompiled = decoded.compile().expect("recompile").into_bytes();
        assert_eq!(recompiled, wire, "round-trip must be byte-exact");
    }

    #[test]
    fn udp_4500_nonzero_leading_word_decodes_to_esp_and_round_trips() {
        // RFC 3948 §2.1: a UDP-encapsulated ESP datagram is the ESP packet
        // directly; its leading word is a (nonzero) ESP SPI, so the registry must
        // decode it as ESP, not as IKE.
        let ipv4 = Ipv4::new()
            .protocol(IPPROTO_UDP)
            .src("192.0.2.1".parse().unwrap())
            .dst("192.0.2.2".parse().unwrap());
        let udp = Udp::new().sport(NATT_UDP_PORT).dport(NATT_UDP_PORT);
        // The built-in registry carries no SA, so ESP decodes opaquely: SPI/Seq
        // exposed, the encrypted body preserved verbatim.
        let esp = Esp::new().spi(0x0000_2000).sequence(7);
        let body = Raw::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
        let packet = Packet::from_layer(ipv4) / udp / esp / body;
        let wire = packet.compile().expect("compile NAT-T ESP").into_bytes();

        let decoded =
            Packet::decode_from_l3(NetworkLayer::Ipv4, &wire).expect("decode NAT-T ESP from L3");

        // The UDP payload's nonzero leading word routes to the ESP decoder.
        let esp = decoded
            .layer::<Esp>()
            .expect("UDP-encapsulated ESP decoded");
        assert_eq!(esp.spi_value(), Some(0x0000_2000));
        assert_eq!(esp.sequence_value(), Some(7));
        assert!(esp.opaque_body().is_some());
        // It must NOT have decoded as an IKE message or a NAT-T marker.
        assert!(
            decoded.layer::<IkeHeader>().is_none(),
            "must not decode an ESP SPI as an IKE header"
        );
        assert!(
            decoded.layer::<NatTraversal>().is_none(),
            "an ESP datagram carries no non-ESP marker"
        );

        // The decoded packet re-compiles byte-for-byte.
        let recompiled = decoded.compile().expect("recompile").into_bytes();
        assert_eq!(recompiled, wire, "round-trip must be byte-exact");
    }
}
