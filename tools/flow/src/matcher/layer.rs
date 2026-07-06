use crate::{Matcher, PacketContext};

/// Matcher that checks for a typed packet layer and an optional layer predicate.
pub struct LayerMatcher {
    layer_name: &'static str,
    predicate_description: Option<String>,
    predicate: Box<dyn Fn(&crafter::Packet) -> bool>,
}

impl LayerMatcher {
    /// Match packets that contain layer `L`.
    pub fn present<L>() -> Self
    where
        L: crafter::Layer,
    {
        Self {
            layer_name: short_type_name::<L>(),
            predicate_description: None,
            predicate: Box::new(|packet| packet.layer::<L>().is_some()),
        }
    }

    /// Match packets that contain layer `L` and satisfy `predicate`.
    pub fn where_layer<L>(desc: impl Into<String>, predicate: impl Fn(&L) -> bool + 'static) -> Self
    where
        L: crafter::Layer,
    {
        Self {
            layer_name: short_type_name::<L>(),
            predicate_description: Some(desc.into()),
            predicate: Box::new(move |packet| match packet.layer::<L>() {
                Some(layer) => predicate(layer),
                None => false,
            }),
        }
    }
}

impl Matcher for LayerMatcher {
    fn matches(&self, packet: &crafter::Packet, _ctx: &PacketContext) -> bool {
        (self.predicate)(packet)
    }

    fn describe(&self) -> String {
        match &self.predicate_description {
            Some(desc) => format!("{} where {}", self.layer_name, desc),
            None => format!("{} present", self.layer_name),
        }
    }
}

fn short_type_name<L>() -> &'static str {
    let type_name = std::any::type_name::<L>();
    type_name.rsplit("::").next().unwrap_or(type_name)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::{Matcher, PacketContext};

    use super::LayerMatcher;

    fn decoded_udp_packet() -> crafter::Packet {
        let packet = crafter::Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 10))
            .dst(Ipv4Addr::new(198, 51, 100, 20))
            / crafter::Udp::new()
                .source_port(40000)
                .destination_port(40001)
            / crafter::Raw::from("payload");
        let compiled = packet.compile().expect("udp packet should compile");

        crafter::Packet::decode_from_l3(crafter::NetworkLayer::Ipv4, compiled.as_bytes())
            .expect("udp packet should decode")
    }

    #[test]
    fn layer_matcher_matches_udp_layer_and_rejects_absent_layer() {
        let present = LayerMatcher::present::<crafter::Udp>();
        let source_port = LayerMatcher::where_layer::<crafter::Udp>("source port 40000", |udp| {
            udp.source_port_value() == 40000
        });
        let udp_packet = decoded_udp_packet();
        let raw_packet = crafter::Packet::decode_raw([0xde, 0xad, 0xbe, 0xef])
            .expect("raw packet should decode");
        let ctx = PacketContext::new();

        assert!(present.matches(&udp_packet, &ctx));
        assert!(source_port.matches(&udp_packet, &ctx));
        assert!(!present.matches(&raw_packet, &ctx));
        assert!(!source_port.matches(&raw_packet, &ctx));
        assert!(source_port.describe().contains("Udp"));
        assert!(source_port.describe().contains("source port 40000"));
    }
}
