//! Packet stack, raw payload layer, and protocol-neutral encode/decode plumbing.

use core::any::Any;
use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};
use core::ops::Div;

use crate::checksum::{ipv4_pseudo_header_checksum, ipv6_pseudo_header_checksum};
use crate::error::Result;
use crate::registry::ProtocolRegistry;

/// Pseudo-header context used by transport layers when auto-filling checksums.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportChecksumContext {
    /// IPv4 pseudo-header checksum inputs.
    Ipv4 {
        /// IPv4 source address.
        source: Ipv4Addr,
        /// IPv4 destination address.
        destination: Ipv4Addr,
        /// IPv4 protocol number encoded in the pseudo-header.
        protocol: u8,
    },
    /// IPv6 pseudo-header checksum inputs.
    Ipv6 {
        /// IPv6 source address.
        source: Ipv6Addr,
        /// IPv6 destination address.
        destination: Ipv6Addr,
        /// IPv6 next-header value encoded in the pseudo-header.
        next_header: u8,
    },
}

impl TransportChecksumContext {
    /// Compute the checksum for an encoded transport segment.
    pub fn checksum(self, transport: &[u8]) -> u16 {
        match self {
            Self::Ipv4 {
                source,
                destination,
                protocol,
            } => ipv4_pseudo_header_checksum(source, destination, protocol, transport),
            Self::Ipv6 {
                source,
                destination,
                next_header,
            } => ipv6_pseudo_header_checksum(source, destination, next_header, transport),
        }
    }
}

/// A protocol or payload layer that can live in a [`Packet`] stack.
///
/// Protocol implementations are expected to encode only their own bytes. The
/// packet compiler provides neighboring layer context so future protocols can
/// fill dependent fields without hidden global state.
pub trait Layer: fmt::Debug + Send + Sync + 'static {
    /// Stable layer name used by summaries and generated tools.
    fn name(&self) -> &'static str;

    /// A one-line layer summary.
    fn summary(&self) -> String {
        self.name().to_string()
    }

    /// Stable field/value pairs used by packet inspection output.
    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    /// Encoded length for this layer before dependent auto-fill.
    fn encoded_len(&self) -> usize;

    /// Encoded length for this layer when neighboring layers affect it.
    fn encoded_len_with_context(&self, _ctx: &LayerContext<'_>) -> usize {
        self.encoded_len()
    }

    /// Encode this layer into `out`.
    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()>;

    /// Return pseudo-header data for a following transport layer, when present.
    fn transport_checksum_context(
        &self,
        _transport_protocol: u8,
    ) -> Option<TransportChecksumContext> {
        None
    }

    /// Clone this layer behind a trait object.
    fn clone_layer(&self) -> Box<dyn Layer>;

    /// Return this layer as [`Any`] for typed packet access.
    fn as_any(&self) -> &dyn Any;

    /// Return this layer mutably as [`Any`] for typed packet access.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    /// Convert an owned trait object into [`Any`] for downcasting.
    fn into_any(self: Box<Self>) -> Box<dyn Any>;
}

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Self {
        self.clone_layer()
    }
}

/// Context supplied to each layer while a packet is being compiled.
#[derive(Debug, Clone, Copy)]
pub struct LayerContext<'a> {
    packet: &'a Packet,
    index: usize,
}

impl<'a> LayerContext<'a> {
    /// Create a compile context for a layer index.
    pub const fn new(packet: &'a Packet, index: usize) -> Self {
        Self { packet, index }
    }

    /// The packet being compiled.
    pub const fn packet(self) -> &'a Packet {
        self.packet
    }

    /// The zero-based index of the layer being compiled.
    pub const fn index(self) -> usize {
        self.index
    }

    /// The previous layer in the packet stack.
    pub fn previous(self) -> Option<&'a dyn Layer> {
        self.index
            .checked_sub(1)
            .and_then(|index| self.packet.get(index))
    }

    /// The next layer in the packet stack.
    pub fn next(self) -> Option<&'a dyn Layer> {
        self.packet.get(self.index + 1)
    }
}

/// Opaque link-layer decode entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkType {
    /// Decode bytes as an unsupported or caller-defined raw link payload.
    Raw,
    /// Ethernet frames.
    Ethernet,
    /// Linux cooked capture frames.
    LinuxCooked,
    /// Linux cooked capture frames.
    LinuxSll,
    /// BSD null/loopback frames.
    NullLoopback,
}

/// Opaque network-layer decode entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkLayer {
    /// Decode bytes as an unsupported or caller-defined raw network payload.
    Raw,
    /// IPv4 packets. Protocol-specific decoding is added in later steps.
    Ipv4,
    /// IPv6 packets. Protocol-specific decoding is added in later steps.
    Ipv6,
}

/// Raw payload bytes or an unsupported decoded tail.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Raw {
    bytes: Vec<u8>,
}

impl Raw {
    /// Create an empty raw layer.
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Create a raw layer by copying bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        Self {
            bytes: bytes.as_ref().to_vec(),
        }
    }

    /// Borrow the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the raw bytes.
    pub fn as_bytes_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    /// Append bytes to this raw layer.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(bytes);
        self
    }

    /// Consume the layer and return its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of raw bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when this raw layer contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return a canonical hex dump of the raw bytes.
    pub fn hexdump(&self) -> String {
        hexdump(self.as_bytes())
    }

    /// Return raw bytes as a lossy UTF-8 string.
    pub fn raw_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }
}

impl Layer for Raw {
    fn name(&self) -> &'static str {
        "Raw"
    }

    fn summary(&self) -> String {
        format!("Raw(len={})", self.bytes.len())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("len", self.bytes.len().to_string()),
            ("bytes", hex_bytes(&self.bytes)),
            ("text_lossy", quoted_lossy_text(self.as_bytes())),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.bytes.len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.bytes);
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

impl From<Vec<u8>> for Raw {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

impl From<&[u8]> for Raw {
    fn from(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl<const N: usize> From<&[u8; N]> for Raw {
    fn from(bytes: &[u8; N]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl<const N: usize> From<[u8; N]> for Raw {
    fn from(bytes: [u8; N]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<&str> for Raw {
    fn from(value: &str) -> Self {
        Self::from_bytes(value.as_bytes())
    }
}

impl From<String> for Raw {
    fn from(value: String) -> Self {
        Self::from_bytes(value.as_bytes())
    }
}

/// Ordered stack of packet layers.
#[derive(Debug, Clone, Default)]
pub struct Packet {
    layers: Vec<Box<dyn Layer>>,
}

impl Packet {
    /// Create an empty packet.
    pub const fn new() -> Self {
        Self { layers: Vec::new() }
    }

    /// Create a packet containing one layer.
    pub fn from_layer<L>(layer: L) -> Self
    where
        L: Layer,
    {
        Self::new().push(layer)
    }

    /// Append a concrete layer and return the packet for builder chaining.
    pub fn push<L>(mut self, layer: L) -> Self
    where
        L: Layer,
    {
        self.layers.push(Box::new(layer));
        self
    }

    /// Append a boxed layer and return the packet for builder chaining.
    pub fn push_box(mut self, layer: Box<dyn Layer>) -> Self {
        self.layers.push(layer);
        self
    }

    /// Mutably append a concrete layer.
    pub fn push_mut<L>(&mut self, layer: L) -> &mut Self
    where
        L: Layer,
    {
        self.layers.push(Box::new(layer));
        self
    }

    /// Mutably append a boxed layer.
    pub fn push_box_mut(&mut self, layer: Box<dyn Layer>) -> &mut Self {
        self.layers.push(layer);
        self
    }

    /// Append all layers from another packet.
    pub fn concat(mut self, other: impl IntoPacket) -> Self {
        self.layers.extend(other.into_packet().layers);
        self
    }

    /// Mutably append all layers from another packet.
    pub fn extend(&mut self, other: impl IntoPacket) -> &mut Self {
        self.layers.extend(other.into_packet().layers);
        self
    }

    /// Remove and return the final layer.
    pub fn pop(&mut self) -> Option<Box<dyn Layer>> {
        self.layers.pop()
    }

    /// Remove and return the final layer when it has type `T`.
    pub fn pop_typed<T>(&mut self) -> Option<T>
    where
        T: Layer,
    {
        let layer = self.pop()?;
        if layer.as_any().is::<T>() {
            let any = layer.into_any();
            Some(*any.downcast::<T>().ok()?)
        } else {
            self.layers.push(layer);
            None
        }
    }

    /// Number of layers in the packet.
    pub fn len(&self) -> usize {
        self.layers.len()
    }

    /// Return true when the packet contains no layers.
    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    /// Return the encoded byte length implied by the current layers.
    pub fn encoded_len(&self) -> usize {
        self.layers
            .iter()
            .enumerate()
            .map(|(index, layer)| {
                let ctx = LayerContext::new(self, index);
                layer.encoded_len_with_context(&ctx)
            })
            .sum()
    }

    /// Positional layer access.
    pub fn get(&self, index: usize) -> Option<&dyn Layer> {
        self.layers.get(index).map(|layer| layer.as_ref())
    }

    /// Mutable positional layer access.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut dyn Layer> {
        self.layers.get_mut(index).map(|layer| layer.as_mut())
    }

    /// First layer of type `T`.
    pub fn layer<T>(&self) -> Option<&T>
    where
        T: Layer,
    {
        self.layers
            .iter()
            .find_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// First mutable layer of type `T`.
    pub fn layer_mut<T>(&mut self) -> Option<&mut T>
    where
        T: Layer,
    {
        self.layers
            .iter_mut()
            .find_map(|layer| layer.as_any_mut().downcast_mut::<T>())
    }

    /// All layers of type `T`, preserving packet order.
    pub fn layers<T>(&self) -> impl Iterator<Item = &T>
    where
        T: Layer,
    {
        self.layers
            .iter()
            .filter_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// All mutable layers of type `T`, preserving packet order.
    pub fn layers_mut<T>(&mut self) -> impl Iterator<Item = &mut T>
    where
        T: Layer,
    {
        self.layers
            .iter_mut()
            .filter_map(|layer| layer.as_any_mut().downcast_mut::<T>())
    }

    /// Ordered layer iteration.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Layer> {
        self.layers.iter().map(|layer| layer.as_ref())
    }

    /// Ordered mutable layer iteration.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut dyn Layer> {
        self.layers.iter_mut().map(|layer| layer.as_mut())
    }

    /// Compile the packet into deterministic bytes.
    pub fn compile(&self) -> Result<CompiledPacket> {
        let mut bytes = Vec::with_capacity(self.encoded_len());
        self.compile_into(&mut bytes)?;
        Ok(CompiledPacket::new(bytes))
    }

    /// Append compiled bytes into an existing buffer.
    pub fn compile_into(&self, out: &mut Vec<u8>) -> Result<()> {
        for (index, layer) in self.layers.iter().enumerate() {
            let ctx = LayerContext::new(self, index);
            layer.compile(&ctx, out)?;
        }
        Ok(())
    }

    /// Decode bytes as raw payload.
    pub fn decode_raw(bytes: impl AsRef<[u8]>) -> Result<Self> {
        Ok(Self::new().push(Raw::from_bytes(bytes)))
    }

    /// Decode bytes from a link-layer entrypoint.
    pub fn decode_from_link(link_type: LinkType, bytes: impl AsRef<[u8]>) -> Result<Self> {
        ProtocolRegistry::new().decode_from_link(link_type, bytes)
    }

    /// Decode bytes from a link-layer entrypoint using an explicit registry.
    pub fn decode_from_link_with_registry(
        registry: &ProtocolRegistry,
        link_type: LinkType,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self> {
        registry.decode_from_link(link_type, bytes)
    }

    /// Decode bytes from a network-layer entrypoint.
    pub fn decode_from_l3(network_layer: NetworkLayer, bytes: impl AsRef<[u8]>) -> Result<Self> {
        ProtocolRegistry::new().decode_from_l3(network_layer, bytes)
    }

    /// Decode bytes from a network-layer entrypoint using an explicit registry.
    pub fn decode_from_l3_with_registry(
        registry: &ProtocolRegistry,
        network_layer: NetworkLayer,
        bytes: impl AsRef<[u8]>,
    ) -> Result<Self> {
        registry.decode_from_l3(network_layer, bytes)
    }

    /// One-line packet summary.
    pub fn summary(&self) -> String {
        if self.layers.is_empty() {
            "Packet(empty)".to_string()
        } else {
            self.layers
                .iter()
                .map(|layer| layer.summary())
                .collect::<Vec<_>>()
                .join(" / ")
        }
    }

    /// Multi-line packet tree intended for display in examples and tools.
    pub fn show(&self) -> String {
        if self.layers.is_empty() {
            return "Packet(empty)".to_string();
        }

        let mut output = format!(
            "Packet(len={}, layers={})",
            self.encoded_len(),
            self.layers.len()
        );
        for (index, layer) in self.layers.iter().enumerate() {
            output.push_str(&format!("\n  [{index}] {}", layer.name()));
            for (name, value) in layer.inspection_fields() {
                output.push_str(&format!("\n      {name}: {value}"));
            }
        }
        output
    }

    /// Compile and return a canonical hex dump.
    pub fn hexdump(&self) -> Result<String> {
        Ok(hexdump(self.compile()?.as_bytes()))
    }

    /// Compile and return raw bytes as a lossy UTF-8 string.
    pub fn raw_string_lossy(&self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.compile()?.as_bytes()).into_owned())
    }
}

/// Conversion into a packet stack used by composition helpers.
pub trait IntoPacket {
    /// Convert this value into a packet.
    fn into_packet(self) -> Packet;
}

impl IntoPacket for Packet {
    fn into_packet(self) -> Packet {
        self
    }
}

impl<T> IntoPacket for T
where
    T: Layer,
{
    fn into_packet(self) -> Packet {
        Packet::from_layer(self)
    }
}

impl IntoPacket for Box<dyn Layer> {
    fn into_packet(self) -> Packet {
        Packet::new().push_box(self)
    }
}

impl<R> Div<R> for Packet
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        self.concat(rhs)
    }
}

impl<R> Div<R> for Raw
where
    R: IntoPacket,
{
    type Output = Packet;

    fn div(self, rhs: R) -> Self::Output {
        Packet::from_layer(self).concat(rhs)
    }
}

/// Compiled packet bytes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CompiledPacket {
    bytes: Vec<u8>,
}

impl CompiledPacket {
    /// Create a compiled packet from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow compiled bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume and return compiled bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of compiled bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when there are no compiled bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return a canonical hex dump.
    pub fn hexdump(&self) -> String {
        hexdump(self.as_bytes())
    }

    /// Return compiled bytes as a lossy UTF-8 string.
    pub fn raw_string_lossy(&self) -> String {
        String::from_utf8_lossy(self.as_bytes()).into_owned()
    }
}

impl AsRef<[u8]> for CompiledPacket {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl core::ops::Deref for CompiledPacket {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_bytes()
    }
}

impl From<CompiledPacket> for Vec<u8> {
    fn from(packet: CompiledPacket) -> Self {
        packet.into_bytes()
    }
}

/// Return a stable hex dump with 16 bytes per line.
pub fn hexdump(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (offset, chunk) in bytes.chunks(16).enumerate() {
        if offset > 0 {
            output.push('\n');
        }

        output.push_str(&format!("{:04x}: ", offset * 16));
        for (index, byte) in chunk.iter().enumerate() {
            if index > 0 {
                output.push(' ');
            }
            output.push_str(&format!("{byte:02x}"));
        }
    }

    output
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::new();

    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{byte:02x}"));
    }

    output
}

fn quoted_lossy_text(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut output = String::from("\"");

    for ch in text.chars() {
        match ch {
            '\0' => output.push_str("\\0"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            ch if ch.is_control() => output.extend(ch.escape_default()),
            ch if ch.is_ascii() => output.push(ch),
            ch => output.extend(ch.escape_default()),
        }
    }

    output.push('"');
    output
}

#[cfg(test)]
mod raw_layer {
    use super::{Layer, Packet, Raw};

    #[test]
    fn raw_layer_preserves_bytes() {
        let raw = Raw::from_bytes(b"hello");

        assert_eq!(raw.name(), "Raw");
        assert_eq!(raw.len(), 5);
        assert_eq!(raw.as_bytes(), b"hello");
        assert_eq!(raw.clone().into_bytes(), b"hello".to_vec());
        assert_eq!(raw.summary(), "Raw(len=5)");
    }

    #[test]
    fn raw_layer_compiles_to_its_payload() {
        let packet = Packet::new().push(Raw::from("hello"));

        assert_eq!(packet.compile().unwrap().as_bytes(), b"hello");
        assert_eq!(packet.raw_string_lossy().unwrap(), "hello");
    }

    #[test]
    fn raw_decode_preserves_unknown_bytes() {
        let decoded = Packet::decode_raw([0xde, 0xad, 0xbe, 0xef]).unwrap();
        let raw = decoded.layer::<Raw>().unwrap();

        assert_eq!(decoded.len(), 1);
        assert_eq!(raw.as_bytes(), [0xde, 0xad, 0xbe, 0xef]);
    }
}

#[cfg(test)]
mod packet_stack {
    use super::{hexdump, Layer, LinkType, NetworkLayer, Packet, Raw};

    #[test]
    fn builder_push_preserves_layer_order() {
        let packet = Packet::new()
            .push(Raw::from("first"))
            .push(Raw::from("second"));

        let layers: Vec<_> = packet.layers::<Raw>().map(Raw::as_bytes).collect();

        assert_eq!(packet.len(), 2);
        assert_eq!(layers, vec![b"first".as_slice(), b"second".as_slice()]);
        assert_eq!(packet.summary(), "Raw(len=5) / Raw(len=6)");
    }

    #[test]
    fn slash_composition_builds_packets() {
        let packet = Raw::from("a") / Raw::from("b") / Packet::new().push(Raw::from("c"));

        assert_eq!(packet.len(), 3);
        assert_eq!(packet.compile().unwrap().as_bytes(), b"abc");
    }

    #[test]
    fn concat_and_pop_keep_stack_predictable() {
        let mut packet = Packet::new()
            .push(Raw::from("a"))
            .concat(Packet::new().push(Raw::from("b")));

        assert_eq!(packet.compile().unwrap().as_bytes(), b"ab");

        let popped = packet.pop_typed::<Raw>().unwrap();

        assert_eq!(popped.as_bytes(), b"b");
        assert_eq!(packet.compile().unwrap().as_bytes(), b"a");
    }

    #[test]
    fn typed_access_supports_mutation_and_ordered_iteration() {
        let mut packet = Packet::new().push(Raw::from("one")).push(Raw::from("two"));

        packet.layer_mut::<Raw>().unwrap().extend_from_slice(b"!");

        let names: Vec<_> = packet.iter().map(Layer::name).collect();
        let bytes: Vec<_> = packet.layers::<Raw>().map(Raw::as_bytes).collect();

        assert_eq!(names, vec!["Raw", "Raw"]);
        assert_eq!(bytes, vec![b"one!".as_slice(), b"two".as_slice()]);
    }

    #[test]
    fn raw_decode_entrypoints_are_lossless_raw_packets() {
        let link = Packet::decode_from_link(LinkType::Raw, b"frame").unwrap();
        let l3 = Packet::decode_from_l3(NetworkLayer::Raw, b"packet").unwrap();

        assert_eq!(link.compile().unwrap().as_bytes(), b"frame");
        assert_eq!(l3.compile().unwrap().as_bytes(), b"packet");
    }

    #[test]
    fn inspection_helpers_are_stable() {
        let packet = Packet::new().push(Raw::from([0x41, 0x42, 0x43].as_slice()));

        assert_eq!(
            packet.show(),
            "Packet(len=3, layers=1)\n  [0] Raw\n      len: 3\n      bytes: 41 42 43\n      text_lossy: \"ABC\""
        );
        assert_eq!(packet.hexdump().unwrap(), "0000: 41 42 43");
        assert_eq!(hexdump(&[]), "");
    }
}

#[cfg(test)]
mod formatting {
    use super::{hexdump, Layer, Packet, Raw};

    const RAW_ONLY_SUMMARY: &str = fixture_str!("summaries/raw-hello-agents.summary.txt");

    fn raw_only_packet() -> Packet {
        Packet::new().push(Raw::from("Hello, agents!"))
    }

    fn raw_only_snapshot() -> String {
        let packet = raw_only_packet();

        format!(
            "summary:\n{}\n\nshow:\n{}\n\nhexdump:\n{}\n\nraw_string_lossy_debug:\n{:?}\n",
            packet.summary(),
            packet.show(),
            packet.hexdump().unwrap(),
            packet.raw_string_lossy().unwrap()
        )
    }

    #[test]
    fn formatting_raw_only_packet_matches_summary_fixture() {
        assert_eq!(raw_only_snapshot(), RAW_ONLY_SUMMARY);
    }

    #[test]
    fn formatting_empty_packet_is_stable() {
        let packet = Packet::new();

        assert_eq!(packet.summary(), "Packet(empty)");
        assert_eq!(packet.show(), "Packet(empty)");
        assert_eq!(packet.hexdump().unwrap(), "");
        assert_eq!(packet.raw_string_lossy().unwrap(), "");
    }

    #[test]
    fn formatting_raw_layer_helpers_are_stable() {
        let raw = Raw::from([0x48, 0x69, 0xff, 0x00].as_slice());

        assert_eq!(raw.summary(), "Raw(len=4)");
        assert_eq!(raw.hexdump(), "0000: 48 69 ff 00");
        assert_eq!(raw.raw_string_lossy(), "Hi\u{fffd}\0");
        assert_eq!(
            raw.inspection_fields(),
            vec![
                ("len", "4".to_string()),
                ("bytes", "48 69 ff 00".to_string()),
                ("text_lossy", "\"Hi\\u{fffd}\\0\"".to_string()),
            ]
        );
    }

    #[test]
    fn formatting_hexdump_chunks_sixteen_bytes_per_line() {
        let bytes: Vec<u8> = (0x00..=0x11).collect();

        assert_eq!(
            hexdump(&bytes),
            "0000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n0010: 10 11"
        );
    }
}
