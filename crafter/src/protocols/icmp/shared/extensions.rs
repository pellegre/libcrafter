//! ICMPv4 RFC 4884 multi-part extension structure and its typed extension
//! objects.
//!
//! Extracted verbatim from the original `icmp.rs`; nothing here changes wire
//! behavior, defaults, or the public API surface. This covers the RFC 4884
//! extension header and generic extension object, plus the typed object bodies
//! for RFC 4950 MPLS, RFC 5837 interface information, and RFC 8335 interface
//! identification. Shared compile/auto-fill helpers and codepoints are reached
//! through the `icmp` module root (`use super::super::*;`) and its codepoint
//! constants (`use super::super::constants::*;`); the file now lives under
//! `icmp/shared/`, one level below that root.
use super::super::constants::*;
use super::super::*;

/// RFC 4884 ICMP extension header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtension {
    version: Field<u8>,
    reserved: Field<u16>,
    checksum: Field<u16>,
}

impl IcmpExtension {
    /// Create an ICMP extension header.
    pub fn new() -> Self {
        Self {
            version: Field::defaulted(2),
            reserved: Field::defaulted(0),
            checksum: Field::unset(),
        }
    }

    /// Set the extension version.
    pub fn version(mut self, version: u8) -> Self {
        self.version.set_user(version);
        self
    }

    /// Set the 12-bit reserved field.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Set the extension checksum explicitly.
    pub fn checksum(mut self, checksum: u16) -> Self {
        self.checksum.set_user(checksum);
        self
    }

    /// Version value.
    pub fn version_value(&self) -> u8 {
        value_or_copy(&self.version, 2)
    }

    /// Reserved field value.
    pub fn reserved_value(&self) -> u16 {
        value_or_copy(&self.reserved, 0)
    }

    /// Stored checksum when explicit or decoded.
    pub fn checksum_value(&self) -> Option<u16> {
        self.checksum.value().copied()
    }

    fn validate(&self) -> Result<()> {
        if self.version_value() > 0x0f {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension.version",
                "version must fit in four bits",
            ));
        }
        if self.reserved_value() > 0x0fff {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension.reserved",
                "reserved field must fit in 12 bits",
            ));
        }
        Ok(())
    }
}

impl Default for IcmpExtension {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtension {
    fn name(&self) -> &'static str {
        "IcmpExtension"
    }

    fn summary(&self) -> String {
        format!("IcmpExtension(version={})", self.version_value())
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("version", self.version_value().to_string()),
            ("reserved", format!("0x{:03x}", self.reserved_value())),
            (
                "checksum",
                self.checksum_value()
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_HEADER_LEN
    }

    fn encoded_len_with_context(&self, ctx: &LayerContext<'_>) -> usize {
        // The RFC 4884 zero padding emitted before the extension header is part
        // of this layer's on-wire size, so enclosing length fields (the outer
        // IPv4 total length, for one) count it.
        ICMP_EXTENSION_HEADER_LEN + extension_original_datagram_padding(*ctx)
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        // RFC 4884: the preceding "original datagram" field is zero padded so
        // the extension structure starts at the offset the length field claims.
        // The padding belongs to the original datagram (it is not covered by the
        // extension checksum), so emit it before the extension header.
        let padding = extension_original_datagram_padding(*ctx);
        out.resize(out.len() + padding, 0);

        let mut header = Vec::with_capacity(ICMP_EXTENSION_HEADER_LEN);
        let version_reserved =
            ((self.version_value() as u16) << 12) | (self.reserved_value() & 0x0fff);
        header.extend_from_slice(&version_reserved.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        let payload = payload_bytes_after(*ctx)?;
        let checksum = self.checksum.value().copied().unwrap_or_else(|| {
            let mut bytes = Vec::with_capacity(header.len() + payload.len());
            bytes.extend_from_slice(&header);
            bytes.extend_from_slice(&payload);
            internet_checksum(&bytes)
        });
        header[2..4].copy_from_slice(&checksum.to_be_bytes());
        out.extend_from_slice(&header);
        Ok(())
    }

    impl_layer_object!(IcmpExtension);
}

impl_layer_div!(IcmpExtension);

/// RFC 4884 ICMP extension object header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionObject {
    length: Field<u16>,
    class_num: Field<u8>,
    c_type: Field<u8>,
}

impl IcmpExtensionObject {
    /// Create an extension object header.
    pub fn new() -> Self {
        Self {
            length: Field::unset(),
            class_num: Field::defaulted(0),
            c_type: Field::defaulted(0),
        }
    }

    /// Set the object length explicitly.
    pub fn length(mut self, length: u16) -> Self {
        self.length.set_user(length);
        self
    }

    /// Set the object class number.
    pub fn class_num(mut self, class_num: u8) -> Self {
        self.class_num.set_user(class_num);
        self
    }

    /// Set the object C-Type.
    pub fn c_type(mut self, c_type: u8) -> Self {
        self.c_type.set_user(c_type);
        self
    }

    /// Object length when explicit or decoded.
    pub fn length_value(&self) -> Option<u16> {
        self.length.value().copied()
    }

    /// Object class number.
    pub fn class_num_value(&self) -> u8 {
        value_or_copy(&self.class_num, 0)
    }

    /// Object C-Type.
    pub fn c_type_value(&self) -> u8 {
        value_or_copy(&self.c_type, 0)
    }

    fn effective_length(&self, ctx: LayerContext<'_>) -> Result<u16> {
        if let Some(length) = self.length.value().copied() {
            return Ok(length);
        }

        u16::try_from(ICMP_EXTENSION_OBJECT_LEN + extension_object_payload_len(ctx)).map_err(|_| {
            CrafterError::invalid_field_value(
                "icmp_extension_object.length",
                "extension object length exceeds 65535 bytes",
            )
        })
    }

    fn effective_class_num(&self, next: Option<&dyn Layer>) -> u8 {
        if self.class_num.is_user_set() {
            return self.class_num_value();
        }
        if next
            .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CLASS_MPLS
        } else if next
            .map(|layer| layer.as_any().is::<IcmpExtensionInterfaceInfo>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CLASS_INTERFACE_INFO
        } else if next
            .map(|layer| layer.as_any().is::<IcmpExtensionInterfaceId>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CLASS_INTERFACE_ID
        } else {
            self.class_num_value()
        }
    }

    fn effective_c_type(&self, next: Option<&dyn Layer>) -> u8 {
        if self.c_type.is_user_set() {
            return self.c_type_value();
        }
        if next
            .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
            .unwrap_or(false)
        {
            ICMP_EXTENSION_CTYPE_MPLS_INCOMING
        } else if let Some(info) =
            next.and_then(|layer| layer.as_any().downcast_ref::<IcmpExtensionInterfaceInfo>())
        {
            info.c_type_byte()
        } else if let Some(id) =
            next.and_then(|layer| layer.as_any().downcast_ref::<IcmpExtensionInterfaceId>())
        {
            id.c_type()
        } else {
            self.c_type_value()
        }
    }
}

impl Default for IcmpExtensionObject {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionObject {
    fn name(&self) -> &'static str {
        "IcmpExtensionObject"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpExtensionObject(class={}, ctype={})",
            self.class_num_value(),
            self.c_type_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "length",
                self.length_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("class_num", self.class_num_value().to_string()),
            ("c_type", self.c_type_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_OBJECT_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.effective_length(*ctx)?.to_be_bytes());
        out.push(self.effective_class_num(ctx.next()));
        out.push(self.effective_c_type(ctx.next()));
        Ok(())
    }

    impl_layer_object!(IcmpExtensionObject);
}

impl_layer_div!(IcmpExtensionObject);

/// MPLS label stack entry for ICMP extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionMpls {
    label: Field<u32>,
    experimental: Field<u8>,
    bottom_of_stack: Field<bool>,
    ttl: Field<u8>,
}

impl IcmpExtensionMpls {
    /// Create an MPLS extension entry.
    pub fn new() -> Self {
        Self {
            label: Field::defaulted(0),
            experimental: Field::defaulted(0),
            bottom_of_stack: Field::unset(),
            ttl: Field::defaulted(0),
        }
    }

    /// Set the MPLS label.
    pub fn label(mut self, label: u32) -> Self {
        self.label.set_user(label);
        self
    }

    /// Set the experimental bits.
    pub fn experimental(mut self, experimental: u8) -> Self {
        self.experimental.set_user(experimental);
        self
    }

    /// Alias for the experimental bits.
    pub fn exp(self, experimental: u8) -> Self {
        self.experimental(experimental)
    }

    /// Set the bottom-of-stack bit explicitly.
    pub fn bottom_of_stack(mut self, bottom_of_stack: bool) -> Self {
        self.bottom_of_stack.set_user(bottom_of_stack);
        self
    }

    /// Set the MPLS TTL.
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.ttl.set_user(ttl);
        self
    }

    /// MPLS label value.
    pub fn label_value(&self) -> u32 {
        value_or_copy(&self.label, 0)
    }

    /// Experimental bits value.
    pub fn experimental_value(&self) -> u8 {
        value_or_copy(&self.experimental, 0)
    }

    /// Stored bottom-of-stack bit when explicit or decoded.
    pub fn bottom_of_stack_value(&self) -> Option<bool> {
        self.bottom_of_stack.value().copied()
    }

    /// MPLS TTL value.
    pub fn ttl_value(&self) -> u8 {
        value_or_copy(&self.ttl, 0)
    }

    fn effective_bottom_of_stack(&self, next: Option<&dyn Layer>) -> bool {
        self.bottom_of_stack.value().copied().unwrap_or_else(|| {
            !next
                .map(|layer| layer.as_any().is::<IcmpExtensionMpls>())
                .unwrap_or(false)
        })
    }

    fn validate(&self) -> Result<()> {
        if self.label_value() > MPLS_MAX_LABEL {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension_mpls.label",
                "MPLS label must fit in 20 bits",
            ));
        }
        if self.experimental_value() > MPLS_MAX_EXP {
            return Err(CrafterError::invalid_field_value(
                "icmp_extension_mpls.experimental",
                "MPLS experimental field must fit in three bits",
            ));
        }
        Ok(())
    }
}

impl Default for IcmpExtensionMpls {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionMpls {
    fn name(&self) -> &'static str {
        "IcmpExtensionMpls"
    }

    fn summary(&self) -> String {
        format!(
            "IcmpExtensionMpls(label={}, ttl={})",
            self.label_value(),
            self.ttl_value()
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("label", self.label_value().to_string()),
            ("experimental", self.experimental_value().to_string()),
            (
                "bottom_of_stack",
                self.bottom_of_stack_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("ttl", self.ttl_value().to_string()),
        ]
    }

    fn encoded_len(&self) -> usize {
        ICMP_EXTENSION_MPLS_LEN
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;

        let word = (self.label_value() << 12)
            | ((self.experimental_value() as u32) << 9)
            | ((self.effective_bottom_of_stack(ctx.next()) as u32) << 8)
            | self.ttl_value() as u32;
        out.extend_from_slice(&word.to_be_bytes());
        Ok(())
    }

    impl_layer_object!(IcmpExtensionMpls);
}

impl_layer_div!(IcmpExtensionMpls);

/// RFC 5837 IP Address sub-object carried inside an interface information
/// object: a 16-bit Address Family Identifier, a 16-bit reserved field, and the
/// address bytes (4 for IPv4, 16 for IPv6). The address is kept as raw bytes so
/// unknown AFIs and non-canonical reserved values round-trip byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpInterfaceIpAddress {
    afi: Field<u16>,
    reserved: Field<u16>,
    address: Vec<u8>,
}

impl IcmpInterfaceIpAddress {
    /// Build an IPv4 IP Address sub-object.
    pub fn ipv4(address: Ipv4Addr) -> Self {
        Self {
            afi: Field::user(ICMP_INTERFACE_AFI_IPV4),
            reserved: Field::defaulted(0),
            address: address.octets().to_vec(),
        }
    }

    /// Build an IPv6 IP Address sub-object.
    pub fn ipv6(address: core::net::Ipv6Addr) -> Self {
        Self {
            afi: Field::user(ICMP_INTERFACE_AFI_IPV6),
            reserved: Field::defaulted(0),
            address: address.octets().to_vec(),
        }
    }

    /// Build an IP Address sub-object from a raw AFI and address bytes, the
    /// escape hatch for unknown or malformed address families.
    pub fn raw(afi: u16, address: impl Into<Vec<u8>>) -> Self {
        Self {
            afi: Field::user(afi),
            reserved: Field::defaulted(0),
            address: address.into(),
        }
    }

    /// Set the 16-bit reserved field explicitly.
    pub fn reserved(mut self, reserved: u16) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Address Family Identifier value.
    pub fn afi_value(&self) -> u16 {
        value_or_copy(&self.afi, 0)
    }

    /// Reserved field value.
    pub fn reserved_value(&self) -> u16 {
        value_or_copy(&self.reserved, 0)
    }

    /// Raw address bytes.
    pub fn address_bytes(&self) -> &[u8] {
        &self.address
    }

    /// Address as an [`Ipv4Addr`] when the AFI is IPv4 and four bytes follow.
    pub fn ipv4_value(&self) -> Option<Ipv4Addr> {
        if self.afi_value() == ICMP_INTERFACE_AFI_IPV4 && self.address.len() == 4 {
            Some(Ipv4Addr::new(
                self.address[0],
                self.address[1],
                self.address[2],
                self.address[3],
            ))
        } else {
            None
        }
    }

    /// Address as an [`Ipv6Addr`](core::net::Ipv6Addr) when the AFI is IPv6 and
    /// sixteen bytes follow.
    pub fn ipv6_value(&self) -> Option<core::net::Ipv6Addr> {
        if self.afi_value() == ICMP_INTERFACE_AFI_IPV6 && self.address.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.address);
            Some(core::net::Ipv6Addr::from(octets))
        } else {
            None
        }
    }

    fn encoded_len(&self) -> usize {
        ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN + self.address.len()
    }

    fn compile(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.afi_value().to_be_bytes());
        out.extend_from_slice(&self.reserved_value().to_be_bytes());
        out.extend_from_slice(&self.address);
    }
}

/// RFC 5837 ICMP extension object carrying interface information.
///
/// The single object holds an interface role (RFC 5837 figure 1, C-Type bits
/// 0-1), a two-bit reserved field (bits 2-3), and up to four optional
/// sub-objects in their mandatory order: a 32-bit `ifIndex`, an
/// [`IcmpInterfaceIpAddress`], an interface name, and a 32-bit MTU. The C-Type
/// presence bits (4-7) are derived from which sub-objects are present, so the
/// preceding [`IcmpExtensionObject`] auto-fills class 2 and the matching C-Type
/// byte. Unknown or malformed bodies stay raw through the generic object path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionInterfaceInfo {
    role: Field<u8>,
    reserved: Field<u8>,
    if_index: Option<u32>,
    ip_address: Option<IcmpInterfaceIpAddress>,
    name: Option<Vec<u8>>,
    mtu: Option<u32>,
}

impl IcmpExtensionInterfaceInfo {
    /// Create an interface information object with the incoming-interface role
    /// and no sub-objects.
    pub fn new() -> Self {
        Self {
            role: Field::defaulted(ICMP_INTERFACE_ROLE_INCOMING),
            reserved: Field::defaulted(0),
            if_index: None,
            ip_address: None,
            name: None,
            mtu: None,
        }
    }

    /// Set the two-bit interface role (RFC 5837 C-Type bits 0-1).
    pub fn role(mut self, role: u8) -> Self {
        self.role.set_user(role);
        self
    }

    /// Set the two-bit reserved field (RFC 5837 C-Type bits 2-3).
    pub fn reserved(mut self, reserved: u8) -> Self {
        self.reserved.set_user(reserved);
        self
    }

    /// Include the 32-bit ifIndex sub-object.
    pub fn if_index(mut self, if_index: u32) -> Self {
        self.if_index = Some(if_index);
        self
    }

    /// Include the IP Address sub-object.
    pub fn ip_address(mut self, ip_address: IcmpInterfaceIpAddress) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    /// Include the Interface Name sub-object from raw name octets (UTF-8 per
    /// RFC 5837, but bytes are preserved verbatim and zero padded on the wire).
    pub fn name_bytes(mut self, name: impl Into<Vec<u8>>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Include the Interface Name sub-object from a string.
    pub fn name(self, name: &str) -> Self {
        self.name_bytes(name.as_bytes().to_vec())
    }

    /// Include the 32-bit MTU sub-object.
    pub fn mtu(mut self, mtu: u32) -> Self {
        self.mtu = Some(mtu);
        self
    }

    /// Interface role value (C-Type bits 0-1).
    pub fn role_value(&self) -> u8 {
        value_or_copy(&self.role, ICMP_INTERFACE_ROLE_INCOMING)
    }

    /// Reserved field value (C-Type bits 2-3).
    pub fn reserved_value(&self) -> u8 {
        value_or_copy(&self.reserved, 0)
    }

    /// ifIndex sub-object value, if present.
    pub fn if_index_value(&self) -> Option<u32> {
        self.if_index
    }

    /// IP Address sub-object, if present.
    pub fn ip_address_value(&self) -> Option<&IcmpInterfaceIpAddress> {
        self.ip_address.as_ref()
    }

    /// Interface name octets, if present.
    pub fn name_value(&self) -> Option<&[u8]> {
        self.name.as_deref()
    }

    /// MTU sub-object value, if present.
    pub fn mtu_value(&self) -> Option<u32> {
        self.mtu
    }

    /// RFC 5837 C-Type byte: role in bits 0-1, reserved in bits 2-3, and one
    /// presence bit per included sub-object in bits 4-7.
    pub fn c_type_byte(&self) -> u8 {
        let mut byte = ((self.role_value() & 0x03) << 6) | ((self.reserved_value() & 0x03) << 4);
        if self.if_index.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_IFINDEX;
        }
        if self.ip_address.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_IP_ADDRESS;
        }
        if self.name.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_NAME;
        }
        if self.mtu.is_some() {
            byte |= ICMP_INTERFACE_CTYPE_MTU;
        }
        byte
    }

    /// On-wire length of the interface name sub-object (length octet plus name
    /// octets, zero padded to a 4-octet boundary), when a name is present.
    fn name_encoded_len(&self) -> usize {
        self.name
            .as_ref()
            .map(|name| {
                let raw = 1 + name.len();
                raw.div_ceil(4) * 4
            })
            .unwrap_or(0)
    }

    fn validate(&self) -> Result<()> {
        if self.role_value() > 0x03 {
            return Err(CrafterError::invalid_field_value(
                "icmp_interface_info.role",
                "interface role must fit in two bits",
            ));
        }
        if self.reserved_value() > 0x03 {
            return Err(CrafterError::invalid_field_value(
                "icmp_interface_info.reserved",
                "interface reserved field must fit in two bits",
            ));
        }
        if let Some(name) = &self.name {
            if name.len() > ICMP_INTERFACE_NAME_MAX {
                return Err(CrafterError::invalid_field_value(
                    "icmp_interface_info.name",
                    "interface name must not exceed 63 octets",
                ));
            }
        }
        Ok(())
    }
}

impl Default for IcmpExtensionInterfaceInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for IcmpExtensionInterfaceInfo {
    fn name(&self) -> &'static str {
        "IcmpExtensionInterfaceInfo"
    }

    fn summary(&self) -> String {
        let mut parts = vec![format!(
            "role={}",
            interface_role_summary(self.role_value())
        )];
        if let Some(if_index) = self.if_index {
            parts.push(format!("ifindex={if_index}"));
        }
        if let Some(ip) = &self.ip_address {
            let rendered = ip
                .ipv4_value()
                .map(|addr| addr.to_string())
                .or_else(|| ip.ipv6_value().map(|addr| addr.to_string()))
                .unwrap_or_else(|| {
                    format!("afi={} {}", ip.afi_value(), hex_bytes(ip.address_bytes()))
                });
            parts.push(format!("ip={rendered}"));
        }
        if let Some(name) = &self.name {
            parts.push(format!("name={}", String::from_utf8_lossy(name)));
        }
        if let Some(mtu) = self.mtu {
            parts.push(format!("mtu={mtu}"));
        }
        format!("IcmpExtensionInterfaceInfo({})", parts.join(", "))
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("role", interface_role_summary(self.role_value())),
            ("reserved", self.reserved_value().to_string()),
            ("c_type", format!("0x{:02x}", self.c_type_byte())),
            (
                "if_index",
                self.if_index
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "ip_address",
                self.ip_address
                    .as_ref()
                    .map(|ip| {
                        ip.ipv4_value()
                            .map(|addr| addr.to_string())
                            .or_else(|| ip.ipv6_value().map(|addr| addr.to_string()))
                            .unwrap_or_else(|| {
                                format!("afi={} {}", ip.afi_value(), hex_bytes(ip.address_bytes()))
                            })
                    })
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "name",
                self.name
                    .as_ref()
                    .map(|name| String::from_utf8_lossy(name).into_owned())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "mtu",
                self.mtu
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        let mut len = 0;
        if self.if_index.is_some() {
            len += ICMP_INTERFACE_IFINDEX_LEN;
        }
        if let Some(ip) = &self.ip_address {
            len += ip.encoded_len();
        }
        len += self.name_encoded_len();
        if self.mtu.is_some() {
            len += ICMP_INTERFACE_MTU_LEN;
        }
        len
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        if let Some(if_index) = self.if_index {
            out.extend_from_slice(&if_index.to_be_bytes());
        }
        if let Some(ip) = &self.ip_address {
            ip.compile(out);
        }
        if let Some(name) = &self.name {
            // RFC 5837: a one-octet length (covering itself plus the name) leads
            // the name, which is then zero padded to a 4-octet boundary.
            let padded = self.name_encoded_len();
            out.push((1 + name.len()) as u8);
            out.extend_from_slice(name);
            out.resize(out.len() + (padded - 1 - name.len()), 0);
        }
        if let Some(mtu) = self.mtu {
            out.extend_from_slice(&mtu.to_be_bytes());
        }
        Ok(())
    }

    impl_layer_object!(IcmpExtensionInterfaceInfo);
}

impl_layer_div!(IcmpExtensionInterfaceInfo);

/// RFC 8335 Interface Identification Object body (extension object class 3).
///
/// The object identifies the probed interface in exactly one of three ways,
/// selected by the C-Type of the preceding [`IcmpExtensionObject`]:
///
/// - C-Type 1 (by name): the interface name (RFC 7223) zero padded to a 32-bit
///   boundary.
/// - C-Type 2 (by index): a 32-bit ifIndex.
/// - C-Type 3 (by address): a 16-bit AFI, an 8-bit address length, an 8-bit
///   reserved field, and the address bytes zero padded to a 32-bit boundary.
///
/// The form is kept as a typed body so the object's C-Type auto-fills from which
/// constructor was used, and so decode can surface each form's fields. A `raw`
/// escape hatch carries an explicit C-Type and arbitrary body bytes for crafting
/// objects the typed forms do not cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpExtensionInterfaceId {
    body: InterfaceIdBody,
}

/// The selected RFC 8335 Interface Identification Object form.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InterfaceIdBody {
    /// C-Type 1: interface name, zero padded to a 32-bit boundary on the wire.
    Name(Vec<u8>),
    /// C-Type 2: a 32-bit ifIndex.
    Index(u32),
    /// C-Type 3: AFI, an explicit address length, reserved byte, and address.
    Address {
        afi: u16,
        address_length: u8,
        reserved: u8,
        address: Vec<u8>,
    },
    /// An explicit C-Type plus raw body bytes (escape hatch). The bytes are
    /// emitted verbatim without padding so deliberately malformed objects survive.
    Raw { c_type: u8, bytes: Vec<u8> },
}

impl IcmpExtensionInterfaceId {
    /// Identify the interface by name (RFC 8335 C-Type 1).
    pub fn by_name(name: &str) -> Self {
        Self::by_name_bytes(name.as_bytes().to_vec())
    }

    /// Identify the interface by raw name octets (RFC 8335 C-Type 1). The octets
    /// are zero padded to a 32-bit boundary on the wire.
    pub fn by_name_bytes(name: impl Into<Vec<u8>>) -> Self {
        Self {
            body: InterfaceIdBody::Name(name.into()),
        }
    }

    /// Identify the interface by a 32-bit ifIndex (RFC 8335 C-Type 2).
    pub fn by_index(if_index: u32) -> Self {
        Self {
            body: InterfaceIdBody::Index(if_index),
        }
    }

    /// Identify the interface by IPv4 address (RFC 8335 C-Type 3).
    pub fn by_ipv4(address: Ipv4Addr) -> Self {
        Self::by_address(ICMP_INTERFACE_AFI_IPV4, address.octets())
    }

    /// Identify the interface by IPv6 address (RFC 8335 C-Type 3).
    pub fn by_ipv6(address: core::net::Ipv6Addr) -> Self {
        Self::by_address(ICMP_INTERFACE_AFI_IPV6, address.octets())
    }

    /// Identify the interface by a raw AFI and address bytes (RFC 8335 C-Type 3).
    ///
    /// The address length defaults to the number of address bytes; the address
    /// is zero padded to a 32-bit boundary on the wire.
    pub fn by_address(afi: u16, address: impl Into<Vec<u8>>) -> Self {
        let address = address.into();
        let address_length = address.len() as u8;
        Self {
            body: InterfaceIdBody::Address {
                afi,
                address_length,
                reserved: 0,
                address,
            },
        }
    }

    /// Build an object with an explicit C-Type and raw body bytes, the escape
    /// hatch for crafting objects the typed forms do not cover. The bytes are
    /// emitted verbatim (no padding).
    pub fn raw(c_type: u8, bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            body: InterfaceIdBody::Raw {
                c_type,
                bytes: bytes.into(),
            },
        }
    }

    /// Override the C-Type 3 address length field (the count of significant
    /// address bytes) explicitly, the escape hatch for deliberately mismatched
    /// lengths. Has no effect on the other forms.
    pub fn address_length(mut self, address_length: u8) -> Self {
        if let InterfaceIdBody::Address {
            address_length: slot,
            ..
        } = &mut self.body
        {
            *slot = address_length;
        }
        self
    }

    /// Override the C-Type 3 reserved byte explicitly. Has no effect on the other
    /// forms.
    pub fn reserved(mut self, reserved: u8) -> Self {
        if let InterfaceIdBody::Address { reserved: slot, .. } = &mut self.body {
            *slot = reserved;
        }
        self
    }

    /// RFC 8335 C-Type for the selected form.
    pub fn c_type(&self) -> u8 {
        match &self.body {
            InterfaceIdBody::Name(_) => ICMP_INTERFACE_ID_CTYPE_NAME,
            InterfaceIdBody::Index(_) => ICMP_INTERFACE_ID_CTYPE_INDEX,
            InterfaceIdBody::Address { .. } => ICMP_INTERFACE_ID_CTYPE_ADDRESS,
            InterfaceIdBody::Raw { c_type, .. } => *c_type,
        }
    }

    /// Interface name octets (C-Type 1), if this is a name object.
    pub fn name_value(&self) -> Option<&[u8]> {
        match &self.body {
            InterfaceIdBody::Name(name) => Some(name),
            _ => None,
        }
    }

    /// ifIndex (C-Type 2), if this is an index object.
    pub fn index_value(&self) -> Option<u32> {
        match &self.body {
            InterfaceIdBody::Index(index) => Some(*index),
            _ => None,
        }
    }

    /// Address Family Identifier (C-Type 3), if this is an address object.
    pub fn afi_value(&self) -> Option<u16> {
        match &self.body {
            InterfaceIdBody::Address { afi, .. } => Some(*afi),
            _ => None,
        }
    }

    /// Address bytes (C-Type 3), if this is an address object.
    pub fn address_bytes(&self) -> Option<&[u8]> {
        match &self.body {
            InterfaceIdBody::Address { address, .. } => Some(address),
            _ => None,
        }
    }

    /// Address length field (C-Type 3), if this is an address object.
    pub fn address_length_value(&self) -> Option<u8> {
        match &self.body {
            InterfaceIdBody::Address { address_length, .. } => Some(*address_length),
            _ => None,
        }
    }

    /// Address as an [`Ipv4Addr`] when this is an IPv4 address object.
    pub fn ipv4_value(&self) -> Option<Ipv4Addr> {
        match &self.body {
            InterfaceIdBody::Address { afi, address, .. }
                if *afi == ICMP_INTERFACE_AFI_IPV4 && address.len() == 4 =>
            {
                Some(Ipv4Addr::new(
                    address[0], address[1], address[2], address[3],
                ))
            }
            _ => None,
        }
    }

    /// Address as an [`Ipv6Addr`](core::net::Ipv6Addr) when this is an IPv6
    /// address object.
    pub fn ipv6_value(&self) -> Option<core::net::Ipv6Addr> {
        match &self.body {
            InterfaceIdBody::Address { afi, address, .. }
                if *afi == ICMP_INTERFACE_AFI_IPV6 && address.len() == 16 =>
            {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(address);
                Some(core::net::Ipv6Addr::from(octets))
            }
            _ => None,
        }
    }

    /// Raw escape-hatch body bytes, if this object was built with [`Self::raw`].
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        match &self.body {
            InterfaceIdBody::Raw { bytes, .. } => Some(bytes),
            _ => None,
        }
    }
}

impl Layer for IcmpExtensionInterfaceId {
    fn name(&self) -> &'static str {
        "IcmpExtensionInterfaceId"
    }

    fn summary(&self) -> String {
        let detail = match &self.body {
            InterfaceIdBody::Name(name) => {
                format!("name={}", String::from_utf8_lossy(name))
            }
            InterfaceIdBody::Index(index) => format!("ifindex={index}"),
            InterfaceIdBody::Address { afi, address, .. } => {
                if let Some(addr) = self.ipv4_value() {
                    format!("address={addr}")
                } else if let Some(addr) = self.ipv6_value() {
                    format!("address={addr}")
                } else {
                    format!("address=afi={afi} {}", hex_bytes(address))
                }
            }
            InterfaceIdBody::Raw { c_type, bytes } => {
                format!("ctype={c_type} raw={}", hex_bytes(bytes))
            }
        };
        format!("IcmpExtensionInterfaceId({detail})")
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("c_type", self.c_type().to_string()),
            (
                "name",
                self.name_value()
                    .map(|name| String::from_utf8_lossy(name).into_owned())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "index",
                self.index_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "afi",
                self.afi_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            ),
            (
                "address",
                self.address_bytes()
                    .map(hex_bytes)
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ]
    }

    fn encoded_len(&self) -> usize {
        match &self.body {
            InterfaceIdBody::Name(name) => name.len().div_ceil(4) * 4,
            InterfaceIdBody::Index(_) => ICMP_INTERFACE_ID_INDEX_LEN,
            InterfaceIdBody::Address { address, .. } => {
                ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN + address.len().div_ceil(4) * 4
            }
            InterfaceIdBody::Raw { bytes, .. } => bytes.len(),
        }
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        match &self.body {
            InterfaceIdBody::Name(name) => {
                let padded = name.len().div_ceil(4) * 4;
                out.extend_from_slice(name);
                out.resize(out.len() + (padded - name.len()), 0);
            }
            InterfaceIdBody::Index(index) => {
                out.extend_from_slice(&index.to_be_bytes());
            }
            InterfaceIdBody::Address {
                afi,
                address_length,
                reserved,
                address,
            } => {
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*address_length);
                out.push(*reserved);
                let padded = address.len().div_ceil(4) * 4;
                out.extend_from_slice(address);
                out.resize(out.len() + (padded - address.len()), 0);
            }
            InterfaceIdBody::Raw { bytes, .. } => {
                out.extend_from_slice(bytes);
            }
        }
        Ok(())
    }

    impl_layer_object!(IcmpExtensionInterfaceId);
}

impl_layer_div!(IcmpExtensionInterfaceId);

/// Decode a single RFC 4950 MPLS label stack entry (4 octets) into a typed
/// [`IcmpExtensionMpls`] layer.
///
/// The 32-bit word packs a 20-bit label, a 3-bit experimental/traffic-class
/// field, a 1-bit bottom-of-stack flag, and an 8-bit TTL. Every field is set as
/// a user value — including the bottom-of-stack bit — so a re-compile reproduces
/// the exact bits even when the decoded stack is non-canonical (for example a
/// set bottom-of-stack bit that is not on the final entry).
pub(crate) fn decode_mpls_entry(chunk: &[u8]) -> IcmpExtensionMpls {
    let word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    let label = word >> 12;
    let experimental = ((word >> 9) & 0x07) as u8;
    let bottom_of_stack = (word >> 8) & 0x01 == 1;
    let ttl = (word & 0xff) as u8;
    IcmpExtensionMpls {
        label: Field::user(label),
        experimental: Field::user(experimental),
        bottom_of_stack: Field::user(bottom_of_stack),
        ttl: Field::user(ttl),
    }
}

/// Decode an RFC 5837 interface information object body into a typed
/// [`IcmpExtensionInterfaceInfo`] layer.
///
/// The C-Type byte drives which sub-objects are present (bits 0-1 role, bits
/// 2-3 reserved, bits 4-7 ifIndex/IP-address/name/MTU). Sub-objects are parsed
/// in their mandatory order and must consume the body exactly, with canonical
/// (zero) name padding, so a re-compile reproduces the bytes. Any short,
/// trailing, or non-canonical body returns `None` so the caller keeps the
/// region as raw bytes and decoding never panics.
pub(crate) fn decode_interface_info(
    c_type: u8,
    mut body: &[u8],
) -> Option<IcmpExtensionInterfaceInfo> {
    let role = (c_type >> 6) & 0x03;
    let reserved = (c_type >> 4) & 0x03;
    let mut info = IcmpExtensionInterfaceInfo {
        role: Field::user(role),
        reserved: Field::user(reserved),
        if_index: None,
        ip_address: None,
        name: None,
        mtu: None,
    };

    if c_type & ICMP_INTERFACE_CTYPE_IFINDEX != 0 {
        if body.len() < ICMP_INTERFACE_IFINDEX_LEN {
            return None;
        }
        info.if_index = Some(u32::from_be_bytes(copy_array_4(
            &body[..ICMP_INTERFACE_IFINDEX_LEN],
        )));
        body = &body[ICMP_INTERFACE_IFINDEX_LEN..];
    }

    if c_type & ICMP_INTERFACE_CTYPE_IP_ADDRESS != 0 {
        if body.len() < ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN {
            return None;
        }
        let afi = u16::from_be_bytes([body[0], body[1]]);
        let reserved16 = u16::from_be_bytes([body[2], body[3]]);
        // Only AFIs with a fixed address width can be split unambiguously from
        // any following name/MTU sub-objects; unknown AFIs stay raw.
        let addr_len = match afi {
            ICMP_INTERFACE_AFI_IPV4 => 4,
            ICMP_INTERFACE_AFI_IPV6 => 16,
            _ => return None,
        };
        let total = ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN + addr_len;
        if body.len() < total {
            return None;
        }
        info.ip_address = Some(IcmpInterfaceIpAddress {
            afi: Field::user(afi),
            reserved: Field::user(reserved16),
            address: body[ICMP_INTERFACE_IP_ADDRESS_PREFIX_LEN..total].to_vec(),
        });
        body = &body[total..];
    }

    if c_type & ICMP_INTERFACE_CTYPE_NAME != 0 {
        if body.is_empty() {
            return None;
        }
        let length = body[0] as usize;
        // The length octet covers itself plus the name; the name is then padded
        // to a 4-octet boundary. Reject lengths that do not fit or exceed the
        // 64-octet ceiling.
        if length < 1 || length > body.len() {
            return None;
        }
        let name_len = length - 1;
        if name_len > ICMP_INTERFACE_NAME_MAX {
            return None;
        }
        let padded = length.div_ceil(4) * 4;
        if padded > body.len() {
            return None;
        }
        // Only canonical zero padding round-trips through compile.
        if body[length..padded].iter().any(|&byte| byte != 0) {
            return None;
        }
        info.name = Some(body[1..length].to_vec());
        body = &body[padded..];
    }

    if c_type & ICMP_INTERFACE_CTYPE_MTU != 0 {
        if body.len() < ICMP_INTERFACE_MTU_LEN {
            return None;
        }
        info.mtu = Some(u32::from_be_bytes(copy_array_4(
            &body[..ICMP_INTERFACE_MTU_LEN],
        )));
        body = &body[ICMP_INTERFACE_MTU_LEN..];
    }

    // Sub-objects must consume the body exactly so the typed layer round-trips.
    if !body.is_empty() {
        return None;
    }

    Some(info)
}

/// Decode an RFC 8335 Interface Identification Object body into a typed
/// [`IcmpExtensionInterfaceId`] layer.
///
/// The object's C-Type selects the form: name (1), index (2), or address (3).
/// Each form must consume the whole body exactly with canonical (zero) padding
/// so a re-compile reproduces the bytes; anything else — an unknown C-Type, a
/// mismatched length, non-canonical padding, or an unknown-width address AFI —
/// returns `None` so the caller keeps the body as raw bytes and decoding never
/// panics.
pub(crate) fn decode_interface_id(c_type: u8, body: &[u8]) -> Option<IcmpExtensionInterfaceId> {
    match c_type {
        ICMP_INTERFACE_ID_CTYPE_NAME => {
            // The name is zero padded to a 32-bit boundary; reject a body whose
            // length is not a whole number of words or whose padding is not zero.
            if body.is_empty() || body.len() % 4 != 0 {
                return None;
            }
            // RFC 7223 names are NUL-padded; the name is the leading non-NUL run,
            // and every trailing byte after the first NUL must be NUL so the
            // padded form round-trips through compile.
            let name_len = body
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(body.len());
            if body[name_len..].iter().any(|&byte| byte != 0) {
                return None;
            }
            // Reject names whose unpadded length would re-pad to a different size
            // (only canonical minimal padding round-trips).
            if name_len.div_ceil(4) * 4 != body.len() {
                return None;
            }
            Some(IcmpExtensionInterfaceId::by_name_bytes(
                body[..name_len].to_vec(),
            ))
        }
        ICMP_INTERFACE_ID_CTYPE_INDEX => {
            if body.len() != ICMP_INTERFACE_ID_INDEX_LEN {
                return None;
            }
            Some(IcmpExtensionInterfaceId::by_index(u32::from_be_bytes(
                copy_array_4(body),
            )))
        }
        ICMP_INTERFACE_ID_CTYPE_ADDRESS => {
            if body.len() < ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN {
                return None;
            }
            let afi = u16::from_be_bytes([body[0], body[1]]);
            let address_length = body[2];
            let reserved = body[3];
            let address = &body[ICMP_INTERFACE_ID_ADDRESS_PREFIX_LEN..];
            // The significant address length must fit the padded address region
            // and re-pad to exactly the body length so a re-compile reproduces it.
            let significant = address_length as usize;
            if significant > address.len() || significant.div_ceil(4) * 4 != address.len() {
                return None;
            }
            // Only canonical zero padding past the significant address bytes
            // round-trips through compile.
            if address[significant..].iter().any(|&byte| byte != 0) {
                return None;
            }
            Some(
                IcmpExtensionInterfaceId::by_address(afi, address[..significant].to_vec())
                    .reserved(reserved),
            )
        }
        _ => None,
    }
}

#[cfg(test)]
mod icmpv4_rfc4884_extensions {
    use super::{
        IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpQuotedIpv4, Icmpv4,
        ICMP_EXTENSION_HEADER_LEN, ICMP_PARAMETER_PROBLEM, ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM,
    };
    use crate::checksum::verify_internet_checksum;
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // The standard 32-byte quoted datagram (IPv4 + UDP + payload) an agent would
    // attach to an error message.
    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // The first byte of the ICMP body after the 20-byte IPv4 header sits at
    // offset 28; the RFC 4884 length field is the ICMP rest-of-header byte 1.
    const ICMP_BODY_START: usize = 28;
    const RFC4884_LENGTH_BYTE: usize = 25;

    // A time-exceeded message that quotes a short datagram and appends an
    // extension structure auto-fills the RFC 4884 length field, measured in
    // 32-bit words of the *padded* original datagram (128 octets minimum here).
    #[test]
    fn icmpv4_rfc4884_extensions_autofills_length_field() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1234).ttl(64))
        .compile()
        .unwrap();

        // 128 octets / 4 = 32 words.
        assert_eq!(bytes.as_bytes()[RFC4884_LENGTH_BYTE], 32);
    }

    // A plain error message with no extension structure leaves the length field
    // zero, so a compliant receiver reads "no extensions present".
    #[test]
    fn icmpv4_rfc4884_extensions_length_is_zero_without_extensions() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp()))
        .compile()
        .unwrap();

        assert_eq!(bytes.as_bytes()[RFC4884_LENGTH_BYTE], 0);
    }

    // The original datagram is zero padded up to the RFC 4884 minimum of 128
    // octets before the extension header when the quote is shorter, and a quote
    // longer than the minimum is only padded up to the next 32-bit boundary.
    #[test]
    fn icmpv4_rfc4884_extensions_pads_minimum_original_datagram() {
        // A short quote (well under 128 octets) is padded up to the 128-octet
        // minimum.
        let quote_len = quoted_udp().encoded_len();
        assert!(quote_len < ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM);
        let short = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::destination_unreachable()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new())
        .compile()
        .unwrap();
        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        // Everything past the quote and before the extension header is zero
        // padding making up the rest of the 128-octet original datagram.
        assert!(short.as_bytes()[ICMP_BODY_START + quote_len..ext_start]
            .iter()
            .all(|&byte| byte == 0));
        // The extension header (version 2) starts exactly at the padded boundary.
        assert_eq!(short.as_bytes()[ext_start] >> 4, 2);
        assert_eq!(short.as_bytes()[RFC4884_LENGTH_BYTE], 32);

        // A quote longer than 128 octets but not word-aligned (133 bytes) is
        // padded only up to the next 32-bit boundary (136 octets / 4 = 34 words),
        // never back down to the minimum.
        let long_quote = Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from_bytes(vec![0xab; 105]); // 20 + 8 + 105 = 133 bytes
        let long = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(long_quote)
            / IcmpExtension::new())
        .compile()
        .unwrap();
        assert_eq!(long.as_bytes()[RFC4884_LENGTH_BYTE], 34);
        // The three padding octets that round 133 up to 136 are zero.
        let long_ext_start = ICMP_BODY_START + 136;
        assert!(long.as_bytes()[ICMP_BODY_START + 133..long_ext_start]
            .iter()
            .all(|&byte| byte == 0));
        assert_eq!(long.as_bytes()[long_ext_start] >> 4, 2);
    }

    // The extension header checksum is auto-filled over the whole extension
    // structure (header plus objects), so the structure verifies on the wire.
    #[test]
    fn icmpv4_rfc4884_extensions_autofills_extension_checksum() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(99).ttl(10))
        .compile()
        .unwrap();

        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        // The one's-complement sum over the extension structure is zero.
        assert!(verify_internet_checksum(&bytes.as_bytes()[ext_start..]));
        // A non-zero checksum was actually emitted (not left at zero).
        assert_ne!(&bytes.as_bytes()[ext_start + 2..ext_start + 4], &[0, 0]);
    }

    // An explicit extension checksum is honored verbatim, even when it is
    // intentionally wrong, and it survives a decode round-trip.
    #[test]
    fn icmpv4_rfc4884_extensions_explicit_malformed_checksum_is_preserved() {
        let bytes = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new().checksum(0xdead)
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(7).ttl(5))
        .compile()
        .unwrap();

        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        assert_eq!(
            &bytes.as_bytes()[ext_start + 2..ext_start + 4],
            &0xdeadu16.to_be_bytes()
        );

        // A non-zero but wrong checksum is treated as "not a real extension" on
        // decode, so the trailing bytes stay raw rather than being typed.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpExtension>().is_none());
        assert!(decoded.layer::<Raw>().is_some());
        // The bytes round-trip unchanged regardless.
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes.as_bytes());
    }

    // A generic, unrecognized extension object retains its length, class,
    // sub-type, and raw payload across a compile/decode round-trip.
    #[test]
    fn icmpv4_rfc4884_extensions_generic_unknown_object_roundtrip() {
        let payload = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let packet = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::new().icmp_type(ICMP_PARAMETER_PROBLEM)
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new().class_num(200).c_type(7)
            / Raw::from_bytes(payload);
        let compiled = packet.compile().unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        // Length covers the 4-byte object header plus the 8-byte payload.
        assert_eq!(object.length_value(), Some(12));
        assert_eq!(object.class_num_value(), 200);
        assert_eq!(object.c_type_value(), 7);
        // The unknown object payload survives as raw bytes.
        let raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(raw.as_bytes(), &payload);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A complete RFC 4884 packet decodes into typed Icmpv4, quoted datagram,
    // extension header, and extension object layers.
    #[test]
    fn icmpv4_rfc4884_extensions_decode_splits_typed_layers() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1234).ttl(100)
            / IcmpExtensionMpls::new().label(2345).ttl(50))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();

        // The ICMP header and quoted datagram are typed.
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        assert_eq!(icmp.length_value(), Some(32));
        let quoted = decoded.layer::<IcmpQuotedIpv4>().unwrap();
        assert_eq!(
            quoted.quoted_layer::<Ipv4>().unwrap().source(),
            Ipv4Addr::new(192, 0, 2, 1)
        );

        // The extension header and object are typed.
        let extension = decoded.layer::<IcmpExtension>().unwrap();
        assert_eq!(extension.version_value(), 2);
        assert_eq!(extension.checksum_value().map(|_| true), Some(true));
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        // Object length covers the 4-byte object header plus the two 4-byte MPLS
        // label stack words.
        assert_eq!(object.length_value(), Some(12));
        assert_eq!(object.class_num_value(), 1);
        assert_eq!(object.c_type_value(), 1);

        // The whole structure round-trips byte-for-byte.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // When the length field claims an extension structure but the bytes that
    // follow are not a valid one (here a corrupted version nibble), decoding
    // keeps the trailing bytes as a single Raw tail instead of fabricating typed
    // layers or panicking, and the buffer still round-trips unchanged.
    #[test]
    fn icmpv4_rfc4884_extensions_ambiguous_data_stays_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1).ttl(1))
        .compile()
        .unwrap();

        // Corrupt the extension version nibble (set it to 0xf instead of 2).
        let mut corrupt = compiled.as_bytes().to_vec();
        let ext_start = ICMP_BODY_START + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
        corrupt[ext_start] = 0xf0 | (corrupt[ext_start] & 0x0f);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &corrupt).unwrap();
        // No typed extension layers were produced.
        assert!(decoded.layer::<IcmpExtension>().is_none());
        assert!(decoded.layer::<IcmpExtensionObject>().is_none());
        // The quoted datagram is still typed and the ambiguous tail is raw.
        assert!(decoded.layer::<IcmpQuotedIpv4>().is_some());
        let raw = decoded.layer::<Raw>().unwrap();
        // The raw tail is the padding plus the unparsed extension bytes.
        assert!(raw.as_bytes().len() >= ICMP_EXTENSION_HEADER_LEN);
        // The corrupted buffer round-trips unchanged.
        assert_eq!(decoded.compile().unwrap().as_bytes(), &corrupt[..]);
    }
}

#[cfg(test)]
mod icmpv4_rfc4950_mpls {
    use super::{
        IcmpExtension, IcmpExtensionMpls, IcmpExtensionObject, IcmpQuotedIpv4, Icmpv4,
        ICMP_EXTENSION_CLASS_MPLS, ICMP_EXTENSION_CTYPE_MPLS_INCOMING,
        ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM,
    };
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::Ipv4Addr;

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // The standard short quoted datagram (IPv4 + UDP + payload) attached to an
    // error message before the extension structure.
    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // The ICMP body begins at offset 28 (20-byte IPv4 header + 8-byte ICMP
    // header). The quote is padded up to the 128-octet RFC 4884 minimum, so the
    // extension header sits at offset 28 + 128 and the first object header four
    // bytes later.
    const EXT_HEADER_START: usize = 28 + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
    const OBJECT_HEADER_START: usize = EXT_HEADER_START + 4;
    const FIRST_ENTRY_START: usize = OBJECT_HEADER_START + 4;

    // A single MPLS label stack entry encodes its label, experimental bits,
    // bottom-of-stack flag, and TTL into one 4-octet word, and decodes back into
    // a typed IcmpExtensionMpls layer.
    #[test]
    fn icmpv4_rfc4950_mpls_single_label_encode_decode() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(0xabcde).exp(5).ttl(64))
        .compile()
        .unwrap();

        // Object header: length 8 (4-byte object header + one 4-byte entry),
        // class 1 (MPLS), C-Type 1 (incoming label stack).
        assert_eq!(
            &compiled.as_bytes()[OBJECT_HEADER_START..OBJECT_HEADER_START + 4],
            &[
                0x00,
                0x08,
                ICMP_EXTENSION_CLASS_MPLS,
                ICMP_EXTENSION_CTYPE_MPLS_INCOMING
            ]
        );
        // The 32-bit entry word packs label (20 bits) | exp (3) | S (1) | TTL.
        let expected = (0xabcdeu32 << 12) | (5u32 << 9) | (1u32 << 8) | 64u32;
        assert_eq!(
            &compiled.as_bytes()[FIRST_ENTRY_START..FIRST_ENTRY_START + 4],
            &expected.to_be_bytes()
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let mpls = decoded.layer::<IcmpExtensionMpls>().unwrap();
        assert_eq!(mpls.label_value(), 0xabcde);
        assert_eq!(mpls.experimental_value(), 5);
        assert_eq!(mpls.ttl_value(), 64);
        // A single entry is the bottom of the stack.
        assert_eq!(mpls.bottom_of_stack_value(), Some(true));
        // The typed object header is also exposed.
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.length_value(), Some(8));
        assert_eq!(object.class_num_value(), ICMP_EXTENSION_CLASS_MPLS);
        assert_eq!(object.c_type_value(), ICMP_EXTENSION_CTYPE_MPLS_INCOMING);
    }

    // A multi-label stack encodes each entry as its own 4-octet word, and decode
    // exposes every entry as a separate typed layer in order, preserving each
    // entry's label, experimental bits, and TTL.
    #[test]
    fn icmpv4_rfc4950_mpls_multi_label_encode_decode() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(100).exp(1).ttl(10)
            / IcmpExtensionMpls::new().label(200).exp(2).ttl(20)
            / IcmpExtensionMpls::new().label(300).exp(3).ttl(30))
        .compile()
        .unwrap();

        // Object length covers the 4-byte header plus three 4-byte entries.
        let object = {
            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
            decoded
                .layer::<IcmpExtensionObject>()
                .unwrap()
                .length_value()
        };
        assert_eq!(object, Some(16));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let entries: Vec<&IcmpExtensionMpls> = decoded.layers::<IcmpExtensionMpls>().collect();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].label_value(), 100);
        assert_eq!(entries[0].experimental_value(), 1);
        assert_eq!(entries[0].ttl_value(), 10);
        assert_eq!(entries[1].label_value(), 200);
        assert_eq!(entries[2].label_value(), 300);
        // Only the final entry carries the bottom-of-stack bit.
        assert_eq!(entries[0].bottom_of_stack_value(), Some(false));
        assert_eq!(entries[1].bottom_of_stack_value(), Some(false));
        assert_eq!(entries[2].bottom_of_stack_value(), Some(true));
    }

    // With the bottom-of-stack bit left unset, compile auto-fills it: only the
    // final entry in a stack is the bottom of stack.
    #[test]
    fn icmpv4_rfc4950_mpls_bottom_of_stack_autofill() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1).ttl(1)
            / IcmpExtensionMpls::new().label(2).ttl(2))
        .compile()
        .unwrap();

        // The bottom-of-stack S bit is bit 8 of the 32-bit entry word, which in
        // big-endian layout is the LSB of the entry's third octet (offset +2).
        // First entry: S bit clear (not the bottom of the stack).
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 2] & 0x01, 0);
        // Second entry (four octets later): S bit set (bottom of the stack).
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 6] & 0x01, 1);
    }

    // An explicit bottom-of-stack override is honored verbatim, even when it
    // contradicts the auto-fill rule (here a set bit on a non-final entry and a
    // clear bit on the final entry), and survives a decode round-trip.
    #[test]
    fn icmpv4_rfc4950_mpls_explicit_bottom_of_stack_override() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new()
                .label(1)
                .ttl(1)
                .bottom_of_stack(true)
            / IcmpExtensionMpls::new()
                .label(2)
                .ttl(2)
                .bottom_of_stack(false))
        .compile()
        .unwrap();

        // The S bit lives in the LSB of each entry's third octet (offset +2).
        // First entry forced to bottom-of-stack despite a following entry.
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 2] & 0x01, 1);
        // Final entry forced to not-bottom-of-stack despite being last.
        assert_eq!(compiled.as_bytes()[FIRST_ENTRY_START + 6] & 0x01, 0);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let entries: Vec<&IcmpExtensionMpls> = decoded.layers::<IcmpExtensionMpls>().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].bottom_of_stack_value(), Some(true));
        assert_eq!(entries[1].bottom_of_stack_value(), Some(false));
    }

    // A label that does not fit in 20 bits, and experimental bits that do not fit
    // in 3 bits, are rejected at compile time per the existing invalid-field
    // policy.
    #[test]
    fn icmpv4_rfc4950_mpls_invalid_field_bounds() {
        let too_large_label = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(0x10_0000).ttl(1);
        assert!(too_large_label.compile().is_err());

        let too_large_exp = Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(1).exp(8).ttl(1);
        assert!(too_large_exp.compile().is_err());
    }

    // A complete MPLS-bearing error message round-trips byte-for-byte through
    // Packet::decode_from_l3 even when the entries carry maximal field values.
    #[test]
    fn icmpv4_rfc4950_mpls_byte_for_byte_roundtrip() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::destination_unreachable()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(0xfffff).exp(7).ttl(255)
            / IcmpExtensionMpls::new().label(0).exp(0).ttl(0))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // The typed MPLS entries are present.
        assert_eq!(decoded.layers::<IcmpExtensionMpls>().count(), 2);
        // And the whole packet reproduces the original bytes exactly.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An MPLS object whose body is not a whole number of 4-octet entries is
    // malformed; decode keeps the body as a single Raw payload (never panicking)
    // and the buffer still round-trips unchanged.
    #[test]
    fn icmpv4_rfc4950_mpls_partial_entry_stays_raw() {
        // Build a valid two-entry MPLS object, then truncate the object so its
        // body holds one full entry plus two stray octets (a partial entry).
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionMpls::new().label(7).ttl(7)
            / IcmpExtensionMpls::new().label(8).ttl(8))
        .compile()
        .unwrap();

        let mut bytes = compiled.as_bytes().to_vec();
        // Drop the final two octets so the trailing object body is 6 bytes (one
        // 4-octet entry + a 2-octet partial entry), shrinking the object length
        // and the IPv4 total length to keep the buffer self-consistent.
        bytes.truncate(bytes.len() - 2);
        // Object length field (big-endian u16) drops from 12 to 10.
        bytes[OBJECT_HEADER_START] = 0x00;
        bytes[OBJECT_HEADER_START + 1] = 0x0a;
        // IPv4 total length (offset 2..4) drops by two as well.
        let total = u16::from_be_bytes([bytes[2], bytes[3]]) - 2;
        bytes[2..4].copy_from_slice(&total.to_be_bytes());
        // Recompute the IPv4 header checksum over the patched header.
        bytes[10] = 0;
        bytes[11] = 0;
        let mut sum = 0u32;
        for pair in bytes[0..20].chunks(2) {
            sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        bytes[10..12].copy_from_slice(&csum.to_be_bytes());

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, &bytes).unwrap();
        // The malformed MPLS body is not typed into entries.
        assert_eq!(decoded.layers::<IcmpExtensionMpls>().count(), 0);
        // It survives as a raw body and the buffer round-trips unchanged.
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), &bytes[..]);
    }
}

#[cfg(test)]
mod icmpv4_rfc5837_interface_info {
    use super::{
        IcmpExtension, IcmpExtensionInterfaceInfo, IcmpExtensionObject, IcmpInterfaceIpAddress,
        IcmpQuotedIpv4, Icmpv4, ICMP_EXTENSION_CLASS_INTERFACE_INFO, ICMP_INTERFACE_CTYPE_IFINDEX,
        ICMP_INTERFACE_CTYPE_IP_ADDRESS, ICMP_INTERFACE_CTYPE_MTU, ICMP_INTERFACE_CTYPE_NAME,
        ICMP_INTERFACE_ROLE_NEXT_HOP, ICMP_INTERFACE_ROLE_OUTGOING,
        ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM,
    };
    use crate::checksum::verify_internet_checksum;
    use crate::{IpProtocol, Ipv4, NetworkLayer, Packet, Raw, Udp};
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    fn quoted_udp() -> Packet {
        Ipv4::new()
            .src(Ipv4Addr::new(192, 0, 2, 1))
            .dst(Ipv4Addr::new(198, 51, 100, 1))
            .proto(IpProtocol::Udp)
            / Udp::new().sport(40000).dport(53)
            / Raw::from("query")
    }

    // The ICMP body begins at offset 28; the quote is padded up to the 128-octet
    // RFC 4884 minimum, so the extension header sits at offset 28 + 128 and the
    // first object header four bytes later.
    const EXT_HEADER_START: usize = 28 + ICMP_RFC4884_MIN_ORIGINAL_DATAGRAM;
    const OBJECT_HEADER_START: usize = EXT_HEADER_START + 4;
    const OBJECT_BODY_START: usize = OBJECT_HEADER_START + 4;

    // A full interface information object carrying every RFC 5837 sub-object
    // (ifIndex, IPv4 address, name, MTU) encodes its C-Type presence bits and
    // decodes back into a typed layer that exposes each field.
    #[test]
    fn icmpv4_rfc5837_interface_info_all_subobjects_encode_decode() {
        let info = IcmpExtensionInterfaceInfo::new()
            .role(ICMP_INTERFACE_ROLE_OUTGOING)
            .if_index(7)
            .ip_address(IcmpInterfaceIpAddress::ipv4(Ipv4Addr::new(192, 0, 2, 99)))
            .name("eth0")
            .mtu(1500);
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / info)
            .compile()
            .unwrap();

        // The object header auto-fills class 2 and a C-Type with role=2 and all
        // four presence bits set.
        let expected_ctype = (ICMP_INTERFACE_ROLE_OUTGOING << 6)
            | ICMP_INTERFACE_CTYPE_IFINDEX
            | ICMP_INTERFACE_CTYPE_IP_ADDRESS
            | ICMP_INTERFACE_CTYPE_NAME
            | ICMP_INTERFACE_CTYPE_MTU;
        assert_eq!(
            compiled.as_bytes()[OBJECT_HEADER_START + 2],
            ICMP_EXTENSION_CLASS_INTERFACE_INFO
        );
        assert_eq!(compiled.as_bytes()[OBJECT_HEADER_START + 3], expected_ctype);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.role_value(), ICMP_INTERFACE_ROLE_OUTGOING);
        assert_eq!(info.if_index_value(), Some(7));
        assert_eq!(
            info.ip_address_value().unwrap().ipv4_value(),
            Some(Ipv4Addr::new(192, 0, 2, 99))
        );
        assert_eq!(info.name_value(), Some(&b"eth0"[..]));
        assert_eq!(info.mtu_value(), Some(1500));
        // The whole packet reproduces its bytes exactly.
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // Each sub-object can stand alone; an ifIndex-only object sets just the
    // ifIndex presence bit and round-trips.
    #[test]
    fn icmpv4_rfc5837_interface_info_ifindex_only() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new().if_index(0xdead_beef))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.if_index_value(), Some(0xdead_beef));
        assert_eq!(info.ip_address_value(), None);
        assert_eq!(info.name_value(), None);
        assert_eq!(info.mtu_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An IPv6 IP Address sub-object carries a 16-byte address and is recognized
    // on decode by its AFI.
    #[test]
    fn icmpv4_rfc5837_interface_info_ipv6_address_subobject() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1234);
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new()
                .role(ICMP_INTERFACE_ROLE_NEXT_HOP)
                .ip_address(IcmpInterfaceIpAddress::ipv6(addr)))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.role_value(), ICMP_INTERFACE_ROLE_NEXT_HOP);
        assert_eq!(info.ip_address_value().unwrap().ipv6_value(), Some(addr));
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The interface name sub-object emits a leading length octet covering itself
    // plus the name, then zero pads to a 4-octet boundary; decode strips both.
    #[test]
    fn icmpv4_rfc5837_interface_info_name_padding() {
        // "eth0" is 4 octets; with the length octet the sub-object is 5 octets,
        // padded up to 8.
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new().name("eth0"))
        .compile()
        .unwrap();

        // Length octet: 1 (itself) + 4 (name) = 5.
        assert_eq!(compiled.as_bytes()[OBJECT_BODY_START], 5);
        assert_eq!(
            &compiled.as_bytes()[OBJECT_BODY_START + 1..OBJECT_BODY_START + 5],
            b"eth0"
        );
        // Three zero pad octets bring the sub-object to an 8-octet boundary.
        assert_eq!(
            &compiled.as_bytes()[OBJECT_BODY_START + 5..OBJECT_BODY_START + 8],
            &[0, 0, 0]
        );
        // Object length covers the 4-byte header plus the 8-byte name sub-object.
        let object = compiled.as_bytes()[OBJECT_HEADER_START + 1];
        assert_eq!(object, 12);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let info = decoded.layer::<IcmpExtensionInterfaceInfo>().unwrap();
        assert_eq!(info.name_value(), Some(&b"eth0"[..]));
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The object length field auto-fills to the 4-byte object header plus the
    // sub-object body length when left unset.
    #[test]
    fn icmpv4_rfc5837_interface_info_length_autofill() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new().if_index(1).mtu(9000))
        .compile()
        .unwrap();

        // Body: 4-byte ifIndex + 4-byte MTU = 8; object length = 4 + 8 = 12.
        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.length_value(), Some(12));
        assert_eq!(
            object.class_num_value(),
            ICMP_EXTENSION_CLASS_INTERFACE_INFO
        );
    }

    // An explicit object length override is honored verbatim even when it does
    // not match the auto-computed body length.
    #[test]
    fn icmpv4_rfc5837_interface_info_explicit_length_override() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new().length(99)
            / IcmpExtensionInterfaceInfo::new().if_index(1))
        .compile()
        .unwrap();

        // The big-endian length field carries the override, not the computed 8.
        assert_eq!(
            u16::from_be_bytes([
                compiled.as_bytes()[OBJECT_HEADER_START],
                compiled.as_bytes()[OBJECT_HEADER_START + 1],
            ]),
            99
        );
    }

    // The RFC 4884 extension checksum is computed over the whole extension
    // structure including the interface information object and verifies on
    // decode.
    #[test]
    fn icmpv4_rfc5837_interface_info_extension_checksum() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceInfo::new()
                .if_index(5)
                .name("wlan0")
                .mtu(1280))
        .compile()
        .unwrap();

        // The extension structure (from the version/reserved/checksum header to
        // the end) carries a one's-complement checksum that verifies.
        assert!(verify_internet_checksum(
            &compiled.as_bytes()[EXT_HEADER_START..]
        ));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // The decoded extension header preserves the transmitted checksum.
        let extension = decoded.layer::<IcmpExtension>().unwrap();
        assert!(extension.checksum_value().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An unknown extension object class is not an interface information object;
    // it falls back to the generic IcmpExtensionObject + Raw body and is not
    // mistakenly typed as RFC 5837.
    #[test]
    fn icmpv4_rfc5837_interface_info_unknown_class_stays_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new().class_num(200).c_type(0x0f)
            / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpExtensionInterfaceInfo>().is_none());
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.class_num_value(), 200);
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An interface information object whose body is too short for the sub-objects
    // its C-Type claims cannot be parsed defensibly; decode keeps the body raw
    // and never panics, and the buffer round-trips unchanged.
    #[test]
    fn icmpv4_rfc5837_interface_info_truncated_subobject_stays_raw() {
        // Class 2, C-Type with the MTU presence bit set, but only two body octets
        // (an MTU needs four). The object is otherwise well-formed.
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::time_exceeded()
            / IcmpQuotedIpv4::new(quoted_udp())
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
                .class_num(ICMP_EXTENSION_CLASS_INTERFACE_INFO)
                .c_type(ICMP_INTERFACE_CTYPE_MTU)
            / Raw::from_bytes([0xaa, 0xbb]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // The under-length body is not typed as an interface information object.
        assert!(decoded.layer::<IcmpExtensionInterfaceInfo>().is_none());
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The summary names the interface role and surfaces each present sub-object's
    // value without hiding the raw numbers.
    #[test]
    fn icmpv4_rfc5837_interface_info_summary() {
        let info = IcmpExtensionInterfaceInfo::new()
            .role(ICMP_INTERFACE_ROLE_OUTGOING)
            .if_index(42)
            .ip_address(IcmpInterfaceIpAddress::ipv4(Ipv4Addr::new(192, 0, 2, 1)))
            .name("eth1")
            .mtu(1500);
        let summary = crate::packet::Layer::summary(&info);
        assert!(summary.contains("outgoing"), "summary was {summary}");
        assert!(summary.contains("ifindex=42"), "summary was {summary}");
        assert!(summary.contains("192.0.2.1"), "summary was {summary}");
        assert!(summary.contains("name=eth1"), "summary was {summary}");
        assert!(summary.contains("mtu=1500"), "summary was {summary}");
    }
}

#[cfg(test)]
mod icmpv4_rfc8335_extended_echo {
    use super::{
        IcmpExtension, IcmpExtensionInterfaceId, IcmpExtensionObject, Icmpv4,
        ICMP_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
        ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES, ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR,
        ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
        ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY, ICMP_EXTENDED_ECHO_REPLY,
        ICMP_EXTENDED_ECHO_REQUEST, ICMP_EXTENSION_CLASS_INTERFACE_ID,
        ICMP_INTERFACE_ID_CTYPE_ADDRESS, ICMP_INTERFACE_ID_CTYPE_INDEX,
        ICMP_INTERFACE_ID_CTYPE_NAME,
    };
    use crate::checksum::verify_internet_checksum;
    use crate::{Ipv4, NetworkLayer, Packet, Raw};
    use core::net::{Ipv4Addr, Ipv6Addr};

    fn src() -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, 10)
    }

    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(198, 51, 100, 20)
    }

    // An extended echo request carries its 16-bit identifier, 8-bit sequence
    // number, and flag byte in the fixed header, then an RFC 4884 extension
    // structure with a single Interface Identification Object directly after the
    // header (no quoted datagram, no original-datagram padding). The whole packet
    // round-trips and the typed object surfaces the ifIndex.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_compile_decode() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request().id(0x1234).seq(7)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(42))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Fixed ICMP header at offset 20: type 42, code 0.
        assert_eq!(bytes[20], ICMP_EXTENDED_ECHO_REQUEST);
        assert_eq!(bytes[21], 0);
        // Identifier (bytes 24-25), 8-bit sequence (byte 26), flag byte (byte 27).
        assert_eq!(&bytes[24..26], &0x1234u16.to_be_bytes());
        assert_eq!(bytes[26], 7);
        assert_eq!(bytes[27], 0);
        // The extension header begins immediately after the fixed header (no
        // quote, no padding): version 2.
        assert_eq!(bytes[28] >> 4, 2);
        // The object header auto-fills class 3 and C-Type 2 (by index).
        assert_eq!(bytes[34], ICMP_EXTENSION_CLASS_INTERFACE_ID);
        assert_eq!(bytes[35], ICMP_INTERFACE_ID_CTYPE_INDEX);
        // Object length: 4-byte header + 4-byte ifIndex = 8.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 8);
        // ifIndex value.
        assert_eq!(
            u32::from_be_bytes([bytes[36], bytes[37], bytes[38], bytes[39]]),
            42
        );

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        assert_eq!(icmp.icmp_type_value(), ICMP_EXTENDED_ECHO_REQUEST);
        assert_eq!(icmp.identifier_value(), Some(0x1234));
        assert_eq!(icmp.sequence_number_value(), Some(7));
        assert_eq!(icmp.extended_l_bit_value(), Some(false));
        assert!(decoded.layer::<IcmpExtension>().is_some());
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.index_value(), Some(42));
        assert_eq!(id.c_type(), ICMP_INTERFACE_ID_CTYPE_INDEX);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The Interface Identification Object can identify by name (C-Type 1), with
    // the name zero padded to a 32-bit boundary.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_name() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request().id(1).seq(1)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_name("eth0"))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[35], ICMP_INTERFACE_ID_CTYPE_NAME);
        // "eth0" is 4 octets, already on a 32-bit boundary; object length 4 + 4.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 8);
        assert_eq!(&bytes[36..40], b"eth0");

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.name_value(), Some(&b"eth0"[..]));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A short name is zero padded to a 32-bit boundary on the wire and the
    // padding is stripped on decode.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_name_padding() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_name("e0"))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // "e0" (2 octets) pads to 4; object length 4 + 4 = 8.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 8);
        assert_eq!(&bytes[36..38], b"e0");
        assert_eq!(&bytes[38..40], &[0, 0]);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.name_value(), Some(&b"e0"[..]));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The Interface Identification Object can identify by IPv4 address (C-Type 3):
    // AFI, address length, reserved, then the address padded to a 32-bit boundary.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_ipv4_address() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_ipv4(Ipv4Addr::new(192, 0, 2, 99)))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        assert_eq!(bytes[35], ICMP_INTERFACE_ID_CTYPE_ADDRESS);
        // AFI 1 (IPv4), address length 4, reserved 0, then the 4 address octets.
        assert_eq!(u16::from_be_bytes([bytes[36], bytes[37]]), 1);
        assert_eq!(bytes[38], 4);
        assert_eq!(bytes[39], 0);
        assert_eq!(&bytes[40..44], &[192, 0, 2, 99]);
        // Object length: 4-byte header + 4-byte prefix + 4-byte address = 12.
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 12);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.ipv4_value(), Some(Ipv4Addr::new(192, 0, 2, 99)));
        assert_eq!(id.address_length_value(), Some(4));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // An IPv6 address object carries a 16-byte address (already 32-bit aligned).
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_by_ipv6_address() {
        let addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x99);
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_ipv6(addr))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // AFI 2 (IPv6), address length 16. Object length 4 + 4 + 16 = 24.
        assert_eq!(u16::from_be_bytes([bytes[36], bytes[37]]), 2);
        assert_eq!(bytes[38], 16);
        assert_eq!(u16::from_be_bytes([bytes[32], bytes[33]]), 24);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let id = decoded.layer::<IcmpExtensionInterfaceId>().unwrap();
        assert_eq!(id.ipv6_value(), Some(addr));
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // The request L-bit is the rightmost bit of the flag byte and round-trips.
    #[test]
    fn icmpv4_rfc8335_extended_echo_request_l_bit() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
                .id(9)
                .seq(3)
                .extended_l_bit(true)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(1))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // Flag byte (offset 27): only the rightmost (L) bit set.
        assert_eq!(bytes[27], 0x01);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        assert_eq!(icmp.extended_l_bit_value(), Some(true));
        // Reply-only accessors are not meaningful on a request.
        assert_eq!(icmp.extended_state_value(), None);
        assert_eq!(icmp.extended_active_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // Every reply code (0-4) compiles and decodes, keeping its numeric code and a
    // stable summary name; replies carry no body of their own.
    #[test]
    fn icmpv4_rfc8335_extended_echo_reply_all_codes() {
        let codes = [
            (ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR, "no-error"),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_MALFORMED_QUERY,
                "malformed-query",
            ),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_INTERFACE,
                "no-such-interface",
            ),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_NO_SUCH_TABLE_ENTRY,
                "no-such-table-entry",
            ),
            (
                ICMP_CODE_EXTENDED_ECHO_REPLY_MULTIPLE_INTERFACES,
                "multiple-interfaces",
            ),
        ];
        for (code, name) in codes {
            let compiled = (Ipv4::new().src(src()).dst(dst())
                / Icmpv4::extended_echo_reply().id(0xabcd).seq(5).code(code))
            .compile()
            .unwrap();

            let bytes = compiled.as_bytes();
            assert_eq!(bytes[20], ICMP_EXTENDED_ECHO_REPLY);
            assert_eq!(bytes[21], code);

            let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
            let icmp = decoded.layer::<Icmpv4>().unwrap();
            assert_eq!(icmp.code_value(), code);
            assert_eq!(icmp.identifier_value(), Some(0xabcd));
            assert_eq!(icmp.sequence_number_value(), Some(5));
            assert!(
                crate::packet::Layer::summary(icmp).contains(name),
                "summary missing {name}"
            );
            assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
        }
    }

    // The reply flag byte packs State (3 bits), reserved (2 bits), and the A/4/6
    // flags; each typed accessor surfaces its field and the byte round-trips.
    #[test]
    fn icmpv4_rfc8335_extended_echo_reply_flags() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_reply()
                .code(ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR)
                .extended_state(super::ICMP_EXTENDED_ECHO_REPLY_STATE_REACHABLE)
                .extended_active(true)
                .extended_ipv4(true)
                .extended_ipv6(false))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // State 2 in bits 5-7 (0b010 << 5 = 0x40), A bit (0x04), 4 bit (0x02).
        assert_eq!(bytes[27], 0x40 | 0x04 | 0x02);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        assert_eq!(
            icmp.extended_state_value(),
            Some(super::ICMP_EXTENDED_ECHO_REPLY_STATE_REACHABLE)
        );
        assert_eq!(icmp.extended_active_value(), Some(true));
        assert_eq!(icmp.extended_ipv4_value(), Some(true));
        assert_eq!(icmp.extended_ipv6_value(), Some(false));
        // The L-bit accessor is request-only and not meaningful on a reply.
        assert_eq!(icmp.extended_l_bit_value(), None);
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // A reply with an unexpected trailing payload keeps it as a Raw layer rather
    // than typing it; the buffer round-trips unchanged.
    #[test]
    fn icmpv4_rfc8335_extended_echo_reply_trailing_payload_stays_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_reply().code(ICMP_CODE_EXTENDED_ECHO_REPLY_NO_ERROR)
            / Raw::from_bytes([0xde, 0xad, 0xbe, 0xef]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let raw = decoded.layer::<Raw>().unwrap();
        assert_eq!(raw.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
        assert!(decoded.layer::<IcmpExtension>().is_none());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The default request carries exactly one Interface Identification Object and
    // its object length covers just that object.
    #[test]
    fn icmpv4_rfc8335_extended_echo_exactly_one_object_default() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(3))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let object_count = decoded
            .iter()
            .filter(|layer| layer.as_any().is::<IcmpExtensionObject>())
            .count();
        assert_eq!(object_count, 1);
        let id_count = decoded
            .iter()
            .filter(|layer| layer.as_any().is::<IcmpExtensionInterfaceId>())
            .count();
        assert_eq!(id_count, 1);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // A deliberately malformed object count (two objects in a single request) is
    // preserved on compile and decode; the crate does not refuse to emit it.
    #[test]
    fn icmpv4_rfc8335_extended_echo_malformed_object_count_preserved() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(1)
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(2))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        // Both Interface Identification Objects survive (RFC 8335 expects exactly
        // one, but malformed multi-object requests must still round-trip).
        let ids: Vec<_> = decoded
            .iter()
            .filter_map(|layer| layer.as_any().downcast_ref::<IcmpExtensionInterfaceId>())
            .map(|id| id.index_value())
            .collect();
        assert_eq!(ids, vec![Some(1), Some(2)]);
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // An unknown Interface Identification Object C-Type is not typed; it falls
    // back to the generic IcmpExtensionObject + Raw body and round-trips.
    #[test]
    fn icmpv4_rfc8335_extended_echo_unknown_object_falls_back_to_raw() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
                .class_num(ICMP_EXTENSION_CLASS_INTERFACE_ID)
                .c_type(0x7f)
            / Raw::from_bytes([1, 2, 3, 4]))
        .compile()
        .unwrap();

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        assert!(decoded.layer::<IcmpExtensionInterfaceId>().is_none());
        let object = decoded.layer::<IcmpExtensionObject>().unwrap();
        assert_eq!(object.class_num_value(), ICMP_EXTENSION_CLASS_INTERFACE_ID);
        assert_eq!(object.c_type_value(), 0x7f);
        assert!(decoded.layer::<Raw>().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }

    // The RFC 4884 extension checksum covers the whole extension structure and
    // verifies on decode; an extended echo request round-trips byte-for-byte.
    #[test]
    fn icmpv4_rfc8335_extended_echo_checksum_roundtrip() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request().id(0x55aa).seq(2)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_name("wlan0"))
        .compile()
        .unwrap();

        let bytes = compiled.as_bytes();
        // The extension structure starts at offset 28 (right after the 8-byte
        // ICMP header, no quote or padding) and carries a verifying checksum.
        assert!(verify_internet_checksum(&bytes[28..]));
        // The outer ICMP checksum also verifies (covers the ICMP header + body).
        assert!(verify_internet_checksum(&bytes[20..]));

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, bytes).unwrap();
        let extension = decoded.layer::<IcmpExtension>().unwrap();
        assert!(extension.checksum_value().is_some());
        assert_eq!(decoded.compile().unwrap().as_bytes(), bytes);
    }

    // An explicit raw flag byte survives compilation untouched, the escape hatch
    // for crafting reserved bits the typed builders do not expose.
    #[test]
    fn icmpv4_rfc8335_extended_echo_explicit_flag_byte_preserved() {
        let compiled = (Ipv4::new().src(src()).dst(dst())
            / Icmpv4::extended_echo_request()
                .id(1)
                .seq(1)
                .extended_flags(0xfe)
            / IcmpExtension::new()
            / IcmpExtensionObject::new()
            / IcmpExtensionInterfaceId::by_index(1))
        .compile()
        .unwrap();

        // The raw flag byte (including the reserved bits) is emitted verbatim.
        assert_eq!(compiled.as_bytes()[27], 0xfe);

        let decoded = Packet::decode_from_l3(NetworkLayer::Ipv4, compiled.as_bytes()).unwrap();
        let icmp = decoded.layer::<Icmpv4>().unwrap();
        assert_eq!(icmp.extended_flags_value(), Some(0xfe));
        assert_eq!(decoded.compile().unwrap().as_bytes(), compiled.as_bytes());
    }
}
