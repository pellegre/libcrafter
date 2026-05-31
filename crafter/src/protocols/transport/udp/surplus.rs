use crate::checksum::{crc32c, internet_checksum_chunks};
use crate::error::{CrafterError, Result};
use crate::packet::{Layer, LayerContext, Packet};
use crate::protocols::ip::Ipv4;
use crate::protocols::ipv6::Ipv6;

use super::super::common::{hex_bytes, impl_layer_div, impl_layer_object};
use super::constants::{
    UDP_OPTION_APC, UDP_OPTION_APC_LEN, UDP_OPTION_CHECKSUM_LEN, UDP_OPTION_FRAG,
    UDP_OPTION_SHORT_HEADER_LEN,
};
use super::datagram::{is_current_udp_surplus_layer, is_udp_application_layer};
use super::option::{
    encode_udp_options, udp_option_is_malformed_apc, udp_option_is_malformed_frag,
    udp_options_inspection_summary, UdpOption, UdpOptionIter, UdpOptionKindClass,
};
use super::Udp;

/// Inspection status for UDP surplus option processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UdpOptionStatus {
    /// No UDP surplus area is present.
    NoSurplus,
    /// UDP surplus option parsing has not been attempted.
    NotParsed,
    /// UDP surplus options are well-formed.
    Valid,
    /// UDP surplus options were intentionally ignored.
    Ignored,
    /// UDP surplus option bytes are malformed.
    Malformed,
    /// UDP surplus option length or fixed-format envelope is malformed.
    MalformedEnvelope,
    /// Bytes after EOL contain nonzero data.
    NonzeroAfterEndOfList,
    /// More than seven consecutive NOP options were present.
    TooManyNoOperations,
    /// UDP surplus options include unsupported behavior.
    Unsupported,
    /// UDP FRAG is present and preserved, but fragmentation is unsupported.
    UnsupportedFragmentation,
    /// Unknown SAFE option bytes were preserved and skipped.
    UnknownSafe,
    /// Unknown UNSAFE option bytes were preserved and stopped option processing.
    UnknownUnsafe,
    /// UDP Option Checksum validation failed.
    OptionChecksumInvalid,
    /// UDP Additional Payload Checksum validation failed.
    AdditionalPayloadChecksumInvalid,
}

/// UDP surplus option bytes.
///
/// This layer preserves the area after UDP Length in packets that carry RFC
/// 9868 UDP options and caches generic option parsing status for inspection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UdpOptions {
    bytes: Vec<u8>,
    options: Vec<UdpOption>,
    status: UdpOptionStatus,
    option_checksum: Option<u16>,
    alignment: Option<Vec<u8>>,
    raw_surplus: Option<Vec<u8>>,
    auto_apc_offsets: Vec<usize>,
}

impl UdpOptions {
    /// Create an empty UDP options layer.
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            options: Vec::new(),
            status: UdpOptionStatus::NoSurplus,
            option_checksum: None,
            alignment: None,
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
        }
    }

    /// Create a UDP options layer by copying option bytes after OCS.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Self {
        let bytes = bytes.as_ref().to_vec();
        let (options, status) = parse_udp_options_for_status(&bytes);
        Self {
            bytes,
            options,
            status,
            option_checksum: None,
            alignment: None,
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
        }
    }

    /// Create a UDP options layer from typed options.
    pub fn from_options(options: impl Into<Vec<UdpOption>>) -> Result<Self> {
        let bytes = encode_udp_options(&options.into())?;
        let (options, status) = parse_udp_options_for_status(&bytes);
        Ok(Self {
            bytes,
            options,
            status,
            option_checksum: None,
            alignment: None,
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
        })
    }

    pub(super) fn from_decoded_surplus(
        surplus: &[u8],
        user_payload: &[u8],
        surplus_offset_in_ip_datagram: usize,
        udp_checksum: u16,
    ) -> Self {
        if surplus.is_empty() {
            return Self::new();
        }

        let alignment_len = udp_options_alignment_len(surplus_offset_in_ip_datagram);
        if surplus.len() < alignment_len + UDP_OPTION_CHECKSUM_LEN {
            return Self {
                bytes: Vec::new(),
                options: Vec::new(),
                status: UdpOptionStatus::MalformedEnvelope,
                option_checksum: None,
                alignment: Some(surplus[..surplus.len().min(alignment_len)].to_vec()),
                raw_surplus: Some(surplus.to_vec()),
                auto_apc_offsets: Vec::new(),
            };
        }

        let alignment = surplus[..alignment_len].to_vec();
        let option_checksum =
            u16::from_be_bytes([surplus[alignment_len], surplus[alignment_len + 1]]);
        let bytes = surplus[alignment_len + UDP_OPTION_CHECKSUM_LEN..].to_vec();
        let (options, parsed_status) = parse_udp_options_for_status(&bytes);
        let status = if alignment.iter().any(|byte| *byte != 0) {
            UdpOptionStatus::Ignored
        } else if !udp_options_ocs_valid(surplus, alignment_len, option_checksum, udp_checksum) {
            UdpOptionStatus::OptionChecksumInvalid
        } else if udp_option_status_allows_apc_validation(parsed_status) {
            match udp_options_apc_status(&options, user_payload) {
                UdpOptionStatus::Valid => parsed_status,
                status => status,
            }
        } else {
            parsed_status
        };

        Self {
            bytes,
            options,
            status,
            option_checksum: Some(option_checksum),
            alignment: Some(alignment),
            raw_surplus: None,
            auto_apc_offsets: Vec::new(),
        }
    }

    /// Borrow the encoded UDP option bytes after OCS.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Mutably borrow the encoded UDP option bytes after OCS.
    pub fn as_bytes_mut(&mut self) -> &mut Vec<u8> {
        self.options.clear();
        self.status = UdpOptionStatus::NotParsed;
        self.raw_surplus = None;
        self.auto_apc_offsets.clear();
        &mut self.bytes
    }

    /// Append encoded UDP option bytes.
    pub fn extend_from_slice(&mut self, bytes: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(bytes);
        self.raw_surplus = None;
        self.refresh_parse();
        self
    }

    /// Append a typed UDP option.
    pub fn udp_option(mut self, option: UdpOption) -> Result<Self> {
        self.bytes.extend_from_slice(&option.encode()?);
        self.raw_surplus = None;
        self.refresh_parse();
        Ok(self)
    }

    /// Append an APC option whose CRC32c is filled from UDP user data at compile time.
    pub fn additional_payload_checksum(mut self) -> Self {
        let offset = self.bytes.len();
        self.bytes
            .extend_from_slice(&[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8]);
        self.bytes.extend_from_slice(&0u32.to_be_bytes());
        self.auto_apc_offsets.push(offset);
        self.raw_surplus = None;
        self.refresh_parse();
        self
    }

    /// Compatibility-style short alias for [`Self::additional_payload_checksum`].
    pub fn apc(self) -> Self {
        self.additional_payload_checksum()
    }

    /// Append an APC option with an explicit checksum value.
    pub fn additional_payload_checksum_value(mut self, checksum: u32) -> Self {
        self.bytes
            .extend_from_slice(&[UDP_OPTION_APC, UDP_OPTION_APC_LEN as u8]);
        self.bytes.extend_from_slice(&checksum.to_be_bytes());
        self.raw_surplus = None;
        self.refresh_parse();
        self
    }

    /// Compatibility-style short alias for [`Self::additional_payload_checksum_value`].
    pub fn apc_value(self, checksum: u32) -> Self {
        self.additional_payload_checksum_value(checksum)
    }

    /// Set the UDP Option Checksum field explicitly.
    pub fn option_checksum(mut self, checksum: u16) -> Self {
        self.option_checksum = Some(checksum);
        self.raw_surplus = None;
        self
    }

    /// Compatibility-style short alias for [`Self::option_checksum`].
    pub fn ocs(self, checksum: u16) -> Self {
        self.option_checksum(checksum)
    }

    /// Stored UDP Option Checksum value, when explicit or decoded.
    pub const fn option_checksum_value(&self) -> Option<u16> {
        self.option_checksum
    }

    /// Alignment bytes before OCS, when decoded or explicitly preserved.
    pub fn alignment_bytes(&self) -> Option<&[u8]> {
        self.alignment.as_deref()
    }

    /// Consume the layer and return its encoded UDP option bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Number of encoded UDP option bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return true when no UDP option bytes are present.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Inspection status from generic option parsing.
    pub const fn status(&self) -> UdpOptionStatus {
        self.status
    }

    /// Parsed options cached when the layer was created or last extended.
    pub fn options(&self) -> &[UdpOption] {
        &self.options
    }

    /// Iterate over the current encoded UDP option bytes.
    pub fn option_iter(&self) -> UdpOptionIter<'_> {
        UdpOptionIter::new(&self.bytes)
    }

    /// Decode the current encoded UDP option bytes into typed values.
    pub fn parsed_options(&self) -> Result<Vec<UdpOption>> {
        UdpOption::decode_all(&self.bytes)
    }

    fn refresh_parse(&mut self) {
        (self.options, self.status) = parse_udp_options_for_status(&self.bytes);
    }

    fn materialized_option_bytes(&self, ctx: &LayerContext<'_>) -> Result<Vec<u8>> {
        let mut bytes = self.bytes.clone();
        if self.auto_apc_offsets.is_empty() {
            return Ok(bytes);
        }

        let checksum = crc32c(&udp_user_payload_bytes_before_options(*ctx)?).to_be_bytes();
        for &offset in &self.auto_apc_offsets {
            if offset + UDP_OPTION_APC_LEN > bytes.len()
                || bytes[offset] != UDP_OPTION_APC
                || bytes[offset + 1] != UDP_OPTION_APC_LEN as u8
            {
                return Err(CrafterError::invalid_field_value(
                    "udp.option.apc",
                    "auto APC offset no longer points to an APC option",
                ));
            }
            bytes[offset + UDP_OPTION_SHORT_HEADER_LEN..offset + UDP_OPTION_APC_LEN]
                .copy_from_slice(&checksum);
        }

        Ok(bytes)
    }
}

impl Default for UdpOptions {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_udp_options_for_status(bytes: &[u8]) -> (Vec<UdpOption>, UdpOptionStatus) {
    if bytes.is_empty() {
        return (Vec::new(), UdpOptionStatus::NoSurplus);
    }

    let mut options = Vec::new();
    let mut status = UdpOptionStatus::Valid;
    let mut has_malformed_apc = false;
    for option in UdpOptionIter::new(bytes) {
        match option {
            Ok(option) => {
                has_malformed_apc |= udp_option_is_malformed_apc(&option);
                let option_status = udp_option_status_for_option(&option);
                options.push(option);
                match option_status {
                    Some(UdpOptionStatus::MalformedEnvelope) => {
                        return (options, UdpOptionStatus::MalformedEnvelope);
                    }
                    Some(
                        status @ (UdpOptionStatus::UnsupportedFragmentation
                        | UdpOptionStatus::UnknownUnsafe),
                    ) => {
                        let status = if has_malformed_apc {
                            UdpOptionStatus::AdditionalPayloadChecksumInvalid
                        } else {
                            status
                        };
                        return (options, status);
                    }
                    Some(UdpOptionStatus::UnknownSafe) if status == UdpOptionStatus::Valid => {
                        status = UdpOptionStatus::UnknownSafe;
                    }
                    Some(_) | None => {}
                }
            }
            Err(err) => return (options, udp_option_status_for_parse_error(&err)),
        }
    }

    let status = if has_malformed_apc {
        UdpOptionStatus::AdditionalPayloadChecksumInvalid
    } else {
        status
    };

    (options, status)
}

const fn udp_option_status_allows_apc_validation(status: UdpOptionStatus) -> bool {
    matches!(
        status,
        UdpOptionStatus::Valid | UdpOptionStatus::UnknownSafe
    )
}

fn udp_option_status_for_parse_error(err: &CrafterError) -> UdpOptionStatus {
    match err {
        CrafterError::InvalidFieldValue { field, .. } if *field == "udp.option.eol_padding" => {
            UdpOptionStatus::NonzeroAfterEndOfList
        }
        CrafterError::InvalidFieldValue { field, .. } if *field == "udp.option.nop" => {
            UdpOptionStatus::TooManyNoOperations
        }
        _ => UdpOptionStatus::MalformedEnvelope,
    }
}

fn udp_option_status_for_option(option: &UdpOption) -> Option<UdpOptionStatus> {
    if udp_option_is_malformed_frag(option) {
        return Some(UdpOptionStatus::MalformedEnvelope);
    }
    if option.kind() == UDP_OPTION_FRAG {
        return Some(UdpOptionStatus::UnsupportedFragmentation);
    }

    match option.kind_class() {
        UdpOptionKindClass::UnassignedSafe | UdpOptionKindClass::ReservedSafe => {
            Some(UdpOptionStatus::UnknownSafe)
        }
        UdpOptionKindClass::UnassignedUnsafe | UdpOptionKindClass::ReservedUnsafe => {
            Some(UdpOptionStatus::UnknownUnsafe)
        }
        _ => None,
    }
}

fn udp_options_apc_status(options: &[UdpOption], user_payload: &[u8]) -> UdpOptionStatus {
    let expected = crc32c(user_payload).to_be_bytes();
    if options.iter().any(|option| match option {
        UdpOption::AdditionalPayloadChecksum { checksum } => checksum != &expected,
        option => udp_option_is_malformed_apc(option),
    }) {
        UdpOptionStatus::AdditionalPayloadChecksumInvalid
    } else {
        UdpOptionStatus::Valid
    }
}

fn udp_options_alignment_len(offset_in_ip_datagram: usize) -> usize {
    offset_in_ip_datagram & 1
}

fn udp_options_generated_ocs(alignment: &[u8], option_bytes: &[u8]) -> Result<u16> {
    let surplus_len = alignment
        .len()
        .checked_add(UDP_OPTION_CHECKSUM_LEN)
        .and_then(|len| len.checked_add(option_bytes.len()))
        .ok_or_else(|| {
            CrafterError::invalid_field_value(
                "udp.options.length",
                "UDP surplus area length overflows usize",
            )
        })?;
    let surplus_len = u16::try_from(surplus_len).map_err(|_| {
        CrafterError::invalid_field_value(
            "udp.options.length",
            "UDP surplus area length must fit in two bytes",
        )
    })?;

    // RFC 9868 aligns OCS relative to the IP datagram; pre-OCS bytes are
    // zero padding, while the OCS covers the remainder plus full surplus len.
    let mut checksummed = Vec::with_capacity(UDP_OPTION_CHECKSUM_LEN + option_bytes.len());
    checksummed.extend_from_slice(&0u16.to_be_bytes());
    checksummed.extend_from_slice(option_bytes);

    let len_bytes = surplus_len.to_be_bytes();
    let checksum = internet_checksum_chunks([len_bytes.as_slice(), checksummed.as_slice()]);
    Ok(if checksum == 0 { 0xffff } else { checksum })
}

fn udp_options_ocs_valid(
    surplus: &[u8],
    alignment_len: usize,
    option_checksum: u16,
    udp_checksum: u16,
) -> bool {
    if option_checksum == 0 {
        return udp_checksum == 0;
    }

    let Ok(surplus_len) = u16::try_from(surplus.len()) else {
        return false;
    };
    let len_bytes = surplus_len.to_be_bytes();
    internet_checksum_chunks([len_bytes.as_slice(), &surplus[alignment_len..]]) == 0
}

fn first_ip_layer_index(packet: &Packet) -> Option<usize> {
    packet
        .iter()
        .position(|layer| layer.as_any().is::<Ipv4>() || layer.as_any().is::<Ipv6>())
}

fn udp_options_surplus_offset_in_ip_datagram(ctx: LayerContext<'_>) -> usize {
    let packet = ctx.packet();
    let start = first_ip_layer_index(packet).unwrap_or(0);
    packet
        .iter()
        .enumerate()
        .skip(start)
        .take(ctx.index().saturating_sub(start))
        .map(|(index, layer)| {
            let layer_ctx = LayerContext::new(packet, index);
            layer.encoded_len_with_context(&layer_ctx)
        })
        .sum()
}

pub(super) fn udp_decoded_surplus_offset_in_ip_datagram(
    packet_before_udp: &Packet,
    udp_length: usize,
) -> usize {
    let start = first_ip_layer_index(packet_before_udp).unwrap_or(0);
    packet_before_udp
        .iter()
        .enumerate()
        .skip(start)
        .map(|(index, layer)| {
            let layer_ctx = LayerContext::new(packet_before_udp, index);
            layer.encoded_len_with_context(&layer_ctx)
        })
        .sum::<usize>()
        + udp_length
}

fn udp_user_payload_bytes_before_options(ctx: LayerContext<'_>) -> Result<Vec<u8>> {
    let mut udp_index = None;
    for (index, layer) in ctx.packet().iter().enumerate().take(ctx.index()) {
        if layer.as_any().is::<Udp>() {
            udp_index = Some(index);
        }
    }

    let Some(udp_index) = udp_index else {
        return Ok(Vec::new());
    };

    let mut payload = Vec::new();
    let mut seen_application_layer = false;

    for (index, layer) in ctx
        .packet()
        .iter()
        .enumerate()
        .take(ctx.index())
        .skip(udp_index + 1)
    {
        if is_current_udp_surplus_layer(layer, seen_application_layer) {
            break;
        }

        let layer_ctx = LayerContext::new(ctx.packet(), index);
        layer.compile(&layer_ctx, &mut payload)?;

        if is_udp_application_layer(layer) {
            seen_application_layer = true;
        }
    }

    Ok(payload)
}

impl Layer for UdpOptions {
    fn name(&self) -> &'static str {
        "UdpOptions"
    }

    fn summary(&self) -> String {
        format!(
            "UdpOptions(len={}, status={:?}, options={})",
            self.bytes.len(),
            self.status,
            udp_options_inspection_summary(&self.options)
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("len", self.bytes.len().to_string()),
            ("status", format!("{:?}", self.status)),
            (
                "ocs",
                self.option_checksum
                    .map(|value| format!("0x{value:04x}"))
                    .unwrap_or_else(|| {
                        if self.bytes.is_empty() {
                            "absent".to_string()
                        } else {
                            "auto".to_string()
                        }
                    }),
            ),
            (
                "alignment",
                self.alignment
                    .as_ref()
                    .map(|bytes| hex_bytes(bytes))
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("option_count", self.options.len().to_string()),
            ("options", udp_options_inspection_summary(&self.options)),
            ("bytes", hex_bytes(&self.bytes)),
        ]
    }

    fn encoded_len(&self) -> usize {
        if let Some(raw_surplus) = &self.raw_surplus {
            return raw_surplus.len();
        }
        if self.bytes.is_empty() && self.option_checksum.is_none() {
            return 0;
        }

        self.alignment.as_ref().map_or(0, Vec::len) + UDP_OPTION_CHECKSUM_LEN + self.bytes.len()
    }

    fn encoded_len_with_context(&self, ctx: &LayerContext<'_>) -> usize {
        if let Some(raw_surplus) = &self.raw_surplus {
            return raw_surplus.len();
        }
        if self.bytes.is_empty() && self.option_checksum.is_none() {
            return 0;
        }

        let alignment_len = self.alignment.as_ref().map_or_else(
            || udp_options_alignment_len(udp_options_surplus_offset_in_ip_datagram(*ctx)),
            Vec::len,
        );
        alignment_len + UDP_OPTION_CHECKSUM_LEN + self.bytes.len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        if let Some(raw_surplus) = &self.raw_surplus {
            out.extend_from_slice(raw_surplus);
            return Ok(());
        }
        if self.bytes.is_empty() && self.option_checksum.is_none() {
            return Ok(());
        }

        let alignment = self.alignment.clone().unwrap_or_else(|| {
            vec![0; udp_options_alignment_len(udp_options_surplus_offset_in_ip_datagram(*ctx))]
        });
        let option_bytes = self.materialized_option_bytes(ctx)?;
        let option_checksum = match self.option_checksum {
            Some(value) => value,
            None => udp_options_generated_ocs(&alignment, &option_bytes)?,
        };

        out.extend_from_slice(&alignment);
        out.extend_from_slice(&option_checksum.to_be_bytes());
        out.extend_from_slice(&option_bytes);
        Ok(())
    }

    impl_layer_object!(UdpOptions);
}

impl_layer_div!(UdpOptions);
