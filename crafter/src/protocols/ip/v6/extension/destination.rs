use crate::error::{CrafterError, Result};
use crate::field::Field;
use crate::packet::{Layer, LayerContext};

use super::super::display::{ipv6_options_summary, next_header_summary};
use super::super::options::Ipv6Option;
use super::super::{layer_ipv6_next_header, value_or_copy};
use super::{
    decode_extension_total_len, header_ext_len_from_total, round_up_to_8,
    validate_extension_total_len,
};

/// IPv6 Destination Options Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6DestinationOptionsHeader {
    next_header: Field<u8>,
    header_ext_len: Field<u8>,
    options: Vec<Ipv6Option>,
}

impl Ipv6DestinationOptionsHeader {
    /// Create an empty Destination Options header.
    pub fn new() -> Self {
        Self {
            next_header: Field::defaulted(0),
            header_ext_len: Field::unset(),
            options: Vec::new(),
        }
    }

    /// Set the next header after this Destination Options header.
    pub fn next_header(mut self, next_header: u8) -> Self {
        self.next_header.set_user(next_header);
        self
    }

    /// Compatibility alias for next header.
    pub fn nh(self, next_header: u8) -> Self {
        self.next_header(next_header)
    }

    /// Set the encoded header extension length.
    pub fn header_ext_len(mut self, header_ext_len: u8) -> Self {
        self.header_ext_len.set_user(header_ext_len);
        self
    }

    /// Replace the Destination options.
    pub fn options(mut self, options: impl Into<Vec<Ipv6Option>>) -> Self {
        self.options = options.into();
        self
    }

    /// Append one Destination option.
    pub fn option(mut self, option: Ipv6Option) -> Self {
        self.options.push(option);
        self
    }

    /// Compatibility alias for appending one Destination option.
    pub fn push_option(self, option: Ipv6Option) -> Self {
        self.option(option)
    }

    /// Next-header value.
    pub fn next_header_value(&self) -> u8 {
        value_or_copy(&self.next_header, 0)
    }

    /// Header extension length when explicit or decoded.
    pub fn header_ext_len_value(&self) -> Option<u8> {
        self.header_ext_len.value().copied()
    }

    /// Destination options in caller order.
    pub fn options_value(&self) -> &[Ipv6Option] {
        &self.options
    }

    /// Compatibility alias for Destination options.
    pub fn options_list(&self) -> &[Ipv6Option] {
        self.options_value()
    }

    fn options_len(&self) -> usize {
        self.options.iter().map(Ipv6Option::encoded_len).sum()
    }

    fn minimum_total_len(&self) -> usize {
        round_up_to_8(2 + self.options_len())
    }

    fn effective_total_len(&self) -> usize {
        self.header_ext_len
            .value()
            .map(|value| super::super::constants::IPV6_EXTENSION_MIN_LEN + *value as usize * 8)
            .unwrap_or_else(|| self.minimum_total_len())
    }

    fn effective_header_ext_len(&self) -> Result<u8> {
        header_ext_len_from_total(
            "ipv6.destination_options.header_ext_len",
            self.effective_total_len(),
        )
    }

    fn effective_next_header(&self, next: Option<&dyn Layer>) -> u8 {
        if self.next_header.is_user_set() {
            return self.next_header_value();
        }

        next.and_then(layer_ipv6_next_header)
            .or_else(|| self.next_header.value().copied())
            .unwrap_or(0)
    }

    fn validate(&self) -> Result<()> {
        validate_extension_total_len(
            "ipv6.destination_options.header_ext_len",
            self.effective_total_len(),
        )?;
        if self.effective_total_len() < 2 + self.options_len() {
            return Err(CrafterError::invalid_field_value(
                "ipv6.destination_options.options",
                "Destination options do not fit in the header extension length",
            ));
        }
        for option in &self.options {
            option.encode()?;
        }
        Ok(())
    }
}

impl Default for Ipv6DestinationOptionsHeader {
    fn default() -> Self {
        Self::new()
    }
}

impl Layer for Ipv6DestinationOptionsHeader {
    fn name(&self) -> &'static str {
        "Ipv6DestinationOptionsHeader"
    }

    fn summary(&self) -> String {
        format!(
            "Ipv6DestinationOptionsHeader(options={}, next={})",
            ipv6_options_summary(&self.options),
            next_header_summary(self.next_header_value())
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("next_header", next_header_summary(self.next_header_value())),
            (
                "header_ext_len",
                self.header_ext_len_value()
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "auto".to_string()),
            ),
            ("options", ipv6_options_summary(&self.options)),
        ]
    }

    fn encoded_len(&self) -> usize {
        self.effective_total_len()
    }

    fn compile(&self, ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.validate()?;
        let start = out.len();
        let total_len = self.effective_total_len();

        out.push(self.effective_next_header(ctx.next()));
        out.push(self.effective_header_ext_len()?);
        for option in &self.options {
            out.extend_from_slice(&option.encode()?);
        }
        out.resize(start + total_len, 0);
        Ok(())
    }

    impl_ipv6_extension_layer_object!(Ipv6DestinationOptionsHeader);
}

impl_ipv6_extension_layer_div!(Ipv6DestinationOptionsHeader);

pub(in crate::protocols::ip::v6) fn decode_destination_options_header(
    bytes: &[u8],
) -> Result<(Ipv6DestinationOptionsHeader, u8, &[u8])> {
    let total_len = decode_extension_total_len("ipv6 destination options header", bytes)?;
    let next_header = bytes[0];
    let options = Ipv6Option::decode_all(&bytes[2..total_len])?;

    Ok((
        Ipv6DestinationOptionsHeader {
            next_header: Field::user(next_header),
            header_ext_len: Field::user(bytes[1]),
            options,
        },
        next_header,
        &bytes[total_len..],
    ))
}
