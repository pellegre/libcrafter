//! IEEE 802.11 management tagged parameter (information element).

use crate::error::{CrafterError, Result};
use crate::protocols::rsn::RsnInformation;

use super::{DOT11_TAG_DS_PARAMETER_SET, DOT11_TAG_RSN, DOT11_TAG_SSID};
use super::{DOT11_TAG_SUPPORTED_RATES, DOT11_TAG_TIM};

/// Raw IEEE 802.11 management tagged parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dot11TaggedParameter {
    id: u8,
    length: usize,
    data: Vec<u8>,
}

impl Dot11TaggedParameter {
    /// Create a tagged parameter with an element ID and raw value bytes.
    pub fn new(id: u8, data: impl Into<Vec<u8>>) -> Self {
        let data = data.into();
        let length = data.len();

        Self { id, length, data }
    }

    /// Create an SSID tagged parameter.
    pub fn ssid(ssid: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_SSID, ssid)
    }

    /// Create a Supported Rates tagged parameter.
    pub fn supported_rates(rates: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_SUPPORTED_RATES, rates)
    }

    /// Create a DS Parameter Set tagged parameter with the current channel.
    pub fn ds_parameter_set(current_channel: u8) -> Self {
        Self::new(DOT11_TAG_DS_PARAMETER_SET, [current_channel])
    }

    /// Create a raw TIM tagged parameter.
    pub fn tim(data: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_TIM, data)
    }

    /// Create a raw RSN tagged parameter.
    pub fn rsn(data: impl Into<Vec<u8>>) -> Self {
        Self::new(DOT11_TAG_RSN, data)
    }

    /// Create an RSN tagged parameter from typed RSN information.
    pub fn from_rsn_information(rsn: &RsnInformation) -> Result<Self> {
        let data = rsn.to_tagged_parameter_value()?;
        if data.len() > u8::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                "dot11.tagged_parameter.length",
                "tagged parameter length must fit in one byte",
            ));
        }

        Ok(Self::rsn(data))
    }

    /// Parse this tagged parameter as typed RSN information when it is an RSN tag.
    pub fn rsn_information(&self) -> Option<Result<RsnInformation>> {
        if self.id == DOT11_TAG_RSN {
            Some(RsnInformation::from_tagged_parameter_value(&self.data))
        } else {
            None
        }
    }

    /// Element ID.
    pub const fn id(&self) -> u8 {
        self.id
    }

    /// Declared tagged-parameter value length.
    pub const fn length(&self) -> usize {
        self.length
    }

    /// Raw value bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Raw value bytes.
    pub fn value(&self) -> &[u8] {
        &self.data
    }

    /// Override the declared value length octet.
    pub fn with_length(mut self, length: u8) -> Self {
        self.length = length as usize;
        self
    }

    /// Encoded length including ID and length octets.
    pub fn encoded_len(&self) -> usize {
        2 + self.data.len()
    }

    pub(super) fn from_wire(id: u8, length: u8, data: &[u8]) -> Self {
        Self {
            id,
            length: length as usize,
            data: data.to_vec(),
        }
    }

    pub(super) fn compile(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.length > u8::MAX as usize {
            return Err(CrafterError::invalid_field_value(
                "dot11.tagged_parameter.length",
                "tagged parameter length must fit in one byte",
            ));
        }

        out.push(self.id);
        out.push(self.length as u8);
        out.extend_from_slice(&self.data);
        Ok(())
    }
}
