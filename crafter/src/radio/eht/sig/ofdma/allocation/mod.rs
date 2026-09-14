//! EHT20 OFDMA resource allocation and ordered RU/MRU ownership.

mod resource;
mod table;
#[cfg(test)]
mod tests;

pub use resource::{EhtOfdmaUserKind, EhtResourceUnit, EhtRuComponent, EhtRuSize};

use super::super::EhtSigError;

/// Validated 20 MHz RU Allocation subfield and its resource layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtRuAllocation20 {
    code: u16,
    resources: &'static [EhtResourceUnit],
}

impl EhtRuAllocation20 {
    pub(super) fn decode(code: u16) -> Result<Self, EhtSigError> {
        let resources = table::lookup(code).ok_or(EhtSigError::RuAllocation(code))?;
        Ok(Self { code, resources })
    }

    pub const fn code(self) -> u16 {
        self.code
    }

    /// RUs and MRUs in increasing frequency order.
    pub const fn resources(self) -> &'static [EhtResourceUnit] {
        self.resources
    }

    /// Number of EHT-SIG User fields described by this allocation.
    pub fn user_count(self) -> u8 {
        self.resources
            .iter()
            .map(|resource| resource.user_count())
            .sum()
    }

    pub fn user_kind(self) -> EhtOfdmaUserKind {
        if self
            .resources
            .iter()
            .any(|resource| resource.user_kind() == EhtOfdmaUserKind::MuMimo)
        {
            EhtOfdmaUserKind::MuMimo
        } else {
            EhtOfdmaUserKind::NonMu
        }
    }
}
