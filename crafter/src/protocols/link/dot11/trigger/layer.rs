//! Lossless Trigger body layer and variant-independent framing.

use super::{Dot11TriggerCommonFields, Dot11TriggerUser, Dot11TriggerUserFields};
use crate::error::{CrafterError, Result};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use core::{any::Any, ops::Div};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Dot11TriggerRemainder {
    #[default]
    None,
    /// Starts with the AID4095 marker. Even noncanonical padding is preserved.
    Padding(Vec<u8>),
    /// NFRP, unknown variant, or an undecidable MU-BAR User Info boundary.
    Opaque(Vec<u8>),
}

impl Dot11TriggerRemainder {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::None => &[],
            Self::Padding(bytes) | Self::Opaque(bytes) => bytes,
        }
    }
}

/// Trigger body layer, composed after `Dot11::control(Dot11ControlSubtype::Trigger)`.
/// Inputs exclude FCS. Fields and variant-dependent bytes can be overridden,
/// including malformed combinations; compile never rewrites those overrides.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dot11Trigger {
    pub common: Dot11TriggerCommonFields,
    pub dependent_common: Vec<u8>,
    pub users: Vec<Dot11TriggerUser>,
    pub remainder: Dot11TriggerRemainder,
}

impl Dot11Trigger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn common(mut self, common: Dot11TriggerCommonFields) -> Self {
        self.common = common;
        self
    }

    pub fn user(mut self, user: Dot11TriggerUser) -> Self {
        self.users.push(user);
        self
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        fn need<'a>(bytes: &'a [u8], len: usize, context: &'static str) -> Result<&'a [u8]> {
            bytes
                .get(..len)
                .ok_or_else(|| CrafterError::buffer_too_short(context, len, bytes.len()))
        }

        let common = Dot11TriggerCommonFields::from_le_bytes(
            need(bytes, 8, "dot11.trigger.common")?.try_into().unwrap(),
        );
        let mut result = Self::new().common(common);
        let mut rest = &bytes[8..];
        if common.trigger_type >= 7 {
            result.remainder = Dot11TriggerRemainder::Opaque(rest.to_vec());
            return Ok(result);
        }
        if common.trigger_type == 5 {
            result.dependent_common = need(rest, 4, "dot11.trigger.gcr_common")?.to_vec();
            rest = &rest[4..];
        }
        while !rest.is_empty() {
            let first = need(rest, 2, "dot11.trigger.user")?;
            let aid = u16::from_le_bytes(first.try_into().unwrap()) & 4095;
            if aid == 4095 {
                result.remainder = Dot11TriggerRemainder::Padding(rest.to_vec());
                break;
            }
            let fields = Dot11TriggerUserFields::from_le_bytes(
                need(rest, 5, "dot11.trigger.user")?.try_into().unwrap(),
            );
            let dependent = match common.trigger_type {
                0 | 1 => 1,
                2 => {
                    let bytes = need(rest, 7, "dot11.trigger.mu_bar_control")?;
                    let control = u16::from_le_bytes([bytes[5], bytes[6]]);
                    match (control >> 1) & 15 {
                        2 => 4,
                        3 => 2 + 4 * (usize::from(control >> 12) + 1),
                        _ => {
                            result.remainder = Dot11TriggerRemainder::Opaque(rest.to_vec());
                            break;
                        }
                    }
                }
                _ => 0,
            };
            let raw = need(rest, 5 + dependent, "dot11.trigger.user_dependent")?;
            result.users.push(Dot11TriggerUser {
                fields,
                dependent: raw[5..].to_vec(),
            });
            rest = &rest[raw.len()..];
        }
        Ok(result)
    }
}

impl Layer for Dot11Trigger {
    fn name(&self) -> &'static str {
        "Dot11Trigger"
    }

    fn summary(&self) -> String {
        format!(
            "Dot11Trigger(type={}, ul_length={}, users={}, opaque={})",
            self.common.trigger_type,
            self.common.ul_length,
            self.users.len(),
            matches!(self.remainder, Dot11TriggerRemainder::Opaque(_))
        )
    }

    fn inspection_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("common", format!("{:?}", self.common)),
            ("users", format!("{:?}", self.users)),
            (
                "dependent_common",
                format!("{:02x?}", self.dependent_common),
            ),
            ("remainder", format!("{:?}", self.remainder)),
        ]
    }

    fn encoded_len(&self) -> usize {
        8 + self.dependent_common.len()
            + self
                .users
                .iter()
                .map(|user| 5 + user.dependent.len())
                .sum::<usize>()
            + self.remainder.as_bytes().len()
    }

    fn compile(&self, _ctx: &LayerContext<'_>, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&self.common.compile());
        out.extend_from_slice(&self.dependent_common);
        for user in &self.users {
            out.extend_from_slice(&user.fields.compile());
            out.extend_from_slice(&user.dependent);
        }
        out.extend_from_slice(self.remainder.as_bytes());
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

impl<R: IntoPacket> Div<R> for Dot11Trigger {
    type Output = Packet;

    fn div(self, rhs: R) -> Packet {
        Packet::from_layer(self).concat(rhs)
    }
}
