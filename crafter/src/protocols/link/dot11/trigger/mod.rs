//! HE and EHT Trigger bodies.
//!
//! The wire layer remains lossless and variant-neutral. Variant modules expose
//! the different meanings assigned to the shared bits by HE and EHT.

macro_rules! trigger_fields {
    ($name:ident, $len:literal; $($field:ident: $ty:ident = $start:literal, $width:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name { $(pub $field: $ty,)* }
        impl $name {
            pub fn from_bits(bits: u64) -> Self {
                Self { $($field: trigger_fields!(@value (bits >> $start) & ((1u64 << $width) - 1), $ty),)* }
            }
            pub fn from_le_bytes(bytes: [u8; $len]) -> Self {
                Self::from_bits(bytes.iter().enumerate().fold(0, |value, (index, byte)| {
                    value | (u64::from(*byte) << (8 * index))
                }))
            }
            pub fn bits(self) -> u64 {
                0 $(| (((self.$field as u64) & ((1u64 << $width) - 1)) << $start))*
            }
            pub fn compile(self) -> [u8; $len] {
                let bits = self.bits();
                std::array::from_fn(|index| (bits >> (8 * index)) as u8)
            }
        }
    };
    (@value $value:expr, bool) => { $value != 0 };
    (@value $value:expr, $ty:ident) => { $value as $ty };
}

mod eht;
mod fields;
mod layer;
#[cfg(test)]
mod tests;

pub use eht::{
    Dot11EhtTrigger, Dot11EhtTriggerCommonFields, Dot11EhtTriggerSpecialUser,
    Dot11EhtTriggerSpecialUserFields, Dot11EhtTriggerUser, Dot11EhtTriggerUserFields,
    Dot11EhtTriggerUserInfo,
};
pub use fields::{Dot11TriggerCommonFields, Dot11TriggerUser, Dot11TriggerUserFields};
pub use layer::{Dot11Trigger, Dot11TriggerRemainder};
