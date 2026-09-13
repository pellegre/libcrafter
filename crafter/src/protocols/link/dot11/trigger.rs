//! HE Trigger bodies; IEEE802.11ax-2021 9.3.1.22, Figures9-64b/d.
//! Reserved values are preserved. PHY admission is separate from MAC parsing.
use crate::error::{CrafterError, Result};
use crate::packet::{IntoPacket, Layer, LayerContext, Packet};
use core::{any::Any, ops::Div};

macro_rules! value {
    ($v:expr, bool) => {
        $v != 0
    };
    ($v:expr, $ty:ident) => {
        $v as $ty
    };
}
macro_rules! fields {
    ($name:ident, $len:literal; $($field:ident: $ty:ident = $start:literal, $width:literal;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name { $(pub $field: $ty,)* }
        impl $name {
            pub fn from_bits(bits: u64) -> Self {
                Self { $($field: value!((bits >> $start) & ((1u64 << $width) - 1), $ty),)* }
            }
            pub fn from_le_bytes(bytes: [u8; $len]) -> Self {
                Self::from_bits(bytes.iter().enumerate().fold(0, |v,(i,b)| v | (u64::from(*b) << (8*i))))
            }
            pub fn bits(self) -> u64 {
                0 $(| (((self.$field as u64) & ((1u64 << $width) - 1)) << $start))*
            }
            pub fn compile(self) -> [u8; $len] {
                let bits = self.bits();
                std::array::from_fn(|i| (bits >> (8*i)) as u8)
            }
        }
    }
}

fields!(Dot11TriggerCommonFields, 8;
    trigger_type: u8 = 0,4;
    ul_length: u16 = 4,12;
    more_tf: bool = 16,1;
    cs_required: bool = 17,1;
    bandwidth: u8 = 18,2;
    gi_ltf: u8 = 20,2;
    masked_ltf: bool = 22,1;
    ltf_symbols_midamble: u8 = 23,3;
    stbc: bool = 26,1;
    ldpc_extra_segment: bool = 27,1;
    ap_tx_power: u8 = 28,6;
    pre_fec_padding_raw: u8 = 34,2;
    pe_disambiguity: bool = 36,1;
    spatial_reuse: u16 = 37,16;
    doppler: bool = 53,1;
    sig_a2_reserved: u16 = 54,9;
    reserved: bool = 63,1;
);
impl Default for Dot11TriggerCommonFields {
    fn default() -> Self {
        Self::from_bits((301 << 4) | (1 << 20) | (511 << 54))
    }
}

// Normal User Info fields, not NFRP's different five-octet layout.
// `spatial_allocation` is SS allocation or RA-RU information depending on AID.
fields!(Dot11TriggerUserFields, 5;
    aid12: u16 = 0,12;
    ru_allocation: u8 = 12,8;
    ldpc: bool = 20,1;
    mcs: u8 = 21,4;
    dcm: bool = 25,1;
    spatial_allocation: u8 = 26,6;
    target_receive_power: u8 = 32,7;
    reserved: bool = 39,1;
);
impl Default for Dot11TriggerUserFields {
    fn default() -> Self {
        Self::from_bits(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11TriggerUser {
    pub fields: Dot11TriggerUserFields,
    /// Variant-dependent bytes, including BAR Control/Information when present.
    pub dependent: Vec<u8>,
}

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
            Self::Padding(b) | Self::Opaque(b) => b,
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
        fn need<'a>(b: &'a [u8], n: usize, context: &'static str) -> Result<&'a [u8]> {
            b.get(..n)
                .ok_or_else(|| CrafterError::buffer_too_short(context, n, b.len()))
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
                    let b = need(rest, 7, "dot11.trigger.mu_bar_control")?;
                    let control = u16::from_le_bytes([b[5], b[6]]);
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
                .map(|u| 5 + u.dependent.len())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(bytes: &[u8]) -> Dot11Trigger {
        let decoded = Dot11Trigger::decode(bytes).unwrap();
        let packet = Packet::from_layer(decoded.clone());
        assert_eq!(packet.compile().unwrap().as_bytes(), bytes);
        assert_eq!(decoded.encoded_len(), bytes.len());
        decoded
    }

    #[test]
    fn trigger_fields_preserve_every_wire_bit() {
        for bit in 0..64 {
            let bits = 1u64 << bit;
            let fields = Dot11TriggerCommonFields::from_le_bytes(bits.to_le_bytes());
            assert_eq!(fields.bits(), bits);
            assert_eq!(fields.compile(), bits.to_le_bytes());
            // Figure 9-64b, in transmission order. Check semantic mapping,
            // not only a serializer/parser pair that could share an error.
            let values = [
                fields.trigger_type as u64,
                fields.ul_length as u64,
                fields.more_tf as u64,
                fields.cs_required as u64,
                fields.bandwidth as u64,
                fields.gi_ltf as u64,
                fields.masked_ltf as u64,
                fields.ltf_symbols_midamble as u64,
                fields.stbc as u64,
                fields.ldpc_extra_segment as u64,
                fields.ap_tx_power as u64,
                fields.pre_fec_padding_raw as u64,
                fields.pe_disambiguity as u64,
                fields.spatial_reuse as u64,
                fields.doppler as u64,
                fields.sig_a2_reserved as u64,
                fields.reserved as u64,
            ];
            let widths = [4, 12, 1, 1, 2, 2, 1, 3, 1, 1, 6, 2, 1, 16, 1, 9, 1];
            let mut offset = 0;
            for (value, width) in values.into_iter().zip(widths) {
                assert_eq!(value, (bits >> offset) & ((1 << width) - 1));
                offset += width;
            }
        }
        for bit in 0..40 {
            let bits = 1u64 << bit;
            let bytes: [u8; 5] = bits.to_le_bytes()[..5].try_into().unwrap();
            let fields = Dot11TriggerUserFields::from_le_bytes(bytes);
            assert_eq!(fields.bits(), bits);
            assert_eq!(fields.compile(), bytes);
            // Figure 9-64d, normal User Info (NFRP is deliberately opaque).
            let values = [
                fields.aid12 as u64,
                fields.ru_allocation as u64,
                fields.ldpc as u64,
                fields.mcs as u64,
                fields.dcm as u64,
                fields.spatial_allocation as u64,
                fields.target_receive_power as u64,
                fields.reserved as u64,
            ];
            let mut offset = 0;
            for (value, width) in values.into_iter().zip([12, 8, 1, 4, 1, 6, 7, 1]) {
                assert_eq!(value, (bits >> offset) & ((1 << width) - 1));
                offset += width;
            }
        }
        assert_eq!(
            Dot11TriggerCommonFields::from_bits(u64::MAX).compile(),
            [255; 8]
        );
        assert_eq!(
            Dot11TriggerUserFields::from_bits(u64::MAX).compile(),
            [255; 5]
        );
    }

    #[test]
    fn trigger_variant_boundaries_and_padding() {
        // IEEE 802.11ax-2021 9.3.1.22: Basic/BFRP have one dependent
        // User octet; GCR has four dependent Common octets instead.
        for variant in 0..7 {
            let mut bytes = vec![variant, 0, 0, 0, 0, 0, 0, 0];
            if variant == 5 {
                bytes.extend([4, 0, 0x30, 0x12]);
            }
            for aid in [1, 2] {
                bytes.extend([aid, 0, 0, 0, 0]);
                match variant {
                    0 | 1 => bytes.push(0xa5),
                    2 => bytes.extend([4, 0, 0x30, 0x12]),
                    _ => (),
                }
            }
            bytes.extend([255, 15, 0x12]); // Preserve noncanonical padding.
            let decoded = roundtrip(&bytes);
            assert_eq!(decoded.users.len(), 2);
            assert_eq!(decoded.users[1].fields.aid12, 2);
            assert_eq!(
                decoded.remainder,
                Dot11TriggerRemainder::Padding(vec![255, 15, 0x12])
            );
        }
    }

    #[test]
    fn trigger_multi_tid_count_includes_sixteen() {
        // BAR Type=3, TID_INFO=count-1; each Per-TID Info/SSC occupies four octets.
        for count in 1..=16usize {
            let mut bytes = vec![2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
            bytes.extend((6u16 | (((count - 1) as u16) << 12)).to_le_bytes());
            bytes.extend(vec![0x23; 4 * count]);
            bytes.extend([255, 255]);
            let decoded = roundtrip(&bytes);
            assert_eq!(decoded.users.len(), 1);
            assert_eq!(decoded.users[0].dependent.len(), 2 + 4 * count);
            for missing in 1..=4 * count {
                assert!(Dot11Trigger::decode(&bytes[..bytes.len() - 2 - missing]).is_err());
            }
        }
    }

    #[test]
    fn trigger_unknown_boundaries_are_lossless_not_guessed() {
        for variant in 7..16 {
            let bytes = [variant, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1];
            let decoded = roundtrip(&bytes);
            assert!(decoded.users.is_empty());
            assert_eq!(
                decoded.remainder,
                Dot11TriggerRemainder::Opaque(vec![255, 255, 1])
            );
        }
        let bytes = [2, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 42];
        assert_eq!(
            roundtrip(&bytes).remainder,
            Dot11TriggerRemainder::Opaque(bytes[8..].to_vec())
        );
    }

    #[test]
    fn trigger_short_fields_are_structured_errors() {
        for len in 0..8 {
            assert_eq!(
                Dot11Trigger::decode(&[0; 8][..len]).unwrap_err(),
                CrafterError::buffer_too_short("dot11.trigger.common", 8, len)
            );
        }
        for len in 1..6 {
            let bytes = vec![0; 8 + len];
            assert!(Dot11Trigger::decode(&bytes).is_err());
        }
        for len in 0..4 {
            let mut bytes = vec![0; 8 + len];
            bytes[0] = 5;
            assert_eq!(
                Dot11Trigger::decode(&bytes).unwrap_err(),
                CrafterError::buffer_too_short("dot11.trigger.gcr_common", 4, len)
            );
        }
    }
}
