//! HE meanings for the shared Trigger Common and User Info wire fields.

trigger_fields!(Dot11TriggerCommonFields, 8;
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

impl Dot11TriggerCommonFields {
    /// Both discriminator bits are one for an HE-variant Common Info field.
    pub const fn is_he_variant(self) -> bool {
        self.sig_a2_reserved & 3 == 3
    }
}

// Normal User Info fields, not NFRP's different five-octet layout.
// `spatial_allocation` is SS allocation or RA-RU information depending on AID.
trigger_fields!(Dot11TriggerUserFields, 5;
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
