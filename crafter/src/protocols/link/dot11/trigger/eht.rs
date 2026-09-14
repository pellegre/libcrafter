//! EHT meanings for Trigger Common, Special User, and User Info fields.

use super::{Dot11Trigger, Dot11TriggerCommonFields, Dot11TriggerRemainder, Dot11TriggerUser};
use crate::error::{CrafterError, Result};

trigger_fields!(Dot11EhtTriggerCommonFields, 8;
    trigger_type: u8 = 0,4;
    ul_length: u16 = 4,12;
    more_tf: bool = 16,1;
    cs_required: bool = 17,1;
    bandwidth: u8 = 18,2;
    gi_ltf: u8 = 20,2;
    reserved_22: bool = 22,1;
    ltf_symbols: u8 = 23,3;
    reserved_26: bool = 26,1;
    ldpc_extra_segment: bool = 27,1;
    ap_tx_power: u8 = 28,6;
    pre_fec_padding_raw: u8 = 34,2;
    pe_disambiguity: bool = 36,1;
    spatial_reuse: u16 = 37,16;
    reserved_53: bool = 53,1;
    he_eht_p160: bool = 54,1;
    special_user_info_absent: bool = 55,1;
    eht_reserved: u8 = 56,7;
    reserved_63: bool = 63,1;
);

impl Default for Dot11EhtTriggerCommonFields {
    fn default() -> Self {
        Self::from_bits((301 << 4) | (1 << 20) | (127 << 56))
    }
}

impl From<Dot11EhtTriggerCommonFields> for Dot11TriggerCommonFields {
    fn from(fields: Dot11EhtTriggerCommonFields) -> Self {
        Self::from_bits(fields.bits())
    }
}

impl From<Dot11TriggerCommonFields> for Dot11EhtTriggerCommonFields {
    fn from(fields: Dot11TriggerCommonFields) -> Self {
        Self::from_bits(fields.bits())
    }
}

trigger_fields!(Dot11EhtTriggerSpecialUserFields, 5;
    aid12: u16 = 0,12;
    phy_version: u8 = 12,3;
    bandwidth_extension: u8 = 15,2;
    spatial_reuse_1: u8 = 17,4;
    spatial_reuse_2: u8 = 21,4;
    usig_disregard_validate: u16 = 25,12;
    reserved: u8 = 37,3;
);

impl Default for Dot11EhtTriggerSpecialUserFields {
    fn default() -> Self {
        Self::from_bits(2007 | (4095 << 25))
    }
}

trigger_fields!(Dot11EhtTriggerUserFields, 5;
    aid12: u16 = 0,12;
    ru_allocation: u8 = 12,8;
    ldpc: bool = 20,1;
    mcs: u8 = 21,4;
    reserved: bool = 25,1;
    spatial_allocation: u8 = 26,6;
    target_receive_power: u8 = 32,7;
    ps160: bool = 39,1;
);

impl Default for Dot11EhtTriggerUserFields {
    fn default() -> Self {
        Self::from_bits(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EhtTriggerSpecialUser {
    pub fields: Dot11EhtTriggerSpecialUserFields,
    pub dependent: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EhtTriggerUser {
    pub fields: Dot11EhtTriggerUserFields,
    pub dependent: Vec<u8>,
}

/// Per-station User Info interpreted using the EHT Common Info discriminators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dot11EhtTriggerUserInfo {
    He(Dot11TriggerUser),
    Eht(Dot11EhtTriggerUser),
}

/// Typed EHT interpretation of a losslessly decoded `Dot11Trigger` layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dot11EhtTrigger {
    pub common: Dot11EhtTriggerCommonFields,
    pub dependent_common: Vec<u8>,
    pub special: Dot11EhtTriggerSpecialUser,
    pub users: Vec<Dot11EhtTriggerUserInfo>,
    pub remainder: Dot11TriggerRemainder,
}

impl Dot11EhtTrigger {
    pub fn new(common: Dot11EhtTriggerCommonFields, special: Dot11EhtTriggerSpecialUser) -> Self {
        Self {
            common,
            dependent_common: Vec::new(),
            special,
            users: Vec::new(),
            remainder: Dot11TriggerRemainder::None,
        }
    }

    pub fn user(mut self, user: Dot11EhtTriggerUser) -> Self {
        self.users.push(Dot11EhtTriggerUserInfo::Eht(user));
        self
    }

    pub fn he_user(mut self, user: Dot11TriggerUser) -> Self {
        self.users.push(Dot11EhtTriggerUserInfo::He(user));
        self
    }

    pub fn eht_users(&self) -> impl Iterator<Item = &Dot11EhtTriggerUser> {
        self.users.iter().filter_map(|user| match user {
            Dot11EhtTriggerUserInfo::Eht(user) => Some(user),
            Dot11EhtTriggerUserInfo::He(_) => None,
        })
    }

    pub fn into_trigger(self) -> Dot11Trigger {
        self.into()
    }
}

impl TryFrom<&Dot11Trigger> for Dot11EhtTrigger {
    type Error = CrafterError;

    fn try_from(trigger: &Dot11Trigger) -> Result<Self> {
        let common = Dot11EhtTriggerCommonFields::from_bits(trigger.common.bits());
        if common.special_user_info_absent {
            return Err(CrafterError::invalid_field_value(
                "dot11.trigger.common",
                "does not identify an EHT variant Trigger frame",
            ));
        }
        if matches!(trigger.remainder, Dot11TriggerRemainder::Opaque(_)) {
            return Err(CrafterError::invalid_field_value(
                "dot11.trigger.remainder",
                "opaque bytes prevent complete EHT User Info interpretation",
            ));
        }
        let (special, users) = trigger.users.split_first().ok_or_else(|| {
            CrafterError::invalid_field_value(
                "dot11.trigger.users",
                "EHT Trigger frame has no Special User Info field",
            )
        })?;
        let special_fields = Dot11EhtTriggerSpecialUserFields::from_bits(special.fields.bits());
        if special_fields.aid12 != 2007 {
            return Err(CrafterError::invalid_field_value(
                "dot11.trigger.special_user.aid12",
                "EHT Special User Info is not the first User Info field",
            ));
        }
        if special_fields.phy_version != 0 {
            return Err(CrafterError::invalid_field_value(
                "dot11.trigger.special_user.phy_version",
                "unsupported EHT PHY version",
            ));
        }
        let mut eht_users = Vec::with_capacity(users.len());
        for user in users {
            let fields = Dot11EhtTriggerUserFields::from_bits(user.fields.bits());
            if fields.aid12 == 2007 {
                return Err(CrafterError::invalid_field_value(
                    "dot11.trigger.user.aid12",
                    "additional EHT Special User Info field",
                ));
            }
            eht_users.push(if common.he_eht_p160 && !fields.ps160 {
                Dot11EhtTriggerUserInfo::He(user.clone())
            } else {
                Dot11EhtTriggerUserInfo::Eht(Dot11EhtTriggerUser {
                    fields,
                    dependent: user.dependent.clone(),
                })
            });
        }
        Ok(Self {
            common,
            dependent_common: trigger.dependent_common.clone(),
            special: Dot11EhtTriggerSpecialUser {
                fields: special_fields,
                dependent: special.dependent.clone(),
            },
            users: eht_users,
            remainder: trigger.remainder.clone(),
        })
    }
}

impl From<Dot11EhtTrigger> for Dot11Trigger {
    fn from(eht: Dot11EhtTrigger) -> Self {
        let mut users = Vec::with_capacity(eht.users.len() + 1);
        users.push(Dot11TriggerUser {
            fields: super::Dot11TriggerUserFields::from_bits(eht.special.fields.bits()),
            dependent: eht.special.dependent,
        });
        users.extend(eht.users.into_iter().map(|user| match user {
            Dot11EhtTriggerUserInfo::He(user) => user,
            Dot11EhtTriggerUserInfo::Eht(user) => Dot11TriggerUser {
                fields: super::Dot11TriggerUserFields::from_bits(user.fields.bits()),
                dependent: user.dependent,
            },
        }));
        Self {
            common: Dot11TriggerCommonFields::from_bits(eht.common.bits()),
            dependent_common: eht.dependent_common,
            users,
            remainder: eht.remainder,
        }
    }
}

impl Dot11Trigger {
    pub fn eht(&self) -> Result<Dot11EhtTrigger> {
        Dot11EhtTrigger::try_from(self)
    }
}
