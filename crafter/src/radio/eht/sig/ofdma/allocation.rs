use super::super::EhtSigError;

/// User-field interpretation selected by a 20 MHz RU Allocation subfield.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtOfdmaUserKind {
    NonMu,
    MuMimo,
}

/// Validated 20 MHz RU Allocation subfield and its User-field layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtRuAllocation20 {
    code: u16,
    users: u8,
    user_kind: EhtOfdmaUserKind,
}

impl EhtRuAllocation20 {
    pub(super) fn decode(code: u16) -> Result<Self, EhtSigError> {
        const ORDINARY_USERS: [u8; 26] = [
            9, 8, 8, 7, 8, 7, 7, 6, 8, 7, 7, 6, 7, 6, 6, 5, 6, 5, 5, 4, 6, 5, 5, 4, 4, 3,
        ];
        const MULTI_RU_USERS: [u8; 24] = [
            7, 6, 6, 5, 7, 6, 6, 5, 4, 4, 5, 4, 4, 3, 2, 5, 4, 4, 3, 2, 3, 3, 5, 4,
        ];
        let (users, user_kind) = match code {
            0..=25 => (ORDINARY_USERS[code as usize], EhtOfdmaUserKind::NonMu),
            32..=55 => (
                MULTI_RU_USERS[usize::from(code - 32)],
                EhtOfdmaUserKind::NonMu,
            ),
            64 => (1, EhtOfdmaUserKind::NonMu),
            65..=71 => ((code - 63) as u8, EhtOfdmaUserKind::MuMimo),
            _ => return Err(EhtSigError::RuAllocation(code)),
        };
        Ok(Self {
            code,
            users,
            user_kind,
        })
    }

    pub const fn code(self) -> u16 {
        self.code
    }

    pub const fn user_count(self) -> u8 {
        self.users
    }

    pub const fn user_kind(self) -> EhtOfdmaUserKind {
        self.user_kind
    }
}
