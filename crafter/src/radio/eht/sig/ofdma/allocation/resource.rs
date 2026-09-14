/// User-field interpretation selected by an EHT resource allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtOfdmaUserKind {
    NonMu,
    MuMimo,
}

/// Number of occupied tones in one EHT20 resource-unit component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EhtRuSize {
    Ru26,
    Ru52,
    Ru106,
    Ru242,
}

impl EhtRuSize {
    pub const fn tone_count(self) -> u16 {
        match self {
            Self::Ru26 => 26,
            Self::Ru52 => 52,
            Self::Ru106 => 106,
            Self::Ru242 => 242,
        }
    }
}

/// One equal-size RU component, identified by its one-based frequency index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtRuComponent {
    size: EhtRuSize,
    index: u8,
}

impl EhtRuComponent {
    pub(super) const fn new(size: EhtRuSize, index: u8) -> Self {
        Self { size, index }
    }

    pub const fn size(self) -> EhtRuSize {
        self.size
    }

    pub const fn index(self) -> u8 {
        self.index
    }

    pub const fn tone_count(self) -> u16 {
        self.size.tone_count()
    }

    /// Whether this component owns the signed 256-point FFT tone.
    pub fn contains_tone(self, tone: i16) -> bool {
        match (self.size, self.index) {
            (EhtRuSize::Ru26, 1) => (-121..=-96).contains(&tone),
            (EhtRuSize::Ru26, 2) => (-95..=-70).contains(&tone),
            (EhtRuSize::Ru26, 3) => (-68..=-43).contains(&tone),
            (EhtRuSize::Ru26, 4) => (-42..=-17).contains(&tone),
            (EhtRuSize::Ru26, 5) => (-16..=-4).contains(&tone) || (4..=16).contains(&tone),
            (EhtRuSize::Ru26, 6) => (17..=42).contains(&tone),
            (EhtRuSize::Ru26, 7) => (43..=68).contains(&tone),
            (EhtRuSize::Ru26, 8) => (70..=95).contains(&tone),
            (EhtRuSize::Ru26, 9) => (96..=121).contains(&tone),
            (EhtRuSize::Ru52, 1) => (-121..=-70).contains(&tone),
            (EhtRuSize::Ru52, 2) => (-68..=-17).contains(&tone),
            (EhtRuSize::Ru52, 3) => (17..=68).contains(&tone),
            (EhtRuSize::Ru52, 4) => (70..=121).contains(&tone),
            (EhtRuSize::Ru106, 1) => (-122..=-17).contains(&tone),
            (EhtRuSize::Ru106, 2) => (17..=122).contains(&tone),
            (EhtRuSize::Ru242, 1) => (-122..=-2).contains(&tone) || (2..=122).contains(&tone),
            _ => false,
        }
    }

    #[cfg(test)]
    pub(super) const fn first_tone(self) -> i16 {
        match (self.size, self.index) {
            (EhtRuSize::Ru26, 1) | (EhtRuSize::Ru52, 1) => -121,
            (EhtRuSize::Ru26, 2) => -95,
            (EhtRuSize::Ru26, 3) | (EhtRuSize::Ru52, 2) => -68,
            (EhtRuSize::Ru26, 4) => -42,
            (EhtRuSize::Ru26, 5) => -16,
            (EhtRuSize::Ru26, 6) | (EhtRuSize::Ru52, 3) | (EhtRuSize::Ru106, 2) => 17,
            (EhtRuSize::Ru26, 7) => 43,
            (EhtRuSize::Ru26, 8) | (EhtRuSize::Ru52, 4) => 70,
            (EhtRuSize::Ru26, 9) => 96,
            (EhtRuSize::Ru106, 1) | (EhtRuSize::Ru242, 1) => -122,
            _ => i16::MAX,
        }
    }
}

/// One frequency allocation: either an RU or a two-component MRU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EhtResourceUnit {
    components: [EhtRuComponent; 2],
    component_count: u8,
    users: u8,
}

impl EhtResourceUnit {
    pub(in crate::radio) const fn full_band(users: u8) -> Option<Self> {
        if users == 0 || users > 8 {
            return None;
        }
        Some(Self::ru(EhtRuComponent::new(EhtRuSize::Ru242, 1), users))
    }

    /// Decode the EHT Trigger RU Allocation field for a 20 MHz response.
    /// The low field bit is the primary-160 selector and must be zero here.
    pub(in crate::radio) fn from_trigger_20(raw: u8) -> Option<Self> {
        if raw & 1 != 0 {
            return None;
        }
        let code = raw >> 1;
        let component = |size, index| EhtRuComponent::new(size, index);
        Some(match code {
            0..=8 => Self::ru(component(EhtRuSize::Ru26, code + 1), 1),
            37..=40 => Self::ru(component(EhtRuSize::Ru52, code - 36), 1),
            53..=54 => Self::ru(component(EhtRuSize::Ru106, code - 52), 1),
            61 => Self::ru(component(EhtRuSize::Ru242, 1), 1),
            70 => Self::mru(component(EhtRuSize::Ru26, 2), component(EhtRuSize::Ru52, 2)),
            71 => Self::mru(component(EhtRuSize::Ru52, 2), component(EhtRuSize::Ru26, 5)),
            72 => Self::mru(component(EhtRuSize::Ru52, 3), component(EhtRuSize::Ru26, 8)),
            82 => Self::mru(
                component(EhtRuSize::Ru106, 1),
                component(EhtRuSize::Ru26, 5),
            ),
            83 => Self::mru(
                component(EhtRuSize::Ru26, 5),
                component(EhtRuSize::Ru106, 2),
            ),
            _ => return None,
        })
    }

    pub(super) const fn ru(component: EhtRuComponent, users: u8) -> Self {
        Self {
            components: [component, component],
            component_count: 1,
            users,
        }
    }

    pub(super) const fn mru(first: EhtRuComponent, second: EhtRuComponent) -> Self {
        Self {
            components: [first, second],
            component_count: 2,
            users: 1,
        }
    }

    pub fn components(&self) -> &[EhtRuComponent] {
        &self.components[..usize::from(self.component_count)]
    }

    pub const fn user_count(self) -> u8 {
        self.users
    }

    pub const fn user_kind(self) -> EhtOfdmaUserKind {
        if self.users > 1 {
            EhtOfdmaUserKind::MuMimo
        } else {
            EhtOfdmaUserKind::NonMu
        }
    }

    pub fn tone_count(self) -> u16 {
        self.components()
            .iter()
            .map(|component| component.tone_count())
            .sum()
    }

    pub fn contains_tone(self, tone: i16) -> bool {
        self.components()
            .iter()
            .any(|component| component.contains_tone(tone))
    }

    #[cfg(test)]
    pub(super) const fn first_tone(self) -> i16 {
        self.components[0].first_tone()
    }
}
