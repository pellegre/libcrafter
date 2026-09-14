use super::{EhtResourceUnit, EhtRuComponent, EhtRuSize};

const fn component(size: EhtRuSize, index: u8) -> EhtRuComponent {
    EhtRuComponent::new(size, index)
}

const fn ru(size: EhtRuSize, index: u8) -> EhtResourceUnit {
    EhtResourceUnit::ru(component(size, index), 1)
}

const fn ru26(index: u8) -> EhtResourceUnit {
    ru(EhtRuSize::Ru26, index)
}

const fn ru52(index: u8) -> EhtResourceUnit {
    ru(EhtRuSize::Ru52, index)
}

const fn ru106(index: u8) -> EhtResourceUnit {
    ru(EhtRuSize::Ru106, index)
}

const fn mru(
    first_size: EhtRuSize,
    first_index: u8,
    second_size: EhtRuSize,
    second_index: u8,
) -> EhtResourceUnit {
    EhtResourceUnit::mru(
        component(first_size, first_index),
        component(second_size, second_index),
    )
}

const LOW_52_26: EhtResourceUnit = mru(EhtRuSize::Ru26, 2, EhtRuSize::Ru52, 2);
const HIGH_52_26: EhtResourceUnit = mru(EhtRuSize::Ru52, 3, EhtRuSize::Ru26, 8);
const LOW_106_26: EhtResourceUnit = mru(EhtRuSize::Ru106, 1, EhtRuSize::Ru26, 5);
const HIGH_106_26: EhtResourceUnit = mru(EhtRuSize::Ru26, 5, EhtRuSize::Ru106, 2);

const A0: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru26(3),
    ru26(4),
    ru26(5),
    ru26(6),
    ru26(7),
    ru26(8),
    ru26(9),
];
const A1: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru26(3),
    ru26(4),
    ru26(5),
    ru26(6),
    ru26(7),
    ru52(4),
];
const A2: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru26(3),
    ru26(4),
    ru26(5),
    ru52(3),
    ru26(8),
    ru26(9),
];
const A3: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru26(3),
    ru26(4),
    ru26(5),
    ru52(3),
    ru52(4),
];
const A4: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru52(2),
    ru26(5),
    ru26(6),
    ru26(7),
    ru26(8),
    ru26(9),
];
const A5: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru52(2),
    ru26(5),
    ru26(6),
    ru26(7),
    ru52(4),
];
const A6: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru52(2),
    ru26(5),
    ru52(3),
    ru26(8),
    ru26(9),
];
const A7: &[EhtResourceUnit] = &[ru26(1), ru26(2), ru52(2), ru26(5), ru52(3), ru52(4)];
const A8: &[EhtResourceUnit] = &[
    ru52(1),
    ru26(3),
    ru26(4),
    ru26(5),
    ru26(6),
    ru26(7),
    ru26(8),
    ru26(9),
];
const A9: &[EhtResourceUnit] = &[
    ru52(1),
    ru26(3),
    ru26(4),
    ru26(5),
    ru26(6),
    ru26(7),
    ru52(4),
];
const A10: &[EhtResourceUnit] = &[
    ru52(1),
    ru26(3),
    ru26(4),
    ru26(5),
    ru52(3),
    ru26(8),
    ru26(9),
];
const A11: &[EhtResourceUnit] = &[ru52(1), ru26(3), ru26(4), ru26(5), ru52(3), ru52(4)];
const A12: &[EhtResourceUnit] = &[
    ru52(1),
    ru52(2),
    ru26(5),
    ru26(6),
    ru26(7),
    ru26(8),
    ru26(9),
];
const A13: &[EhtResourceUnit] = &[ru52(1), ru52(2), ru26(5), ru26(6), ru26(7), ru52(4)];
const A14: &[EhtResourceUnit] = &[ru52(1), ru52(2), ru26(5), ru52(3), ru26(8), ru26(9)];
const A15: &[EhtResourceUnit] = &[ru52(1), ru52(2), ru26(5), ru52(3), ru52(4)];
const A16: &[EhtResourceUnit] = &[ru26(1), ru26(2), ru26(3), ru26(4), ru26(5), ru106(2)];
const A17: &[EhtResourceUnit] = &[ru26(1), ru26(2), ru52(2), ru26(5), ru106(2)];
const A18: &[EhtResourceUnit] = &[ru52(1), ru26(3), ru26(4), ru26(5), ru106(2)];
const A19: &[EhtResourceUnit] = &[ru52(1), ru52(2), ru26(5), ru106(2)];
const A20: &[EhtResourceUnit] = &[ru106(1), ru26(5), ru26(6), ru26(7), ru26(8), ru26(9)];
const A21: &[EhtResourceUnit] = &[ru106(1), ru26(5), ru26(6), ru26(7), ru52(4)];
const A22: &[EhtResourceUnit] = &[ru106(1), ru26(5), ru52(3), ru26(8), ru26(9)];
const A23: &[EhtResourceUnit] = &[ru106(1), ru26(5), ru52(3), ru52(4)];
const A24: &[EhtResourceUnit] = &[ru52(1), ru52(2), ru52(3), ru52(4)];
const A25: &[EhtResourceUnit] = &[ru106(1), ru26(5), ru106(2)];
const A32: &[EhtResourceUnit] = &[
    ru26(1),
    ru26(2),
    ru26(3),
    ru26(4),
    ru26(5),
    HIGH_52_26,
    ru26(9),
];
const A33: &[EhtResourceUnit] = &[ru26(1), ru26(2), ru52(2), ru26(5), HIGH_52_26, ru26(9)];
const A34: &[EhtResourceUnit] = &[ru52(1), ru26(3), ru26(4), ru26(5), HIGH_52_26, ru26(9)];
const A35: &[EhtResourceUnit] = &[ru52(1), ru52(2), ru26(5), HIGH_52_26, ru26(9)];
const A36: &[EhtResourceUnit] = &[
    ru26(1),
    LOW_52_26,
    ru26(5),
    ru26(6),
    ru26(7),
    ru26(8),
    ru26(9),
];
const A37: &[EhtResourceUnit] = &[ru26(1), LOW_52_26, ru26(5), ru26(6), ru26(7), ru52(4)];
const A38: &[EhtResourceUnit] = &[ru26(1), LOW_52_26, ru26(5), ru52(3), ru26(8), ru26(9)];
const A39: &[EhtResourceUnit] = &[ru26(1), LOW_52_26, ru26(5), ru52(3), ru52(4)];
const A40: &[EhtResourceUnit] = &[ru26(1), ru26(2), ru26(3), ru26(4), HIGH_106_26];
const A41: &[EhtResourceUnit] = &[ru26(1), ru26(2), ru52(2), HIGH_106_26];
const A42: &[EhtResourceUnit] = &[ru52(1), ru26(3), ru26(4), HIGH_106_26];
const A43: &[EhtResourceUnit] = &[ru52(1), ru52(2), HIGH_106_26];
const A44: &[EhtResourceUnit] = &[LOW_106_26, ru26(6), ru26(7), ru26(8), ru26(9)];
const A45: &[EhtResourceUnit] = &[LOW_106_26, ru26(6), ru26(7), ru52(4)];
const A46: &[EhtResourceUnit] = &[LOW_106_26, ru52(3), ru26(8), ru26(9)];
const A47: &[EhtResourceUnit] = &[LOW_106_26, ru52(3), ru52(4)];
const A48: &[EhtResourceUnit] = &[LOW_106_26, ru106(2)];
const A49: &[EhtResourceUnit] = &[LOW_106_26, HIGH_52_26, ru26(9)];
const A50: &[EhtResourceUnit] = &[ru106(1), HIGH_106_26];
const A51: &[EhtResourceUnit] = &[ru26(1), LOW_52_26, HIGH_106_26];
const A52: &[EhtResourceUnit] = &[ru106(1), ru26(5), HIGH_52_26, ru26(9)];
const A53: &[EhtResourceUnit] = &[ru26(1), LOW_52_26, ru26(5), ru106(2)];
const A54: &[EhtResourceUnit] = &[ru26(1), LOW_52_26, ru26(5), HIGH_52_26, ru26(9)];
const A55: &[EhtResourceUnit] = &[
    ru52(1),
    mru(EhtRuSize::Ru52, 2, EhtRuSize::Ru26, 5),
    ru52(3),
    ru52(4),
];

const fn full_band(users: u8) -> EhtResourceUnit {
    EhtResourceUnit::ru(component(EhtRuSize::Ru242, 1), users)
}

const A64: &[EhtResourceUnit] = &[full_band(1)];
const A65: &[EhtResourceUnit] = &[full_band(2)];
const A66: &[EhtResourceUnit] = &[full_band(3)];
const A67: &[EhtResourceUnit] = &[full_band(4)];
const A68: &[EhtResourceUnit] = &[full_band(5)];
const A69: &[EhtResourceUnit] = &[full_band(6)];
const A70: &[EhtResourceUnit] = &[full_band(7)];
const A71: &[EhtResourceUnit] = &[full_band(8)];

pub(super) const fn lookup(code: u16) -> Option<&'static [EhtResourceUnit]> {
    Some(match code {
        0 => A0,
        1 => A1,
        2 => A2,
        3 => A3,
        4 => A4,
        5 => A5,
        6 => A6,
        7 => A7,
        8 => A8,
        9 => A9,
        10 => A10,
        11 => A11,
        12 => A12,
        13 => A13,
        14 => A14,
        15 => A15,
        16 => A16,
        17 => A17,
        18 => A18,
        19 => A19,
        20 => A20,
        21 => A21,
        22 => A22,
        23 => A23,
        24 => A24,
        25 => A25,
        32 => A32,
        33 => A33,
        34 => A34,
        35 => A35,
        36 => A36,
        37 => A37,
        38 => A38,
        39 => A39,
        40 => A40,
        41 => A41,
        42 => A42,
        43 => A43,
        44 => A44,
        45 => A45,
        46 => A46,
        47 => A47,
        48 => A48,
        49 => A49,
        50 => A50,
        51 => A51,
        52 => A52,
        53 => A53,
        54 => A54,
        55 => A55,
        64 => A64,
        65 => A65,
        66 => A66,
        67 => A67,
        68 => A68,
        69 => A69,
        70 => A70,
        71 => A71,
        _ => return None,
    })
}
