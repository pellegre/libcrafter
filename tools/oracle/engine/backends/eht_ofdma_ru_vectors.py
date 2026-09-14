"""Independent EHT20 OFDMA RU and MRU allocation vectors.

The allocation rows are transcribed from IEEE 802.11be-2024 Table 36-34.
They intentionally do not import the production Rust allocation table.
"""

import argparse
from dataclasses import dataclass
from pathlib import Path


OUT = (
    Path(__file__).resolve().parents[4]
    / "crafter/tests/fixtures/iq/eht-ofdma-ru-index.tsv"
)


@dataclass(frozen=True)
class Component:
    size: int
    index: int


@dataclass(frozen=True)
class Resource:
    components: tuple[Component, ...]
    users: int = 1


def ru(size, index, users=1):
    return Resource((Component(size, index),), users)


def mru(first_size, first_index, second_size, second_index):
    return Resource(
        (Component(first_size, first_index), Component(second_size, second_index))
    )


R26 = lambda index: ru(26, index)
R52 = lambda index: ru(52, index)
R106 = lambda index: ru(106, index)
LOW_52_26 = mru(26, 2, 52, 2)
HIGH_52_26 = mru(52, 3, 26, 8)
LOW_106_26 = mru(106, 1, 26, 5)
HIGH_106_26 = mru(26, 5, 106, 2)


# Resources are listed in increasing frequency order. Each list item is one
# user allocation except the 242-tone entries, whose explicit user count
# selects non-MU or MU-MIMO User field interpretation.
ALLOCATIONS = {
    0: [R26(1), R26(2), R26(3), R26(4), R26(5), R26(6), R26(7), R26(8), R26(9)],
    1: [R26(1), R26(2), R26(3), R26(4), R26(5), R26(6), R26(7), R52(4)],
    2: [R26(1), R26(2), R26(3), R26(4), R26(5), R52(3), R26(8), R26(9)],
    3: [R26(1), R26(2), R26(3), R26(4), R26(5), R52(3), R52(4)],
    4: [R26(1), R26(2), R52(2), R26(5), R26(6), R26(7), R26(8), R26(9)],
    5: [R26(1), R26(2), R52(2), R26(5), R26(6), R26(7), R52(4)],
    6: [R26(1), R26(2), R52(2), R26(5), R52(3), R26(8), R26(9)],
    7: [R26(1), R26(2), R52(2), R26(5), R52(3), R52(4)],
    8: [R52(1), R26(3), R26(4), R26(5), R26(6), R26(7), R26(8), R26(9)],
    9: [R52(1), R26(3), R26(4), R26(5), R26(6), R26(7), R52(4)],
    10: [R52(1), R26(3), R26(4), R26(5), R52(3), R26(8), R26(9)],
    11: [R52(1), R26(3), R26(4), R26(5), R52(3), R52(4)],
    12: [R52(1), R52(2), R26(5), R26(6), R26(7), R26(8), R26(9)],
    13: [R52(1), R52(2), R26(5), R26(6), R26(7), R52(4)],
    14: [R52(1), R52(2), R26(5), R52(3), R26(8), R26(9)],
    15: [R52(1), R52(2), R26(5), R52(3), R52(4)],
    16: [R26(1), R26(2), R26(3), R26(4), R26(5), R106(2)],
    17: [R26(1), R26(2), R52(2), R26(5), R106(2)],
    18: [R52(1), R26(3), R26(4), R26(5), R106(2)],
    19: [R52(1), R52(2), R26(5), R106(2)],
    20: [R106(1), R26(5), R26(6), R26(7), R26(8), R26(9)],
    21: [R106(1), R26(5), R26(6), R26(7), R52(4)],
    22: [R106(1), R26(5), R52(3), R26(8), R26(9)],
    23: [R106(1), R26(5), R52(3), R52(4)],
    24: [R52(1), R52(2), R52(3), R52(4)],
    25: [R106(1), R26(5), R106(2)],
    32: [R26(1), R26(2), R26(3), R26(4), R26(5), HIGH_52_26, R26(9)],
    33: [R26(1), R26(2), R52(2), R26(5), HIGH_52_26, R26(9)],
    34: [R52(1), R26(3), R26(4), R26(5), HIGH_52_26, R26(9)],
    35: [R52(1), R52(2), R26(5), HIGH_52_26, R26(9)],
    36: [R26(1), LOW_52_26, R26(5), R26(6), R26(7), R26(8), R26(9)],
    37: [R26(1), LOW_52_26, R26(5), R26(6), R26(7), R52(4)],
    38: [R26(1), LOW_52_26, R26(5), R52(3), R26(8), R26(9)],
    39: [R26(1), LOW_52_26, R26(5), R52(3), R52(4)],
    40: [R26(1), R26(2), R26(3), R26(4), HIGH_106_26],
    41: [R26(1), R26(2), R52(2), HIGH_106_26],
    42: [R52(1), R26(3), R26(4), HIGH_106_26],
    43: [R52(1), R52(2), HIGH_106_26],
    44: [LOW_106_26, R26(6), R26(7), R26(8), R26(9)],
    45: [LOW_106_26, R26(6), R26(7), R52(4)],
    46: [LOW_106_26, R52(3), R26(8), R26(9)],
    47: [LOW_106_26, R52(3), R52(4)],
    48: [LOW_106_26, R106(2)],
    49: [LOW_106_26, HIGH_52_26, R26(9)],
    50: [R106(1), HIGH_106_26],
    51: [R26(1), LOW_52_26, HIGH_106_26],
    52: [R106(1), R26(5), HIGH_52_26, R26(9)],
    53: [R26(1), LOW_52_26, R26(5), R106(2)],
    54: [R26(1), LOW_52_26, R26(5), HIGH_52_26, R26(9)],
    55: [R52(1), mru(52, 2, 26, 5), R52(3), R52(4)],
    **{code: [ru(242, 1, code - 63)] for code in range(64, 72)},
}


def component_tones(component):
    size, index = component.size, component.index
    ranges = {
        26: [(-121, -96), (-95, -70), (-68, -43), (-42, -17),
             (-16, -4, 4, 16), (17, 42), (43, 68), (70, 95), (96, 121)],
        52: [(-121, -70), (-68, -17), (17, 68), (70, 121)],
        106: [(-122, -17), (17, 122)],
        242: [(-122, -2, 2, 122)],
    }
    assert size in ranges and 1 <= index <= len(ranges[size])
    bounds = ranges[size][index - 1]
    if len(bounds) == 2:
        tones = set(range(bounds[0], bounds[1] + 1))
    else:
        tones = set(range(bounds[0], bounds[1] + 1))
        tones.update(range(bounds[2], bounds[3] + 1))
    assert len(tones) == size
    return tones


def validate():
    assert len(ALLOCATIONS) == 58
    assert set(ALLOCATIONS) == set(range(26)) | set(range(32, 56)) | set(range(64, 72))
    for code, resources in ALLOCATIONS.items():
        occupied = set()
        previous = -10_000
        for resource in resources:
            assert 1 <= resource.users <= 8
            assert len(resource.components) in (1, 2)
            if len(resource.components) == 2:
                assert sorted(component.size for component in resource.components) in (
                    [26, 52], [26, 106]
                )
                assert resource.users == 1
            tones = set()
            for component in resource.components:
                component_set = component_tones(component)
                assert tones.isdisjoint(component_set), (code, resource)
                tones.update(component_set)
            assert min(tones) > previous, (code, resources)
            previous = max(tones)
            assert occupied.isdisjoint(tones), (code, resource)
            occupied.update(tones)
        expected = sum(
            component.size
            for resource in resources
            for component in resource.components
        )
        assert len(occupied) == expected, (code, len(occupied), expected)
        assert len(occupied) <= 242
    assert sum(component.size for resource in ALLOCATIONS[24] for component in resource.components) == 208


def generate():
    validate()
    rows = ["code\tstatus\tusers\tkind\tresources\toccupied_tones"]
    for code in range(512):
        resources = ALLOCATIONS.get(code)
        if resources is None:
            rows.append(f"{code}\tunsupported\t0\t-\t-\t0")
            continue
        users = sum(resource.users for resource in resources)
        kind = "mu" if any(resource.users > 1 for resource in resources) else "nonmu"
        encoded = ";".join(
            "+".join(f"{part.size}:{part.index}" for part in resource.components)
            + (f"@{resource.users}" if resource.users > 1 else "")
            for resource in resources
        )
        occupied = len({
            tone
            for resource in resources
            for component in resource.components
            for tone in component_tones(component)
        })
        rows.append(f"{code}\tok\t{users}\t{kind}\t{encoded}\t{occupied}")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    output = generate()
    if args.write:
        OUT.write_text(output)
    else:
        assert OUT.read_text() == output, "EHT20 OFDMA RU inventory differs"
    print("512 EHT20 OFDMA RU allocation contexts verified")
