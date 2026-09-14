"""Independent EHT20 RU/MRU DATA tone geometry and joint mappings."""

from dataclasses import dataclass

from tools.oracle.engine.backends.wifi.eht.signal.ofdma.allocation import (
    component_tones,
)


PILOTS = {
    26: (
        (-116, -102),
        (-90, -76),
        (-62, -48),
        (-36, -22),
        (-10, 10),
        (22, 36),
        (48, 62),
        (76, 90),
        (102, 116),
    ),
    52: (
        (-116, -102, -90, -76),
        (-62, -48, -36, -22),
        (22, 36, 48, 62),
        (76, 90, 102, 116),
    ),
    106: ((-116, -90, -48, -22), (22, 48, 90, 116)),
    242: ((-116, -90, -48, -22, 22, 48, 90, 116),),
}
PILOT_SIGNS = {
    26: (1, -1),
    52: (1, 1, 1, -1),
    106: (1, 1, 1, -1),
    242: (1, 1, 1, -1, -1, 1, 1, 1),
}
MRU_PILOT_SIGNS = (1, 1, 1, -1, -1, 1)


@dataclass(frozen=True)
class Geometry:
    """Frequency-ordered tones and whole-resource bit mapping parameters."""

    data: tuple[int, ...]
    pilots: tuple[int, ...]
    component_sizes: tuple[int, ...]
    pilot_signs: tuple[int, ...]

    @classmethod
    def for_resource(cls, resource):
        data = []
        pilots = []
        sizes = []
        for component in resource.components:
            active = sorted(component_tones(component))
            component_pilots = PILOTS[component.size][component.index - 1]
            component_data = [tone for tone in active if tone not in component_pilots]
            assert len(active) == component.size
            assert len(component_data) == {26: 24, 52: 48, 106: 102, 242: 234}[
                component.size
            ]
            data.extend(component_data)
            pilots.extend(component_pilots)
            sizes.append(component.size)
        data.sort()
        pilots.sort()
        assert len(set(data)) == len(data)
        assert len(set(pilots)) == len(pilots)
        assert set(data).isdisjoint(pilots)
        if len(sizes) == 1:
            signs = PILOT_SIGNS[sizes[0]]
        else:
            assert sorted(sizes) in ([26, 52], [26, 106])
            assert len(pilots) == 6
            signs = MRU_PILOT_SIGNS
        return cls(tuple(data), tuple(pilots), tuple(sizes), signs)

    @property
    def tone_count(self):
        return sum(self.component_sizes)

    def short_tones(self, dcm):
        values = {
            (26, False): 6,
            (26, True): 2,
            (52, False): 12,
            (52, True): 6,
            (106, False): 24,
            (106, True): 12,
            (242, False): 60,
            (242, True): 30,
        }
        return sum(values[size, dcm] for size in self.component_sizes)

    def bcc_interleave(self, bits, bits_per_tone, dcm):
        if len(self.component_sizes) == 1:
            columns = {26: 8, 52: 16, 106: 17, 242: 26}[
                self.component_sizes[0]
            ]
            if dcm and self.component_sizes[0] != 106:
                columns //= 2
        else:
            columns = {
                (78, False): 18,
                (78, True): 12,
                (132, False): 21,
                (132, True): 21,
            }[self.tone_count, dcm]
        span = len(bits)
        assert span == len(self.data) // (1 + int(dcm)) * bits_per_tone
        assert span % columns == 0
        significance = max(bits_per_tone // 2, 1)
        output = [0] * span
        for index, bit in enumerate(bits):
            transposed = (span // columns) * (index % columns) + index // columns
            target = (
                significance * (transposed // significance)
                + (transposed + span - columns * transposed // span) % significance
            )
            output[target] = bit
        return output

    def ldpc_target(self, index, dcm):
        mapped_tones = len(self.data) // (1 + int(dcm))
        if len(self.component_sizes) == 1:
            distance = {
                (26, False): 1,
                (26, True): 1,
                (52, False): 3,
                (52, True): 1,
                (106, False): 6,
                (106, True): 3,
                (242, False): 9,
                (242, True): 9,
            }[self.component_sizes[0], dcm]
        else:
            distance = {
                (78, False): 4,
                (78, True): 3,
                (132, False): 6,
                (132, True): 3,
            }[self.tone_count, dcm]
        assert 0 <= index < mapped_tones
        assert mapped_tones % distance == 0
        columns = mapped_tones // distance
        return distance * (index % columns) + index // columns

    def pilot_sign(self, symbol, index):
        return self.pilot_signs[(symbol + index) % len(self.pilot_signs)]
