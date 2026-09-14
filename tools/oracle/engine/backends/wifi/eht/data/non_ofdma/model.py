"""Shared EHT20 non-OFDMA DATA modulation and scrambler model."""

MODES = {
    0: (1, 1, 2, 0),
    1: (2, 1, 2, 0),
    2: (2, 3, 4, 0),
    3: (4, 1, 2, 0),
    4: (4, 3, 4, 0),
    5: (6, 2, 3, 0),
    6: (6, 3, 4, 0),
    7: (6, 5, 6, 0),
    8: (8, 3, 4, 0),
    9: (8, 5, 6, 0),
    10: (10, 3, 4, 0),
    11: (10, 5, 6, 0),
    12: (12, 3, 4, 0),
    13: (12, 5, 6, 0),
    15: (1, 1, 2, 1),
}


def scramble(bits, seed):
    assert 0 < seed < 2048
    state = seed
    output = []
    for bit in bits:
        generated = state >> 10
        feedback = ((state >> 10) ^ (state >> 8)) & 1
        state = ((state << 1) | feedback) & 0x7FF
        output.append(bit ^ generated)
    return output
