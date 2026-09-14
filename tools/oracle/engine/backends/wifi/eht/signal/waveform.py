"""Shared EHT20 preamble, EHT-SIG modulation, and training synthesis."""

import math

import tools.oracle.engine.backends.wifi.he.training as training
import tools.oracle.engine.backends.wifi.ht.bcc as ht
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.prefix.iq import symbol
from tools.oracle.engine.backends.wifi.he.sig_b.coded import encode
from tools.oracle.engine.backends.wifi.he.sig_b.modulation import modulate
from tools.oracle.engine.backends.wifi.he.signal import encoded


MODES = {
    0: (0, 0, 26, 2),
    1: (1, 0, 52, 1),
    2: (3, 0, 104, 1),
    3: (0, 1, 13, 4),
}


def prefix(usig, legacy_length=300):
    legacy = base.signal("1101", legacy_length)
    samples = [0j] * 37 + [value * math.sqrt(52 / 56) for value in base.preamble()]
    samples += symbol(base.interleave(base.encode(legacy), 1), legacy=True)
    samples += symbol(base.interleave(base.encode(legacy), 1), legacy=True)
    coded = encoded(usig)
    samples += symbol(coded[:52]) + symbol(coded[52:])
    return samples


def append_training(samples, ltf_mode, ltf_code):
    stf_frequency = [0j] * 245
    for tone, value in zip(
        range(-112, 113, 16),
        [-1, -1, -1, 1, 1, 1, -1, 1, 1, 1, -1, 1, 1, -1, 1],
    ):
        if tone:
            stf_frequency[tone + 122] = value * (1 + 1j) / math.sqrt(2)
    samples += [
        value * 4 * math.sqrt(52 / 14) for value in training.ifft(stf_frequency)
    ][:80]

    ltf_size, guard = [(2, 16), (2, 32), (4, 16), (4, 64)][ltf_mode]
    ltf_symbols = [1, 2, 4, 6, 8][ltf_code]
    sequence = {2: training.LTF2, 4: training.LTF4}[ltf_size]
    normalization = 242 * ltf_size / 4
    ltf = [
        value * 4 * math.sqrt(52 / normalization)
        for value in training.ifft(
            [{"-": -1, "+": 1, "0": 0}[value] for value in sequence]
        )
    ][: 64 * ltf_size]
    coefficients = {
        1: [1],
        2: [1, -1],
        4: [1, -1, 1, 1],
        6: [1, -1, 1, 1, 1, -1],
        8: [1, -1, 1, 1, 1, -1, 1, 1],
    }[ltf_symbols]
    ltf_start = len(samples)
    for coefficient in coefficients:
        wave = [coefficient * value for value in ltf]
        samples += wave[-guard:] + wave
    return ltf_size, guard, ltf_symbols, ltf_start, len(samples)


def signaling(blocks, raw_mcs, symbols, actual_mcs=None):
    actual_mcs = raw_mcs if actual_mcs is None else actual_mcs
    mcs, dcm, dbps, _ = MODES[actual_mcs]
    padding = symbols * dbps - sum(map(len, blocks))
    assert padding >= 0
    encoded_blocks = [list(bits) for bits in blocks]
    encoded_blocks[-1] += [
        int(index % 7 in (0, 2, 3, 6)) for index in range(padding)
    ]
    coded = "".join(
        str(value)
        for bits in encoded_blocks
        for pair in encode(bits)
        for value in pair
    )
    points = [
        complex(*map(float, point.split(",")))
        for point in modulate(coded, mcs, dcm).split(";")
    ]
    assert len(points) == symbols * 52
    energy = [1, 2, 2, 10, 10, 42][mcs]
    pilot_bits = base.scramble([0] * (symbols + 4), 127)
    samples = []
    for index in range(symbols):
        frequency = [0j] * 57
        for tone, value in zip(
            ht.CARRIERS, points[52 * index : 52 * (index + 1)]
        ):
            frequency[tone + 28] = value / math.sqrt(energy)
        for tone, sign in [(-21, 1), (-7, 1), (7, 1), (21, -1)]:
            frequency[tone + 28] = sign * (1 - 2 * pilot_bits[index + 4])
        time = [value * math.sqrt(52 / 56) for value in ht.ifft(frequency)]
        samples += time[-16:] + time
    return samples
