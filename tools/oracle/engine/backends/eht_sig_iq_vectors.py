"""Independent 20 MHz EHT-SIG IQ for downlink EHT PPDUs.

IEEE 802.11 TGbe 11-21/0140r2 and 11-21/1386r1. The forward model uses
independent CRC, BCC, interleaving, constellation and direct-DFT synthesis.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile

import ofdm_vectors as base
import ht_bcc_vectors as ht
import he_training_vectors as training
from eht_sig_vectors import (
    DATA_BCC_MODES,
    DATA_MODES,
    OFDMA_USERS,
    block,
    data_bcc_case,
    data_ldpc_case,
    data_ldpc_layout,
    mu_blocks,
    ofdma_blocks,
    repair as repair_sig,
)
from eht_usig_vectors import mu_header, put
from he_prefix_iq_vectors import symbol
from he_sig_b_coded_vectors import encode
from he_sig_b_modulation_vectors import modulate
from he_signal_vectors import checksum, encoded
from vht_ampdu_vectors import delimiter
from vht_bcc_iq_vectors import constellation


OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq"
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
        value * 4 * math.sqrt(52 / 14)
        for value in training.ifft(stf_frequency)
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
    ][:64 * ltf_size]
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


DATA_PILOTS = [-116, -90, -48, -22, 22, 48, 90, 116]
DATA_TONES = [tone for tone in training.TONES if tone not in DATA_PILOTS]
DATA_PILOT_SIGNS = [1, 1, 1, -1, -1, 1, 1, 1]


def data_interleave(bits, bits_per_tone, dcm):
    columns = 26 // (1 + int(dcm))
    span = len(bits)
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


def data_constellation(bits):
    if len(bits) <= 8:
        return constellation(bits)
    width = len(bits) // 2
    labels = {
        format(index ^ (index >> 1), f"0{width}b"): value
        for index, value in enumerate(range(-(2 ** width - 1), 2 ** width, 2))
    }
    label = "".join(map(str, bits))
    energy = {10: 682, 12: 2730}[len(bits)]
    return complex(labels[label[:width]], labels[label[width:]]) / math.sqrt(energy)


def data_symbol(
    bits, bits_per_tone, dcm, symbol_index, polarity, guard, ldpc=False
):
    mapped = bits if ldpc else data_interleave(bits, bits_per_tone, dcm)
    frequency = [0j] * 245
    tones = len(DATA_TONES) // (1 + int(dcm))
    for index in range(tones):
        target = (
            9 * (index % (tones // 9)) + index // (tones // 9)
            if ldpc else index
        )
        label = mapped[index * bits_per_tone:(index + 1) * bits_per_tone]
        lower = data_constellation(label)
        frequency[DATA_TONES[target] + 122] = lower
        if dcm:
            frequency[DATA_TONES[target + tones] + 122] = lower * (
                -1 if (index + tones) % 2 else 1
            )
    for index, tone in enumerate(DATA_PILOTS):
        sign = DATA_PILOT_SIGNS[(symbol_index + index) % len(DATA_PILOT_SIGNS)]
        frequency[tone + 122] = polarity * sign
    wave = [
        value * 4 * math.sqrt(52 / 242)
        for value in training.ifft(frequency)
    ]
    return wave[-guard:] + wave


def data_bcc_waveform(mcs, ltf_mode, padding, impaired):
    signal_symbols = 2
    data_symbols = (
        [13, 15, 14, 11] if mcs == 15 else [8, 10, 9, 6]
    )[ltf_mode]
    ltf_stride = [144, 160, 272, 320][ltf_mode]
    rounded = 320 + 80 * signal_symbols + ltf_stride
    rounded += data_symbols * [272, 288, 272, 320][ltf_mode]
    assert rounded % 80 == 0
    legacy_length = 3 * (rounded // 80 - 1)

    case = 65536 + 1024 * mcs + 64 * ltf_mode + padding
    bits, _ = block(case)
    for start, width, value in [
        (0, 4, 0),
        (4, 2, ltf_mode),
        (6, 3, 0),
        (9, 1, 0),
        (10, 2, padding % 4),
        (12, 1, 0),
        (17, 3, 0),
        (31, 4, mcs),
        (35, 1, 0),
        (36, 4, 0),
        (40, 1, 0),
        (41, 1, 0),
    ]:
        put(bits, start, width, value)
    repair_sig(bits)
    usig, _ = mu_header(case, 0, 0, 1, 0, signal_symbols)
    samples = prefix(usig, legacy_length)
    samples += signaling([bits], 0, signal_symbols)
    _, guard, _, ltf_start, data_start = append_training(samples, ltf_mode, 0)

    values, _, _ = data_bcc_case(mcs, padding, data_symbols)
    mpdu = base.frame(0)
    psdu = bytearray(delimiter(len(mpdu)) + mpdu)
    psdu += b"\xa5" * min(-len(psdu) % 4, values[13] - len(psdu))
    while len(psdu) + 4 <= values[13]:
        psdu += delimiter(0, 1)
    psdu += b"\xa5" * (values[13] - len(psdu))
    values, psdu, coded = data_bcc_case(
        mcs, padding, data_symbols, psdu
    )
    bits_per_tone = DATA_BCC_MODES[mcs][0]
    coded_per_symbol = values[7]
    pilot_bits = base.scramble([0] * (4 + signal_symbols + data_symbols), 127)
    for symbol_index in range(data_symbols):
        start = symbol_index * coded_per_symbol
        samples += data_symbol(
            coded[start:start + coded_per_symbol],
            bits_per_tone,
            mcs == 15,
            symbol_index,
            1 - 2 * pilot_bits[4 + signal_symbols + symbol_index],
            guard,
        )
    data_end = len(samples)
    assert data_end == 37 + 400 + rounded

    if impaired:
        samples = [
            (value + (0.22j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.45 + 0.01 * index))
            for index, value in enumerate(samples)
        ]
    gain = min(
        180,
        120 / max(max(abs(value.real), abs(value.imag)) for value in samples),
    )
    assert all(max(abs(value.real), abs(value.imag)) * gain < 127 for value in samples)
    return (
        base.quantize(samples, scale=gain),
        "".join(map(str, usig)),
        "".join(map(str, bits)),
        psdu.hex(),
        data_symbols,
        legacy_length,
        guard,
        ltf_start,
        data_start,
        data_end,
    )


def data_ldpc_candidate(mcs, ltf_mode, initial_padding):
    ltf_stride = [144, 160, 272, 320][ltf_mode]
    data_stride = [272, 288, 272, 320][ltf_mode]
    fixed = 320 + 160 + ltf_stride
    for initial_symbols in range(1, 101):
        sizing = data_ldpc_layout(mcs, initial_symbols, initial_padding)
        psdu_bytes = (sizing[8] - 16) // 8
        if (
            psdu_bytes >= 60
            and (fixed + sizing[0] * data_stride) % 80 == 0
        ):
            return initial_symbols
    raise AssertionError((mcs, ltf_mode, initial_padding))


def data_ldpc_waveform(mcs, ltf_mode, initial_padding, impaired):
    signal_symbols = 2
    initial_symbols = data_ldpc_candidate(mcs, ltf_mode, initial_padding)
    values, _, _ = data_ldpc_case(mcs, initial_symbols, initial_padding)
    symbols, padding, extra = values[3:6]
    ltf_stride = [144, 160, 272, 320][ltf_mode]
    rounded = 320 + 80 * signal_symbols + ltf_stride
    rounded += symbols * [272, 288, 272, 320][ltf_mode]
    assert rounded % 80 == 0
    legacy_length = 3 * (rounded // 80 - 1)

    case = 131072 + 4096 * mcs + 128 * ltf_mode + initial_padding
    bits, _ = block(case)
    for start, width, value in [
        (0, 4, 0),
        (4, 2, ltf_mode),
        (6, 3, 0),
        (9, 1, extra),
        (10, 2, padding % 4),
        (12, 1, 0),
        (17, 3, 0),
        (31, 4, mcs),
        (35, 1, 0),
        (36, 4, 0),
        (40, 1, 0),
        (41, 1, 1),
    ]:
        put(bits, start, width, value)
    repair_sig(bits)
    usig, _ = mu_header(case, 0, 0, 1, 0, signal_symbols)
    samples = prefix(usig, legacy_length)
    samples += signaling([bits], 0, signal_symbols)
    _, guard, _, ltf_start, data_start = append_training(samples, ltf_mode, 0)

    mpdu = base.frame(0)
    psdu = bytearray(delimiter(len(mpdu)) + mpdu)
    psdu += b"\xa5" * min(-len(psdu) % 4, values[17] - len(psdu))
    while len(psdu) + 4 <= values[17]:
        psdu += delimiter(0, 1)
    psdu += b"\xa5" * (values[17] - len(psdu))
    values, psdu, coded = data_ldpc_case(
        mcs, initial_symbols, initial_padding, psdu
    )
    bits_per_tone = DATA_MODES[mcs][0]
    coded_per_symbol = values[11]
    pilot_bits = base.scramble([0] * (4 + signal_symbols + symbols), 127)
    for symbol_index in range(symbols):
        start = symbol_index * coded_per_symbol
        samples += data_symbol(
            coded[start:start + coded_per_symbol],
            bits_per_tone,
            mcs == 15,
            symbol_index,
            1 - 2 * pilot_bits[4 + signal_symbols + symbol_index],
            guard,
            True,
        )
    data_end = len(samples)
    assert data_end == 37 + 400 + rounded

    if impaired:
        samples = [
            (value + (0.18j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.35 + 0.007 * index))
            for index, value in enumerate(samples)
        ]
    peak = max(max(abs(value.real), abs(value.imag)) for value in samples)
    gain = 125 / peak if bits_per_tone == 12 else min(180, 120 / peak)
    assert all(max(abs(value.real), abs(value.imag)) * gain < 127 for value in samples)
    return (
        base.quantize(samples, scale=gain),
        "".join(map(str, usig)),
        "".join(map(str, bits)),
        psdu.hex(),
        initial_symbols,
        symbols,
        padding,
        extra,
        legacy_length,
        guard,
        ltf_start,
        data_start,
        data_end,
    )


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
        for tone, value in zip(ht.CARRIERS, points[52 * index:52 * (index + 1)]):
            frequency[tone + 28] = value / math.sqrt(energy)
        for tone, sign in [(-21, 1), (-7, 1), (7, 1), (21, -1)]:
            frequency[tone + 28] = sign * (1 - 2 * pilot_bits[index + 4])
        time = [value * math.sqrt(52 / 56) for value in ht.ifft(frequency)]
        samples += time[-16:] + time
    return samples


def waveform(case, raw_mcs, impaired=False, damage=None):
    _, _, _, expected_symbols = MODES[raw_mcs]
    advertised_symbols = expected_symbols
    bandwidth = 0
    actual_mcs = raw_mcs
    bits, _ = block(case)
    if damage == "crc":
        bits[42] ^= 1
    elif damage == "tail":
        bits[49] = 1
    elif damage == "users":
        put(bits, 17, 3, 1)
        repair_sig(bits)
    elif damage == "ltf":
        put(bits, 6, 3, 5)
        repair_sig(bits)
    elif damage == "symbol-count":
        advertised_symbols += 1
    elif damage == "bandwidth":
        bandwidth = 1
    elif damage == "wrong-modulation":
        actual_mcs = (raw_mcs + 1) % 4
    usig, _ = mu_header(
        case, bandwidth, case & 1, 1, raw_mcs, advertised_symbols
    )
    samples = prefix(usig) + signaling([bits], raw_mcs, advertised_symbols, actual_mcs)
    if damage == "erased":
        samples[-80 * advertised_symbols:] = [0j] * (80 * advertised_symbols)
    if impaired:
        samples = [
            (value + (0.22j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.55 + 0.014 * index))
            for index, value in enumerate(samples)
        ]
    if damage == "truncated":
        samples = samples[:-1]
    assert all(max(abs(value.real), abs(value.imag)) * 180 < 127 for value in samples)
    return (
        base.quantize(samples, scale=180),
        "".join(map(str, usig)),
        "".join(map(str, bits)),
        advertised_symbols,
    )


def split_mu_blocks(bits, users):
    blocks = [bits[:52]]
    cursor = 52
    remaining = users - 1
    while remaining:
        count = min(remaining, 2)
        length = 22 * count + 10
        blocks.append(bits[cursor:cursor + length])
        cursor += length
        remaining -= count
    assert cursor == len(bits)
    return blocks


def split_ofdma_blocks(bits, users):
    blocks = [bits[:36]]
    cursor = 36
    remaining = users
    while remaining:
        count = min(remaining, 2)
        length = 22 * count + 10
        blocks.append(bits[cursor:cursor + length])
        cursor += length
        remaining -= count
    assert cursor == len(bits)
    return blocks


def repair_block(bits):
    protected = len(bits) - 10
    value = checksum(bits[:protected])
    bits[protected:protected + 4] = [
        (value >> shift) & 1 for shift in (3, 2, 1, 0)
    ]


def mu_waveform(case, users, raw_mcs, impaired=False, damage=None):
    bits, _, _ = mu_blocks(case, users)
    blocks = split_mu_blocks(bits, users)
    _, _, dbps, _ = MODES[raw_mcs]
    expected_symbols = math.ceil(len(bits) / dbps)
    advertised_symbols = expected_symbols
    bandwidth = 0
    actual_mcs = raw_mcs
    if damage == "crc":
        blocks[-1][-10] ^= 1
    elif damage == "tail":
        blocks[-1][-1] = 1
    elif damage == "users":
        put(blocks[0], 17, 3, 0)
        repair_sig(blocks[0])
    elif damage == "ltf":
        put(blocks[0], 6, 3, 5)
        repair_sig(blocks[0])
    elif damage == "symbol-count":
        advertised_symbols += 1
    elif damage == "bandwidth":
        bandwidth = 1
    elif damage == "wrong-modulation":
        actual_mcs = (raw_mcs + 1) % 4
    usig, _ = mu_header(case, bandwidth, 0, 2, raw_mcs, advertised_symbols)
    samples = prefix(usig) + signaling(
        blocks, raw_mcs, advertised_symbols, actual_mcs
    )
    if damage == "erased":
        samples[-80 * advertised_symbols:] = [0j] * (80 * advertised_symbols)
    if impaired:
        samples = [
            (value + (0.22j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.55 + 0.014 * index))
            for index, value in enumerate(samples)
        ]
    if damage == "truncated":
        samples = samples[:-1]
    assert all(max(abs(value.real), abs(value.imag)) * 180 < 127 for value in samples)
    return (
        base.quantize(samples, scale=180),
        "".join(map(str, usig)),
        "".join(map(str, bits)),
        advertised_symbols,
    )


def ofdma_waveform(case, allocation, raw_mcs, impaired=False, damage=None):
    users = OFDMA_USERS[allocation]
    bits, common, _ = ofdma_blocks(case, allocation)
    blocks = split_ofdma_blocks(bits, users)
    _, _, dbps, _ = MODES[raw_mcs]
    advertised_symbols = math.ceil(len(bits) / dbps)
    bandwidth = 0
    actual_mcs = raw_mcs
    if damage == "crc":
        blocks[-1][-10] ^= 1
    elif damage == "tail":
        blocks[-1][-1] = 1
    elif damage == "allocation":
        put(blocks[0], 17, 9, 26)
        repair_block(blocks[0])
    elif damage == "ltf":
        put(blocks[0], 6, 3, 5)
        repair_block(blocks[0])
    elif damage == "symbol-count":
        advertised_symbols += 1
    elif damage == "bandwidth":
        bandwidth = 1
    elif damage == "wrong-modulation":
        actual_mcs = (raw_mcs + 1) % 4
    usig, _ = mu_header(case, bandwidth, 0, 0, raw_mcs, advertised_symbols)
    samples = prefix(usig) + signaling(
        blocks, raw_mcs, advertised_symbols, actual_mcs
    )
    if damage == "erased":
        samples[-80 * advertised_symbols:] = [0j] * (80 * advertised_symbols)
    if impaired:
        samples = [
            (value + (0.22j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.55 + 0.014 * index))
            for index, value in enumerate(samples)
        ]
    if damage == "truncated":
        samples = samples[:-1]
    assert all(max(abs(value.real), abs(value.imag)) * 180 < 127 for value in samples)
    return (
        base.quantize(samples, scale=180),
        "".join(map(str, usig)),
        "".join(map(str, bits)),
        common[9],
        common[10],
        common[11],
        advertised_symbols,
    )


def training_waveform(raw_mcs, ltf_mode, ltf_code, impaired):
    case = 32768 + 128 * raw_mcs + 16 * ltf_mode + ltf_code
    bits, _ = block(case)
    put(bits, 4, 2, ltf_mode)
    put(bits, 6, 3, ltf_code)
    put(bits, 31, 4, case % 14)
    put(bits, 36, 4, 0)
    repair_sig(bits)
    _, _, _, signal_symbols = MODES[raw_mcs]
    usig, _ = mu_header(case, 0, 0, 1, raw_mcs, signal_symbols)
    samples = prefix(usig) + signaling([bits], raw_mcs, signal_symbols)
    ltf_size, guard, ltf_symbols, ltf_start, data_start = append_training(
        samples, ltf_mode, ltf_code
    )

    if impaired:
        samples = [
            (value + (0.22j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.45 + 0.01 * index))
            for index, value in enumerate(samples)
        ]
    gain = 120
    assert all(max(abs(value.real), abs(value.imag)) * gain < 127 for value in samples)
    return (
        base.quantize(samples, scale=gain),
        "".join(map(str, usig)),
        "".join(map(str, bits)),
        ltf_size,
        guard,
        ltf_symbols,
        signal_symbols,
        ltf_start,
        data_start,
    )


def generate_data_ldpc_iq(out):
    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tmcs\tltf_mode\tguard\tinitial_symbols\tinitial_padding\tsymbols\tpadding\textra\tpsdu\tlegacy_length\tltf_start\tdata_start\tdata_end\timpaired\toffset\tbytes\tsha256"
    ]
    for mcs in DATA_MODES:
        if mcs == 13:
            continue
        bits_per_tone = DATA_MODES[mcs][0]
        for ltf_mode in range(4):
            for initial_padding in range(1, 5):
                for impaired in ((False,) if bits_per_tone == 12 else (False, True)):
                    suffix = "offset" if impaired else "clean"
                    name = (
                        f"eht-data-ldpc-iq-m{mcs}-ltf{ltf_mode}-"
                        f"pad{initial_padding}-{suffix}"
                    )
                    fields = data_ldpc_waveform(
                        mcs, ltf_mode, initial_padding, impaired
                    )
                    (
                        iq,
                        usig,
                        bits,
                        psdu,
                        initial_symbols,
                        symbols,
                        padding,
                        extra,
                        legacy_length,
                        guard,
                        ltf_start,
                        data_start,
                        data_end,
                    ) = fields
                    offset = len(corpus)
                    corpus.extend(iq)
                    rows.append("\t".join(map(str, [
                        name, usig, bits, mcs, ltf_mode, guard,
                        initial_symbols, initial_padding, symbols, padding,
                        extra, psdu, legacy_length, ltf_start, data_start,
                        data_end, int(impaired), offset, len(iq),
                        hashlib.sha256(iq).hexdigest(),
                    ])))
    (out / "eht-data-ldpc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-data-ldpc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 LDPC DATA IQ waveforms")


def generate(out):
    base.self_check()
    corpus = bytearray()
    rows = ["name\tusig\tbits\tmcs\tsymbols\tend_sample\toffset\tbytes\tsha256"]
    for raw_mcs in range(4):
        for case in range(64):
            for impaired in (False, True):
                suffix = "offset" if impaired else "clean"
                name = f"eht-sig-iq-m{raw_mcs}-c{case}-{suffix}"
                iq, usig, bits, symbols = waveform(case, raw_mcs, impaired)
                offset = len(corpus)
                corpus.extend(iq)
                rows.append("\t".join(map(str, [
                    name, usig, bits, raw_mcs, symbols, 677 + 80 * symbols,
                    offset, len(iq), hashlib.sha256(iq).hexdigest(),
                ])))
    invalid = ["name\treason\toffset\tbytes\tsha256"]
    cases = [
        (raw_mcs, damage)
        for raw_mcs in range(4)
        for damage in ("crc", "tail", "erased", "truncated")
    ] + [(0, damage) for damage in ("users", "ltf", "symbol-count", "bandwidth", "wrong-modulation")]
    for case, (raw_mcs, damage) in enumerate(cases):
        name = f"eht-sig-iq-invalid-m{raw_mcs}-{damage}"
        iq, _, _, _ = waveform(case, raw_mcs, True, damage)
        offset = len(corpus)
        corpus.extend(iq)
        invalid.append("\t".join(map(str, [
            name, damage, offset, len(iq), hashlib.sha256(iq).hexdigest(),
        ])))
    (out / "eht-sig-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-sig-iq-invalid-index.tsv").write_text("\n".join(invalid) + "\n")
    (out / "eht-sig-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} valid and {len(invalid) - 1} invalid independent EHT-SIG IQ waveforms")

    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tusers\tmcs\tsymbols\tend_sample\toffset\tbytes\tsha256"
    ]
    for raw_mcs in range(4):
        for users in range(2, 9):
            for case in range(8):
                seed = 512 * raw_mcs + 64 * users + case
                for impaired in (False, True):
                    suffix = "offset" if impaired else "clean"
                    name = f"eht-mu-sig-iq-m{raw_mcs}-u{users}-c{case}-{suffix}"
                    iq, usig, bits, symbols = mu_waveform(
                        seed, users, raw_mcs, impaired
                    )
                    offset = len(corpus)
                    corpus.extend(iq)
                    rows.append("\t".join(map(str, [
                        name, usig, bits, users, raw_mcs, symbols,
                        677 + 80 * symbols, offset, len(iq),
                        hashlib.sha256(iq).hexdigest(),
                    ])))
    invalid = ["name\treason\toffset\tbytes\tsha256"]
    cases = [
        (raw_mcs, damage)
        for raw_mcs in range(4)
        for damage in ("crc", "tail", "erased", "truncated")
    ] + [
        (0, damage)
        for damage in ("users", "ltf", "symbol-count", "bandwidth", "wrong-modulation")
    ]
    for case, (raw_mcs, damage) in enumerate(cases):
        name = f"eht-mu-sig-iq-invalid-m{raw_mcs}-{damage}"
        iq, _, _, _ = mu_waveform(4096 + case, 4, raw_mcs, True, damage)
        offset = len(corpus)
        corpus.extend(iq)
        invalid.append("\t".join(map(str, [
            name, damage, offset, len(iq), hashlib.sha256(iq).hexdigest(),
        ])))
    (out / "eht-mu-sig-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-mu-sig-iq-invalid-index.tsv").write_text(
        "\n".join(invalid) + "\n"
    )
    (out / "eht-mu-sig-iq.cs8").write_bytes(corpus)
    print(
        f"{len(rows) - 1} valid and {len(invalid) - 1} invalid "
        "independent MU-MIMO EHT-SIG IQ waveforms"
    )

    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tallocation\tusers\tkind\tmcs\tsymbols\tend_sample\toffset\tbytes\tsha256"
    ]
    for raw_mcs in range(4):
        for allocation in OFDMA_USERS:
            seed = 8192 + 512 * raw_mcs + allocation
            for impaired in (False, True):
                suffix = "offset" if impaired else "clean"
                name = f"eht-ofdma-sig-iq-m{raw_mcs}-a{allocation}-{suffix}"
                iq, usig, bits, actual, users, kind, symbols = ofdma_waveform(
                    seed, allocation, raw_mcs, impaired
                )
                offset = len(corpus)
                corpus.extend(iq)
                rows.append("\t".join(map(str, [
                    name, usig, bits, actual, users, kind, raw_mcs, symbols,
                    677 + 80 * symbols, offset, len(iq),
                    hashlib.sha256(iq).hexdigest(),
                ])))
    invalid = ["name\treason\toffset\tbytes\tsha256"]
    cases = [
        (raw_mcs, damage)
        for raw_mcs in range(4)
        for damage in ("crc", "tail", "erased", "truncated")
    ] + [
        (0, damage)
        for damage in (
            "allocation", "ltf", "symbol-count", "bandwidth", "wrong-modulation"
        )
    ]
    for case, (raw_mcs, damage) in enumerate(cases):
        name = f"eht-ofdma-sig-iq-invalid-m{raw_mcs}-{damage}"
        iq, _, _, _, _, _, _ = ofdma_waveform(
            16384 + case, 65, raw_mcs, True, damage
        )
        offset = len(corpus)
        corpus.extend(iq)
        invalid.append("\t".join(map(str, [
            name, damage, offset, len(iq), hashlib.sha256(iq).hexdigest(),
        ])))
    (out / "eht-ofdma-sig-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-ofdma-sig-iq-invalid-index.tsv").write_text(
        "\n".join(invalid) + "\n"
    )
    (out / "eht-ofdma-sig-iq.cs8").write_bytes(corpus)
    print(
        f"{len(rows) - 1} valid and {len(invalid) - 1} invalid "
        "independent OFDMA EHT-SIG IQ waveforms"
    )

    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tltf_mode\tltf_size\tguard\tltf_symbols\tsignal_symbols\tltf_start\tdata_start\timpaired\toffset\tbytes\tsha256"
    ]
    for raw_mcs in range(4):
        for ltf_mode in range(4):
            for ltf_code in range(5):
                for impaired in (False, True):
                    suffix = "offset" if impaired else "clean"
                    name = (
                        f"eht-training-m{raw_mcs}-ltf{ltf_mode}-"
                        f"count{ltf_code}-{suffix}"
                    )
                    fields = training_waveform(
                        raw_mcs, ltf_mode, ltf_code, impaired
                    )
                    iq, usig, bits, size, guard, count, symbols, start, end = fields
                    offset = len(corpus)
                    corpus.extend(iq)
                    rows.append("\t".join(map(str, [
                        name, usig, bits, ltf_mode, size, guard, count, symbols,
                        start, end, int(impaired), offset, len(iq),
                        hashlib.sha256(iq).hexdigest(),
                    ])))
    (out / "eht-training-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-training-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 training waveforms")

    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tmcs\tltf_mode\tguard\tpadding\tsymbols\tpsdu\tlegacy_length\tltf_start\tdata_start\tdata_end\timpaired\toffset\tbytes\tsha256"
    ]
    for mcs in DATA_BCC_MODES:
        for ltf_mode in range(4):
            for padding in range(1, 5):
                for impaired in (False, True):
                    suffix = "offset" if impaired else "clean"
                    name = (
                        f"eht-data-bcc-iq-m{mcs}-ltf{ltf_mode}-"
                        f"pad{padding}-{suffix}"
                    )
                    fields = data_bcc_waveform(mcs, ltf_mode, padding, impaired)
                    (
                        iq,
                        usig,
                        bits,
                        psdu,
                        symbols,
                        legacy_length,
                        guard,
                        ltf_start,
                        data_start,
                        data_end,
                    ) = fields
                    offset = len(corpus)
                    corpus.extend(iq)
                    rows.append("\t".join(map(str, [
                        name, usig, bits, mcs, ltf_mode, guard, padding,
                        symbols, psdu, legacy_length, ltf_start, data_start,
                        data_end, int(impaired), offset, len(iq),
                        hashlib.sha256(iq).hexdigest(),
                    ])))
    (out / "eht-data-bcc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-data-bcc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 BCC DATA IQ waveforms")

    generate_data_ldpc_iq(out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-sig-iq-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
