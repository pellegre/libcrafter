"""Independent complete EHT20 non-OFDMA DATA IQ waveforms."""

import argparse
import cmath
import hashlib
import math
import tempfile
from pathlib import Path

import tools.oracle.engine.backends.wifi.he.training as training
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.bcc import MODES as BCC_MODES
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.bcc import case as bcc_case
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.ldpc import case as ldpc_case
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.ldpc import layout as ldpc_layout
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import MODES
from tools.oracle.engine.backends.wifi.eht.signal.fields import block, repair
from tools.oracle.engine.backends.wifi.eht.signal.waveform import (
    append_training,
    prefix,
    signaling,
)
from tools.oracle.engine.backends.wifi.eht.usig import mu_header, put
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter
from tools.oracle.engine.backends.wifi.vht.bcc.iq import constellation


OUT = IQ_FIXTURES
PILOTS = [-116, -90, -48, -22, 22, 48, 90, 116]
TONES = [tone for tone in training.TONES if tone not in PILOTS]
PILOT_SIGNS = [1, 1, 1, -1, -1, 1, 1, 1]


def interleave(bits, bits_per_tone, dcm):
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


def point(bits):
    if len(bits) <= 8:
        return constellation(bits)
    width = len(bits) // 2
    labels = {
        format(index ^ (index >> 1), f"0{width}b"): value
        for index, value in enumerate(range(-(2**width - 1), 2**width, 2))
    }
    label = "".join(map(str, bits))
    energy = {10: 682, 12: 2730}[len(bits)]
    return complex(labels[label[:width]], labels[label[width:]]) / math.sqrt(energy)


def symbol(bits, bits_per_tone, dcm, symbol_index, polarity, guard, ldpc=False):
    mapped = bits if ldpc else interleave(bits, bits_per_tone, dcm)
    frequency = [0j] * 245
    tones = len(TONES) // (1 + int(dcm))
    for index in range(tones):
        target = (
            9 * (index % (tones // 9)) + index // (tones // 9) if ldpc else index
        )
        label = mapped[index * bits_per_tone : (index + 1) * bits_per_tone]
        lower = point(label)
        frequency[TONES[target] + 122] = lower
        if dcm:
            frequency[TONES[target + tones] + 122] = lower * (
                -1 if (index + tones) % 2 else 1
            )
    for index, tone in enumerate(PILOTS):
        sign = PILOT_SIGNS[(symbol_index + index) % len(PILOT_SIGNS)]
        frequency[tone + 122] = polarity * sign
    wave = [
        value * 4 * math.sqrt(52 / 242) for value in training.ifft(frequency)
    ]
    return wave[-guard:] + wave


def bcc_waveform(mcs, ltf_mode, padding, impaired):
    signal_symbols = 2
    data_symbols = ([13, 15, 14, 11] if mcs == 15 else [8, 10, 9, 6])[
        ltf_mode
    ]
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
    repair(bits)
    usig, _ = mu_header(case, 0, 0, 1, 0, signal_symbols)
    samples = prefix(usig, legacy_length)
    samples += signaling([bits], 0, signal_symbols)
    _, guard, _, ltf_start, data_start = append_training(samples, ltf_mode, 0)

    values, _, _ = bcc_case(mcs, padding, data_symbols)
    mpdu = base.frame(0)
    psdu = bytearray(delimiter(len(mpdu)) + mpdu)
    psdu += b"\xA5" * min(-len(psdu) % 4, values[13] - len(psdu))
    while len(psdu) + 4 <= values[13]:
        psdu += delimiter(0, 1)
    psdu += b"\xA5" * (values[13] - len(psdu))
    values, psdu, coded = bcc_case(mcs, padding, data_symbols, psdu)
    bits_per_tone = BCC_MODES[mcs][0]
    coded_per_symbol = values[7]
    pilot_bits = base.scramble([0] * (4 + signal_symbols + data_symbols), 127)
    for symbol_index in range(data_symbols):
        start = symbol_index * coded_per_symbol
        samples += symbol(
            coded[start : start + coded_per_symbol],
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


def ldpc_candidate(mcs, ltf_mode, initial_padding):
    ltf_stride = [144, 160, 272, 320][ltf_mode]
    data_stride = [272, 288, 272, 320][ltf_mode]
    fixed = 320 + 160 + ltf_stride
    for initial_symbols in range(1, 101):
        sizing = ldpc_layout(mcs, initial_symbols, initial_padding)
        psdu_bytes = (sizing[8] - 16) // 8
        if psdu_bytes >= 60 and (fixed + sizing[0] * data_stride) % 80 == 0:
            return initial_symbols
    raise AssertionError((mcs, ltf_mode, initial_padding))


def ldpc_waveform(mcs, ltf_mode, initial_padding, impaired):
    signal_symbols = 2
    initial_symbols = ldpc_candidate(mcs, ltf_mode, initial_padding)
    values, _, _ = ldpc_case(mcs, initial_symbols, initial_padding)
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
    repair(bits)
    usig, _ = mu_header(case, 0, 0, 1, 0, signal_symbols)
    samples = prefix(usig, legacy_length)
    samples += signaling([bits], 0, signal_symbols)
    _, guard, _, ltf_start, data_start = append_training(samples, ltf_mode, 0)

    mpdu = base.frame(0)
    psdu = bytearray(delimiter(len(mpdu)) + mpdu)
    psdu += b"\xA5" * min(-len(psdu) % 4, values[17] - len(psdu))
    while len(psdu) + 4 <= values[17]:
        psdu += delimiter(0, 1)
    psdu += b"\xA5" * (values[17] - len(psdu))
    values, psdu, coded = ldpc_case(mcs, initial_symbols, initial_padding, psdu)
    bits_per_tone = MODES[mcs][0]
    coded_per_symbol = values[11]
    pilot_bits = base.scramble([0] * (4 + signal_symbols + symbols), 127)
    for symbol_index in range(symbols):
        start = symbol_index * coded_per_symbol
        samples += symbol(
            coded[start : start + coded_per_symbol],
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


def generate_ldpc(out):
    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tmcs\tltf_mode\tguard\tinitial_symbols\tinitial_padding\tsymbols\tpadding\textra\tpsdu\tlegacy_length\tltf_start\tdata_start\tdata_end\timpaired\toffset\tbytes\tsha256"
    ]
    for mcs in MODES:
        if mcs == 13:
            continue
        bits_per_tone = MODES[mcs][0]
        for ltf_mode in range(4):
            for initial_padding in range(1, 5):
                for impaired in (
                    (False,) if bits_per_tone == 12 else (False, True)
                ):
                    suffix = "offset" if impaired else "clean"
                    name = (
                        f"eht-data-ldpc-iq-m{mcs}-ltf{ltf_mode}-"
                        f"pad{initial_padding}-{suffix}"
                    )
                    values = ldpc_waveform(
                        mcs, ltf_mode, initial_padding, impaired
                    )
                    iq = values[0]
                    offset = len(corpus)
                    corpus.extend(iq)
                    rows.append(
                        "\t".join(
                            map(
                                str,
                                [
                                    name,
                                    values[1],
                                    values[2],
                                    mcs,
                                    ltf_mode,
                                    values[9],
                                    values[4],
                                    initial_padding,
                                    values[5],
                                    values[6],
                                    values[7],
                                    values[3],
                                    values[8],
                                    values[10],
                                    values[11],
                                    values[12],
                                    int(impaired),
                                    offset,
                                    len(iq),
                                    hashlib.sha256(iq).hexdigest(),
                                ],
                            )
                        )
                    )
    (out / "eht-data-ldpc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-data-ldpc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 LDPC DATA IQ waveforms")


def generate(out):
    base.self_check()
    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tmcs\tltf_mode\tguard\tpadding\tsymbols\tpsdu\tlegacy_length\tltf_start\tdata_start\tdata_end\timpaired\toffset\tbytes\tsha256"
    ]
    for mcs in BCC_MODES:
        for ltf_mode in range(4):
            for padding in range(1, 5):
                for impaired in (False, True):
                    suffix = "offset" if impaired else "clean"
                    name = (
                        f"eht-data-bcc-iq-m{mcs}-ltf{ltf_mode}-"
                        f"pad{padding}-{suffix}"
                    )
                    values = bcc_waveform(mcs, ltf_mode, padding, impaired)
                    iq = values[0]
                    offset = len(corpus)
                    corpus.extend(iq)
                    rows.append(
                        "\t".join(
                            map(
                                str,
                                [
                                    name,
                                    values[1],
                                    values[2],
                                    mcs,
                                    ltf_mode,
                                    values[6],
                                    padding,
                                    values[4],
                                    values[3],
                                    values[5],
                                    values[7],
                                    values[8],
                                    values[9],
                                    int(impaired),
                                    offset,
                                    len(iq),
                                    hashlib.sha256(iq).hexdigest(),
                                ],
                            )
                        )
                    )
    (out / "eht-data-bcc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-data-bcc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 BCC DATA IQ waveforms")
    generate_ldpc(out)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-data-iq-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
