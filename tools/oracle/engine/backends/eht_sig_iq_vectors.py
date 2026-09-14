"""Independent 20 MHz EHT-SIG IQ for non-OFDMA single-user PPDUs.

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
from eht_sig_vectors import block, repair as repair_sig
from eht_usig_vectors import mu_header, put
from he_prefix_iq_vectors import symbol
from he_sig_b_coded_vectors import encode
from he_sig_b_modulation_vectors import modulate
from he_signal_vectors import encoded


OUT = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq"
MODES = {
    0: (0, 0, 26, 2),
    1: (1, 0, 52, 1),
    2: (3, 0, 104, 1),
    3: (0, 1, 13, 4),
}


def prefix(usig):
    legacy = base.signal("1101", 300)
    samples = [0j] * 37 + [value * math.sqrt(52 / 56) for value in base.preamble()]
    samples += symbol(base.interleave(base.encode(legacy), 1), legacy=True)
    samples += symbol(base.interleave(base.encode(legacy), 1), legacy=True)
    coded = encoded(usig)
    samples += symbol(coded[:52]) + symbol(coded[52:])
    return samples


def signaling(bits, raw_mcs, symbols, actual_mcs=None):
    actual_mcs = raw_mcs if actual_mcs is None else actual_mcs
    mcs, dcm, dbps, _ = MODES[actual_mcs]
    padding = symbols * dbps - len(bits)
    assert padding >= 0
    padded = bits + [int(index % 7 in (0, 2, 3, 6)) for index in range(padding)]
    coded = "".join(str(value) for pair in encode(padded) for value in pair)
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
    samples = prefix(usig) + signaling(bits, raw_mcs, advertised_symbols, actual_mcs)
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
