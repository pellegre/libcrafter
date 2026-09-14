"""Independent EHT preamble and U-SIG IQ prefixes at 20 Msps.

IEEE 802.11 TGbe 11-21/0002r2 and 11-21/0049r1. No production
receiver, EHT-SIG, training or DATA implementation is imported.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile

import ofdm_vectors as base
from eht_usig_vectors import mu_header, put, repair, tb_header
from he_prefix_iq_vectors import symbol
from he_signal_vectors import encoded


def waveform(bits, impaired=False, invalid=None):
    bits = bits.copy()
    if invalid == "version":
        put(bits, 0, 3, 1)
        repair(bits)
    if invalid == "bandwidth":
        put(bits, 3, 3, 6)
        repair(bits)
    if invalid == "validate":
        bits[25] = 0
        repair(bits)
    if invalid == "tail":
        bits[46] = 1
    if invalid == "crc":
        bits[42] ^= 1
    length = {"remainder1": 301, "remainder2": 302}.get(invalid, 300)
    legacy = base.signal("0101" if invalid == "rate" else "1101", length)
    repeated = base.signal("1101", length + (3 if invalid == "repeat" else 0))
    if invalid == "parity":
        repeated[17] ^= 1
    samples = [0j] * 37 + [value * math.sqrt(52 / 56) for value in base.preamble()]
    samples += symbol(base.interleave(base.encode(legacy), 1), legacy=True)
    samples += symbol(base.interleave(base.encode(repeated), 1), legacy=True)
    coded = encoded(bits)
    samples += symbol(coded[:52], rotate=invalid == "first-qbpsk")
    samples += symbol(coded[52:], rotate=invalid == "second-qbpsk")
    if invalid == "erased-second":
        samples[-80:] = [0j] * 80
    if impaired:
        samples = [
            (value + (0.25j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.7 + 0.018 * index))
            for index, value in enumerate(samples)
        ]
    assert len(samples) == 677
    assert all(max(abs(value.real), abs(value.imag)) * 180 < 127 for value in samples)
    return base.quantize(samples, scale=180), "".join(map(str, bits)), length


def generate(out):
    base.self_check()
    corpus = bytearray()
    rows = ["name\tbits\tlength\tend_sample\toffset\tbytes\tsha256"]

    def emit_valid(name, iq, wire, length):
        offset = len(corpus)
        corpus.extend(iq)
        rows.append(
            f"{name}\t{wire}\t{length}\t677\t{offset}\t{len(iq)}\t{hashlib.sha256(iq).hexdigest()}"
        )

    case = 0
    for uplink, ppdu_type in ((0, 0), (0, 1), (1, 1), (0, 2)):
        for bandwidth in range(6):
            for mcs in range(4):
                bits, _ = mu_header(case, bandwidth, uplink, ppdu_type, mcs, 1 + 31 * (case & 1))
                for impaired in (False, True):
                    suffix = "offset" if impaired else "clean"
                    name = f"eht-mu-u{uplink}-t{ppdu_type}-bw{bandwidth}-m{mcs}-{suffix}"
                    iq, wire, length = waveform(bits, impaired)
                    emit_valid(name, iq, wire, length)
                case += 1
    for bandwidth in range(6):
        for first in range(16):
            second = (first * 7 + bandwidth * 3) % 16
            bits = tb_header(case, bandwidth, first, second)
            for impaired in (False, True):
                suffix = "offset" if impaired else "clean"
                name = f"eht-tb-bw{bandwidth}-r{first}-{second}-{suffix}"
                iq, wire, length = waveform(bits, impaired)
                emit_valid(name, iq, wire, length)
            case += 1
    assert len(rows) == 385
    (out / "eht-prefix-index.tsv").write_text("\n".join(rows) + "\n")

    invalid = ["name\treason\toffset\tbytes\tsha256"]
    baseline, _ = mu_header(0, 0, 0, 1, 0, 1)
    for reason in (
        "version", "bandwidth", "validate", "tail", "crc", "remainder1",
        "remainder2", "rate", "repeat", "parity", "first-qbpsk",
        "second-qbpsk", "erased-second",
    ):
        name = f"eht-prefix-invalid-{reason}"
        iq, _, _ = waveform(baseline, invalid=reason)
        offset = len(corpus)
        corpus.extend(iq)
        invalid.append(
            f"{name}\t{reason}\t{offset}\t{len(iq)}\t{hashlib.sha256(iq).hexdigest()}"
        )
    (out / "eht-prefix-invalid-index.tsv").write_text("\n".join(invalid) + "\n")
    (out / "eht-prefix-iq.cs8").write_bytes(corpus)
    print("384 valid and 13 invalid independent EHT IQ prefixes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-prefix-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for file in generated.iterdir():
                assert file.read_bytes() == (base.OUT / file.name).read_bytes(), file.name
    else:
        generate(base.OUT)
