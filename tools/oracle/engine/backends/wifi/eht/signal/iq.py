"""Independent 20 MHz EHT-SIG IQ for downlink EHT PPDUs.

IEEE 802.11 TGbe 11-21/0140r2 and 11-21/1386r1. The forward model uses
independent CRC, BCC, interleaving, constellation and direct-DFT synthesis.
"""

import argparse
import cmath
import hashlib
import math
import tempfile
from pathlib import Path

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.signal.fields import (
    OFDMA_USERS,
    block,
    mu_blocks,
    ofdma_blocks,
    repair,
    repair_block,
    split_mu_blocks,
    split_ofdma_blocks,
)
from tools.oracle.engine.backends.wifi.eht.signal.waveform import (
    MODES,
    prefix,
    signaling,
)
from tools.oracle.engine.backends.wifi.eht.usig import mu_header, put
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES


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
        repair(bits)
    elif damage == "ltf":
        put(bits, 6, 3, 5)
        repair(bits)
    elif damage == "symbol-count":
        advertised_symbols += 1
    elif damage == "bandwidth":
        bandwidth = 1
    elif damage == "wrong-modulation":
        actual_mcs = (raw_mcs + 1) % 4
    usig, _ = mu_header(
        case, bandwidth, case & 1, 1, raw_mcs, advertised_symbols
    )
    samples = prefix(usig) + signaling(
        [bits], raw_mcs, advertised_symbols, actual_mcs
    )
    if damage == "erased":
        samples[-80 * advertised_symbols :] = [0j] * (80 * advertised_symbols)
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
        repair(blocks[0])
    elif damage == "ltf":
        put(blocks[0], 6, 3, 5)
        repair(blocks[0])
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
        samples[-80 * advertised_symbols :] = [0j] * (80 * advertised_symbols)
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
        samples[-80 * advertised_symbols :] = [0j] * (80 * advertised_symbols)
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


def generate_single(out):
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
                rows.append(
                    "\t".join(
                        map(
                            str,
                            [
                                name,
                                usig,
                                bits,
                                raw_mcs,
                                symbols,
                                677 + 80 * symbols,
                                offset,
                                len(iq),
                                hashlib.sha256(iq).hexdigest(),
                            ],
                        )
                    )
                )
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
        name = f"eht-sig-iq-invalid-m{raw_mcs}-{damage}"
        iq, _, _, _ = waveform(case, raw_mcs, True, damage)
        offset = len(corpus)
        corpus.extend(iq)
        invalid.append(
            "\t".join(
                map(
                    str,
                    [name, damage, offset, len(iq), hashlib.sha256(iq).hexdigest()],
                )
            )
        )
    (out / "eht-sig-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-sig-iq-invalid-index.tsv").write_text("\n".join(invalid) + "\n")
    (out / "eht-sig-iq.cs8").write_bytes(corpus)
    print(
        f"{len(rows) - 1} valid and {len(invalid) - 1} invalid "
        "independent EHT-SIG IQ waveforms"
    )


def generate_mu(out):
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
                    rows.append(
                        "\t".join(
                            map(
                                str,
                                [
                                    name,
                                    usig,
                                    bits,
                                    users,
                                    raw_mcs,
                                    symbols,
                                    677 + 80 * symbols,
                                    offset,
                                    len(iq),
                                    hashlib.sha256(iq).hexdigest(),
                                ],
                            )
                        )
                    )
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
        invalid.append(
            "\t".join(
                map(
                    str,
                    [name, damage, offset, len(iq), hashlib.sha256(iq).hexdigest()],
                )
            )
        )
    (out / "eht-mu-sig-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-mu-sig-iq-invalid-index.tsv").write_text(
        "\n".join(invalid) + "\n"
    )
    (out / "eht-mu-sig-iq.cs8").write_bytes(corpus)
    print(
        f"{len(rows) - 1} valid and {len(invalid) - 1} invalid "
        "independent MU-MIMO EHT-SIG IQ waveforms"
    )


def generate_ofdma(out):
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
                rows.append(
                    "\t".join(
                        map(
                            str,
                            [
                                name,
                                usig,
                                bits,
                                actual,
                                users,
                                kind,
                                raw_mcs,
                                symbols,
                                677 + 80 * symbols,
                                offset,
                                len(iq),
                                hashlib.sha256(iq).hexdigest(),
                            ],
                        )
                    )
                )
    invalid = ["name\treason\toffset\tbytes\tsha256"]
    cases = [
        (raw_mcs, damage)
        for raw_mcs in range(4)
        for damage in ("crc", "tail", "erased", "truncated")
    ] + [
        (0, damage)
        for damage in (
            "allocation",
            "ltf",
            "symbol-count",
            "bandwidth",
            "wrong-modulation",
        )
    ]
    for case, (raw_mcs, damage) in enumerate(cases):
        name = f"eht-ofdma-sig-iq-invalid-m{raw_mcs}-{damage}"
        iq, _, _, _, _, _, _ = ofdma_waveform(
            16384 + case, 65, raw_mcs, True, damage
        )
        offset = len(corpus)
        corpus.extend(iq)
        invalid.append(
            "\t".join(
                map(
                    str,
                    [name, damage, offset, len(iq), hashlib.sha256(iq).hexdigest()],
                )
            )
        )
    (out / "eht-ofdma-sig-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-ofdma-sig-iq-invalid-index.tsv").write_text(
        "\n".join(invalid) + "\n"
    )
    (out / "eht-ofdma-sig-iq.cs8").write_bytes(corpus)
    print(
        f"{len(rows) - 1} valid and {len(invalid) - 1} invalid "
        "independent OFDMA EHT-SIG IQ waveforms"
    )


def generate(out):
    base.self_check()
    generate_single(out)
    generate_mu(out)
    generate_ofdma(out)


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
