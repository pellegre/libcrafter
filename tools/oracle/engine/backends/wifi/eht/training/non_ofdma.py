"""Independent EHT20 non-OFDMA channel-training IQ waveforms."""

import argparse
import cmath
import hashlib
import tempfile
from pathlib import Path

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.signal.fields import block, repair
from tools.oracle.engine.backends.wifi.eht.signal.waveform import (
    MODES,
    append_training,
    prefix,
    signaling,
)
from tools.oracle.engine.backends.wifi.eht.usig import mu_header, put
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES


def waveform(raw_mcs, ltf_mode, ltf_code, impaired):
    case = 32768 + 128 * raw_mcs + 16 * ltf_mode + ltf_code
    bits, _ = block(case)
    put(bits, 4, 2, ltf_mode)
    put(bits, 6, 3, ltf_code)
    put(bits, 31, 4, case % 14)
    put(bits, 36, 4, 0)
    repair(bits)
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


def generate(out):
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
                    fields = waveform(raw_mcs, ltf_mode, ltf_code, impaired)
                    iq, usig, bits, size, guard, count, symbols, start, end = fields
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
                                    ltf_mode,
                                    size,
                                    guard,
                                    count,
                                    symbols,
                                    start,
                                    end,
                                    int(impaired),
                                    offset,
                                    len(iq),
                                    hashlib.sha256(iq).hexdigest(),
                                ],
                            )
                        )
                    )
    (out / "eht-training-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-training-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 training waveforms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-training-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
