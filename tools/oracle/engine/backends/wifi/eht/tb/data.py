"""Independent EHT20 TB BCC DATA IQ waveforms."""

import argparse
import cmath
import hashlib
import math
import tempfile
from pathlib import Path

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.data.ofdma.bcc import (
    DATA_MODES,
    capacity,
    data_symbol,
    encode_payload,
)
from tools.oracle.engine.backends.wifi.eht.signal.ofdma.allocation import (
    Component,
    Resource,
)
from tools.oracle.engine.backends.wifi.eht.signal.waveform import (
    append_training,
    prefix,
)
from tools.oracle.engine.backends.wifi.eht.tb.resource import RESOURCES
from tools.oracle.engine.backends.wifi.eht.usig import tb_header
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter


OUT = IQ_FIXTURES


def resource(raw):
    return Resource(tuple(Component(size, index) for size, index in RESOURCES[raw >> 1]))


def append_tb_training(samples, gi_ltf, ltf_code):
    ltf_mode = {1: 1, 2: 3}[gi_ltf]
    generated = []
    ltf_size, guard, ltf_symbols, _, _ = append_training(
        generated, ltf_mode, ltf_code
    )
    samples += generated[:80] + generated
    return ltf_size, guard, ltf_symbols


def waveform(case, raw, mcs, gi_ltf, ltf_code, impaired):
    reuse = ((case * 7 + 3) % 16, (case * 11 + 5) % 16)
    usig = tb_header(case, 0, *reuse)
    allocated = resource(raw)
    symbols = 100
    ltf_symbols = (1, 2, 4, 6, 8)[ltf_code]
    ltf_stride = {1: 160, 2: 320}[gi_ltf]
    data_stride = {1: 288, 2: 320}[gi_ltf]
    rounded = 400 + ltf_symbols * ltf_stride + symbols * data_stride
    assert rounded % 80 == 0
    legacy_length = 3 * (rounded // 80 - 1)
    samples = prefix(usig, legacy_length)
    ltf_size, guard, actual_ltf_symbols = append_tb_training(
        samples, gi_ltf, ltf_code
    )
    assert actual_ltf_symbols == ltf_symbols

    layout = capacity(allocated, mcs, symbols)
    mpdu = base.frame(case % 16)
    psdu = bytearray(delimiter(len(mpdu)) + mpdu)
    psdu += b"\xA5" * min(-len(psdu) % 4, layout["psdu_bytes"] - len(psdu))
    while len(psdu) + 4 <= layout["psdu_bytes"]:
        psdu += delimiter(0, 1)
    psdu += b"\xA5" * (layout["psdu_bytes"] - len(psdu))
    seed = 1 + (case * 149) % 2047
    encoded, checked = encode_payload(allocated, mcs, symbols, psdu, seed)
    assert checked == layout
    pilot_bits = base.scramble([0] * (4 + symbols), 127)
    for symbol in range(symbols):
        samples += data_symbol(
            [allocated],
            [encoded],
            [layout],
            symbol,
            1 - 2 * pilot_bits[4 + symbol],
            guard,
        )
    if impaired:
        samples = [
            (value + (0.12j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.23 + 0.004 * index))
            for index, value in enumerate(samples)
        ]
    peak = max(max(abs(value.real), abs(value.imag)) for value in samples)
    gain = min(170, 116 / peak)
    iq = base.quantize(samples, scale=gain)
    return (
        iq,
        "".join(map(str, usig)),
        reuse,
        ltf_size,
        guard,
        ltf_symbols,
        symbols,
        legacy_length,
        bytes(psdu),
    )


def generate(out):
    corpus = bytearray()
    rows = [
        "name\tusig\traw\tmcs\tgi_ltf\tltf_code\tltf_size\tguard\tltf_symbols\tdata_symbols\tlength\treuse1\treuse2\tpsdu\timpaired\toffset\tbytes\tsha256"
    ]
    raws = (0, 16, 74, 80, 106, 108, 122, 140, 142, 144, 164, 166)
    modes = tuple(DATA_MODES)
    for position, raw in enumerate(raws):
        case = 0xE7100 + position
        mcs = modes[position % len(modes)]
        gi_ltf = 1 + position % 2
        ltf_code = position % 5
        impaired = position % 3 == 2
        values = waveform(case, raw, mcs, gi_ltf, ltf_code, impaired)
        iq, usig, reuse, ltf_size, guard, ltf_symbols, symbols, length, psdu = values
        offset = len(corpus)
        corpus.extend(iq)
        name = f"eht-tb-bcc-ru{raw}-mcs{mcs}-{'offset' if impaired else 'clean'}"
        rows.append(
            "\t".join(
                map(
                    str,
                    (
                        name,
                        usig,
                        raw,
                        mcs,
                        gi_ltf,
                        ltf_code,
                        ltf_size,
                        guard,
                        ltf_symbols,
                        symbols,
                        length,
                        reuse[0],
                        reuse[1],
                        psdu.hex(),
                        int(impaired),
                        offset,
                        len(iq),
                        hashlib.sha256(iq).hexdigest(),
                    ),
                )
            )
        )
    (out / "eht-tb-data-bcc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-tb-data-bcc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 TB BCC DATA IQ waveforms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-tb-data-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
