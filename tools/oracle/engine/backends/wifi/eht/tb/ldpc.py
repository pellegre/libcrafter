"""Independent EHT20 TB LDPC DATA IQ waveforms."""

import argparse
import cmath
import hashlib
import tempfile
from pathlib import Path

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.data.ofdma.ldpc import (
    data_symbol,
    encode_payload,
    rate_layout,
)
from tools.oracle.engine.backends.wifi.eht.signal.waveform import prefix
from tools.oracle.engine.backends.wifi.eht.tb.data import (
    append_tb_training,
    resource,
)
from tools.oracle.engine.backends.wifi.eht.usig import tb_header
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter


OUT = IQ_FIXTURES


def choose_layout(allocated, mcs, initial_padding, fixed, stride):
    for initial_symbols in range(1, 401):
        initial = rate_layout(allocated, mcs, initial_symbols, initial_padding, False)
        layout = rate_layout(
            allocated, mcs, initial_symbols, initial_padding, initial["needs_extra"]
        )
        if (
            layout["psdu_bytes"] >= 64
            and layout["symbols"] <= 400
            and (fixed + layout["symbols"] * stride) % 80 == 0
        ):
            return layout
    raise AssertionError((allocated, mcs, initial_padding, fixed, stride))


def waveform(case, raw, mcs, gi_ltf, ltf_code, initial_padding, impaired):
    reuse = ((case * 5 + 1) % 16, (case * 13 + 7) % 16)
    usig = tb_header(case, 0, *reuse)
    allocated = resource(raw)
    ltf_symbols = (1, 2, 4, 6, 8)[ltf_code]
    ltf_stride = {1: 160, 2: 320}[gi_ltf]
    data_stride = {1: 288, 2: 320}[gi_ltf]
    fixed = 400 + ltf_symbols * ltf_stride
    layout = choose_layout(
        allocated, mcs, initial_padding, fixed, data_stride
    )
    rounded = fixed + layout["symbols"] * data_stride
    legacy_length = 3 * (rounded // 80 - 1)
    samples = prefix(usig, legacy_length)
    ltf_size, guard, actual_ltf_symbols = append_tb_training(
        samples, gi_ltf, ltf_code
    )
    assert actual_ltf_symbols == ltf_symbols

    mpdu = base.frame(case % 16)
    psdu = bytearray(delimiter(len(mpdu)) + mpdu)
    psdu += b"\xA5" * min(-len(psdu) % 4, layout["psdu_bytes"] - len(psdu))
    while len(psdu) + 4 <= layout["psdu_bytes"]:
        psdu += delimiter(0, 1)
    psdu += b"\xA5" * (layout["psdu_bytes"] - len(psdu))
    seed = 1 + (case * 173) % 2047
    encoded = encode_payload(mcs, layout, psdu, seed)
    pilot_bits = base.scramble([0] * (4 + layout["symbols"]), 127)
    for symbol in range(layout["symbols"]):
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
            (value + (0.08j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.19 + 0.003 * index))
            for index, value in enumerate(samples)
        ]
    peak = max(max(abs(value.real), abs(value.imag)) for value in samples)
    gain = min(155, 114 / peak)
    iq = base.quantize(samples, scale=gain)
    return (
        iq,
        "".join(map(str, usig)),
        reuse,
        ltf_size,
        guard,
        ltf_symbols,
        layout,
        legacy_length,
        bytes(psdu),
    )


def generate(out):
    corpus = bytearray()
    rows = [
        "name\tusig\traw\tmcs\tgi_ltf\tltf_code\tltf_size\tguard\tltf_symbols\tdata_symbols\tpadding\textra\tlength\treuse1\treuse2\tpsdu\timpaired\toffset\tbytes\tsha256"
    ]
    cases = ((0, 0), (74, 3), (106, 5), (122, 12), (140, 9), (164, 11), (166, 15))
    for position, (raw, mcs) in enumerate(cases):
        case = 0xE7200 + position
        gi_ltf = 1 + position % 2
        ltf_code = (2 * position) % 5
        initial_padding = position % 4 + 1
        impaired = position % 3 == 1 and mcs < 10
        values = waveform(
            case, raw, mcs, gi_ltf, ltf_code, initial_padding, impaired
        )
        iq, usig, reuse, ltf_size, guard, ltf_symbols, layout, length, psdu = values
        offset = len(corpus)
        corpus.extend(iq)
        name = f"eht-tb-ldpc-ru{raw}-mcs{mcs}-{'offset' if impaired else 'clean'}"
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
                        layout["symbols"],
                        layout["padding"],
                        int(layout["needs_extra"]),
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
    (out / "eht-tb-data-ldpc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-tb-data-ldpc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 TB LDPC DATA IQ waveforms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-tb-ldpc-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
