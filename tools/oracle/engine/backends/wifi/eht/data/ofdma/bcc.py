"""Independent EHT20 OFDMA BCC DATA IQ vectors.

Several users occupy disjoint resource units in each waveform. The forward
model independently constructs signaling, per-user FEC and interleaving,
constellations, pilots, and the combined time-domain channel.
"""

import argparse
import cmath
import hashlib
import math
import tempfile
from pathlib import Path

import tools.oracle.engine.backends.wifi.ofdm.base as base
import tools.oracle.engine.backends.wifi.he.training as training
from tools.oracle.engine.backends.wifi.eht.signal.ofdma.allocation import ALLOCATIONS
from tools.oracle.engine.backends.wifi.eht.signal.fields import protected
from tools.oracle.engine.backends.wifi.eht.signal.waveform import (
    MODES,
    append_training,
    prefix,
    signaling,
)
from tools.oracle.engine.backends.wifi.eht.data.ofdma.resource import Geometry
from tools.oracle.engine.backends.wifi.eht.usig import mu_header, put
from tools.oracle.engine.backends.wifi.ht.bcc import PUNCTURE
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter
from tools.oracle.engine.backends.wifi.vht.bcc.iq import constellation


OUT = IQ_FIXTURES
DATA_MODES = {
    0: (1, 1, 2, False),
    1: (2, 1, 2, False),
    2: (2, 3, 4, False),
    3: (4, 1, 2, False),
    4: (4, 3, 4, False),
    5: (6, 2, 3, False),
    6: (6, 3, 4, False),
    7: (6, 5, 6, False),
    8: (8, 3, 4, False),
    9: (8, 5, 6, False),
    15: (1, 1, 2, True),
}


def scramble(bits, seed):
    assert 0 < seed < 2048
    output = []
    state = seed
    for bit in bits:
        generated = state >> 10
        feedback = ((state >> 10) ^ (state >> 8)) & 1
        state = ((state << 1) | feedback) & 0x7FF
        output.append(bit ^ generated)
    return output


def capacity(resource, mcs, symbols):
    bits, numerator, denominator, dcm = DATA_MODES[mcs]
    geometry = Geometry.for_resource(resource)
    data_tones = len(geometry.data) // (1 + int(dcm))
    short_tones = geometry.short_tones(dcm)
    coded = data_tones * bits
    coded_short = short_tones * bits
    payload = symbols * (coded * numerator // denominator) - 22
    assert payload >= 0
    return {
        "bits": bits,
        "dcm": dcm,
        "coded": coded,
        "coded_short": coded_short,
        "data": coded * numerator // denominator,
        "psdu_bytes": payload // 8,
        "phy_pad": payload % 8,
        "filler": dcm and coded % 2 == 1,
    }


def encode_payload(resource, mcs, symbols, psdu, seed):
    layout = capacity(resource, mcs, symbols)
    assert len(psdu) == layout["psdu_bytes"]
    information = [0] * 16 + base.bits(psdu)
    information += [(seed + index) & 1 for index in range(layout["phy_pad"])]
    information = scramble(information, seed) + [0] * 6
    puncturing = (
        PUNCTURE[mcs]
        if mcs < 8
        else (
            [1, 1, 1, 0, 0, 1]
            if mcs == 8
            else [1, 1, 1, 0, 0, 1, 1, 0, 0, 1]
        )
    )
    if mcs == 15:
        puncturing = [1, 1]
    fec = [
        bit
        for index, bit in enumerate(base.encode(information))
        if puncturing[index % len(puncturing)]
    ]
    output = []
    cursor = 0
    for symbol in range(symbols):
        keep = layout["coded"] - int(layout["filler"])
        output += fec[cursor : cursor + keep]
        cursor += keep
        if layout["filler"]:
            output.append((seed + symbol) & 1)
    assert cursor == len(fec), (resource, mcs, layout, cursor, len(fec))
    assert len(output) == symbols * layout["coded"]
    return output, layout


def point(bits):
    if len(bits) <= 8:
        return constellation(bits)
    raise AssertionError(len(bits))


def data_symbol(resources, encoded, layouts, symbol, polarity, guard):
    frequency = [0j] * 245
    for resource, coded, layout in zip(resources, encoded, layouts):
        geometry = Geometry.for_resource(resource)
        start = symbol * layout["coded"]
        block = geometry.bcc_interleave(
            coded[start : start + layout["coded"]],
            layout["bits"],
            layout["dcm"],
        )
        mapped_tones = len(geometry.data) // (1 + int(layout["dcm"]))
        for index in range(mapped_tones):
            label = block[
                index * layout["bits"] : (index + 1) * layout["bits"]
            ]
            lower = point(label)
            frequency[geometry.data[index] + 122] = lower
            if layout["dcm"]:
                frequency[geometry.data[index + mapped_tones] + 122] = lower * (
                    -1 if (index + mapped_tones) % 2 else 1
                )
        for index, tone in enumerate(geometry.pilots):
            frequency[tone + 122] = polarity * geometry.pilot_sign(symbol, index)
    wave = [value * 4 * math.sqrt(52 / 242) for value in training.ifft(frequency)]
    return wave[-guard:] + wave


def signaling_blocks(case, allocation, data_mcs, ltf_mode):
    resources = ALLOCATIONS[allocation]
    common = [0] * 26
    put(common, 0, 4, case % 16)
    put(common, 4, 2, ltf_mode)
    put(common, 6, 3, 0)
    put(common, 9, 1, 0)
    put(common, 10, 2, 0)
    put(common, 12, 1, 0)
    put(common, 13, 4, (case * 11 + 3) % 16)
    put(common, 17, 9, allocation)
    users = []
    for index, mcs in enumerate(data_mcs):
        field = [0] * 22
        put(field, 0, 11, (case * 977 + index * 619 + 17) % 2048)
        put(field, 11, 4, mcs)
        put(field, 15, 1, index & 1)
        put(field, 16, 4, 0)
        put(field, 20, 1, (case + index) & 1)
        put(field, 21, 1, 0)
        users.append(field)
    assert len(users) == len(resources)
    blocks = [protected(common)]
    for start in range(0, len(users), 2):
        payload = list(users[start])
        if start + 1 < len(users):
            payload += users[start + 1]
        blocks.append(protected(payload))
    return blocks


def waveform(case, allocation, ltf_mode, impaired):
    resources = ALLOCATIONS[allocation]
    assert all(resource.users == 1 for resource in resources)
    mcs = []
    for index, resource in enumerate(resources):
        if len(resource.components) == 2:
            mcs.append((0, 5, 9, 15)[(ltf_mode + 2 * int(impaired)) % 4])
        else:
            mcs.append(tuple(DATA_MODES)[(case + index) % len(DATA_MODES)])
    blocks = signaling_blocks(case, allocation, mcs, ltf_mode)
    signal_mcs = case % len(MODES)
    signal_symbols = math.ceil(sum(map(len, blocks)) / MODES[signal_mcs][2])
    usig, _ = mu_header(case, 0, 0, 0, signal_mcs, signal_symbols)
    data_symbols = (98, 100, 99, 98)[ltf_mode]
    ltf_stride = [144, 160, 272, 320][ltf_mode]
    data_stride = [272, 288, 272, 320][ltf_mode]
    rounded = 320 + signal_symbols * 80 + ltf_stride + data_symbols * data_stride
    assert rounded % 80 == 0
    legacy_length = 3 * (rounded // 80 - 1)
    assert legacy_length <= 4095
    samples = prefix(usig, legacy_length) + signaling(blocks, signal_mcs, signal_symbols)
    _, guard, _, ltf_start, data_start = append_training(samples, ltf_mode, 0)

    encoded = []
    layouts = []
    psdus = []
    mpdus = []
    for index, (resource, user_mcs) in enumerate(zip(resources, mcs)):
        layout = capacity(resource, user_mcs, data_symbols)
        mpdu = base.frame(index)
        psdu = bytearray(delimiter(len(mpdu)) + mpdu)
        psdu += b"\xA5" * min(-len(psdu) % 4, layout["psdu_bytes"] - len(psdu))
        while len(psdu) + 4 <= layout["psdu_bytes"]:
            psdu += delimiter(0, 1)
        psdu += b"\xA5" * (layout["psdu_bytes"] - len(psdu))
        seed = 1 + (case * 149 + index * 263) % 2047
        coded, checked = encode_payload(resource, user_mcs, data_symbols, psdu, seed)
        assert checked == layout
        encoded.append(coded)
        layouts.append(layout)
        psdus.append(bytes(psdu))
        mpdus.append(mpdu)
    pilot_bits = base.scramble([0] * (4 + signal_symbols + data_symbols), 127)
    for symbol in range(data_symbols):
        samples += data_symbol(
            resources,
            encoded,
            layouts,
            symbol,
            1 - 2 * pilot_bits[4 + signal_symbols + symbol],
            guard,
        )
    data_end = len(samples)
    assert data_end == 37 + 400 + rounded
    if impaired:
        samples = [
            (value + (0.16j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.31 + 0.006 * index))
            for index, value in enumerate(samples)
        ]
    peak = max(max(abs(value.real), abs(value.imag)) for value in samples)
    gain = min(170, 118 / peak)
    iq = base.quantize(samples, scale=gain)
    return (
        iq,
        "".join(map(str, usig)),
        "".join(str(bit) for block in blocks for bit in block),
        ",".join(map(str, mcs)),
        ";".join(psdu.hex() for psdu in psdus),
        ";".join(mpdu.hex() for mpdu in mpdus),
        signal_symbols,
        data_symbols,
        legacy_length,
        guard,
        ltf_start,
        data_start,
        data_end,
    )


def generate(out):
    corpus = bytearray()
    rows = [
        "name\tusig\tbits\tallocation\tusers\tmcs\tpsdus\tmpdus\t"
        "signal_symbols\tdata_symbols\tlegacy_length\tguard\tltf_start\t"
        "data_start\tdata_end\timpaired\toffset\tbytes\tsha256"
    ]
    for position, allocation in enumerate((0, 24, 25, 48, 55, 64)):
        for ltf_mode in range(4):
            for impaired in (False, True):
                case = 524288 + position * 32 + ltf_mode * 2 + int(impaired)
                values = waveform(case, allocation, ltf_mode, impaired)
                iq = values[0]
                offset = len(corpus)
                corpus.extend(iq)
                name = (
                    f"eht-ofdma-data-bcc-a{allocation}-ltf{ltf_mode}-"
                    f"{'offset' if impaired else 'clean'}"
                )
                rows.append(
                    "\t".join(
                        map(
                            str,
                            [
                                name,
                                values[1],
                                values[2],
                                allocation,
                                len(ALLOCATIONS[allocation]),
                                *values[3:],
                                int(impaired),
                                offset,
                                len(iq),
                                hashlib.sha256(iq).hexdigest(),
                            ],
                        )
                    )
                )
    (out / "eht-ofdma-data-bcc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-ofdma-data-bcc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 OFDMA BCC DATA IQ waveforms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-ofdma-data-bcc-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
