"""Independent EHT20 OFDMA LDPC DATA IQ vectors."""

import argparse
import cmath
from fractions import Fraction
import hashlib
import math
import tempfile
from pathlib import Path

import tools.oracle.engine.backends.wifi.he.training as training
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.data.ofdma.bcc import (
    PILOT_SIGNS,
    tones,
)
from tools.oracle.engine.backends.wifi.eht.signal.ofdma.allocation import ALLOCATIONS
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.ldpc import encode as ldpc_encode
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import MODES as DATA_MODES
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import scramble
from tools.oracle.engine.backends.wifi.eht.signal.fields import protected
from tools.oracle.engine.backends.wifi.eht.signal.waveform import (
    MODES,
    append_training,
    prefix,
    signaling,
)
from tools.oracle.engine.backends.wifi.eht.usig import mu_header, put
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter
from tools.oracle.engine.backends.wifi.vht.bcc.iq import constellation


OUT = IQ_FIXTURES
# A CS8 corpus cannot retain enough constellation separation for 4096-QAM on
# narrow RUs. MCS12 is still exercised on a full 242-tone RU below; MCS13 is
# covered by the bit-exact LDPC fixtures rather than claimed as robust IQ.
MCS_VALUES = tuple(mcs for mcs in DATA_MODES if mcs not in (12, 13))


def geometry(component, mcs):
    bits, numerator, denominator, dcm = DATA_MODES[mcs]
    data, _ = tones(component)
    data_tones = len(data) // (1 + dcm)
    short_tones = {
        (26, 0): 6,
        (26, 1): 2,
        (52, 0): 12,
        (52, 1): 6,
        (106, 0): 24,
        (106, 1): 12,
        (242, 0): 60,
        (242, 1): 30,
    }[component.size, dcm]
    coded = data_tones * bits
    coded_short = short_tones * bits
    return bits, numerator, denominator, bool(dcm), coded, coded_short


def dimensions(payload, available, numerator, denominator):
    threshold = lambda constant: (
        available * denominator
        >= payload * denominator + constant * (denominator - numerator)
    )
    if available <= 648:
        return 1, 1296 if threshold(912) else 648
    if available <= 1296:
        return 1, 1944 if threshold(1464) else 1296
    if available <= 1944:
        return 1, 1944
    if available <= 2592:
        return 2, 1944 if threshold(2916) else 1296
    information = 1944 * numerator // denominator
    return math.ceil(Fraction(payload, information)), 1944


def rate_layout(component, mcs, initial_symbols, initial_padding, extra):
    bits, numerator, denominator, dcm, coded, coded_short = geometry(component, mcs)
    data = coded * numerator // denominator
    data_short = coded_short * numerator // denominator
    payload = (initial_symbols - 1) * data
    payload += data if initial_padding == 4 else initial_padding * data_short
    initial_available = (initial_symbols - 1) * coded
    initial_available += coded if initial_padding == 4 else initial_padding * coded_short
    count, size = dimensions(payload, initial_available, numerator, denominator)
    shortened = max(0, count * size * numerator // denominator - payload)
    initial_punctured = max(0, count * size - initial_available - shortened)
    parity = count * size * (denominator - numerator) // denominator
    needs_extra = (
        10 * initial_punctured > parity
        and 5 * shortened * (denominator - numerator)
        < 6 * initial_punctured * numerator
    ) or 10 * initial_punctured > 3 * parity
    symbols = initial_symbols
    padding = initial_padding
    available = initial_available
    if extra:
        available += coded - 3 * coded_short if initial_padding == 3 else coded_short
        if initial_padding == 4:
            symbols += 1
            padding = 1
        else:
            padding += 1
    punctured = max(0, count * size - available - shortened)
    repeated = max(0, available - parity - payload)
    assert count * size - shortened - punctured + repeated == available
    assert not (punctured and repeated)
    sizing = [
        symbols,
        padding,
        int(extra),
        count,
        size,
        shortened,
        punctured,
        repeated,
        payload,
        available,
    ]
    return {
        "bits": bits,
        "dcm": dcm,
        "coded": coded,
        "coded_short": coded_short,
        "data": data,
        "symbols": symbols,
        "padding": padding,
        "needs_extra": needs_extra,
        "sizing": sizing,
        "psdu_bytes": (payload - 16) // 8,
        "phy_pad": (payload - 16) % 8,
    }


def choose_layouts(resources, mcs_values, ltf_mode, signal_symbols, initial_padding):
    fixed = 320 + signal_symbols * 80 + [144, 160, 272, 320][ltf_mode]
    stride = [272, 288, 272, 320][ltf_mode]
    for initial_symbols in range(1, 401):
        initial = [
            rate_layout(resource.components[0], mcs, initial_symbols, initial_padding, False)
            for resource, mcs in zip(resources, mcs_values)
        ]
        extra = any(layout["needs_extra"] for layout in initial)
        layouts = [
            rate_layout(resource.components[0], mcs, initial_symbols, initial_padding, extra)
            for resource, mcs in zip(resources, mcs_values)
        ]
        symbols = layouts[0]["symbols"]
        if (
            all(
                layout["symbols"] == symbols and layout["psdu_bytes"] >= 60 + index
                for index, layout in enumerate(layouts)
            )
            and (fixed + symbols * stride) % 80 == 0
        ):
            return initial_symbols, extra, layouts
    raise AssertionError((mcs_values, ltf_mode, signal_symbols, initial_padding))


def signaling_blocks(case, allocation, mcs_values, ltf_mode, padding, extra):
    resources = ALLOCATIONS[allocation]
    common = [0] * 26
    put(common, 0, 4, case % 16)
    put(common, 4, 2, ltf_mode)
    put(common, 6, 3, 0)
    put(common, 9, 1, int(extra))
    put(common, 10, 2, padding % 4)
    put(common, 12, 1, 0)
    put(common, 13, 4, (case * 11 + 3) % 16)
    put(common, 17, 9, allocation)
    users = []
    for index, mcs in enumerate(mcs_values):
        field = [0] * 22
        put(field, 0, 11, (case * 977 + index * 619 + 17) % 2048)
        put(field, 11, 4, mcs)
        put(field, 15, 1, index & 1)
        put(field, 16, 4, 0)
        put(field, 20, 1, (case + index) & 1)
        put(field, 21, 1, 1)
        users.append(field)
    assert len(users) == len(resources)
    blocks = [protected(common)]
    for start in range(0, len(users), 2):
        payload = list(users[start])
        if start + 1 < len(users):
            payload += users[start + 1]
        blocks.append(protected(payload))
    return blocks


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


def encode_payload(component, mcs, layout, psdu, seed):
    assert len(psdu) == layout["psdu_bytes"]
    information = [0] * 16 + base.bits(psdu)
    information += [(seed + index) & 1 for index in range(layout["phy_pad"])]
    fec = ldpc_encode(scramble(information, seed), layout["sizing"], mcs)
    output = []
    cursor = 0
    for symbol in range(layout["symbols"]):
        keep = (
            layout["coded"]
            if symbol + 1 < layout["symbols"] or layout["padding"] == 4
            else layout["padding"] * layout["coded_short"]
        )
        output += fec[cursor : cursor + keep]
        cursor += keep
        output += [
            (seed + symbol + index) & 1
            for index in range(layout["coded"] - keep)
        ]
    assert cursor == len(fec)
    assert len(output) == layout["symbols"] * layout["coded"]
    return output


def data_symbol(resources, encoded, layouts, symbol, polarity, guard):
    frequency = [0j] * 245
    for resource, coded, layout in zip(resources, encoded, layouts):
        component = resource.components[0]
        data, pilots = tones(component)
        start = symbol * layout["coded"]
        block = coded[start : start + layout["coded"]]
        mapped_tones = len(data) // (1 + int(layout["dcm"]))
        distance = {
            (26, False): 1,
            (26, True): 1,
            (52, False): 3,
            (52, True): 1,
            (106, False): 6,
            (106, True): 3,
            (242, False): 9,
            (242, True): 9,
        }[component.size, layout["dcm"]]
        columns = mapped_tones // distance
        for index in range(mapped_tones):
            target = distance * (index % columns) + index // columns
            label = block[index * layout["bits"] : (index + 1) * layout["bits"]]
            lower = point(label)
            frequency[data[target] + 122] = lower
            if layout["dcm"]:
                frequency[data[target + mapped_tones] + 122] = lower * (
                    -1 if (target + mapped_tones) % 2 else 1
                )
        signs = PILOT_SIGNS[component.size]
        for index, tone in enumerate(pilots):
            frequency[tone + 122] = polarity * signs[(symbol + index) % len(signs)]
    wave = [value * 4 * math.sqrt(52 / 242) for value in training.ifft(frequency)]
    return wave[-guard:] + wave


def waveform(case, allocation, ltf_mode, impaired):
    resources = ALLOCATIONS[allocation]
    assert all(len(resource.components) == 1 and resource.users == 1 for resource in resources)
    if allocation == 64:
        mcs_values = [(9, 10, 11, 12)[ltf_mode]]
    else:
        mcs_values = [
            MCS_VALUES[(case + index) % len(MCS_VALUES)]
            for index in range(len(resources))
        ]
    signal_mcs = case % len(MODES)
    provisional = signaling_blocks(case, allocation, mcs_values, ltf_mode, 4, False)
    signal_symbols = math.ceil(sum(map(len, provisional)) / MODES[signal_mcs][2])
    initial_padding = case % 4 + 1
    initial_symbols, extra, layouts = choose_layouts(
        resources, mcs_values, ltf_mode, signal_symbols, initial_padding
    )
    symbols = layouts[0]["symbols"]
    padding = layouts[0]["padding"]
    assert all(layout["symbols"] == symbols and layout["padding"] == padding for layout in layouts)
    blocks = signaling_blocks(case, allocation, mcs_values, ltf_mode, padding, extra)
    usig, _ = mu_header(case, 0, 0, 0, signal_mcs, signal_symbols)
    ltf_stride = [144, 160, 272, 320][ltf_mode]
    data_stride = [272, 288, 272, 320][ltf_mode]
    rounded = 320 + signal_symbols * 80 + ltf_stride + symbols * data_stride
    assert rounded % 80 == 0
    legacy_length = 3 * (rounded // 80 - 1)
    assert legacy_length <= 4095
    samples = prefix(usig, legacy_length) + signaling(blocks, signal_mcs, signal_symbols)
    _, guard, _, ltf_start, data_start = append_training(samples, ltf_mode, 0)

    encoded = []
    psdus = []
    mpdus = []
    for index, (resource, mcs, layout) in enumerate(zip(resources, mcs_values, layouts)):
        mpdu = base.frame(index)
        psdu = bytearray(delimiter(len(mpdu)) + mpdu)
        psdu += b"\xA5" * min(-len(psdu) % 4, layout["psdu_bytes"] - len(psdu))
        while len(psdu) + 4 <= layout["psdu_bytes"]:
            psdu += delimiter(0, 1)
        psdu += b"\xA5" * (layout["psdu_bytes"] - len(psdu))
        seed = 1 + (case * 149 + index * 263) % 2047
        encoded.append(encode_payload(resource.components[0], mcs, layout, psdu, seed))
        psdus.append(bytes(psdu))
        mpdus.append(mpdu)
    pilot_bits = base.scramble([0] * (4 + signal_symbols + symbols), 127)
    for symbol in range(symbols):
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
            (value + (0.14j * samples[index - 3] if index >= 3 else 0))
            * cmath.exp(1j * (0.27 + 0.005 * index))
            for index, value in enumerate(samples)
        ]
    peak = max(max(abs(value.real), abs(value.imag)) for value in samples)
    gain = min(160, 116 / peak)
    iq = base.quantize(samples, scale=gain)
    return (
        iq,
        "".join(map(str, usig)),
        "".join(str(bit) for block in blocks for bit in block),
        ",".join(map(str, mcs_values)),
        ";".join(psdu.hex() for psdu in psdus),
        ";".join(mpdu.hex() for mpdu in mpdus),
        signal_symbols,
        initial_symbols,
        symbols,
        padding,
        int(extra),
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
        "signal_symbols\tinitial_symbols\tdata_symbols\tpadding\textra\t"
        "legacy_length\tguard\tltf_start\tdata_start\tdata_end\timpaired\t"
        "offset\tbytes\tsha256"
    ]
    for position, allocation in enumerate((0, 24, 25, 64)):
        for ltf_mode in range(4):
            impaired = (position + ltf_mode) % 2 != 0
            case = 786432 + position * 32 + ltf_mode * 3
            values = waveform(case, allocation, ltf_mode, impaired)
            iq = values[0]
            offset = len(corpus)
            corpus.extend(iq)
            name = (
                f"eht-ofdma-data-ldpc-a{allocation}-ltf{ltf_mode}-"
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
    (out / "eht-ofdma-data-ldpc-iq-index.tsv").write_text("\n".join(rows) + "\n")
    (out / "eht-ofdma-data-ldpc-iq.cs8").write_bytes(corpus)
    print(f"{len(rows) - 1} independent EHT20 OFDMA LDPC DATA IQ waveforms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-ofdma-data-ldpc-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
