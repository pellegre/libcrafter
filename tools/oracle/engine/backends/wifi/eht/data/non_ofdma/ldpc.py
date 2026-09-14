"""Independent EHT20 non-OFDMA LDPC rate matching and payload model."""

import argparse
from fractions import Fraction as F
import json
import math

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import MODES
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import scramble
from tools.oracle.engine.backends.wifi.ldpc.codeword import FIXTURE as LDPC_FIXTURE
from tools.oracle.engine.backends.wifi.ldpc.codeword import encode as ldpc_encode
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


LAYOUT_OUT = IQ_FIXTURES / "eht-data-ldpc-index.tsv"
PAYLOAD_OUT = IQ_FIXTURES / "eht-data-ldpc-payload-index.tsv"
CODES = {
    (entry["n"], tuple(entry["rate"])): entry
    for entry in json.loads(LDPC_FIXTURE.read_text())["codes"]
}


def layout(mcs, initial_symbols, initial_padding):
    bits, rate_num, rate_den, dcm = MODES[mcs]
    rate = F(rate_num, rate_den)
    coded = (117 if dcm else 234) * bits
    coded_short = (30 if dcm else 60) * bits
    data = int(coded * rate)
    data_short = int(coded_short * rate)
    payload = (initial_symbols - 1) * data
    payload += data if initial_padding == 4 else initial_padding * data_short
    available = (initial_symbols - 1) * coded
    available += coded if initial_padding == 4 else initial_padding * coded_short
    if available <= 648:
        count, size = (
            1,
            1296 if available >= payload + 912 * (1 - rate) else 648,
        )
    elif available <= 1296:
        count, size = (
            1,
            1944 if available >= payload + 1464 * (1 - rate) else 1296,
        )
    elif available <= 1944:
        count, size = 1, 1944
    elif available <= 2592:
        count, size = (
            2,
            1944 if available >= payload + 2916 * (1 - rate) else 1296,
        )
    else:
        count, size = math.ceil(F(payload, 1944) / rate), 1944
    shortened = max(0, int(count * size * rate) - payload)
    punctured = max(0, count * size - available - shortened)
    parity = count * size * (1 - rate)
    extra = (
        punctured > parity / 10
        and shortened < F(6, 5) * punctured * rate / (1 - rate)
    ) or punctured > 3 * parity / 10
    symbols = initial_symbols
    padding = initial_padding
    if extra:
        available += coded - 3 * coded_short if padding == 3 else coded_short
        if padding == 4:
            symbols += 1
            padding = 1
        else:
            padding += 1
    punctured = max(0, count * size - available - shortened)
    repeated = max(0, int(available - parity - payload))
    assert count * size - shortened - punctured + repeated == available
    assert not (punctured and repeated)
    return [
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


def encode(bits, sizing, mcs):
    _, _, _, count, size, shortened, punctured, repeated, payload, available = sizing
    assert len(bits) == payload
    _, rate_num, rate_den, _ = MODES[mcs]
    matrix = CODES[size, (rate_num, rate_den)]
    expansion = matrix["z"]
    information = matrix["k"]
    checks = [
        sum(
            1 << (column * expansion + (offset + shift) % expansion)
            for column, shift in enumerate(block)
            if shift >= 0
        )
        for block in matrix["matrix"]
        for offset in range(expansion)
    ]
    cursor = 0
    transmitted = []
    for index in range(count):
        short = shortened // count + int(index < shortened % count)
        puncture = punctured // count + int(index < punctured % count)
        repeat = repeated // count + int(index < repeated % count)
        word_bits = bits[cursor : cursor + information - short]
        cursor += information - short
        word = list(
            map(
                int,
                ldpc_encode(
                    checks,
                    information,
                    size,
                    sum(bit << position for position, bit in enumerate(word_bits)),
                ),
            )
        )
        word = word[: information - short] + word[information : size - puncture]
        transmitted += word
        transmitted += [word[position % len(word)] for position in range(repeat)]
    assert cursor == payload and len(transmitted) == available
    return transmitted


def case(mcs, initial_symbols, initial_padding, psdu=None):
    sizing = layout(mcs, initial_symbols, initial_padding)
    symbols, padding = sizing[:2]
    bits_per_tone, rate_num, rate_den, dcm = MODES[mcs]
    coded_per_symbol = (117 if dcm else 234) * bits_per_tone
    coded_short = (30 if dcm else 60) * bits_per_tone
    data_per_symbol = coded_per_symbol * rate_num // rate_den
    coded_last = coded_per_symbol if padding == 4 else padding * coded_short
    payload_bits = sizing[8] - 16
    psdu_bytes, phy_pad_bits = divmod(payload_bits, 8)
    seed = 1 + (mcs * 131 + initial_padding * 257 + initial_symbols * 509) % 2047
    if psdu is None:
        psdu = bytes(
            (index * 37 + seed + mcs * 13) % 256 for index in range(psdu_bytes)
        )
    else:
        psdu = bytes(psdu)
        assert len(psdu) == psdu_bytes
    information = [0] * 16 + base.bits(psdu) + [
        (seed + index) & 1 for index in range(phy_pad_bits)
    ]
    fec = encode(scramble(information, seed), sizing, mcs)
    output = []
    cursor = 0
    for symbol in range(symbols):
        keep = coded_last if symbol + 1 == symbols else coded_per_symbol
        output += fec[cursor : cursor + keep]
        cursor += keep
        output += [
            (seed + symbol + index) & 1
            for index in range(coded_per_symbol - keep)
        ]
    assert cursor == len(fec)
    assert len(output) == symbols * coded_per_symbol
    values = [
        mcs,
        initial_symbols,
        initial_padding,
        symbols,
        padding,
        sizing[2],
        seed,
        bits_per_tone,
        rate_num,
        rate_den,
        dcm,
        coded_per_symbol,
        coded_short,
        data_per_symbol,
        coded_last,
        sizing[9],
        sizing[8],
        psdu_bytes,
        phy_pad_bits,
        sizing[3],
        sizing[4],
        sizing[5],
        sizing[6],
        sizing[7],
    ]
    return values, psdu, output


def generate_layouts():
    rows = [
        "mcs\tinitial_symbols\tinitial_padding\tsymbols\tpadding\textra\twords\tblock\tshort\tpuncture\trepeat\tpayload\tavailable"
    ]
    initial_counts = sorted(set(range(1, 65)) | {127, 128, 129, 199, 200, 399, 400})
    for mcs in MODES:
        for initial_symbols in initial_counts:
            for initial_padding in range(1, 5):
                result = layout(mcs, initial_symbols, initial_padding)
                if result[8] < 16 or result[0] > 400:
                    continue
                rows.append(
                    "\t".join(map(str, [mcs, initial_symbols, initial_padding, *result]))
                )
    return "\n".join(rows) + "\n"


def generate_payloads():
    rows = [
        "mcs\tinitial_symbols\tinitial_padding\tsymbols\tpadding\textra\tseed\tbits_per_tone\trate_num\trate_den\tdcm\tcoded_per_symbol\tcoded_short\tdata_per_symbol\tcoded_last\tcoded_bits\tdata_bits\tpsdu_bytes\tphy_pad_bits\twords\tblock\tshort\tpuncture\trepeat\tpsdu\tcoded"
    ]
    for mcs in MODES:
        for initial_symbols in (2, 5):
            for initial_padding in range(1, 5):
                values, psdu, coded = case(mcs, initial_symbols, initial_padding)
                rows.append(
                    "\t".join(
                        map(str, [*values, psdu.hex(), "".join(map(str, coded))])
                    )
                )
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    layouts = generate_layouts()
    payloads = generate_payloads()
    if args.write:
        LAYOUT_OUT.write_text(layouts)
        PAYLOAD_OUT.write_text(payloads)
    else:
        assert LAYOUT_OUT.read_text() == layouts, "EHT DATA LDPC inventory differs"
        assert PAYLOAD_OUT.read_text() == payloads, "EHT DATA LDPC payload inventory differs"
    print(
        f"{len(layouts.splitlines()) - 1} EHT DATA LDPC layouts and "
        f"{len(payloads.splitlines()) - 1} payloads verified"
    )
