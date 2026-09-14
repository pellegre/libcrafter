"""Independent EHT20 non-OFDMA BCC DATA payload model."""

import argparse

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import MODES as DATA_MODES
from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import scramble
from tools.oracle.engine.backends.wifi.ht.bcc import PUNCTURE
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES / "eht-data-bcc-index.tsv"
MODES = {
    mcs: values[:3]
    for mcs, values in DATA_MODES.items()
    if mcs in (*range(10), 15)
}


def case(mcs, padding, symbols, psdu=None):
    bits_per_tone, rate_num, rate_den = MODES[mcs]
    dcm = mcs == 15
    data_tones = 117 if dcm else 234
    short_tones = 30 if dcm else 60
    coded_per_symbol = data_tones * bits_per_tone
    coded_short = short_tones * bits_per_tone
    data_per_symbol = coded_per_symbol * rate_num // rate_den
    data_short = coded_short * rate_num // rate_den
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
    coded_last = coded_per_symbol if padding == 4 else padding * coded_short
    data_last = data_per_symbol if padding == 4 else padding * data_short
    coded_bits = (symbols - 1) * coded_per_symbol + coded_last
    data_bits = (symbols - 1) * data_per_symbol + data_last
    payload_bits = data_bits - 22
    psdu_bytes, phy_pad_bits = divmod(payload_bits, 8)
    seed = 1 + (mcs * 131 + padding * 257 + symbols * 509) % 2047
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
    encoded = base.encode(scramble(information, seed) + [0] * 6)
    fec = [
        bit
        for index, bit in enumerate(encoded)
        if puncturing[index % len(puncturing)]
    ]
    output = []
    cursor = 0
    for symbol in range(symbols):
        keep = coded_last if symbol == symbols - 1 else coded_per_symbol
        filler = int(dcm and keep == coded_per_symbol)
        amount = keep - filler
        output.extend(fec[cursor : cursor + amount])
        cursor += amount
        if filler:
            output.append((seed + symbol) & 1)
        output.extend(
            (seed + symbol + index) & 1 for index in range(coded_per_symbol - keep)
        )
    assert cursor == len(fec)
    assert len(output) == symbols * coded_per_symbol
    return (
        [
            mcs,
            padding,
            symbols,
            seed,
            bits_per_tone,
            rate_num,
            rate_den,
            coded_per_symbol,
            coded_short,
            data_per_symbol,
            coded_last,
            coded_bits,
            data_bits,
            psdu_bytes,
            phy_pad_bits,
            6,
        ],
        psdu,
        output,
    )


def generate():
    rows = [
        "mcs\tpadding\tsymbols\tseed\tbits_per_tone\trate_num\trate_den\tcoded_per_symbol\tcoded_short\tdata_per_symbol\tcoded_last\tcoded_bits\tdata_bits\tpsdu_bytes\tphy_pad_bits\ttail_bits\tpsdu\tcoded"
    ]
    for mcs in MODES:
        for padding in range(1, 5):
            for symbols in (3, 5):
                values, psdu, coded = case(mcs, padding, symbols)
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
    result = generate()
    if args.write:
        OUT.write_text(result)
    else:
        assert OUT.read_text() == result, "EHT DATA BCC inventory differs"
    print(f"{len(result.splitlines()) - 1} EHT DATA BCC payloads verified")
