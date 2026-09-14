"""Independent EHT20 non-OFDMA DATA capacity inventory."""

import argparse

from tools.oracle.engine.backends.wifi.eht.data.non_ofdma.model import MODES
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES / "eht-data-capacity-index.tsv"


def generate():
    rows = [
        "mcs\tldpc\textra\tpadding\tsymbols\tbits_per_tone\trate_num\trate_den\tdcm\tcoded_per_symbol\tcoded_short\tdata_per_symbol\tcoded_last\tcoded_bits\tdata_bits\tpsdu_bytes\tphy_pad_bits\ttail_bits\tbcc_dcm_filler"
    ]
    for mcs, (bits, rate_num, rate_den, dcm) in MODES.items():
        for ldpc in (0, 1):
            if not ldpc and mcs not in (*range(10), 15):
                continue
            for extra in (0, 1):
                for padding in (1, 2, 3, 4):
                    for symbols in (1, 2, 3, 4, 7, 16, 31, 64, 127, 256, 400):
                        data_tones = 117 if dcm else 234
                        short_tones = 30 if dcm else 60
                        cbps = data_tones * bits
                        short_cbps = short_tones * bits
                        dbps = cbps * rate_num // rate_den
                        short_dbps = short_cbps * rate_num // rate_den
                        effective_extra = bool(ldpc and extra)
                        if effective_extra and padding == 1:
                            payload_symbols, payload_padding = symbols - 1, 4
                        elif effective_extra:
                            payload_symbols, payload_padding = symbols, padding - 1
                        else:
                            payload_symbols, payload_padding = symbols, padding
                        if payload_symbols < 1:
                            continue
                        data_last = (
                            dbps
                            if payload_padding == 4
                            else payload_padding * short_dbps
                        )
                        data_bits = (payload_symbols - 1) * dbps + data_last
                        tail = 0 if ldpc else 6
                        payload = data_bits - 16 - tail
                        if payload < 0:
                            continue
                        coded_last = (
                            cbps if padding == 4 else padding * short_cbps
                        )
                        coded_bits = (symbols - 1) * cbps + coded_last
                        rows.append(
                            "\t".join(
                                map(
                                    str,
                                    [
                                        mcs,
                                        ldpc,
                                        extra,
                                        padding,
                                        symbols,
                                        bits,
                                        rate_num,
                                        rate_den,
                                        dcm,
                                        cbps,
                                        short_cbps,
                                        dbps,
                                        coded_last,
                                        coded_bits,
                                        data_bits,
                                        payload // 8,
                                        payload % 8,
                                        tail,
                                        int(not ldpc and mcs == 15),
                                    ],
                                )
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
        assert OUT.read_text() == result, "EHT DATA capacity inventory differs"
    print(f"{len(result.splitlines()) - 1} EHT DATA capacities verified")
