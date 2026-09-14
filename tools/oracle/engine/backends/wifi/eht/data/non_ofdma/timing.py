"""Independent EHT20 non-OFDMA DATA timeline inventory."""

import argparse

from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES / "eht-data-timing-index.tsv"


def generate():
    rows = [
        "length\tsig_symbols\tltf_mode\tltf_size\tguard\tltf_symbols\tpe_disambiguity\tdata_symbols\tpe_samples\tdata_start\tdata_end\tpacket_end\tsignaled_end"
    ]
    lengths = [*range(3, 4096, 30), 4095]
    for sig_symbols in (1, 2, 7, 16, 32):
        for ltf_mode, (ltf_size, guard) in enumerate(
            ((2, 16), (2, 32), (4, 16), (4, 64))
        ):
            for ltf_symbols in (1, 2, 4, 6, 8):
                for pe_disambiguity in (0, 1):
                    training = ltf_symbols * (64 * ltf_size + guard)
                    fixed = 320 + 80 * sig_symbols + training
                    stride = 256 + guard
                    for length in lengths:
                        rounded = (length + 3) // 3 * 80
                        available = rounded - fixed
                        if available < 0:
                            continue
                        data_symbols = available // stride - pe_disambiguity
                        if data_symbols <= 0:
                            continue
                        data_start = 720 + 80 * sig_symbols + training
                        data_end = data_start + data_symbols * stride
                        pe_samples = (available - data_symbols * stride) // 80 * 80
                        if pe_samples > 320:
                            continue
                        rows.append(
                            "\t".join(
                                map(
                                    str,
                                    [
                                        length,
                                        sig_symbols,
                                        ltf_mode,
                                        ltf_size,
                                        guard,
                                        ltf_symbols,
                                        pe_disambiguity,
                                        data_symbols,
                                        pe_samples,
                                        data_start,
                                        data_end,
                                        data_end + pe_samples,
                                        400 + rounded,
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
        assert OUT.read_text() == result, "EHT DATA timing inventory differs"
    print(f"{len(result.splitlines()) - 1} EHT DATA timelines verified")
