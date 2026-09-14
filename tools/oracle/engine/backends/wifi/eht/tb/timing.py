"""Independent forward EHT20 TB timelines."""

import argparse
import math
from fractions import Fraction

from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES / "eht-tb-timing.tsv"


def generate():
    rows = [
        "gi_ltf\tltf_code\tsymbols\tpe\tlength\tdisambiguity\tltf_size\tguard\tltf_symbols\tdata_start\tdata_end\tpacket_end\tsignaled_end"
    ]
    for gi_ltf, ltf_size, guard_us in ((1, 2, Fraction(8, 5)), (2, 4, Fraction(16, 5))):
        symbol_us = Fraction(64, 5) + guard_us
        for ltf_code, ltf_symbols in enumerate((1, 2, 4, 6, 8)):
            training_us = ltf_symbols * (Fraction(16, 5) * ltf_size + guard_us)
            for symbols in (1, 2, 3, 7, 15, 31, 63, 127, 255, 400):
                data_start_us = 40 + training_us
                data_end_us = data_start_us + symbols * symbol_us
                for pe_us in (0, 4, 8, 12, 16):
                    packet_end_us = data_end_us + pe_us
                    units = math.ceil((packet_end_us - 20) / 4)
                    length = 3 * (units - 1)
                    if length > 4095:
                        continue
                    disambiguity = int(
                        pe_us + 4 * units - (packet_end_us - 20) >= symbol_us
                    )
                    rows.append(
                        "\t".join(
                            map(
                                str,
                                (
                                    gi_ltf,
                                    ltf_code,
                                    symbols,
                                    pe_us * 20,
                                    length,
                                    disambiguity,
                                    ltf_size,
                                    int(guard_us * 20),
                                    ltf_symbols,
                                    int(data_start_us * 20),
                                    int(data_end_us * 20),
                                    int(packet_end_us * 20),
                                    (20 + 4 * units) * 20,
                                ),
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
        assert OUT.read_text() == result, "EHT TB timing inventory differs"
    print(f"{len(result.splitlines()) - 1} EHT TB timelines verified")
