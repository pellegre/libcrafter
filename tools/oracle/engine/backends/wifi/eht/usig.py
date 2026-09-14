"""Independent EHT U-SIG vectors; IEEE 802.11 TGbe 11-21/0049r1.

Forward CRC, BCC and interleaving use no production receiver implementation.
The resulting vectors qualify the signaling kernel, not complete IQ reception.
"""
import argparse
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

from tools.oracle.engine.backends.wifi.he.signal import checksum, encoded


OUT = IQ_FIXTURES / "eht-usig-index.tsv"


def put(bits, start, width, value):
    bits[start:start + width] = [(value >> index) & 1 for index in range(width)]


def repair(bits):
    value = checksum(bits[:42])
    bits[42:46] = [(value >> shift) & 1 for shift in (3, 2, 1, 0)]


def common(bandwidth, uplink, color, txop):
    bits = [0] * 52
    put(bits, 3, 3, bandwidth)
    put(bits, 6, 1, uplink)
    put(bits, 7, 6, color)
    put(bits, 13, 7, txop)
    return bits


def mu_header(case, bandwidth, uplink, ppdu_type, mcs, symbols):
    bits = common(bandwidth, uplink, (case * 11 + 7) % 64, (case * 23 + 5) % 128)
    put(bits, 20, 5, (case * 13) % 32)
    bits[25] = 1
    put(bits, 26, 2, ppdu_type)
    bits[28] = 1
    puncturing = (15 | ((case & 1) << 4)) if bandwidth <= 1 else (case * 19) % 32
    put(bits, 29, 5, puncturing)
    bits[34] = 1
    put(bits, 35, 2, mcs)
    put(bits, 37, 5, symbols - 1)
    repair(bits)
    return bits, puncturing


def tb_header(case, bandwidth, first, second):
    bits = common(bandwidth, 1, (case * 17 + 3) % 64, (case * 29 + 9) % 128)
    put(bits, 20, 6, (case * 37) % 64)
    bits[28] = 1
    put(bits, 29, 4, first)
    put(bits, 33, 4, second)
    put(bits, 37, 5, (case * 7) % 32)
    repair(bits)
    return bits


def generate():
    rows = ["bits\tinterleaved\tbandwidth\tuplink\tcolor\ttxop\tformat\tppdu_type\tpuncturing\tmcs\tsymbols\treuse1\treuse2"]
    case = 0
    for uplink, ppdu_type in ((0, 0), (0, 1), (1, 1), (0, 2)):
        for bandwidth in range(6):
            for mcs in range(4):
                for symbols in (1, 2, 7, 16, 31, 32):
                    bits, puncturing = mu_header(
                        case, bandwidth, uplink, ppdu_type, mcs, symbols
                    )
                    values = [
                        bandwidth, uplink, (case * 11 + 7) % 64,
                        (case * 23 + 5) % 128, 0, ppdu_type,
                        puncturing, mcs, symbols, 255, 255,
                    ]
                    rows.append("\t".join([
                        "".join(map(str, bits)), encoded(bits), *map(str, values)
                    ]))
                    case += 1
    for bandwidth in range(6):
        for first in range(16):
            for second in range(16):
                bits = tb_header(case, bandwidth, first, second)
                values = [
                    bandwidth, 1, (case * 17 + 3) % 64,
                    (case * 29 + 9) % 128, 1, 255, 255, 255, 255,
                    first, second,
                ]
                rows.append("\t".join([
                    "".join(map(str, bits)), encoded(bits), *map(str, values)
                ]))
                case += 1
    assert len(rows) == 2113
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = generate()
    if args.write:
        OUT.write_text(result)
    else:
        assert OUT.read_text() == result, "EHT U-SIG inventory differs"
    print("2112 independent EHT U-SIG vectors verified")
