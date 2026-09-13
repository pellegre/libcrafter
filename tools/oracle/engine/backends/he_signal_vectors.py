"""Independent HE SU header vectors, IEEE 802.11ax-2021 Tables 27-18/19/35.

CRC uses polynomial long division rather than the receiver's shift register.
These are header vectors, not evidence of a receivable complete PPDU.
"""
import argparse
import itertools
from pathlib import Path


def checksum(bits):
    polynomial = int("".join(map(str, bits)), 2) ^ (255 << (len(bits) - 8))
    polynomial <<= 8
    for shift in range(polynomial.bit_length() - 9, -1, -1):
        if polynomial & (1 << (shift + 8)):
            polynomial ^= 0x107 << shift
    return ((polynomial ^ 255) >> 4) & 15


def encoded(bits):
    state = 0
    coded = []
    for bit in bits:
        # Figure 17-8 convention: newest input occupies the high-order tap
        # when using the published 133/171 octal polynomial representation.
        state = (state >> 1) | (bit << 6)
        coded.extend(((state & mask).bit_count() % 2) for mask in (0o133, 0o171))
    out = [0] * 104
    for symbol in range(2):
        for k in range(52):
            out[52 * symbol + 4 * (k % 13) + k // 13] = coded[52 * symbol + k]
    return "".join(map(str, out))


def vectors():
    example = list(map(int, "110111000000001000000110000000000010011010"))
    assert checksum(example) == 7
    zero = [0] * 42
    assert [i for i in range(42) if checksum(zero[:i] + [1] + zero[i+1:])
            == checksum(zero)] == [18, 40, 41]
    # Impulse response independently pins polynomial bit orientation and A/B
    # output order before any signaling-field expectations are constructed.
    impulse = [1] + [0] * 51
    expected_coded = [1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1] + [0] * 90
    actual = encoded(impulse)
    assert all(int(actual[52 * (k // 52) + 4 * (k % 52 % 13) + (k % 52) // 13])
               == value for k, value in enumerate(expected_coded))
    rows = ["bits\tcoded\tmcs\tbandwidth\tnsts\tmidamble\tdcm\tstbc\tltf\tgi\tldpc\textra\tpadding\tcolor\treuse\ttxop\tbeam_change\tuplink\tbeamformed\tpe"]
    for i, (mcs, bw, gi, mode, doppler, ldpc) in enumerate(itertools.product(
            range(12), range(4), range(4), range(4), range(2), range(2))):
        dcm, stbc = mode & 1, mode >> 1
        if dcm and stbc and gi != 3:
            continue
        # Normal DCM applicability; escape combination applies neither mode.
        if dcm and not stbc and mcs not in (0, 1, 3, 4):
            continue
        bits = [0] * 52
        def put(start, width, value):
            bits[start:start + width] = [(value >> b) & 1 for b in range(width)]
        raw_streams = i % 8
        put(0, 1, 1)
        put(1, 2, i % 4)
        put(3, 4, mcs)
        put(7, 1, dcm)
        put(8, 6, i % 64)
        put(14, 1, 1)
        put(15, 4, i % 16)
        put(19, 2, bw)
        put(21, 2, gi)
        put(23, 3, raw_streams)
        put(26, 7, i % 128)
        put(33, 1, ldpc)
        put(34, 1, (i // 2) % 2 if ldpc else 1)
        put(35, 1, stbc)
        put(36, 1, (i // 3) % 2)
        put(37, 2, (i // 7) % 4)
        put(39, 1, (i // 5) % 2)
        put(40, 1, 1)
        put(41, 1, doppler)
        crc = checksum(bits[:42])
        bits[42:46] = [(crc >> b) & 1 for b in (3, 2, 1, 0)]
        ltf, guard = [(1, 800), (2, 800), (2, 1600), (4, 3200)][gi]
        if dcm and stbc:
            dcm, stbc, ltf, guard = 0, 0, 4, 800
        expected = [mcs, bw, (raw_streams & (3 if doppler else 7)) + 1,
                    (20 if raw_streams & 4 else 10) if doppler else 0,
                    dcm, stbc, ltf, guard, ldpc, bits[34] if ldpc else -1,
                    ((i // 7) % 4) or 4, i % 64, i % 16, i % 128,
                    bits[1], bits[2], bits[36], bits[39]]
        rows.append("\t".join(["".join(map(str, bits)), encoded(bits), *map(str, expected)]))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[4] / "crafter/tests/fixtures/iq/he-signal-a-index.tsv"
    result = vectors()
    if args.write:
        target.write_text(result)
    else:
        assert target.read_text() == result
    print(f"HE SU header vectors: {len(result.splitlines()) - 1}")
