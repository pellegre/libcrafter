"""Independent HT-SIG oracle using polynomial division, not a shift-register CRC.

IEEE 802.11-2020 19.3.9.4.3-4, Table 19-11 and published CRC example.
This generator cannot transmit and imports no crafter implementation.
"""
import argparse
from pathlib import Path

OUT = Path(__file__).resolve().parents[4] / 'crafter/tests/fixtures/iq/ht-signal-index.tsv'


def crc(bits):
    message = int(''.join(map(str, bits)), 2)
    polynomial = (message ^ (255 << (len(bits) - 8))) << 8
    while polynomial.bit_length() > 8:
        polynomial ^= 0x107 << (polynomial.bit_length() - 9)
    return [((polynomial ^ 255) >> shift) & 1 for shift in range(7, -1, -1)]


def generate():
    example = list(map(int, '1111000100100110000000001110000000'))
    assert crc(example) == list(map(int, '10101000'))
    rows = ['bits\tmcs\tcbw40\tlength\tsmoothing\tnot_sounding\taggregation\tstbc\tldpc\tshort_gi\textension_streams']
    for case in range(256):
        fields = [case % 128, case // 128, (case * 257) % 65536,
                  (case >> 1) & 1, (case >> 2) & 1, (case >> 3) & 1,
                  (case >> 4) & 3, (case >> 6) & 1, (case >> 7) & 1, case & 3]
        mcs, width, length, smooth, sounding, aggregate, stbc, ldpc, gi, ess = fields
        wire = [(mcs >> k) & 1 for k in range(7)] + [width]
        wire += [(length >> k) & 1 for k in range(16)]
        wire += [smooth, sounding, 1, aggregate, stbc & 1, stbc >> 1,
                 ldpc, gi, ess & 1, ess >> 1]
        wire += crc(wire) + [0] * 6
        rows.append('\t'.join([''.join(map(str, wire))] + list(map(str, fields))))
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate()
    if args.check:
        assert OUT.read_text() == result, 'HT-SIG inventory differs'
    else:
        OUT.write_text(result)
    print('256 independent HT-SIG vectors verified')
