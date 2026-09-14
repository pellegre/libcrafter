"""Independent VHT20 SIG-B and SERVICE oracle; IEEE 802.11-2020.

Tables 21-14/15/16, Equations 21-46/59/76/77 and 21.3.12.
No production decoder/transmitter imports. Header fixtures, not full IQ.
"""
import argparse
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
import tools.oracle.engine.backends.wifi.ht.signal as ht
import tools.oracle.engine.backends.wifi.ofdm.base as encoder

OUT = IQ_FIXTURES / 'vht-signal-b20-index.tsv'
NDP = '00000111010001000010'


def little(value, count):
    return [(value >> bit) & 1 for bit in range(count)]


def generate():
    assert ht.crc(list(map(int, '10011000000000000000011'))) == list(map(int, '00011100'))
    encoder.self_check()
    rows = ['bits\tmulti_user\tndp\tlength_units\tmcs\tminimum_octets\tmaximum_octets\tservice\tinterleaved']

    def emit(fields, multi, ndp, length, mcs):
        bits = fields + [0] * 6
        coded = encoder.encode(bits)
        assert len(coded) == 52
        indices = [4 * (k % 13) + k // 13 for k in range(52)]
        assert sorted(indices) == list(range(52))
        interleaved = [0] * 52
        for k, index in enumerate(indices):
            interleaved[index] = coded[k]
        service = '-' if ndp else '00000000' + ''.join(map(str, ht.crc(fields)))
        minimum = 0 if not length else 4 * (length - 1) + 1
        rows.append('\t'.join([''.join(map(str, bits)), str(multi), str(ndp), str(length), str(mcs),
                              str(minimum), str(length * 4), service, ''.join(map(str, interleaved))]))

    lengths = [0, 1, 2, 3, 4, 7, 15, 255, 256, 1023, 1024, 16383, 65535, 65536, 131071]
    for length in lengths:
        emit(little(length, 17) + [1, 1, 1], 0, 0, length, -1)
    for length in lengths:
        if length > 65535:
            continue
        for mcs in range(16):
            emit(little(length, 16) + little(mcs, 4), 1, 0, length, mcs)
    ndp_bits = list(map(int, NDP))
    emit(ndp_bits, 0, 1, 0, -1)
    collision_length = sum(bit << i for i, bit in enumerate(ndp_bits[:16]))
    collision_mcs = sum(bit << i for i, bit in enumerate(ndp_bits[16:]))
    emit(ndp_bits, 1, 0, collision_length, collision_mcs)
    assert len(rows) == 226
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate()
    if args.check:
        assert OUT.read_text() == result, 'VHT20 SIG-B inventory differs'
    else:
        OUT.write_text(result)
    print('225 independent VHT20 SIG-B/SERVICE vectors verified')
