"""Independent VHT-SIG-A bit/BCC oracle, IEEE 802.11-2020 Table 21-12.

Uses polynomial-division CRC and independent BCC/interleaving primitives.
No production decoder or transmitter is imported. These are header fixtures,
not complete IQ waveforms or evidence of DATA reception.
"""
import argparse
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

import tools.oracle.engine.backends.wifi.ht.signal as ht
import tools.oracle.engine.backends.wifi.ofdm.base as encoder

OUT = IQ_FIXTURES / 'vht-signal-a-index.tsv'


def little(value, count):
    return [(value >> bit) & 1 for bit in range(count)]


def generate():
    encoder.self_check()
    rows = ['bits\tbandwidth_code\tgroup_id\tstbc\tnsts_or_partial_aid\tshort_gi\tdisambiguation\tldpc_extra\ttxop_ps_not_allowed\tcoding\tmcs_or_mu_coding\tbeamformed\tinterleaved']

    def emit(width, group, stbc, dimensions, gi, disambiguation, extra, txop, coding, mcs, beamformed):
        bits = little(width, 2) + [1, stbc] + little(group, 6)
        bits += little(dimensions, 12) + [txop, 1]
        bits += [gi, disambiguation, coding, extra] + little(mcs, 4) + [beamformed, 1]
        assert len(bits) == 34
        bits += ht.crc(bits) + [0] * 6
        coded = encoder.encode(bits)
        interleaved = encoder.interleave(coded[:48], 1) + encoder.interleave(coded[48:], 1)
        fields = [width, group, stbc, dimensions, gi, disambiguation, extra, txop, coding, mcs, beamformed]
        rows.append('\t'.join([''.join(map(str, bits))] + list(map(str, fields)) + [''.join(map(str, interleaved))]))

    for group in [0, 63]:
        for width in range(4):
            for nsts in range(1, 9):
                for mcs in range(10):
                    aid = (nsts * 61 + mcs * 17 + width + group) & 511
                    coding = (mcs + nsts + width) & 1
                    gi = (mcs + width) & 1
                    emit(width, group, int(nsts % 2 == 0 and mcs % 2 == 0),
                         (nsts - 1) | (aid << 3), gi, gi & (nsts & 1),
                         coding & (nsts & 1), (mcs >> 1) & 1, coding, mcs, nsts & 1)

    for group in range(1, 63):
        for width in range(4):
            for pattern in range(5):
                counts = [1, 1, 1, 1] if pattern == 4 else [
                    ((group + width) % 4 + 1) if user == pattern else 0
                    for user in range(4)]
                coding = [((group + user + width) & 1) if counts[user] else 1
                          for user in range(4)]
                dimensions = sum(count << (3 * user) for user, count in enumerate(counts))
                mu_coding = 8 | sum(coding[user] << (user - 1) for user in range(1, 4))
                gi = (group + width) & 1
                extra = int(any(count and code for count, code in zip(counts, coding))) & (pattern & 1)
                emit(width, group, 0, dimensions, gi, gi & (pattern & 1),
                     extra, (group >> 1) & 1, coding[0], mu_coding, 1)
    assert len(rows) == 1881
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate()
    if args.check:
        assert OUT.read_text() == result, 'VHT-SIG-A inventory differs'
    else:
        OUT.write_text(result)
    print('1880 independent VHT-SIG-A vectors verified')
