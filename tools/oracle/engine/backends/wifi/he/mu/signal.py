"""Independent HE MU SIG-A vectors (IEEE 802.11ax-2021 Table 27-20).

Reuse the independent polynomial-division CRC and forward BCC/interleaver,
never the receiver. These fixtures qualify headers, not complete MU PPDUs.
"""
import argparse
import itertools
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.he.signal import checksum, encoded


def put(bits, start, width, value):
    bits[start:start + width] = [(value >> i) & 1 for i in range(width)]


def repair(bits):
    crc = checksum(bits[:42])
    bits[42:46] = [(crc >> i) & 1 for i in (3, 2, 1, 0)]


def vectors():
    rows = ['bits\tcoded\tuplink\tmcs\tdcm\tcolor\treuse\tbandwidth\tcount\tcompression\tltf\tgi\tltf_symbols\tmidamble\ttxop\textra\tstbc\tpadding\tpe']
    modes = [(mcs, dcm) for mcs in range(6) for dcm in range(2)
             if not dcm or mcs in (0, 1, 3, 4)]
    widths = [(bw, comp) for bw in range(8) for comp in range(2)
              if not comp or bw < 4]
    training = [(0, raw) for raw in range(5)] + [(1, raw) for raw in (0, 1, 2, 4, 5, 6)]
    for i, ((mcs, dcm), (bw, comp), gi, (doppler, raw)) in enumerate(
            itertools.product(modes, widths, range(4), training)):
        bits = [0] * 52
        ltf_symbols = [1, 2, 4, 6, 8][raw & 3 if doppler else raw]
        stbc = (i // 3) % 2 if ltf_symbols > 1 else 0
        count = 0 if comp and stbc else i % 16
        values = [(0,1,i%2), (1,3,mcs), (4,1,dcm), (5,6,i%64),
                  (11,4,i%16), (15,3,bw), (18,4,count), (22,1,comp),
                  (23,2,gi), (25,1,doppler), (26,7,i%128), (33,1,1),
                  (34,3,raw), (37,1,(i//2)%2), (38,1,stbc),
                  (39,2,(i//7)%4), (41,1,(i//5)%2)]
        for start, width, value in values:
            put(bits, start, width, value)
        repair(bits)
        ltf, guard = [(4,800), (2,800), (2,1600), (4,3200)][gi]
        expected = [i%2, mcs, dcm, i%64, i%16, bw, count, comp, ltf,
                    guard, ltf_symbols, (20 if raw & 4 else 10) if doppler else 0,
                    i%128, (i//2)%2, stbc, ((i//7)%4) or 4, (i//5)%2]
        rows.append('\t'.join([''.join(map(str,bits)), encoded(bits), *map(str,expected)]))
    invalid = ['name\tbits\terror\tindex']
    baseline = [0]*52
    baseline[33] = 1
    repair(baseline)
    cases = [('reserved-bit',[(33,1,0)],33)]
    cases += [(f'mcs-{m}',[(1,3,m)],1) for m in (6,7)]
    cases += [(f'dcm-{m}',[(1,3,m),(4,1,1)],4) for m in (2,5)]
    cases += [(f'compressed-bw-{bw}',[(15,3,bw),(22,1,1)],15) for bw in range(4,8)]
    cases += [(f'ltf-{raw}',[(34,3,raw)],34) for raw in (5,6,7)]
    cases += [(f'doppler-ltf-{raw}',[(25,1,1),(34,3,raw)],34) for raw in (3,7)]
    for name, fields, index in cases:
        bits = baseline.copy()
        for start,width,value in fields:
            put(bits,start,width,value)
        repair(bits)
        invalid.append('\t'.join([name,''.join(map(str,bits)),'reserved',str(index)]))
    for index in range(42,52):
        bits = baseline.copy(); bits[index] ^= 1
        invalid.append('\t'.join([f'bit-{index}',''.join(map(str,bits)),
                                  'crc' if index < 46 else 'tail',str(index)]))
    return {'he-mu-signal-a-index.tsv':'\n'.join(rows)+'\n',
            'he-mu-signal-a-invalid.tsv':'\n'.join(invalid)+'\n'}


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true'); args=parser.parse_args()
    out=IQ_FIXTURES
    for name, content in vectors().items():
        if args.write:
            (out/name).write_text(content)
        else:
            assert (out/name).read_text()==content,name
        print(f'{name}: {len(content.splitlines())-1} cases')
