"""Independent equalized HE SIG-B streams, ax-2021 Eq27-21/Tables27-35/111.

Forward interleaving uses matrix columns with per-column bit-group rotations.
Constellation points use explicit Gray-label tables, not the Rust demapper.
Coordinates are unnormalized; the fixture consumer divides by sqrt(energy).
"""
import argparse
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.he.sig_b.coded import vectors as coded_vectors

AXES = {1: {'0': -1, '1': 1},
        2: dict(zip('00 01 11 10'.split(), [-3, -1, 1, 3])),
        3: dict(zip('000 001 011 010 110 111 101 100'.split(), range(-7, 8, 2)))}


def point(bits):
    if len(bits) == 1: return AXES[1][bits], 0
    half = len(bits)//2
    return AXES[half][bits[:half]], AXES[half][bits[half:]]


def interleave(bits, bps):
    rows = len(bits)//13
    output = []
    group = max(1, bps//2)
    for col in range(13):
        column = [bits[row*13+col] for row in range(rows)]
        for start in range(0, rows, group):
            values = column[start:start+group]
            shift = col % group
            output.extend(values[shift:] + values[:shift])
    return ''.join(output)


def modulate(stream, mcs, dcm):
    bps = [1, 2, 2, 4, 4, 6][mcs]
    count = 52*bps//(1+dcm)
    points = []
    for offset in range(0, len(stream), count):
        mapped = interleave(stream[offset:offset+count], bps)
        lower = [point(mapped[k:k+bps]) for k in range(0, count, bps)]
        if dcm:
            upper = []
            for k, (i, q) in enumerate(lower):
                if bps == 1: upper.append((i*(-1 if (k+26)%2 else 1), 0))
                elif bps == 2: upper.append((i, -q))
                else:
                    b = mapped[4*k:4*k+4]
                    upper.append(point(b[1]+b[0]+b[3]+b[2]))
            lower += upper
        for k, (i, q) in enumerate(lower):
            sign = -1 if k >= 26 and k%2 and not (mcs == 0 and dcm) else 1
            points.append(f'{sign*i+(k%3-1)/32:g},{sign*q+(k%5-2)/64:g}')
    return ';'.join(points)


def vectors():
    rows = ['mcs\tdcm\tcommon\tusers\tdamage\tweights\tblocks\tcoded\ttones']
    for row in coded_vectors().splitlines()[1:]:
        mcs, common, users, damage, blocks, coded, _ = row.split('\t')
        mcs = int(mcs)
        if int(users) not in (3, 8, 17): continue
        bps = [1, 2, 2, 4, 4, 6][mcs]
        for dcm in range(2):
            if dcm and mcs not in (0, 1, 3, 4): continue
            count = 52*bps//(1+dcm)
            padding = (-len(coded)) % count
            stream = coded + ('1011001'*((padding+6)//7))[:padding]
            points = modulate(stream, mcs, dcm)
            for weights in (('both', 'lower', 'upper') if dcm else ('both',)):
                rows.append('\t'.join(map(str, [mcs, dcm, common, users, damage, weights, blocks, stream, points])))
    # Every input bit position independently, plus constant symbols. These
    # establish the complete permutation, not just a few likely bit patterns.
    for mcs in range(6):
        for dcm in range(2):
            if dcm and mcs not in (0, 1, 3, 4): continue
            count = 52*[1, 2, 2, 4, 4, 6][mcs]//(1+dcm)
            for index in range(-2, count):
                stream = ('1'*count if index == -2 else
                          ''.join('1' if k==index else '0' for k in range(count)))
                rows.append('\t'.join(map(str, [mcs, dcm, 0, 0, 'symbol', 'both', '-', stream, modulate(stream,mcs,dcm)])))
    return '\n'.join(rows)+'\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true'); args = parser.parse_args()
    path = IQ_FIXTURES / 'he-sig-b-modulation.tsv'
    content = vectors()
    if args.write: path.write_text(content)
    else: assert path.read_text() == content
    print(f'{len(content.splitlines())-1} independent HE SIG-B modulated streams')
