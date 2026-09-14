"""Independent HT NSS1/NSTS2 pairs; IEEE802.11-2020 Tables19-18 and Eq19-27."""
import argparse
import math
import random
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

OUT = IQ_FIXTURES / 'stbc-pairs.tsv'


def generate():
    rng = random.Random(0x1918)
    rows = ['name\th1_i\th1_q\th2_i\th2_q\ty0_i\ty0_q\ty1_i\ty1_q\ta_i\ta_q\tb_i\tb_q\tltf1_i\tltf1_q\tltf2_i\tltf2_q']
    alphabets = [('bpsk', [-1+0j, 1+0j])]
    for name, axes in [('qpsk', [-1,1]), ('qam16', [-3,-1,1,3]),
                       ('qam64', [-7,-5,-3,-1,1,3,5,7])]:
        scale = math.sqrt(2*sum(v*v for v in axes)/len(axes))
        alphabets.append((name, [complex(i,q)/scale for i in axes for q in axes]))
    channels = [(1+0j,0j), (0j,1+0j), (1+0j,1+0j), (1+0j,-1+0j),
                (1+2j,-2+1j), (0.001j,0.002+0j)]
    for name, points in alphabets:
        for channel, (h1,h2) in enumerate(channels):
            for pair in range(100):
                a,b = rng.choice(points),rng.choice(points)
                # Forward rules only; no production or oracle receiver inverse.
                y0,y1 = h1*a-h2*b.conjugate(),h1*b+h2*a.conjugate()
                ltf1,ltf2 = h1+h2,-h1+h2
                values = [h1,h2,y0,y1,a,b,ltf1,ltf2]
                rows.append('\t'.join([f'{name}-{channel}-{pair}']+
                                       [format(v,'.17g') for z in values for v in [z.real,z.imag]]))
    return '\n'.join(rows)+'\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    data = generate()
    if args.check:
        assert OUT.read_text() == data, OUT
    else:
        OUT.write_text(data)
    print('2400 independent HT STBC constellation/training pairs verified')
