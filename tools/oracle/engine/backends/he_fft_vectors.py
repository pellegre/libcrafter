"""HE transform arithmetic oracle: direct O(N^2) double-precision DFT.

No radix-2 factorization, receiver implementation or radio hardware is used.
The period-to-size mapping follows IEEE802.11ax-2021 Table27-12 at20Msps.
"""
import argparse
import cmath
import math
from pathlib import Path


def generate():
    rows = ['case\tsize\tindex\tinput_i\tinput_q\tdft_i\tdft_q']
    for n in (128,256):
        cases = {
            'dc': [complex(0.5,-0.25)]*n,
            'last-impulse': [0j]*(n-1)+[complex(0.75,0.5)],
            'nyquist': [complex((-1)**i) for i in range(n)],
            'complex-ramp': [complex((i%17-8)/16,(i%13-6)/16) for i in range(n)],
            'asymmetric': [complex(((i*i*7+3*i+11)%61-30)/32, ((i*i*11+5*i+7)%53-26)/32) for i in range(n)],
        }
        for name, values in cases.items():
            for k in range(n):
                products = [v*cmath.exp(-2j*math.pi*k*t/n) for t,v in enumerate(values)]
                output = complex(math.fsum(v.real for v in products), math.fsum(v.imag for v in products))
                # Remove roundoff in mathematically zero reference components.
                numbers = [values[k].real,values[k].imag,output.real,output.imag]
                rows.append('\t'.join([name,str(n),str(k)] +
                    [format(0. if abs(v)<1e-10 else v,'.10g') for v in numbers]))
    return '\n'.join(rows)+'\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true')
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/he-transform-index.tsv'
    content = generate()
    if args.write:
        target.write_text(content)
    else:
        assert target.read_text() == content
    print('10 independent DFT cases, 1920 complex input/output pairs')
