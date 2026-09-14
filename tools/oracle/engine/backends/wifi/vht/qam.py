"""Independent 256-QAM metric fixtures from IEEE 802.11-2020 Figures 21-24..27.

The axis label table is transcribed from the visually reviewed diagrams;
no production mapping formula or decoder is imported. Metrics use exact
rational distances in unnormalized coordinates, divided by energy 170.
"""
import argparse
from fractions import Fraction
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

OUT = IQ_FIXTURES / 'vht-qam-index.tsv'
LABELS = '0000 0001 0011 0010 0110 0111 0101 0100 1100 1101 1111 1110 1010 1011 1001 1000'.split()
AXIS = list(zip(range(-15, 16, 2), LABELS))


def metrics(value):
    return [(min((value - x) ** 2 for x, bits in AXIS if bits[b] == '0')
             - min((value - x) ** 2 for x, bits in AXIS if bits[b] == '1')) / 170
            for b in range(4)]


def generate():
    points = [(Fraction(i), Fraction(q), a + b) for i, a in AXIS for q, b in AXIS]
    points += [(Fraction(n, 4), Fraction(-n, 8), '-') for n in range(-72, 73)]
    rows = ['i\tq\tbits\tm0\tm1\tm2\tm3\tm4\tm5\tm6\tm7']
    for i, q, bits in points:
        values = [format(float(x), '.17g') for x in [i, q]]
        values += [bits] + [format(float(x), '.17g') for x in metrics(i) + metrics(q)]
        rows.append('\t'.join(values))
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = generate()
    if args.check:
        assert OUT.read_text() == result, 'VHT QAM inventory differs'
    else:
        OUT.write_text(result)
    print(f'{len(result.splitlines()) - 1} independent VHT QAM cases verified')
