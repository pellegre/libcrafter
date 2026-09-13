"""IEEE802.11ax-2021 Figures27-37..40, Table27-36 and Equation27-95.

Axis labels transcribed from reviewed diagrams in increasing coordinate order.
Exact rational distance oracle; no production constellation formula imported.
Tone oracle enumerates a 9-row by 26-column transpose in transmit order.
"""
import argparse
from fractions import Fraction as F
from pathlib import Path

OUT=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq'
LABELS='00000 00001 00011 00010 00110 00111 00101 00100 01100 01101 01111 01110 01010 01011 01001 01000 11000 11001 11011 11010 11110 11111 11101 11100 10100 10101 10111 10110 10010 10011 10001 10000'.split()
AXIS=list(zip(range(-31,32,2),LABELS))


def metrics(value):
    return [(min((value-x)**2 for x,bits in AXIS if bits[b]=='0')
             -min((value-x)**2 for x,bits in AXIS if bits[b]=='1'))/682
            for b in range(5)]


def generate():
    points=[(F(i),F(q),a+b) for i,a in AXIS for q,b in AXIS]
    points += [(F(n,4),F(-n,8),'-') for n in range(-144,145)]
    rows=['i\tq\tbits\t'+'\t'.join(f'm{i}' for i in range(10))]
    for i,q,bits in points:
        rows.append('\t'.join([format(float(i),'.17g'),format(float(q),'.17g'),bits]
                    +[format(float(v),'.17g') for v in metrics(i)+metrics(q)]))
    grid=[list(range(r*26,(r+1)*26)) for r in range(9)]
    transmitted=[grid[r][col] for col in range(26) for r in range(9)]
    tones=['source\tdata_tone']+[f'{source}\t{transmitted.index(source)}' for source in range(234)]
    return {'he-qam-index.tsv':'\n'.join(rows)+'\n','he-ldpc-tones.tsv':'\n'.join(tones)+'\n'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    for name,content in generate().items():
        if args.check: assert (OUT/name).read_text()==content,name
        else: (OUT/name).write_text(content)
        print(f'{name}: {len(content.splitlines())-1} independent cases')
