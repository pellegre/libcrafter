"""Independent forward VHT timing, IEEE 802.11-2020 21.4.3.

Uses exact rational microseconds and ceiling TXTIME, not the receiver's
inverse formula. No production decoder or device imports.
"""
import argparse
from fractions import Fraction
from math import ceil
from pathlib import Path

OUT = Path(__file__).resolve().parents[4] / 'crafter/tests/fixtures/iq/vht-timing-index.tsv'


def generate():
    rows = ['nsts\tshort_gi\tstbc\tsymbols\tlsig_length\tdisambiguation\tltf_symbols\tdata_start\tdata_end\tsignaled_end']
    counts = list(range(41)) + [49,50,59,60,99,100,109,110,511,512,1023,1360,1361,1362,1503,1504,1505,1511,1512,1513]
    for nsts, ltf in enumerate([1,2,4,4,6,6,8,8], 1):
        for short in [0,1]:
            for stbc in ([0,1] if nsts % 2 == 0 else [0]):
                for symbols in counts:
                    if stbc and symbols % 2:
                        continue
                    preamble = 36 + 4 * ltf
                    data_us = symbols * (Fraction(18,5) if short else Fraction(4))
                    txtime = preamble + 4 * ceil(data_us / 4)
                    length = 3 * ceil(Fraction(txtime - 20,4)) - 3
                    if length > 4095:
                        continue
                    disambiguation = int(short and symbols % 10 == 9)
                    values = [nsts,short,stbc,symbols,length,disambiguation,ltf,
                              20*preamble,int(20*(preamble+data_us)),20*txtime]
                    rows.append('\t'.join(map(str,values)))
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    result = generate()
    if args.check:
        assert OUT.read_text() == result, 'VHT timing inventory differs'
    else:
        OUT.write_text(result)
    print(f'{len(result.splitlines())-1} independent VHT timing vectors verified')
