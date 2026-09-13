"""Independent HE20 Trigger allocation tables, IEEE802.11ax-2021 9.3.1.22.1.

Enumerate every RA range/count/More flag and every pair of HE20 RU supports.
No receiver or shared IQ generator geometry is imported.
"""
import argparse
from pathlib import Path

def vectors():
    groups = [list(range(0,18,2)), list(range(74,82,2)), [106,108], [122]]
    supports = {}
    intervals = [(-121,-96),(-95,-70),(-68,-43),(-42,-17),None,(17,42),(43,68),(70,95),(96,121),
                 (-121,-70),(-68,-17),(17,68),(70,121),(-122,-17),(17,122),None]
    codes = sum(groups, [])
    for code, interval in zip(codes,intervals):
        if interval is not None: supports[code] = set(range(interval[0],interval[1]+1))
        elif code == 8: supports[code] = set(range(-16,-3)) | set(range(4,17))
        else: supports[code] = set(range(-122,-1)) | set(range(2,123))
    rows = ['kind\taid_or_first\tstart_or_second\tcount\tmore\texpected']
    for group in groups:
        for index, start in enumerate(group):
            for aid in [0,2045]:
                for count in range(1,33):
                    for more in [0,1]:
                        expected = ','.join(map(str,group[index:index+count])) if index+count <= len(group) else 'invalid'
                        rows.append(f'ra\t{aid}\t{start}\t{count}\t{more}\t{expected}')
    for a in codes:
        for b in codes:
            rows.append(f'pair\t{a}\t{b}\t0\t0\t{int(bool(supports[a] & supports[b]))}')
    return '\n'.join(rows)+'\n'

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--write',action='store_true')
    args=parser.parse_args()
    path=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/he-tb-schedule.tsv'
    result=vectors()
    if args.write: path.write_text(result)
    else: assert path.read_text()==result
    print(f'{len(result.splitlines())-1} independent TB schedule cases')
