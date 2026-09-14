"""Independent GF(2) LDPC codeword oracle, IEEE 802.11-2020 Annex F.

Matrix prototypes are factual IEEE table inputs, reviewed and transcribed into
the fixture. Parity is solved by full Gaussian elimination, independently of
the Rust graph expansion and min-sum decoder. No production encoder is called.
"""
import argparse
import hashlib
import json
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES

FIXTURE = IQ_FIXTURES / 'ldpc-codewords.json'


def encode(checks, k, n, data):
    equations = [(row >> k) | (((row & data).bit_count()%2) << (n-k)) for row in checks]
    for column in range(n-k):
        pivot = next(row for row in range(column,n-k) if equations[row] >> column & 1)
        equations[column],equations[pivot] = equations[pivot],equations[column]
        for row in range(n-k):
            if row != column and equations[row] >> column & 1:
                equations[row] ^= equations[column]
    parity = sum(((row >> (n-k)) & 1) << j for j,row in enumerate(equations))
    word = data | (parity << k)
    assert all((row & word).bit_count()%2 == 0 for row in checks)
    return ''.join(str(word >> j & 1) for j in range(n))


def generate(fixture):
    entries = fixture['codes']
    assert {(c['n'],tuple(c['rate'])) for c in entries} == {
        (n,r) for n in [648,1296,1944] for r in [(1,2),(2,3),(3,4),(5,6)]}
    assert len(entries)==12
    for entry in entries:
        n,k,z,rate,table = (entry[key] for key in ['n','k','z','rate','matrix'])
        assert z*24==n and k==n*rate[0]//rate[1] and len(table)*z==n-k
        assert all(len(row)==24 and all(-1<=v<z for v in row) for row in table)
        checks = [sum(1 << (column*z+(offset+shift)%z)
                      for column,shift in enumerate(block) if shift>=0)
                  for block in table for offset in range(z)]
        words = []
        for seed in range(3):
            raw = hashlib.shake_256(f'ieee-ht-ldpc-{n}-{tuple(rate)}-{seed}'.encode()).digest((k+7)//8)
            data = int.from_bytes(raw,'little') & ((1<<k)-1)
            words.append(encode(checks,k,n,data))
        entry['codewords']=words
    return fixture


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    original=FIXTURE.read_text()
    generated=generate(json.loads(original))
    rows=['n\tk\tz\tnumerator\tdenominator\tmatrix\tcodewords']
    for c in generated['codes']:
        rows.append('\t'.join(map(str,[c['n'],c['k'],c['z'],*c['rate'],
            ';'.join(','.join(map(str,row)) for row in c['matrix']),';'.join(c['codewords'])])))
    tsv='\n'.join(rows)+'\n'
    if args.check:
        assert generated==json.loads(original)
        assert tsv==FIXTURE.with_suffix('.tsv').read_text()
    else:
        FIXTURE.write_text(json.dumps(generated,separators=(',',':'))+'\n')
        FIXTURE.with_suffix('.tsv').write_text(tsv)
    print('12 IEEE matrices, 36 independent zero-syndrome codewords verified')
