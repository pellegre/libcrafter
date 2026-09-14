"""HE20 SIG-B Common oracle, IEEE 802.11ax-2021 Tables 27-24/26.

Literal table templates and binary-prefix expansion, independent of the Rust
half/pair mapping. CRC is polynomial division from the independent HE oracle.
"""
import argparse
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.he.signal import checksum


# A dash preserves the unassigned central 26-tone RU. y/z encode users minus1.
SMALL = [
    '26 26 26 26 26 26 26 26 26', '26 26 26 26 26 26 26 52',
    '26 26 26 26 26 52 26 26', '26 26 26 26 26 52 52',
    '26 26 52 26 26 26 26 26', '26 26 52 26 26 26 52',
    '26 26 52 26 52 26 26', '26 26 52 26 52 52',
    '52 26 26 26 26 26 26 26', '52 26 26 26 26 26 52',
    '52 26 26 26 52 26 26', '52 26 26 26 52 52',
    '52 52 26 26 26 26 26', '52 52 26 26 26 52',
    '52 52 26 52 26 26', '52 52 26 52 52',
]
TABLE = [(f'{code:08b}', layout) for code,layout in enumerate(SMALL)] + [
    ('00010yyy','52 52 - 106y'), ('00011yyy','106y - 52 52'),
    ('00100yyy','26 26 26 26 26 106y'), ('00101yyy','26 26 52 26 106y'),
    ('00110yyy','52 26 26 26 106y'), ('00111yyy','52 52 26 106y'),
    ('01000yyy','106y 26 26 26 26 26'), ('01001yyy','106y 26 26 26 52'),
    ('01010yyy','106y 26 52 26 26'), ('01011yyy','106y 26 52 52'),
    ('0110yyzz','106y - 106z'), ('01110000','52 52 - 52 52'),
    ('01110001','empty'), ('10yyyzzz','106y 26 106z'), ('11000yyy','242y'),
]


def allocation(code):
    binary=f'{code:08b}'
    for pattern, layout in TABLE:
        if not all(p in 'yz' or p==b for p,b in zip(pattern,binary)): continue
        variables={letter:int(''.join(b for p,b in zip(pattern,binary) if p==letter),2)+1
                   for letter in 'yz' if letter in pattern}
        slot=1; rus=[]
        for token in layout.split():
            if token=='empty': size,users=242,0
            elif token=='-': size,users=26,0
            elif token[-1] in 'yz': size,users=int(token[:-1]),variables[token[-1]]
            else: size,users=int(token),1
            rus.append((size,slot,users)); slot+={26:1,52:2,106:4,242:9}[size]
        assert slot==10
        return 'ok',','.join(':'.join(map(str,ru)) for ru in rus),sum(ru[2] for ru in rus)
    return ('wider' if code in (114,115) or 200<=code<=215 else 'reserved'),'-',0


def vectors():
    rows=['code\tbits\tstatus\trus\tusers']
    for code in range(256):
        bits=[code>>i&1 for i in range(8)]
        crc=checksum(bits)
        bits += [crc>>i&1 for i in (3,2,1,0)]+[0]*6
        status,rus,users=allocation(code)
        rows.append('\t'.join([str(code),''.join(map(str,bits)),status,rus,str(users)]))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true'); args=parser.parse_args()
    path=IQ_FIXTURES / 'he-sig-b-common.tsv'
    content=vectors()
    if args.write: path.write_text(content)
    else: assert path.read_text()==content
    print('256 independent HE20 SIG-B common fields')
