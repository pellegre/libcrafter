"""Independent HE20 RU STBC DATA pairs, ax-2021 27.3.12.8-13.

Forward coding-order mapping and Table21-20 STBC, direct inverse DFT.
Known effective channels include cyclic shifts. Not complete packets or RF.
"""
import argparse
import cmath
import math
from pathlib import Path
import random
from he_ru_symbol_vectors import geometry, point
from he_training_vectors import ifft

OUT = Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/he-ru-stbc-symbol.tsv'


def generate():
    rows=['ru\tindex\tbps\tldpc\tcase\tsymbol\tpolarity0\tpolarity1\telapsed\tstride\tcfo\tbits0\tbits1\twave0\twave1']
    rng=random.Random(8117)
    for ru,index,data,pilots in geometry():
        for ldpc in (False,True):
            for bps in ((1,2,4,6,8,10) if ldpc else (1,2,4,6,8)):
                cbps=len(data)*bps
                order=list(range(cbps))
                if not ldpc:
                    cols={26:8,52:16,106:17,242:26}[ru]
                    transpose=[row+col*(cbps//cols) for row in range(cbps//cols) for col in range(cols)]
                    s=max(bps//2,1)
                    order=[s*(i//s)+(i+cbps-cols*i//cbps)%s for i in transpose]
                distance={26:1,52:3,106:6,242:9}[ru]
                permutation=[row+col*distance for row in range(distance) for col in range(len(data)//distance)]
                target=[data[permutation[i//bps] if ldpc else i//bps] for i in order]
                bits=[[rng.randrange(2) for _ in range(cbps)] for _ in range(2)]
                points=[]
                for block in bits:
                    mapped=[0]*cbps
                    for k,j in enumerate(order):mapped[j]=block[k]
                    points.append({data[permutation[k] if ldpc else k]:point(mapped[k*bps:(k+1)*bps]) for k in range(len(data))})
                for case in range(5):
                    symbol=2*((index+bps+case)%8)
                    polarity=[-1 if (index+case+j)%2 else 1 for j in range(2)]
                    elapsed=1137;stride=[272,288,320][(index+case)%3]
                    cfo=.018 if case else 0.
                    erased=data[len(data)//3] if case==4 else None
                    waves=[]
                    for j in range(2):
                        freq=[0j]*245
                        for k in data+pilots:
                            h0=(1+.25j)*cmath.exp(-2j*math.pi*k*3/256) if case else 1
                            h1=(.6-.3j+.2j*cmath.exp(-2j*math.pi*k*5/256)) if case else .4+.3j
                            h1*=cmath.exp(2j*math.pi*k*8/256)
                            if case==2:h0=0
                            if case==3:h1=0
                            if k==erased:h0=h1=0
                            h0/=math.sqrt(2);h1/=math.sqrt(2)
                            if k in pilots:
                                signs={26:[1,-1],52:[1,1,1,-1],106:[1,1,1,-1],242:[1,1,1,-1,-1,1,1,1]}[ru]
                                value=polarity[j]*signs[(symbol+j+pilots.index(k))%len(signs)]
                                value*=h0+h1
                            else:
                                value=h0*points[j][k]+h1*points[1-j][k].conjugate()*(1 if j else -1)
                            freq[k+122]=value*(cmath.exp(1j*(.7+.13*j+(.004+.0003*j)*k)) if case else 1)
                        waves.append([v*cmath.exp(1j*cfo*(elapsed+j*stride+n)) for n,v in enumerate(ifft(freq))])
                    expected=[''.join('-' if k==erased else str(b) for b,k in zip(block,target)) for block in bits]
                    serialized=[','.join(format(x,'.10g') for v in wave for x in (v.real,v.imag)) for wave in waves]
                    rows.append('\t'.join(map(str,[ru,index,bps,int(ldpc),case,symbol,*polarity,elapsed,stride,cfo,*expected,*serialized])))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    content=generate()
    if args.check:assert OUT.read_text()==content
    else:OUT.write_text(content)
    print(f'{len(content.splitlines())-1} independent HE RU STBC DATA pairs')
