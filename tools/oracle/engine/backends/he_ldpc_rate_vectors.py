"""Independent forward HE20 SU LDPC segments, IEEE802.11ax-2021 27.3.12.5.2.

Rational thresholds and Gaussian parity encoding; no receiver implementation.
Inputs start with initial symbol/segment dimensions, not final header inversion.
"""
import argparse
from fractions import Fraction as F
import hashlib
import json
import math
from pathlib import Path
from ldpc_vectors import FIXTURE, encode
from he_capacity_vectors import BPS, DATA, SHORT

OUT=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq'
RATES=[F(1,2),F(1,2),F(3,4),F(1,2),F(3,4),F(2,3),F(3,4),F(5,6),F(3,4),F(5,6),F(3,4),F(5,6)]


def layout(mcs,nss,dcm,group,initial,padding):
    rate=RATES[mcs]
    coded=234*BPS[mcs]*nss//(1+dcm)
    short_coded=60*BPS[mcs]*nss//(1+dcm)
    data=DATA[mcs]*nss//(1+dcm)
    short_data=SHORT[mcs]*nss//(1+dcm)
    payload=(initial-group)*data+group*(data if padding==4 else padding*short_data)
    available=(initial-group)*coded+group*(coded if padding==4 else padding*short_coded)
    if available<=648:
        count,size=1,1296 if available>=payload+912*(1-rate) else 648
    elif available<=1296:
        count,size=1,1944 if available>=payload+1464*(1-rate) else 1296
    elif available<=1944: count,size=1,1944
    elif available<=2592:
        count,size=2,1944 if available>=payload+2916*(1-rate) else 1296
    else: count,size=math.ceil(payload/(1944*rate)),1944
    short=max(0,int(count*size*rate)-payload)
    puncture=max(0,count*size-available-short)
    parity=count*size*(1-rate)
    extra=((puncture>parity/10 and short<F(6,5)*puncture*rate/(1-rate))
           or puncture>3*parity/10)
    symbols=initial
    if extra:
        available+=group*(coded-3*short_coded if padding==3 else short_coded)
        if padding==4: symbols+=group; padding=1
        else: padding+=1
    puncture=max(0,count*size-available-short)
    repeat=max(0,int(available-parity-payload))
    assert count*size-short-puncture+repeat==available
    assert not (puncture and repeat)
    return [symbols,padding,int(extra),count,size,short,puncture,repeat,payload,available]


def generate():
    rows=['mcs\tnss\tdcm\tgroup\tinitial\tainit\tsymbols\tpadding\textra\twords\tblock\tshort\tpuncture\trepeat\tpayload\tavailable']
    for nss in (1,2,4,8):
        for mcs in range(12):
            for dcm in ([0,1] if nss<=2 and mcs in (0,1,3,4) else [0]):
                for group in ([1,2] if nss==1 and not dcm else [1]):
                    for initial in sorted(set(range(group,65,group))|{n for n in (127,128,129,199,200,399,400) if n%group==0}):
                        for padding in range(1,5):
                            result=layout(mcs,nss,dcm,group,initial,padding)
                            if result[8]<16 or result[0]>400: continue
                            rows.append('\t'.join(map(str,[mcs,nss,dcm,group,initial,padding,*result])))
    return '\n'.join(rows)+'\n'


def encode_information(bits, sizing, mcs):
    _,_,_,count,n,short,punc,repeat,payload,available=sizing
    assert len(bits)==payload
    rate=RATES[mcs]
    matrix=next(c for c in json.loads(FIXTURE.read_text())['codes']
                if c['n']==n and c['rate']==[rate.numerator,rate.denominator])
    z,k=matrix['z'],matrix['k']
    checks=[sum(1<<(col*z+(offset+shift)%z) for col,shift in enumerate(block) if shift>=0)
            for block in matrix['matrix'] for offset in range(z)]
    offset=0;transmitted=''
    for index in range(count):
        s=short//count+(index<short%count)
        p=punc//count+(index<punc%count)
        r=repeat//count+(index<repeat%count)
        data=bits[offset:offset+k-s];offset+=k-s
        word=encode(checks,k,n,sum(int(b)<<i for i,b in enumerate(data)))
        word=word[:k-s]+word[k:n-p]
        transmitted+=word+''.join(word[i%len(word)] for i in range(r))
    assert offset==payload and len(transmitted)==available
    return list(map(int,transmitted))


def codewords():
    matrices={(c['n'],tuple(c['rate'])):c for c in json.loads(FIXTURE.read_text())['codes']}
    rows=['mcs\tsymbols\tpadding\textra\tpayload_bits\ttransmitted_bits']
    for mcs in range(12):
        for initial in (1,4):
            for padding in (1,3,4):
                symbols,pad,extra,count,n,short,punc,repeat,payload,available=layout(mcs,1,0,1,initial,padding)
                rate=RATES[mcs];matrix=matrices[n,(rate.numerator,rate.denominator)]
                z,k=matrix['z'],matrix['k']
                checks=[sum(1<<(col*z+(offset+shift)%z) for col,shift in enumerate(block) if shift>=0)
                        for block in matrix['matrix'] for offset in range(z)]
                raw=hashlib.shake_256(f'he-ldpc-{mcs}-{initial}-{padding}'.encode()).digest((payload+7)//8)
                bits=''.join(str(b>>i&1) for b in raw for i in range(8))[:payload]
                offset=0;transmitted=''
                for index in range(count):
                    s=short//count+(index<short%count)
                    p=punc//count+(index<punc%count)
                    r=repeat//count+(index<repeat%count)
                    data=bits[offset:offset+k-s];offset+=k-s
                    word=encode(checks,k,n,sum(int(b)<<i for i,b in enumerate(data)))
                    word=word[:k-s]+word[k:n-p]
                    transmitted+=word+''.join(word[i%len(word)] for i in range(r))
                assert offset==payload and len(transmitted)==available
                rows.append('\t'.join(map(str,[mcs,symbols,pad,extra,bits,transmitted])))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    for name,content in [('he-ldpc-rate-index.tsv',generate()),('he-ldpc-rate-codewords.tsv',codewords())]:
        if args.check: assert (OUT/name).read_text()==content,name
        else: (OUT/name).write_text(content)
        print(f'{name}: {len(content.splitlines())-1} independent cases')
