"""Independent exact-rational HT LDPC geometry, IEEE 802.11-2020 19.3.11.7.5."""
import argparse
import hashlib
import json
from fractions import Fraction
import math
from pathlib import Path
from ldpc_vectors import FIXTURE, encode

OUT=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/ldpc-rate-index.tsv'
PARAMETERS=[(52,Fraction(1,2)),(104,Fraction(1,2)),(104,Fraction(3,4)),
            (208,Fraction(1,2)),(208,Fraction(3,4)),(312,Fraction(2,3)),
            (312,Fraction(3,4)),(312,Fraction(5,6))]


def layout(length, coded, rate, group):
    payload=length*8+16
    available=coded*group*math.ceil(Fraction(payload)/(coded*rate*group))
    original=available
    if available<=648:
        count=1
        size=1296 if available>=payload+912*(1-rate) else 648
    elif available<=1296:
        count=1
        size=1944 if available>=payload+1464*(1-rate) else 1296
    elif available<=1944:
        count,size=1,1944
    elif available<=2592:
        count=2
        size=1944 if available>=payload+2916*(1-rate) else 1296
    else:
        count,size=math.ceil(Fraction(payload)/(1944*rate)),1944
    short=max(0,count*size*rate-payload)
    puncture=max(0,count*size-available-short)
    if ((puncture>Fraction(1,10)*count*size*(1-rate)
         and short<Fraction(6,5)*puncture*rate/(1-rate))
        or puncture>Fraction(3,10)*count*size*(1-rate)):
        available+=coded*group
        puncture=max(0,count*size-available-short)
    repeat=max(0,available-count*size*(1-rate)-payload)
    assert not (puncture and repeat)
    assert count*size-short-puncture+repeat==available
    return [int(v) for v in [available//coded,count,size,short,puncture,repeat,available!=original]]


def generate():
    rows=['length\tmcs\tgroup\tcoded\tnumerator\tdenominator\tsymbols\tcodewords\tblock\tshort\tpuncture\trepeat\textra']
    for length in [1,4,15,16,30,50,75,100,200,500,1000,4095,65535]:
        for mcs,(coded,rate) in enumerate(PARAMETERS):
            for group in [1,2]:
                rows.append('\t'.join(map(str,[length,mcs,group,coded,rate.numerator,rate.denominator,*layout(length,coded,rate,group)])))
    return '\n'.join(rows)+'\n'


def encoded_vectors():
    matrices={(c['n'],tuple(c['rate'])):c for c in json.loads(FIXTURE.read_text())['codes']}
    rows=['length\tmcs\tgroup\tpayload_bits\ttransmitted_bits']
    for length in [4,75,500]:
        for mcs,(coded,rate) in enumerate(PARAMETERS):
            for group in [1,2]:
                symbols,count,n,short,puncture,repeat,_=layout(length,coded,rate,group)
                matrix=matrices[n,(rate.numerator,rate.denominator)]
                z,k=matrix['z'],matrix['k']
                checks=[sum(1<<(col*z+(offset+shift)%z) for col,shift in enumerate(block) if shift>=0)
                        for block in matrix['matrix'] for offset in range(z)]
                raw=hashlib.shake_256(f'ht-rate-{length}-{mcs}-{group}'.encode()).digest(length+2)
                payload=''.join(str(byte>>bit&1) for byte in raw for bit in range(8))
                offset=0
                transmitted=''
                for index in range(count):
                    s=short//count+(index<short%count)
                    p=puncture//count+(index<puncture%count)
                    r=repeat//count+(index<repeat%count)
                    info=payload[offset:offset+k-s]
                    assert len(info)==k-s
                    offset+=len(info)
                    word=encode(checks,k,n,sum(int(bit)<<i for i,bit in enumerate(info)))
                    word=word[:k-s]+word[k:n-p]
                    transmitted+=word+''.join(word[i%len(word)] for i in range(r))
                assert offset==len(payload) and len(transmitted)==symbols*coded
                rows.append('\t'.join(map(str,[length,mcs,group,payload,transmitted])))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    text=generate()
    encoded=encoded_vectors()
    encoded_path=OUT.with_name('ldpc-rate-codewords.tsv')
    if args.check:
        assert OUT.read_text()==text
        assert encoded_path.read_text()==encoded
    else:
        OUT.write_text(text)
        encoded_path.write_text(encoded)
    print(f'{len(text.splitlines())-1} independent HT LDPC rate-matching geometries verified')
    print('48 independent shortened/punctured/repeated codeword streams verified')
