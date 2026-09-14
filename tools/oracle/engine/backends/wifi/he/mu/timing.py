"""Forward MU timelines, ax-2021 Eq27-119..122; no receiver inversion.

These test timing arithmetic, not per-RU admission or complete IQ packets.
Durations are exact rational microseconds before conversion to sample indices.
"""
import argparse
from fractions import Fraction as F
import hashlib
from math import ceil
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


def vectors():
    rows=['nltf\tltf\tgi\tperiod\tstbc\tsigb\tsymbols\tpe\tlsig\tb\tmidambles\tstart\tend\tpacket\tsignaled\toffsets_sha256']
    for nltf in [1,2,4,6,8]:
        for size,gi in [(4,800),(2,800),(2,1600),(4,3200)]:
            training=nltf*(F(16,5)*size+F(gi,1000))
            symbol=F(64,5)+F(gi,1000)
            for period in ([0,10,20] if nltf<=4 else [0]):
                for stbc in ([0,1] if nltf>=2 else [0]):
                    for sigb in [1,2,15,16,17,36]:
                        for count in [1,2,9,10,11,12,19,20,21,22,39,40,41,99,100,399,400]:
                            if stbc and count%2: continue
                            clock=36+4*sigb+training
                            start=int(clock*20); offsets=[]; midambles=0
                            for i in range(count):
                                offsets.append(int(clock*20)); clock+=symbol
                                if period and (i+1)%period==0 and count-i-1>=2:
                                    clock+=training;midambles+=1
                            end=int(clock*20)
                            digest=hashlib.sha256(b''.join(n.to_bytes(4,'little') for n in offsets)).hexdigest()
                            for pe in [0,4,8,12,16]:
                                packet=clock+pe
                                units=ceil((packet-20)/4)
                                lsig=3*units-4
                                if lsig>4095: continue
                                b=int(pe+4*units-(packet-20)>=symbol)
                                rows.append('\t'.join(map(str,[nltf,size,gi,period,stbc,sigb,count,pe*20,lsig,b,midambles,start,end,int(packet*20),(20+4*units)*20,digest])))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true');args=parser.parse_args()
    path=IQ_FIXTURES / 'he-mu-timing.tsv'
    content=vectors()
    if args.write:path.write_text(content)
    else:assert path.read_text()==content
    print(f'{len(content.splitlines())-1} independent MU timelines')
