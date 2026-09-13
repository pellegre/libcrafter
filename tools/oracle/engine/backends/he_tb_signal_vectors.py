"""Independent HE TB SIG-A vectors; IEEE802.11ax-2021 Table27-21.

Forward polynomial CRC, BCC and interleaving; no receiver implementation.
"""
import argparse
from pathlib import Path
from he_signal_vectors import encoded
from he_mu_signal_vectors import put, repair


def header(bw, color, reuse, txop, reserved):
    bits=[0]*52
    for start,width,value in [(1,6,color),(23,1,1),(24,2,bw),(26,7,txop),(33,9,reserved)]:
        put(bits,start,width,value)
    for i,value in enumerate(reuse):put(bits,7+4*i,4,value)
    repair(bits)
    return bits


def vectors():
    rows=['bits\tcoded\tbandwidth\tcolor\treuse1\treuse2\treuse3\treuse4\ttxop\treserved']
    for bw in range(4):
        for reserved in range(512):
            color=(reserved*7+bw)%64;txop=(reserved*13+bw)%128
            reuse=[(reserved*(2*j+1)+bw+j)%16 for j in range(4)]
            if bw==0:reuse=[reuse[0]]*4
            if bw==1:reuse=reuse[:2]*2
            bits=header(bw,color,reuse,txop,reserved)
            rows.append('\t'.join([''.join(map(str,bits)),encoded(bits),*map(str,[bw,color,*reuse,txop,reserved])]))
    invalid=['name\tbits\terror\tindex']
    baseline=header(0,37,[7]*4,21,0x1ad)
    cases=[]
    for name,index,value,error in [('format',0,1,'not_tb'),('reserved',23,0,'reserved')]:
        bits=baseline.copy();bits[index]=value;repair(bits)
        cases.append((name,bits,error,index))
    for bw,indices in [(0,(11,15,19)),(1,(15,19))]:
        for index in indices:
            bits=header(bw,37,[7]*4,21,0x1ad);bits[index]^=1;repair(bits)
            cases.append((f'copy-b{bw}-bit{index}',bits,'reuse',index))
    for index in range(52):
        # The transmitted CRC8 nibble misses bits18/40/41. The spatial-copy
        # constraint catches18; Trigger-supplied bits40/41 remain valid here.
        if index in (40,41):continue
        bits=baseline.copy();bits[index]^=1
        cases.append((f'bit-{index}',bits,'reuse' if index==18 else 'crc' if index<46 else 'tail',15 if index==18 else index))
    for name,bits,error,index in cases:
        invalid.append('\t'.join([name,''.join(map(str,bits)),error,str(index)]))
    return {'he-tb-signal-a-index.tsv':'\n'.join(rows)+'\n',
            'he-tb-signal-a-invalid.tsv':'\n'.join(invalid)+'\n'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write',action='store_true');args=parser.parse_args()
    out=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq'
    for name,content in vectors().items():
        if args.write:(out/name).write_text(content)
        else:assert (out/name).read_text()==content,name
        print(f'{name}: {len(content.splitlines())-1} cases')
