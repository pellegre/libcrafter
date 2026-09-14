"""Independent HE ER SU header IQ, IEEE802.11ax-2021 27.3.11.7.4/22.

Only signaling, no DATA. Originals use the 13-column interleaver; repeats
use raw convolutionally encoded bits. Pilots are not constellation-rotated.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
import tools.oracle.engine.backends.wifi.ht.bcc as ht
import tools.oracle.engine.backends.wifi.he.signal as he


def symbols(bits):
    state=0;coded=[]
    for bit in bits:
        state=(state>>1)|(bit<<6)
        coded.extend((state&mask).bit_count()%2 for mask in (0o133,0o171))
    out=[]
    for start in (0,52):
        original=[0]*52
        for k in range(52):original[4*(k%13)+k//13]=coded[start+k]
        out+=original+coded[start:start+52]
    return out


def header(mcs,bw,gi,mode,ldpc,variant):
    bits=[0]*52
    def put(start,count,value):bits[start:start+count]=[(value>>n)&1 for n in range(count)]
    for i in (0,14,34,40):bits[i]=1
    put(3,4,mcs);put(19,2,bw);put(21,2,gi)
    if mode=='dcm':bits[7]=1
    if mode=='stbc':bits[35]=bits[23]=1
    if mode=='escape':bits[7]=bits[35]=1
    bits[33]=int(ldpc)
    if ldpc:bits[34]=variant%2
    put(8,6,variant%64);put(15,4,variant%16);put(26,7,variant%128)
    put(37,2,variant%4)
    bits[1]=variant%2;bits[2]=(variant//2)%2;bits[36]=(variant//3)%2
    bits[39]=(variant//4)%2
    if variant%3:bits[41]=1;bits[25]=variant%2
    return bits


def ofdm(data,legacy=False,index=0,rotation=1,erase=False):
    freq=[0j]*57
    for k,b in zip(base.CARRIERS if legacy else ht.CARRIERS,data):
        freq[k+28]=0 if erase else (2*b-1)*rotation
    if legacy:
        for k,v in zip([-28,-27,27,28],[-1,-1,-1,1]):freq[k+28]=v*math.sqrt(2)
    polarity=[1,1,1,1,-1,-1][index]
    for k,v in [(-21,1),(-7,1),(7,1),(21,-1)]:freq[k+28]=v*polarity
    time=[v*math.sqrt(52/56) for v in ht.ifft(freq)]
    return time[-16:]+time


def prefix_wave(bits,length):
    """Full unquantized ER prefix, including the corpus's 37 leading samples."""
    coded=symbols(bits)
    legacy=base.interleave(base.encode(base.signal('1101',length)),1)
    wave=[0j]*37+[v*math.sqrt(2*52/56) for v in base.preamble()]
    wave+=ofdm(legacy,legacy=True,index=0)+ofdm(legacy,legacy=True,index=1)
    for n in range(4):
        wave+=ofdm(coded[n*52:(n+1)*52],index=n+2,rotation=1j if n==1 else 1)
    return wave


def waveform(bits,condition,invalid=None):
    bits=bits.copy()
    if invalid=='format':bits[0]=0
    if invalid=='bandwidth':bits[20]=1
    if invalid=='mcs':bits[3:7]=[1,1,0,0]
    if invalid=='upper-mcs':bits[19]=bits[3]=1
    if invalid=='streams':bits[24]=1
    if invalid=='nonstbc-streams':bits[23]=1
    if invalid=='dcm-mcs2':bits[7]=bits[4]=1
    if invalid=='reserved':bits[14]=0
    if invalid=='tail':bits[46]=1
    crc=he.checksum(bits[:42]);bits[42:46]=[(crc>>i)&1 for i in (3,2,1,0)]
    if invalid=='crc':bits[42]^=1
    coded=symbols(bits)
    length={'remainder0':300,'remainder1':301}.get(invalid,302)
    lsig=base.signal('0101' if invalid=='rate' else '1101',length)
    rlsig=base.signal('1101',length+(3 if invalid=='repeat' else 0))
    if invalid=='parity':rlsig[17]^=1

    wave=[0j]*37+[v*math.sqrt(2*52/56) for v in base.preamble()]
    wave+=ofdm(base.interleave(base.encode(lsig),1),legacy=True,index=0)
    wave+=ofdm(base.interleave(base.encode(rlsig),1),legacy=True,index=1)
    for n in range(4):
        rotation=1j if n==1 and invalid!='marker' else 1
        wave+=ofdm(coded[n*52:(n+1)*52],index=n+2,rotation=rotation,
                   erase=(condition=='erase-originals' and n in (0,2)) or (invalid=='erased-marker' and n==1))
    if condition!='clean':
        wave=[(v+(0.3j*wave[n-3] if n>=3 else 0)+((.12-.08j)*wave[n-9] if n>=9 else 0))*cmath.exp(1j*(.7+.018*n))
              for n,v in enumerate(wave)]
    if invalid=='truncated':wave=wave[:-1]
    gain=min(180,math.floor(120/max(max(abs(v.real),abs(v.imag)) for v in wave)))
    return base.quantize(wave,scale=gain),bits,coded,length


def generate(out):
    rows=['name\tbits\tcoded\tlength\tend_sample\tsha256']
    variant=0
    for bw,mcs in [(0,0),(0,1),(0,2),(1,0)]:
        for mode in ('plain','dcm','stbc','escape'):
            if mode=='dcm' and mcs==2:continue
            for gi in ([3] if mode=='escape' else range(4)):
                for ldpc in (False,True):
                    bits=header(mcs,bw,gi,mode,ldpc,variant);variant+=1
                    for condition in ('clean','offset','erase-originals'):
                        name=f'he-er-prefix-bw{bw}-mcs{mcs}-gi{gi}-{mode}-{"ldpc" if ldpc else "bcc"}-{condition}'
                        iq,data,coded,length=waveform(bits,condition)
                        (out/f'{name}.cs8').write_bytes(iq)
                        rows.append('\t'.join(map(str,[name,''.join(map(str,data)),''.join(map(str,coded)),length,837,hashlib.sha256(iq).hexdigest()])))
    invalid=['name\treason\tsha256']
    for reason in ('format','bandwidth','mcs','upper-mcs','streams','nonstbc-streams','dcm-mcs2','reserved',
                   'tail','crc','remainder0','remainder1','rate','repeat','parity','marker','erased-marker','truncated'):
        name=f'he-er-prefix-invalid-{reason}'
        iq,*_=waveform(header(0,0,0,'plain',False,0),'clean',reason)
        (out/f'{name}.cs8').write_bytes(iq)
        invalid.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-er-prefix-index.tsv').write_text('\n'.join(rows)+'\n')
    (out/'he-er-prefix-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print(f'{len(rows)-1} HE ER SU prefixes; {len(invalid)-1} invalid cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-er-prefix-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
