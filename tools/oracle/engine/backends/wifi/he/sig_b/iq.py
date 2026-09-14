"""Independent HE20 preamble+SIG-B IQ; no HE training or DATA.

Direct DFT synthesis, independent CRC/BCC/interleaving/constellation models.
Produces cs8 fixtures only; no radio access.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
import tools.oracle.engine.backends.wifi.ht.bcc as ht
from tools.oracle.engine.backends.wifi.he.prefix.iq import symbol
from tools.oracle.engine.backends.wifi.he.signal import encoded
from tools.oracle.engine.backends.wifi.he.mu.signal import put, repair
from tools.oracle.engine.backends.wifi.he.sig_b.common import allocation
from tools.oracle.engine.backends.wifi.he.sig_b.coded import checked, encode
from tools.oracle.engine.backends.wifi.he.sig_b.modulation import modulate


def waveform(mcs,dcm,code,count,impaired=False,damage='none',extra=False):
    compressed=code<0
    if not compressed: count=allocation(code)[2]
    fields=[] if compressed else [checked([code>>i&1 for i in range(8)])]
    values=[37+i | ((i%12)<<15) | ((i%2)<<20) for i in range(count)]
    for start in range(0,count,2):
        fields.append(checked([v>>i&1 for v in values[start:start+2] for i in range(21)]))
    if damage=='common-crc': fields[0][-10]^=1
    if damage=='user-crc': fields[int(not compressed)][-10]^=1
    dbps=[26,52,78,104,156,208][mcs]//(1+dcm)
    nbits=sum(map(len,fields))
    symbols=math.ceil(nbits/dbps)
    if extra: symbols=max(symbols,16)
    padding=[(i%7 in (0,2,3,6))*1 for i in range(symbols*dbps-nbits)]
    pairs=[p for f in fields for p in encode(f)]+encode(padding)
    coded=[]
    for n,(a,b) in enumerate(pairs):
        coded.extend([a,b] if mcs in (0,1,3) else
                     ([a,b],[a],[b])[n%3] if mcs in (2,4) else
                     [a,b] if n%2==0 else [a])
    bps=[1,2,2,4,4,6][mcs]
    assert len(coded)==symbols*52*bps//(1+dcm)
    bits=[0]*52
    for start,width,value in [(1,3,mcs),(4,1,dcm),(5,6,37),(18,4,count-1 if compressed else min(symbols-1,15)),
                              (22,1,int(compressed)),(23,2,1),(26,7,95),(33,1,1),(34,3,4),(37,1,1),(39,2,3)]:
        put(bits,start,width,value)
    if damage=='short-count': put(bits,18,4,0)
    repair(bits)
    siga=encoded(bits)
    lsig=base.signal('1101',302)
    samples=[0j]*37+[v*math.sqrt(52/56) for v in base.preamble()]
    samples+=symbol(base.interleave(base.encode(lsig),1),legacy=True)*2
    samples+=symbol(siga[:52])+symbol(siga[52:])
    points=[complex(*map(float,p.split(','))) for p in modulate(''.join(map(str,coded)),mcs,dcm).split(';')]
    energy=[1,2,2,10,10,42][mcs]
    pilot_bits=base.scramble([0]*(symbols+4),127)
    for n in range(symbols):
        freq=[0j]*57
        for k,v in zip(ht.CARRIERS,points[52*n:52*(n+1)]): freq[k+28]=v/math.sqrt(energy)
        for k,sign in [(-21,1),(-7,1),(7,1),(21,-1)]: freq[k+28]=sign*(1-2*pilot_bits[n+4])
        time=[v*math.sqrt(52/56) for v in ht.ifft(freq)]
        samples+=time[-16:]+time
    if impaired:
        samples=[(v+(0.25j*samples[n-3] if n>=3 else 0))*cmath.exp(1j*(0.7+0.018*n)) for n,v in enumerate(samples)]
    assert all(max(abs(v.real),abs(v.imag))*200<127 for v in samples)
    return base.quantize(samples,scale=200),bits,symbols,count


def generate(out):
    rows=['name\tbits\tcode\tusers\tsymbols\tdamage\tsamples\tsha256']
    cases=[]
    for mcs in range(6):
        for dcm in range(2):
            if dcm and mcs not in (0,1,3,4): continue
            for code,count in [(0,0),(113,0),(191,0),(199,0),(-1,1),(-1,2),(-1,8)]:
                for impaired in range(2): cases.append((mcs,dcm,code,count,impaired,'none',False))
            for damage in ('common-crc','user-crc'):
                cases.append((mcs,dcm,0,0,1,damage,False))
            cases.append((mcs,dcm,199,0,1,'none',True))
    cases.extend([(0,0,0,0,0,'short-count',False),(0,0,-1,9,0,'too-many',False)])
    for mcs,dcm,code,count,impaired,damage,extra in cases:
        name=f'he-sigb-iq-m{mcs}-d{dcm}-a{code}-u{count}-i{impaired}-{damage}-e{int(extra)}'
        iq,bits,symbols,users=waveform(mcs,dcm,code,count,impaired,damage,extra)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,''.join(map(str,bits)),code,users,symbols,damage,len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-sigb-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent HE SIG-B IQ fixtures')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-sigb-iq-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir(): assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else: generate(base.OUT)
