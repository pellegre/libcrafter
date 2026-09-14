"""Independent HE20 MU preamble IQ (802.11ax-2021 27.3.11.7/27.3.22).

No SIG-B or DATA. These fixtures qualify recognition, not frame recovery.
"""
import argparse
import cmath
import hashlib
import itertools
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.signal import encoded
from tools.oracle.engine.backends.wifi.he.mu.signal import put, repair
from tools.oracle.engine.backends.wifi.he.prefix.iq import symbol


def waveform(mcs=0, dcm=False, gi=0, compressed=False, impaired=False, invalid=None):
    bits=[0]*52
    for start,width,value in [(0,1,1), (1,3,mcs), (4,1,int(dcm)), (5,6,37),
            (11,4,13), (18,4,0 if compressed else 15), (22,1,int(compressed)),
            (23,2,gi), (25,1,1), (26,7,95), (33,1,1), (34,3,4),
            (37,1,1), (39,2,3), (41,1,1)]:
        put(bits,start,width,value)
    if invalid=='width': put(bits,15,3,1)
    if invalid=='reserved': bits[33]=0
    if invalid=='mcs': put(bits,1,3,7)
    if invalid=='tail': bits[46]=1
    repair(bits)
    if invalid=='crc': bits[42]^=1
    coded=encoded(bits)
    length={'remainder0':300,'remainder1':301}.get(invalid,302)
    lsig=base.signal('0101' if invalid=='rate' else '1101',length)
    repeated=base.signal('1101',length+(3 if invalid=='repeat' else 0))
    if invalid=='parity': repeated[17]^=1
    samples=[0j]*37+[v*math.sqrt(52/56) for v in base.preamble()]
    samples+=symbol(base.interleave(base.encode(lsig),1),legacy=True)
    samples+=symbol(base.interleave(base.encode(repeated),1),legacy=True)
    samples+=symbol(coded[:52],rotate=invalid=='first-qbpsk')
    samples+=symbol(coded[52:],rotate=invalid=='second-qbpsk')
    if invalid=='erased-second': samples[-80:]=[0j]*80
    if impaired:
        samples=[(v+(0.25j*samples[n-3] if n>=3 else 0))*cmath.exp(1j*(0.7+0.018*n))
                 for n,v in enumerate(samples)]
    assert len(samples)==677
    assert all(max(abs(v.real),abs(v.imag))*200<127 for v in samples)
    return base.quantize(samples,scale=200),''.join(map(str,bits))


def generate(out):
    base.self_check()
    rows=['name\tbits\tlength\tend_sample\tsha256']
    for mcs,dcm,gi,compressed,impaired in itertools.product(range(6),range(2),range(4),range(2),range(2)):
        if dcm and mcs not in (0,1,3,4): continue
        name=f'he-mu-prefix-mcs{mcs}-dcm{dcm}-gi{gi}-comp{compressed}-'+('offset' if impaired else 'clean')
        iq,bits=waveform(mcs,dcm,gi,compressed,impaired)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append(f'{name}\t{bits}\t302\t677\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-mu-prefix-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent MU prefixes')
    rows=['name\treason\tsha256']
    for reason in ['width','reserved','mcs','tail','crc','remainder0','remainder1','rate','repeat',
                   'parity','first-qbpsk','second-qbpsk','erased-second']:
        name=f'he-mu-prefix-invalid-{reason}'
        iq,_=waveform(invalid=reason)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-mu-prefix-invalid-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} invalid MU prefixes')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true'); args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-prefix-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():
                assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else: generate(base.OUT)
