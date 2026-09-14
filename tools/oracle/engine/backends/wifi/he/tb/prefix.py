"""Independent HE20 TB prefixes, IEEE802.11ax-2021 27.3.11/22.

No HE training or DATA, no inferred Trigger parameters. Uniform attenuation
exercises receiver gain tolerance, not multi-transmitter power qualification.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.signal import encoded
from tools.oracle.engine.backends.wifi.he.mu.signal import repair
from tools.oracle.engine.backends.wifi.he.tb.signal import header
from tools.oracle.engine.backends.wifi.he.prefix.iq import symbol


def waveform(value=0, attenuated=False, impaired=False, invalid=None):
    bits=header(1 if invalid=='width' else 0,value%64,[value%16]*4,
                value%128,(value*73)%512)
    if invalid=='format':bits[0]=1
    if invalid=='reserved':bits[23]=0
    if invalid=='reuse':bits[11]^=1
    if invalid=='tail':bits[46]=1
    repair(bits)
    if invalid=='crc':bits[42]^=1
    coded=encoded(bits)
    length={'remainder0':300,'remainder2':302}.get(invalid,301)
    lsig=base.signal('0101' if invalid=='rate' else '1101',length)
    repeated=base.signal('1101',length+(3 if invalid=='repeat' else 0))
    if invalid=='parity':repeated[17]^=1
    samples=[0j]*37+[v*math.sqrt(52/56) for v in base.preamble()]
    samples+=symbol(base.interleave(base.encode(lsig),1),legacy=True)
    samples+=symbol(base.interleave(base.encode(repeated),1),legacy=True)
    samples+=symbol(coded[:52],rotate=invalid=='first-qbpsk')
    samples+=symbol(coded[52:],rotate=invalid=='second-qbpsk')
    if invalid=='erased-second':samples[-80:]=[0j]*80
    if attenuated:samples=[v/math.sqrt(2) for v in samples]
    if impaired:
        samples=[(v+(0.25j*samples[n-3] if n>=3 else 0))*cmath.exp(1j*(0.7+0.018*n))
                 for n,v in enumerate(samples)]
    assert len(samples)==677
    assert all(max(abs(v.real),abs(v.imag))*160<127 for v in samples)
    return base.quantize(samples,scale=160),''.join(map(str,bits))


def generate(out):
    base.self_check()
    rows=['name\tbits\tlength\tend_sample\tsha256']
    for value in range(64):
        for attenuation in range(2):
            for impaired in range(2):
                name=f'he-tb-prefix-v{value}-a{attenuation}-'+('offset' if impaired else 'clean')
                iq,bits=waveform(value,attenuation,impaired)
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append(f'{name}\t{bits}\t301\t677\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-tb-prefix-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent TB prefixes')
    rows=['name\treason\tsha256']
    for reason in ['width','format','reserved','reuse','tail','crc','remainder0','remainder2',
                   'rate','repeat','parity','first-qbpsk','second-qbpsk','erased-second']:
        name=f'he-tb-prefix-invalid-{reason}'
        iq,_=waveform(invalid=reason)
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'he-tb-prefix-invalid-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} invalid TB prefixes')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-prefix-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():
                assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
