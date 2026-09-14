"""Independent simultaneous HE20 TB users on disjoint RUs, ax-2021 27.3.

Each user has its own forward waveform, RU normalization, payload, channel,
phase and residual carrier offset. Sum complex samples before ADC quantization.
27.3.15.3 motivates the +/-350Hz residual-offset cases, not a universal bound
on received signals or proof of sampling-clock/delay-spread qualification.
No Trigger MAC association or MPDU integrity is implied by these synthetic PSDUs.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.mu.data import waveform


def generate(out):
    cases=[]
    for ru,count in ((26,9),(52,4),(106,2)):
        for ldpc in (False,True):
            for mcs in ([0,3,7,9,10,11] if ldpc else [0,3,7,9]):
                for stbc in (False,True):
                    for size,guard in ((2,32),(4,64)):
                        for offset in (False,True):
                            cases.append((ru,count,mcs,ldpc,False,stbc,size,guard,offset,0))
            for mcs in (0,3):
                for size,guard in ((2,32),(4,64)):
                    cases.append((ru,count,mcs,ldpc,True,False,size,guard,True,0))
        for period in (10,20):
            for stbc in (False,True):
                cases.append((ru,count,3,True,False,stbc,4,64,True,period))
    rows=['name\tru\tusers\tmcs\tldpc\tdcm\tstbc\tltf\tguard\tnltf\tperiod\tlength\tpadding\textra\tsymbols\toffset\tpsdus\tsamples\tsha256']
    for number,(ru,count,mcs,ldpc,dcm,stbc,size,guard,offset,period) in enumerate(cases):
        waves=[];payloads=[];reference=None
        nltf=4 if period else 1+int(stbc)
        for user in range(count):
            trace={}
            wave,psdu,symbols=waveform(192,mcs,ldpc,dcm,size,guard,False,nltf,period,
                stbc=stbc,stbc_case='changing' if period else 'selective',tb_ru=(ru,user+1),
                tb_user_number=user,sizing_trace=trace,return_complex=True)
            if reference is None:reference=trace
            assert trace==reference and (not waves or len(wave)==len(waves[0]))
            hz=(-350+700*user/(count-1)) if offset else 0
            phase=.17*user if offset else 0
            gain=1-.35*user/(count-1) if offset else 1
            # Distinct physical channels apply to the entire PPDU, including
            # its common pre-HE portion; HE training estimates them per RU.
            waves.append([(v+(.12j*wave[n-3] if offset and n>=3 else 0))*gain*
                cmath.exp(1j*(phase+2*math.pi*(12000+hz)*n/20_000_000)) for n,v in enumerate(wave)])
            payloads.append(psdu[0])
        mixed=[sum(values) for values in zip(*waves)]
        gain=min(220.,120/max(max(abs(v.real),abs(v.imag)) for v in mixed))
        iq=base.quantize(mixed,scale=gain)
        name=f'he-tb-multi-{number:03d}-ru{ru}-m{mcs}-l{int(ldpc)}-s{int(stbc)}'
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,ru,count,mcs,int(ldpc),int(dcm),int(stbc),size,guard,nltf,period,
            reference['length'],reference['padding']%4,int(reference['extra']),symbols,int(offset),
            ','.join(payloads),len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-tb-multi-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent simultaneous TB IQ waveforms')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-multi-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
