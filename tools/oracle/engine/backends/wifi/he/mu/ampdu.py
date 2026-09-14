"""Independent MU PHY + FCS-qualified MAC fixtures; ax-2021 27.3/26.6.2.

Bad MAC checksums are encoded intact by FEC, not simulated by IQ damage.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.mu.data import waveform
from tools.oracle.engine.backends.wifi.he.sig_b.common import allocation
from tools.oracle.engine.backends.wifi.he.ampdu.iq import qos
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter


def generate(out):
    rows=['name\tcode\tmcs\tldpc\tdcm\tcase\tusers\tframes\tbad_fcs\tsamples\tsha256']
    cases=[]
    for code in (0,15,128,192):
        for ldpc in (False,True):
            for mcs in ([0,4,9,11] if ldpc else [0,4,9]):
                for dcm in ([False,True] if mcs in (0,4) else [False]):
                    for case in ('clean','bad-fcs'):cases.append((code,mcs,ldpc,dcm,case))
    for ldpc in (False,True):
        for case in ('service','user-crc'):cases.append((0,4,ldpc,True,case))
    cases += [(192,11,True,False,'ldpc'),(0,4,True,False,'identical')]
    for code,mcs,ldpc,dcm,case in cases:
        payloads=[];expected=[];positions=[]
        for user in range(allocation(code)[2]):
            payload=bytearray()
            for n in range(2):
                frame=qos(n+1 if case=='identical' else 2*user+n+1)
                bad=case=='bad-fcs' and user==0 and n==0
                if bad:frame=frame[:-1]+bytes([frame[-1]^1])
                payload+=delimiter(len(frame),int(n==0))+frame
                payload+=b'\xc7'*(-len(payload)%4)
                if not bad and not (case=='service' and user==0) and not (case=='user-crc' and user<2):
                    expected.append(frame.hex());positions.append(user)
            payloads.append(payload)
        size,guard=(2,32) if dcm else (4,64)
        iq,_,_=waveform(code,mcs,ldpc,dcm,size,guard,True,damage=case if case in ('service','user-crc','ldpc') else 'none',mac_payloads=payloads)
        name=f'he-mu-ampdu-a{code}-m{mcs}-l{int(ldpc)}-d{int(dcm)}-{case}'
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,code,mcs,int(ldpc),int(dcm),case,','.join(map(str,positions)),','.join(expected),int(case=='bad-fcs'),len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-mu-ampdu-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent MU MAC aggregate IQ waveforms')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-ampdu-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
