"""Compressed one-user HE20 MAC/IQ, ax-2021 27.3.11.8.4/Table27-28.

No Common field: SIG-A carries user count rather than the SIG-B duration.
Independent forward encoding and DFT; no receiver calls or live radio access.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import ofdm_vectors as base
from he_mu_data_iq_vectors import waveform
from he_ampdu_iq_vectors import qos
from vht_ampdu_vectors import delimiter


def generate(out):
    rows=['name\tmcs\tldpc\tdcm\tltf\tguard\tsigb_mcs\tsigb_dcm\tsigb_symbols\tcase\tframes\tsamples\tsha256']
    signaling=[(m,d) for m in range(6) for d in (False,True) if not d or m in (0,1,3,4)]
    modes=[(m,l,d) for l in (False,True) for m in range(12 if l else 10) for d in ([False,True] if m in (0,1,3,4) else [False])]
    cases=[]
    for i,(mcs,ldpc,dcm) in enumerate(modes):
        for j,(size,guard) in enumerate(((4,16),(2,16),(2,32),(4,64))):
            sm,sd=signaling[(i+j)%len(signaling)]
            for case in ('clean','bad-fcs'):cases.append((mcs,ldpc,dcm,size,guard,sm,sd,case))
    for ldpc in (False,True):cases.append((4,ldpc,True,2,32,0,True,'user-crc'))
    for mcs,ldpc,dcm,size,guard,sm,sd,case in cases:
        payload=bytearray();expected=[]
        for n in range(2):
            frame=qos(n+1)
            if case=='bad-fcs' and n==0:frame=frame[:-1]+bytes([frame[-1]^1])
            elif case!='user-crc':expected.append(frame.hex())
            payload+=delimiter(len(frame),int(n==0))+frame
            payload+=b'\xc7'*(-len(payload)%4)
        iq,_,_=waveform(192,mcs,ldpc,dcm,size,guard,case!='clean',damage='user-crc' if case=='user-crc' else 'none',
            mac_payloads=[payload],compressed=True,sig_b_mcs=sm,sig_b_dcm=sd)
        name=f'he-mu-compressed-m{mcs}-l{int(ldpc)}-d{int(dcm)}-t{size}-g{guard}-s{sm}-{int(sd)}-{case}'
        sigb=(31+([26,52,78,104,156,208][sm]//(1+sd))-1)//([26,52,78,104,156,208][sm]//(1+sd))
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,mcs,int(ldpc),int(dcm),size,guard,sm,int(sd),sigb,case,','.join(expected) or '-',len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-mu-compressed-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent compressed HE MU MAC waveforms')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-compressed-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
