"""Independent complete HE20 MU STBC aggregates, ax-2021 27.3/26.6.2.

One DATA stream, two STS on each RU, observed by one receive chain.
Synthetic PHY+MAC qualification, not live RF evidence.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import ofdm_vectors as base
from he_mu_data_iq_vectors import waveform
from he_sig_b_common_vectors import allocation
from he_ampdu_iq_vectors import qos
from vht_ampdu_vectors import delimiter


def generate(out):
    rows=['name\tcode\tmcs\tldpc\tltf\tguard\tnltf\tperiod\tcase\tcompressed\tusers\tframes\tbad_fcs\tsamples\tsha256']
    cases=[]
    guards=[(4,16),(2,16),(2,32),(4,64)]
    for code in (0,15,128,192):
        for ldpc in (False,True):
            for mcs in range(12 if ldpc else 10):
                for case in ('flat','selective'):
                    size,guard=guards[mcs%4]
                    cases.append((code,mcs,ldpc,size,guard,2,0,case,code==192 and case=='flat'))
            for case in ('first-null','second-null'):
                for size,guard in guards:cases.append((code,4,ldpc,size,guard,2,0,case,False))
            for period in (10,20):
                for nltf in ((2,) if code==192 else (2,4)):
                    cases.append((code,4,ldpc,4,64,nltf,period,'changing',False))
            for case in ('bad-fcs','service','user-crc'):
                cases.append((code,4,ldpc,2,32,2,0,case,False))
    for code in (0,15,128):
        for ldpc in (False,True):
            for nltf in (4,6,8):
                for size,guard in guards:cases.append((code,11 if ldpc else 4,ldpc,size,guard,nltf,0,'selective',False))
    cases.append((192,11,True,4,64,2,0,'ldpc',False))
    for code in (0,15,128):
        for ldpc in (False,True):
            for nltf in (2,6):cases.append((code,4,ldpc,4,64,nltf,0,'ru-mapped',False))
    for nltf in (4,6,8):cases.append((192,4,True,4,64,nltf,0,'invalid-ltf',False))
    for code,mcs,ldpc,size,guard,nltf,period,case,compressed in cases:
        payloads=[];frames=[];positions=[]
        for user in range(allocation(code)[2]):
            payload=bytearray()
            for n in range(2):
                frame=qos(2*user+n+1)
                bad=case=='bad-fcs' and user==0 and n==0
                if bad:frame=frame[:-1]+bytes([frame[-1]^1])
                payload+=delimiter(len(frame),int(n==0))+frame
                payload+=b'\xc7'*(-len(payload)%4)
                if not bad and not (case=='service' and user==0) and not (case=='user-crc' and user<2) and case!='invalid-ltf':
                    frames.append(frame.hex());positions.append(user)
            payloads.append(payload)
        iq,_,_=waveform(code,mcs,ldpc,False,size,guard,case!='flat',nltf,period,
            damage=case if case in ('service','user-crc','ldpc') else 'none',mac_payloads=payloads,
            compressed=compressed,stbc=True,stbc_case=case)
        name=f'he-mu-stbc-a{code}-m{mcs}-l{int(ldpc)}-ltf{size}-g{guard}-n{nltf}-p{period}-c{int(compressed)}-{case}'
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,code,mcs,int(ldpc),size,guard,nltf,period,case,int(compressed),','.join(map(str,positions)),','.join(frames),int(case=='bad-fcs'),len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    assert len({row.split('\t')[0] for row in rows})==len(rows)
    (out/'he-mu-stbc-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent complete HE MU STBC waveforms')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-stbc-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
