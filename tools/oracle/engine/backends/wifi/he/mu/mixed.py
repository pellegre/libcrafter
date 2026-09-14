"""Mixed-user HE20 MAC waveforms; ax-2021 27.3.12.5.4, equations 81–89.

Independent forward encoding, including shared LDPC extra-segment decisions.
Synthetic qualification only; no captured traffic or receiver-derived bytes.
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
    rows=['name\tcode\tmodes\tpadding\tstbc\tcase\tusers\tframes\tbad_fcs\tsamples\tsha256']
    boundaries=set();forced_peer=False
    for code in (0,15,128):
        users=allocation(code)[2]
        for stbc in (False,True):
            modes=[(m,l,d) for l in (False,True) for m in range(12 if l else 10)
                   for d in ([False,True] if not stbc and m in (0,1,3,4) else [False])]
            # Interleave FEC families so even two-RU packets exercise both.
            bcc=[mode for mode in modes if not mode[1]]
            ldpc=[mode for mode in modes if mode[1]]
            modes=[mode for i in range(len(ldpc)) for mode in (bcc[i%len(bcc)],ldpc[i])]
            for offset in range(0,len(modes),2):
                selected=[modes[(offset+i)%len(modes)] for i in range(users)]
                for padding in (1,2,3,4):
                    payloads=[];frames=[];positions=[]
                    for user in range(users):
                        payload=bytearray()
                        for n in range(2):
                            frame=qos(2*user+n+1)
                            payload+=delimiter(len(frame),int(n==0))+frame
                            payload+=b'\xc7'*(-len(payload)%4)
                            frames.append(frame.hex());positions.append(user)
                        payloads.append(payload)
                    size,guard=[(4,16),(2,16),(2,32),(4,64)][padding-1]
                    sig_mcs,sig_dcm=[(m,d) for m in range(6) for d in ([False,True] if m in (0,1,3,4) else [False])][offset//2%10]
                    trace={}
                    iq,_,_=waveform(code,0,False,False,size,guard,True,2 if stbc else 1,
                        mac_payloads=payloads,user_modes=selected,pre_fec_padding=padding,
                        sig_b_mcs=sig_mcs,sig_b_dcm=sig_dcm,stbc=stbc,stbc_case='ru-mapped',sizing_trace=trace)
                    boundaries.add((padding,trace['extra']))
                    forced_peer |= trace['extra'] and any(l and not need for (_,l,_),need in zip(selected,trace['user_needs']))
                    name=f'he-mu-mixed-a{code}-s{int(stbc)}-o{offset}-p{padding}'
                    (out/f'{name}.cs8').write_bytes(iq)
                    mode_text=','.join(f'{m}:{int(l)}:{int(d)}' for m,l,d in selected)
                    rows.append('\t'.join(map(str,[name,code,mode_text,padding,int(stbc),'clean',
                        ','.join(map(str,positions)),','.join(frames),0,len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    assert boundaries=={(p,e) for p in range(1,5) for e in (False,True)} and forced_peer
    (out/'he-mu-mixed-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent mixed-user HE MU waveforms')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-mixed-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
