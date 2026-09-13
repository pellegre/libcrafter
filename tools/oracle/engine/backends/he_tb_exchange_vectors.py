"""Independent legacy OFDM Trigger followed by HE20 TB MPDUs.

IEEE802.11ax-2021 9.3.1.22, 26.5.2, 27.3.15.3. All addresses/payloads
are synthetic. This does not establish live interoperability.
"""
import argparse, cmath, hashlib, math, struct, tempfile, zlib
from pathlib import Path
import ofdm_vectors as base
from he_mu_data_iq_vectors import waveform
from he_ampdu_iq_vectors import qos
from vht_ampdu_vectors import delimiter

def legacy(psdu):
    count=math.ceil((16+8*len(psdu)+6)/24)
    data=base.scramble([0]*16+base.bits(psdu)+[0]*(count*24-16-8*len(psdu)),93)
    data[16+8*len(psdu):22+8*len(psdu)]=[0]*6
    coded=base.encode(data)
    pilots=[1-2*v for v in base.scramble([0]*(count+1),127)]
    result=base.preamble()+base.symbol(base.interleave(base.encode(base.signal('1101',len(psdu))),1),1,pilots[0])
    for n in range(count):result+=base.symbol(base.interleave(coded[n*48:(n+1)*48],1),1,pilots[n+1])
    return [4*v for v in result]

def generate(out, cases=None):
    if cases is None:
        cases=[(ru,mcs,ldpc,stbc,size,guard,'clean') for ru in [26,242]
        for mcs,ldpc in [(0,0),(4,0),(9,0),(0,1),(4,1),(9,1),(11,1)]
        for stbc in [0,1] for size,guard in [(2,32),(4,64)]]
        cases += [(26,4,0,0,2,32,case) for case in ['bad-trigger','wrong-context','expired','bad-fcs','no-trigger']]
        cases += [(26,4,0,0,2,32,case) for case in ['zero-duration','reserved-duration']]
    rows=['name\tcase\tru\tmcs\tldpc\tstbc\ttrigger_end\ttb_start\ttrigger\tframes\tsamples\tsha256']
    for number,(ru,mcs,ldpc,stbc,size,guard,case) in enumerate(cases):
        payload=bytearray(); expected=[]
        for n in [1,2]:
            body=bytearray(qos(n)[:-4]);body[4:10]=bytes.fromhex('00005e005301')
            frame=bytes(body)+struct.pack('<I',zlib.crc32(body))
            if case=='bad-fcs' and n==1:frame=frame[:-1]+bytes([frame[-1]^1])
            else:expected.append(frame.hex())
            payload+=delimiter(len(frame),0)+frame
            payload+=b'\xc7'*(-len(payload)%4)
        trace={}; nltf=1+stbc
        tb,_,_=waveform(192,mcs,bool(ldpc),False,size,guard,nltf=nltf,stbc=bool(stbc),
            tb_ru=(ru,1),mac_payloads=[payload],sizing_trace=trace,return_complex=True)
        tb=tb[37:]
        common=(trace['length']<<4)|((1 if size==2 else 2)<<20)|((nltf-1)<<23)|(stbc<<26)|(int(trace['extra'])<<27)|((trace['padding']%4)<<34)|(511<<54)
        if case=='wrong-context':common^=1<<54
        raw_ru=0 if ru==26 else 122
        user=1|(raw_ru<<12)|(ldpc<<20)|(mcs<<21)
        duration=math.ceil(len(tb)/20)+32
        if case=='zero-duration':duration=0
        if case=='reserved-duration':duration=32768
        mac=struct.pack('<HH',0x24,duration)+bytes.fromhex('ffffffffffff00005e005301')+struct.pack('<Q',common)+user.to_bytes(5,'little')+b'\x00\xff\xff'
        trigger=mac+struct.pack('<I',zlib.crc32(mac))
        if case=='bad-trigger':trigger=trigger[:-1]+bytes([trigger[-1]^1])
        ap=legacy(trigger); trigger_end=64+len(ap)
        wait=320 if case!='expired' else (duration+100)*20
        wave=[0j]*64+(ap if case!='no-trigger' else [0j]*len(ap))+[0j]*wait+tb+[0j]*256
        tb_start=trigger_end+wait
        wave=[v*cmath.exp(1j*(.3+2*math.pi*12000*n/20_000_000)) for n,v in enumerate(wave)]
        gain=min(220,120/max(max(abs(v.real),abs(v.imag)) for v in wave))
        iq=base.quantize(wave,scale=gain)
        if case in ['bad-trigger','wrong-context','expired','no-trigger','zero-duration','reserved-duration']:expected=[]
        name=f'he-tb-exchange-{number:03d}-{case}'
        (out/f'{name}.cs8').write_bytes(iq)
        rows.append('\t'.join(map(str,[name,case,ru,mcs,ldpc,stbc,trigger_end,tb_start,
            trigger.hex() if case not in ['bad-trigger','no-trigger'] else '-',','.join(expected) or '-',len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-tb-exchange-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(cases)} independent Trigger/TB exchanges')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--check',action='store_true');args=p.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-exchange-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
