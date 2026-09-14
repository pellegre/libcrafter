"""Independent Basic Trigger plus simultaneous HE20 TB aggregate responses.

IEEE802.11ax-2021 9.3.1.22.1, 26.5.4.2 and 27.3. Each RU has one DATA
stream, its own synthetic transmitter and carrier offset. Common MCS/coding
and RU size are deliberate coverage limits, not arbitrary scheduling support.
"""
import argparse, cmath, hashlib, math, struct, tempfile, zlib
from pathlib import Path
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.tb.exchange.base import legacy
from tools.oracle.engine.backends.wifi.he.mu.data import waveform
from tools.oracle.engine.backends.wifi.he.ampdu.iq import qos
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter


def generate(out):
    rows=['name\tru\tusers\tldpc\tstbc\tra\ttb_start\ttrigger\tframes\tsamples\tsha256']
    for ru,count,start in [(26,9,0),(52,4,37),(106,2,53)]:
        for ldpc,stbc,ra in [(0,0,0),(1,0,0),(1,1,0),(0,0,1)]:
            waves=[]; frames=[]; reference=None
            for user in range(count):
                payload=bytearray()
                for n in [1,2]:
                    body=bytearray(qos(n+2*user)[:-4])
                    body[4:10]=bytes.fromhex('00005e005301')
                    body[10:16]=bytes.fromhex('00005e0053')+bytes([user+2])
                    frame=bytes(body)+struct.pack('<I',zlib.crc32(body))
                    frames.append(frame.hex())
                    payload+=delimiter(len(frame),0)+frame
                    payload+=b'\xc7'*(-len(payload)%4)
                trace={}
                wave,_,_=waveform(192,4,bool(ldpc),False,2,32,nltf=1+stbc,
                    stbc=bool(stbc),stbc_case='selective',tb_ru=(ru,user+1),
                    tb_user_number=user,mac_payloads=[payload],sizing_trace=trace,
                    return_complex=True)
                if reference is None:reference=trace
                assert reference==trace
                wave=wave[37:]
                hz=-350+700*user/(count-1)
                waves.append([(v+(.12j*wave[n-3] if n>=3 else 0))*(1-.35*user/(count-1))*
                    cmath.exp(1j*(.17*user+2*math.pi*hz*n/20_000_000)) for n,v in enumerate(wave)])
            tb=[sum(values) for values in zip(*waves)]
            common=(reference['length']<<4)|(1<<20)|(stbc<<23)|(stbc<<26)|(
                int(reference['extra'])<<27)|((reference['padding']%4)<<34)|(511<<54)
            users=bytearray()
            for user in range(1 if ra else count):
                bits=(0 if ra else user+1)|(2*(start+user)<<12)|(ldpc<<20)|(4<<21)
                if ra:bits|=(count-1)<<26
                users+=bits.to_bytes(5,'little')+b'\x00'
            duration=math.ceil(len(tb)/20)+32
            mac=struct.pack('<HH',0x24,duration)+bytes.fromhex('ffffffffffff00005e005301')+struct.pack('<Q',common)+users+b'\xff\xff'
            trigger=mac+struct.pack('<I',zlib.crc32(mac))
            ap=legacy(trigger)
            tb_start=64+len(ap)+320
            wave=[0j]*64+ap+[0j]*320+tb+[0j]*256
            wave=[v*cmath.exp(1j*(.3+2*math.pi*12000*n/20_000_000)) for n,v in enumerate(wave)]
            gain=min(220.,120/max(max(abs(v.real),abs(v.imag)) for v in wave))
            iq=base.quantize(wave,scale=gain)
            name=f'he-tb-multi-exchange-ru{ru}-l{ldpc}-s{stbc}-ra{ra}'
            (out/f'{name}.cs8').write_bytes(iq)
            rows.append('\t'.join(map(str,[name,ru,count,ldpc,stbc,ra,tb_start,trigger.hex(),','.join(frames),len(iq)//2,hashlib.sha256(iq).hexdigest()])))
    (out/'he-tb-multi-exchange-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent simultaneous Trigger/TB exchanges')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-multi-exchange-') as temporary:
            out=Path(temporary);generate(out)
            for path in out.iterdir():assert path.read_bytes()==(base.OUT/path.name).read_bytes(),path.name
    else:generate(base.OUT)
