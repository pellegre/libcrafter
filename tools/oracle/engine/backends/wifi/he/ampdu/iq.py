"""Independent HE BCC complete PHY+MAC vectors, IEEE802.11ax-2021 27.3/26.6.2.

No production receiver or encoder is used. Reuses the independent HE waveform
and normative shared VHT delimiter encoding. Bad checksums are injected before
PHY encoding, so FEC must recover them exactly before MAC rejects them.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import zlib
import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.he.bcc.iq import waveform
from tools.oracle.engine.backends.wifi.vht.ampdu.frame import delimiter, frame


def qos(sequence):
    body=bytearray(frame(36)[:-4])
    body[0]=0x88
    body[22:24]=(sequence<<4).to_bytes(2,'little')
    body[24:24]=b'\x00\x00'
    return bytes(body)+zlib.crc32(body).to_bytes(4,'little')


def generate(out):
    base.self_check()
    rows=['name\tmcs\tltf\tguard\tpsdu\toffsets\tframes\ttags\tbad_fcs\tsha256']
    for mcs in range(10):
        for size,guard in ((1,16),(2,16),(2,32),(4,16),(4,64)):
            for case in ('single','multi','tagged','bad-fcs'):
                frames=[qos(1)] if case=='single' else [qos(1),qos(2)]
                tags=[1] if case=='single' else ([1,0] if case=='tagged' else [0,0])
                payload=bytearray();offsets=[];expected=[];expected_tags=[]
                for i,(mpdu,tag) in enumerate(zip(frames,tags)):
                    payload+=b'\xc7'*(-len(payload)%4)
                    offset=len(payload)+4
                    wire=mpdu
                    if case=='bad-fcs' and i==0:
                        wire=mpdu[:-1]+bytes([mpdu[-1]^1])
                    else:
                        offsets.append(offset);expected.append(mpdu);expected_tags.append(tag)
                    payload+=delimiter(len(wire),tag)+wire
                payload+=b'\xc7'*(-len(payload)%4)
                iq,fields=waveform(mcs,size,guard,'selective' if case=='single' else 'offset',payload=payload)
                name=f'he-ampdu-iq-mcs{mcs}-ltf{size}-gi{guard*50}-{case}'
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join(map(str,[name,mcs,size,guard,fields[5],
                    ','.join(map(str,offsets)),','.join(v.hex() for v in expected),
                    ','.join(map(str,expected_tags)),int(case=='bad-fcs'),hashlib.sha256(iq).hexdigest()])))
    (out/'he-ampdu-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    print('200 independent complete HE BCC aggregate IQ cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-ampdu-iq-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():
                assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
