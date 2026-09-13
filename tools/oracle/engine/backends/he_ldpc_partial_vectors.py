"""Independent complete HE aggregates with a damaged LDPC codeword.

The first long MPDU spans the damaged word; the later MPDU is intact.
Codeword zero damage instead tests that untrusted SERVICE cannot be delivered.
"""
import argparse
import hashlib
from pathlib import Path
import tempfile
import zlib
import ofdm_vectors as base
from he_ampdu_iq_vectors import qos
from vht_ampdu_vectors import delimiter
from he_bcc_iq_vectors import waveform as single
from he_stbc_iq_vectors import waveform as stbc


def generate(out):
    body=qos(1)[:-4]+bytes(range(256))+bytes(range(32))
    first=body+zlib.crc32(body).to_bytes(4,'little');second=qos(2)
    wire=bytearray()
    for frame in (first,second):
        wire+=delimiter(len(frame),0)+frame
        wire+=b'\xc7'*(-len(wire)%4)
    rows=['name\tformat\tmode\tdamaged_word\texpected_frame\tsha256']
    for form in ('su','er242','er106'):
        for mode in ('plain','dcm','stbc'):
            for damaged in (0,1):
                er=form!='su';upper=form=='er106'
                if mode=='stbc':
                    iq,*_=stbc(0,2,16,True,3,'changing',period=10,er=er,upper106=upper,
                               damaged_codeword=damaged,aggregate=(wire,[first,second]))
                else:
                    iq,_=single(0,2,16,'changing',payload=wire,ldpc=True,initial_padding=3,
                                midamble_period=10,dcm=mode=='dcm',er=er,upper106=upper,damaged_codeword=damaged)
                name=f'he-ldpc-partial-{form}-{mode}-word{damaged}'
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join([name,form,mode,str(damaged),second.hex() if damaged else '-',hashlib.sha256(iq).hexdigest()]))
    (out/'he-ldpc-partial-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent damaged-codeword IQ cases')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-ldpc-partial-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
