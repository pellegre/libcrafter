"""Independent ER upper106 LTF fields, IEEE802.11ax-2021 27.3.11.10.

Isolated training fields, not complete PPDUs or MAC qualification.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import tools.oracle.engine.backends.wifi.he.training as training
import tools.oracle.engine.backends.wifi.ofdm.base as base


def generate(out):
    rows=['name\tltf\tguard\tstbc\tgain\tselective\tsamples\tsha256']
    for size,guard in ((1,16),(2,16),(2,32),(4,16),(4,64)):
        for stbc in (False,True):
            if stbc and (size,guard)==(4,16):continue
            for selective in (False,True):
                for gain in (96,160,224):
                    sequence={1:training.LTF1,2:training.LTF2,4:training.LTF4}[size]
                    samples=[]
                    for field in range(1+stbc):
                        freq=[0j]*245
                        for k in range(17,123):
                            sign={'-':-1,'+':1,'0':0}[sequence[k+122]]
                            h1=1+(.25j*cmath.exp(-2j*math.pi*k*3/256) if selective else 0)
                            h2=(.55+.35j)*cmath.exp(2j*math.pi*k*8/256)
                            value=h1+(h2 if stbc else 0)
                            if field:value=-h1+(-h2 if k in (22,48,90,116) else h2)
                            freq[k+122]=sign*value
                        norm=106*size/4  # Eq27-5, not populated tone count.
                        wave=[v*4*math.sqrt(52/norm)*math.sqrt(2/(1+stbc)) for v in training.ifft(freq)][:64*size]
                        samples+=wave[-guard:]+wave
                    assert all(max(abs(v.real),abs(v.imag))*gain<127 for v in samples)
                    iq=base.quantize(samples,scale=gain)
                    name=f'he-er106-training-ltf{size}-gi{guard*50}-stbc{int(stbc)}-selective{int(selective)}-gain{gain}'
                    (out/f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str,[name,size,guard,int(stbc),gain,int(selective),len(samples),hashlib.sha256(iq).hexdigest()])))
    (out/'he-er106-training-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent upper106 training fields')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-er-training-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
