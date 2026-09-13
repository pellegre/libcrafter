"""Isolated HE20 one-stream RU LTFs; ax-2021 Tables27-7, Eq27-5/42/43/58.

Independent inverse DFT and frequency-domain channel, not complete MU packets.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import he_training_vectors as training
import ofdm_vectors as base


def generate(out):
    ranges = {
        26: [(-121,-96),(-95,-70),(-68,-43),(-42,-17),None,(17,42),(43,68),(70,95),(96,121)],
        52: [(-121,-70),(-68,-17),(17,68),(70,121)],
        106: [(-122,-17),(17,122)], 242: [None],
    }
    rows=['name\tru\tindex\tltf\tguard\tgain\tselective\tsamples\tsha256']
    for ru,locations in ranges.items():
        for index,span in enumerate(locations,1):
            tones = list(range(span[0],span[1]+1)) if span else (list(range(-16,-3))+list(range(4,17)) if ru==26 else list(range(-122,-1))+list(range(2,123)))
            assert len(tones)==ru
            for size,guard in ((2,16),(2,32),(4,16),(4,64)):
                for selective in (False,True):
                    for gain in (96,160,224):
                        sequence={2:training.LTF2,4:training.LTF4}[size]
                        freq=[0j]*245
                        for k in tones:
                            channel=1+(.25j*cmath.exp(-2j*math.pi*k*3/256) if selective else 0)
                            freq[k+122]={'-':-1,'+':1,'0':0}[sequence[k+122]]*channel
                        wave=[v*4*math.sqrt(52/(ru*size/4)) for v in training.ifft(freq)][:64*size]
                        samples=wave[-guard:]+wave
                        assert all(max(abs(v.real),abs(v.imag))*gain<127 for v in samples)
                        iq=base.quantize(samples,scale=gain)
                        name=f'he-mu-training-ru{ru}-index{index}-ltf{size}-gi{guard*50}-selective{int(selective)}-gain{gain}'
                        (out/f'{name}.cs8').write_bytes(iq)
                        rows.append('\t'.join(map(str,[name,ru,index,size,guard,gain,int(selective),len(samples),hashlib.sha256(iq).hexdigest()])))
    (out/'he-mu-training-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent MU RU training fields')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-training-') as temporary:
            out=Path(temporary);generate(out)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT)
