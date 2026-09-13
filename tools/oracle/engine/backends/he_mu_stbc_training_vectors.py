"""Independent HE20 MU STBC LTF fields, not complete packets or RF evidence.

IEEE802.11ax-2021 Eq27-55..58; base Eq19-27/21-44/45.
Two physical channels, STS2 cyclic shift, R pilots, direct inverse DFT.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import he_training_vectors as training
from he_ru_symbol_vectors import geometry
import ofdm_vectors as base


def generate(out,long_delay=False):
    prefix='he-mu-stbc-training-long' if long_delay else 'he-mu-stbc-training'
    rows = ['name\tru\tindex\tltf\tguard\tcount\tbranch\tgain\tsamples\tsha256']
    for ru, index, data, pilots in geometry():
        for size, guard in ((2,16),(2,32),(4,16),(4,64)):
            for count in ((2,) if long_delay else (2,4,6,8)):
                for branch in (0,1,2):
                    samples = []
                    sequence = {2:training.LTF2,4:training.LTF4}[size]
                    for j in range(count):
                        p0 = ([1,-1,1,1,1,-1][j] if count==6 else [1,-1,1,1][j%4])
                        p1 = p0*cmath.exp(-2j*math.pi*j/6) if count==6 else [1,1,-1,1][j%4]
                        freq = [0j]*245
                        for k in data+pilots:
                            h0 = 0 if branch==1 else (1+.25j)*cmath.exp(-2j*math.pi*k*((guard-3) if long_delay else 3)/256)
                            h1 = 0 if branch==2 else ((.6-.3j)*cmath.exp(-2j*math.pi*k*((guard-6) if long_delay else 0)/256)+.2j*cmath.exp(-2j*math.pi*k*((guard-2) if long_delay else 5)/256))*cmath.exp(2j*math.pi*k*8/256)
                            h = (p0*h0+(p0 if k in pilots else p1)*h1)/math.sqrt(2)
                            freq[k+122] = {'+':1,'-':-1,'0':0}[sequence[k+122]]*h
                        wave = [v*4*math.sqrt(52/(ru*size/4)) for v in training.ifft(freq)][:64*size]
                        block = wave[-guard:]+wave
                        start = len(samples)
                        samples.extend(v*cmath.exp(1j*(.7+.08*j+.018*(start+n))) for n,v in enumerate(block))
                    gain = min(200.,120/max(max(abs(v.real),abs(v.imag)) for v in samples))
                    iq = base.quantize(samples,scale=gain)
                    name = f'{prefix}-ru{ru}-index{index}-ltf{size}-gi{guard*50}-n{count}-branch{branch}'
                    (out/f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str,[name,ru,index,size,guard,count,branch,format(gain,'.12g'),len(samples),hashlib.sha256(iq).hexdigest()])))
    (out/f'{prefix}-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent MU STBC training fields')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--long-delay',action='store_true');args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-mu-stbc-training-') as temporary:
            out=Path(temporary);generate(out,args.long_delay)
            for file in out.iterdir():assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:generate(base.OUT,args.long_delay)
