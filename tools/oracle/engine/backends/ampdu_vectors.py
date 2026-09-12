"""Independent HT A-MPDU vectors, IEEE 802.11-2020 9.7 and Annex O.2."""
import argparse
from pathlib import Path
import ofdm_vectors as base
from ht_signal_vectors import crc

OUT=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq'


def delimiter(length, flags=0):
    assert 0<=length<=4095 and 0<=flags<=15
    header=((length<<4)|flags).to_bytes(2,'little')
    checksum=sum(bit<<i for i,bit in enumerate(crc(base.bits(header))))
    return header+bytes([checksum,0x4e])


def aggregate(frames):
    result=b''
    offsets=[]
    for i,frame in enumerate(frames):
        offsets.append(len(result)+4)
        result+=delimiter(len(frame))+frame
        if i+1<len(frames): result+=b'\xa5'*((-len(frame))%4)
    return result,offsets


def generate():
    delimiters=['header_hex\tlength\tflags']
    for length in range(4096):
        flags=length%16
        delimiters.append(f'{delimiter(length,flags).hex()}\t{length}\t{flags}')
    first,second=base.frame(0),base.frame(1)
    cases=[]
    for name,frames in [('alignments',[base.frame(i) for i in range(4)]),('duplicate',[first,first])]:
        wire,offsets=aggregate(frames)
        cases.append((name,wire,offsets,frames))
    wire,offsets=aggregate([first,second])
    cases.append(('empty_padding',delimiter(0)*3+wire,[v+12 for v in offsets],[first,second]))
    bad=bytearray(wire); bad[2]^=1
    cases.append(('bad_delimiter_crc',bytes(bad),[offsets[1]],[second]))
    bad=bytearray(wire); bad[3]^=1
    cases.append(('bad_signature',bytes(bad),[offsets[1]],[second]))
    bad=bytearray(wire); bad[4+len(first)-1]^=1
    cases.append(('bad_fcs',bytes(bad),[offsets[1]],[second]))
    inner=delimiter(len(first))+first
    fake=delimiter(len(inner)+4)+inner+b'junk'
    cases.append(('false_long_delimiter',fake,[8],[first]))
    prefix,offsets=aggregate([first])
    cases.append(('truncated_mpdu',prefix+delimiter(120)+b'\x00'*8,offsets,[first]))
    cases.append(('truncated_delimiter',prefix+b'\x00\x00',offsets,[first]))
    rows=['name\tpsdu_hex\tframe_offsets\tmpdu_hex']
    for name,wire,offsets,frames in cases:
        rows.append('\t'.join([name,wire.hex(),','.join(map(str,offsets)),','.join(frame.hex() for frame in frames)]))
    return {'ampdu-delimiters.tsv':'\n'.join(delimiters)+'\n','ampdu-index.tsv':'\n'.join(rows)+'\n'}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    for name,text in generate().items():
        if args.check: assert (OUT/name).read_text()==text
        else: (OUT/name).write_text(text)
    print('4096 independent delimiter CRCs and 9 A-MPDU recovery fixtures verified')
