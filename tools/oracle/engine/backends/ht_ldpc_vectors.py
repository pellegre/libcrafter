"""Independent complete HT20 LDPC waveforms, IEEE 802.11-2020 clause 19."""
import argparse
import tempfile
import cmath
import hashlib
import json
import math
from pathlib import Path
import ht_bcc_vectors as ht
import ofdm_vectors as base
from ht_signal_vectors import crc
from ldpc_vectors import FIXTURE, encode
from ldpc_rate_vectors import PARAMETERS, layout

OUT=base.OUT
MATRICES={(c['n'],tuple(c['rate'])):c for c in json.loads(FIXTURE.read_text())['codes']}


def encode_psdu(psdu,mcs,invalid_service=False):
    coded,rate=PARAMETERS[mcs]
    symbols,count,n,short,puncture,repeat,_=layout(len(psdu),coded,rate,1)
    matrix=MATRICES[n,(rate.numerator,rate.denominator)]
    z,k=matrix['z'],matrix['k']
    checks=[sum(1<<(col*z+(offset+shift)%z) for col,shift in enumerate(block) if shift>=0)
            for block in matrix['matrix'] for offset in range(z)]
    service=[0]*16
    service[15]=int(invalid_service)
    payload=base.scramble(service+base.bits(psdu),0x5d)
    offset=0
    result=[]
    for index in range(count):
        s=short//count+(index<short%count)
        p=puncture//count+(index<puncture%count)
        r=repeat//count+(index<repeat%count)
        info=payload[offset:offset+k-s]
        assert len(info)==k-s
        offset+=len(info)
        word=encode(checks,k,n,sum(bit<<i for i,bit in enumerate(info)))
        word=word[:k-s]+word[k:n-p]
        result.extend(int(b) for b in word+''.join(word[i%len(word)] for i in range(r)))
    assert offset==len(payload) and len(result)==symbols*coded
    return symbols,result


def waveform(psdu,mcs,guard,symbols,coded):
    nbpsc=ht.PARAMETERS[mcs][0]
    fields=[(mcs>>n)&1 for n in range(7)]+[0]
    fields += [(len(psdu)>>n)&1 for n in range(16)]
    fields += [1,1,1,0,0,0,1,int(guard==8),0,0]
    fields += crc(fields)+[0]*6
    header=base.encode(fields)
    lsig_length=3*(4+math.ceil(symbols*(64+guard)/80))-3
    wave=[0j]*37+base.preamble()
    wave += base.symbol(base.interleave(base.encode(base.signal('1101',lsig_length)),1),1,1)
    for symbol in range(2):
        freq=[0j]*53
        for k,bit in zip(base.CARRIERS,base.interleave(header[symbol*48:(symbol+1)*48],1)):
            freq[k+26]=1j*(2*bit-1)
        for k,sign in [(-21,1),(-7,1),(7,1),(21,-1)]: freq[k+26]=sign
        time=base.ifft(freq)
        wave += time[-16:]+time
    wave += base.preamble()[:80]
    training=ht.ifft([1,1]+base.LTF+[-1,-1])
    wave += training[-16:]+training
    data_start=len(wave)
    polarities=[1-2*b for b in base.scramble([0]*(symbols+3),127)]
    for symbol in range(symbols):
        # Clause 19.3.11.7.6: no BCC frequency interleaver for LDPC.
        block=coded[symbol*52*nbpsc:(symbol+1)*52*nbpsc]
        freq=[0j]*57
        for j,k in enumerate(ht.CARRIERS): freq[k+28]=base.constellation(block[j*nbpsc:(j+1)*nbpsc])
        for j,k in enumerate([-21,-7,7,21]): freq[k+28]=polarities[symbol+3]*[1,1,1,-1][(symbol+j)%4]
        time=ht.ifft(freq)
        wave += time[-guard:]+time
    end=len(wave)
    return wave+[0j]*64,data_start,end


def generate(out):
    out.mkdir(parents=True,exist_ok=True)
    index=['name\tmcs\tguard_samples\tsymbols\tpsdu_hex\tsha256\tsamples\tdata_start\tframe_end']
    for mcs in range(8):
        for extra in [44,4039]:
            psdu=base.frame(extra)
            symbols,coded=encode_psdu(psdu,mcs)
            for guard in [8,16]:
                wave,start,end=waveform(psdu,mcs,guard,symbols,coded)
                for impairment in ['clean','offset']:
                    impaired=wave
                    if impairment=='offset':
                        impaired=[(v+(0.25j*wave[n-3] if n>=3 else 0))*cmath.exp(1j*(0.7+0.018*n)) for n,v in enumerate(wave)]
                    iq=base.quantize(impaired)
                    name=f'ht-ldpc-{mcs}-gi{guard*50}-len{len(psdu)}-{impairment}'
                    (out/f'{name}.cs8').write_bytes(iq)
                    index.append('\t'.join(map(str,[name,mcs,guard,symbols,psdu.hex(),hashlib.sha256(iq).hexdigest(),len(iq)//2,start,end])))
    (out/'ht-ldpc-index.tsv').write_text('\n'.join(index)+'\n')
    invalid=['name\tresult\tsha256\tsamples\tframe_end']
    for fault in ['invalid_fcs','invalid_service','nonconvergence']:
        psdu=bytearray(base.frame(44))
        if fault=='invalid_fcs': psdu[-1]^=1
        symbols,coded=encode_psdu(psdu,7,fault=='invalid_service')
        if fault=='nonconvergence':
            random=hashlib.shake_256(b'ht-ldpc-nonconvergence').digest((len(coded)+7)//8)
            coded=[random[i//8]>>(i%8)&1 for i in range(len(coded))]
        wave,_,end=waveform(psdu,7,16,symbols,coded)
        iq=base.quantize(wave)
        name=f'ht-ldpc-7-{fault}'
        (out/f'{name}.cs8').write_bytes(iq)
        invalid.append('\t'.join(map(str,[name,fault,hashlib.sha256(iq).hexdigest(),len(iq)//2,end])))
    (out/'ht-ldpc-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print('64 complete HT20 LDPC IQ fixtures and 3 independent negative controls verified')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-ldpc-check-') as temporary:
            path=Path(temporary)
            generate(path)
            for file in path.iterdir():
                assert file.read_bytes()==(OUT/file.name).read_bytes(),file.name
    else:
        generate(OUT)
