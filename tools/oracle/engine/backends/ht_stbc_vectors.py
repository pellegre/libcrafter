"""Independent full HT20 NSS1/NSTS2 IQ, IEEE802.11-2020 clause19.

Tables19-9/10 cyclic shifts, Eq19-27 training, Table19-18 STBC and Table19-19
pilots. This constructs two transmit waveforms then one simulated receive IQ
stream. It neither uses production TX nor claims a single-antenna STBC TX.
"""
import argparse
import cmath
import hashlib
import math
import tempfile
from pathlib import Path
import ht_ampdu_vectors as aggregate
import ht_bcc_vectors as ht
import ht_ldpc_vectors as ldpc
import ofdm_vectors as base


def waveform(psdu, mcs, guard, coding, greenfield):
    symbols, coded = (ldpc.encode_psdu if coding else aggregate.bcc)(psdu, mcs, stbc=True)
    assert symbols % 2 == 0
    nbpsc = ht.PARAMETERS[mcs][0]
    chains = [[0j]*37, [0j]*37]

    def field(first, second, prefix, repeat=1, legacy=False):
        for chain, time in enumerate([first, second]):
            advance = (4 if legacy else 8) if chain else 0
            shifted = time[advance:]+time[:advance]
            samples = (shifted[-prefix:] if prefix else []) + shifted*repeat
            chains[chain].extend(v/math.sqrt(2) for v in samples)

    short = base.preamble()[:16]
    long = ht.ifft([1,1]+base.LTF+[-1,-1])
    field(short, short, 0, 10, legacy=not greenfield)
    if greenfield:
        field(long, long, 32, 2)
    else:
        legacy_long = base.ifft(base.LTF)
        field(legacy_long, legacy_long, 32, 2, legacy=True)
        length = 3*(5+math.ceil(symbols*(64+guard)/80))-3
        signal = base.symbol(base.interleave(base.encode(base.signal('1101',length)),1),1,1)[16:]
        field(signal, signal, 16, legacy=True)
    fields = [(mcs >> n)&1 for n in range(7)]+[0]
    fields += [(len(psdu) >> n)&1 for n in range(16)]
    fields += [1,1,1,0,1,0,int(coding),int(guard==8),0,0]
    fields += ldpc.crc(fields)+[0]*6
    header = base.encode(fields)
    for n in range(2):
        freq = [0j]*53
        for k, bit in zip(base.CARRIERS, base.interleave(header[n*48:(n+1)*48],1)):
            freq[k+26] = 1j*(2*bit-1)
        for k, sign in [(-21,1),(-7,1),(7,1),(21,-1)]:
            freq[k+26] = sign
        time = base.ifft(freq)
        field(time, time, 16, legacy=not greenfield)
    if not greenfield:
        field(short, short, 0, 5)
        field(long, long, 16)
    field([-v for v in long], long, 16)
    start = len(chains[0])
    assert start == 37+(560 if greenfield else 800)
    offset = 2 if greenfield else 3
    polarity = [1-2*b for b in base.scramble([0]*(symbols+offset),127)]
    pilots = [[1,1,-1,-1], [1,-1,-1,1]]
    for pair in range(symbols//2):
        mapped = []
        for n in [2*pair,2*pair+1]:
            block = coded[n*52*nbpsc:(n+1)*52*nbpsc]
            if not coding:
                block = ht.interleave(block,nbpsc)
            mapped.append([base.constellation(block[j*nbpsc:(j+1)*nbpsc]) for j in range(52)])
        for within in range(2):
            n = 2*pair+within
            freq = [[0j]*57,[0j]*57]
            for j,k in enumerate(ht.CARRIERS):
                freq[0][k+28] = mapped[within][j]
                freq[1][k+28] = (-1 if within==0 else 1)*mapped[1-within][j].conjugate()
            for chain in range(2):
                for j,k in enumerate([-21,-7,7,21]):
                    freq[chain][k+28] = polarity[n+offset]*pilots[chain][(n+j)%4]
            field(ht.ifft(freq[0]),ht.ifft(freq[1]),guard)
    end = len(chains[0])
    assert end == start+symbols*(64+guard) and len(chains[1]) == end
    for chain in chains:
        chain.extend([0j]*64)
    return chains,symbols,start,end


def generate(out):
    out.mkdir(parents=True,exist_ok=True)
    rows=['name\tmcs\tguard_samples\tsymbols\tpsdu_hex\tsha256\tsamples\tdata_start\tframe_end\tldpc\tgreenfield']
    for mcs in range(8):
        for coding in [False,True]:
            for greenfield,guard in [(False,8),(False,16),(True,16)]:
                for extra in [44,4039]:
                    psdu=base.frame(extra)
                    chains,symbols,start,end=waveform(psdu,mcs,guard,coding,greenfield)
                    for impairment in ['clean','offset']:
                        wave=[a+(0.45+0.2j)*b for a,b in zip(*chains)]
                        if impairment=='offset':
                            wave=[(v+(0.2j*chains[0][n-3] if n>=3 else 0)
                                    -(0.1*chains[1][n-2] if n>=2 else 0))
                                  *cmath.exp(1j*(0.7+0.018*n)) for n,v in enumerate(wave)]
                        iq=base.quantize(wave)
                        name=f'ht-stbc-{mcs}-{"ldpc" if coding else "bcc"}-{"gf" if greenfield else "mf"}-gi{guard*50}-len{len(psdu)}-{impairment}'
                        (out/f'{name}.cs8').write_bytes(iq)
                        rows.append('\t'.join(map(str,[name,mcs,guard,symbols,psdu.hex(),hashlib.sha256(iq).hexdigest(),len(iq)//2,start,end,int(coding),int(greenfield)])))
    (out/'ht-stbc-index.tsv').write_text('\n'.join(rows)+'\n')
    print(f'{len(rows)-1} independent complete HT20 STBC waveforms verified')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-stbc-check-') as temporary:
            out=Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:
        generate(base.OUT)
