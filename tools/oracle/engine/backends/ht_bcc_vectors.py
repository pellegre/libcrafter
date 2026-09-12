"""Independent HT20 BCC oracle, IEEE 802.11-2020 clause 19 (not production TX).

Source mapping: docs/wifi-phy-evidence.json. No device access is possible.
"""
import argparse
import cmath
import hashlib
import math
from pathlib import Path
import tempfile
import ofdm_vectors as base
from ht_signal_vectors import crc

OUT = base.OUT
PARAMETERS = [(1,26), (2,52), (2,78), (4,104), (4,156), (6,208), (6,234), (6,260)]
PUNCTURE = [[1,1], [1,1], [1,1,1,0,0,1], [1,1], [1,1,1,0,0,1], [1,1,1,0], [1,1,1,0,0,1], [1,1,1,0,0,1,1,0,0,1]]
CARRIERS = [k for k in range(-28,29) if k not in (-21,-7,0,7,21)]
TWIDDLE = [[cmath.exp(2j*math.pi*k*n/64)/64 for k in range(-28,29)] for n in range(64)]


def ifft(freq):
    return [sum(v*w for v,w in zip(freq, row)) for row in TWIDDLE]


def interleave(bits, nbpsc):
    rows, cols = 4*nbpsc, 13
    matrix = [bits[start:start+cols] for start in range(0, len(bits), cols)]
    transposed = [matrix[row][col] for col in range(cols) for row in range(rows)]
    result = [0] * len(bits)
    s = max(nbpsc//2, 1)
    for i, bit in enumerate(transposed):
        j = s*(i//s) + (i+len(bits)-(cols*i)//len(bits)) % s
        result[j] = bit
    return result


def generate(out):
    base.self_check()
    index = ['name\tmcs\tguard_samples\tsymbols\tpsdu_hex\tsha256\tsamples\tdata_start\tframe_end']
    for mcs, (nbpsc, ndbps) in enumerate(PARAMETERS):
        for guard in [8,16]:
            for extra in [44,4039]:
                psdu = base.frame(extra)
                symbols = math.ceil((16+8*len(psdu)+6)/ndbps)
                service_data = [0]*16 + base.bits(psdu)
                padded = service_data + [0]*(symbols*ndbps-len(service_data))
                scrambled = base.scramble(padded, 0x5d)
                scrambled[len(service_data):len(service_data)+6] = [0]*6
                coded = base.encode(scrambled)
                pattern = PUNCTURE[mcs]
                coded = [bit for i, bit in enumerate(coded) if pattern[i % len(pattern)]]
                assert len(coded) == symbols*52*nbpsc
                fields = [(mcs>>n)&1 for n in range(7)] + [0]
                fields += [(len(psdu)>>n)&1 for n in range(16)]
                fields += [1,1,1,0,0,0,0,int(guard==8),0,0]
                fields += crc(fields) + [0]*6
                header = base.encode(fields)
                lsig_length = 3 * (4+math.ceil(symbols*(64+guard)/80))-3
                wave = [0j]*37 + base.preamble()
                wave += base.symbol(base.interleave(base.encode(base.signal('1101', lsig_length)),1),1,1)
                for symbol in range(2):
                    freq = [0j]*53
                    for k, bit in zip(base.CARRIERS, base.interleave(header[symbol*48:(symbol+1)*48],1)):
                        freq[k+26] = 1j*(2*bit-1)
                    for k, sign in [(-21,1),(-7,1),(7,1),(21,-1)]: freq[k+26] = sign
                    time = base.ifft(freq)
                    wave += time[-16:]+time
                wave += base.preamble()[:80]  # HT-STF, same 20 MHz sequence.
                training = ifft([1,1] + base.LTF + [-1,-1])
                wave += training[-16:] + training
                data_start = len(wave)
                polarities = [1-2*b for b in base.scramble([0]*(symbols+3),127)]
                for symbol in range(symbols):
                    block = interleave(coded[symbol*52*nbpsc:(symbol+1)*52*nbpsc],nbpsc)
                    freq = [0j]*57
                    for j,k in enumerate(CARRIERS): freq[k+28] = base.constellation(block[j*nbpsc:(j+1)*nbpsc])
                    for j,k in enumerate([-21,-7,7,21]): freq[k+28] = polarities[symbol+3] * [1,1,1,-1][(symbol+j)%4]
                    time = ifft(freq)
                    wave += time[-guard:] + time
                end = len(wave)
                wave += [0j]*64
                for impairment in ['clean','offset']:
                    impaired = wave
                    if impairment == 'offset':
                        impaired = [(v+(0.25j*wave[n-3] if n>=3 else 0))*cmath.exp(1j*(0.7+0.018*n)) for n,v in enumerate(wave)]
                    iq = base.quantize(impaired)
                    name = f'ht-bcc-{mcs}-gi{guard*50}-len{len(psdu)}-{impairment}'
                    (out / f'{name}.cs8').write_bytes(iq)
                    index.append('\t'.join(map(str,[name,mcs,guard,symbols,psdu.hex(),hashlib.sha256(iq).hexdigest(),len(iq)//2,data_start,end])))
    (out / 'ht-bcc-index.tsv').write_text('\n'.join(index)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-bcc-check-') as temporary:
            path = Path(temporary)
            generate(path)
            for file in path.iterdir():
                assert file.read_bytes() == (OUT / file.name).read_bytes(), file.name
    else:
        generate(OUT)
    print('64 independent HT20 BCC IQ fixtures verified')
