"""Independent, standard-library-only IEEE 802.11-2007 offline OFDM encoder.

Run from repository root: python3 tools/oracle/engine/backends/ofdm_vectors.py
No production crafter code is imported. No transmission capability is provided.
"""
import cmath
import hashlib
import json
import math
from pathlib import Path
import struct
import zlib
import argparse
import tempfile

VERSION = '1'
ROOT = Path(__file__).resolve().parents[4]
OUT = ROOT / 'crafter/tests/fixtures/iq'
# Table 17-3 and 17-5: rate, transmission-order RATE, NBPSC, NDBPS.
RATES = [(6,'1101',1,24),(9,'1111',1,36),(12,'0101',2,48),
         (18,'0111',2,72),(24,'1001',4,96),(36,'1011',4,144),
         (48,'0001',6,192),(54,'0011',6,216)]
LTF = [1,1,-1,-1,1,1,-1,1,-1,1,1,1,1,1,1,-1,-1,1,1,-1,1,-1,1,1,1,1,0,
       1,-1,-1,1,1,-1,1,-1,1,-1,-1,-1,-1,-1,1,1,-1,-1,1,-1,1,-1,1,1,1,1]
CARRIERS = [k for k in range(-26,27) if k not in (-21,-7,0,7,21)]

def bits(data):
    return [(v >> k) & 1 for v in data for k in range(8)]

def encode(data):
    state = 0
    out = []
    for b in data:
        state = ((state << 1) | b) & 127
        # Figure 17-8, current input at bit 0; reversed octal tap notation.
        out += [(state & p).bit_count() & 1 for p in (0o155, 0o117)]
    return out

def interleave(data, nbpsc):
    n = len(data)
    s = max(nbpsc // 2, 1)
    out = [0] * n
    for k,b in enumerate(data):
        i = (n // 16) * (k % 16) + k // 16
        j = s * (i // s) + (i + n - (16*i)//n) % s
        out[j] = b
    return out

def scramble(data, seed):
    out = []
    for b in data:
        feedback = ((seed >> 6) ^ (seed >> 3)) & 1
        out.append(b ^ feedback)
        seed = ((seed << 1) | feedback) & 127
    return out

def signal(rate_bits, length):
    out = list(map(int,rate_bits)) + [0] + [(length >> k)&1 for k in range(12)]
    return out + [sum(out)&1] + [0]*6

def constellation(b):
    # Figure 17-10 groups I bits before Q bits (not alternating).
    if len(b) == 1:
        return complex(2*b[0]-1)
    def axis(v):
        if len(v)==1: return 2*v[0]-1
        if len(v)==2: return (2*v[0]-1)*(3-2*v[1])
        return (2*v[0]-1)*(4-(2*v[1]-1)*(3-2*v[2]))
    h = len(b)//2
    return complex(axis(b[:h]),axis(b[h:])) / math.sqrt({2:2,4:10,6:42}[len(b)])

TWIDDLE = [[cmath.exp(2j*math.pi*k*t/64)/64 for k in range(-26,27)] for t in range(64)]
def ifft(freq):
    return [sum(v*w for v,w in zip(freq,row)) for row in TWIDDLE]

def symbol(data, nbpsc, polarity):
    freq = [0j]*53
    for i,k in enumerate(CARRIERS):
        freq[k+26] = constellation(data[i*nbpsc:(i+1)*nbpsc])
    for k,p in [(-21,1),(-7,1),(7,1),(21,-1)]:
        freq[k+26] = p*polarity
    wave = ifft(freq)
    return wave[-16:] + wave

def preamble():
    freq = [0j]*53
    for k,p in zip(range(-24,25,4),[1,-1,1,-1,-1,1,0,-1,-1,1,1,1,1]):
        freq[k+26] = p*(1+1j)*math.sqrt(13/6)
    short = ifft(freq)[:16]*10
    long = ifft(LTF)
    return short + long[-32:] + long*2

def self_check():
    # Independently transcribed IEEE Annex G Tables G.7, G.8, G.9, G.15.
    s = signal('1011',100)
    assert ''.join(map(str,s)) == '101100010011000000000000'
    assert ''.join(map(str,encode(s))) == '110100011010000100000010001111100111000000000000'
    assert ''.join(map(str,interleave(encode(s),1))) == '100101001101000000010100100000110010010010010100'
    assert ''.join(map(str,scramble([0]*32,0b1011101))) == '01101100000110011010100111001111'
    assert [1-2*b for b in scramble([0]*8,127)] == [1,1,1,1,-1,-1,-1,1]
    # Table G.18 first 18 punctured DATA bits: zero SERVICE then G.1's 0x04.
    annex_data = encode(scramble([0]*16 + bits(bytes([4])), 0b1011101))
    annex_punctured = [b for i,b in enumerate(annex_data) if [1,1,1,0,0,1][i%6]]
    assert ''.join(map(str,annex_punctured[:18])) == '001010110000100010'
    assert zlib.crc32(b'123456789') == 0xcbf43926

def frame(extra):
    # Synthetic unprotected data frame, local MACs, LLC/SNAP, IPv4 documentation addresses.
    header = bytes.fromhex('080000000200000000010200000000020200000000030000aaaa030000000800')
    payload = bytes(range(extra))
    ip = bytearray(bytes.fromhex('450000000001000040fd0000c0000201c6336402'))
    ip[2:4] = struct.pack('>H',20+len(payload))
    total = sum(struct.unpack('>10H',ip))
    total = (total&65535)+(total>>16)
    ip[10:12] = struct.pack('>H',(~total)&65535)
    body = header + ip + payload
    return body + struct.pack('<I',zlib.crc32(body))

def generate(rate, rb, nbpsc, ndbps, index, case='clean'):
    psdu = frame(index+3)
    if case=='bad_fcs': psdu = psdu[:-1]+bytes([psdu[-1]^1])
    seed = 0x5d-index*3
    nsym = math.ceil((16+8*len(psdu)+6)/ndbps)
    data = [0]*16+bits(psdu)+[0]*(nsym*ndbps-16-8*len(psdu))
    scrambled = scramble(data,seed)
    tail = 16+8*len(psdu)
    scrambled[tail:tail+6] = [0]*6
    coded = encode(scrambled)
    pattern = [1,1] if ndbps*2==48*nbpsc else ([1,1,1,0] if rate==48 else [1,1,1,0,0,1])
    punctured = [b for i,b in enumerate(coded) if pattern[i%len(pattern)]]
    sig = signal(rb,len(psdu))
    if case=='invalid_signal': sig[17] ^= 1
    si = interleave(encode(sig),1)
    polarities = [1-2*b for b in scramble([0]*(nsym+1),127)]
    interleaved = [interleave(punctured[i:i+48*nbpsc],nbpsc) for i in range(0,len(punctured),48*nbpsc)]
    wave = preamble()+symbol(si,1,polarities[0])
    for i,b in enumerate(interleaved): wave += symbol(b,nbpsc,polarities[i+1])
    leading = 37
    wave = [0j]*leading+wave+[0j]*32
    cfo = 80000 if case=='offset' else 0
    noise = 0.003 if case=='noisy' else 0
    # Integer LCG uniform dither avoids implementation-specific Gaussian sampling.
    state = 12345
    def rand():
        nonlocal state
        state = (1664525*state+1013904223)&0xffffffff
        return state/4294967296*2-1
    samples = bytearray()
    for i,v in enumerate(wave):
        v = v*cmath.exp(1j*(0.4+2*math.pi*cfo*i/20_000_000)) + noise*complex(rand(),rand())
        for a in (v.real,v.imag): samples.append(max(-128,min(127,round(a*300)))&255)
    if case=='truncated': samples = samples[:-146]
    name = f'ofdm-{rate}-{case}'
    (OUT/f'{name}.cs8').write_bytes(samples)
    intermediate = dict(signal=sig,signal_coded=encode(sig),signal_interleaved=si,
                        data=data,scrambled=scrambled,coded=coded,punctured=punctured,interleaved=interleaved)
    (OUT/f'{name}.json').write_text(json.dumps(intermediate,separators=(',',':'))+'\n')
    return dict(name=name,rate_mbps=rate,nbpsc=nbpsc,ndbps=ndbps,nsym=nsym,seed=seed,
                sample_count=len(samples)//2,preamble_start=leading,signal_start=leading+320,
                data_start=leading+400,frame_end=leading+400+nsym*80,psdu_hex=psdu.hex(),
                sha256=hashlib.sha256(samples).hexdigest(),fcs_valid=case!='bad_fcs',
                expected='reject' if case in ('invalid_signal','truncated','bad_fcs') else 'frame',
                impairment=dict(cfo_hz=cfo,phase_rad=0.4,uniform_noise_amplitude=noise,noise_seed=12345))

def main():
    self_check()
    entries = [generate(*r,i) for i,r in enumerate(RATES)]
    entries += [generate(*RATES[0],0,c) for c in ('noisy','offset','truncated','invalid_signal','bad_fcs')]
    manifest = dict(schema=1,generator_version=VERSION,generator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    format='cs8',sample_rate_hz=20_000_000,source='IEEE Std 802.11-2007',fixtures=entries)
    (OUT/'ofdm-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    columns = ['name','rate_mbps','nbpsc','ndbps','nsym','sample_count','psdu_hex','sha256','fcs_valid','expected']
    (OUT/'ofdm-index.tsv').write_text('\t'.join(columns)+'\n'+''.join('\t'.join(str(e[c]) for c in columns)+'\n' for e in entries))
    print(f'Generated {len(entries)} independent vectors; Annex G checks passed.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='verify committed outputs without changing them')
    args = parser.parse_args()
    if args.check:
        expected = OUT
        with tempfile.TemporaryDirectory(prefix='ofdm-vectors-') as temporary:
            OUT = Path(temporary)
            main()
            generated = {p.name: p.read_bytes() for p in OUT.iterdir()}
            existing = {p.name: p.read_bytes() for p in expected.glob('ofdm-*') if p.is_file()}
            if generated != existing:
                parser.exit(1, 'OFDM vector outputs differ; regenerate and review the fixtures.\n')
        print('All OFDM vector artifacts match the independent generator.')
    else:
        main()
