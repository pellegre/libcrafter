"""Independent complete VHT20 SU LDPC IQ: 802.11-2020 clauses 10 and 21."""
import argparse
import cmath
import hashlib
from pathlib import Path
import tempfile
import ofdm_vectors as base
from vht_ampdu_vectors import aggregate, frame
from vht_bcc_iq_vectors import waveform


def generate(out):
    base.self_check()
    rows = ['name\tmcs\tguard\tpsdu_hex\tframe_offsets\tmpdu_hex\tsha256\tdata_end\tinvalid_fcs']
    extras = set()
    for mcs in range(9):
        for guard in (8,16):
            cases = ['offset','duplicate','large','bad-fcs']
            if mcs == 0 and guard == 16: cases.append('bad-codeword')
            for case in cases:
                frames = [frame(4100),frame(56)] if case in ('large','bad-codeword') else [frame(56)]*2
                apep, offsets = aggregate(frames)
                if case == 'bad-fcs':
                    damaged = bytearray(apep)
                    damaged[offsets[0]+len(frames[0])-1] ^= 1
                    apep = bytes(damaged)
                    frames,offsets = frames[1:],offsets[1:]
                samples,fields = waveform(mcs,guard,0,corruption='codeword' if case == 'bad-codeword' else None,apep_override=apep,ldpc=True)
                if case == 'bad-codeword': frames,offsets = frames[1:],offsets[1:]
                extras.add(fields[2][27])
                assert fields[1] <= 4095
                if case == 'offset':
                    samples = [(v + (0.25j*samples[n-3] if n >= 3 else 0))*cmath.exp(1j*(0.7+0.018*n))
                               for n,v in enumerate(samples)]
                assert all(max(abs(v.real),abs(v.imag))*300 < 127 for v in samples)
                iq = base.quantize(samples)
                name = f'vht-ldpc-{mcs}-gi{guard*50}-{case}'
                (out/f'{name}.cs8').write_bytes(iq)
                rows.append('\t'.join(map(str,[name,mcs,guard,fields[4].hex(),
                    ','.join(map(str,offsets)),','.join(f.hex() for f in frames),
                    hashlib.sha256(iq).hexdigest(),fields[7],int(case in ('bad-fcs','bad-codeword'))])))
    assert extras == {0,1}
    (out/'vht-ldpc-iq-index.tsv').write_text('\n'.join(rows)+'\n')
    invalid = ['name\treason\tsha256']
    for reason in ['service','extra_flag','sigb_crc']:
        samples,_ = waveform(0,16,44,reason,ldpc=True)
        iq = base.quantize(samples)
        name = f'vht-ldpc-invalid-{reason.replace("_","-")}'
        (out/f'{name}.cs8').write_bytes(iq)
        invalid.append(f'{name}\t{reason}\t{hashlib.sha256(iq).hexdigest()}')
    (out/'vht-ldpc-iq-invalid-index.tsv').write_text('\n'.join(invalid)+'\n')
    print(f'{len(rows)-1} complete independent VHT LDPC waveforms and {len(invalid)-1} invalid cases verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='vht-ldpc-iq-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT/file.name).read_bytes(),file.name
    else:
        generate(base.OUT)
