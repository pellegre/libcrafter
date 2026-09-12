"""Independent HT20 greenfield IQ; IEEE 802.11-2020 19.3.9.5, 19.3.11.11.3.

One space-time stream, no extension streams: long GI only (19.3.11.11.6).
This backend shares independent coding arithmetic, never production TX.
"""
import argparse
import cmath
import hashlib
import tempfile
from pathlib import Path
import ht_ampdu_vectors as aggregate
import ht_ldpc_vectors as ldpc
import ofdm_vectors as base


def generate(out):
    out.mkdir(parents=True, exist_ok=True)
    rows = ['name\tmcs\tguard_samples\tsymbols\tpsdu_hex\tsha256\tsamples\tdata_start\tframe_end\tldpc']
    for mcs in range(8):
        for coding in [False, True]:
            for extra in [44, 4039]:
                psdu = base.frame(extra)
                symbols, coded = (ldpc.encode_psdu if coding else aggregate.bcc)(psdu, mcs)
                wave, start, end = ldpc.waveform(psdu, mcs, 16, symbols, coded,
                                                ldpc=coding, greenfield=True)
                assert start == 37 + 480 and end == start + symbols * 80
                for impairment in ['clean', 'offset']:
                    impaired = wave
                    if impairment == 'offset':
                        impaired = [(v + (0.25j * wave[n-3] if n >= 3 else 0))
                                    * cmath.exp(1j * (0.7 + 0.018*n)) for n, v in enumerate(wave)]
                    iq = base.quantize(impaired)
                    name = f'ht-greenfield-{mcs}-{"ldpc" if coding else "bcc"}-len{len(psdu)}-{impairment}'
                    (out / f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str, [name, mcs, 16, symbols, psdu.hex(),
                                                       hashlib.sha256(iq).hexdigest(), len(iq)//2,
                                                       start, end, int(coding)])))
    (out / 'ht-greenfield-index.tsv').write_text('\n'.join(rows) + '\n')
    invalid = ['name\tresult\tsha256\tsamples\tframe_end']
    for fault in ['header_crc', 'short_gi', 'stbc', 'extension_stream', 'width40',
                  'mcs8', 'invalid_service', 'invalid_fcs']:
        psdu = bytearray(base.frame(44))
        if fault == 'invalid_fcs':
            psdu[-1] ^= 1
        symbols, coded = ldpc.encode_psdu(psdu, 7, fault == 'invalid_service')
        wave, start, end = ldpc.waveform(psdu, 7, 16, symbols, coded, greenfield=True)
        fields = [(7 >> n) & 1 for n in range(7)] + [0]
        fields += [(len(psdu) >> n) & 1 for n in range(16)]
        fields += [1, 1, 1, 0, 0, 0, 1, 0, 0, 0]
        changed_bit = {'short_gi': 31, 'stbc': 29, 'extension_stream': 32, 'width40': 7}.get(fault)
        if changed_bit is not None:
            fields[changed_bit] = 1
        if fault == 'mcs8':
            fields[:7] = [(8 >> n) & 1 for n in range(7)]
        fields += ldpc.crc(fields) + [0]*6
        if fault == 'header_crc':
            fields[34] ^= 1
        header = base.encode(fields)
        signal = []
        for symbol in range(2):
            freq = [0j]*53
            for k, bit in zip(base.CARRIERS, base.interleave(header[symbol*48:(symbol+1)*48], 1)):
                freq[k+26] = 1j*(2*bit-1)
            for k, sign in [(-21,1), (-7,1), (7,1), (21,-1)]:
                freq[k+26] = sign
            time = base.ifft(freq)
            signal += time[-16:]+time
        wave[start-160:start] = signal
        iq = base.quantize(wave)
        name = f'ht-greenfield-invalid-{fault}'
        (out / f'{name}.cs8').write_bytes(iq)
        invalid.append('\t'.join(map(str, [name, fault, hashlib.sha256(iq).hexdigest(), len(iq)//2, end])))
    (out / 'ht-greenfield-invalid-index.tsv').write_text('\n'.join(invalid) + '\n')
    aggregated = ['name\tmcs\tguard_samples\tldpc\tpsdu_hex\tframe_offsets\tmpdu_hex\tsha256\tframe_end']
    mpdu = base.frame(0)
    psdu, offsets = aggregate.ampdu.aggregate([mpdu, mpdu])
    for mcs in [0, 7]:
        for coding in [False, True]:
            symbols, coded = (ldpc.encode_psdu if coding else aggregate.bcc)(psdu, mcs)
            wave, _, end = ldpc.waveform(psdu, mcs, 16, symbols, coded,
                                         aggregation=True, ldpc=coding, greenfield=True)
            iq = base.quantize(wave)
            name = f'ht-greenfield-ampdu-{mcs}-{"ldpc" if coding else "bcc"}'
            (out / f'{name}.cs8').write_bytes(iq)
            aggregated.append('\t'.join(map(str, [name, mcs, 16, int(coding), psdu.hex(),
                                                    ','.join(map(str, offsets)), ','.join([mpdu.hex()]*2),
                                                    hashlib.sha256(iq).hexdigest(), end])))
    (out / 'ht-greenfield-ampdu-index.tsv').write_text('\n'.join(aggregated) + '\n')
    print(f'{len(rows)-1} independent HT20 greenfield IQ fixtures verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-greenfield-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT / file.name).read_bytes(), file.name
    else:
        generate(base.OUT)
