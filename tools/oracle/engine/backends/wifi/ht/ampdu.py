"""Independent complete aggregated HT20 IQ, IEEE 802.11-2020 9.7 and 19.3."""
import argparse
import hashlib
import tempfile
from pathlib import Path
import tools.oracle.engine.backends.wifi.ampdu as ampdu
import tools.oracle.engine.backends.wifi.ht.bcc as ht
import tools.oracle.engine.backends.wifi.ht.ldpc as ldpc
import tools.oracle.engine.backends.wifi.ofdm.base as base


def bcc(psdu, mcs, stbc=False):
    nbpsc, ndbps = ht.PARAMETERS[mcs]
    group = 2 if stbc else 1
    symbols = group * ((16 + 8 * len(psdu) + 6 + group*ndbps - 1) // (group*ndbps))
    payload = [0] * 16 + base.bits(psdu)
    bits = base.scramble(payload + [0] * (symbols * ndbps - len(payload)), 0x5d)
    bits[len(payload):len(payload) + 6] = [0] * 6
    pattern = ht.PUNCTURE[mcs]
    coded = [v for i, v in enumerate(base.encode(bits)) if pattern[i % len(pattern)]]
    assert len(coded) == symbols * 52 * nbpsc
    return symbols, coded


def generate(out):
    out.mkdir(parents=True, exist_ok=True)
    rows = ['name\tmcs\tguard_samples\tldpc\tpsdu_hex\tframe_offsets\tmpdu_hex\tsha256\tframe_end']
    cases = {}
    for row in ampdu.generate()['ampdu-index.tsv'].splitlines()[1:]:
        name, psdu, offsets, frames = row.split('\t')
        cases[name] = (bytes.fromhex(psdu), offsets, frames)
    wire, offsets = ampdu.aggregate([base.frame(0)] * 80)
    cases['large'] = (wire, ','.join(map(str, offsets)), ','.join([base.frame(0).hex()] * 80))
    wire, offsets = ampdu.aggregate([base.frame(1278), base.frame(44)])
    cases['damaged_codeword'] = (wire, str(offsets[1]), base.frame(44).hex())
    for mcs in range(8):
        for guard in [8, 16]:
            for coding in [False, True]:
                names = ['alignments', 'duplicate', 'bad_fcs']
                if mcs == 7:
                    names += [n for n in cases if n not in names and n != 'damaged_codeword']
                if coding and mcs in [3, 7]:
                    names.append('damaged_codeword')
                for case in names:
                    psdu, offsets, frames = cases[case]
                    symbols, coded = ldpc.encode_psdu(psdu, mcs) if coding else bcc(psdu, mcs)
                    if case == 'damaged_codeword':
                        ncbps, rate = ldpc.PARAMETERS[mcs]
                        _, count, block, short, puncture, repeat, _ = ldpc.layout(len(psdu), ncbps, rate, 1)
                        lengths = [block - short//count - (i < short%count)
                                   - puncture//count - (i < puncture%count)
                                   + repeat//count + (i < repeat%count) for i in range(count)]
                        assert count > 3
                        start = sum(lengths[:2])
                        noise = hashlib.shake_256(b'ht-ampdu-damaged-codeword').digest((lengths[2]+7)//8)
                        coded[start:start+lengths[2]] = [noise[i//8] >> (i%8) & 1 for i in range(lengths[2])]
                    wave, _, end = ldpc.waveform(psdu, mcs, guard, symbols, coded, True, coding)
                    iq = base.quantize(wave)
                    name = f'ht-ampdu-{mcs}-gi{guard*50}-{"ldpc" if coding else "bcc"}-{case}'
                    (out / f'{name}.cs8').write_bytes(iq)
                    rows.append('\t'.join(map(str, [name, mcs, guard, int(coding), psdu.hex(), offsets,
                                                   frames, hashlib.sha256(iq).hexdigest(), end])))
    (out / 'ht-ampdu-index.tsv').write_text('\n'.join(rows) + '\n')
    print(f'{len(rows)-1} complete HT20 aggregate IQ fixtures verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-ampdu-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes() == (base.OUT / file.name).read_bytes(), file.name
    else:
        generate(base.OUT)
