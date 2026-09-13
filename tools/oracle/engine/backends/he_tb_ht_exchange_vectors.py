"""Independent HT Trigger / HE TB exchanges, ax-2021 26.5.2.2.1.

HT20 BCC/LDPC, plain/aggregate, long-GI positives and short-GI exclusion.
Synthetic offline support does not establish negotiated live capability.
"""
import argparse
from pathlib import Path
import tempfile
import ampdu_vectors as ampdu
import he_tb_exchange_vectors as exchange
import ht_ampdu_vectors as ht
import ht_ldpc_vectors as ldpc


def generate(out):
    rows = []
    original = exchange.legacy
    try:
        with tempfile.TemporaryDirectory(prefix='he-tb-ht-carrier-') as temporary:
            scratch = Path(temporary)
            for mcs in [0, 7]:
                for coding in [False, True]:
                    for aggregate in [False, True]:
                        for guard in [8, 16]:
                            def carrier(trigger):
                                psdu = ampdu.aggregate([trigger])[0] if aggregate else trigger
                                symbols, coded = ldpc.encode_psdu(psdu, mcs) if coding else ht.bcc(psdu, mcs)
                                wave, _, end = ldpc.waveform(psdu, mcs, guard, symbols, coded, aggregate, coding)
                                return wave[37:end]
                            exchange.legacy = carrier
                            exchange.generate(scratch, [(26, 4, 0, 0, 2, 32, 'clean')])
                            header, row = (scratch / 'he-tb-exchange-index.tsv').read_text().splitlines()
                            fields = row.split('\t')
                            iq = (scratch / (fields[0] + '.cs8')).read_bytes()
                            fields[0] = f'he-tb-ht-exchange-m{mcs}-l{int(coding)}-a{int(aggregate)}-gi{guard*50}'
                            fields[1] = 'clean' if guard == 16 else 'short-gi'
                            if guard == 8:
                                fields[9] = '-'
                            (out / (fields[0] + '.cs8')).write_bytes(iq)
                            if not rows:
                                rows.append(header)
                            rows.append('\t'.join(fields))
    finally:
        exchange.legacy = original
    (out / 'he-tb-ht-exchange-index.tsv').write_text('\n'.join(rows) + '\n')
    print('16 independent HT Trigger / HE TB exchanges')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-ht-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for path in out.iterdir():
                assert path.read_bytes() == (exchange.base.OUT / path.name).read_bytes(), path.name
    else:
        generate(exchange.base.OUT)
