"""Independent VHT Trigger / HE TB exchanges, ax-2021 26.5.2.2.1.

Long-GI BCC/LDPC, repeated identical Triggers, short-GI context exclusion.
No live 5GHz test or recipient capability negotiation is claimed.
"""
import argparse
from pathlib import Path
import tempfile
import he_tb_exchange_vectors as exchange
from vht_ampdu_vectors import aggregate
from vht_bcc_iq_vectors import waveform


def generate(out):
    rows = []
    original = exchange.legacy
    try:
        with tempfile.TemporaryDirectory(prefix='he-tb-vht-carrier-') as temporary:
            scratch = Path(temporary)
            for mcs in [0, 4, 8]:
                for coding in [False, True]:
                    for repeats in [1, 2]:
                        for guard in [8, 16]:
                            def carrier(trigger):
                                apep, _ = aggregate([trigger] * repeats, smpdu=repeats == 1)
                                wave, fields = waveform(mcs, guard, 0, apep_override=apep, ldpc=coding)
                                return wave[37:fields[7]]
                            exchange.legacy = carrier
                            exchange.generate(scratch, [(26, 4, 0, 0, 2, 32, 'clean')])
                            header, row = (scratch / 'he-tb-exchange-index.tsv').read_text().splitlines()
                            fields = row.split('\t')
                            iq = (scratch / (fields[0] + '.cs8')).read_bytes()
                            fields[0] = f'he-tb-vht-exchange-m{mcs}-l{int(coding)}-r{repeats}-gi{guard*50}'
                            fields[1] = 'clean' if guard == 16 else 'short-gi'
                            if guard == 8:
                                fields[9] = '-'
                            (out / (fields[0] + '.cs8')).write_bytes(iq)
                            if not rows:
                                rows.append(header + '\ttrigger_count')
                            rows.append('\t'.join(fields + [str(repeats)]))
    finally:
        exchange.legacy = original
    (out / 'he-tb-vht-exchange-index.tsv').write_text('\n'.join(rows) + '\n')
    print('24 independent VHT Trigger / HE TB exchanges')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-vht-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for path in out.iterdir():
                assert path.read_bytes() == (exchange.base.OUT / path.name).read_bytes(), path.name
    else:
        generate(exchange.base.OUT)
