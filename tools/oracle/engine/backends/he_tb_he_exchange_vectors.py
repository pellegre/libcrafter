"""Independent HE SU/ER SU Trigger / HE TB exchanges, ax-2021 26.5.2.

BCC/LDPC and plain/DCM Trigger carriers, carrier/response BSS color matching,
and STBC context exclusion. Synthetic offline support is not live negotiation.
"""
import argparse
from pathlib import Path
import tempfile

import he_bcc_iq_vectors as he
import he_stbc_iq_vectors as stbc
import he_tb_exchange_vectors as exchange
from vht_ampdu_vectors import delimiter


def aggregate(trigger):
    payload = bytearray(delimiter(len(trigger), 0) + trigger)
    payload += b'\xc7' * (-len(payload) % 4)
    return bytes(payload)


def generate(out):
    rows = []
    original = exchange.legacy
    try:
        with tempfile.TemporaryDirectory(prefix='he-tb-he-carrier-') as temporary:
            scratch = Path(temporary)
            cases = [
                (format_, ldpc, dcm, False, 'clean')
                for format_ in ('su', 'er')
                for ldpc in (False, True)
                for dcm in (False, True)
            ]
            cases += [(format_, False, False, False, 'wrong-color') for format_ in ('su', 'er')]
            cases += [(format_, False, False, True, 'stbc-carrier') for format_ in ('su', 'er')]
            for format_, coding, dcm, use_stbc, case in cases:
                er = format_ == 'er'
                mcs = 0 if er else 4

                def carrier(trigger):
                    payload = aggregate(trigger)
                    if use_stbc:
                        wave, _, _, _, _ = stbc.waveform(
                            mcs,
                            2,
                            32,
                            coding,
                            2,
                            'selective',
                            er=er,
                            aggregate=(payload, [trigger]),
                            bss_color=37,
                            return_complex=True,
                        )
                    else:
                        wave, _ = he.waveform(
                            mcs,
                            2,
                            32,
                            'selective',
                            payload=payload,
                            ldpc=coding,
                            initial_padding=2,
                            dcm=dcm,
                            er=er,
                            bss_color=37,
                            return_complex=True,
                        )
                    return wave[37:]

                exchange.legacy = carrier
                exchange.generate(
                    scratch,
                    [(26, 4, 0, 0, 2, 32, 'wrong-color' if case == 'wrong-color' else 'clean')],
                )
                header, row = (scratch / 'he-tb-exchange-index.tsv').read_text().splitlines()
                fields = row.split('\t')
                iq = (scratch / (fields[0] + '.cs8')).read_bytes()
                fields[0] = (
                    f'he-tb-he-exchange-{format_}-m{mcs}-l{int(coding)}-'
                    f'd{int(dcm)}-s{int(use_stbc)}-{case}'
                )
                fields[1] = case
                if use_stbc:
                    fields[9] = '-'
                (out / (fields[0] + '.cs8')).write_bytes(iq)
                if not rows:
                    rows.append(
                        header
                        + '\tcarrier_format\tcarrier_mcs\tcarrier_ldpc\tcarrier_dcm'
                        + '\tcarrier_stbc\tcarrier_bss_color'
                    )
                rows.append(
                    '\t'.join(
                        fields
                        + [
                            format_,
                            str(mcs),
                            str(int(coding)),
                            str(int(dcm)),
                            str(int(use_stbc)),
                            '37',
                        ]
                    )
                )
    finally:
        exchange.legacy = original
    (out / 'he-tb-he-exchange-index.tsv').write_text('\n'.join(rows) + '\n')
    print(f'{len(rows) - 1} independent HE SU/ER SU Trigger / HE TB exchanges')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='he-tb-he-check-') as temporary:
            out = Path(temporary)
            generate(out)
            for path in out.iterdir():
                assert path.read_bytes() == (exchange.base.OUT / path.name).read_bytes(), path.name
    else:
        generate(exchange.base.OUT)
