"""Forward TB LDPC layouts, IEEE802.11ax-2021 27.3.12.5.5/Eq27-90.

The Trigger flag controls transmitted parity even when it differs from the
local extra-segment recommendation. No receiver imports or inverse sizing.
"""
import argparse
from fractions import Fraction as F
from math import ceil
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.he.capacity import BPS
from tools.oracle.engine.backends.wifi.he.ldpc.rate import RATES


def layout(ru, mcs, nss, dcm, group, initial, padding, extra):
    rate = RATES[mcs]
    coded = {26:24, 52:48, 106:102, 242:234}[ru] * BPS[mcs] * nss // (1 + dcm)
    short_tones = 2 if ru == 26 and dcm else {26:6, 52:12, 106:24, 242:60}[ru] // (1 + dcm)
    short_coded = short_tones * BPS[mcs] * nss
    data, short_data = int(coded * rate), int(short_coded * rate)
    payload = (initial - group) * data + group * (data if padding == 4 else padding * short_data)
    available = (initial - group) * coded + group * (coded if padding == 4 else padding * short_coded)
    if available <= 648:
        count, size = 1, 1296 if available >= payload + 912 * (1-rate) else 648
    elif available <= 1296:
        count, size = 1, 1944 if available >= payload + 1464 * (1-rate) else 1296
    elif available <= 1944:
        count, size = 1, 1944
    elif available <= 2592:
        count, size = 2, 1944 if available >= payload + 2916 * (1-rate) else 1296
    else:
        count, size = ceil(payload / (1944 * rate)), 1944
    shortened = max(0, int(count * size * rate) - payload)
    punctured = max(0, count * size - available - shortened)
    parity = count * size * (1-rate)
    recommended = int((punctured > parity/10 and shortened < F(6,5)*punctured*rate/(1-rate)) or punctured > 3*parity/10)
    symbols = initial
    if extra:
        available += group * (coded - 3*short_coded if padding == 3 else short_coded)
        if padding == 4:
            symbols += group
            padding = 1
        else:
            padding += 1
    punctured = max(0, count * size - available - shortened)
    repeated = max(0, int(available - parity - payload))
    assert count * size - shortened - punctured + repeated == available
    return [recommended, symbols, padding, extra, count, size, shortened, punctured, repeated, payload, available]


def generate():
    rows = ["ru\tmcs\tnss\tdcm\tgroup\tinitial\tainit\tlocal_extra\tsymbols\tpadding\textra\twords\tblock\tshort\tpuncture\trepeat\tpayload\tavailable"]
    for ru in (26,52,106,242):
        for nss in (1,2,4,8):
            for mcs in range(12):
                for dcm in ([0,1] if nss <= 2 and mcs in (0,1,3,4) else [0]):
                    for group in ([1,2] if nss == 1 and not dcm else [1]):
                        for initial in (group*k for k in (1,2,4,9,31,64,99,199)):
                            for padding in range(1,5):
                                for extra in (0,1):
                                    result = layout(ru,mcs,nss,dcm,group,initial,padding,extra)
                                    if result[9] < 16 or result[1] > 400:
                                        continue
                                    rows.append("\t".join(map(str,[ru,mcs,nss,dcm,group,initial,padding,*result])))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = IQ_FIXTURES / "he-tb-ldpc-layout.tsv"
    content = generate()
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content
    print(f"{len(content.splitlines())-1} independent TB LDPC layouts")
