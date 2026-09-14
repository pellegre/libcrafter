"""MU forward LDPC geometry, ax-2021 27.3.12.5.4; peer-forced extra segments.

Geometry only, not codeword/IQ recovery or proof of global multi-user admission.
"""
import argparse
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
from tools.oracle.engine.backends.wifi.he.ldpc.rate import layout


def generate():
    rows=['ru\tmcs\tnss\tdcm\tgroup\tinitial\tainit\tlocal_extra\tsymbols\tpadding\textra\twords\tblock\tshort\tpuncture\trepeat\tpayload\tavailable']
    for ru in (26,52,106,242):
        for nss in (1,2,4,8):
            for mcs in range(12):
                for dcm in ([0,1] if nss<=2 and mcs in (0,1,3,4) else [0]):
                    for group in ([1,2] if nss==1 and not dcm else [1]):
                        for initial in (group*k for k in (1,2,4,9,31,64,99,199)):
                            for padding in range(1,5):
                                natural=layout(mcs,nss,dcm,group,initial,padding,mu_tones=ru)
                                for forced in ([False] if natural[2] else [False,True]):
                                    result=layout(mcs,nss,dcm,group,initial,padding,mu_tones=ru,force_extra=forced)
                                    if result[8]<16 or result[0]>400:continue
                                    rows.append('\t'.join(map(str,[ru,mcs,nss,dcm,group,initial,padding,natural[2],*result])))
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    output=IQ_FIXTURES / 'he-mu-ldpc-layout.tsv'
    content=generate()
    if args.check:assert output.read_text()==content
    else:output.write_text(content)
    print(f'{len(content.splitlines())-1} independent MU LDPC layouts')
