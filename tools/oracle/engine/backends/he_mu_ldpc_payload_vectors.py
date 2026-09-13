"""Independent MU LDPC payloads, ax-2021 27.3.12.4/5; not MAC/IQ packets."""
import argparse
from pathlib import Path
import ofdm_vectors as base
from he_capacity_vectors import BPS
from he_ldpc_rate_vectors import layout, encode_information, damage_codeword


def generate():
    rows=['ru\tmcs\tdcm\tgroup\tsymbols\tpadding\textra\tstatus\tpsdu\tcoded']
    def emit(ru,mcs,dcm,group,padding,forced=False,status='ok'):
        sizing=layout(mcs,1,dcm,group,4*group,padding,mu_tones=ru,force_extra=forced)
        symbols,pad,extra=sizing[:3];payload=sizing[8]
        if payload<16:return
        octets,phy=divmod(payload-16,8)
        psdu=bytes((n*37+93+13*mcs)%256 for n in range(octets))
        service=[0]*16
        if status=='service':service[7]=1
        bits=base.scramble(service+base.bits(psdu)+[n%2 for n in range(phy)],93)
        coded=encode_information(bits,sizing,mcs)
        if status=='damage':coded=damage_codeword(coded,sizing,sizing[3]-1)
        cbps={26:24,52:48,106:102,242:234}[ru]*BPS[mcs]//(1+dcm)
        short=(2 if ru==26 and dcm else {26:6,52:12,106:24,242:60}[ru]//(1+dcm))*BPS[mcs]
        last=cbps if pad==4 else pad*short
        output=[];cursor=0
        for symbol in range(symbols):
            keep=last if symbol>=symbols-group else cbps
            output+=coded[cursor:cursor+keep];cursor+=keep
            output += [(symbol+n)%2 for n in range(cbps-keep)]
        assert cursor==len(coded)
        rows.append('\t'.join(map(str,[ru,mcs,dcm,group,symbols,pad,int(extra),status,psdu.hex(),''.join(map(str,output))])))
    for ru in (26,52,106,242):
        for mcs in range(12):
            for dcm in ([0,1] if mcs in (0,1,3,4) else [0]):
                for group in ([1,2] if not dcm else [1]):
                    for padding in (1,3,4):
                        natural=layout(mcs,1,dcm,group,4*group,padding,mu_tones=ru)
                        emit(ru,mcs,dcm,group,padding)
                        if not natural[2]:emit(ru,mcs,dcm,group,padding,True)
        emit(ru,0,0,1,1,status='service')
    emit(242,11,0,1,4,status='damage')
    return '\n'.join(rows)+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check',action='store_true');args=parser.parse_args()
    output=Path(__file__).resolve().parents[4]/'crafter/tests/fixtures/iq/he-mu-ldpc-payload.tsv'
    content=generate()
    if args.check:assert output.read_text()==content
    else:output.write_text(content)
    print(f'{len(content.splitlines())-1} independent MU LDPC payloads')
