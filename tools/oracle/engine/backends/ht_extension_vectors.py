"""Independent HT20 DATA after extension training, IEEE802.11-2020 19.3.9.4.6.

Direct spatial mapping separates DATA dimensions from additional sounding
dimensions. This is an offline receive oracle, not production multi-chain TX.
"""
import argparse
import cmath
import hashlib
import tempfile
from pathlib import Path
import ht_ampdu_vectors as aggregate
import ht_stbc_vectors as stbc_iq
import ofdm_vectors as base


def received(chains, impaired):
    gains=[1,0.45+0.2j,-0.3+0.15j,0.15-0.25j]
    delayed=[0.2j,-0.1,0.08+0.04j,-0.05j]
    result=[]
    for n,values in enumerate(zip(*chains)):
        value=sum(gain*sample for gain,sample in zip(gains,values))
        if impaired:
            value+=sum(delayed[j]*chain[n-j-2] for j,chain in enumerate(chains) if n>=j+2)
            value*=cmath.exp(1j*(0.7+0.018*n))
        result.append(value)
    return base.quantize(result)


def configurations():
    for stbc in [False,True]:
        for extension in range(1,4-int(stbc)):
            for greenfield,guard in [(False,8),(False,16),(True,16)]:
                yield stbc,extension,greenfield,guard


def name(mcs,coding,stbc,extension,greenfield,guard):
    return f'ht-extension-{mcs}-{"ldpc" if coding else "bcc"}-{"gf" if greenfield else "mf"}-gi{guard*50}-stbc{int(stbc)}-ess{extension}'


def generate(out):
    out.mkdir(parents=True,exist_ok=True)
    rows=['name\tmcs\tguard_samples\tsymbols\tpsdu_hex\tsha256\tsamples\tdata_start\tframe_end\tldpc\tgreenfield\tstbc\textension']
    for stbc,extension,greenfield,guard in configurations():
        for mcs in range(8):
            for coding in [False,True]:
                for extra in ([44,4039] if mcs in [0,7] else [44]):
                    psdu=base.frame(extra)
                    chains,symbols,start,end=stbc_iq.waveform(psdu,mcs,guard,coding,greenfield,
                                                           extension=extension,stbc=stbc)
                    nsts=1+int(stbc)
                    count=[0,1,2,4][extension]
                    assert start==37+(480 if greenfield else 720)+80*(int(stbc)+count)
                    # Extra dimensions are silent during DATA, but genuinely
                    # excited in the extension portion. DATA dimensions are
                    # silent during that separate sounding portion.
                    for chain in chains[:nsts]:
                        assert all(v==0 for v in chain[start-80*count:start])
                    for chain in chains[nsts:]:
                        assert any(v!=0 for v in chain[start-80*count:start])
                        assert all(v==0 for v in chain[start:end])
                    for impaired in ([False,True] if extra==44 else [True]):
                        iq=received(chains,impaired)
                        label=name(mcs,coding,stbc,extension,greenfield,guard)+f'-len{len(psdu)}-{"offset" if impaired else "clean"}'
                        (out/f'{label}.cs8').write_bytes(iq)
                        rows.append('\t'.join(map(str,[label,mcs,guard,symbols,psdu.hex(),hashlib.sha256(iq).hexdigest(),
                                                          len(iq)//2,start,end,int(coding),int(greenfield),int(stbc),extension])))
    assert len(rows)==541
    (out/'ht-extension-index.tsv').write_text('\n'.join(rows)+'\n')
    aggregated=['name\tmcs\tguard_samples\tldpc\tpsdu_hex\tframe_offsets\tmpdu_hex\tsha256\tframe_end\tstbc\textension\tgreenfield']
    cases=[(mcs,coding,stbc,extension,gf,guard,None) for stbc,extension,gf,guard in configurations()
           for mcs in [0,7] for coding in [False,True]]
    cases += [(3,True,True,2,False,8,'damaged_codeword'),(3,True,False,3,True,16,'damaged_codeword')]
    for mcs,coding,stbc,extension,greenfield,guard,fault in cases:
        frames=[base.frame(1278),base.frame(44)] if fault else [base.frame(0)]*2
        psdu,offsets=aggregate.ampdu.aggregate(frames)
        chains,_,_,end=stbc_iq.waveform(psdu,mcs,guard,coding,greenfield,aggregation=True,
                                       fault=fault,extension=extension,stbc=stbc)
        if fault: frames,offsets=frames[1:],offsets[1:]
        iq=received(chains,False)
        label=name(mcs,coding,stbc,extension,greenfield,guard).replace('ht-extension-','ht-extension-ampdu-')
        if fault: label+='-'+fault
        (out/f'{label}.cs8').write_bytes(iq)
        aggregated.append('\t'.join(map(str,[label,mcs,guard,int(coding),psdu.hex(),','.join(map(str,offsets)),
                                              ','.join(f.hex() for f in frames),hashlib.sha256(iq).hexdigest(),end,
                                              int(stbc),extension,int(greenfield)])))
    assert len(aggregated)==63
    (out/'ht-extension-ampdu-index.tsv').write_text('\n'.join(aggregated)+'\n')
    print('540 complete and 62 aggregate HT20 extension-training waveforms verified')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix='ht-extension-check-') as temporary:
            out=Path(temporary)
            generate(out)
            for file in out.iterdir():
                assert file.read_bytes()==(base.OUT/file.name).read_bytes(),file.name
    else:
        generate(base.OUT)
