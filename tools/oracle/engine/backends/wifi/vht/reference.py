"""Independent radiotap VHT eligibility/known-field fixtures.

Authority: radiotap.org/fields/VHT.html and fields/A-MPDU%20status.html.
Eligibility is the implemented VHT20 SU NSS1 BCC/LDPC subset, not all valid VHT.
"""
import argparse
import json
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES
import struct

OUT = IQ_FIXTURES / 'vht-reference-index.tsv'


def generate():
    rows = ['name\tvht_hex\tampdu_hex\texpected_json']

    def emit(name, known=511, flags=0, bandwidth=0, users=(0x81, 0, 0, 0),
             coding=0, group=63, aid=0, ampdu_flags=None):
        field = struct.pack('<HBB4BBBH', known, flags, bandwidth, *users, coding, group, aid)
        status = None if ampdu_flags is None else struct.pack('<IHBB', 0x12345678, ampdu_flags, 0xa5, 0)
        observed = lambda bit, value: value if known & bit else None
        stbc = observed(1, bool(flags & 1))
        short = bool(flags & 4)
        disambiguation = observed(8, bool(flags & 8))
        extra = observed(16, bool(flags & 16))
        observed_group = observed(128, group)
        observed_aid = observed(256, aid)
        requirements = [
            known & 0x44 == 0x44, bandwidth & 31 == 0,
            users[0] & 15 == 1, all(user & 15 == 0 for user in users[1:]),
            users[0] >> 4 <= 8,
            observed_group in (None, 0, 63), observed_aid is None or observed_aid <= 511,
            short or disambiguation is not True, bool(coding & 1) or extra is not True,
            stbc is not True or disambiguation is not True,
            ampdu_flags is None or (ampdu_flags & 0x10 == 0 and ampdu_flags & 3 != 3),
        ]
        expected = None
        if all(requirements):
            expected = dict(
                bandwidth_mhz=20, spatial_streams=1, ldpc=bool(coding & 1),
                mcs=users[0] >> 4, short_gi=short, stbc=stbc,
                group_id=observed_group, partial_aid=observed_aid,
                beamformed=observed(32, bool(flags & 32)),
                short_gi_disambiguation=disambiguation,
                txop_ps_not_allowed=observed(2, bool(flags & 2)),
                ldpc_extra_symbol=extra,
                eof=None if ampdu_flags is None or not ampdu_flags & 128 else bool(ampdu_flags & 64),
                ampdu_reference=None if status is None else 0x12345678,
                delimiter_offset=None,
            )
        rows.append('\t'.join((name, field.hex(), '' if status is None else status.hex(),
                               json.dumps(expected, sort_keys=True, separators=(',', ':')))))

    for known in range(512):
        for flags in (0, 4, 12, 32, 1, 16, 0x3b, 0xff):
            for coding in (0xfe,0xff):
                emit(f'known-{known}-flags-{flags}-coding-{coding}', known, flags, 0xe0,
                     ((known % 9) << 4 | 1, 0xf0, 0xf0, 0xf0), coding,
                     63 if known & 128 else 201, 511 if known & 256 else 65535)
    for flags in range(256):
        emit(f'ampdu-{flags}', ampdu_flags=flags)
    for mcs in range(16):
        for nss in range(16):
            emit(f'mcs-{mcs}-nss-{nss}', users=(mcs << 4 | nss, 0, 0, 0))
    for bandwidth in range(32):
        emit(f'bandwidth-{bandwidth}', bandwidth=bandwidth)
    for group in range(256):
        emit(f'group-{group}', group=group)
    for coding in range(256):
        emit(f'coding-{coding}', coding=coding)
    for index in range(1, 4):
        users = [0x81, 0, 0, 0]
        users[index] = 1
        emit(f'additional-user-{index}', users=users)
    emit('unused-known-bits', known=65535)
    emit('invalid-partial-aid', aid=512)
    return '\n'.join(rows) + '\n'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    content = generate()
    if args.check:
        assert OUT.read_text() == content
    else:
        OUT.write_text(content)
    print(f'{len(content.splitlines()) - 1} independent VHT reference metadata cases verified')
