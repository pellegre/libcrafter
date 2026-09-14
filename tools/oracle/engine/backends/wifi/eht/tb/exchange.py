"""Independent legacy Trigger and EHT20 TB BCC response exchanges."""

import argparse
import hashlib
import math
import struct
import tempfile
import zlib
from pathlib import Path

import tools.oracle.engine.backends.wifi.ofdm.base as base
from tools.oracle.engine.backends.wifi.eht.tb.data import waveform
from tools.oracle.engine.backends.wifi.he.tb.exchange.base import legacy
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES


def trigger_frame(length, gi_ltf, ltf_code, raw, mcs, reuse, duration):
    common = length << 4
    common |= gi_ltf << 20
    common |= ltf_code << 23
    common |= 127 << 56
    special = 2007 | (reuse[0] << 17) | (reuse[1] << 21) | (4095 << 25)
    user = 1 | (raw << 12) | (mcs << 21)
    mac = struct.pack("<HH", 0x24, duration)
    mac += bytes.fromhex("ffffffffffff00005e005301")
    mac += common.to_bytes(8, "little")
    mac += special.to_bytes(5, "little") + b"\x00"
    mac += user.to_bytes(5, "little") + b"\x00"
    mac += b"\xff\x0f"
    return mac + struct.pack("<I", zlib.crc32(mac))


def generate(out):
    cases = (
        ("clean", 0, 0, 1, 0),
        ("clean", 80, 4, 2, 1),
        ("clean", 140, 9, 1, 2),
        ("clean", 166, 15, 2, 4),
        ("bad-fcs", 0, 0, 1, 0),
        ("wrong-reuse", 80, 4, 2, 1),
        ("wrong-length", 140, 9, 1, 2),
        ("expired", 166, 15, 2, 4),
        ("no-trigger", 0, 0, 1, 0),
    )
    rows = [
        "name\tcase\traw\tmcs\tgi_ltf\tltf_code\ttrigger_start\ttb_start\ttrigger\tresponse\tsamples\tsha256"
    ]
    for number, (kind, raw, mcs, gi_ltf, ltf_code) in enumerate(cases):
        case = 0xE7300 + number
        iq, _, reuse, _, _, _, _, length, psdu = waveform(
            case, raw, mcs, gi_ltf, ltf_code, False
        )
        response_length = ((psdu[0] >> 2) & 3) << 12
        response_length |= psdu[1] << 4
        response_length |= psdu[0] >> 4
        response = psdu[4 : 4 + response_length]
        gap = 320
        duration = math.ceil((gap + len(iq) // 2) / 20) + 32
        if kind == "expired":
            duration = 4
            gap = 600
        trigger_reuse = reuse
        trigger_length = length
        if kind == "wrong-reuse":
            trigger_reuse = (reuse[0] ^ 1, reuse[1])
        if kind == "wrong-length":
            trigger_length += 3
        trigger = trigger_frame(
            trigger_length, gi_ltf, ltf_code, raw, mcs, trigger_reuse, duration
        )
        if kind == "bad-fcs":
            trigger = trigger[:-1] + bytes((trigger[-1] ^ 1,))
        ap = legacy(trigger)
        peak = max(max(abs(value.real), abs(value.imag)) for value in ap)
        ap_iq = base.quantize([0j] * 64 + ap, scale=min(100, 112 / peak))
        if kind == "no-trigger":
            ap_iq = bytearray(len(ap_iq))
        trace = ap_iq + bytearray(gap * 2) + iq + bytearray(512)
        trigger_start = 64
        tb_start = len(ap_iq) // 2 + gap + 37
        success = kind == "clean"
        name = f"eht-tb-exchange-{number:02d}-{kind}"
        (out / f"{name}.cs8").write_bytes(trace)
        rows.append(
            "\t".join(
                map(
                    str,
                    (
                        name,
                        kind,
                        raw,
                        mcs,
                        gi_ltf,
                        ltf_code,
                        trigger_start,
                        tb_start,
                        trigger.hex() if kind not in ("bad-fcs", "no-trigger") else "-",
                        response.hex() if success else "-",
                        len(trace) // 2,
                        hashlib.sha256(trace).hexdigest(),
                    ),
                )
            )
        )
    (out / "eht-tb-exchange-index.tsv").write_text("\n".join(rows) + "\n")
    print(f"{len(rows) - 1} independent EHT20 TB exchanges")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        with tempfile.TemporaryDirectory(prefix="eht-tb-exchange-") as temporary:
            generated = Path(temporary)
            generate(generated)
            for path in generated.iterdir():
                assert path.read_bytes() == (OUT / path.name).read_bytes(), path.name
    else:
        generate(OUT)
