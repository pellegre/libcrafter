"""Forward TB timelines, IEEE802.11ax-2021 9.3.1.22.1 and Eq27-119..122.

Build each symbol's temporal position, then signal that duration in L-SIG.
This does not call or invert libcrafter's receiver timing implementation.
"""
import argparse
from fractions import Fraction as F
import hashlib
from math import ceil
from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


def vectors():
    rows = ["gi_code\tltf_code\tdoppler\tstbc\tsymbols\tpe\tlsig\tb\tnltf\tmidambles\tstart\tend\tpacket\tsignaled\toffsets_sha256"]
    for gi_code, size, gi in [(0, 1, 1600), (1, 2, 1600), (2, 4, 3200)]:
        for doppler in [0, 1]:
            layouts = [(0, 1, 10), (1, 2, 10), (2, 4, 10), (4, 1, 20), (5, 2, 20), (6, 4, 20)] if doppler else [(i, n, 0) for i, n in enumerate([1, 2, 4, 6, 8])]
            for code, nltf, period in layouts:
                training = nltf * (F(16, 5) * size + F(gi, 1000))
                symbol = F(64, 5) + F(gi, 1000)
                for stbc in ([0, 1] if nltf >= 2 else [0]):
                    for count in [1, 2, 9, 10, 11, 12, 19, 20, 21, 22, 39, 40, 41, 99, 100, 399, 400]:
                        if stbc and count % 2:
                            continue
                        # Legacy20us + RL-SIG4us + SIG-A8us + TB STF8us.
                        clock = 40 + training
                        start = int(clock * 20)
                        offsets = []
                        midambles = 0
                        for i in range(count):
                            offsets.append(int(clock * 20))
                            clock += symbol
                            if period and (i + 1) % period == 0 and count - i - 1 >= 2:
                                clock += training
                                midambles += 1
                        end = int(clock * 20)
                        digest = hashlib.sha256(b"".join(n.to_bytes(4, "little") for n in offsets)).hexdigest()
                        for pe in [0, 4, 8, 12, 16]:
                            packet = clock + pe
                            units = ceil((packet - 20) / 4)
                            lsig = 3 * units - 5  # TB m=2.
                            if lsig > 4095:
                                continue
                            b = int(pe + 4 * units - (packet - 20) >= symbol)
                            rows.append("\t".join(map(str, [gi_code, code, doppler, stbc, count, pe * 20, lsig, b, nltf, midambles, start, end, int(packet * 20), (20 + 4 * units) * 20, digest])))
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    path = IQ_FIXTURES / "he-tb-timing.tsv"
    content = vectors()
    if args.write:
        path.write_text(content)
    else:
        assert path.read_text() == content
    print(f"{len(content.splitlines()) - 1} independent TB timelines")
