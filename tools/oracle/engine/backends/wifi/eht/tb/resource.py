"""Independent EHT20 Trigger RU/MRU allocation vectors.

The table is transcribed from IEEE 802.11be-2024 Table 9-53a. It does not
import the production Rust allocation implementation.
"""

import argparse

from tools.oracle.engine.backends.wifi.paths import IQ_FIXTURES


OUT = IQ_FIXTURES / "eht-tb-resource-index.tsv"

RESOURCES = {
    **{code: ((26, code + 1),) for code in range(9)},
    **{code: ((52, code - 36),) for code in range(37, 41)},
    **{code: ((106, code - 52),) for code in range(53, 55)},
    61: ((242, 1),),
    70: ((26, 2), (52, 2)),
    71: ((52, 2), (26, 5)),
    72: ((52, 3), (26, 8)),
    82: ((106, 1), (26, 5)),
    83: ((26, 5), (106, 2)),
}


def generate():
    rows = ["raw\tstatus\tcomponents"]
    for raw in range(256):
        components = RESOURCES.get(raw >> 1) if raw & 1 == 0 else None
        if components is None:
            rows.append(f"{raw}\tunsupported\t-")
        else:
            encoded = "+".join(f"{size}:{index}" for size, index in components)
            rows.append(f"{raw}\tok\t{encoded}")
    return "\n".join(rows) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    output = generate()
    if args.write:
        OUT.write_text(output)
    else:
        assert OUT.read_text() == output, "EHT20 Trigger RU inventory differs"
    print("256 EHT20 Trigger RU allocation values verified")
