"""Deterministic, network-free cross-crypto IPSec behavioral parity (interop).

Step 54-56 (oracle) prove that libcrafter-sealed ESP/AH/IKEv2 bytes equal the
Scapy-sealed bytes (byte parity). This module adds the *open*-direction interop
that the spec's "Behavioral parity" acceptance asks for: each implementation can
actually consume the packet the other sealed.

For every ESP suite (AES-GCM, AES-CBC + HMAC-SHA2-256-128, ChaCha20-Poly1305),
for AH (HMAC-SHA2-256-128 integrity), and for the IKEv2 SK (Encrypted) payload,
it asserts, with pinned keys/IV and documentation addresses, that:

* a **libcrafter-sealed** packet is opened by the **reference crypto** (Scapy's
  ``SecurityAssociation.decrypt`` for ESP/AH; pyca/cryptography's AEAD — the same
  primitive Scapy uses — for the SK payload) and the recovered plaintext matches;
* a **reference-sealed** packet is opened by **libcrafter** (the public
  ``ProtocolRegistry`` SA-decode API for ESP/AH; the public
  ``decode_sk_payload_with_sa`` for SK) and the recovered plaintext matches;
* a one-bit tamper fails open/verify in **both** directions (fail-closed).

The libcrafter half runs through the ``ipsec_interop`` oracle adapter binary; the
reference half runs in a ``uv`` subprocess that carries ``scapy`` + ``cryptography``
so the probe's own interpreter needs neither. Everything is offline: no provider,
no sockets, no live traffic — only documentation address space and pinned keys.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .report import REPO_ROOT


# Documentation address space only (RFC 5737 / RFC 3849).
_DOC_SRC_V4 = "192.0.2.10"
_DOC_DST_V4 = "198.51.100.20"
_DOC_SRC_V6 = "2001:db8::1"
_DOC_DST_V6 = "2001:db8::2"

# Pinned documentation key/salt/IV material. These are fixed repeated/sequential
# bytes — never real keys — so the sealed bytes are deterministic and a leak
# would surface as an obvious repeated-hex run.
_AES_KEY = "24" * 16
_GCM_SALT = "a1b2c3d4"
_AEAD_IV = "0102030405060708"
_CBC_KEY = "11" * 16
_CBC_IV = "000102030405060708090a0b0c0d0e0f"
_HMAC_KEY = "33" * 32
_CHACHA_KEY = "55" * 32
_CHACHA_SALT = "aabbccdd"
_CHACHA_IV = "1112131415161718"

# uv requirements for the reference-crypto subprocess (Scapy seals/opens ESP/AH;
# cryptography opens/seals the SK AEAD body — the primitive Scapy itself uses).
_SCAPY_REQUIREMENT = "scapy>=2.5,<3"
_CRYPTOGRAPHY_REQUIREMENT = "cryptography>=42,<46"


class IpsecInteropError(RuntimeError):
    """Raised when a cross-crypto interop assertion fails or a tool is missing."""


@dataclass
class InteropCase:
    """One pinned cross-crypto interop case (one suite, one protocol, one mode)."""

    name: str
    protocol: str  # "esp" | "ah" | "sk"
    suite: str  # "aes-gcm" | "aes-cbc-hmac" | "chacha20-poly1305" | "hmac-sha2-256-128"
    spi: int
    payload: str
    mode: str = "transport"
    ip_version: str = "ipv4"
    enc_key_hex: str = ""
    salt_hex: str = ""
    iv_hex: str = ""
    integ_key_hex: str = ""
    source: str = _DOC_SRC_V4
    destination: str = _DOC_DST_V4

    def to_operation(self, *, kind: str, wire_hex: str = "") -> dict[str, object]:
        """Render the JSON operation the libcrafter ``ipsec_interop`` bin reads."""

        operation: dict[str, object] = {
            "name": self.name,
            "kind": kind,
            "protocol": self.protocol,
            "suite": self.suite,
            "mode": self.mode,
            "spi": self.spi,
            "sequence": 1,
            "enc_key_hex": self.enc_key_hex,
            "salt_hex": self.salt_hex,
            "iv_hex": self.iv_hex,
            "integ_key_hex": self.integ_key_hex,
            "ip_version": self.ip_version,
            "source": self.source,
            "destination": self.destination,
            "payload": self.payload,
        }
        if wire_hex:
            operation["wire_hex"] = wire_hex
        return operation


def interop_cases() -> list[InteropCase]:
    """The pinned cross-crypto interop matrix: ESP suites x mode, AH, and SK."""

    return [
        InteropCase(
            name="esp-aes-gcm-transport",
            protocol="esp",
            suite="aes-gcm",
            spi=0x2100,
            payload="interop-esp-gcm",
            enc_key_hex=_AES_KEY,
            salt_hex=_GCM_SALT,
            iv_hex=_AEAD_IV,
        ),
        InteropCase(
            name="esp-aes-gcm-tunnel",
            protocol="esp",
            suite="aes-gcm",
            spi=0x2101,
            payload="interop-esp-gcm-tunnel",
            mode="tunnel",
            enc_key_hex=_AES_KEY,
            salt_hex=_GCM_SALT,
            iv_hex=_AEAD_IV,
        ),
        InteropCase(
            name="esp-aes-cbc-hmac-transport",
            protocol="esp",
            suite="aes-cbc-hmac",
            spi=0x2800,
            payload="interop-esp-cbc",
            enc_key_hex=_CBC_KEY,
            integ_key_hex=_HMAC_KEY,
            iv_hex=_CBC_IV,
        ),
        InteropCase(
            name="esp-chacha20-poly1305-transport",
            protocol="esp",
            suite="chacha20-poly1305",
            spi=0x3000,
            payload="interop-esp-chacha",
            enc_key_hex=_CHACHA_KEY,
            salt_hex=_CHACHA_SALT,
            iv_hex=_CHACHA_IV,
        ),
        InteropCase(
            name="ah-hmac-sha2-256-128-transport",
            protocol="ah",
            suite="hmac-sha2-256-128",
            spi=0x3100,
            payload="interop-ah",
            integ_key_hex=_HMAC_KEY,
        ),
        InteropCase(
            name="sk-aes-gcm",
            protocol="sk",
            suite="aes-gcm",
            spi=0x4400,
            payload="interop-sk-gcm",
            enc_key_hex=_AES_KEY,
            salt_hex=_GCM_SALT,
            iv_hex=_AEAD_IV,
        ),
    ]


@dataclass
class CaseResult:
    """The structured outcome of one interop case (both directions + tamper)."""

    name: str
    protocol: str
    suite: str
    mode: str
    libcrafter_to_reference: bool = False
    reference_to_libcrafter: bool = False
    tamper_detected_by_reference: bool = False
    tamper_detected_by_libcrafter: bool = False
    detail: dict[str, object] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return (
            self.libcrafter_to_reference
            and self.reference_to_libcrafter
            and self.tamper_detected_by_reference
            and self.tamper_detected_by_libcrafter
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "protocol": self.protocol,
            "suite": self.suite,
            "mode": self.mode,
            "passed": self.passed,
            "libcrafter_to_reference": self.libcrafter_to_reference,
            "reference_to_libcrafter": self.reference_to_libcrafter,
            "tamper_detected_by_reference": self.tamper_detected_by_reference,
            "tamper_detected_by_libcrafter": self.tamper_detected_by_libcrafter,
            "detail": self.detail,
        }


def run_interop(*, repo_root: Path | None = None) -> dict[str, object]:
    """Run the full cross-crypto interop matrix and return a structured report.

    Raises :class:`IpsecInteropError` only when a required tool (``cargo`` / ``uv``)
    is unavailable; a *failed assertion* is reported as ``passed: False`` in the
    returned report rather than raised, so a caller (the probe dry-run) can record
    the result deterministically and still surface a non-zero outcome to fix.
    """

    root = repo_root or REPO_ROOT
    cases = interop_cases()

    # libcrafter seals every case; the reference opens them (direction A).
    seal_results = _libcrafter_run(root, [case.to_operation(kind="seal") for case in cases])
    reference_seals = _reference_seal(root, cases)

    results: list[CaseResult] = []
    for case in cases:
        result = CaseResult(
            name=case.name, protocol=case.protocol, suite=case.suite, mode=case.mode
        )
        _evaluate_case(root, case, result, seal_results, reference_seals)
        results.append(result)

    passed = all(result.passed for result in results)
    return {
        "check": "ipsec-cross-crypto-interop",
        "passed": passed,
        "network_free": True,
        "deterministic": True,
        "reference_backend": "scapy+cryptography",
        "documentation_addresses": [
            _DOC_SRC_V4,
            _DOC_DST_V4,
            _DOC_SRC_V6,
            _DOC_DST_V6,
        ],
        "case_count": len(results),
        "passed_count": sum(1 for result in results if result.passed),
        "cases": [result.to_dict() for result in results],
    }


def _evaluate_case(
    root: Path,
    case: InteropCase,
    result: CaseResult,
    seal_results: dict[str, dict[str, object]],
    reference_seals: dict[str, dict[str, object]],
) -> None:
    """Fill ``result`` from the seal artifacts: both directions + tamper."""

    # Direction A: libcrafter sealed -> reference opens.
    libcrafter_sealed = seal_results.get(case.name, {})
    a_open = _reference_open(root, case, libcrafter_sealed)
    result.libcrafter_to_reference = bool(a_open.get("recovered_matches"))
    result.tamper_detected_by_reference = bool(a_open.get("tamper_detected"))

    # Direction B: reference sealed -> libcrafter opens.
    reference_sealed = reference_seals.get(case.name, {})
    b_open = _libcrafter_open(root, case, reference_sealed)
    result.reference_to_libcrafter = bool(b_open.get("recovered_matches"))
    result.tamper_detected_by_libcrafter = bool(b_open.get("tamper_detected"))

    result.detail = {
        "libcrafter_seal_self_check": bool(libcrafter_sealed.get("recovered_matches")),
        "reference_open": {
            "recovered_matches": result.libcrafter_to_reference,
            "tamper_detected": result.tamper_detected_by_reference,
        },
        "reference_seal_self_check": bool(reference_sealed.get("recovered_matches")),
        "libcrafter_open": {
            "recovered_matches": result.reference_to_libcrafter,
            "tamper_detected": result.tamper_detected_by_libcrafter,
        },
    }


# --------------------------------------------------------------------------- #
# libcrafter side: the ``ipsec_interop`` oracle adapter binary.
# --------------------------------------------------------------------------- #


def _libcrafter_run(root: Path, operations: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    """Run the libcrafter ``ipsec_interop`` bin and return results keyed by name."""

    binary = _ensure_ipsec_interop_binary(root)
    request = json.dumps({"operations": operations})
    completed = subprocess.run(
        [str(binary)],
        input=request,
        capture_output=True,
        text=True,
        cwd=str(root),
        check=False,
    )
    if completed.returncode != 0:
        raise IpsecInteropError(
            "libcrafter ipsec_interop binary failed: "
            f"rc={completed.returncode} stderr={completed.stderr.strip()}"
        )
    report = json.loads(completed.stdout)
    return {
        str(item.get("name")): item
        for item in report.get("results", [])
        if isinstance(item, dict)
    }


def _libcrafter_open(
    root: Path, case: InteropCase, reference_sealed: dict[str, object]
) -> dict[str, object]:
    """Open the reference-sealed bytes with libcrafter (clean + tampered)."""

    wire_hex = str(reference_sealed.get("open_input_hex", ""))
    if not wire_hex:
        return {"recovered_matches": False, "tamper_detected": False}

    clean = _libcrafter_run(root, [case.to_operation(kind="open", wire_hex=wire_hex)])
    clean_result = clean.get(case.name, {})

    tampered_hex = _flip_last_byte(wire_hex)
    tampered = _libcrafter_run(root, [case.to_operation(kind="open", wire_hex=tampered_hex)])
    tampered_result = tampered.get(case.name, {})
    # Fail-closed: a tampered packet must NOT open to the original plaintext.
    tamper_detected = not bool(tampered_result.get("ok")) or not bool(
        tampered_result.get("recovered_matches")
    )
    return {
        "recovered_matches": bool(clean_result.get("ok"))
        and bool(clean_result.get("recovered_matches")),
        "tamper_detected": tamper_detected,
    }


def _ensure_ipsec_interop_binary(root: Path) -> Path:
    """Locate (building if needed) the ``ipsec_interop`` oracle adapter binary."""

    for profile in ("debug", "release"):
        candidate = root / "target" / profile / "ipsec_interop"
        if candidate.exists():
            return candidate

    cargo = shutil.which("cargo")
    if cargo is None:
        raise IpsecInteropError("cargo is required to build the ipsec_interop interop binary")
    completed = subprocess.run(
        [cargo, "build", "-p", "oracle-adapters", "--bin", "ipsec_interop"],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise IpsecInteropError(
            "failed to build ipsec_interop binary: " f"{completed.stderr.strip()}"
        )
    candidate = root / "target" / "debug" / "ipsec_interop"
    if not candidate.exists():
        raise IpsecInteropError("ipsec_interop binary not found after build")
    return candidate


# --------------------------------------------------------------------------- #
# Reference side: Scapy (ESP/AH) + cryptography (SK), in a uv subprocess.
# --------------------------------------------------------------------------- #


def _reference_seal(root: Path, cases: list[InteropCase]) -> dict[str, dict[str, object]]:
    """Seal every case with the reference crypto and capture the open inputs."""

    request = {"action": "seal", "cases": [_reference_case_json(case) for case in cases]}
    return _reference_run(root, request)


def _reference_open(
    root: Path, case: InteropCase, libcrafter_sealed: dict[str, object]
) -> dict[str, object]:
    """Open libcrafter-sealed bytes with the reference crypto (clean + tampered)."""

    # ESP/AH expose ``wire_hex`` (the full L3 datagram); SK exposes ``sk_payload_hex``
    # (the standalone SK payload the reference AEAD opens).
    if case.protocol == "sk":
        sealed_hex = str(libcrafter_sealed.get("sk_payload_hex", ""))
    else:
        sealed_hex = str(libcrafter_sealed.get("wire_hex", ""))
    if not sealed_hex:
        return {"recovered_matches": False, "tamper_detected": False}

    request = {
        "action": "open",
        "case": _reference_case_json(case),
        "sealed_hex": sealed_hex,
        "tampered_hex": _flip_last_byte(sealed_hex),
    }
    report = _reference_run(root, request)
    return report.get(case.name, {})


def _reference_case_json(case: InteropCase) -> dict[str, object]:
    return {
        "name": case.name,
        "protocol": case.protocol,
        "suite": case.suite,
        "mode": case.mode,
        "ip_version": case.ip_version,
        "spi": case.spi,
        "sequence": 1,
        "enc_key_hex": case.enc_key_hex,
        "salt_hex": case.salt_hex,
        "iv_hex": case.iv_hex,
        "integ_key_hex": case.integ_key_hex,
        "source": case.source,
        "destination": case.destination,
        "payload": case.payload,
        "inner_src_v4": "192.0.2.71",
        "inner_dst_v4": "198.51.100.72",
        "inner_src_v6": "2001:db8::71",
        "inner_dst_v6": "2001:db8::72",
        "inner_sport": 40001,
        "inner_dport": 443,
    }


def _reference_run(root: Path, request: dict[str, object]) -> dict[str, dict[str, object]]:
    """Run the embedded reference-crypto script in a uv subprocess with scapy."""

    uv = shutil.which(os.environ.get("PROBE_UV", "uv"))
    if uv is None:
        raise IpsecInteropError("uv is required to run the reference IPSec crypto")
    completed = subprocess.run(
        [
            uv,
            "run",
            "--quiet",
            "--no-project",
            "--with",
            _SCAPY_REQUIREMENT,
            "--with",
            _CRYPTOGRAPHY_REQUIREMENT,
            "--",
            os.environ.get("PROBE_PYTHON", "python3"),
            "-c",
            _REFERENCE_SCRIPT,
        ],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        cwd=str(root),
        check=False,
        env={**os.environ, "UV_NO_PROGRESS": "1"},
    )
    if completed.returncode != 0:
        raise IpsecInteropError(
            "reference IPSec crypto subprocess failed: "
            f"rc={completed.returncode} stderr={completed.stderr.strip()}"
        )
    report = json.loads(completed.stdout)
    return {
        str(item.get("name")): item
        for item in report.get("results", [])
        if isinstance(item, dict)
    }


def _flip_last_byte(hex_string: str) -> str:
    """Flip the low bit of the final octet of a hex string (a one-bit tamper)."""

    if len(hex_string) < 2:
        return hex_string
    data = bytearray.fromhex(hex_string)
    data[-1] ^= 0x01
    return data.hex()


# The reference-crypto worker runs inside a uv subprocess that carries scapy +
# cryptography. It seals/opens ESP and AH with scapy.layers.ipsec.SecurityAssociation
# and seals/opens the IKEv2 SK AEAD body with pyca/cryptography (the same AEAD
# primitive scapy uses), entirely offline over documentation addresses.
_REFERENCE_SCRIPT = r"""
import json
import sys


def _scapy():
    from scapy.layers import ipsec as ips
    from scapy.layers.ipsec import SecurityAssociation, ESP, AH
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.all import conf
    conf.verb = 0
    return ips, SecurityAssociation, ESP, AH, IP, TCP, IPv6


_CRYPT_ALGO = {
    "aes-gcm": "AES-GCM",
    "chacha20-poly1305": "CHACHA20-POLY1305",
    "aes-cbc-hmac": "AES-CBC",
}
_AUTH_ALGO = {"hmac-sha2-256-128": "SHA2-256-128"}
_AEAD_ICV = {"AES-GCM": 16, "CHACHA20-POLY1305": 16}
_AEAD_SUITES = {"aes-gcm", "chacha20-poly1305"}


def _build_sa(case, ESP, AH, SecurityAssociation):
    proto = case["protocol"]
    suite = case["suite"]
    spi = int(case["spi"])
    if proto == "ah":
        return SecurityAssociation(
            AH, spi=spi, auth_algo="SHA2-256-128",
            auth_key=bytes.fromhex(case["integ_key_hex"]))
    crypt_algo = _CRYPT_ALGO[suite]
    kwargs = {"spi": spi, "crypt_algo": crypt_algo}
    if suite in _AEAD_SUITES:
        kwargs["crypt_key"] = bytes.fromhex(case["enc_key_hex"]) + bytes.fromhex(case["salt_hex"])
        kwargs["crypt_icv_size"] = _AEAD_ICV[crypt_algo]
    else:
        kwargs["crypt_key"] = bytes.fromhex(case["enc_key_hex"])
        kwargs["auth_algo"] = "SHA2-256-128"
        kwargs["auth_key"] = bytes.fromhex(case["integ_key_hex"])
    return SecurityAssociation(ESP, **kwargs)


def _outer_ip(case, IP, IPv6):
    if case["ip_version"] == "ipv6":
        return IPv6(src=case["source"], dst=case["destination"])
    return IP(src=case["source"], dst=case["destination"])


def _inner_cleartext(case, IP, TCP, IPv6):
    outer = _outer_ip(case, IP, IPv6)
    tcp = TCP(sport=int(case["inner_sport"]), dport=int(case["inner_dport"]))
    payload = case["payload"].encode()
    if case["mode"] == "tunnel":
        if case["ip_version"] == "ipv6":
            inner_ip = IPv6(src=case["inner_src_v6"], dst=case["inner_dst_v6"])
        else:
            inner_ip = IP(src=case["inner_src_v4"], dst=case["inner_dst_v4"])
        return inner_ip / tcp / payload
    return outer / tcp / payload


def _explicit_iv(case):
    if case["suite"] == "aes-cbc-hmac":
        return bytes.fromhex(case["iv_hex"])  # 16-octet CBC IV
    return bytes.fromhex(case["iv_hex"])  # 8-octet AEAD IV


def _esp_ah_seal(case, env):
    ips, SecurityAssociation, ESP, AH, IP, TCP, IPv6 = env
    sa = _build_sa(case, ESP, AH, SecurityAssociation)
    outer = _outer_ip(case, IP, IPv6)
    inner = _inner_cleartext(case, IP, TCP, IPv6)
    tunnel = outer if case["mode"] == "tunnel" else None
    if tunnel is not None:
        sa.tunnel_header = tunnel
    if case["protocol"] == "ah":
        sealed = sa.encrypt(inner, seq_num=1)
    else:
        sealed = sa.encrypt(inner, seq_num=1, iv=_explicit_iv(case))
    wire = bytes(sealed)
    # Self-check: the reference opens what it just sealed.
    recovered = _esp_ah_recover(case, env, wire)
    return {
        "name": case["name"],
        "open_input_hex": wire.hex(),
        "recovered_matches": recovered == case["payload"].encode(),
    }


def _esp_ah_recover(case, env, wire):
    from scapy.packet import Raw
    ips, SecurityAssociation, ESP, AH, IP, TCP, IPv6 = env
    sa = _build_sa(case, ESP, AH, SecurityAssociation)
    if case["mode"] == "tunnel":
        sa.tunnel_header = _outer_ip(case, IP, IPv6)
    pkt_cls = IPv6 if case["ip_version"] == "ipv6" else IP
    decoded = sa.decrypt(pkt_cls(wire))
    if TCP in decoded:
        return bytes(decoded[TCP].payload)
    # AH does not encrypt, so scapy verifies the ICV but leaves the protected
    # upper-layer data as a Raw blob under the IP header rather than re-dissecting
    # it. Re-parse that blob: tunnel mode wraps an inner IP datagram, transport
    # mode carries the upper-layer (TCP) data directly.
    if Raw not in decoded:
        return None
    blob = bytes(decoded[Raw].load)
    if case["mode"] == "tunnel":
        inner_cls = IPv6 if case["ip_version"] == "ipv6" else IP
        inner = inner_cls(blob)
        return bytes(inner[TCP].payload) if TCP in inner else None
    tcp = TCP(blob)
    return bytes(tcp.payload)


def _esp_ah_open(case, env, sealed_hex, tampered_hex):
    recovered = None
    try:
        recovered = _esp_ah_recover(case, env, bytes.fromhex(sealed_hex))
    except Exception:
        recovered = None
    tamper_detected = False
    try:
        tampered = _esp_ah_recover(case, env, bytes.fromhex(tampered_hex))
        tamper_detected = tampered != case["payload"].encode()
    except Exception:
        tamper_detected = True
    return {
        "name": case["name"],
        "recovered_matches": recovered == case["payload"].encode(),
        "tamper_detected": tamper_detected,
    }


def _aead(case):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
    key = bytes.fromhex(case["enc_key_hex"])
    salt = bytes.fromhex(case["salt_hex"])
    nonce = salt + bytes.fromhex(case["iv_hex"])
    if case["suite"] == "chacha20-poly1305":
        return ChaCha20Poly1305(key), nonce
    return AESGCM(key), nonce


def _sk_inner_plaintext(case):
    # The inner SK chain is one Nonce payload: 4-octet generic header + nonce data,
    # then 0 pad octets and a Pad Length octet (RFC 7296 section 3.14). libcrafter
    # uses next-payload 0, critical bit clear, length = 4 + len(data).
    data = case["payload"].encode()
    header = bytes([0, 0]) + (4 + len(data)).to_bytes(2, "big")
    inner = header + data
    return inner + bytes([0])  # zero pad octets, pad length 0


def _sk_seal(case):
    aead, nonce = _aead(case)
    plaintext = _sk_inner_plaintext(case)
    sealed = aead.encrypt(nonce, plaintext, b"")  # ciphertext || tag
    iv = bytes.fromhex(case["iv_hex"])
    # SK payload = generic header (next payload 41=Nonce, length) + IV || ct||tag.
    body = iv + sealed
    gen = bytes([41, 0]) + (4 + len(body)).to_bytes(2, "big")
    sk_payload = gen + body
    recovered = _sk_recover(case, sk_payload)
    return {
        "name": case["name"],
        "open_input_hex": sk_payload.hex(),
        "recovered_matches": recovered == case["payload"].encode(),
    }


def _sk_recover(case, sk_payload):
    aead, nonce = _aead(case)
    body = sk_payload[4:]
    iv = bytes.fromhex(case["iv_hex"])
    ct_and_tag = body[len(iv):]
    plaintext = aead.decrypt(nonce, ct_and_tag, b"")
    # Strip the Pad Length octet and its padding, then the inner generic header.
    pad_len = plaintext[-1]
    inner = plaintext[: len(plaintext) - 1 - pad_len]
    return inner[4:]


def _sk_open(case, sealed_hex, tampered_hex):
    recovered = None
    try:
        recovered = _sk_recover(case, bytes.fromhex(sealed_hex))
    except Exception:
        recovered = None
    tamper_detected = False
    try:
        tampered = _sk_recover(case, bytes.fromhex(tampered_hex))
        tamper_detected = tampered != case["payload"].encode()
    except Exception:
        tamper_detected = True
    return {
        "name": case["name"],
        "recovered_matches": recovered == case["payload"].encode(),
        "tamper_detected": tamper_detected,
    }


def main():
    request = json.load(sys.stdin)
    action = request["action"]
    results = []
    if action == "seal":
        env = _scapy()
        for case in request["cases"]:
            if case["protocol"] == "sk":
                results.append(_sk_seal(case))
            else:
                results.append(_esp_ah_seal(case, env))
    elif action == "open":
        case = request["case"]
        if case["protocol"] == "sk":
            results.append(_sk_open(case, request["sealed_hex"], request["tampered_hex"]))
        else:
            env = _scapy()
            results.append(
                _esp_ah_open(case, env, request["sealed_hex"], request["tampered_hex"])
            )
    json.dump({"results": results}, sys.stdout)


main()
"""


def _main() -> int:
    """Stand-alone entrypoint: run the interop matrix and print the JSON report."""

    report = run_interop()
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(_main())
