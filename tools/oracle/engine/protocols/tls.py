"""Generator-stage sampler plugin for the TLS layer.

TLS oracle generation is packet-layer only: it emits deterministic record,
handshake, and extension field plans over documentation-safe TCP stacks. Endpoint
state, transcript hashing, key schedules, certificate validation, decryption, and
TCP stream reassembly stay out of scope. Backend byte materialization is added by
the Scapy/Wireshark TLS adapter steps; this plugin owns generator plans.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from ..model import JSONObject
from ..sampling import _SKIP_FIELD, _SamplingContext
from .base import ProtocolSampler, register


TLS_PORT_HTTPS = 443

_SUPPORTED_FIELDS = frozenset(
    {
        "records",
        "record_content_type",
        "record_legacy_version",
        "record_length",
        "record_fragment_hex",
        "record_body_kind",
        "handshake_messages",
        "handshake_type",
        "handshake_length",
        "hello_random",
        "session_id",
        "cipher_suites",
        "compression_methods",
        "extensions",
        "extension_type",
        "extension_body_hex",
        "alert_level",
        "alert_description",
        "change_cipher_spec",
        "heartbeat_message_type",
        "application_data_hex",
        "raw_preservation",
    }
)

_TLS_FEATURES = frozenset({"tls_records", "tls_handshake", "tls_extensions"})

_CLIENT_RANDOM_12 = "12" * 32
_CLIENT_RANDOM_13 = "13" * 32
_SERVER_RANDOM_12 = "22" * 32
_SERVER_RANDOM_13 = "23" * 32


def _sample(
    ctx: _SamplingContext,
    field_name: str,
    domain: object,
    *,
    field_spec: Mapping[str, object],
    current_fields: Mapping[str, object],
) -> object:
    del domain, field_spec, current_fields
    fields = _tls_fields_for_case(ctx.case)
    return fields.get(field_name, _SKIP_FIELD)


def _handles_feature(feature: str) -> bool:
    return feature in _TLS_FEATURES


def _apply_behavior(
    fields: dict[str, JSONObject],
    *,
    stack: Sequence[str],
    feature: str,
    case: str,
    behavior: str,
    grammar: JSONObject | None = None,
) -> None:
    del feature, behavior, grammar
    fields["tls"] = _tls_fields_for_case(case)
    _apply_tls_transport_defaults(fields, stack=stack)


def _tls_fields_for_case(case: str) -> JSONObject:
    key = case.replace("_", "-")
    if key in {"tls-record-client-hello", "tls-handshake-client-hello-tls13"}:
        return _fields_from_records([_client_hello_record(tls13=True)])
    if key == "tls-handshake-client-hello-tls12":
        return _fields_from_records([_client_hello_record(tls13=False)])
    if key in {"tls-record-alert", "tls-alert"}:
        return _fields_from_records([_alert_record(level="fatal", description="decode_error")])
    if key == "tls-record-change-cipher-spec":
        return _fields_from_records([_change_cipher_spec_record()])
    if key == "tls-record-application-data-opaque":
        return _fields_from_records([_application_data_record("deadbeef")])
    if key == "tls-record-unknown-content-type":
        return _fields_from_records([_unknown_record()])
    if key == "tls-stacked-records":
        return _fields_from_records(
            [
                _change_cipher_spec_record(),
                _alert_record(level="warning", description="close_notify"),
                _application_data_record("dead"),
            ]
        )
    if key == "tls-record-explicit-length-override":
        return _fields_from_records([_application_data_record("aa", declared_length=0)])
    if key == "tls-handshake-server-hello-tls12":
        return _fields_from_records([_server_hello_record(tls13=False)])
    if key == "tls-handshake-server-hello-tls13":
        return _fields_from_records([_server_hello_record(tls13=True)])
    if key == "tls-handshake-hello-retry-request":
        return _fields_from_records([_hello_retry_request_record()])
    if key == "tls-handshake-encrypted-extensions-empty":
        return _fields_from_records([_handshake_record([_encrypted_extensions([])])])
    if key == "tls-handshake-encrypted-extensions-unknown":
        return _fields_from_records(
            [
                _handshake_record(
                    [
                        _encrypted_extensions(
                            [
                                _extension(
                                    "application_layer_protocol_negotiation",
                                    body_hex="0003026832",
                                ),
                                _extension(type_raw=0xBEEF, body_hex="dead"),
                            ]
                        )
                    ]
                )
            ]
        )
    if key == "tls-handshake-certificate-tls12":
        return _fields_from_records([_handshake_record([_certificate(tls13=False)])])
    if key == "tls-handshake-certificate-tls13":
        return _fields_from_records([_handshake_record([_certificate(tls13=True)])])
    if key == "tls-handshake-certificate-request-tls12":
        return _fields_from_records([_handshake_record([_certificate_request(tls13=False)])])
    if key == "tls-handshake-certificate-request-tls13":
        return _fields_from_records([_handshake_record([_certificate_request(tls13=True)])])
    if key == "tls-handshake-certificate-verify":
        return _fields_from_records([_handshake_record([_certificate_verify()])])
    if key == "tls-handshake-finished":
        return _fields_from_records([_handshake_record([_finished()])])
    if key == "tls-handshake-new-session-ticket-tls12":
        return _fields_from_records([_handshake_record([_new_session_ticket(tls13=False)])])
    if key == "tls-handshake-new-session-ticket-tls13":
        return _fields_from_records([_handshake_record([_new_session_ticket(tls13=True)])])
    if key == "tls-handshake-key-update":
        return _fields_from_records([_handshake_record([_key_update()])])
    if key == "tls-handshake-end-of-early-data":
        return _fields_from_records([_handshake_record([_end_of_early_data()])])
    if key == "tls-handshake-unknown-preservation":
        return _fields_from_records([_handshake_record([_unknown_handshake()])])
    if key.startswith("tls-extension-"):
        return _fields_from_records([_extension_case_record(key)])
    return _fields_from_records([_client_hello_record(tls13=True)])


def _fields_from_records(records: list[JSONObject]) -> JSONObject:
    fields: JSONObject = {"records": records}
    first = records[0] if records else {}
    content_type = first.get("content_type")
    if isinstance(content_type, str):
        fields["record_content_type"] = content_type
    elif isinstance(first.get("content_type_raw"), int):
        fields["record_content_type"] = {"raw": first["content_type_raw"]}
    fields["record_legacy_version"] = first.get("legacy_record_version", 0x0303)
    fields["record_length"] = first.get("declared_length", "derived")
    fields["record_fragment_hex"] = first.get("fragment_hex", "")
    fields["record_body_kind"] = first.get("body_kind", _record_body_kind(first))

    messages = first.get("handshake_messages")
    if isinstance(messages, list):
        fields["handshake_messages"] = messages
        if messages:
            first_message = messages[0]
            if isinstance(first_message, Mapping):
                fields["handshake_type"] = first_message.get("type", "unknown_preserved")
                fields["handshake_length"] = first_message.get("declared_length", "derived")
                _copy_if_present(fields, first_message, "hello_random", "random_hex")
                _copy_if_present(fields, first_message, "session_id", "session_id_hex")
                _copy_if_present(fields, first_message, "cipher_suites", "cipher_suites")
                _copy_if_present(fields, first_message, "compression_methods", "compression_methods_hex")
                extensions = first_message.get("extensions")
                if isinstance(extensions, list):
                    fields["extensions"] = extensions
                    _copy_first_extension(fields, extensions)

    if first.get("content_type") == "alert":
        alert = first.get("alert")
        if isinstance(alert, Mapping):
            fields["alert_level"] = alert.get("level")
            fields["alert_description"] = alert.get("description")
    if first.get("content_type") == "change_cipher_spec":
        fields["change_cipher_spec"] = first.get("value", 1)
    if first.get("content_type") == "application_data":
        fields["application_data_hex"] = first.get("fragment_hex", "")
    if "raw_fragment_hex" in first:
        fields["raw_preservation"] = first["raw_fragment_hex"]
    return fields


def _copy_if_present(
    fields: JSONObject,
    source: Mapping[str, object],
    dest_key: str,
    source_key: str,
) -> None:
    if source_key in source:
        fields[dest_key] = source[source_key]  # type: ignore[assignment]


def _copy_first_extension(fields: JSONObject, extensions: list[object]) -> None:
    if not extensions or not isinstance(extensions[0], Mapping):
        return
    extension = extensions[0]
    extension_type = extension.get("type")
    if isinstance(extension_type, str):
        fields["extension_type"] = extension_type
    elif isinstance(extension.get("type_raw"), int):
        fields["extension_type"] = {"raw": extension["type_raw"]}
    if "body_hex" in extension:
        fields["extension_body_hex"] = extension["body_hex"]  # type: ignore[assignment]


def _record_body_kind(record: Mapping[str, object]) -> str:
    content_type = record.get("content_type")
    if content_type in {"handshake", "alert", "change_cipher_spec", "application_data", "heartbeat"}:
        return str(content_type)
    return "opaque_raw"


def _client_hello_record(*, tls13: bool, extensions: list[JSONObject] | None = None) -> JSONObject:
    if extensions is None:
        extensions = _client_hello_extensions(tls13=tls13)
    message: JSONObject = {
        "type": "client_hello",
        "legacy_version": 0x0303,
        "random_hex": _CLIENT_RANDOM_13 if tls13 else _CLIENT_RANDOM_12,
        "session_id_hex": "131415161718191a1b1c1d1e" if tls13 else "12131415",
        "cipher_suites": [0x1301, 0x1303] if tls13 else [0xC02B, 0xC02F],
        "compression_methods_hex": "00",
        "extensions": extensions,
    }
    return _handshake_record([message])


def _client_hello_extensions(*, tls13: bool) -> list[JSONObject]:
    extensions = [
        _extension("server_name", host_names=["tls13.client.example.test" if tls13 else "tls12.client.example.test"]),
        _extension("application_layer_protocol_negotiation", protocols=["h2", "http/1.1"]),
    ]
    if tls13:
        extensions.append(_extension("supported_versions", context="client_hello", versions=[0x0304, 0x0303]))
    extensions.extend(
        [
            _extension("supported_groups", named_groups=[0x001D, 0x0017] if tls13 else [0x0017, 0x001D]),
            _extension("signature_algorithms", signature_schemes=[0x0807, 0x0804, 0x0403] if tls13 else [0x0403, 0x0804]),
        ]
    )
    if tls13:
        extensions.append(_extension("key_share", context="client_hello", shares=[{"group": 0x001D, "key_exchange_hex": "44" * 32}]))
    return extensions


def _server_hello_record(*, tls13: bool) -> JSONObject:
    message: JSONObject = {
        "type": "server_hello",
        "legacy_version": 0x0303,
        "random_hex": _SERVER_RANDOM_13 if tls13 else _SERVER_RANDOM_12,
        "session_id_echo_hex": "131415161718191a1b1c1d1e" if tls13 else "12131415",
        "cipher_suite": 0x1301 if tls13 else 0xC02F,
        "extensions": [],
        "form": "server_hello",
    }
    if tls13:
        message["extensions"] = [
            _extension("supported_versions", context="server_hello", selected_version=0x0304),
            _extension("key_share", context="server_hello", group=0x001D, key_exchange_hex="55" * 32),
        ]
    return _handshake_record([message])


def _hello_retry_request_record() -> JSONObject:
    return _handshake_record(
        [
            {
                "type": "server_hello",
                "form": "hello_retry_request",
                "legacy_version": 0x0303,
                "random_hex": "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c",
                "session_id_echo_hex": "131415161718191a1b1c1d1e",
                "cipher_suite": 0x1301,
                "extensions": [
                    _extension("supported_versions", context="server_hello", selected_version=0x0304),
                    _extension("key_share", context="hello_retry_request", selected_group=0x0017),
                ],
            }
        ]
    )


def _handshake_record(messages: list[JSONObject]) -> JSONObject:
    return {
        "content_type": "handshake",
        "legacy_record_version": 0x0303,
        "body_kind": "handshake",
        "handshake_messages": messages,
    }


def _alert_record(*, level: str, description: str) -> JSONObject:
    return {
        "content_type": "alert",
        "legacy_record_version": 0x0303,
        "body_kind": "alert",
        "alert": {"level": level, "description": description},
        "fragment_hex": "0232" if description == "decode_error" else "0100",
    }


def _change_cipher_spec_record() -> JSONObject:
    return {
        "content_type": "change_cipher_spec",
        "legacy_record_version": 0x0303,
        "body_kind": "change_cipher_spec",
        "value": 1,
        "fragment_hex": "01",
    }


def _application_data_record(fragment_hex: str, *, declared_length: int | None = None) -> JSONObject:
    record: JSONObject = {
        "content_type": "application_data",
        "legacy_record_version": 0x0303,
        "body_kind": "application_data",
        "fragment_hex": fragment_hex,
    }
    if declared_length is not None:
        record["declared_length"] = declared_length
    return record


def _unknown_record() -> JSONObject:
    return {
        "content_type_raw": 0xFE,
        "legacy_record_version": 0x4242,
        "body_kind": "opaque_raw",
        "raw_fragment_hex": "dead",
        "fragment_hex": "dead",
    }


def _encrypted_extensions(extensions: list[JSONObject]) -> JSONObject:
    return {
        "type": "encrypted_extensions",
        "extensions": extensions,
    }


def _certificate(*, tls13: bool) -> JSONObject:
    if tls13:
        return {
            "type": "certificate",
            "form": "tls13",
            "request_context_hex": "0102",
            "certificates": [
                {"hex": "3082", "extensions": [_extension(type_raw=0xBEEF, body_hex="aa")]},
                {"hex": "04", "extensions": []},
            ],
        }
    return {
        "type": "certificate",
        "form": "tls12",
        "certificates": [{"hex": "300301"}, {"hex": "3001"}],
    }


def _certificate_request(*, tls13: bool) -> JSONObject:
    if tls13:
        return {
            "type": "certificate_request",
            "form": "tls13",
            "request_context_hex": "10",
            "extensions": [
                _extension("signature_algorithms", signature_schemes=[0x0807]),
                _extension("certificate_authorities", distinguished_names_hex=["dead"]),
                _extension(type_raw=0xBEEF, body_hex="cafe"),
            ],
        }
    return {
        "type": "certificate_request",
        "form": "tls12",
        "certificate_types": ["rsa_sign", "ecdsa_sign", {"raw": 0xFE}],
        "signature_algorithms": [0x0401, 0x0807],
        "certificate_authorities_hex": ["300331", "aa"],
    }


def _certificate_verify() -> JSONObject:
    return {
        "type": "certificate_verify",
        "signature_scheme": 0xBEEF,
        "signature_hex": "deadfa",
    }


def _finished() -> JSONObject:
    return {"type": "finished", "verify_data_hex": "deadbeef"}


def _new_session_ticket(*, tls13: bool) -> JSONObject:
    if tls13:
        return {
            "type": "new_session_ticket",
            "form": "tls13",
            "ticket_lifetime": 7,
            "ticket_age_add": 0x01020304,
            "ticket_nonce_hex": "09",
            "ticket_hex": "aabbcc",
            "extensions": [_extension(type_raw=0xBEEF, body_hex="de")],
        }
    return {
        "type": "new_session_ticket",
        "form": "tls12",
        "lifetime_hint": 0x01020304,
        "ticket_hex": "aabb",
    }


def _key_update() -> JSONObject:
    return {"type": "key_update", "request_update": "update_requested"}


def _end_of_early_data() -> JSONObject:
    return {"type": "end_of_early_data"}


def _unknown_handshake() -> JSONObject:
    return {"type_raw": 0xFA, "body_kind": "opaque_raw", "body_hex": "cafe00"}


def _extension_case_record(case_key: str) -> JSONObject:
    if case_key == "tls-extension-sni":
        extension = _extension("server_name", host_names=["example.com"])
    elif case_key == "tls-extension-alpn":
        extension = _extension("application_layer_protocol_negotiation", protocols=["h2", "http/1.1"])
    elif case_key == "tls-extension-supported-versions-client":
        extension = _extension("supported_versions", context="client_hello", versions=[0x0304, 0x0303])
    elif case_key == "tls-extension-supported-versions-server":
        extension = _extension("supported_versions", context="server_hello", selected_version=0x0304)
    elif case_key == "tls-extension-supported-groups":
        extension = _extension("supported_groups", named_groups=[0x001D, 0x0017])
    elif case_key == "tls-extension-signature-algorithms":
        extension = _extension("signature_algorithms", signature_schemes=[0x0807, 0x0804, 0x0403])
    elif case_key == "tls-extension-key-share-client":
        extension = _extension("key_share", context="client_hello", shares=[{"group": 0x001D, "key_exchange_hex": "aabbcc"}])
    elif case_key == "tls-extension-key-share-server":
        extension = _extension("key_share", context="server_hello", group=0x001D, key_exchange_hex="bbcc")
    elif case_key == "tls-extension-key-share-hello-retry-request":
        extension = _extension("key_share", context="hello_retry_request", selected_group=0x0017)
    elif case_key == "tls-extension-psk-key-exchange-modes":
        extension = _extension("psk_key_exchange_modes", modes=["psk_ke", "psk_dhe_ke"])
    elif case_key == "tls-extension-pre-shared-key-client":
        extension = _extension(
            "pre_shared_key",
            context="client_hello",
            identities=[{"identity_hex": "deadbeef", "obfuscated_ticket_age": 0x01020304}],
            binders=[{"binder_hex": "11" * 32}],
        )
    elif case_key == "tls-extension-pre-shared-key-server":
        extension = _extension("pre_shared_key", context="server_hello", selected_identity=2)
    elif case_key == "tls-extension-cookie":
        extension = _extension("cookie", cookie_hex="00ff7a")
    elif case_key == "tls-extension-padding":
        extension = _extension("padding", padding_hex="aa00bb")
    elif case_key == "tls-extension-record-size-limit":
        extension = _extension("record_size_limit", limit=512)
    elif case_key == "tls-extension-status-request":
        extension = _extension(
            "status_request",
            status_type="ocsp",
            responder_ids=["aabb"],
            request_extensions_hex="3000",
        )
    elif case_key == "tls-extension-certificate-authorities":
        extension = _extension("certificate_authorities", distinguished_names_hex=["300331", "aabb"])
    elif case_key == "tls-extension-unknown-preservation":
        extension = _extension(type_raw=0xBEEF, body_hex="deadface")
    elif case_key == "tls-extension-duplicate-preservation":
        return _client_hello_record(
            tls13=True,
            extensions=[
                _extension(type_raw=0xBEEF, body_hex="dead"),
                _extension("supported_versions", context="client_hello", body_hex="0304"),
                _extension(type_raw=0xBEEF, body_hex="face00"),
            ],
        )
    else:
        extension = _extension(type_raw=0xBEEF, body_hex="dead")
    return _client_hello_record(tls13=True, extensions=[extension])


def _extension(
    extension_type: str | None = None,
    *,
    type_raw: int | None = None,
    body_hex: str | None = None,
    **fields: object,
) -> JSONObject:
    extension: JSONObject = {}
    if extension_type is not None:
        extension["type"] = extension_type
    if type_raw is not None:
        extension["type_raw"] = type_raw
    if body_hex is not None:
        extension["body_hex"] = body_hex
    extension.update(fields)  # type: ignore[arg-type]
    return extension


def _apply_tls_transport_defaults(fields: dict[str, JSONObject], *, stack: Sequence[str]) -> None:
    tcp = fields.get("tcp")
    if isinstance(tcp, dict):
        tcp["src_port"] = 49152
        tcp["dst_port"] = TLS_PORT_HTTPS
        tcp["sequence"] = 0x84460001
        tcp["acknowledgement"] = 0x84470001
        tcp["flags"] = "ack"
        tcp.setdefault("window", 8192)

    if "ipv4" in fields:
        fields["ipv4"]["src"] = "192.0.2.46"
        fields["ipv4"]["dst"] = "198.51.100.46"
        fields["ipv4"]["protocol"] = "tcp"
        fields["ipv4"].setdefault("ttl", 64)
    if "ipv6" in fields:
        fields["ipv6"]["src"] = "2001:db8::46"
        fields["ipv6"]["dst"] = "2001:db8::8446"
        fields["ipv6"]["next_header"] = "tcp"
        fields["ipv6"].setdefault("hop_limit", 64)
    if "ethernet" in fields:
        fields["ethernet"].setdefault("src", "00:00:5e:00:53:46")
        fields["ethernet"].setdefault("dst", "00:00:5e:00:53:47")

    if "tcp" not in stack and "tls" in fields:
        fields["tls"]["raw_root"] = True


register(
    ProtocolSampler(
        layer="tls",
        supported_fields=_SUPPORTED_FIELDS,
        sample=_sample,
        apply_behavior=_apply_behavior,
        handles_feature=_handles_feature,
    )
)
