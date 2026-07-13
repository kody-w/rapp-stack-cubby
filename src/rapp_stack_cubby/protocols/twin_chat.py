"""Exact signed request and response profile for local twin chat."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import secrets
from collections.abc import Mapping, Sequence
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    parse_canonical_wire,
    parse_json,
)
from .crypto import (
    KeyMaterialError,
    b64url_decode,
    b64url_encode,
    key_id_for_jwk,
    sign_object,
    validate_public_jwk,
    verify_object,
)

REQUEST_SCHEMA = "rapp-twin-chat/1.0"
COMMONS_SCHEMA = "rapp-commons-event/1.0"
RESPONSE_SCHEMA = "rapp-twin-chat-response/1.0"
ALGORITHM = "ecdsa-p256"
KIND = "say"
DEFAULT_FRESHNESS_SECONDS = 300

_RAPPID_RE = re.compile(
    r"^rappid:@[a-z0-9][a-z0-9-]{0,62}/"
    r"[a-z0-9][a-z0-9-]{0,127}:[0-9a-f]{64}$"
)
_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MODEL_RE = re.compile(r"^[^\x00-\x1f]{1,128}$")
_INNER_KEYS = {
    "schema",
    "from_rappid",
    "to_rappid",
    "utc",
    "nonce",
    "key_epoch",
    "kind",
    "payload",
    "facets",
}
_WRAPPER_KEYS = {
    "schema",
    "from",
    "pub",
    "alg",
    "ts",
    "kind",
    "body",
    "key_id",
    "sig",
}
_RESPONSE_KEYS = {
    "schema",
    "from_rappid",
    "to_rappid",
    "utc",
    "request_nonce",
    "request_digest",
    "key_epoch",
    "status",
    "payload",
    "key_id",
    "sig",
}
_PAYLOAD_KEYS = {"user_input", "conversation_history", "session_id"}
_HISTORY_ROLES = {"user", "assistant", "tool"}
_CHILD_RESPONSE_KEYS = {
    "response",
    "session_id",
    "agent_logs",
    "voice_mode",
    "model",
    "requested_model",
}
_PROTOCOL_SCHEMAS = frozenset(
    {REQUEST_SCHEMA, COMMONS_SCHEMA, RESPONSE_SCHEMA}
)
_JSON_STRING_TOKEN_RE = re.compile(
    r'"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*"'
)


class ProtocolError(ValueError):
    """Base error for the signed twin-chat profile."""


class ProtocolValidationError(ProtocolError):
    """Raised for malformed, unpaired, or cryptographically invalid input."""


class ProtocolFreshnessError(ProtocolValidationError):
    """Raised when a new live request is outside the accepted UTC window."""


class ProtocolClaimError(ProtocolValidationError):
    """Raised when JSON claims a protocol schema but is not a valid wrapper."""


class VerifiedRequest:
    """Immutable-enough validated request view used by runtime dispatch."""

    __slots__ = (
        "wrapper",
        "inner",
        "digest",
        "sender_rappid",
        "key_id",
        "nonce",
        "key_epoch",
    )

    def __init__(self, wrapper: dict[str, Any], inner: dict[str, Any]) -> None:
        self.wrapper = wrapper
        self.inner = inner
        self.digest = request_digest(inner)
        self.sender_rappid = inner["from_rappid"]
        self.key_id = wrapper["key_id"]
        self.nonce = inner["nonce"]
        self.key_epoch = inner["key_epoch"]

    @property
    def payload(self) -> dict[str, Any]:
        return dict(self.inner["payload"])


def utc_now() -> str:
    return (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def classify_protocol_text(text: str) -> str | None:
    """Return exact claimed wire text, ordinary ``None``, or fail closed."""

    if not isinstance(text, str):
        raise ProtocolClaimError("user_input must be text")
    stripped = text.lstrip()
    if stripped.startswith("\ufeff{"):
        stripped = stripped[1:]
    if not stripped.startswith("{"):
        return None
    try:
        value = parse_json(text)
    except CanonicalJSONError as error:
        if _textually_claims_protocol(text):
            raise ProtocolClaimError("claimed twin-chat JSON is malformed") from error
        return None
    if not isinstance(value, dict):
        return None
    if not _decoded_claims_protocol(value):
        return None
    if value.get("schema") != COMMONS_SCHEMA:
        raise ProtocolClaimError("twin-chat must be carried by the Commons wrapper")
    return text


def _textually_claims_protocol(text: str) -> bool:
    if any(schema in text for schema in _PROTOCOL_SCHEMAS):
        return True
    for match in _JSON_STRING_TOKEN_RE.finditer(text):
        try:
            decoded = json.loads(match.group(0))
        except (TypeError, ValueError):
            continue
        if decoded in _PROTOCOL_SCHEMAS:
            return True
    return False


def _decoded_claims_protocol(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("schema") in _PROTOCOL_SCHEMAS:
            return True
        return any(_decoded_claims_protocol(item) for item in value.values())
    if isinstance(value, list):
        return any(_decoded_claims_protocol(item) for item in value)
    return False


def sign_request(
    *,
    private_key: ec.EllipticCurvePrivateKey,
    public_jwk: Mapping[str, Any],
    from_rappid: str,
    to_rappid: str,
    payload: Mapping[str, Any],
    facets: Sequence[str] = (),
    utc: str | None = None,
    nonce: str | None = None,
    key_epoch: int = 1,
) -> dict[str, Any]:
    normalized_jwk = validate_public_jwk(public_jwk)
    inner = {
        "schema": REQUEST_SCHEMA,
        "from_rappid": from_rappid,
        "to_rappid": to_rappid,
        "utc": utc or utc_now(),
        "nonce": nonce or b64url_encode(secrets.token_bytes(24)),
        "key_epoch": key_epoch,
        "kind": KIND,
        "payload": dict(payload),
        "facets": list(facets),
    }
    _validate_inner(inner)
    wrapper = {
        "schema": COMMONS_SCHEMA,
        "from": from_rappid,
        "pub": normalized_jwk,
        "alg": ALGORITHM,
        "ts": inner["utc"],
        "kind": inner["kind"],
        "body": inner,
        "key_id": key_id_for_jwk(normalized_jwk),
    }
    wrapper["sig"] = sign_object(wrapper, private_key)
    return wrapper


def verify_request(
    value: Mapping[str, Any] | str | bytes,
    *,
    paired_public_jwk: Mapping[str, Any],
    paired_controller_rappid: str,
    twin_rappid: str,
    now: dt.datetime | None = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    enforce_freshness: bool = True,
    expected_key_epoch: int = 1,
) -> VerifiedRequest:
    try:
        wrapper = (
            parse_canonical_wire(value)
            if isinstance(value, (str, bytes))
            else dict(value)
        )
        _validate_wrapper(wrapper)
        paired = validate_public_jwk(paired_public_jwk)
        if wrapper["pub"] != paired:
            raise ProtocolValidationError("wrapper public key is not the paired key")
        expected_key_id = key_id_for_jwk(paired)
        if wrapper["key_id"] != expected_key_id:
            raise ProtocolValidationError("wrapper key_id does not match the paired key")
        inner = wrapper["body"]
        if wrapper["from"] != inner["from_rappid"]:
            raise ProtocolValidationError("wrapper and inner sender differ")
        if wrapper["ts"] != inner["utc"]:
            raise ProtocolValidationError("wrapper and inner UTC differ")
        if wrapper["kind"] != inner["kind"]:
            raise ProtocolValidationError("wrapper and inner kind differ")
        if inner["from_rappid"] != paired_controller_rappid:
            raise ProtocolValidationError("request sender is not the paired controller")
        if inner["to_rappid"] != twin_rappid:
            raise ProtocolValidationError("request destination is not this installed twin")
        _validate_epoch(expected_key_epoch)
        if inner["key_epoch"] != expected_key_epoch:
            raise ProtocolValidationError("request key epoch is not current")
        verify_object(wrapper, paired)
        verified = VerifiedRequest(wrapper, inner)
        if enforce_freshness:
            validate_freshness(
                inner["utc"],
                now=now,
                freshness_seconds=freshness_seconds,
            )
        return verified
    except ProtocolError:
        raise
    except (CanonicalJSONError, KeyMaterialError, KeyError, TypeError) as error:
        raise ProtocolValidationError("signed twin-chat request is invalid") from error


def validate_freshness(
    utc: str,
    *,
    now: dt.datetime | None = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
) -> None:
    if (
        not isinstance(freshness_seconds, int)
        or isinstance(freshness_seconds, bool)
        or not 1 <= freshness_seconds <= 3600
    ):
        raise ProtocolValidationError("freshness window must be 1-3600 seconds")
    parsed = _parse_utc(utc)
    current = now or dt.datetime.now(dt.timezone.utc)
    if current.tzinfo is None:
        raise ProtocolValidationError("current time must be timezone-aware")
    current = current.astimezone(dt.timezone.utc)
    if abs((current - parsed).total_seconds()) > freshness_seconds:
        raise ProtocolFreshnessError("request UTC is outside the freshness window")


def request_digest(inner: Mapping[str, Any]) -> str:
    _validate_inner(inner)
    return hashlib.sha256(canonical_json_bytes(dict(inner))).hexdigest()


def sign_response(
    *,
    private_key: ec.EllipticCurvePrivateKey,
    child_public_jwk: Mapping[str, Any],
    from_rappid: str,
    to_rappid: str,
    request_nonce: str,
    request_digest_value: str,
    status: str,
    payload: Mapping[str, Any],
    utc: str | None = None,
    key_epoch: int = 1,
) -> dict[str, Any]:
    response = {
        "schema": RESPONSE_SCHEMA,
        "from_rappid": from_rappid,
        "to_rappid": to_rappid,
        "utc": utc or utc_now(),
        "request_nonce": request_nonce,
        "request_digest": request_digest_value,
        "key_epoch": key_epoch,
        "status": status,
        "payload": dict(payload),
        "key_id": key_id_for_jwk(child_public_jwk),
    }
    _validate_response(response, require_signature=False)
    response["sig"] = sign_object(response, private_key)
    _validate_response(response, require_signature=True)
    return response


def verify_response(
    value: Mapping[str, Any] | str | bytes,
    *,
    paired_child_public_jwk: Mapping[str, Any],
    expected_child_rappid: str,
    expected_controller_rappid: str,
    expected_request_nonce: str,
    expected_request_digest: str,
    now: dt.datetime | None = None,
    freshness_seconds: int = DEFAULT_FRESHNESS_SECONDS,
    enforce_freshness: bool = True,
    expected_key_epoch: int = 1,
) -> dict[str, Any]:
    try:
        response = (
            parse_canonical_wire(value)
            if isinstance(value, (str, bytes))
            else dict(value)
        )
        _validate_response(response, require_signature=True)
        paired = validate_public_jwk(paired_child_public_jwk)
        if response["key_id"] != key_id_for_jwk(paired):
            raise ProtocolValidationError("response key_id is not the paired child key")
        if response["from_rappid"] != expected_child_rappid:
            raise ProtocolValidationError("response sender is not the installed twin")
        if response["to_rappid"] != expected_controller_rappid:
            raise ProtocolValidationError("response destination is not the controller")
        if response["request_nonce"] != expected_request_nonce:
            raise ProtocolValidationError("response nonce binding is invalid")
        if response["request_digest"] != expected_request_digest:
            raise ProtocolValidationError("response digest binding is invalid")
        _validate_epoch(expected_key_epoch)
        if response["key_epoch"] != expected_key_epoch:
            raise ProtocolValidationError("response key epoch binding is invalid")
        verify_object(response, paired)
        if enforce_freshness:
            validate_freshness(
                response["utc"],
                now=now,
                freshness_seconds=freshness_seconds,
            )
        return response
    except ProtocolError:
        raise
    except (CanonicalJSONError, KeyMaterialError, KeyError, TypeError) as error:
        raise ProtocolValidationError("signed twin-chat response is invalid") from error


def _validate_wrapper(wrapper: Mapping[str, Any]) -> None:
    if not isinstance(wrapper, Mapping) or set(wrapper) != _WRAPPER_KEYS:
        raise ProtocolValidationError("Commons wrapper fields are not exact")
    if wrapper.get("schema") != COMMONS_SCHEMA:
        raise ProtocolValidationError("Commons wrapper schema is invalid")
    if wrapper.get("alg") != ALGORITHM:
        raise ProtocolValidationError("Commons wrapper algorithm is invalid")
    if wrapper.get("kind") != KIND:
        raise ProtocolValidationError("Commons wrapper kind is invalid")
    _validate_rappid(wrapper.get("from"), "wrapper sender")
    _parse_utc(wrapper.get("ts"))
    if not isinstance(wrapper.get("key_id"), str) or not _HEX_64_RE.fullmatch(
        wrapper["key_id"]
    ):
        raise ProtocolValidationError("wrapper key_id is invalid")
    if not isinstance(wrapper.get("sig"), str):
        raise ProtocolValidationError("wrapper signature is invalid")
    validate_public_jwk(wrapper.get("pub"))
    _validate_inner(wrapper.get("body"))


def _validate_inner(inner: Mapping[str, Any]) -> None:
    if not isinstance(inner, Mapping) or set(inner) != _INNER_KEYS:
        raise ProtocolValidationError("inner request fields are not exact")
    if inner.get("schema") != REQUEST_SCHEMA:
        raise ProtocolValidationError("inner request schema is invalid")
    _validate_rappid(inner.get("from_rappid"), "request sender")
    _validate_rappid(inner.get("to_rappid"), "request destination")
    _parse_utc(inner.get("utc"))
    _validate_nonce(inner.get("nonce"))
    _validate_epoch(inner.get("key_epoch"))
    if inner.get("kind") != KIND:
        raise ProtocolValidationError("inner request kind is invalid")
    _validate_chat_payload(inner.get("payload"))
    facets = inner.get("facets")
    if not isinstance(facets, list) or len(facets) > 16:
        raise ProtocolValidationError("facets must be an array of at most 16 strings")
    seen: set[str] = set()
    for facet in facets:
        if (
            not isinstance(facet, str)
            or not facet
            or len(facet.encode("utf-8")) > 128
            or any(ord(character) < 0x20 for character in facet)
            or facet in seen
        ):
            raise ProtocolValidationError("facet is invalid or duplicated")
        seen.add(facet)
    canonical_json_bytes(dict(inner))


def _validate_chat_payload(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload, Mapping) or not set(payload) <= _PAYLOAD_KEYS:
        raise ProtocolValidationError("chat payload fields are invalid")
    if "user_input" not in payload:
        raise ProtocolValidationError("chat payload requires user_input")
    user_input = payload.get("user_input")
    if (
        not isinstance(user_input, str)
        or not user_input.strip()
        or len(user_input.encode("utf-8")) > 1024 * 1024
    ):
        raise ProtocolValidationError("chat payload user_input is invalid")
    history = payload.get("conversation_history", [])
    if not isinstance(history, list) or len(history) > 512:
        raise ProtocolValidationError("conversation_history is invalid")
    history_bytes = 0
    for entry in history:
        if not isinstance(entry, Mapping) or set(entry) != {"role", "content"}:
            raise ProtocolValidationError("conversation_history entry is not exact")
        if entry.get("role") not in _HISTORY_ROLES or not isinstance(
            entry.get("content"), str
        ):
            raise ProtocolValidationError("conversation_history entry is invalid")
        history_bytes += len(entry["content"].encode("utf-8"))
        if history_bytes > 1024 * 1024:
            raise ProtocolValidationError("conversation_history exceeds its limit")
    if "session_id" in payload:
        session = payload["session_id"]
        if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
            raise ProtocolValidationError("session_id is invalid")


def _validate_response(
    response: Mapping[str, Any],
    *,
    require_signature: bool,
) -> None:
    expected = _RESPONSE_KEYS if require_signature else _RESPONSE_KEYS - {"sig"}
    if not isinstance(response, Mapping) or set(response) != expected:
        raise ProtocolValidationError("signed response fields are not exact")
    if response.get("schema") != RESPONSE_SCHEMA:
        raise ProtocolValidationError("signed response schema is invalid")
    _validate_rappid(response.get("from_rappid"), "response sender")
    _validate_rappid(response.get("to_rappid"), "response destination")
    _parse_utc(response.get("utc"))
    _validate_nonce(response.get("request_nonce"))
    if not isinstance(response.get("request_digest"), str) or not _HEX_64_RE.fullmatch(
        response["request_digest"]
    ):
        raise ProtocolValidationError("response request_digest is invalid")
    if not isinstance(response.get("key_id"), str) or not _HEX_64_RE.fullmatch(
        response["key_id"]
    ):
        raise ProtocolValidationError("response key_id is invalid")
    _validate_epoch(response.get("key_epoch"))
    status = response.get("status")
    payload = response.get("payload")
    if status == "ok":
        _validate_child_response(payload)
    elif status == "rejected":
        _validate_error_payload(payload)
    else:
        raise ProtocolValidationError("response status is invalid")
    if require_signature and not isinstance(response.get("sig"), str):
        raise ProtocolValidationError("response signature is invalid")
    canonical_json_bytes(dict(response))


def _validate_child_response(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload, Mapping) or set(payload) != _CHILD_RESPONSE_KEYS:
        raise ProtocolValidationError("child response payload fields are not exact")
    try:
        response_size = (
            len(payload["response"].encode("utf-8"))
            if isinstance(payload.get("response"), str)
            else -1
        )
        log_size = (
            len(payload["agent_logs"].encode("utf-8"))
            if isinstance(payload.get("agent_logs"), str)
            else -1
        )
    except UnicodeEncodeError as error:
        raise ProtocolValidationError(
            "child response contains an invalid Unicode scalar"
        ) from error
    if (
        response_size < 0
        or response_size > 1024 * 1024
        or log_size < 0
        or log_size > 1024 * 1024
    ):
        raise ProtocolValidationError("child response text fields are invalid")
    session = payload.get("session_id")
    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
        raise ProtocolValidationError("child response session_id is invalid")
    if not isinstance(payload.get("voice_mode"), bool):
        raise ProtocolValidationError("child response voice_mode is invalid")
    for field in ("model", "requested_model"):
        if not isinstance(payload.get(field), str) or not _MODEL_RE.fullmatch(
            payload[field]
        ):
            raise ProtocolValidationError(f"child response {field} is invalid")


def _validate_error_payload(payload: Mapping[str, Any]) -> None:
    if not isinstance(payload, Mapping) or set(payload) != {"error"}:
        raise ProtocolValidationError("rejection payload must contain only error")
    error = payload.get("error")
    if not isinstance(error, Mapping) or set(error) != {"code", "message"}:
        raise ProtocolValidationError("rejection error fields are not exact")
    code = error.get("code")
    message = error.get("message")
    if (
        not isinstance(code, str)
        or not re.fullmatch(r"^[a-z][a-z0-9_]{0,63}$", code)
        or not isinstance(message, str)
        or not 1 <= len(message.encode("utf-8")) <= 240
    ):
        raise ProtocolValidationError("rejection error is invalid")


def _validate_rappid(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _RAPPID_RE.fullmatch(value):
        raise ProtocolValidationError(f"{label} is not a canonical RAPPID")
    return value


def _validate_nonce(value: Any) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise ProtocolValidationError("nonce is invalid")
    try:
        decoded = b64url_decode(value)
    except KeyMaterialError as error:
        raise ProtocolValidationError("nonce is not canonical base64url") from error
    if not 16 <= len(decoded) <= 64:
        raise ProtocolValidationError("nonce decoded length is invalid")
    return value


def _validate_epoch(value: Any) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= 2**31 - 1
    ):
        raise ProtocolValidationError("key epoch is invalid")
    return value


def _parse_utc(value: Any) -> dt.datetime:
    if not isinstance(value, str) or not _UTC_RE.fullmatch(value):
        raise ProtocolValidationError("UTC timestamp must use second-precision Z form")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ProtocolValidationError("UTC timestamp is not a real date") from error
    return parsed.replace(tzinfo=dt.timezone.utc)
