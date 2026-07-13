"""Bounded canonical JSON subset used by the signed local protocol."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


class CanonicalJSONError(ValueError):
    """Raised when a value is outside the project-owned canonical subset."""


@dataclass(frozen=True, slots=True)
class CanonicalLimits:
    """Resource limits for canonical values.

    Integers are restricted to the signed 64-bit range.  The root is depth
    zero, so ``max_depth=16`` permits at most sixteen nested containers.
    """

    max_depth: int = 16
    max_string_bytes: int = 1024 * 1024
    max_list_items: int = 512
    max_object_items: int = 256
    max_nodes: int = 4096
    max_output_bytes: int = 2 * 1024 * 1024
    min_integer: int = -(2**63)
    max_integer: int = 2**63 - 1


DEFAULT_LIMITS = CanonicalLimits()


class _DuplicateKeyError(ValueError):
    pass


def _pairs_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateKeyError(key)
        value[key] = item
    return value


def _reject_float(value: str) -> Any:
    raise CanonicalJSONError("floating-point JSON numbers are forbidden")


def _reject_constant(value: str) -> Any:
    raise CanonicalJSONError(f"non-finite JSON number {value!r} is forbidden")


def _parse_integer(value: str) -> int:
    parsed = int(value, 10)
    if not DEFAULT_LIMITS.min_integer <= parsed <= DEFAULT_LIMITS.max_integer:
        raise CanonicalJSONError("JSON integer is outside the signed 64-bit range")
    return parsed


def parse_json(
    text: str | bytes,
    *,
    limits: CanonicalLimits = DEFAULT_LIMITS,
) -> Any:
    """Parse UTF-8 JSON while rejecting duplicate keys, floats, and excess."""

    if isinstance(text, bytes):
        try:
            source = text.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CanonicalJSONError("JSON must be UTF-8") from error
    elif isinstance(text, str):
        source = text
        try:
            source.encode("utf-8")
        except UnicodeEncodeError as error:
            raise CanonicalJSONError("JSON contains an invalid Unicode scalar") from error
    else:
        raise CanonicalJSONError("JSON input must be text or bytes")
    if len(source.encode("utf-8")) > limits.max_output_bytes:
        raise CanonicalJSONError("JSON exceeds the byte limit")
    try:
        value = json.loads(
            source,
            object_pairs_hook=_pairs_object,
            parse_float=_reject_float,
            parse_int=lambda raw: _parse_bounded_integer(raw, limits),
            parse_constant=_reject_constant,
        )
    except _DuplicateKeyError as error:
        raise CanonicalJSONError("JSON object contains a duplicate key") from error
    except (json.JSONDecodeError, RecursionError) as error:
        raise CanonicalJSONError("JSON is malformed or too deeply nested") from error
    validate_canonical_value(value, limits=limits)
    return value


def parse_canonical_wire(
    text: str | bytes,
    *,
    limits: CanonicalLimits = DEFAULT_LIMITS,
) -> Any:
    """Parse JSON and require the received UTF-8 bytes to be canonical."""

    if isinstance(text, bytes):
        received = text
    elif isinstance(text, str):
        try:
            received = text.encode("utf-8")
        except UnicodeEncodeError as error:
            raise CanonicalJSONError(
                "JSON contains an invalid Unicode scalar"
            ) from error
    else:
        raise CanonicalJSONError("JSON input must be text or bytes")
    value = parse_json(received, limits=limits)
    if received != canonical_json_bytes(value, limits=limits):
        raise CanonicalJSONError("JSON wire bytes are not canonical")
    return value


def _parse_bounded_integer(value: str, limits: CanonicalLimits) -> int:
    parsed = int(value, 10)
    if not limits.min_integer <= parsed <= limits.max_integer:
        raise CanonicalJSONError("JSON integer is outside the configured range")
    return parsed


def validate_canonical_value(
    value: Any,
    *,
    limits: CanonicalLimits = DEFAULT_LIMITS,
) -> None:
    """Validate the restricted JSON type and resource model."""

    nodes = 0

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > limits.max_nodes:
            raise CanonicalJSONError("JSON contains too many values")
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            if not limits.min_integer <= item <= limits.max_integer:
                raise CanonicalJSONError("integer is outside the configured range")
            return
        if isinstance(item, float):
            raise CanonicalJSONError("floating-point values are forbidden")
        if isinstance(item, str):
            try:
                size = len(item.encode("utf-8"))
            except UnicodeEncodeError as error:
                raise CanonicalJSONError(
                    "string contains an invalid Unicode scalar"
                ) from error
            if size > limits.max_string_bytes:
                raise CanonicalJSONError("string exceeds the byte limit")
            return
        if depth >= limits.max_depth:
            raise CanonicalJSONError("JSON exceeds the nesting-depth limit")
        if isinstance(item, list):
            if len(item) > limits.max_list_items:
                raise CanonicalJSONError("array contains too many items")
            for child in item:
                visit(child, depth + 1)
            return
        if isinstance(item, dict):
            if len(item) > limits.max_object_items:
                raise CanonicalJSONError("object contains too many members")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise CanonicalJSONError("object keys must be strings")
                visit(key, depth + 1)
                visit(child, depth + 1)
            return
        raise CanonicalJSONError(
            f"value of type {type(item).__name__} is not in the JSON subset"
        )

    visit(value, 0)


def canonical_json_bytes(
    value: Any,
    *,
    limits: CanonicalLimits = DEFAULT_LIMITS,
) -> bytes:
    """Encode sorted, compact, UTF-8 JSON with Unicode preserved."""

    validate_canonical_value(value, limits=limits)
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as error:
        raise CanonicalJSONError("value cannot be canonically encoded") from error
    if len(encoded) > limits.max_output_bytes:
        raise CanonicalJSONError("canonical JSON exceeds the byte limit")
    return encoded


def canonical_json_text(
    value: Any,
    *,
    limits: CanonicalLimits = DEFAULT_LIMITS,
) -> str:
    return canonical_json_bytes(value, limits=limits).decode("utf-8")
