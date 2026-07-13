"""Deterministic canonical RAPPID parsing, minting, and door derivation."""

import hashlib
import json
import re

from agents.basic_agent import BasicAgent


__manifest__ = {
    "schema": "rapp-agent/1.0",
    "name": "Rappid",
    "version": "1.0.0",
    "description": "Canonicalize birth data and work with one selected 64-hex RAPPID form.",
    "actions": ["canonicalize", "validate", "parse", "mint", "door"],
    "capability_ids": [
        "identity.canonical-json",
        "identity.lineage",
        "identity.rappid-eternity",
    ],
    "mutability": "read_only",
    "enabled_by_default": True,
    "provenance": "original_new",
    "dependencies": ["python-stdlib", "BasicAgent"],
}

_OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_RAPPID_RE = re.compile(
    r"^rappid:@(?P<owner>[a-z0-9][a-z0-9-]{0,62})/"
    r"(?P<slug>[a-z0-9][a-z0-9-]{0,62}):(?P<digest>[0-9a-f]{64})$"
)
_LEGACY_HEX_RE = re.compile(r"^(?:rappid:)?(?P<digest>[0-9a-fA-F]{16,128})$")
_LEGACY_V2_RE = re.compile(r"^rappid:v[0-9]+:.+$", re.IGNORECASE)
_EXCLUDED_FIELDS = frozenset(
    {
        "id",
        "rappid",
        "self",
        "sig",
        "signature",
        "signatures",
        "transport",
        "transport_key",
        "private_key",
        "public_key",
        "wire",
    }
)
_MAX_BIRTH_BYTES = 32 * 1024
_MAX_DEPTH = 12


def _json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _response(action, *, ok=True, **values):
    result = {"agent": "Rappid", "action": action, "ok": ok}
    result.update(values)
    return _json(result)


def _clean_json(value, depth=0):
    if depth > _MAX_DEPTH:
        raise ValueError("birth fixture is too deeply nested")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise ValueError("floating-point birth values are not supported")
    if isinstance(value, list):
        return [_clean_json(item, depth + 1) for item in value]
    if isinstance(value, dict):
        cleaned = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise ValueError("birth keys must be strings")
            if key.casefold() in _EXCLUDED_FIELDS:
                continue
            cleaned[key] = _clean_json(value[key], depth + 1)
        return cleaned
    raise ValueError("birth fixture must contain only JSON values")


def _birth(value):
    if isinstance(value, str):
        if len(value.encode("utf-8")) > _MAX_BIRTH_BYTES:
            raise ValueError("birth fixture is too large")
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("birth fixture must be an object")
    cleaned = _clean_json(value)
    canonical = _json(cleaned)
    if len(canonical.encode("utf-8")) > _MAX_BIRTH_BYTES:
        raise ValueError("birth fixture is too large")
    return cleaned, canonical


def _owner_slug(owner, slug):
    if not isinstance(owner, str) or not _OWNER_RE.fullmatch(owner):
        raise ValueError("owner is invalid")
    if not isinstance(slug, str) or not _SLUG_RE.fullmatch(slug):
        raise ValueError("slug is invalid")
    return owner, slug


def _mint(owner, slug, birth):
    owner, slug = _owner_slug(owner, slug)
    cleaned, canonical = _birth(birth)
    fixture = {
        "birth": cleaned,
        "owner": owner,
        "schema": "rapp-birth/1.0",
        "slug": slug,
    }
    fixture_canonical = _json(fixture)
    digest = hashlib.sha256(fixture_canonical.encode("utf-8")).hexdigest()
    return (
        f"rappid:@{owner}/{slug}:{digest}",
        fixture,
        fixture_canonical,
        canonical,
    )


class Rappid(BasicAgent):
    """Use one content-addressed identity form without mutating legacy IDs."""

    name = "Rappid"
    metadata = {
        "name": "Rappid",
        "description": "Canonicalize, validate, parse, mint, or derive a RAPPID door.",
        "parameters": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["canonicalize", "validate", "parse", "mint", "door"],
                },
                "value": {"type": "string", "maxLength": 4096},
                "owner": {"type": "string", "maxLength": 63},
                "slug": {"type": "string", "maxLength": 63},
                "birth": {"type": ["object", "string"]},
                "rappid": {"type": "string", "maxLength": 512},
                "door": {"type": "string", "maxLength": 63},
            },
            "required": ["action"],
            "additionalProperties": False,
        },
    }

    def perform(self, **kwargs):
        action = kwargs.get("action")
        if action not in __manifest__["actions"]:
            return _response(
                str(action or ""),
                ok=False,
                error={"code": "invalid_action", "message": "Unsupported action."},
            )
        try:
            if action == "canonicalize":
                _, canonical = _birth(kwargs.get("birth"))
                return _response(
                    action,
                    canonical=canonical,
                    utf8_sha256=hashlib.sha256(
                        canonical.encode("utf-8")
                    ).hexdigest(),
                    excluded_fields=sorted(_EXCLUDED_FIELDS),
                )
            if action == "validate":
                value = kwargs.get("rappid", kwargs.get("value"))
                match = _RAPPID_RE.fullmatch(value or "")
                return _response(
                    action,
                    valid=match is not None,
                    format="rapp-eternity/1.0" if match else "invalid",
                )
            if action == "parse":
                return self._parse(kwargs.get("rappid", kwargs.get("value")))
            if action == "mint":
                rappid, fixture, canonical, _ = _mint(
                    kwargs.get("owner"),
                    kwargs.get("slug"),
                    kwargs.get("birth"),
                )
                return _response(
                    action,
                    rappid=rappid,
                    canonical_birth=canonical,
                    fixture=fixture,
                    deterministic=True,
                )
            return self._door(kwargs.get("rappid"), kwargs.get("door"))
        except Exception:
            return _response(
                action,
                ok=False,
                error={
                    "code": "invalid_input",
                    "message": "Input does not satisfy the selected identity contract.",
                },
            )

    def _parse(self, value):
        if not isinstance(value, str) or not value or len(value) > 512:
            raise ValueError("identity input is invalid")
        match = _RAPPID_RE.fullmatch(value)
        if match:
            return _response(
                "parse",
                format="rapp-eternity/1.0",
                canonical=True,
                owner=match.group("owner"),
                slug=match.group("slug"),
                digest=match.group("digest"),
                rappid=value,
                mutable=False,
            )
        legacy_hex = _LEGACY_HEX_RE.fullmatch(value)
        if legacy_hex:
            return _response(
                "parse",
                format="legacy_hex",
                canonical=False,
                legacy_input=value,
                legacy_digest=legacy_hex.group("digest").lower(),
                mutable=False,
            )
        if _LEGACY_V2_RE.fullmatch(value) or value.lower().startswith("rappid:"):
            return _response(
                "parse",
                format="legacy_other",
                canonical=False,
                legacy_input=value,
                mutable=False,
            )
        return _response(
            "parse",
            ok=False,
            error={"code": "invalid_rappid", "message": "Identity is not recognized."},
        )

    def _door(self, value, door):
        match = _RAPPID_RE.fullmatch(value or "")
        if not match:
            raise ValueError("canonical rappid is required")
        if not isinstance(door, str) or not _SLUG_RE.fullmatch(door):
            raise ValueError("door name is invalid")
        material = _json(
            {
                "door": door,
                "parent": value,
                "schema": "rapp-door/1.0",
            }
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
        derived_slug = f"{match.group('slug')}-{door}"
        if len(derived_slug) > 63:
            derived_slug = derived_slug[:54] + "-" + digest[:8]
        rappid = (
            f"rappid:@{match.group('owner')}/{derived_slug}:{digest}"
        )
        return _response(
            "door",
            rappid=rappid,
            parent_rappid=value,
            door=door,
            derivation_sha256=digest,
            mutable=False,
        )


TEST_VECTORS = (
    {
        "birth": {"kind": "synthetic", "name": "Sample"},
        "canonical_birth": (
            '{"birth":{"kind":"synthetic","name":"Sample"},'
            '"owner":"example","schema":"rapp-birth/1.0","slug":"sample"}'
        ),
        "owner": "example",
        "rappid": (
            "rappid:@example/sample:"
            "280cbe5df87f88ed24d52eff2b64ffd190b9083ef37ce389f0efeab660087016"
        ),
        "slug": "sample",
    },
)
