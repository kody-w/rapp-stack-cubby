"""Stable public product identity derived only from canonical birth facts."""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

from .common import PackagingError, canonical_json_bytes

BIRTH_SCHEMA = "rapp-birth/1.0"
RAPPID_SCHEMA = "rapp-eternity/1.0"
OWNER = "kody-w"
SLUG = "rapp-stack-cubby"
_RAPPID_RE = re.compile(
    r"^rappid:@(?P<owner>[a-z0-9][a-z0-9-]{0,62})/"
    r"(?P<slug>[a-z0-9][a-z0-9-]{0,62}):(?P<digest>[0-9a-f]{64})$"
)
_EXCLUDED = frozenset(
    {
        "id",
        "private_key",
        "public_key",
        "rappid",
        "self",
        "sig",
        "signature",
        "signatures",
        "transport",
        "transport_key",
        "wire",
    }
)


def _clean(value: Any, depth: int = 0) -> Any:
    if depth > 12:
        raise PackagingError("birth facts are too deeply nested")
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        raise PackagingError("birth facts cannot contain floats")
    if isinstance(value, list):
        return [_clean(item, depth + 1) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key in sorted(value):
            if not isinstance(key, str):
                raise PackagingError("birth keys must be strings")
            if key.casefold() in _EXCLUDED:
                continue
            result[key] = _clean(value[key], depth + 1)
        return result
    raise PackagingError("birth facts must contain JSON values")


def build_identity(
    birth_facts: dict[str, Any],
    *,
    owner: str = OWNER,
    slug: str = SLUG,
) -> tuple[dict, dict]:
    """Return canonical birth and RAPPID documents."""

    if owner != OWNER or slug != SLUG:
        raise PackagingError("product owner and slug are fixed")
    cleaned = _clean(birth_facts)
    if not isinstance(cleaned, dict):
        raise PackagingError("birth facts must be an object")
    birth = {
        "birth": cleaned,
        "owner": owner,
        "schema": BIRTH_SCHEMA,
        "slug": slug,
    }
    canonical = canonical_json_bytes(birth)
    digest = hashlib.sha256(canonical).hexdigest()
    rappid = f"rappid:@{owner}/{slug}:{digest}"
    identity = {
        "birth_sha256": digest,
        "identity_hash": digest,
        "owner": owner,
        "rappid": rappid,
        "schema": RAPPID_SCHEMA,
        "slug": slug,
    }
    return birth, identity


def validate_identity(birth: dict, identity: dict) -> dict:
    """Reject legacy or self-referential public product identities."""

    if not isinstance(birth, dict) or set(birth) != {
        "birth",
        "owner",
        "schema",
        "slug",
    }:
        raise PackagingError("birth document is invalid")
    expected_birth, expected = build_identity(
        birth["birth"],
        owner=birth["owner"],
        slug=birth["slug"],
    )
    if expected_birth != birth or expected != identity:
        raise PackagingError("product identity is not canonical")
    match = _RAPPID_RE.fullmatch(identity.get("rappid", ""))
    if match is None:
        raise PackagingError("legacy or malformed RAPPID")
    return expected


def build_instance_identity(
    product_rappid: str,
    source_revision: str,
    source_tree_digest: str,
) -> dict:
    """Mint a private instance RAPPID without retaining its random birth nonce."""

    match = _RAPPID_RE.fullmatch(product_rappid)
    if (
        match is None
        or not isinstance(source_revision, str)
        or not source_revision
        or not re.fullmatch(r"[0-9a-f]{64}", source_tree_digest)
    ):
        raise PackagingError("instance identity inputs are invalid")
    nonce = secrets.token_bytes(32)
    birth = {
        "schema": "rapp-private-instance-birth/1.0",
        "product_rappid": product_rappid,
        "source_revision": source_revision,
        "source_tree_digest": source_tree_digest,
        "birth_nonce": nonce.hex(),
    }
    digest = hashlib.sha256(canonical_json_bytes(birth)).hexdigest()
    suffix = "-twin"
    slug = match.group("slug")[: 63 - len(suffix)].rstrip("-") + suffix
    return {
        "identity_hash": digest,
        "instance_rappid": (
            f"rappid:@{match.group('owner')}/{slug}:{digest}"
        ),
        "product_rappid": product_rappid,
        "schema": "rapp-private-instance-identity/1.0",
    }
