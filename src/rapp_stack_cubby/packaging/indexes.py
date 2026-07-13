"""Build source and release-specific RAPP Store/super-RAR indexes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from ..constants import __version__
from .common import PackagingError

SUPER_RAR_SCHEMA = "rapp-super-rar/1.0"
STORE_INDEX_SCHEMA = "rapp-store-index/1.0"


def deduplicate_by_sha(
    entries: Iterable[Mapping[str, object]],
) -> list[dict]:
    """Join identical descriptors by SHA while preserving best rank."""

    joined: dict[str, dict] = {}
    for raw in entries:
        entry = dict(raw)
        digest = entry.get("sha256")
        rank = entry.get("rank")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or not isinstance(rank, int)
            or isinstance(rank, bool)
            or rank < 0
        ):
            raise PackagingError("index entry digest or rank is invalid")
        existing = joined.get(digest)
        if existing is None:
            entry["sources"] = sorted(set(entry.get("sources", [])))
            joined[digest] = entry
            continue
        if (
            existing.get("kind") != entry.get("kind")
            or existing.get("streamable") != entry.get("streamable")
        ):
            raise PackagingError("same SHA has conflicting index semantics")
        existing["rank"] = min(existing["rank"], rank)
        existing["sources"] = sorted(
            set(existing.get("sources", []))
            | set(entry.get("sources", []))
        )
    return sorted(
        joined.values(),
        key=lambda item: (
            item["rank"],
            str(item.get("kind", "")),
            item["sha256"],
        ),
    )


def build_super_rar_index(
    entries: Iterable[Mapping[str, object]],
    *,
    source_tree_digest: str,
    source_revision: str | None = None,
    release_specific: bool = False,
) -> dict:
    """Build one index in which only the controller may be streamable."""

    values = deduplicate_by_sha(entries)
    streamable = [entry for entry in values if entry.get("streamable") is True]
    if len(streamable) != 1 or streamable[0].get("kind") != "controller-agent":
        raise PackagingError(
            "super-RAR requires exactly one streamable controller"
        )
    for entry in values:
        if entry.get("kind") != "controller-agent" and entry.get(
            "streamable"
        ) is not False:
            raise PackagingError("non-controller super-RAR entries cannot stream")
    result = {
        "entries": values,
        "release_specific": release_specific,
        "schema": SUPER_RAR_SCHEMA,
        "source_tree_digest": source_tree_digest,
        "streamable_entry_count": 1,
        "version": __version__,
    }
    if source_revision is not None:
        result["source_revision"] = source_revision
    return result


def build_store_index(
    applications: Iterable[Mapping[str, object]],
    *,
    source_tree_digest: str,
    source_revision: str | None = None,
    release_specific: bool = False,
) -> dict:
    """Build a deterministic local Store intake index."""

    values = [dict(item) for item in applications]
    values.sort(
        key=lambda item: (
            str(item.get("application_id", "")),
            str(item.get("sha256", "")),
        )
    )
    if len(values) != 1 or values[0].get("application_id") != "rapp-stack":
        raise PackagingError("Store index must contain the RAPP stack application")
    application = values[0]
    if (
        "manifest_sha256" in application
        or not isinstance(application.get("application_manifest_sha256"), str)
        or len(application["application_manifest_sha256"]) != 64
        or not isinstance(application.get("application_manifest_size"), int)
        or isinstance(application["application_manifest_size"], bool)
        or application["application_manifest_size"] <= 0
    ):
        raise PackagingError("Store index application manifest binding is invalid")
    result = {
        "applications": values,
        "published": False,
        "release_specific": release_specific,
        "schema": STORE_INDEX_SCHEMA,
        "source_tree_digest": source_tree_digest,
        "version": __version__,
    }
    if source_revision is not None:
        result["source_revision"] = source_revision
    return result
