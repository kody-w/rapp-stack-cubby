"""Generate and validate repository-local source-census evidence shards."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import RappStackCubbyError

AUDIT_DIRECTORY = Path("docs/research/shards")
AUDIT_MANIFEST = Path("docs/research/AUDIT_MANIFEST.json")
SNAPSHOT = Path("docs/research/public-account-snapshot.json")
RAW_DIRECTORY = Path("docs/research/raw")
SHARD_COUNT = 8
PROMOTED_RAW_FIELDS = (
    "created_at",
    "current_head_sha",
    "current_observed_at",
    "default_branch",
    "description",
    "fork",
    "has_pages",
    "head_observed_at",
    "html_url",
    "language",
    "license_spdx_id",
    "name",
    "private",
    "pushed_at",
    "repository_id",
    "topics",
    "updated_at",
    "visibility",
)


class AuditArtifactError(RappStackCubbyError, ValueError):
    """Raised when local census evidence is incomplete or stale."""


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuditArtifactError(f"cannot read {path.name}") from error
    if not isinstance(value, dict):
        raise AuditArtifactError(f"{path.name} must contain an object")
    return value


def _pretty_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    try:
        return _sha256(path.read_bytes())
    except OSError as error:
        raise AuditArtifactError(f"cannot hash {path.name}") from error


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AuditArtifactError(f"{label} must be RFC3339 UTC")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise AuditArtifactError(f"{label} must be RFC3339 UTC") from error


def _validate_snapshot_capture(
    snapshot: Mapping[str, Any],
    census: Mapping[str, Any],
    raw_records: Sequence[Mapping[str, Any]],
    inventory_records: Sequence[Mapping[str, Any]],
    head_observations: Sequence[Mapping[str, Any]],
) -> None:
    existence_cutoff = snapshot.get("existence_cutoff")
    if existence_cutoff != census.get("existence_cutoff"):
        raise AuditArtifactError("census existence cutoff does not match snapshot")
    times = [
        _timestamp(existence_cutoff, "existence_cutoff"),
        _timestamp(snapshot.get("capture_started_at"), "capture_started_at"),
        _timestamp(
            snapshot.get("inventory_completed_at"),
            "inventory_completed_at",
        ),
        _timestamp(snapshot.get("heads_started_at"), "heads_started_at"),
        _timestamp(snapshot.get("capture_completed_at"), "capture_completed_at"),
    ]
    if times != sorted(times):
        raise AuditArtifactError("snapshot observation-window timing is invalid")

    if not (
        len(inventory_records) == len(head_observations) == len(raw_records)
    ):
        raise AuditArtifactError("raw inventory/head observation counts disagree")

    inventory_by_name = {
        str(item.get("name")): item for item in inventory_records
    }
    heads_by_name = {
        str(item.get("repository_name")): item for item in head_observations
    }
    if len(inventory_by_name) != len(inventory_records) or len(
        heads_by_name
    ) != len(head_observations):
        raise AuditArtifactError("raw inventory/head names are not unique")

    heads_start, capture_end = times[3], times[4]
    for raw in raw_records:
        name = str(raw.get("name"))
        inventory = inventory_by_name.get(name)
        head = heads_by_name.get(name)
        if inventory is None or head is None:
            raise AuditArtifactError(f"{name}: raw inventory/head record is absent")
        metadata = {
            key: value
            for key, value in raw.items()
            if key
            not in {
                "candidate_audit_shard",
                "candidate_sorted_index",
                "current_head_sha",
                "current_observed_at",
                "head_observed_at",
                "head_status",
            }
        }
        if metadata != dict(inventory):
            raise AuditArtifactError(f"{name}: combined raw metadata is stale")
        if (
            head.get("repository_id") != raw.get("repository_id")
            or head.get("default_branch") != raw.get("default_branch")
            or head.get("current_head_sha") != raw.get("current_head_sha")
            or head.get("observed_at") != raw.get("current_observed_at")
            or head.get("head_observed_at") != raw.get("head_observed_at")
            or raw.get("head_observed_at") != raw.get("current_observed_at")
            or head.get("head_status") != raw.get("head_status")
        ):
            raise AuditArtifactError(f"{name}: combined raw head is stale")
        observed = _timestamp(head.get("observed_at"), f"{name}: observed_at")
        started = _timestamp(
            head.get("request_started_at"),
            f"{name}: head request_started_at",
        )
        received = _timestamp(
            head.get("response_received_at"),
            f"{name}: head response_received_at",
        )
        if not (heads_start <= started <= received <= capture_end):
            raise AuditArtifactError(f"{name}: head timing is outside capture window")
        if (
            not isinstance(head.get("response_time_ms"), (int, float))
            or head["response_time_ms"] < 0
            or not isinstance(head.get("body_sha256"), str)
            or len(head["body_sha256"]) != 64
        ):
            raise AuditArtifactError(f"{name}: head response evidence is invalid")

    pages = snapshot.get("response_pages")
    if not isinstance(pages, list) or not pages:
        raise AuditArtifactError("inventory response pages are absent")
    inventory_start, inventory_end = times[1], times[2]
    for page in pages:
        if not isinstance(page, Mapping):
            raise AuditArtifactError("inventory response page is invalid")
        started = _timestamp(
            page.get("request_started_at"),
            "inventory page request_started_at",
        )
        received = _timestamp(
            page.get("response_received_at"),
            "inventory page response_received_at",
        )
        headers = page.get("headers")
        if not (
            inventory_start <= started <= received <= inventory_end
            and isinstance(page.get("response_time_ms"), (int, float))
            and page["response_time_ms"] >= 0
            and isinstance(page.get("body_sha256"), str)
            and len(page["body_sha256"]) == 64
            and isinstance(headers, Mapping)
            and isinstance(headers.get("etag"), str)
            and bool(headers["etag"])
        ):
            raise AuditArtifactError("inventory page response evidence is invalid")


def _snapshot_raw_records(
    repository: Path,
    snapshot: Mapping[str, Any],
) -> tuple[
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[Mapping[str, Any]],
    list[dict[str, Any]],
]:
    raw_records = snapshot.get("repositories")
    inventory_records = snapshot.get("inventory_records")
    head_observations = snapshot.get("head_observations")
    if all(
        isinstance(value, list)
        for value in (raw_records, inventory_records, head_observations)
    ):
        if not all(
            isinstance(item, Mapping)
            for values in (raw_records, inventory_records, head_observations)
            for item in values
        ):
            raise AuditArtifactError("inline raw snapshot records are invalid")
        return (
            list(raw_records),
            list(inventory_records),
            list(head_observations),
            [],
        )

    manifests = snapshot.get("raw_shards")
    if not isinstance(manifests, list) or len(manifests) != SHARD_COUNT:
        raise AuditArtifactError("raw snapshot shard manifest is invalid")
    repositories: list[Mapping[str, Any]] = []
    inventories: list[Mapping[str, Any]] = []
    heads: list[Mapping[str, Any]] = []
    validated: list[dict[str, Any]] = []
    for expected_shard, manifest in enumerate(manifests):
        if (
            not isinstance(manifest, Mapping)
            or manifest.get("shard") != expected_shard
            or not isinstance(manifest.get("path"), str)
        ):
            raise AuditArtifactError("raw snapshot shard descriptor is invalid")
        relative = Path(manifest["path"])
        if relative.parent != RAW_DIRECTORY or relative.name != (
            f"shard-{expected_shard}.json"
        ):
            raise AuditArtifactError("raw snapshot shard path is invalid")
        path = repository / relative
        try:
            payload = path.read_bytes()
            value = json.loads(payload)
        except (OSError, json.JSONDecodeError) as error:
            raise AuditArtifactError(
                f"cannot read raw snapshot shard {expected_shard}"
            ) from error
        if (
            payload != _pretty_bytes(value)
            or not isinstance(value, Mapping)
            or value.get("schema") != "rapp-raw-census-shard/1.0"
            or value.get("shard") != expected_shard
            or _sha256(payload) != manifest.get("sha256")
            or len(payload) != manifest.get("size")
        ):
            raise AuditArtifactError(
                f"raw snapshot shard {expected_shard} is invalid"
            )
        records = value.get("records")
        if not isinstance(records, list) or not all(
            isinstance(item, Mapping) for item in records
        ):
            raise AuditArtifactError(
                f"raw snapshot shard {expected_shard} records are invalid"
            )
        if len(records) != manifest.get("repository_count"):
            raise AuditArtifactError(
                f"raw snapshot shard {expected_shard} count is invalid"
            )
        for item in records:
            raw = item.get("repository")
            inventory = item.get("inventory_record")
            head = item.get("head_observation")
            if not all(
                isinstance(record, Mapping)
                for record in (raw, inventory, head)
            ):
                raise AuditArtifactError(
                    f"raw snapshot shard {expected_shard} entry is invalid"
                )
            if raw.get("candidate_audit_shard") != expected_shard:
                raise AuditArtifactError(
                    f"raw snapshot shard {expected_shard} assignment is stale"
                )
            repositories.append(raw)
            inventories.append(inventory)
            heads.append(head)
        validated.append(dict(manifest))
    repositories.sort(key=lambda item: int(item["candidate_sorted_index"]))
    inventories.sort(key=lambda item: str(item["name"]).casefold())
    heads.sort(key=lambda item: str(item["repository_name"]).casefold())
    return repositories, inventories, heads, validated


def _validate_cross_binding(
    records: Sequence[Mapping[str, Any]],
    raw_records: Sequence[Mapping[str, Any]],
) -> None:
    raw_by_name = {str(item.get("name")): item for item in raw_records}
    for record in records:
        name = str(record.get("name"))
        raw = raw_by_name.get(name)
        if raw is None:
            raise AuditArtifactError(f"{name}: promoted record lacks raw evidence")
        for field in PROMOTED_RAW_FIELDS:
            if record.get(field) != raw.get(field):
                raise AuditArtifactError(
                    f"{name}: promoted {field} does not match raw evidence"
                )


def _validate_drift_review(record: Mapping[str, Any]) -> None:
    name = str(record.get("name"))
    review = record.get("drift_review")
    if not isinstance(review, Mapping):
        raise AuditArtifactError(f"{name}: required drift review is absent")
    required_sections = {
        "capability_changes",
        "code",
        "disposition",
        "inspection_head_sha",
        "license",
        "pages",
        "readme",
        "specification_or_manifest",
        "tree",
    }
    missing = sorted(required_sections - review.keys())
    if missing:
        raise AuditArtifactError(
            f"{name}: drift review lacks {', '.join(missing)}"
        )
    if (
        review.get("completed") is not True
        or review.get("inspection_head_sha") != record.get("current_head_sha")
    ):
        raise AuditArtifactError(f"{name}: drift review is not pinned to current head")
    tree = review.get("tree")
    if (
        not isinstance(tree, Mapping)
        or not isinstance(tree.get("locator"), str)
        or not isinstance(tree.get("file_count"), int)
    ):
        raise AuditArtifactError(f"{name}: drift tree inspection is invalid")
    for section in ("code", "license", "pages", "readme", "specification_or_manifest"):
        if not isinstance(review.get(section), Mapping):
            raise AuditArtifactError(f"{name}: drift {section} inspection is invalid")


def _shard_record(repository: Mapping[str, Any]) -> dict[str, Any]:
    record = dict(repository)
    record["promoted_record_sha256"] = _sha256(_canonical_bytes(repository))
    return record


def build_audit_artifacts(
    root: str | Path,
) -> tuple[dict[str, bytes], dict[str, Any]]:
    """Build deterministic shard bytes and their digest manifest."""

    repository = Path(root).resolve()
    census = _read_object(repository / "SOURCE_CENSUS.json")
    snapshot = _read_object(repository / SNAPSHOT)
    records = census.get("repositories")
    (
        raw_records,
        inventory_records,
        head_observations,
        raw_shards,
    ) = _snapshot_raw_records(repository, snapshot)
    if not isinstance(records, list) or not all(
        isinstance(item, Mapping) for item in records
    ):
        raise AuditArtifactError("SOURCE_CENSUS repositories are invalid")
    count = census.get("repository_count")
    if count != len(records) or count != len(raw_records):
        raise AuditArtifactError("census and raw snapshot counts disagree")
    names = [str(item.get("name")) for item in records]
    raw_names = [str(item.get("name")) for item in raw_records]
    if names != sorted(names, key=str.casefold) or names != raw_names:
        raise AuditArtifactError(
            "census and snapshot names must match in deterministic order"
        )
    if len(set(names)) != len(names):
        raise AuditArtifactError("census repository names are not unique")
    _validate_snapshot_capture(
        snapshot,
        census,
        raw_records,
        inventory_records,
        head_observations,
    )
    _validate_cross_binding(records, raw_records)
    snapshot_digest = _sha256(_canonical_bytes(raw_records))
    inventory_digest = _sha256(_canonical_bytes(inventory_records))
    heads_digest = _sha256(_canonical_bytes(head_observations))
    declared_raw = census.get("raw_inventory")
    snapshot_raw = snapshot.get("raw_inventory")
    if (
        not isinstance(declared_raw, Mapping)
        or not isinstance(snapshot_raw, Mapping)
        or declared_raw.get("sha256") != snapshot_digest
        or snapshot_raw.get("sha256") != snapshot_digest
        or declared_raw.get("inventory_records_sha256") != inventory_digest
        or snapshot_raw.get("inventory_records_sha256") != inventory_digest
        or declared_raw.get("head_observations_sha256") != heads_digest
        or snapshot_raw.get("head_observations_sha256") != heads_digest
    ):
        raise AuditArtifactError("raw inventory digest does not match snapshot")

    required_drift = [
        item
        for item in records
        if item.get("head_drift") == "observed_changed_since_evidence"
        and item.get("classification") in {"A", "C", "I"}
    ]
    for record in required_drift:
        _validate_drift_review(record)

    grouped: dict[int, list[dict[str, Any]]] = {
        index: [] for index in range(SHARD_COUNT)
    }
    for index, record in enumerate(records):
        shard = record.get("audit_shard")
        if record.get("sorted_index") != index or shard != index % SHARD_COUNT:
            raise AuditArtifactError("census sorted index or shard assignment is stale")
        grouped[int(shard)].append(_shard_record(record))

    shard_bytes: dict[str, bytes] = {}
    shard_manifests: list[dict[str, Any]] = []
    for shard in range(SHARD_COUNT):
        value = {
            "existence_cutoff": census.get("existence_cutoff"),
            "methodology": {
                "evidence_scope": (
                    "Evidence notes and locators are pinned to evidence_head_sha; "
                    "current_head_sha is bounded observation-window drift context."
                ),
                "record_binding": (
                    "Each shard embeds every promoted census field plus a "
                    "canonical record digest."
                ),
                "source": "SOURCE_CENSUS.json",
            },
            "owner": census.get("owner"),
            "repositories": grouped[shard],
            "repository_count": len(grouped[shard]),
            "schema": "rapp-audit-shard/1.0",
            "shard": shard,
        }
        relative = (AUDIT_DIRECTORY / f"shard-{shard}.json").as_posix()
        payload = _pretty_bytes(value)
        shard_bytes[relative] = payload
        shard_manifests.append(
            {
                "first_repository": (
                    grouped[shard][0]["name"] if grouped[shard] else None
                ),
                "last_repository": (
                    grouped[shard][-1]["name"] if grouped[shard] else None
                ),
                "path": relative,
                "repository_count": len(grouped[shard]),
                "sha256": _sha256(payload),
                "shard": shard,
                "size": len(payload),
            }
        )

    inspection_records = [
        {
            "classification": record.get("classification"),
            "evidence_head_sha": record.get("evidence_head_sha"),
            "inspection": record.get("new_repository_inspection"),
            "name": record.get("name"),
        }
        for record in records
        if isinstance(record.get("new_repository_inspection"), Mapping)
    ]
    drift_review_records = [
        {
            "classification": record.get("classification"),
            "current_head_sha": record.get("current_head_sha"),
            "evidence_head_sha": record.get("evidence_head_sha"),
            "name": record.get("name"),
            "review": record.get("drift_review"),
        }
        for record in required_drift
    ]
    post_window_records = [
        {
            "current_head_sha": record.get("current_head_sha"),
            "evidence_head_sha": record.get("evidence_head_sha"),
            "head_observed_at": record.get("head_observed_at"),
            "name": record.get("name"),
        }
        for record in records
        if record.get("head_drift") == "post_window_drift"
    ]
    drift_counts = Counter(str(item.get("head_drift")) for item in records)
    classification_counts = Counter(
        str(item.get("classification")) for item in records
    )
    manifest = {
        "coverage": {
            "all_current_public_names_accounted": names == raw_names,
            "audit_complete": all(
                item.get("audited") is True for item in records
            )
            and len(drift_review_records) == len(required_drift),
            "audited_repository_count": sum(
                item.get("audited") is True for item in records
            ),
            "classification_counts": dict(sorted(classification_counts.items())),
            "head_drift_counts": dict(sorted(drift_counts.items())),
            "repository_count": len(records),
            "unique_repository_names": len(set(names)),
        },
        "drift_review": {
            "complete": len(drift_review_records) == len(required_drift),
            "records": drift_review_records,
            "required_count": len(required_drift),
        },
        "existence_cutoff": census.get("existence_cutoff"),
        "empty_repositories": [
            item["name"]
            for item in records
            if item.get("current_head_sha") is None
        ],
        "external_reports_required": False,
        "methodology": {
            "assignment": (
                "Case-insensitive repository-name order; sorted_index modulo 8."
            ),
            "authority": (
                "Authenticated GitHub API inventory and direct repository-local "
                "inspection; indexes are navigation only."
            ),
            "evidence_pinning": (
                "Existing evidence remains at evidence_head_sha. "
                "current_head_sha/head_drift never move old line citations."
            ),
            "observation_window": (
                "The snapshot is a bounded, non-atomic observation window. "
                "Inventory and head request/response times are retained; each "
                "head applies at its own observed_at."
            ),
            "local_context": (
                "Every shard and the raw sanitized snapshot are checked in; "
                "no external crawler report is needed."
            ),
        },
        "new_repository_inspections": inspection_records,
        "owner": census.get("owner"),
        "post_window_drift": {
            "repository_count": len(post_window_records),
            "repositories": post_window_records,
            "semantics": (
                "Movement after an earlier pinned inspection is recorded "
                "separately and does not rewrite that inspection."
            ),
        },
        "raw_inventory": {
            "canonical_repositories_sha256": snapshot_digest,
            "file_sha256": _sha256_file(repository / SNAPSHOT),
            "head_observations_sha256": heads_digest,
            "inventory_records_sha256": inventory_digest,
            "path": SNAPSHOT.as_posix(),
            "query": declared_raw.get("query"),
            "raw_shards": raw_shards,
            "repository_count": len(raw_records),
        },
        "schema": "rapp-audit-manifest/1.0",
        "shard_count": SHARD_COUNT,
        "shards": shard_manifests,
        "source_census": {
            "path": "SOURCE_CENSUS.json",
            "sha256": _sha256_file(repository / "SOURCE_CENSUS.json"),
        },
    }
    return shard_bytes, manifest


def write_audit_artifacts(root: str | Path) -> dict[str, Any]:
    repository = Path(root).resolve()
    shards, manifest = build_audit_artifacts(repository)
    directory = repository / AUDIT_DIRECTORY
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.glob("*.json"):
        if stale.name not in {Path(path).name for path in shards}:
            stale.unlink()
    for relative, payload in shards.items():
        (repository / relative).write_bytes(payload)
    (repository / AUDIT_MANIFEST).write_bytes(_pretty_bytes(manifest))
    validate_audit_artifacts(repository)
    return manifest


def validate_audit_artifacts(root: str | Path) -> dict[str, Any]:
    repository = Path(root).resolve()
    expected_shards, expected_manifest = build_audit_artifacts(repository)
    errors: list[str] = []
    observed_paths = sorted(
        path.relative_to(repository).as_posix()
        for path in (repository / AUDIT_DIRECTORY).glob("*.json")
    )
    if observed_paths != sorted(expected_shards):
        errors.append("audit shard file set is stale")
    for relative, payload in expected_shards.items():
        try:
            actual = (repository / relative).read_bytes()
        except OSError:
            errors.append(f"missing audit shard: {relative}")
            continue
        if actual != payload:
            errors.append(f"stale audit shard: {relative}")
    try:
        actual_manifest = (repository / AUDIT_MANIFEST).read_bytes()
    except OSError:
        errors.append("missing AUDIT_MANIFEST.json")
    else:
        if actual_manifest != _pretty_bytes(expected_manifest):
            errors.append("AUDIT_MANIFEST.json is stale")
    if errors:
        raise AuditArtifactError("; ".join(errors))
    return {
        "new_repository_inspection_count": len(
            expected_manifest["new_repository_inspections"]
        ),
        "repository_count": expected_manifest["coverage"]["repository_count"],
        "shard_count": expected_manifest["shard_count"],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.check:
            result = validate_audit_artifacts(args.root)
        else:
            manifest = write_audit_artifacts(args.root)
            result = {
                "repository_count": manifest["coverage"]["repository_count"],
                "shard_count": manifest["shard_count"],
            }
    except AuditArtifactError as error:
        print(f"error: {error}")
        return 2
    print(
        "PASS local census evidence: "
        f"{result['repository_count']} repositories in "
        f"{result['shard_count']} shards"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
