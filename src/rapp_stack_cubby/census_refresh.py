"""Authenticated, candidate-only refreshes of the public source census."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .errors import RappStackCubbyError

API_VERSION = "2022-11-28"
CANDIDATE_SCHEMA = "rapp-census-refresh-candidate/1.0"
PER_PAGE = 100
SHARD_COUNT = 8
_CUTOFF_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)
_STATUS_RE = re.compile(r"^HTTP/\S+\s+(\d{3})(?:\s+.*)?$")
_TOKEN_RE = re.compile(
    r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"(?i:authorization:\s*(?:token|bearer)\s+\S+))"
)
_PUBLIC_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)
_SAFE_RESPONSE_HEADERS = frozenset(
    {
        "date",
        "etag",
        "last-modified",
        "link",
        "x-github-api-version-selected",
        "x-github-request-id",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
        "x-ratelimit-used",
    }
)
_PROTECTED_OUTPUTS = frozenset(
    {
        "CAPABILITY_MATRIX.json",
        "SOURCE_CENSUS.json",
        "SYSTEM_GRAPH.json",
        "docs/research/AUDIT_MANIFEST.json",
        "docs/research/account-crawl.md",
        "docs/research/public-account-snapshot.json",
    }
)


class CensusRefreshError(RappStackCubbyError, ValueError):
    """Raised when a candidate refresh cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class ApiResponse:
    status: int
    headers: Mapping[str, str]
    body: Any


class ApiClient(Protocol):
    tool_version: str

    def get(
        self, path: str, *, parameters: Mapping[str, str] | None = None
    ) -> ApiResponse: ...


class GhApiClient:
    """Small `gh api` transport that never places a credential in arguments."""

    def __init__(self, executable: str = "gh") -> None:
        self._executable = executable
        try:
            completed = subprocess.run(
                [executable, "--version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise CensusRefreshError(
                "authenticated GitHub CLI is unavailable"
            ) from error
        first_line = completed.stdout.splitlines()
        self.tool_version = first_line[0].strip() if first_line else "gh (unknown)"

    def get(
        self, path: str, *, parameters: Mapping[str, str] | None = None
    ) -> ApiResponse:
        command = [
            self._executable,
            "api",
            "--include",
            "--method",
            "GET",
            "--header",
            f"X-GitHub-Api-Version: {API_VERSION}",
            path,
        ]
        for key, value in sorted((parameters or {}).items()):
            command.extend(("--raw-field", f"{key}={value}"))
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise CensusRefreshError("GitHub API transport failed") from error
        try:
            response = _parse_included_response(completed.stdout)
        except CensusRefreshError:
            detail = _safe_error_detail(completed.stderr)
            raise CensusRefreshError(
                "GitHub API returned no parseable response"
                + (f": {detail}" if detail else "")
            ) from None
        return response


def _safe_error_detail(value: bytes) -> str:
    text = value.decode("utf-8", "replace").strip().splitlines()
    if not text:
        return ""
    detail = _TOKEN_RE.sub("[REDACTED]", text[-1])
    return detail[:240]


def _parse_included_response(value: bytes) -> ApiResponse:
    separator = re.search(rb"\r?\n\r?\n", value)
    if separator is None:
        raise CensusRefreshError("missing GitHub API response headers")
    header_bytes = value[: separator.start()]
    body_bytes = value[separator.end() :]
    lines = header_bytes.decode("utf-8", "replace").splitlines()
    if not lines:
        raise CensusRefreshError("missing GitHub API status")
    status_match = _STATUS_RE.fullmatch(lines[0].strip())
    if status_match is None:
        raise CensusRefreshError("invalid GitHub API status")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator_text, content = line.partition(":")
        if separator_text and name.strip().casefold() in _SAFE_RESPONSE_HEADERS:
            headers[name.strip().casefold()] = content.strip()
    try:
        body = json.loads(body_bytes)
    except json.JSONDecodeError as error:
        raise CensusRefreshError("invalid GitHub API JSON") from error
    return ApiResponse(int(status_match.group(1)), headers, body)


def _checked(
    response: ApiResponse,
    *,
    expected: frozenset[int] = frozenset({200}),
) -> Any:
    if response.status in expected:
        return response.body
    if response.status in {403, 429}:
        remaining = response.headers.get("x-ratelimit-remaining", "unknown")
        reset = response.headers.get("x-ratelimit-reset", "unknown")
        raise CensusRefreshError(
            "GitHub API rate/error response "
            f"{response.status} (remaining={remaining}, reset={reset})"
        )
    raise CensusRefreshError(f"GitHub API request failed with HTTP {response.status}")


def _validate_cutoff(value: str) -> datetime:
    if not _CUTOFF_RE.fullmatch(value):
        raise CensusRefreshError(
            "cutoff must be an exact UTC RFC3339 timestamp ending in Z"
        )
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CensusRefreshError("cutoff is not a valid timestamp") from error


def _parse_observed_time(value: str, *, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CensusRefreshError(f"{label} is invalid") from error
    if parsed.utcoffset() is None:
        raise CensusRefreshError(f"{label} lacks a timezone")
    return parsed


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _observed_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _timed_get(
    client: ApiClient,
    path: str,
    *,
    parameters: Mapping[str, str] | None = None,
) -> tuple[ApiResponse, dict[str, Any]]:
    request_started_at = _observed_now()
    started = time.monotonic_ns()
    response = client.get(path, parameters=parameters)
    elapsed_ns = time.monotonic_ns() - started
    response_received_at = _observed_now()
    return response, {
        "request_started_at": request_started_at,
        "response_received_at": response_received_at,
        "response_time_ms": round(elapsed_ns / 1_000_000, 3),
    }


def _response_metadata(
    page: int,
    response: ApiResponse,
    item_count: int,
    timing: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "body_sha256": hashlib.sha256(
            _canonical_bytes(response.body)
        ).hexdigest(),
        "headers": dict(sorted(response.headers.items())),
        "item_count": item_count,
        "page": page,
        "status": response.status,
        **timing,
    }


def _metadata_record(repository: Mapping[str, Any]) -> dict[str, Any]:
    license_value = repository.get("license")
    topics = repository.get("topics")
    if not isinstance(topics, list):
        topics = []
    description = repository.get("description")
    if isinstance(description, str):
        description = _PUBLIC_EMAIL_RE.sub(
            "[PUBLIC-IDENTIFIER-REDACTED]", description
        )
    return {
        "archived": bool(repository.get("archived")),
        "created_at": repository.get("created_at"),
        "default_branch": repository.get("default_branch"),
        "description": description,
        "disabled": bool(repository.get("disabled")),
        "fork": bool(repository.get("fork")),
        "full_name": repository.get("full_name"),
        "has_pages": bool(repository.get("has_pages")),
        "homepage": repository.get("homepage"),
        "html_url": repository.get("html_url"),
        "language": repository.get("language"),
        "license_spdx_id": (
            license_value.get("spdx_id")
            if isinstance(license_value, Mapping)
            else None
        ),
        "name": repository.get("name"),
        "private": bool(repository.get("private")),
        "pushed_at": repository.get("pushed_at"),
        "repository_id": repository.get("id"),
        "size_kib": repository.get("size"),
        "topics": sorted(
            topic
            for topic in topics
            if isinstance(topic, str)
        ),
        "updated_at": repository.get("updated_at"),
        "visibility": repository.get("visibility"),
    }


def _head_for(
    client: ApiClient, owner: str, repository: Mapping[str, Any]
) -> tuple[str | None, str, dict[str, Any]]:
    branch = repository.get("default_branch")
    name = str(repository["name"])
    repository_endpoint = (
        f"repos/{urllib.parse.quote(owner, safe='')}/"
        f"{urllib.parse.quote(name, safe='')}/commits"
    )
    if isinstance(branch, str) and branch:
        endpoint = (
            f"{repository_endpoint}/{urllib.parse.quote(branch, safe='')}"
        )
        parameters = None
    else:
        endpoint = repository_endpoint
        parameters = {"per_page": "1"}
    response, timing = _timed_get(
        client,
        endpoint,
        parameters=parameters,
    )
    observation = {
        "body_sha256": hashlib.sha256(
            _canonical_bytes(response.body)
        ).hexdigest(),
        "default_branch": branch,
        "endpoint": f"GET /{endpoint}",
        "headers": dict(sorted(response.headers.items())),
        "head_observed_at": timing["response_received_at"],
        "observed_at": timing["response_received_at"],
        "repository_id": repository.get("id"),
        "repository_name": name,
        "status": response.status,
        **timing,
    }
    if response.status in {404, 409} and int(repository.get("size") or 0) == 0:
        observation["current_head_sha"] = None
        observation["head_status"] = "empty_repository"
        return None, "empty_repository", observation
    body = _checked(response)
    if isinstance(body, list) and len(body) == 0 and not branch:
        observation["current_head_sha"] = None
        observation["head_status"] = "empty_repository"
        return None, "empty_repository", observation
    if isinstance(body, list) and len(body) == 1:
        body = body[0]
    if not isinstance(body, Mapping):
        raise CensusRefreshError(f"{name}: commit response is not an object")
    sha = body.get("sha")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise CensusRefreshError(f"{name}: default-branch head is invalid")
    observation["current_head_sha"] = sha
    observation["head_status"] = "resolved_exact"
    return sha, "resolved_exact", observation


def _baseline_records(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    repositories = value.get("repositories")
    if not isinstance(repositories, list) or not all(
        isinstance(item, Mapping) for item in repositories
    ):
        raise CensusRefreshError("baseline census repositories are invalid")
    return repositories


def _diff(
    baseline: Mapping[str, Any],
    current: list[dict[str, Any]],
) -> dict[str, Any]:
    old_records = _baseline_records(baseline)
    old_by_name = {str(item.get("name")): item for item in old_records}
    current_by_name = {str(item["name"]): item for item in current}
    old_names = set(old_by_name)
    current_names = set(current_by_name)
    old_by_id = {
        item.get("repository_id"): str(item.get("name"))
        for item in old_records
        if isinstance(item.get("repository_id"), int)
    }
    current_by_id = {
        item.get("repository_id"): str(item.get("name"))
        for item in current
        if isinstance(item.get("repository_id"), int)
    }
    renames = [
        {
            "from": old_by_id[repository_id],
            "repository_id": repository_id,
            "to": current_by_id[repository_id],
        }
        for repository_id in sorted(set(old_by_id) & set(current_by_id))
        if old_by_id[repository_id] != current_by_id[repository_id]
    ]
    renamed_old = {item["from"] for item in renames}
    renamed_new = {item["to"] for item in renames}
    changed_heads: list[str] = []
    changed_relevant: list[str] = []
    for name in sorted(old_names & current_names, key=str.casefold):
        old = old_by_name[name]
        baseline_head = old.get("current_head_sha", old.get("head_sha"))
        if baseline_head != current_by_name[name].get("current_head_sha"):
            changed_heads.append(name)
            if old.get("classification") != "U":
                changed_relevant.append(name)
    return {
        "added": sorted(current_names - old_names - renamed_new, key=str.casefold),
        "baseline_count": len(old_records),
        "candidate_count": len(current),
        "changed_heads": changed_heads,
        "changed_relevant_repositories": changed_relevant,
        "removed": sorted(old_names - current_names - renamed_old, key=str.casefold),
        "renamed": renames,
    }


def build_refresh_candidate(
    client: ApiClient,
    *,
    owner: str,
    cutoff: str,
    baseline: Mapping[str, Any],
) -> dict[str, Any]:
    """Fetch metadata and heads without mutating audited evidence."""

    cutoff_time = _validate_cutoff(cutoff)
    capture_started_at = _observed_now()
    pages: list[dict[str, Any]] = []
    repositories: list[Mapping[str, Any]] = []
    page = 1
    while True:
        response, timing = _timed_get(
            client,
            f"users/{urllib.parse.quote(owner, safe='')}/repos",
            parameters={
                "direction": "asc",
                "page": str(page),
                "per_page": str(PER_PAGE),
                "sort": "full_name",
                "type": "owner",
            },
        )
        body = _checked(response)
        if not isinstance(body, list) or not all(
            isinstance(item, Mapping) for item in body
        ):
            raise CensusRefreshError("repository page is not an object array")
        pages.append(_response_metadata(page, response, len(body), timing))
        repositories.extend(body)
        if len(body) < PER_PAGE:
            break
        page += 1
        if page > 1_000:
            raise CensusRefreshError("repository pagination did not terminate")
    inventory_completed_at = _observed_now()

    names = [item.get("name") for item in repositories]
    if not all(isinstance(name, str) and name for name in names):
        raise CensusRefreshError("repository metadata contains an invalid name")
    if len(set(names)) != len(names):
        raise CensusRefreshError("repository metadata contains duplicate names")

    included: list[dict[str, Any]] = []
    inventory_records: list[dict[str, Any]] = []
    head_observations: list[dict[str, Any]] = []
    excluded_after_cutoff: list[str] = []
    post_cutoff_metadata: list[str] = []
    heads_started_at = _observed_now()
    for source in sorted(repositories, key=lambda item: str(item["name"]).casefold()):
        created = source.get("created_at")
        if not isinstance(created, str):
            raise CensusRefreshError(f"{source['name']}: created_at is absent")
        created_time = _parse_observed_time(
            created, label=f"{source['name']}: created_at"
        )
        if created_time > cutoff_time:
            excluded_after_cutoff.append(str(source["name"]))
            continue
        record = _metadata_record(source)
        inventory_records.append(dict(record))
        head, head_status, observation = _head_for(client, owner, source)
        record["current_head_sha"] = head
        record["current_observed_at"] = observation["observed_at"]
        record["head_observed_at"] = observation["head_observed_at"]
        record["head_status"] = head_status
        head_observations.append(observation)
        for field in ("updated_at", "pushed_at"):
            observed = record.get(field)
            if isinstance(observed, str) and _parse_observed_time(
                observed, label=f"{source['name']}: {field}"
            ) > cutoff_time:
                post_cutoff_metadata.append(str(source["name"]))
                break
        included.append(record)
    capture_completed_at = _observed_now()

    included.sort(key=lambda item: str(item["name"]).casefold())
    inventory_records.sort(key=lambda item: str(item["name"]).casefold())
    head_observations.sort(
        key=lambda item: str(item["repository_name"]).casefold()
    )
    for index, record in enumerate(included):
        record["candidate_audit_shard"] = index % SHARD_COUNT
        record["candidate_sorted_index"] = index

    difference = _diff(baseline, included)
    inventory_digest = hashlib.sha256(_canonical_bytes(included)).hexdigest()
    metadata_digest = hashlib.sha256(
        _canonical_bytes(inventory_records)
    ).hexdigest()
    heads_digest = hashlib.sha256(
        _canonical_bytes(head_observations)
    ).hexdigest()
    return {
        "capture_completed_at": capture_completed_at,
        "capture_started_at": capture_started_at,
        "cutoff": cutoff,
        "diff": difference,
        "existence_cutoff": cutoff,
        "excluded_after_cutoff": sorted(excluded_after_cutoff, key=str.casefold),
        "head_observations": head_observations,
        "heads_started_at": heads_started_at,
        "inventory_completed_at": inventory_completed_at,
        "inventory_records": inventory_records,
        "methodology": {
            "authority": (
                "Authenticated direct GitHub REST API metadata and exact "
                "default-branch commit responses; ecosystem indexes are not evidence."
            ),
            "candidate_only": True,
            "classification_policy": (
                "New repositories and changed relevant repositories require "
                "human direct inspection before audited promotion."
            ),
            "cutoff_semantics": (
                "Inclusive repository-existence cutoff by created_at. "
                "existence_cutoff is distinct from the observation window."
            ),
            "observation_window": (
                "This is a bounded, non-atomic observation window. Inventory "
                "pages and default-branch heads were observed at their recorded "
                "request/response times. Repositories created on or before the "
                "existence cutoff are eligible; each head describes only its "
                "per-repository observation time."
            ),
            "sanitization": (
                "Only selected public metadata fields are retained; "
                "email-shaped identifiers in free-text descriptions are redacted."
            ),
            "pagination": "Explicit page/per_page loop until a short page.",
        },
        "owner": owner,
        "post_cutoff_metadata_observations": sorted(
            set(post_cutoff_metadata), key=str.casefold
        ),
        "query": {
            "api_version": API_VERSION,
            "endpoint": f"GET /users/{owner}/repos",
            "parameters": {
                "direction": "asc",
                "per_page": PER_PAGE,
                "sort": "full_name",
                "type": "owner",
            },
            "tool": client.tool_version,
        },
        "raw_inventory": {
            "canonicalization": "UTF-8 RFC8259; sorted keys; compact separators",
            "head_observations_sha256": heads_digest,
            "inventory_records_sha256": metadata_digest,
            "repository_count": len(included),
            "sha256": inventory_digest,
        },
        "repositories": included,
        "response_pages": pages,
        "review_required": {
            "changed_relevant_repositories": difference[
                "changed_relevant_repositories"
            ],
            "new_repositories": difference["added"],
        },
        "schema": CANDIDATE_SCHEMA,
        "sharding": {
            "assignment": "case-insensitive name sort; sorted_index modulo 8",
            "shard_count": SHARD_COUNT,
        },
    }


def write_refresh_candidate(
    root: str | Path,
    output: str | Path,
    *,
    owner: str,
    cutoff: str,
    client: ApiClient | None = None,
) -> dict[str, Any]:
    repository = Path(root).resolve(strict=True)
    destination = Path(output)
    if not destination.is_absolute():
        destination = repository / destination
    destination = destination.resolve()
    try:
        relative = destination.relative_to(repository).as_posix()
    except ValueError as error:
        raise CensusRefreshError(
            "candidate output must remain inside the repository"
        ) from error
    if relative in _PROTECTED_OUTPUTS or relative.startswith(
        "docs/research/shards/"
    ):
        raise CensusRefreshError(
            "refresh-census never overwrites audited evidence or promoted inventory"
        )
    if destination.suffix.casefold() != ".json":
        raise CensusRefreshError("candidate output must be an explicit JSON path")
    baseline_path = repository / "SOURCE_CENSUS.json"
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CensusRefreshError("cannot read baseline SOURCE_CENSUS.json") from error
    selected_client = client if client is not None else GhApiClient()
    candidate = build_refresh_candidate(
        selected_client,
        owner=owner,
        cutoff=cutoff,
        baseline=baseline,
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(candidate, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return candidate


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="refresh-census",
        description=(
            "Fetch an authenticated public-repository candidate without "
            "overwriting audited evidence."
        ),
    )
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--cutoff", required=True)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        candidate = write_refresh_candidate(
            args.root,
            args.output,
            owner=args.owner,
            cutoff=args.cutoff,
        )
    except CensusRefreshError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(
        "PASS census refresh candidate: "
        f"{candidate['raw_inventory']['repository_count']} repositories, "
        f"{len(candidate['diff']['added'])} added, "
        f"{len(candidate['diff']['removed'])} removed, "
        f"{len(candidate['diff']['renamed'])} renamed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
