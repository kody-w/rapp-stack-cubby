"""Structured validation for the repository's scaffold contracts."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .constants import (
    AGENT_CATALOG_SCHEMA,
    CAPABILITY_MATRIX_SCHEMA,
    CONTROLLER_CATALOG_SCHEMA,
    CUBBY_ANATOMY,
    CUBBY_SCHEMA,
    EXPECTED_ACTUAL_AGENT_COUNT,
    EXPECTED_CAPABILITY_COUNT,
    EXPECTED_REPOSITORY_COUNT,
    EXPECTED_SELECTED_CAPABILITY_COUNT,
    EXPECTED_STREAMABLE_CONTROLLER_COUNT,
    IMPLEMENTATION_MATRIX_SCHEMA,
    MINIMUM_CAPABILITY_COUNT,
    PROVENANCE_SCHEMA,
    REQUIRED_TOP_LEVEL_FILES,
    SOURCE_CENSUS_SCHEMA,
    STACK_LOCK_SCHEMA,
    SYSTEM_GRAPH_SCHEMA,
    __version__,
)
from .catalog import (
    CATALOG_RELATIVE,
    CONTROLLER_AGENT_RELATIVE,
    CONTROLLER_CATALOG_RELATIVE,
    IMPLEMENTATION_MATRIX_RELATIVE,
    build_controller_catalog,
    validate_catalogs,
)
from .context import SCHEMAS, validate_context
from .dependencies import validate_dependency_inputs
from .errors import (
    ContractReadError,
    RappStackCubbyError,
    UnsafePathError,
    VerificationError,
)
from .paths import repository_path

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RFC3339_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:api[_-]?key|credential|password|private[_-]?key|secret|token)",
    re.IGNORECASE,
)
_ABSOLUTE_LOCAL_PATH_RE = re.compile(
    r"(?:/(?:Users|home)/[^/\s]+/|[A-Za-z]:\\Users\\[^\\\s]+\\)"
)
_SAFE_PLACEHOLDERS = frozenset(
    {
        "",
        "changeme",
        "example",
        "not-set",
        "null",
        "placeholder",
        "replace-me",
        "unset",
    }
)
_FORBIDDEN_FILE_NAMES = frozenset(
    {
        ".DS_Store",
        ".env",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "secrets.json",
    }
)
_FORBIDDEN_SUFFIXES = (
    ".db",
    ".journal",
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".pid",
    ".pyc",
    ".sqlite",
    ".sqlite3",
    ".sqlite-shm",
    ".sqlite-wal",
)
_IGNORED_SCAN_PARTS = frozenset({".git", ".check-cache"})
_FORBIDDEN_DIRECTORY_NAMES = frozenset(
    {"__pycache__", ".rapp-stack-cubby", ".venv", "runtime", "state", "venv"}
)
_REVIEWED_RUNTIME_PREFIXES = (
    ("src", "rapp_stack_cubby", "runtime"),
    ("src", "rapp_stack_cubby", "protocols"),
    ("tests", "runtime"),
    ("tests", "protocols"),
)
_REQUIRED_RUNTIME_MODULES = frozenset(
    {
        "__init__.py",
        "app.py",
        "basic_agent.py",
        "config.py",
        "orchestrator.py",
        "provider.py",
        "registry.py",
        "server.py",
        "storage.py",
    }
)
_REQUIRED_PROTOCOL_MODULES = frozenset(
    {
        "__init__.py",
        "canonical.py",
        "crypto.py",
        "replay.py",
        "twin_chat.py",
    }
)
_ORIGINAL_IMPLEMENTATION_PREFIXES = (
    "src/rapp_stack_cubby/imessage/",
    "src/rapp_stack_cubby/runtime/",
    "src/rapp_stack_cubby/protocols/",
)
_ORIGINAL_IMPLEMENTATION_FILES = frozenset(
    {
        "src/rapp_stack_cubby/command_manifest.py",
        "src/rapp_stack_cubby/demo.py",
        "src/rapp_stack_cubby/dependencies.py",
        "src/rapp_stack_cubby/doctor.py",
    }
)


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The structured result of one repository check."""

    name: str
    passed: bool
    details: Mapping[str, bool | int | str] = field(default_factory=dict)
    errors: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "name": self.name,
            "passed": self.passed,
            "details": dict(self.details),
            "errors": list(self.errors),
        }


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """The complete repository verification result."""

    root: Path
    checks: tuple[CheckResult, ...]

    @property
    def ok(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failed_checks(self) -> tuple[CheckResult, ...]:
        return tuple(check for check in self.checks if not check.passed)

    @property
    def error_count(self) -> int:
        return sum(len(check.errors) for check in self.checks)

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""

        return {
            "ok": self.ok,
            "check_count": len(self.checks),
            "failed_check_count": len(self.failed_checks),
            "error_count": self.error_count,
            "checks": [check.as_dict() for check in self.checks],
        }


CheckFunction = Callable[[Path], tuple[dict[str, bool | int | str], list[str]]]


def verify_repository(root: str | Path) -> VerificationResult:
    """Validate every current repository scaffold contract."""

    repository = Path(root).expanduser().resolve()
    checks = (
        _run_check("required_files", repository, _check_required_files),
        _run_check("source_census", repository, _check_source_census),
        _run_check("capability_matrix", repository, _check_capability_matrix),
        _run_check("system_graph", repository, _check_system_graph),
        _run_check("stack_lock", repository, _check_stack_lock),
        _run_check("dependency_lock", repository, _check_dependency_lock),
        _run_check("packaging_closure", repository, _check_packaging_closure),
        _run_check("provenance", repository, _check_provenance),
        _run_check("agent_closure", repository, _check_agent_closure),
        _run_check(
            "controller_closure", repository, _check_controller_closure
        ),
        _run_check("context_closure", repository, _check_context_closure),
        _run_check("placeholder_config", repository, _check_placeholder_config),
    )
    return VerificationResult(root=repository, checks=checks)


def census_summary(root: str | Path) -> dict[str, Any]:
    """Return a summary only after the census contract validates."""

    repository = Path(root).expanduser().resolve()
    details, errors = _check_source_census(repository)
    if errors:
        raise VerificationError("SOURCE_CENSUS.json: " + "; ".join(errors))

    data = _read_json_object(repository, "SOURCE_CENSUS.json")
    return {
        "schema": data["schema"],
        "owner": data["owner"],
        "audited_at": data["audited_at"],
        "repository_count": details["repository_count"],
        "classification_counts": data["aggregates"]["classification_counts"],
    }


def _run_check(
    name: str, root: Path, function: CheckFunction
) -> CheckResult:
    try:
        details, errors = function(root)
    except ContractReadError as error:
        return CheckResult(name=name, passed=False, errors=(str(error),))
    return CheckResult(
        name=name,
        passed=not errors,
        details=details,
        errors=tuple(errors),
    )


def _check_dependency_lock(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    result = validate_dependency_inputs(root)
    return {
        "package_count": result.package_count,
        "scanned_file_count": result.scanned_file_count,
    }, list(result.errors)


def _check_packaging_closure(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    from .packaging.common import PackagingError, read_json_object
    from .packaging.identity import validate_identity
    from .packaging.release import load_release_trust
    from .packaging.source import validate_source_manifest

    errors: list[str] = []
    file_count = 0
    try:
        source = validate_source_manifest(root)
        file_count = source["file_count"]
        validate_identity(
            read_json_object(root / "birth.json"),
            read_json_object(root / "rappid.json"),
        )
        load_release_trust(root / "RELEASE_TRUST.json")
    except (PackagingError, OSError) as error:
        errors.append(str(error))
    controller = root / "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
    singleton = (
        root
        / "cubbies/kody-w/rapplications/rapp-stack/singleton/"
        "rapp_stack_cubby_agent.py"
    )
    try:
        if controller.read_bytes() != singleton.read_bytes():
            errors.append("controller singleton is not byte-identical")
    except OSError:
        errors.append("controller singleton is missing")
    for relative, schema in (
        ("STORE_INDEX.json", "rapp-store-index/1.0"),
        ("rapp-super-rar.json", "rapp-super-rar/1.0"),
        (
            "cubbies/kody-w/rapplications/rapp-stack/manifest.json",
            "rapp-application/1.0",
        ),
        (
            "cubbies/kody-w/rapplications/rapp-stack/index_entry.json",
            "rapp-store-entry/1.0",
        ),
    ):
        try:
            value = read_json_object(root / relative)
            if value.get("schema") != schema:
                errors.append(f"{relative}: schema is invalid")
        except PackagingError as error:
            errors.append(str(error))
    try:
        super_index = read_json_object(root / "rapp-super-rar.json")
        entries = super_index.get("entries")
        if not isinstance(entries, list):
            raise PackagingError("super-RAR entries are invalid")
        for entry in entries:
            if not isinstance(entry, dict):
                raise PackagingError("super-RAR entry is invalid")
            sources = entry.get("sources")
            if not isinstance(sources, list) or not sources:
                raise PackagingError("super-RAR source binding is missing")
            source_path = sources[0]
            if (
                not isinstance(source_path, str)
                or _sha256(root, source_path) != entry.get("sha256")
                or (root / source_path).stat().st_size != entry.get("size")
            ):
                raise PackagingError("super-RAR source entry is stale")
        if (
            sum(item.get("streamable") is True for item in entries) != 1
            or next(
                item for item in entries if item.get("streamable") is True
            ).get("kind")
            != "controller-agent"
        ):
            raise PackagingError("super-RAR streamability is invalid")

        application_root = (
            root / "cubbies/kody-w/rapplications/rapp-stack"
        )
        application = read_json_object(application_root / "manifest.json")
        records = [application.get("controller"), *application.get("agents", [])]
        for record in records:
            if (
                not isinstance(record, dict)
                or _sha256(application_root, record.get("path"))
                != record.get("sha256")
            ):
                raise PackagingError("rapplication source descriptor is stale")
        index_entry = read_json_object(application_root / "index_entry.json")
        if "manifest_sha256" in index_entry:
            raise PackagingError("embedded Store entry cannot self-bind a manifest")
        store = read_json_object(root / "STORE_INDEX.json")
        applications = store.get("applications")
        if (
            not isinstance(applications, list)
            or len(applications) != 1
            or applications[0].get("application_manifest_sha256")
            != _sha256(application_root, "manifest.json")
            or applications[0].get("application_manifest_size")
            != (application_root / "manifest.json").stat().st_size
        ):
            raise PackagingError("committed Store index is stale")
        ui = (application_root / "ui/index.html").read_text(encoding="utf-8")
        if any(
            token in ui.casefold()
            for token in (
                "fetch(",
                "xmlhttprequest",
                "localstorage",
                "sessionstorage",
                "http://",
                "https://",
            )
        ):
            raise PackagingError("local UI uses network or browser storage")
    except (PackagingError, OSError, StopIteration, TypeError) as error:
        errors.append(str(error))
    forbidden_binary_count = 0
    for directory, names, files in os.walk(root, topdown=True):
        current = Path(directory)
        relative = current.relative_to(root)
        names[:] = [
            name
            for name in names
            if name
            not in {
                ".git",
                ".check-cache",
                "__pycache__",
                "build",
                "dist",
            }
        ]
        for name in files:
            path = relative / name
            lowered = name.casefold()
            if (
                lowered.endswith((".whl", ".egg", ".pyc"))
                or lowered == "imsg-macos.zip"
            ):
                forbidden_binary_count += 1
                errors.append(f"source binary is forbidden: {path.as_posix()}")
    return {
        "forbidden_binary_count": forbidden_binary_count,
        "source_file_count": file_count,
    }, errors


def _read_json_object(root: Path, relative_path: str) -> dict[str, Any]:
    try:
        path = repository_path(root, relative_path)
    except UnsafePathError as error:
        raise ContractReadError(str(error)) from error

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ContractReadError(
            f"{relative_path}: cannot read ({error.strerror or type(error).__name__})"
        ) from error

    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ContractReadError(
            f"{relative_path}: invalid JSON at line {error.lineno}, "
            f"column {error.colno}: {error.msg}"
        ) from error

    if not isinstance(value, dict):
        raise ContractReadError(f"{relative_path}: top-level value must be an object")
    return value


def _sha256(root: Path, relative_path: str) -> str:
    try:
        path = repository_path(root, relative_path)
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except (OSError, UnsafePathError) as error:
        detail = getattr(error, "strerror", None) or str(error)
        raise ContractReadError(
            f"{relative_path}: cannot hash ({detail})"
        ) from error


def _check_required_files(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    missing = [name for name in REQUIRED_TOP_LEVEL_FILES if not (root / name).is_file()]
    errors = [f"missing required top-level file: {name}" for name in missing]
    return {
        "required_count": len(REQUIRED_TOP_LEVEL_FILES),
        "present_count": len(REQUIRED_TOP_LEVEL_FILES) - len(missing),
    }, errors


def _check_source_census(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    data = _read_json_object(root, "SOURCE_CENSUS.json")
    errors: list[str] = []
    repositories = data.get("repositories")

    if data.get("schema") != SOURCE_CENSUS_SCHEMA:
        errors.append(f"schema must be {SOURCE_CENSUS_SCHEMA}")
    if not isinstance(repositories, list):
        return {"repository_count": 0}, errors + ["repositories must be an array"]

    declared_count = data.get("repository_count")
    actual_count = len(repositories)
    if declared_count != actual_count:
        errors.append(
            f"repository_count is {declared_count!r}, expected array length {actual_count}"
        )
    if actual_count != EXPECTED_REPOSITORY_COUNT:
        errors.append(
            f"repositories contains {actual_count}, expected "
            f"{EXPECTED_REPOSITORY_COUNT}"
        )

    names: list[str] = []
    casefolded_names: list[str] = []
    audited_count = 0
    classifications: Counter[str] = Counter()
    required_keys = {
        "audit_shard",
        "audited",
        "classification",
        "current_head_sha",
        "current_observed_at",
        "created_at",
        "default_branch",
        "description",
        "direct_evidence_note",
        "evidence_head_sha",
        "evidence_locators",
        "evidence_release",
        "evidence_scope",
        "has_pages",
        "head_observed_at",
        "head_sha",
        "head_drift",
        "html_url",
        "language",
        "license",
        "license_spdx_id",
        "license_report_label",
        "name",
        "parse_status",
        "private",
        "primary_plane",
        "pushed_at",
        "rapp_relevance",
        "repository_id",
        "sorted_index",
        "topics",
        "updated_at",
        "visibility",
    }

    for index, repository in enumerate(repositories):
        if not isinstance(repository, dict):
            errors.append(f"repositories[{index}] must be an object")
            continue
        missing = sorted(required_keys - repository.keys())
        if missing:
            errors.append(
                f"repositories[{index}] missing keys: {', '.join(missing)}"
            )
        name = repository.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"repositories[{index}].name must be a non-empty string")
        else:
            names.append(name)
            casefolded_names.append(name.casefold())
        if repository.get("sorted_index") != index:
            errors.append(
                f"repositories[{index}].sorted_index must equal {index}"
            )
        if repository.get("audited") is True:
            audited_count += 1
        else:
            errors.append(f"repositories[{index}].audited must be true")
        classification = repository.get("classification")
        if isinstance(classification, str):
            classifications[classification] += 1
        head_sha = repository.get("head_sha")
        if head_sha is not None and (
            not isinstance(head_sha, str) or not _COMMIT_RE.fullmatch(head_sha)
        ):
            errors.append(
                f"repositories[{index}].head_sha must be null or 40 lowercase hex"
            )
        evidence_head = repository.get("evidence_head_sha")
        current_head = repository.get("current_head_sha")
        if head_sha != evidence_head:
            errors.append(
                f"repositories[{index}].head_sha must alias evidence_head_sha"
            )
        for field, value in (
            ("evidence_head_sha", evidence_head),
            ("current_head_sha", current_head),
        ):
            if value is not None and (
                not isinstance(value, str) or not _COMMIT_RE.fullmatch(value)
            ):
                errors.append(
                    f"repositories[{index}].{field} must be null or 40 lowercase hex"
                )
        observed_at = repository.get("current_observed_at")
        if not isinstance(observed_at, str) or not _RFC3339_Z_RE.fullmatch(
            observed_at
        ):
            errors.append(
                f"repositories[{index}].current_observed_at must be RFC3339 UTC"
            )
        if repository.get("head_observed_at") != observed_at:
            errors.append(
                f"repositories[{index}].head_observed_at must alias "
                "current_observed_at"
            )
        drift = repository.get("head_drift")
        allowed_drift = {
            "empty_repository",
            "new_repository_inspected_at_current_head",
            "observed_changed_since_evidence",
            "post_window_drift",
            "unchanged",
        }
        if drift not in allowed_drift:
            errors.append(f"repositories[{index}].head_drift is invalid")
        elif drift == "empty_repository" and not (
            evidence_head is None and current_head is None
        ):
            errors.append(
                f"repositories[{index}].head_drift contradicts non-empty head"
            )
        elif drift == "observed_changed_since_evidence" and (
            evidence_head is None or current_head is None or evidence_head == current_head
        ):
            errors.append(
                f"repositories[{index}].head_drift does not describe changed heads"
            )
        elif drift == "post_window_drift" and (
            evidence_head is None or current_head is None or evidence_head == current_head
        ):
            errors.append(
                f"repositories[{index}].head_drift does not describe post-window change"
            )
        elif drift in {"unchanged", "new_repository_inspected_at_current_head"} and (
            evidence_head != current_head
        ):
            errors.append(
                f"repositories[{index}].head_drift does not describe equal heads"
            )

    if len(set(names)) != len(names):
        errors.append("repository names must be unique")
    if len(set(casefolded_names)) != len(casefolded_names):
        errors.append("repository names must be unique case-insensitively")
    if names != sorted(names, key=str.casefold):
        errors.append("repositories must be sorted case-insensitively by name")

    aggregates = data.get("aggregates")
    if not isinstance(aggregates, dict):
        errors.append("aggregates must be an object")
    else:
        expected_aggregates = {
            "repository_objects": actual_count,
            "audited_true": audited_count,
            "unique_repository_names": len(set(names)),
            "unique_repository_names_case_insensitive": len(
                set(casefolded_names)
            ),
        }
        for key, expected in expected_aggregates.items():
            if aggregates.get(key) != expected:
                errors.append(
                    f"aggregates.{key} is {aggregates.get(key)!r}, expected {expected}"
                )
        if aggregates.get("classification_counts") != dict(classifications):
            errors.append("aggregates.classification_counts does not match repositories")

    cutoff = data.get("snapshot_cutoff")
    if not isinstance(cutoff, str) or not _RFC3339_Z_RE.fullmatch(cutoff):
        errors.append("snapshot_cutoff must be an exact UTC RFC3339 timestamp")
    existence_cutoff = data.get("existence_cutoff")
    if (
        not isinstance(existence_cutoff, str)
        or not _RFC3339_Z_RE.fullmatch(existence_cutoff)
        or cutoff != existence_cutoff
    ):
        errors.append(
            "existence_cutoff must be exact UTC RFC3339 and match the "
            "snapshot compatibility cutoff"
        )
    observation_window = data.get("observation_window")
    if not isinstance(observation_window, dict) or any(
        not isinstance(observation_window.get(field), str)
        or not _RFC3339_Z_RE.fullmatch(observation_window[field])
        for field in (
            "capture_started_at",
            "inventory_completed_at",
            "heads_started_at",
            "capture_completed_at",
        )
    ):
        errors.append("observation_window timing is invalid")
    antecedent = data.get("antecedent_audit")
    if not isinstance(antecedent, dict) or antecedent.get("repository_count") != 299:
        errors.append("antecedent audit must preserve the 299-repository release")
    local_product = data.get("local_product")
    if (
        not isinstance(local_product, dict)
        or local_product.get("node_id") != "product:local/rapp-stack-cubby"
        or local_product.get("antecedent_public_repository") is not False
        or local_product.get("included_in_repository_count") is not False
    ):
        errors.append("local product census boundary is invalid")
    try:
        from .audit import validate_audit_artifacts

        audit = validate_audit_artifacts(root)
    except (RappStackCubbyError, OSError) as error:
        errors.append(f"local audit artifacts are invalid: {error}")
    else:
        if audit["repository_count"] != actual_count:
            errors.append("local audit artifact coverage does not match census")

    return {
        "repository_count": actual_count,
        "unique_name_count": len(set(names)),
        "audited_count": audited_count,
    }, errors


def _check_capability_matrix(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    data = _read_json_object(root, "CAPABILITY_MATRIX.json")
    errors: list[str] = []
    capabilities = data.get("capabilities")

    if data.get("schema") != CAPABILITY_MATRIX_SCHEMA:
        errors.append(f"schema must be {CAPABILITY_MATRIX_SCHEMA}")
    if data.get("repository_count") != EXPECTED_REPOSITORY_COUNT:
        errors.append(
            f"repository_count must be {EXPECTED_REPOSITORY_COUNT}"
        )
    if not isinstance(capabilities, list):
        return {"capability_count": 0}, errors + ["capabilities must be an array"]

    if len(capabilities) < MINIMUM_CAPABILITY_COUNT:
        errors.append(
            f"capabilities contains {len(capabilities)}, expected at least "
            f"{MINIMUM_CAPABILITY_COUNT}"
        )
    if len(capabilities) != EXPECTED_CAPABILITY_COUNT:
        errors.append(
            f"capabilities contains {len(capabilities)}, expected exactly "
            f"{EXPECTED_CAPABILITY_COUNT}"
        )

    ids: list[str] = []
    selected_count = 0
    statuses: Counter[str] = Counter()
    planes: Counter[str] = Counter()
    required_keys = {
        "direct_source_repositories",
        "id",
        "implementations",
        "major_gaps",
        "plane",
        "protocol_or_contract",
        "purpose",
        "required_tests",
        "security_notes",
        "selected_for_cubby",
        "selected_implementation",
        "status",
    }

    for index, capability in enumerate(capabilities):
        if not isinstance(capability, dict):
            errors.append(f"capabilities[{index}] must be an object")
            continue
        missing = sorted(required_keys - capability.keys())
        if missing:
            errors.append(
                f"capabilities[{index}] missing keys: {', '.join(missing)}"
            )
        capability_id = capability.get("id")
        if not isinstance(capability_id, str) or not capability_id:
            errors.append(f"capabilities[{index}].id must be a non-empty string")
        else:
            ids.append(capability_id)
        selected = capability.get("selected_for_cubby")
        if not isinstance(selected, bool):
            errors.append(
                f"capabilities[{index}].selected_for_cubby must be boolean"
            )
        elif selected:
            selected_count += 1
        status = capability.get("status")
        plane = capability.get("plane")
        if isinstance(status, str):
            statuses[status] += 1
        if isinstance(plane, str):
            planes[plane] += 1
        sources = capability.get("direct_source_repositories")
        if isinstance(sources, list):
            for source_index, source in enumerate(sources):
                if not isinstance(source, dict):
                    continue
                if (
                    "evidence_head_sha" not in source
                    or "current_head_sha" not in source
                    or "head_drift" not in source
                ):
                    errors.append(
                        f"capabilities[{index}].direct_source_repositories"
                        f"[{source_index}] lacks explicit evidence/current head context"
                    )

    if len(set(ids)) != len(ids):
        errors.append("capability ids must be unique")
    if ids != sorted(ids):
        errors.append("capabilities must be sorted by id")
    if selected_count != EXPECTED_SELECTED_CAPABILITY_COUNT:
        errors.append(
            f"selected capability count is {selected_count}, expected "
            f"{EXPECTED_SELECTED_CAPABILITY_COUNT}"
        )

    aggregates = data.get("aggregates")
    if not isinstance(aggregates, dict):
        errors.append("aggregates must be an object")
    else:
        expected = {
            "capability_count": len(capabilities),
            "selected_count": selected_count,
            "counts_by_status": dict(statuses),
            "counts_by_plane": dict(planes),
        }
        for key, value in expected.items():
            if aggregates.get(key) != value:
                errors.append(f"aggregates.{key} does not match capabilities")

    _check_census_reference(root, data.get("source_census"), errors)
    by_id = {
        item.get("id"): item for item in capabilities if isinstance(item, dict)
    }
    clean_room = by_id.get("runtime.clean-room-implementation")
    if (
        not isinstance(clean_room, dict)
        or clean_room.get("selected_for_cubby") is not True
        or clean_room.get("selected_implementation")
        != "runtime:isolated-runtime/clean-room"
        or clean_room.get("status") != "implemented"
        or clean_room.get("direct_source_repositories") != []
        or "runtime.microsoft-source-baseline" in by_id
    ):
        errors.append("clean-room runtime capability selection is invalid")
    scanner = by_id.get("release.scanner-matrix")
    if (
        not isinstance(scanner, dict)
        or scanner.get("selected_implementation")
        != "packaging:publication-scan"
        or scanner.get("status") != "implemented"
    ):
        errors.append("full publication scanner selection is invalid")
    return {
        "capability_count": len(capabilities),
        "unique_id_count": len(set(ids)),
        "selected_count": selected_count,
    }, errors


def _check_system_graph(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    data = _read_json_object(root, "SYSTEM_GRAPH.json")
    census = _read_json_object(root, "SOURCE_CENSUS.json")
    errors: list[str] = []
    repo_nodes = data.get("repo_nodes")
    non_repo_nodes = data.get("non_repo_nodes")
    edges = data.get("edges")

    if data.get("schema") != SYSTEM_GRAPH_SCHEMA:
        errors.append(f"schema must be {SYSTEM_GRAPH_SCHEMA}")
    if not isinstance(repo_nodes, list):
        return {"repo_node_count": 0}, errors + ["repo_nodes must be an array"]
    if not isinstance(non_repo_nodes, list):
        errors.append("non_repo_nodes must be an array")
        non_repo_nodes = []
    if not isinstance(edges, list):
        errors.append("edges must be an array")
        edges = []

    if len(repo_nodes) != EXPECTED_REPOSITORY_COUNT:
        errors.append(
            f"repo_nodes contains {len(repo_nodes)}, expected "
            f"{EXPECTED_REPOSITORY_COUNT}"
        )

    census_repositories = census.get("repositories")
    if not isinstance(census_repositories, list):
        errors.append("SOURCE_CENSUS.json repositories must be an array")
        census_repositories = []
    census_by_name = {
        repository["name"]: repository
        for repository in census_repositories
        if isinstance(repository, dict) and isinstance(repository.get("name"), str)
    }

    repo_ids: list[str] = []
    repo_names: list[str] = []
    for index, node in enumerate(repo_nodes):
        if not isinstance(node, dict):
            errors.append(f"repo_nodes[{index}] must be an object")
            continue
        node_id = node.get("id")
        name = node.get("name")
        if isinstance(node_id, str):
            repo_ids.append(node_id)
        else:
            errors.append(f"repo_nodes[{index}].id must be a string")
        if isinstance(name, str):
            repo_names.append(name)
        else:
            errors.append(f"repo_nodes[{index}].name must be a string")
            continue
        census_repository = census_by_name.get(name)
        if census_repository is None:
            errors.append(f"repo node has no census match: {name}")
            continue
        expected_id = f"repo:{census.get('owner')}/{name}"
        if node_id != expected_id:
            errors.append(f"repo node {name} id must be {expected_id}")
        for field_name in (
            "audited",
            "classification",
            "current_head_sha",
            "current_observed_at",
            "direct_evidence_note",
            "evidence_head_sha",
            "head_sha",
            "head_drift",
            "head_observed_at",
        ):
            if node.get(field_name) != census_repository.get(field_name):
                errors.append(
                    f"repo node {name} field {field_name} does not match census"
                )

    if len(set(repo_ids)) != len(repo_ids):
        errors.append("repo node ids must be unique")
    if len(set(repo_names)) != len(repo_names):
        errors.append("repo node names must be unique")
    if set(repo_names) != set(census_by_name):
        missing = sorted(set(census_by_name) - set(repo_names), key=str.casefold)
        errors.append(
            "graph repository names must exactly match census"
            + (f"; missing: {', '.join(missing[:5])}" if missing else "")
        )
    if repo_names != sorted(repo_names, key=str.casefold):
        errors.append("repo_nodes must be sorted case-insensitively by name")

    non_repo_ids = [
        node.get("id")
        for node in non_repo_nodes
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    ]
    if len(non_repo_ids) != len(non_repo_nodes):
        errors.append("every non_repo_node must be an object with a string id")
    all_node_ids = set(repo_ids) | set(non_repo_ids)
    if len(all_node_ids) != len(repo_ids) + len(non_repo_ids):
        errors.append("all graph node ids must be unique")

    edge_ids: list[str] = []
    endpoint_errors = 0
    for index, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"edges[{index}] must be an object")
            continue
        edge_id = edge.get("id")
        if isinstance(edge_id, str):
            edge_ids.append(edge_id)
        else:
            errors.append(f"edges[{index}].id must be a string")
        for endpoint in ("source_id", "target_id"):
            endpoint_id = edge.get(endpoint)
            if endpoint_id not in all_node_ids:
                endpoint_errors += 1
                errors.append(
                    f"edge {edge_id or index} {endpoint} does not name a graph node"
                )
    if len(set(edge_ids)) != len(edge_ids):
        errors.append("edge ids must be unique")
    if edge_ids != sorted(edge_ids):
        errors.append("edges must be sorted by id")

    aggregates = data.get("aggregates")
    if not isinstance(aggregates, dict):
        errors.append("aggregates must be an object")
    else:
        expected_counts = {
            "repo_node_count": len(repo_nodes),
            "non_repo_node_count": len(non_repo_nodes),
            "edge_count": len(edges),
            "total_node_count": len(repo_nodes) + len(non_repo_nodes),
        }
        for key, expected in expected_counts.items():
            if aggregates.get(key) != expected:
                errors.append(
                    f"aggregates.{key} is {aggregates.get(key)!r}, expected {expected}"
                )

    _check_census_reference(root, data.get("source_census"), errors)
    try:
        from .graph import validate_system_graph

        validate_system_graph(root)
    except (RappStackCubbyError, OSError) as error:
        errors.append(f"generated system graph is invalid: {error}")
    product_nodes = [
        item
        for item in non_repo_nodes
        if isinstance(item, dict)
        and item.get("id") == "product:local/rapp-stack-cubby"
    ]
    if (
        len(product_nodes) != 1
        or product_nodes[0].get("antecedent_public_repository") is not False
    ):
        errors.append("explicit non-antecedent local product node is required")
    node_ids = set(non_repo_ids)
    if "runtime:microsoft-hardened-adaptation" in node_ids:
        errors.append("false Microsoft runtime adaptation node is forbidden")
    if "runtime:clean-room-brainstem" not in node_ids:
        errors.append("clean-room runtime node is required")
    actor_edges = {
        (edge.get("source_id"), edge.get("target_id"))
        for edge in edges
        if isinstance(edge, dict)
    }
    for required in (
        ("actor:local-owner", "runtime:global-controller"),
        ("actor:local-owner", "transport:imsg-json-rpc"),
    ):
        if required not in actor_edges:
            errors.append(f"local owner graph edge is missing: {required[1]}")
    return {
        "repo_node_count": len(repo_nodes),
        "non_repo_node_count": len(non_repo_nodes),
        "edge_count": len(edges),
        "invalid_endpoint_count": endpoint_errors,
    }, errors


def _check_stack_lock(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    data = _read_json_object(root, "STACK_LOCK.json")
    errors: list[str] = []
    required_keys = {
        "artifact_chain",
        "build_policy",
        "dependency_policy",
        "evidence_inputs",
        "lock_status",
        "pin_counts",
        "profile",
        "project",
        "protocol_pins",
        "runtime_pins",
        "schema",
        "source_pins",
        "unresolved",
    }

    if data.get("schema") != STACK_LOCK_SCHEMA:
        errors.append(f"schema must be {STACK_LOCK_SCHEMA}")
    missing = sorted(required_keys - data.keys())
    if missing:
        errors.append(f"missing top-level keys: {', '.join(missing)}")

    pin_groups = (
        ("source", data.get("source_pins")),
        ("runtime", data.get("runtime_pins")),
        ("protocol", data.get("protocol_pins")),
    )
    pin_ids: list[str] = []
    malformed_pins = 0
    counts: dict[str, int] = {}
    for group_name, pins in pin_groups:
        if not isinstance(pins, list):
            errors.append(f"{group_name}_pins must be an array")
            counts[group_name] = 0
            continue
        counts[group_name] = len(pins)
        for index, pin in enumerate(pins):
            if not isinstance(pin, dict):
                errors.append(f"{group_name}_pins[{index}] must be an object")
                malformed_pins += 1
                continue
            pin_id = pin.get("id")
            if isinstance(pin_id, str) and pin_id:
                pin_ids.append(pin_id)
            else:
                errors.append(f"{group_name}_pins[{index}].id must be a string")
            commit = pin.get("commit")
            if not isinstance(commit, str) or not _COMMIT_RE.fullmatch(commit):
                malformed_pins += 1
                errors.append(
                    f"{group_name}_pins[{index}].commit must be 40 lowercase hex"
                )
            commit_url = pin.get("commit_url")
            if (
                isinstance(commit, str)
                and _COMMIT_RE.fullmatch(commit)
                and (
                    not isinstance(commit_url, str)
                    or commit not in commit_url
                )
            ):
                errors.append(
                    f"{group_name}_pins[{index}].commit_url must contain commit"
                )
            verification = pin.get("verification")
            status = (
                verification.get("status")
                if isinstance(verification, dict)
                else None
            )
            if not isinstance(status, str) or not status.startswith("verified"):
                errors.append(
                    f"{group_name}_pins[{index}] verification is unresolved"
                )

    if len(set(pin_ids)) != len(pin_ids):
        errors.append("pin ids must be unique across all pin groups")

    pin_counts = data.get("pin_counts")
    if not isinstance(pin_counts, dict):
        errors.append("pin_counts must be an object")
    else:
        for group_name, count in counts.items():
            if pin_counts.get(group_name) != count:
                errors.append(
                    f"pin_counts.{group_name} is {pin_counts.get(group_name)!r}, "
                    f"expected {count}"
                )
        if pin_counts.get("total") != len(pin_ids):
            errors.append("pin_counts.total does not match pin arrays")
        if pin_counts.get("verified_commit_pins") != len(pin_ids) - malformed_pins:
            errors.append("pin_counts.verified_commit_pins does not match valid pins")
        if pin_counts.get("unresolved_commit_pins") != 0:
            errors.append("pin_counts.unresolved_commit_pins must be zero")

    unresolved = data.get("unresolved")
    if not isinstance(unresolved, list):
        errors.append("unresolved must be an array")
        unresolved = []
    unresolved_ids = [
        item.get("id")
        for item in unresolved
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    if len(unresolved_ids) != len(unresolved):
        errors.append("every unresolved entry must be an object with a string id")
    if len(set(unresolved_ids)) != len(unresolved_ids):
        errors.append("unresolved ids must be unique")
    for index, item in enumerate(unresolved):
        if isinstance(item, dict) and item.get("status") != "unresolved":
            errors.append(f"unresolved[{index}].status must be unresolved")

    lock_status = data.get("lock_status")
    if not isinstance(lock_status, dict):
        errors.append("lock_status must be an object")
    elif lock_status.get("unresolved_count") != len(unresolved):
        errors.append("lock_status.unresolved_count does not match unresolved")

    build_policy = data.get("build_policy")
    release_stages = (
        build_policy.get("release_stages")
        if isinstance(build_policy, dict)
        else None
    )
    candidate_stage = (
        release_stages.get("candidate")
        if isinstance(release_stages, dict)
        else None
    )
    final_stage = (
        release_stages.get("final")
        if isinstance(release_stages, dict)
        else None
    )
    protected_stage = (
        release_stages.get("protected_prerelease")
        if isinstance(release_stages, dict)
        else None
    )
    live_stage = (
        release_stages.get("live_private")
        if isinstance(release_stages, dict)
        else None
    )
    expected_candidate_gates = {
        "final-release-sha",
        "live-enrollment-publication-proof",
        "publication-scan",
        "public-end-to-end-attestation",
    }
    if (
        not isinstance(release_stages, dict)
        or not isinstance(candidate_stage, dict)
        or not isinstance(final_stage, dict)
        or release_stages.get("profile") != "unchanged-candidate/1.0"
        or release_stages.get("follow_up_source_commit_allowed") is not False
        or release_stages.get("phase_order")
        != [
            "A-source-offline",
            "B-protected-prerelease",
            "C-live-private",
            "D-pages-promotion",
        ]
        or set(
            candidate_stage.get("allowed_unresolved_ids", [])
        )
        != expected_candidate_gates
        or candidate_stage.get("publication")
        != "protected_prerelease_only"
        or candidate_stage.get("asset_mutation_after_attestation")
        is not False
        or candidate_stage.get("phase") != "A-source-offline"
        or candidate_stage.get("offline_installed_attestation_required")
        is not True
        or candidate_stage.get("publication_scan_receipt")
        != "signed_source_history_pages_release_assets_zero_findings"
        or not isinstance(protected_stage, dict)
        or protected_stage.get("phase") != "B-protected-prerelease"
        or protected_stage.get("commit_and_assets")
        != "unchanged_from_phase_a"
        or protected_stage.get("public_redownload_attestation_required")
        is not True
        or protected_stage.get("candidate_publication_scan_asset_required")
        is not True
        or protected_stage.get("postflight_evidence")
        != "signed_attested_actions_artifact_not_release_mutation"
        or protected_stage.get("failure_state")
        != "explicit_failed_prerelease_no_pages"
        or not isinstance(live_stage, dict)
        or live_stage.get("phase") != "C-live-private"
        or live_stage.get("same_public_commit_required") is not True
        or live_stage.get("model_preflight_required") is not True
        or live_stage.get("owner_enrollment_private") is not True
        or final_stage.get("allowed_unresolved_ids") != []
        or set(final_stage.get("source_allowed_unresolved_ids", []))
        != expected_candidate_gates
        or final_stage.get("external_promotion_receipt_closes_source_gates")
        is not True
        or final_stage.get("receipt_signature_required") is not True
        or final_stage.get("same_source_commit_required") is not True
        or final_stage.get("phase") != "D-pages-promotion"
        or final_stage.get("new_source_commit_allowed") is not False
        or final_stage.get("promotion")
        != "same_prerelease_assets_tag_and_commit_only"
        or final_stage.get("promotion_evidence")
        != "signed_attested_actions_artifact_then_verified_pages"
        or final_stage.get("second_publication_scan_required")
        != "signed_public_redownload_and_completed_actions_logs"
    ):
        errors.append("build_policy.release_stages is invalid")

    project = data.get("project")
    if not isinstance(project, dict):
        errors.append("project must be an object")
    elif project.get("newly_authored_code_license") != "MIT":
        errors.append("project.newly_authored_code_license must be MIT")
    elif (
        project.get("candidate_version") != __version__
        or project.get("candidate_tag")
        != "v" + re.sub(r"rc([1-9][0-9]*)$", r"-rc.\1", __version__)
    ):
        errors.append("project candidate version/tag is invalid")

    dependency_policy = data.get("dependency_policy")
    python_policy = (
        dependency_policy.get("python")
        if isinstance(dependency_policy, dict)
        else None
    )
    if (
        not isinstance(python_policy, dict)
        or python_policy.get("version_range") != ">=3.11,<3.12"
    ):
        errors.append(
            "dependency_policy.python.version_range must be >=3.11,<3.12"
        )
    imsg_policy = (
        dependency_policy.get("imsg")
        if isinstance(dependency_policy, dict)
        else None
    )
    installed = (
        imsg_policy.get("installed_verification")
        if isinstance(imsg_policy, dict)
        else None
    )
    if (
        not isinstance(imsg_policy, dict)
        or imsg_policy.get("status") != "resolved_pinned_verified_installer"
        or imsg_policy.get("version") != "0.12.3"
        or imsg_policy.get("sha256")
        != "35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2"
        or imsg_policy.get("annotated_ref")
        != "76585a9e13a33534bec26d5478482efcc238f803"
        or imsg_policy.get("source_commit")
        != "dea78a9e9c493740575b03e443041ef5fbd2d463"
        or not isinstance(installed, dict)
        or installed.get("archive_hash_verified") is not True
        or installed.get("architectures_verified") is not True
        or installed.get("codesign_strict_verified") is not True
        or installed.get("layout_verified") is not True
        or installed.get("team_and_authority_verified") is not True
        or installed.get("version_verified") is not True
        or installed.get("owner_config_initialized") is not False
        or installed.get("message_sent") is not False
    ):
        errors.append("dependency_policy.imsg installed verification is invalid")

    _check_evidence_inputs(root, data.get("evidence_inputs"), errors)
    return {
        "pin_count": len(pin_ids),
        "malformed_pin_count": malformed_pins,
        "unresolved_contract_count": len(unresolved),
    }, errors


def _check_provenance(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    data = _read_json_object(root, "PROVENANCE.json")
    lock = _read_json_object(root, "STACK_LOCK.json")
    errors: list[str] = []
    entries = data.get("entries")

    if data.get("schema") != PROVENANCE_SCHEMA:
        errors.append(f"schema must be {PROVENANCE_SCHEMA}")
    legal_scope = data.get("legal_review_scope")
    if (
        not isinstance(legal_scope, str)
        or "not an independent external legal audit" not in legal_scope
    ):
        errors.append("provenance must not overstate external legal review")
    if not isinstance(entries, list):
        return {"entry_count": 0}, errors + ["entries must be an array"]

    entry_ids: list[str] = []
    inclusion_states: Counter[str] = Counter()
    cleared_count = 0
    copied_count = 0
    external_entries = 0
    valid_external_commits = 0
    unresolved_external_commits = 0
    lock_entry_valid_commits = 0
    lock_entry_unresolved_commits = 0
    original_file_count = 0
    authored_agent_file_count = 0
    agent_closure_support_file_count = 0
    generated_catalog_file_count = 0
    context_closure_file_count = 0
    generated_context_file_count = 0
    schema_profile_file_count = 0
    pages_file_count = 0
    github_action_pin_count = 0

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"entries[{index}] must be an object")
            continue
        entry_id = entry.get("id")
        if isinstance(entry_id, str) and entry_id:
            entry_ids.append(entry_id)
        else:
            errors.append(f"entries[{index}].id must be a non-empty string")
        state = entry.get("inclusion_state")
        if isinstance(state, str):
            inclusion_states[state] += 1
        cleared = entry.get("cleared_files")
        copied = entry.get("copied_files")
        if isinstance(cleared, list):
            cleared_count += len(cleared)
        else:
            errors.append(f"entries[{index}].cleared_files must be an array")
        if isinstance(copied, list):
            copied_count += len(copied)
        else:
            errors.append(f"entries[{index}].copied_files must be an array")
        original_files = entry.get("original_files")
        if state == "original_new":
            if isinstance(original_files, list):
                original_file_count += len(original_files)
            elif original_files is not None:
                errors.append(f"entries[{index}].original_files must be an array")
            authored_agent_files = entry.get("authored_agent_files")
            if isinstance(authored_agent_files, list):
                authored_agent_file_count += len(authored_agent_files)
            elif authored_agent_files is not None:
                errors.append(
                    f"entries[{index}].authored_agent_files must be an array"
                )
            generated_catalog_files = entry.get("generated_catalog_files")
            if isinstance(generated_catalog_files, list):
                generated_catalog_file_count += len(generated_catalog_files)
            elif generated_catalog_files is not None:
                errors.append(
                    f"entries[{index}].generated_catalog_files must be an array"
                )
            context_files = entry.get("context_closure_files")
            if isinstance(context_files, list):
                context_closure_file_count += len(context_files)
                generated_context_file_count += sum(
                    isinstance(record, dict)
                    and record.get("provenance") == "generated_local"
                    for record in context_files
                )
                schema_profile_file_count += sum(
                    isinstance(record, dict)
                    and isinstance(record.get("path"), str)
                    and record["path"].startswith("schemas/")
                    for record in context_files
                )
            elif context_files is not None:
                errors.append(
                    f"entries[{index}].context_closure_files must be an array"
                )
            support_files = entry.get("agent_closure_support_files")
            if isinstance(support_files, list):
                agent_closure_support_file_count += len(support_files)
            elif support_files is not None:
                errors.append(
                    f"entries[{index}].agent_closure_support_files must be an array"
                )
            pages_files = entry.get("pages_files")
            if isinstance(pages_files, list):
                pages_file_count += len(pages_files)
            elif pages_files is not None:
                errors.append(f"entries[{index}].pages_files must be an array")
        if isinstance(entry_id, str) and entry_id.startswith(
            "dependency-github-action-"
        ):
            github_action_pin_count += 1

        is_external = state != "original_new"
        commit = entry.get("commit")
        commit_valid = isinstance(commit, str) and bool(_COMMIT_RE.fullmatch(commit))
        if commit is not None and not commit_valid:
            errors.append(
                f"entries[{index}].commit must be null or 40 lowercase hex"
            )
        if commit_valid:
            commit_url = entry.get("commit_url")
            if not isinstance(commit_url, str) or commit not in commit_url:
                errors.append(
                    f"entries[{index}].commit_url must contain commit"
                )
        if is_external:
            external_entries += 1
            if commit_valid:
                valid_external_commits += 1
            elif commit is None:
                unresolved_external_commits += 1
        if entry.get("stack_lock_id") is not None:
            if commit_valid:
                lock_entry_valid_commits += 1
            elif commit is None:
                lock_entry_unresolved_commits += 1

    if len(set(entry_ids)) != len(entry_ids):
        errors.append("entry ids must be unique")
    if entry_ids != sorted(entry_ids):
        errors.append("entries must be sorted by id")

    counts = data.get("counts")
    expected_counts: dict[str, Any] = {
        "entry_count": len(entries),
        "external_source_entries": external_entries,
        "cleared_file_count": cleared_count,
        "copied_file_count": copied_count,
        "declared_external_commit_pins": valid_external_commits,
        "verified_external_commit_pins": valid_external_commits,
        "unresolved_external_commit_pins": unresolved_external_commits,
        "lock_pin_reference_count": lock_entry_valid_commits
        + lock_entry_unresolved_commits,
        "lock_pin_verified_count": lock_entry_valid_commits,
        "lock_pin_unresolved_count": lock_entry_unresolved_commits,
        "original_file_count": original_file_count,
        "authored_agent_file_count": authored_agent_file_count,
        "agent_closure_support_file_count": agent_closure_support_file_count,
        "generated_catalog_file_count": generated_catalog_file_count,
        "context_closure_file_count": context_closure_file_count,
        "generated_context_file_count": generated_context_file_count,
        "schema_profile_file_count": schema_profile_file_count,
        "pages_file_count": pages_file_count,
        "github_action_pin_count": github_action_pin_count,
        "inclusion_states": dict(inclusion_states),
    }
    if not isinstance(counts, dict):
        errors.append("counts must be an object")
    else:
        for key, expected in expected_counts.items():
            if counts.get(key) != expected:
                errors.append(f"counts.{key} does not match entries")

    lock_pin_ids = data.get("lock_pin_ids")
    stack_pin_ids = {
        pin.get("id")
        for group in ("source_pins", "runtime_pins", "protocol_pins")
        for pin in lock.get(group, [])
        if isinstance(pin, dict)
    }
    if not isinstance(lock_pin_ids, list):
        errors.append("lock_pin_ids must be an array")
    elif set(lock_pin_ids) != stack_pin_ids:
        errors.append("lock_pin_ids must exactly match STACK_LOCK.json pin ids")

    target_entries = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("id") == "target-rapp-stack-cubby"
    ]
    if len(target_entries) != 1:
        errors.append("target-rapp-stack-cubby provenance entry is required")
    else:
        target_license = target_entries[0].get("license")
        if (
            target_entries[0].get("inclusion_state") != "original_new"
            or not isinstance(target_license, dict)
            or target_license.get("spdx") != "MIT"
        ):
            errors.append(
                "target-rapp-stack-cubby must be original_new with MIT license"
            )
        _check_original_runtime_files(
            root,
            target_entries[0],
            lock,
            errors,
        )
        _check_authored_agent_files(
            root,
            target_entries[0],
            lock,
            errors,
        )
        _check_controller_files(
            root,
            target_entries[0],
            lock,
            errors,
        )
        _check_context_files(
            root,
            target_entries[0],
            lock,
            errors,
        )
        _check_pages_files(
            root,
            target_entries[0],
            lock,
            entries,
            errors,
        )

    runtime_reference = [
        entry
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("id") == "runtime-microsoft-aibast"
    ]
    if len(runtime_reference) != 1:
        errors.append("runtime-microsoft-aibast provenance entry is required")
    elif (
        runtime_reference[0].get("inclusion_state") != "reference_only"
        or runtime_reference[0].get("copied_files") != []
        or runtime_reference[0].get("cleared_files") != []
    ):
        errors.append(
            "runtime-microsoft-aibast must remain reference_only with no files"
        )

    _check_imessage_provenance(root, entries, errors)

    _check_evidence_inputs(root, data.get("evidence_inputs"), errors)
    return {
        "entry_count": len(entries),
        "external_entry_count": external_entries,
        "cleared_file_count": cleared_count,
        "copied_file_count": copied_count,
        "original_file_count": original_file_count,
        "authored_agent_file_count": authored_agent_file_count,
        "agent_closure_support_file_count": agent_closure_support_file_count,
        "generated_catalog_file_count": generated_catalog_file_count,
        "context_closure_file_count": context_closure_file_count,
        "generated_context_file_count": generated_context_file_count,
        "schema_profile_file_count": schema_profile_file_count,
        "pages_file_count": pages_file_count,
        "github_action_pin_count": github_action_pin_count,
    }, errors


def _check_imessage_provenance(
    root: Path,
    entries: Sequence[object],
    errors: list[str],
) -> None:
    adapted = [
        entry
        for entry in entries
        if isinstance(entry, Mapping)
        and entry.get("id") == "adapted-openrappter-imessage"
    ]
    dependency = [
        entry
        for entry in entries
        if isinstance(entry, Mapping) and entry.get("id") == "dependency-imsg"
    ]
    expected_sources = {
        "scripts/install-imsg.sh": (
            "scripts/install-imsg.sh",
            "a6e3726428ce4fb0eda8ad187e0c57da977b3df1",
        ),
        "src/rapp_stack_cubby/imessage/bridge.py": (
            "python/openrappter/imessage/service.py",
            "84c90aced30e710233b6c21f8bb053f5d7032fc6",
        ),
        "src/rapp_stack_cubby/imessage/cli.py": (
            "python/openrappter/imessage/cli.py",
            "51d32a5424890a9c100226b35da90e29f3383fd3",
        ),
        "src/rapp_stack_cubby/imessage/config.py": (
            "python/openrappter/imessage/config.py",
            "04f381698c23231d092ac2c63168c8faef736a5a",
        ),
        "src/rapp_stack_cubby/imessage/rpc.py": (
            "python/openrappter/imessage/rpc.py",
            "6940824a02e65440d01ba43f50719880aec9b20e",
        ),
        "src/rapp_stack_cubby/imessage/state.py": (
            "python/openrappter/imessage/state.py",
            "c83a9d6e5f227c1b155bd6a6906aed7b69da3a72",
        ),
    }
    if len(adapted) != 1:
        errors.append("adapted OpenRappter iMessage provenance entry is required")
    else:
        entry = adapted[0]
        license_value = entry.get("license")
        cleared = entry.get("cleared_files")
        copied = entry.get("copied_files")
        if (
            entry.get("inclusion_state") != "adapted_source"
            or entry.get("commit")
            != "7b6dbca2cf23f3a21dacc604d2bda34e7e13cd6a"
            or not isinstance(license_value, Mapping)
            or license_value.get("spdx") != "MIT"
            or license_value.get("blob")
            != "30c15336d3a2eae7f3e15ee9bbb59cf173935bf5"
            or not isinstance(cleared, list)
            or not isinstance(copied, list)
        ):
            errors.append("adapted OpenRappter provenance header is invalid")
        else:
            observed: dict[str, tuple[object, object]] = {}
            for record in cleared:
                if not isinstance(record, Mapping):
                    continue
                destination = record.get("destination")
                if isinstance(destination, str):
                    observed[destination] = (
                        record.get("source_path"),
                        record.get("source_blob"),
                    )
                    if (
                        record.get("license") != "MIT"
                        or not isinstance(record.get("modification_summary"), str)
                        or not record["modification_summary"]
                        or not (root / destination).is_file()
                    ):
                        errors.append(
                            f"{destination}: adapted source review is incomplete"
                        )
            if observed != expected_sources:
                errors.append("adapted source/blob/destination records are incomplete")
            copied_records = {
                record.get("destination"): record.get("source_blob")
                for record in copied
                if isinstance(record, Mapping)
            }
            if copied_records != {
                destination: source[1]
                for destination, source in expected_sources.items()
            }:
                errors.append("adapted copied-file records are incomplete")
            try:
                sbom_input = _read_json_object(root, "SBOM_INPUT.json")
                notice = (root / "NOTICE").read_text(encoding="utf-8")
            except (ContractReadError, OSError, UnicodeError) as error:
                errors.append(f"adapted SBOM/NOTICE mapping cannot be read: {error}")
            else:
                adapted_inputs = sbom_input.get("adapted_files")
                mapped = (
                    {
                        item.get("destination"): (
                            item.get("source_path"),
                            item.get("source_blob"),
                            item.get("license"),
                            item.get("provenance_entry"),
                            item.get("license_text"),
                        )
                        for item in adapted_inputs
                        if isinstance(item, Mapping)
                    }
                    if isinstance(adapted_inputs, list)
                    else {}
                )
                expected_mapped = {
                    destination: (
                        source_path,
                        source_blob,
                        "MIT",
                        "adapted-openrappter-imessage",
                        "THIRD_PARTY_LICENSES/OpenRappter-MIT.txt",
                    )
                    for destination, (source_path, source_blob) in expected_sources.items()
                }
                if mapped != expected_mapped:
                    errors.append(
                        "SBOM_INPUT adapted files do not match provenance"
                    )
                if any(destination not in notice for destination in expected_sources):
                    errors.append("NOTICE omits an adapted OpenRappter destination")
                if "not an independent external legal audit" not in notice:
                    errors.append("NOTICE must bound the legal review claim")
    if len(dependency) != 1:
        errors.append("pinned imsg provenance entry is required")
    else:
        entry = dependency[0]
        license_value = entry.get("license")
        review = entry.get("review")
        installed = (
            review.get("installed_verification")
            if isinstance(review, Mapping)
            else None
        )
        if (
            entry.get("inclusion_state") != "dependency_locked"
            or entry.get("stack_lock_id") != "dependency-imsg"
            or entry.get("commit")
            != "dea78a9e9c493740575b03e443041ef5fbd2d463"
            or entry.get("version") != "0.12.3"
            or not isinstance(license_value, Mapping)
            or license_value.get("blob")
            != "0ae0cb57d8c6c1417f796b39fc0d6a7f2f7c5c39"
            or not isinstance(review, Mapping)
            or review.get("annotated_ref")
            != "76585a9e13a33534bec26d5478482efcc238f803"
            or review.get("archive_sha256")
            != "35977a22e9721440acf9f5b945d67034939948ba4fa4ea46b0f55d527f24d4f2"
            or not isinstance(installed, Mapping)
            or installed.get("archive_hash") is not True
            or installed.get("codesign_strict") is not True
            or installed.get("team_and_authority") is not True
            or installed.get("architectures") is not True
            or installed.get("layout") is not True
            or installed.get("version") is not True
            or installed.get("owner_enrolled") is not False
        ):
            errors.append("pinned imsg provenance evidence is invalid")


def _check_original_runtime_files(
    root: Path,
    target: Mapping[str, Any],
    lock: Mapping[str, Any],
    errors: list[str],
) -> None:
    files = target.get("original_files")
    if not isinstance(files, list) or not files:
        errors.append(
            "target-rapp-stack-cubby.original_files must list runtime source"
        )
        return
    paths: list[str] = []
    for index, record in enumerate(files):
        if not isinstance(record, dict):
            errors.append(
                f"target original_files[{index}] must be an object"
            )
            continue
        path = record.get("path")
        digest = record.get("sha256")
        if (
            not isinstance(path, str)
            or not (
                path in _ORIGINAL_IMPLEMENTATION_FILES
                or any(
                    path.startswith(prefix)
                    for prefix in _ORIGINAL_IMPLEMENTATION_PREFIXES
                )
            )
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            errors.append(
                f"target original_files[{index}].path is not implementation source"
            )
            continue
        paths.append(path)
        if record.get("provenance") != "original_new":
            errors.append(
                f"target original_files[{index}].provenance must be original_new"
            )
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            errors.append(
                f"target original_files[{index}].sha256 must be 64 lowercase hex"
            )
            continue
        if _sha256(root, path) != digest:
            errors.append(
                f"target original_files[{index}].sha256 does not match {path}"
            )
    if len(set(paths)) != len(paths):
        errors.append("target original runtime paths must be unique")
    if paths != sorted(paths):
        errors.append("target original runtime paths must be sorted")

    canonical = json.dumps(
        files,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_digest = hashlib.sha256(canonical).hexdigest()
    if target.get("original_manifest_sha256") != manifest_digest:
        errors.append(
            "target original_manifest_sha256 does not match original_files"
        )

    build_policy = lock.get("build_policy")
    manifest = (
        build_policy.get("original_runtime_manifest")
        if isinstance(build_policy, dict)
        else None
    )
    if not isinstance(manifest, dict):
        errors.append(
            "STACK_LOCK build_policy.original_runtime_manifest is required"
        )
    else:
        if manifest.get("files") != files:
            errors.append(
                "STACK_LOCK original runtime files must match provenance"
            )
        if manifest.get("manifest_sha256") != manifest_digest:
            errors.append(
                "STACK_LOCK original runtime manifest digest does not match"
            )


def _check_authored_agent_files(
    root: Path,
    target: Mapping[str, Any],
    lock: Mapping[str, Any],
    errors: list[str],
) -> None:
    files = target.get("authored_agent_files")
    if not isinstance(files, list) or len(files) != EXPECTED_ACTUAL_AGENT_COUNT:
        errors.append(
            "target authored_agent_files must list all actual agents"
        )
        return
    paths: list[str] = []
    expected_prefix = (
        "cubbies/kody-w/rapplications/rapp-stack/twin/agents/"
    )
    for index, record in enumerate(files):
        if not isinstance(record, dict):
            errors.append(f"authored_agent_files[{index}] must be an object")
            continue
        path = record.get("path")
        digest = record.get("sha256")
        if (
            not isinstance(path, str)
            or not path.startswith(expected_prefix)
            or not path.endswith("_agent.py")
            or Path(path).is_absolute()
            or ".." in Path(path).parts
        ):
            errors.append(
                f"authored_agent_files[{index}].path is not actual agent source"
            )
            continue
        paths.append(path)
        if record.get("provenance") != "original_new":
            errors.append(
                f"authored_agent_files[{index}].provenance must be original_new"
            )
        if not isinstance(digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", digest
        ):
            errors.append(
                f"authored_agent_files[{index}].sha256 must be 64 lowercase hex"
            )
        elif _sha256(root, path) != digest:
            errors.append(
                f"authored_agent_files[{index}].sha256 does not match {path}"
            )
    if paths != sorted(paths) or len(set(paths)) != len(paths):
        errors.append("authored agent paths must be sorted and unique")

    canonical = json.dumps(
        files,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_digest = hashlib.sha256(canonical).hexdigest()
    if target.get("authored_agent_manifest_sha256") != manifest_digest:
        errors.append(
            "target authored_agent_manifest_sha256 does not match agent files"
        )

    build_policy = lock.get("build_policy")
    manifest = (
        build_policy.get("actual_agent_manifest")
        if isinstance(build_policy, dict)
        else None
    )
    if not isinstance(manifest, dict):
        errors.append("STACK_LOCK actual_agent_manifest is required")
        return
    if manifest.get("files") != files:
        errors.append(
            "STACK_LOCK actual agent files must match provenance"
        )
    if manifest.get("manifest_sha256") != manifest_digest:
        errors.append(
            "STACK_LOCK actual agent manifest digest does not match"
        )

    support = target.get("agent_closure_support_files")
    expected_support_paths = [
        "src/rapp_stack_cubby/agents/__init__.py",
        "src/rapp_stack_cubby/agents/source_scan.py",
        "src/rapp_stack_cubby/catalog.py",
    ]
    if not isinstance(support, list) or len(support) != len(
        expected_support_paths
    ):
        errors.append(
            "target agent_closure_support_files must list source helpers"
        )
    else:
        support_paths: list[str] = []
        for index, record in enumerate(support):
            if not isinstance(record, dict):
                errors.append(
                    f"agent_closure_support_files[{index}] must be an object"
                )
                continue
            path = record.get("path")
            digest = record.get("sha256")
            if not isinstance(path, str):
                errors.append(
                    f"agent_closure_support_files[{index}].path must be text"
                )
                continue
            support_paths.append(path)
            if record.get("provenance") != "original_new":
                errors.append(
                    f"agent_closure_support_files[{index}].provenance is invalid"
                )
            if (
                not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or _sha256(root, path) != digest
            ):
                errors.append(
                    f"agent_closure_support_files[{index}].sha256 does not match"
                )
        if support_paths != expected_support_paths:
            errors.append("agent closure support paths are incomplete or unordered")
        support_canonical = json.dumps(
            support,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        support_digest = hashlib.sha256(support_canonical).hexdigest()
        if (
            target.get("agent_closure_support_manifest_sha256")
            != support_digest
        ):
            errors.append(
                "target agent closure support manifest digest does not match"
            )
        if manifest.get("support_files") != support:
            errors.append(
                "STACK_LOCK agent closure support files must match provenance"
            )
        if manifest.get("support_manifest_sha256") != support_digest:
            errors.append(
                "STACK_LOCK support manifest digest does not match"
            )

    generated = target.get("generated_catalog_files")
    if not isinstance(generated, list) or len(generated) != 2:
        errors.append("target generated_catalog_files must list both catalogs")
    else:
        generated_paths: list[str] = []
        for index, record in enumerate(generated):
            if not isinstance(record, dict):
                errors.append(
                    f"generated_catalog_files[{index}] must be an object"
                )
                continue
            path = record.get("path")
            digest = record.get("sha256")
            if not isinstance(path, str):
                errors.append(
                    f"generated_catalog_files[{index}].path must be text"
                )
                continue
            generated_paths.append(path)
            if record.get("provenance") != "generated_local":
                errors.append(
                    f"generated_catalog_files[{index}].provenance is invalid"
                )
            if (
                not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or _sha256(root, path) != digest
            ):
                errors.append(
                    f"generated_catalog_files[{index}].sha256 does not match"
                )
        expected_generated = [
            CATALOG_RELATIVE.as_posix(),
            IMPLEMENTATION_MATRIX_RELATIVE.as_posix(),
        ]
        if generated_paths != expected_generated:
            errors.append("generated catalog paths are incomplete or unordered")
        if manifest.get("agent_catalog") != generated[0]:
            errors.append(
                "STACK_LOCK agent catalog record must match provenance"
            )
        if manifest.get("implementation_matrix") != generated[1]:
            errors.append(
                "STACK_LOCK implementation matrix record must match provenance"
            )

    soul = target.get("twin_soul")
    if not isinstance(soul, dict):
        errors.append("target twin_soul provenance is required")
    else:
        soul_path = (
            "cubbies/kody-w/rapplications/rapp-stack/twin/soul.md"
        )
        if (
            soul.get("path") != soul_path
            or soul.get("provenance") != "original_new"
            or soul.get("sha256") != _sha256(root, soul_path)
        ):
            errors.append("target twin_soul provenance does not match")
        if manifest.get("soul") != soul:
            errors.append("STACK_LOCK soul record must match provenance")


def _check_controller_files(
    root: Path,
    target: Mapping[str, Any],
    lock: Mapping[str, Any],
    errors: list[str],
) -> None:
    source = target.get("controller_source")
    expected_source_path = (
        "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
    )
    if not isinstance(source, dict):
        errors.append("target controller_source is required")
        return
    if (
        source.get("path") != expected_source_path
        or source.get("provenance") != "original_new"
        or source.get("sha256") != _sha256(root, expected_source_path)
    ):
        errors.append("target controller_source does not match source")

    expected_support_paths = [
        "cubbies/kody-w/soul.md",
        "scripts/check.sh",
        "scripts/context-check.sh",
        "src/rapp_stack_cubby/cli.py",
        "src/rapp_stack_cubby/constants.py",
        "src/rapp_stack_cubby/context.py",
        "src/rapp_stack_cubby/controller/__init__.py",
        "src/rapp_stack_cubby/controller/loadout.py",
        "src/rapp_stack_cubby/controller/source_scan.py",
        "src/rapp_stack_cubby/verification.py",
        "tools/build_controller_loadout.py",
    ]
    support = target.get("controller_support_files")
    support_paths: list[str] = []
    if (
        not isinstance(support, list)
        or len(support) != len(expected_support_paths)
    ):
        errors.append(
            "target controller_support_files must list controller helpers"
        )
        support = []
    for index, record in enumerate(support):
        if not isinstance(record, dict):
            errors.append(
                f"controller_support_files[{index}] must be an object"
            )
            continue
        path = record.get("path")
        if not isinstance(path, str):
            errors.append(
                f"controller_support_files[{index}].path must be text"
            )
            continue
        support_paths.append(path)
        if (
            record.get("provenance") != "original_new"
            or record.get("sha256") != _sha256(root, path)
        ):
            errors.append(
                f"controller_support_files[{index}].sha256 does not match"
            )
    if support_paths != expected_support_paths:
        errors.append("target controller support paths are not expected")

    catalog = target.get("controller_catalog")
    receipt = target.get("controller_receipt_template")
    expected_catalog_path = (
        "cubbies/kody-w/catalog/controller-catalog.json"
    )
    expected_receipt_path = (
        "cubbies/kody-w/catalog/controller-receipt-template.json"
    )
    if (
        not isinstance(catalog, dict)
        or catalog.get("path") != expected_catalog_path
        or catalog.get("provenance") != "generated_local"
        or catalog.get("sha256") != _sha256(root, expected_catalog_path)
    ):
        errors.append("target controller_catalog does not match")
    if (
        not isinstance(receipt, dict)
        or receipt.get("path") != expected_receipt_path
        or receipt.get("provenance") != "original_new"
        or receipt.get("sha256") != _sha256(root, expected_receipt_path)
    ):
        errors.append("target controller_receipt_template does not match")

    material = {
        "catalog": catalog,
        "receipt_template": receipt,
        "source": source,
        "support_files": support,
    }
    digest = hashlib.sha256(
        json.dumps(
            material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    if target.get("controller_manifest_sha256") != digest:
        errors.append(
            "target controller_manifest_sha256 does not match controller files"
        )
    build_policy = lock.get("build_policy")
    locked = (
        build_policy.get("controller_manifest")
        if isinstance(build_policy, dict)
        else None
    )
    if not isinstance(locked, dict):
        errors.append("STACK_LOCK controller_manifest is required")
    elif (
        locked.get("source") != source
        or locked.get("support_files") != support
        or locked.get("catalog") != catalog
        or locked.get("receipt_template") != receipt
        or locked.get("manifest_sha256") != digest
    ):
        errors.append(
            "STACK_LOCK controller manifest must match provenance"
        )


def _check_context_files(
    root: Path,
    target: Mapping[str, Any],
    lock: Mapping[str, Any],
    errors: list[str],
) -> None:
    files = target.get("context_closure_files")
    expected_paths = sorted(
        [
            "AI_CONTEXT.md",
            "CONTEXT_INDEX.json",
            "scripts/context-check.sh",
            "src/rapp_stack_cubby/context.py",
            "tests/test_context.py",
            *(f"schemas/{name}" for name in SCHEMAS),
        ]
    )
    if not isinstance(files, list) or len(files) != len(expected_paths):
        errors.append(
            "target context_closure_files must list the entrypoint, index, "
            "schemas, helper, script, and tests"
        )
        return
    paths: list[str] = []
    for index, record in enumerate(files):
        if not isinstance(record, dict):
            errors.append(f"context_closure_files[{index}] must be an object")
            continue
        path = record.get("path")
        digest = record.get("sha256")
        if not isinstance(path, str):
            errors.append(f"context_closure_files[{index}].path must be text")
            continue
        paths.append(path)
        expected_provenance = (
            "generated_local" if path == "CONTEXT_INDEX.json" else "original_new"
        )
        if record.get("provenance") != expected_provenance:
            errors.append(
                f"context_closure_files[{index}].provenance must be "
                f"{expected_provenance}"
            )
        if (
            not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or _sha256(root, path) != digest
        ):
            errors.append(
                f"context_closure_files[{index}].sha256 does not match {path}"
            )
    if paths != expected_paths or len(set(paths)) != len(paths):
        errors.append("context closure paths are incomplete, duplicated, or unordered")
    canonical = json.dumps(
        files,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest_digest = hashlib.sha256(canonical).hexdigest()
    if target.get("context_closure_manifest_sha256") != manifest_digest:
        errors.append(
            "target context_closure_manifest_sha256 does not match context files"
        )

    build_policy = lock.get("build_policy")
    manifest = (
        build_policy.get("context_manifest")
        if isinstance(build_policy, dict)
        else None
    )
    if not isinstance(manifest, dict):
        errors.append("STACK_LOCK build_policy.context_manifest is required")
        return
    if (
        manifest.get("files") != files
        or manifest.get("manifest_sha256") != manifest_digest
    ):
        errors.append("STACK_LOCK context manifest must match provenance")
    by_path = {
        record.get("path"): record
        for record in files
        if isinstance(record, dict)
    }
    if manifest.get("context_index") != by_path.get("CONTEXT_INDEX.json"):
        errors.append("STACK_LOCK context index record must match provenance")
    if manifest.get("context_schema") != by_path.get(
        "schemas/context-index.schema.json"
    ):
        errors.append("STACK_LOCK context schema record must match provenance")


def _check_pages_files(
    root: Path,
    target: Mapping[str, Any],
    lock: Mapping[str, Any],
    entries: Sequence[Any],
    errors: list[str],
) -> None:
    expected_paths = sorted(
        [
            ".github/workflows/ci.yml",
            ".github/workflows/pages.yml",
            ".github/workflows/promote.yml",
            ".github/workflows/release.yml",
            "CHANGELOG.md",
            "GITHUB_ACTIONS_LOCK.json",
            "RELEASE_CHECKLIST.md",
            "RELEASE_STATUS.json",
            "RELEASE_TRUST.json",
            "VERSION",
            "docs/.nojekyll",
            "docs/404.html",
            "docs/assets/favicon.svg",
            "docs/assets/styles.css",
            "docs/canon/SHOWCASE_PROMPTS.md",
            "docs/decisions/static-pages-public-boundary.md",
            "docs/index.html",
            "docs/pages-manifest.json",
            "docs/operations/EXACT_COMMIT_PROMOTION.md",
            "docs/operations/PAGES_OPERATIONS.md",
            "docs/operations/REPOSITORY_SETTINGS.md",
            "docs/robots.txt",
            "docs/sitemap.xml",
            "requirements-ci.lock",
            "scripts/check-toolchain.sh",
            "scripts/configure-repository.sh",
            "scripts/pages-build.sh",
            "scripts/pages-check.sh",
            "scripts/postflight-release.sh",
            "scripts/prepare-release.sh",
            "scripts/promote-release.sh",
            "scripts/record-attestations.py",
            "scripts/resolve-release-tag.sh",
            "scripts/validate-release-inputs.sh",
            "scripts/verify-github-attestations.sh",
            "src/rapp_stack_cubby/pages.py",
            "src/rapp_stack_cubby/promotion.py",
            "tests/packaging/test_release_scripts.py",
            "tests/pages/__init__.py",
            "tests/pages/test_pages.py",
            *(
                f"docs/api/v1/{name}"
                for name in (
                    "architecture.json",
                    "capabilities.json",
                    "context.json",
                    "downloads.json",
                    "prompts.json",
                    "status.json",
                )
            ),
        ]
    )
    files = target.get("pages_files")
    if not isinstance(files, list) or len(files) != len(expected_paths):
        errors.append("target pages_files must list the complete Pages handoff")
        return
    paths: list[str] = []
    for index, record in enumerate(files):
        if not isinstance(record, dict):
            errors.append(f"pages_files[{index}] must be an object")
            continue
        path = record.get("path")
        if not isinstance(path, str):
            errors.append(f"pages_files[{index}].path must be text")
            continue
        paths.append(path)
        expected_provenance = (
            "generated_local"
            if path.startswith("docs/api/v1/")
            or path == "docs/pages-manifest.json"
            else "original_new"
        )
        if (
            record.get("provenance") != expected_provenance
            or record.get("sha256") != _sha256(root, path)
        ):
            errors.append(f"pages_files[{index}] does not match {path}")
    if paths != expected_paths or len(paths) != len(set(paths)):
        errors.append("Pages provenance paths are incomplete or unordered")
    canonical = json.dumps(
        files,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    if target.get("pages_manifest_sha256") != digest:
        errors.append("target Pages manifest digest does not match pages_files")
    build_policy = lock.get("build_policy")
    manifest = (
        build_policy.get("pages_manifest")
        if isinstance(build_policy, dict)
        else None
    )
    if not isinstance(manifest, dict) or manifest != {
        "files": files,
        "manifest_sha256": digest,
        "release_status": "pending",
        "site_url": "https://kody-w.github.io/rapp-stack-cubby/",
    }:
        errors.append("STACK_LOCK Pages manifest must match provenance")

    try:
        action_lock = _read_json_object(root, "GITHUB_ACTIONS_LOCK.json")
    except ContractReadError as error:
        errors.append(str(error))
        return
    actions = action_lock.get("actions")
    if not isinstance(actions, list):
        errors.append("GitHub Actions lock actions are invalid")
        return
    by_id = {
        entry.get("id"): entry
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }
    for action in actions:
        if not isinstance(action, dict) or not isinstance(
            action.get("uses"), str
        ):
            errors.append("GitHub Actions lock record is invalid")
            continue
        slug = action["uses"].split("/", 1)[-1]
        entry = by_id.get(f"dependency-github-action-{slug}")
        license_value = entry.get("license") if isinstance(entry, dict) else None
        review = entry.get("review") if isinstance(entry, dict) else None
        if (
            not isinstance(entry, dict)
            or entry.get("inclusion_state") != "dependency_locked"
            or entry.get("commit") != action.get("commit")
            or entry.get("repository_url") != action.get("repository")
            or entry.get("version") != action.get("tag")
            or entry.get("cleared_files") != []
            or entry.get("copied_files") != []
            or not isinstance(license_value, dict)
            or license_value.get("spdx") != action.get("license", {}).get("spdx")
            or license_value.get("sha256")
            != action.get("license", {}).get("sha256")
            or not isinstance(review, dict)
            or review.get("action_lock") != "GITHUB_ACTIONS_LOCK.json"
            or review.get("status") != "official_action_full_sha_pinned"
        ):
            errors.append(f"GitHub Action provenance is invalid: {action['uses']}")


def _check_placeholder_config(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    errors: list[str] = []
    scanned_files = 0
    cubby_manifests = 0
    placeholder_files = 0
    allowed_dist_files = _validate_development_dist(root, errors)

    try:
        paths = sorted(root.rglob("*"))
    except OSError as error:
        raise ContractReadError(
            f"repository tree cannot be scanned ({error.strerror or error})"
        ) from error

    for path in paths:
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(
            part in _IGNORED_SCAN_PARTS
            or part == "__pycache__"
            or part.casefold().endswith(".egg-info")
            or part.startswith(".test-")
            for part in relative.parts
        ):
            continue
        forbidden_directories = [
            part
            for part in relative.parts
            if (
                part in _FORBIDDEN_DIRECTORY_NAMES
                or part.casefold().endswith(".egg-info")
            )
            and not (
                part == "runtime"
                and _is_reviewed_runtime_path(relative)
            )
        ]
        if forbidden_directories:
            if path.is_dir() and (
                path.name in _FORBIDDEN_DIRECTORY_NAMES
                or path.name.casefold().endswith(".egg-info")
            ):
                errors.append(
                    "cache, environment, or runtime directory is forbidden: "
                    f"{relative.as_posix()}"
                )
            continue
        if not path.is_file():
            continue
        scanned_files += 1
        name = path.name
        lower_name = name.lower()

        if (
            name in _FORBIDDEN_FILE_NAMES
            or lower_name.startswith(".env.")
            and lower_name not in {".env.example", ".env.sample", ".env.template"}
            or lower_name.endswith(_FORBIDDEN_SUFFIXES)
        ):
            errors.append(f"private or runtime file is forbidden: {relative.as_posix()}")
            continue
        if (
            relative.parts[0] == "dist"
            and name != ".gitignore"
            and relative.as_posix() not in allowed_dist_files
        ):
            errors.append(
                "dist output is not an exact verified development artifact: "
                f"{relative.as_posix()}"
            )

        if relative.parts[-1] == "cubby.json":
            cubby_manifests += 1
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                errors.append(
                    f"{relative.as_posix()}: unreadable cubby manifest "
                    f"({type(error).__name__}: {error})"
                )
            else:
                _validate_cubby_manifest(relative, manifest, errors)

        if _is_placeholder_file(name):
            placeholder_files += 1
            _validate_placeholder_file(relative, path, errors)

        if path.suffix.lower() in {
            ".css",
            ".html",
            ".json",
            ".md",
            ".py",
            ".sh",
            ".svg",
            ".toml",
            ".txt",
            ".xml",
            ".yaml",
            ".yml",
        } or name in {"Makefile", ".editorconfig", ".gitattributes", ".gitignore"}:
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeError:
                errors.append(f"text file is not valid UTF-8: {relative.as_posix()}")
            except OSError as error:
                errors.append(
                    f"cannot inspect {relative.as_posix()}: "
                    f"{error.strerror or type(error).__name__}"
                )
            else:
                match = _ABSOLUTE_LOCAL_PATH_RE.search(text)
                if match:
                    errors.append(
                        f"absolute local path is forbidden in {relative.as_posix()}"
                    )

    runtime_source_file_count = _check_runtime_source_safety(root, errors)
    return {
        "scanned_file_count": scanned_files,
        "cubby_manifest_count": cubby_manifests,
        "placeholder_file_count": placeholder_files,
        "runtime_source_file_count": runtime_source_file_count,
    }, errors


def _validate_development_dist(root: Path, errors: list[str]) -> set[str]:
    """Allow only a complete, hash-bound, development-only dist set."""

    dist = root / "dist"
    if not dist.is_dir():
        return set()
    observed = {
        path.name
        for path in dist.iterdir()
        if path.name != ".gitignore"
    }
    if not observed:
        return set()
    unsigned_expected = {
        "SBOM.spdx.json",
        "SHA256SUMS",
        "rapp-stack-cubby-store.zip",
        "rapp-stack-cubby.egg",
        "rapp-super-rar.json",
        "release-manifest.json",
        "release-provenance.json",
        "store-index.json",
    }
    try:
        from .packaging.builder import verify_artifact
        from .packaging.builder import validate_spdx
        from .packaging.common import PackagingError, read_json_object
        from .packaging.release import verify_release

        release = read_json_object(dist / "release-manifest.json")
        signed = release.get("signed") is True
        expected = set(unsigned_expected)
        if signed:
            expected.add("release-manifest.json.sig")
        if observed != expected or any(
            not (dist / name).is_file() for name in observed
        ):
            raise PackagingError(
                "dist must contain one exact signed or unsigned development set"
            )
        release_digest = _sha256(root, "dist/release-manifest.json")
        verified_release = verify_release(
            dist / "release-manifest.json",
            expected_manifest_sha256=release_digest,
            trust_path=root / "RELEASE_TRUST.json",
            source_root=root,
            allow_unsigned_development=True,
        )
        if (
            release.get("schema") != "rapp-release-manifest/1.0"
            or release.get("source_commit") != "WORKTREE"
            or release.get("development_only") is not True
            or release.get("release") is not False
            or not isinstance(release.get("signed"), bool)
            or release.get("version") != __version__
            or verified_release.get("release_eligible") is not False
        ):
            raise PackagingError("dist release sidecar is not development-only")
        declared = release.get("artifacts")
        if not isinstance(declared, list) or len(declared) != 6:
            raise PackagingError("dist release artifact list is invalid")
        by_name = {
            item.get("filename"): item
            for item in declared
            if isinstance(item, dict)
        }
        if set(by_name) != expected - {
            "SHA256SUMS",
            "release-manifest.json",
            "release-manifest.json.sig",
        }:
            raise PackagingError("dist release artifact names are invalid")
        for name, item in by_name.items():
            digest = _sha256(root, f"dist/{name}")
            if (
                item.get("sha256") != digest
                or item.get("size") != (dist / name).stat().st_size
            ):
                raise PackagingError("dist artifact sidecar hash is stale")
        verify_artifact(
            dist / "rapp-stack-cubby-store.zip",
            expected_sha256=by_name["rapp-stack-cubby-store.zip"]["sha256"],
        )
        verify_artifact(
            dist / "rapp-stack-cubby.egg",
            expected_sha256=by_name["rapp-stack-cubby.egg"]["sha256"],
        )
        for name, schema in (
            ("SBOM.spdx.json", "SPDX-2.3"),
            ("release-provenance.json", "rapp-release-provenance/1.0"),
            ("rapp-super-rar.json", "rapp-super-rar/1.0"),
            ("store-index.json", "rapp-store-index/1.0"),
        ):
            value = read_json_object(dist / name)
            key = "spdxVersion" if name == "SBOM.spdx.json" else "schema"
            if value.get(key) != schema:
                raise PackagingError(f"dist {name} schema is invalid")
        validate_spdx(read_json_object(dist / "SBOM.spdx.json", maximum_bytes=64 * 1024 * 1024))
    except (OSError, UnicodeError, PackagingError) as error:
        errors.append(f"dist verification failed: {error}")
        return set()
    return {f"dist/{name}" for name in expected}


def _check_agent_closure(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    errors = list(validate_catalogs(root))
    agent_count = 0
    capability_count = 0
    selected_count = 0
    selected_unmapped_count = 0
    try:
        catalog = _read_json_object(root, CATALOG_RELATIVE.as_posix())
        matrix = _read_json_object(
            root, IMPLEMENTATION_MATRIX_RELATIVE.as_posix()
        )
    except ContractReadError as error:
        errors.append(str(error))
    else:
        agent_count = catalog.get("agent_count", 0)
        aggregates = matrix.get("aggregates", {})
        capability_count = aggregates.get("capability_count", 0)
        selected_count = aggregates.get("selected_count", 0)
        selected_unmapped_count = aggregates.get(
            "selected_unmapped_count", 0
        )
        if catalog.get("schema") != AGENT_CATALOG_SCHEMA:
            errors.append(f"agent catalog schema must be {AGENT_CATALOG_SCHEMA}")
        if matrix.get("schema") != IMPLEMENTATION_MATRIX_SCHEMA:
            errors.append(
                "implementation matrix schema must be "
                f"{IMPLEMENTATION_MATRIX_SCHEMA}"
            )
        if agent_count != EXPECTED_ACTUAL_AGENT_COUNT:
            errors.append(
                f"actual agent count must be {EXPECTED_ACTUAL_AGENT_COUNT}"
            )
    return {
        "agent_count": agent_count,
        "capability_count": capability_count,
        "selected_count": selected_count,
        "selected_unmapped_count": selected_unmapped_count,
    }, errors


def _check_controller_closure(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    errors: list[str] = []
    controller_count = 0
    action_count = 0
    source_sha256 = ""
    try:
        expected = build_controller_catalog(root)
        actual = _read_json_object(
            root, CONTROLLER_CATALOG_RELATIVE.as_posix()
        )
    except (ContractReadError, OSError, ValueError) as error:
        errors.append(str(error))
        expected = {}
        actual = {}
    if expected and actual != expected:
        errors.append(
            "controller catalog must match the sole controller source"
        )
    if actual:
        if actual.get("schema") != CONTROLLER_CATALOG_SCHEMA:
            errors.append(
                f"controller catalog schema must be {CONTROLLER_CATALOG_SCHEMA}"
            )
        actions = actual.get("actions")
        action_count = len(actions) if isinstance(actions, list) else 0
        source = actual.get("source")
        if isinstance(source, dict):
            source_sha256 = str(source.get("sha256", ""))
    directory = root / CONTROLLER_AGENT_RELATIVE.parent
    if directory.is_symlink() or not directory.is_dir():
        errors.append("top-level controller directory is invalid")
    else:
        candidates = sorted(directory.glob("*_agent.py"))
        controller_count = len(candidates)
        if (
            controller_count != EXPECTED_STREAMABLE_CONTROLLER_COUNT
            or candidates != [root / CONTROLLER_AGENT_RELATIVE]
        ):
            errors.append(
                "exactly one top-level streamable controller is required"
            )
    receipt_relative = Path(
        "cubbies/kody-w/catalog/controller-receipt-template.json"
    )
    try:
        receipt = _read_json_object(root, receipt_relative.as_posix())
    except ContractReadError as error:
        errors.append(str(error))
    else:
        if (
            receipt.get("schema")
            != "rapp-controller-receipt-template/1.0"
            or receipt.get("written_runtime_schema")
            != "rapp-controller-receipt/1.0"
        ):
            errors.append("controller receipt template schema is invalid")
    try:
        cubby = _read_json_object(root, "cubbies/kody-w/cubby.json")
    except ContractReadError as error:
        errors.append(str(error))
    else:
        declared = cubby.get("controller")
        if not isinstance(declared, dict):
            errors.append("cubby manifest must identify its controller")
        elif (
            declared.get("path") != CONTROLLER_AGENT_RELATIVE.as_posix()
            or declared.get("sha256") != source_sha256
            or declared.get("streamable_agent_count")
            != EXPECTED_STREAMABLE_CONTROLLER_COUNT
        ):
            errors.append(
                "cubby manifest controller identity does not match source"
            )
    return {
        "controller_count": controller_count,
        "action_count": action_count,
        "source_sha256": source_sha256,
    }, errors


def _check_context_closure(
    root: Path,
) -> tuple[dict[str, bool | int | str], list[str]]:
    result = validate_context(root)
    return {
        "entry_count": result.entry_count,
        "schema_count": result.schema_count,
        "selected_capability_count": result.capability_count,
    }, list(result.errors)


def _is_reviewed_runtime_path(relative: Path) -> bool:
    parts = relative.parts
    return any(
        parts[: len(prefix)] == prefix
        for prefix in _REVIEWED_RUNTIME_PREFIXES
    )


def _check_runtime_source_safety(root: Path, errors: list[str]) -> int:
    package_root = root / "src" / "rapp_stack_cubby"
    directories = (
        (package_root / "runtime", _REQUIRED_RUNTIME_MODULES, "runtime"),
        (package_root / "protocols", _REQUIRED_PROTOCOL_MODULES, "protocol"),
    )
    source_files: list[Path] = []
    for directory, required, label in directories:
        if not directory.exists():
            errors.append(f"{label} source directory is missing")
            continue
        if directory.is_symlink() or not directory.is_dir():
            errors.append(f"{label} source directory must be a regular directory")
            continue
        try:
            selected = sorted(directory.glob("*.py"))
        except OSError as error:
            errors.append(
                f"{label} source cannot be listed ({type(error).__name__})"
            )
            continue
        missing = sorted(required - {path.name for path in selected})
        if missing:
            errors.append(
                f"{label} source modules are missing: " + ", ".join(missing)
            )
        source_files.extend(selected)

    for path in source_files:
        label = path.relative_to(root).as_posix()
        if path.is_symlink() or not path.is_file():
            errors.append(f"{label}: runtime source must be a regular file")
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            errors.append(
                f"{label}: runtime source cannot be inspected "
                f"({type(error).__name__})"
            )
            continue
        try:
            tree = ast.parse(source, filename=label)
        except SyntaxError as error:
            errors.append(
                f"{label}: runtime source has invalid syntax at line "
                f"{error.lineno or 0}"
            )
            continue

        lowered = source.lower()
        for forbidden in (
            "/api/agent",
            "/eval",
            "access-control-allow-origin",
            ".copilot_token",
            ".copilot_session",
            "pip install",
            "auto-pip",
        ):
            if forbidden in lowered:
                errors.append(
                    f"{label}: forbidden runtime surface is present: {forbidden}"
                )

        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                modules = (
                    [alias.name for alias in node.names]
                    if isinstance(node, ast.Import)
                    else [node.module or ""]
                )
                if any(
                    module == "pip" or module.startswith("pip.")
                    for module in modules
                ):
                    errors.append(f"{label}: runtime must not import pip")
            if not isinstance(node, ast.Call):
                continue
            call_name = _ast_call_name(node.func)
            if call_name in {"eval", "os.system", "subprocess.Popen"}:
                errors.append(
                    f"{label}: unsafe runtime call is forbidden: {call_name}"
                )
            if call_name.startswith("subprocess.") and path.name != "provider.py":
                errors.append(
                    f"{label}: subprocess use is restricted to the provider"
                )
            if call_name.endswith("urlretrieve"):
                errors.append(
                    f"{label}: runtime source download is forbidden"
                )
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    errors.append(
                        f"{label}: subprocess shell execution is forbidden"
                    )

        if path.name == "server.py":
            routes = {
                value
                for value in (
                    node.value
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                )
                if re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+", value)
                and not value.startswith("//")
            }
            unsafe_routes = sorted(routes - {"/chat", "/health"})
            if unsafe_routes:
                errors.append(
                    f"{label}: unsupported HTTP routes are declared: "
                    + ", ".join(unsafe_routes)
                )
            if not {"/chat", "/health"}.issubset(routes):
                errors.append(
                    f"{label}: runtime must expose only /chat and /health"
                )
    return len(source_files)


def _ast_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _check_census_reference(
    root: Path, reference: object, errors: list[str]
) -> None:
    if not isinstance(reference, dict):
        errors.append("source_census must be an object")
        return
    path = reference.get("ref")
    expected_digest = reference.get("sha256")
    if path != "SOURCE_CENSUS.json":
        errors.append("source_census.ref must be SOURCE_CENSUS.json")
        return
    if not isinstance(expected_digest, str):
        errors.append("source_census.sha256 must be a string")
        return
    actual_digest = _sha256(root, path)
    if expected_digest != actual_digest:
        errors.append("source_census.sha256 does not match SOURCE_CENSUS.json")


def _check_evidence_inputs(
    root: Path, evidence_inputs: object, errors: list[str]
) -> None:
    if not isinstance(evidence_inputs, list):
        errors.append("evidence_inputs must be an array")
        return
    for index, evidence in enumerate(evidence_inputs):
        if not isinstance(evidence, dict):
            errors.append(f"evidence_inputs[{index}] must be an object")
            continue
        path = evidence.get("path")
        digest = evidence.get("sha256")
        if not isinstance(path, str) or not path:
            errors.append(f"evidence_inputs[{index}].path must be a string")
            continue
        if not isinstance(digest, str):
            errors.append(f"evidence_inputs[{index}].sha256 must be a string")
            continue
        if _sha256(root, path) != digest:
            errors.append(
                f"evidence_inputs[{index}].sha256 does not match {path}"
            )


def _validate_cubby_manifest(
    relative: Path, manifest: object, errors: list[str]
) -> None:
    label = relative.as_posix()
    if not isinstance(manifest, dict):
        errors.append(f"{label}: cubby manifest must be an object")
        return
    required = {
        "schema",
        "github_login",
        "slug",
        "display_name",
        "product_version",
        "what_im_cooking",
        "created_at",
        "estate",
        "streamable",
    }
    missing = sorted(required - manifest.keys())
    if missing:
        errors.append(f"{label}: missing fields: {', '.join(missing)}")
    if manifest.get("schema") != CUBBY_SCHEMA:
        errors.append(f"{label}: schema must be {CUBBY_SCHEMA}")
    for field_name in ("github_login", "display_name", "what_im_cooking"):
        value = manifest.get(field_name)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{label}: {field_name} must be a non-empty string")
    slug = manifest.get("slug")
    if not isinstance(slug, str) or not _SLUG_RE.fullmatch(slug):
        errors.append(f"{label}: slug is invalid")
    elif (
        len(relative.parts) == 3
        and relative.parts[0] == "cubbies"
        and relative.parent.name != slug
    ):
        errors.append(f"{label}: slug must match its cubby directory")
    created_at = manifest.get("created_at")
    if not isinstance(created_at, str) or not _RFC3339_Z_RE.fullmatch(created_at):
        errors.append(f"{label}: created_at must be RFC 3339 UTC")
    estate = manifest.get("estate")
    anatomy = estate.get("anatomy") if isinstance(estate, dict) else None
    if anatomy != list(CUBBY_ANATOMY):
        errors.append(f"{label}: estate.anatomy must declare all seven kinds")
    if manifest.get("streamable") != {"agents": True}:
        errors.append(f"{label}: only agents may be streamable")
    if manifest.get("product_version") != __version__:
        errors.append(f"{label}: product_version must match the package")
    for key in manifest:
        if _SENSITIVE_KEY_RE.search(key):
            errors.append(f"{label}: sensitive field is forbidden: {key}")


def _is_placeholder_file(name: str) -> bool:
    lower = name.lower()
    return (
        lower in {".env.example", ".env.sample", ".env.template"}
        or lower.endswith((".example", ".sample", ".template"))
        or ".example." in lower
        or ".sample." in lower
        or ".template." in lower
    )


def _validate_placeholder_file(
    relative: Path, path: Path, errors: list[str]
) -> None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        errors.append(
            f"{relative.as_posix()}: placeholder cannot be read "
            f"({type(error).__name__}: {error})"
        )
        return

    if path.suffix.lower() == ".json":
        try:
            value = json.loads(text)
        except json.JSONDecodeError as error:
            errors.append(
                f"{relative.as_posix()}: invalid placeholder JSON at "
                f"line {error.lineno}, column {error.colno}"
            )
            return
        _walk_placeholder_values(relative, value, errors)
        return

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if _SENSITIVE_KEY_RE.search(key) and not _is_safe_placeholder(value):
            errors.append(
                f"{relative.as_posix()}:{line_number}: sensitive value must be "
                "an inert placeholder"
            )


def _walk_placeholder_values(
    relative: Path, value: object, errors: list[str], key_path: str = ""
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{key_path}.{key}" if key_path else str(key)
            if _SENSITIVE_KEY_RE.search(str(key)) and not _is_safe_placeholder(child):
                errors.append(
                    f"{relative.as_posix()}: {child_path} must be an inert placeholder"
                )
            _walk_placeholder_values(relative, child, errors, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_placeholder_values(
                relative, child, errors, f"{key_path}[{index}]"
            )


def _is_safe_placeholder(value: object) -> bool:
    if value is None or value is False:
        return True
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    return (
        normalized in _SAFE_PLACEHOLDERS
        or normalized.startswith("${")
        and normalized.endswith("}")
        or normalized.startswith("<")
        and normalized.endswith(">")
    )
