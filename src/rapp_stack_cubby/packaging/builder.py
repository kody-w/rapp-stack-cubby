"""Complete deterministic source-to-Store-to-cubby-egg build chain."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import uuid
import zlib
from pathlib import Path
from typing import Iterable, Mapping

from ..constants import __version__
from .archive import ArchiveEntry, ArchiveLimits, VerifiedZip, write_deterministic_zip
from .common import (
    COMMIT_RE,
    PackagingError,
    atomic_write,
    copy_verified_file,
    mode_text,
    parse_mode,
    pretty_json_bytes,
    read_json_object,
    sha256_file,
    validate_relative_path,
)
from .dependencies import load_dependency_lock, stage_dependency_artifacts
from .identity import validate_identity
from .immutable import (
    SourceMaterial,
    prepare_source_material,
    recheck_source_material,
)
from .indexes import build_store_index, build_super_rar_index
from .release import (
    CHECKSUMS_NAME,
    ReleaseVerification,
    RELEASE_MANIFEST_NAME,
    RELEASE_SIGNATURE_NAME,
    sign_release_manifest,
    verify_release,
)
from .source import RELEASE_SOURCE_MANIFEST, scan_source_tree, validate_source_manifest

APPLICATION_SCHEMA = "rapp-application/1.0"
EGG_SCHEMA = "brainstem-egg/2.3-cubby"
RELEASE_SCHEMA = "rapp-release-manifest/1.0"
PROVENANCE_SCHEMA = "rapp-release-provenance/1.0"

STORE_ARCHIVE_NAME = "rapp-stack-cubby-store.zip"
EGG_ARCHIVE_NAME = "rapp-stack-cubby.egg"
SBOM_NAME = "SBOM.spdx.json"
RELEASE_PROVENANCE_NAME = "release-provenance.json"
RELEASE_SUPER_RAR_NAME = "rapp-super-rar.json"
RELEASE_STORE_INDEX_NAME = "store-index.json"

_ROOT_ALLOWLIST = frozenset(
    {
        ".editorconfig",
        ".gitattributes",
        ".gitignore",
        "AI_CONTEXT.md",
        "CAPABILITY_MATRIX.json",
        "CHANGELOG.md",
        "COMMAND_MANIFEST.json",
        "CONFORMANCE.md",
        "CONTEXT_INDEX.json",
        "CONTRIBUTING.md",
        "DEPENDENCY_LOCK.json",
        "GITHUB_ACTIONS_LOCK.json",
        "LICENSE",
        "LIVE_PROVIDER_STATUS.json",
        "Makefile",
        "NOTICE",
        "PROVENANCE.json",
        "PUBLICATION_SCAN_POLICY.json",
        "RAPP_END_TO_END.md",
        "README.md",
        "RELEASE_CHECKLIST.md",
        "RELEASE_STATUS.json",
        "RELEASE_TRUST.json",
        RELEASE_SOURCE_MANIFEST,
        "SBOM_INPUT.json",
        "SECURITY.md",
        "SOURCE_CENSUS.json",
        "STACK_LOCK.json",
        "STORE_INDEX.json",
        "SYSTEM_GRAPH.json",
        "VENDOR_MANIFEST.json",
        "VERSION",
        "birth.json",
        "pyproject.toml",
        "rapp-super-rar.json",
        "rappid.json",
        "requirements-ci.lock",
        "requirements.lock",
    }
)
_DIRECTORY_ALLOWLIST = frozenset(
    {
        ".github",
        "THIRD_PARTY_LICENSES",
        "cubbies",
        "docs",
        "schemas",
        "scripts",
        "src",
        "tests",
        "tools",
    }
)
_RAPPLICATION_SOURCE = Path("cubbies/kody-w/rapplications/rapp-stack")
_CONTROLLER = Path("cubbies/kody-w/agents/rapp_stack_cubby_agent.py")
_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_ADAPTED_OPENRAPPTER = frozenset(
    {
        "scripts/install-imsg.sh",
        "src/rapp_stack_cubby/imessage/bridge.py",
        "src/rapp_stack_cubby/imessage/cli.py",
        "src/rapp_stack_cubby/imessage/config.py",
        "src/rapp_stack_cubby/imessage/rpc.py",
        "src/rapp_stack_cubby/imessage/state.py",
    }
)
_PROJECT_COPYRIGHT = "Copyright (c) 2026 Kody Wildfeuer"
_OPENRAPPTER_COPYRIGHT = "Copyright (c) 2025 Kody W"
_IMSG_COPYRIGHT = "Copyright (c) 2026 Peter Steinberger"
_PROVENANCE_KINDS = frozenset(
    {
        "adapted_source",
        "external_evidence",
        "generated_local",
        "mixed_notice",
        "original_new",
        "third_party_license",
    }
)
_ARTIFACT_LIMITS = ArchiveLimits(
    maximum_members=25_000,
    maximum_member_bytes=128 * 1024 * 1024,
    maximum_total_bytes=1024 * 1024 * 1024,
    maximum_compression_ratio=300,
    maximum_path_depth=40,
    maximum_archive_bytes=1024 * 1024 * 1024,
)


def _source_revision(value: str) -> tuple[str, bool]:
    if value == "WORKTREE":
        return value, True
    if not isinstance(value, str) or COMMIT_RE.fullmatch(value) is None:
        raise PackagingError("source revision must be WORKTREE or 40 lowercase hex")
    return value, False


def _allowed_source(path: str) -> bool:
    first = path.split("/", 1)[0]
    return path in _ROOT_ALLOWLIST or first in _DIRECTORY_ALLOWLIST


def _records_for_directory(root: Path) -> list[dict]:
    records: list[dict] = []
    for path in sorted(
        (value for value in root.rglob("*") if value.is_file()),
        key=lambda value: value.relative_to(root).as_posix().encode("utf-8"),
    ):
        if path.is_symlink():
            raise PackagingError("staged payload contains a symbolic link")
        relative = validate_relative_path(path.relative_to(root).as_posix())
        info = path.stat()
        digest, size = sha256_file(path)
        records.append(
            {
                "mode": mode_text(info.st_mode),
                "path": relative,
                "sha256": digest,
                "size": size,
            }
        )
    return records


def _write_json(path: Path, value: object, mode: int = 0o644) -> None:
    atomic_write(path, pretty_json_bytes(value), mode=mode)


def _copy_record(
    source_root: Path,
    relative: str,
    destination: Path,
    records: Mapping[str, Mapping[str, object]],
) -> None:
    try:
        record = records[relative]
    except KeyError as error:
        raise PackagingError(f"staged source record is missing: {relative}") from error
    copy_verified_file(
        source_root / relative,
        destination,
        expected_sha256=str(record["sha256"]),
        expected_size=int(record["size"]),
        mode=parse_mode(record["mode"]),
        limit=32 * 1024 * 1024,
    )


def stage_rapplication(
    root: str | Path,
    dependency_cache: str | Path,
    destination: str | Path,
    *,
    source_revision: str,
    development_only: bool | None = None,
) -> dict:
    """Copy reviewed source and locked dependencies into an immutable stage."""

    repository = Path(root).resolve()
    stage = Path(destination)
    revision, worktree = _source_revision(source_revision)
    development = (
        worktree if development_only is None else bool(development_only)
    )
    source_result = validate_source_manifest(repository)
    scan = scan_source_tree(repository)
    if scan.get("secret_scan", {}).get("passed") is not True:
        raise PackagingError("source secret scan did not complete")
    birth = read_json_object(repository / "birth.json")
    identity = read_json_object(repository / "rappid.json")
    validate_identity(birth, identity)
    if stage.exists() or stage.is_symlink():
        raise PackagingError("rapplication stage already exists")
    stage.mkdir(parents=True, mode=0o700)
    try:
        records = list(scan["files"])
        manifest_digest, manifest_size = sha256_file(
            repository / RELEASE_SOURCE_MANIFEST
        )
        records.append(
            {
                "executable": False,
                "mode": "0644",
                "path": RELEASE_SOURCE_MANIFEST,
                "sha256": manifest_digest,
                "size": manifest_size,
            }
        )
        records.sort(key=lambda item: item["path"].encode("utf-8"))
        by_path = {record["path"]: record for record in records}
        for record in records:
            if not _allowed_source(record["path"]):
                raise PackagingError(
                    "source is outside the explicit product allowlist: "
                    f"{record['path']}"
                )
            _copy_record(
                repository,
                record["path"],
                stage / "source" / record["path"],
                by_path,
            )

        application_source = repository / _RAPPLICATION_SOURCE
        application_paths = [
            "README.md",
            "index_entry.json",
            "singleton/rapp_stack_cubby_agent.py",
            "ui/index.html",
        ]
        application_paths.extend(
            path.relative_to(application_source).as_posix()
            for path in sorted(
                (application_source / "twin").rglob("*"),
                key=lambda value: value.relative_to(application_source).as_posix(),
            )
            if path.is_file()
        )
        for relative in application_paths:
            source_relative = (_RAPPLICATION_SOURCE / relative).as_posix()
            _copy_record(
                repository,
                source_relative,
                stage / relative,
                by_path,
            )
        for relative in (
            "requirements.lock",
            "scripts/install-imsg.sh",
            "scripts/check.sh",
        ):
            _copy_record(repository, relative, stage / relative, by_path)
        _write_json(stage / "birth.json", birth)
        _write_json(stage / "rappid.json", identity)

        dependency_records = list(
            stage_dependency_artifacts(repository, dependency_cache, stage)
        )
        existing = read_json_object(application_source / "index_entry.json")
        existing.pop("manifest_sha256", None)
        existing.update(
            {
                "development_only": development,
                "published": False,
                "released": False,
                "source_revision": revision,
                "source_tree_digest": source_result["source_tree_digest"],
            }
        )
        _write_json(stage / "index_entry.json", existing)

        payload_records = _records_for_directory(stage)
        controller = next(
            record
            for record in payload_records
            if record["path"] == "singleton/rapp_stack_cubby_agent.py"
        )
        agents = [
            record
            for record in payload_records
            if record["path"].startswith("twin/agents/")
            and record["path"].endswith("_agent.py")
        ]
        soul = next(
            record for record in payload_records if record["path"] == "twin/soul.md"
        )
        manifest = {
            "agent_first": True,
            "agents": agents,
            "application_id": "rapp-stack",
            "boundaries": {
                "bundled_secrets": False,
                "bundled_state": False,
                "private_state": "created only by the hatcher outside source",
                "public_source": True,
                "secret_scan_profile": scan["secret_scan"]["profile"],
            },
            "controller": controller,
            "dependencies": dependency_records,
            "development_only": development,
            "features": {
                "local_ui": True,
                "owner_only_imessage": True,
                "published": False,
                "released": False,
                "signed_twin_chat": True,
            },
            "files": payload_records,
            "identity": identity["rappid"],
            "platform": {
                "architecture": "arm64",
                "macos_minimum": "11.0",
                "python": "3.11",
            },
            "runtime": {
                "capability_endpoint": "loopback POST /chat",
                "implementation": "source/src/rapp_stack_cubby/runtime",
                "network_install": False,
            },
            "schema": APPLICATION_SCHEMA,
            "soul": soul,
            "source_manifest_sha256": source_result["manifest_sha256"],
            "source_revision": revision,
            "source_tree_digest": source_result["source_tree_digest"],
            "streamable_agent_count": 1,
            "version": __version__,
        }
        _write_json(stage / "manifest.json", manifest)
        complete_records = _records_for_directory(stage)
        return {
            "development_only": development,
            "file_count": len(complete_records),
            "files": complete_records,
            "manifest": manifest,
            "source_tree_digest": source_result["source_tree_digest"],
            "stage": str(stage),
        }
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _entries_from_directory(root: Path, *, prefix: str = "") -> list[ArchiveEntry]:
    return [
        ArchiveEntry(
            path=f"{prefix}{record['path']}",
            source=root / record["path"],
            mode=parse_mode(record["mode"]),
        )
        for record in _records_for_directory(root)
    ]


def _build_egg_manifest(
    root: Path,
    application_stage: Path,
    *,
    source_revision: str,
    source_tree_digest: str,
    development: bool,
) -> tuple[dict, list[ArchiveEntry]]:
    prefix = "cubby/kody-w/rapplications/rapp-stack/"
    entries = _entries_from_directory(application_stage, prefix=prefix)
    entries.append(
        ArchiveEntry(
            "cubby.json",
            source=root / "cubbies/kody-w/cubby.json",
            mode=0o644,
        )
    )
    records = []
    for entry in entries:
        content = entry.bytes()
        records.append(
            {
                "mode": mode_text(entry.mode),
                "path": entry.path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
            }
        )
    records.sort(key=lambda item: item["path"].encode("utf-8"))
    manifest = {
        "artifact": {
            "development_only": development,
            "source_revision": source_revision,
            "source_tree_digest": source_tree_digest,
        },
        "bundled_secrets": False,
        "bundled_state": False,
        "files": records,
        "identity": read_json_object(root / "rappid.json")["rappid"],
        "profile": {
            "architecture": "arm64",
            "macos_minimum": "11.0",
            "python": "3.11",
        },
        "schema": EGG_SCHEMA,
        "version": __version__,
    }
    entries.append(
        ArchiveEntry("manifest.json", data=pretty_json_bytes(manifest), mode=0o644)
    )
    return manifest, entries


def _spdx_id(value: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", value)


def _sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as source:
        while True:
            chunk = source.read(128 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _rfc3339(epoch: int) -> str:
    return (
        datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _detected_licenses(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ["NOASSERTION"]
    identifiers = sorted(
        set(
            re.findall(
                r"(?im)^\s*(?:#|//|/\*|\*)?\s*SPDX-License-Identifier:"
                r"\s*([A-Za-z0-9.+-]+)\s*(?:\*/)?\s*$",
                text,
            )
        )
    )
    if identifiers:
        return identifiers
    normalized = " ".join(text.split()).casefold()
    if all(
        marker in normalized
        for marker in (
            "mit license",
            "permission is hereby granted, free of charge",
            'the software is provided "as is"',
        )
    ):
        return ["MIT"]
    return ["NOASSERTION"]


def _file_provenance(root: Path, scan: Mapping[str, object]) -> dict[str, dict]:
    provenance = read_json_object(root / "PROVENANCE.json")
    sbom_input = read_json_object(root / "SBOM_INPUT.json")
    entries = provenance.get("entries")
    if not isinstance(entries, list):
        raise PackagingError("PROVENANCE entries are invalid")
    targets = [
        item
        for item in entries
        if isinstance(item, dict)
        and item.get("id") == "target-rapp-stack-cubby"
    ]
    if len(targets) != 1:
        raise PackagingError("target per-file provenance is unavailable")
    source_map = targets[0].get("source_file_provenance")
    if not isinstance(source_map, dict) or source_map.get("schema") != (
        "rapp-source-file-provenance/1.0"
    ):
        raise PackagingError("source file provenance map is invalid")
    records = source_map.get("files")
    if not isinstance(records, list) or not all(
        isinstance(item, dict) for item in records
    ):
        raise PackagingError("source file provenance records are invalid")
    by_path: dict[str, dict] = {}
    for record in records:
        path = record.get("path")
        kind = record.get("provenance")
        if (
            not isinstance(path, str)
            or path in by_path
            or kind not in _PROVENANCE_KINDS
        ):
            raise PackagingError("source file provenance path/kind is invalid")
        by_path[path] = record

    scan_records = scan.get("files")
    if not isinstance(scan_records, list):
        raise PackagingError("source scan files are invalid")
    scan_by_path = {
        item["path"]: item
        for item in scan_records
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    if set(by_path) != set(scan_by_path):
        raise PackagingError("source file provenance coverage is incomplete")
    for path, record in by_path.items():
        declared = record.get("sha256")
        if path == "PROVENANCE.json":
            if declared is not None:
                raise PackagingError(
                    "self-describing PROVENANCE hash must be null"
                )
        elif declared != scan_by_path[path].get("sha256"):
            raise PackagingError(f"{path}: provenance hash is stale")

    adapted = sbom_input.get("adapted_files")
    if not isinstance(adapted, list) or not all(
        isinstance(item, dict) for item in adapted
    ):
        raise PackagingError("SBOM adapted-file inputs are invalid")
    adapted_by_path = {
        item.get("destination"): item
        for item in adapted
        if isinstance(item.get("destination"), str)
    }
    if set(adapted_by_path) != set(_ADAPTED_OPENRAPPTER):
        raise PackagingError("adapted OpenRappter provenance is incomplete")
    source_entry = next(
        (
            item
            for item in entries
            if isinstance(item, dict)
            and item.get("id") == "adapted-openrappter-imessage"
        ),
        None,
    )
    cleared = {
        item.get("destination"): item
        for item in (
            source_entry.get("cleared_files", [])
            if isinstance(source_entry, dict)
            else []
        )
        if isinstance(item, dict)
    }
    if set(cleared) != set(_ADAPTED_OPENRAPPTER):
        raise PackagingError("adapted OpenRappter blob map is incomplete")
    for path, item in adapted_by_path.items():
        record = by_path[path]
        if (
            record.get("provenance") != "adapted_source"
            or record.get("source_blob") != item.get("source_blob")
            or record.get("source_blob") != cleared[path].get("source_blob")
            or item.get("license") != "MIT"
        ):
            raise PackagingError(f"{path}: adapted provenance does not cross-bind")

    expected_third_party = {
        "THIRD_PARTY_LICENSES/OpenRappter-MIT.txt": (
            _OPENRAPPTER_COPYRIGHT,
            "MIT",
        ),
        "THIRD_PARTY_LICENSES/imsg-MIT.txt": (_IMSG_COPYRIGHT, "MIT"),
    }
    for path, (copyright_text, license_expression) in expected_third_party.items():
        record = by_path.get(path)
        if (
            not isinstance(record, dict)
            or record.get("provenance") != "third_party_license"
            or record.get("copyright") != copyright_text
            or record.get("license_concluded") != license_expression
            or _detected_licenses(root / path) != ["MIT"]
        ):
            raise PackagingError(f"{path}: third-party license provenance is invalid")
    return by_path


def _build_sbom(
    root: Path,
    *,
    source_revision: str,
    source_tree_digest: str,
    source_date_epoch: int,
) -> dict:
    scan = scan_source_tree(root)
    lock, artifacts = load_dependency_lock(root)
    provenance = _file_provenance(root, scan)
    files = []
    verification_hashes = []
    for index, record in enumerate(scan["files"], start=1):
        sha1 = _sha1(root / record["path"])
        verification_hashes.append(sha1)
        source = provenance[record["path"]]
        kind = source["provenance"]
        adapted = kind == "adapted_source"
        if kind in {"original_new", "generated_local"}:
            copyright_text = _PROJECT_COPYRIGHT
            license_concluded = "MIT"
        elif adapted:
            copyright_text = _OPENRAPPTER_COPYRIGHT
            license_concluded = "MIT"
        elif kind == "third_party_license":
            copyright_text = source["copyright"]
            license_concluded = source["license_concluded"]
        else:
            copyright_text = "NOASSERTION"
            license_concluded = "NOASSERTION"
        value = {
            "SPDXID": _spdx_id(f"File-{index}-{record['path']}"),
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": sha1},
                {"algorithm": "SHA256", "checksumValue": record["sha256"]},
            ],
            "copyrightText": copyright_text,
            "fileName": "./" + record["path"],
            "licenseConcluded": license_concluded,
            "licenseInfoInFiles": _detected_licenses(root / record["path"]),
        }
        if adapted:
            value["fileComment"] = (
                "Adapted from kody-w/openrappter at commit "
                "7b6dbca2cf23f3a21dacc604d2bda34e7e13cd6a; "
                f"source blob {source['source_blob']}; see NOTICE and "
                "THIRD_PARTY_LICENSES/OpenRappter-MIT.txt. The MIT conclusion "
                "comes from validated provenance; the destination contains no "
                "invented in-file license assertion."
            )
        elif kind == "external_evidence":
            value["fileComment"] = (
                "Mixed/public evidence bytes; authorship and per-file license "
                "are not asserted."
            )
        elif kind == "generated_local":
            value["fileComment"] = (
                "Generated local project output identified by PROVENANCE.json."
            )
        elif kind == "mixed_notice":
            value["fileComment"] = (
                "Mixed project and third-party notice; see the referenced "
                "license copies. No single per-file conclusion is asserted."
            )
        files.append(value)
    verification_code = hashlib.sha1(
        "".join(sorted(verification_hashes)).encode("ascii")
    ).hexdigest()
    root_package = {
        "SPDXID": "SPDXRef-Package-rapp-stack-cubby",
        "checksums": [
            {"algorithm": "SHA256", "checksumValue": source_tree_digest}
        ],
        "copyrightText": _PROJECT_COPYRIGHT,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "name": "rapp-stack-cubby",
        "packageVerificationCode": {
            "packageVerificationCodeValue": verification_code
        },
        "versionInfo": source_revision,
    }
    packages = [root_package]
    licenses = {
        item["name"]: item["license_expression"] for item in lock["packages"]
    }
    licenses.update(
        {item["name"]: item["license"]["spdx"] for item in lock["tools"]}
    )
    for artifact in artifacts:
        packages.append(
            {
                "SPDXID": _spdx_id(f"Package-{artifact.name}-{artifact.version}"),
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": artifact.sha256}
                ],
                "copyrightText": "NOASSERTION",
                "downloadLocation": artifact.url,
                "filesAnalyzed": False,
                "licenseConcluded": licenses[artifact.name],
                "licenseDeclared": licenses[artifact.name],
                "name": artifact.name,
                "versionInfo": artifact.version,
            }
        )
    build_system = lock["build_system"]
    packages.append(
        {
            "SPDXID": "SPDXRef-Package-setuptools-80.9.0",
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": build_system["wheel"]["sha256"],
                }
            ],
            "copyrightText": "NOASSERTION",
            "downloadLocation": build_system["wheel"]["url"],
            "filesAnalyzed": False,
            "licenseConcluded": build_system["license_expression"],
            "licenseDeclared": build_system["license_expression"],
            "name": build_system["name"],
            "versionInfo": build_system["version"],
        }
    )
    relationships = [
        {
            "relatedSpdxElement": root_package["SPDXID"],
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        }
    ]
    relationships.extend(
        {
            "relatedSpdxElement": file["SPDXID"],
            "relationshipType": "CONTAINS",
            "spdxElementId": root_package["SPDXID"],
        }
        for file in files
    )
    relationships.extend(
        {
            "relatedSpdxElement": package["SPDXID"],
            "relationshipType": "DEPENDS_ON",
            "spdxElementId": root_package["SPDXID"],
        }
        for package in packages[1:]
    )
    namespace_digest = hashlib.sha256(
        f"{source_revision}:{source_tree_digest}".encode("ascii")
    ).hexdigest()
    result = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _rfc3339(source_date_epoch),
            "creators": ["Tool: rapp-stack-cubby-packager-1.0"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": (
            "https://github.com/kody-w/rapp-stack-cubby/"
            f"spdx/{namespace_digest}"
        ),
        "files": files,
        "name": "RAPP Stack Cubby complete product SBOM",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    validate_spdx(result)
    return result


def validate_spdx(value: Mapping[str, object]) -> dict:
    """Project-owned SPDX 2.3 structural and relationship validator."""

    if (
        value.get("spdxVersion") != "SPDX-2.3"
        or value.get("SPDXID") != "SPDXRef-DOCUMENT"
        or value.get("dataLicense") != "CC0-1.0"
        or not isinstance(value.get("files"), list)
        or not isinstance(value.get("packages"), list)
        or not isinstance(value.get("relationships"), list)
    ):
        raise PackagingError("SPDX document structure is invalid")
    files = value["files"]
    packages = value["packages"]
    relationships = value["relationships"]
    ids = {
        item.get("SPDXID")
        for item in [*files, *packages]
        if isinstance(item, dict)
    }
    if len(ids) != len(files) + len(packages) or None in ids:
        raise PackagingError("SPDX element IDs are invalid or duplicated")
    roots = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("SPDXID") == "SPDXRef-Package-rapp-stack-cubby"
    ]
    if len(roots) != 1 or roots[0].get("filesAnalyzed") is not True:
        raise PackagingError("SPDX root package is invalid")
    code = roots[0].get("packageVerificationCode")
    if (
        not isinstance(code, dict)
        or not isinstance(code.get("packageVerificationCodeValue"), str)
        or re.fullmatch(
            r"[0-9a-f]{40}", code["packageVerificationCodeValue"]
        )
        is None
    ):
        raise PackagingError("SPDX package verification code is missing")
    file_ids = {item["SPDXID"] for item in files}
    external_ids = {
        item["SPDXID"]
        for item in packages
        if item["SPDXID"] != roots[0]["SPDXID"]
    }
    contains = {
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == roots[0]["SPDXID"]
        and item.get("relationshipType") == "CONTAINS"
    }
    dependencies = {
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == roots[0]["SPDXID"]
        and item.get("relationshipType") == "DEPENDS_ON"
    }
    if contains != file_ids or dependencies != external_ids:
        raise PackagingError("SPDX package relationships are incomplete")
    for file in files:
        if (
            file.get("licenseConcluded") is None
            or not isinstance(file.get("licenseInfoInFiles"), list)
            or not file["licenseInfoInFiles"]
            or not isinstance(file.get("copyrightText"), str)
            or not file["copyrightText"]
            or not isinstance(file.get("checksums"), list)
            or {item.get("algorithm") for item in file["checksums"]}
            != {"SHA1", "SHA256"}
        ):
            raise PackagingError("SPDX file license or checksum is incomplete")
    sha1_values = sorted(
        checksum["checksumValue"]
        for file in files
        for checksum in file["checksums"]
        if checksum.get("algorithm") == "SHA1"
    )
    expected_code = hashlib.sha1(
        "".join(sha1_values).encode("ascii")
    ).hexdigest()
    if code["packageVerificationCodeValue"] != expected_code:
        raise PackagingError("SPDX package verification code is invalid")
    for package in packages:
        if (
            not isinstance(package.get("checksums"), list)
            or not package["checksums"]
            or package.get("licenseConcluded") in {None, "NOASSERTION"}
        ):
            raise PackagingError("SPDX package metadata is incomplete")
    return {
        "file_count": len(files),
        "package_count": len(packages),
        "valid": True,
    }


def _artifact_record(path: Path, kind: str) -> dict:
    digest, size = sha256_file(path)
    return {
        "filename": path.name,
        "kind": kind,
        "sha256": digest,
        "size": size,
    }


def _parse_archive_object(raw: bytes, label: str) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise PackagingError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PackagingError(f"{label} is invalid") from error
    if not isinstance(value, dict) or pretty_json_bytes(value) != raw:
        raise PackagingError(f"{label} is not a canonical JSON object")
    return value


def _artifact_semantics(verified: VerifiedZip) -> dict:
    baseline = verified.result
    paths = {record["path"] for record in baseline["files"]}
    if "manifest.json" in paths:
        raw = verified.captured.get("manifest.json")
        if raw is None:
            raise PackagingError("egg manifest was not captured")
        manifest = _parse_archive_object(raw, "egg manifest")
        if manifest.get("schema") != EGG_SCHEMA:
            raise PackagingError("egg profile manifest is invalid")
        declared = manifest.get("files")
        if not isinstance(declared, list):
            raise PackagingError("egg member manifest is missing")
        expected = sorted(
            (dict(item) for item in declared),
            key=lambda item: str(item.get("path", "")).encode("utf-8"),
        )
        actual = [
            record
            for record in baseline["files"]
            if record["path"] != "manifest.json"
        ]
        if expected != actual:
            raise PackagingError("egg has extra, missing, or changed members")
        return {
            **baseline,
            "artifact_type": "cubby-egg",
            "manifest": manifest,
        }
    manifest_path = "rapp-stack/manifest.json"
    raw = verified.captured.get(manifest_path)
    if manifest_path not in paths or raw is None:
        raise PackagingError("unknown RAPP artifact layout")
    manifest = _parse_archive_object(raw, "rapplication manifest")
    if manifest.get("schema") != APPLICATION_SCHEMA:
        raise PackagingError("rapplication manifest is invalid")
    declared = manifest.get("files")
    if not isinstance(declared, list):
        raise PackagingError("rapplication member manifest is missing")
    actual = []
    for record in baseline["files"]:
        if not record["path"].startswith("rapp-stack/"):
            raise PackagingError("Store ZIP contains an out-of-root member")
        relative = record["path"].removeprefix("rapp-stack/")
        if relative == "manifest.json":
            continue
        item = dict(record)
        item["path"] = relative
        actual.append(item)
    expected = sorted(
        (dict(item) for item in declared),
        key=lambda item: str(item.get("path", "")).encode("utf-8"),
    )
    actual.sort(key=lambda item: item["path"].encode("utf-8"))
    if expected != actual:
        raise PackagingError("Store ZIP has extra, missing, or changed members")
    return {
        **baseline,
        "artifact_type": "store-rapplication",
        "manifest": manifest,
    }


def _release_allows_artifact(
    result: Mapping[str, object],
    artifact_name: str,
    digest: str,
    *,
    test_only_allow_development: bool,
) -> bool:
    if not isinstance(result, ReleaseVerification) or result.get("verified") is not True:
        return False
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, list) or not any(
        isinstance(item, dict)
        and item.get("filename") == artifact_name
        and item.get("sha256") == digest
        for item in artifacts
    ):
        return False
    return result.get("release_eligible") is True or (
        test_only_allow_development
        and result.get("development_only") is True
        and result.get("signed") is True
    )


def verify_artifact(
    path: str | Path,
    *,
    expected_sha256: str | None = None,
    release_verification: Mapping[str, object] | None = None,
) -> dict:
    """Verify every member through one descriptor; inspection never authorizes execution."""

    try:
        with VerifiedZip(
            path,
            expected_sha256=expected_sha256,
            limits=_ARTIFACT_LIMITS,
            capture_members=("manifest.json", "rapp-stack/manifest.json"),
        ) as verified:
            result = _artifact_semantics(verified)
    except (OSError, RuntimeError) as error:
        if isinstance(error, PackagingError):
            raise
        raise PackagingError("invalid RAPP artifact") from error
    executable = False
    if release_verification is not None:
        executable = _release_allows_artifact(
            release_verification,
            Path(path).name,
            result["sha256"],
            test_only_allow_development=False,
        )
    return {**result, "execution_allowed": executable}


def extract_verified_artifact(
    path: str | Path,
    destination: str | Path,
    *,
    expected_sha256: str,
    release_verification: Mapping[str, object] | None,
    test_only_allow_development: bool = False,
) -> dict:
    """Verify artifact semantics and extract through the same open descriptor."""

    with VerifiedZip(
        path,
        expected_sha256=expected_sha256,
        limits=_ARTIFACT_LIMITS,
        capture_members=("manifest.json", "rapp-stack/manifest.json"),
    ) as verified:
        result = _artifact_semantics(verified)
        test_only_untrusted = (
            test_only_allow_development
            and release_verification is None
            and result.get("artifact_type") == "cubby-egg"
            and result.get("manifest", {})
            .get("artifact", {})
            .get("development_only")
            is True
        )
        if not test_only_untrusted and (
            release_verification is None
            or not _release_allows_artifact(
                release_verification,
                Path(path).name,
                result["sha256"],
                test_only_allow_development=test_only_allow_development,
            )
        ):
            raise PackagingError(
                "artifact execution requires a pinned signed release verification"
            )
        verified.extract(destination)
        return {**result, "execution_allowed": True}


def _toolchain() -> dict:
    try:
        import cryptography

        cryptography_version = cryptography.__version__
    except ImportError:
        cryptography_version = None
    return {
        "cryptography": cryptography_version,
        "implementation": platform.python_implementation(),
        "python": platform.python_version(),
        "python_executable_identity": (
            f"{sys.implementation.name}-{sys.version_info.major}."
            f"{sys.version_info.minor}.{sys.version_info.micro}"
        ),
        "zip_entries": "stored",
        "zlib_compile": zlib.ZLIB_VERSION,
        "zlib_runtime": zlib.ZLIB_RUNTIME_VERSION,
    }


def _exact_output_names(signed: bool) -> set[str]:
    names = {
        STORE_ARCHIVE_NAME,
        EGG_ARCHIVE_NAME,
        SBOM_NAME,
        RELEASE_PROVENANCE_NAME,
        RELEASE_MANIFEST_NAME,
        CHECKSUMS_NAME,
        RELEASE_SUPER_RAR_NAME,
        RELEASE_STORE_INDEX_NAME,
    }
    if signed:
        names.add(RELEASE_SIGNATURE_NAME)
    return names


def _builder_work_directory(repository: Path, destination: Path) -> Path:
    parent = destination.parent
    if parent == repository or repository in parent.parents:
        parent = repository.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent == repository or repository in parent.parents:
        raise PackagingError("builder work directory must be outside the source root")
    work = parent / f".{destination.name}.builder-{uuid.uuid4().hex}"
    work.mkdir(mode=0o700)
    return work


def build_release(
    root: str | Path,
    dependency_cache: str | Path,
    output: str | Path,
    *,
    source_date_epoch: int,
    source_revision: str,
    signing_key: str | Path | None = None,
    signing_trust: str | Path | None = None,
) -> dict:
    """Build into a unique sibling, verify exactly, and atomically promote."""

    repository = Path(root).resolve()
    destination = Path(output).resolve()
    revision, worktree = _source_revision(source_revision)
    signed = signing_key is not None
    if signing_trust is not None and not signed:
        raise PackagingError("signing trust requires an explicit signing key")
    if signing_trust is not None and not worktree:
        raise PackagingError(
            "external signing trust is restricted to WORKTREE development builds"
        )
    external_trust = (
        Path(signing_trust).resolve()
        if signing_trust is not None
        else None
    )
    if destination.exists() or destination.is_symlink():
        raise PackagingError("release output must not already exist")
    work = _builder_work_directory(repository, destination)
    output_stage: Path | None = None
    material: SourceMaterial | None = None
    try:
        material = prepare_source_material(repository, revision, work)
        source = material.root
        selected_trust = (
            external_trust
            if external_trust is not None
            else source / "RELEASE_TRUST.json"
        )
        destination.parent.mkdir(parents=True, exist_ok=True)
        output_stage = destination.parent / (
            f".{destination.name}.build-{uuid.uuid4().hex}"
        )
        output_stage.mkdir(mode=0o700)
        stage = work / "rapplication"
        development = worktree or not signed
        staged = stage_rapplication(
            source,
            dependency_cache,
            stage,
            source_revision=revision,
            development_only=development,
        )
        store_path = output_stage / STORE_ARCHIVE_NAME
        write_deterministic_zip(
            store_path,
            _entries_from_directory(stage, prefix="rapp-stack/"),
            source_date_epoch=source_date_epoch,
        )
        store_verified = verify_artifact(store_path)

        _, egg_entries = _build_egg_manifest(
            source,
            stage,
            source_revision=revision,
            source_tree_digest=staged["source_tree_digest"],
            development=development,
        )
        egg_path = output_stage / EGG_ARCHIVE_NAME
        write_deterministic_zip(
            egg_path,
            egg_entries,
            source_date_epoch=source_date_epoch,
        )
        egg_verified = verify_artifact(egg_path)

        sbom = _build_sbom(
            source,
            source_revision=revision,
            source_tree_digest=staged["source_tree_digest"],
            source_date_epoch=source_date_epoch,
        )
        sbom_path = output_stage / SBOM_NAME
        _write_json(sbom_path, sbom)

        materials = [
            {
                "sha256": record["sha256"],
                "uri": f"locked:{record['path']}",
            }
            for record in staged["manifest"]["dependencies"]
        ]
        materials.append(
            {
                "sha256": staged["source_tree_digest"],
                "uri": "git+https://github.com/kody-w/rapp-stack-cubby.git"
                f"@{revision}",
            }
        )
        provenance = {
            "build": {
                "builder": "rapp-stack-cubby.packaging/1.0",
                "network_used": False,
                "reproducibility_claim": "same-input/same-locked-toolchain",
                "source_date_epoch": source_date_epoch,
                "toolchain": _toolchain(),
            },
            "development_only": development,
            "materials": sorted(materials, key=lambda item: item["uri"]),
            "profile": "macos-arm64-cpython311",
            "schema": PROVENANCE_SCHEMA,
            "source_git_tree": material.git_tree,
            "source_revision": revision,
            "source_tree_digest": staged["source_tree_digest"],
            "version": __version__,
        }
        provenance_path = output_stage / RELEASE_PROVENANCE_NAME
        _write_json(provenance_path, provenance)

        controller_digest, controller_size = sha256_file(source / _CONTROLLER)
        application_manifest = stage / "manifest.json"
        application_digest, application_size = sha256_file(application_manifest)
        store_record = _artifact_record(store_path, "store-zip")
        egg_record = _artifact_record(egg_path, "cubby-egg")
        release_super_rar = build_super_rar_index(
            [
                {
                    "kind": "controller-agent",
                    "name": "RappStackCubbyController",
                    "rank": 0,
                    "sha256": controller_digest,
                    "size": controller_size,
                    "sources": [_CONTROLLER.as_posix()],
                    "streamable": True,
                },
                {
                    "kind": "rapplication",
                    "name": "rapp-stack",
                    "rank": 10,
                    "sha256": application_digest,
                    "size": application_size,
                    "sources": ["rapp-stack/manifest.json"],
                    "streamable": False,
                },
                {
                    "kind": "release-artifact",
                    "name": STORE_ARCHIVE_NAME,
                    "rank": 20,
                    "sha256": store_record["sha256"],
                    "size": store_record["size"],
                    "sources": [STORE_ARCHIVE_NAME],
                    "streamable": False,
                },
                {
                    "kind": "release-artifact",
                    "name": EGG_ARCHIVE_NAME,
                    "rank": 21,
                    "sha256": egg_record["sha256"],
                    "size": egg_record["size"],
                    "sources": [EGG_ARCHIVE_NAME],
                    "streamable": False,
                },
            ],
            source_tree_digest=staged["source_tree_digest"],
            source_revision=revision,
            release_specific=True,
        )
        super_path = output_stage / RELEASE_SUPER_RAR_NAME
        _write_json(super_path, release_super_rar)
        store_index = build_store_index(
            [
                {
                    "application_id": "rapp-stack",
                    "application_manifest_sha256": application_digest,
                    "application_manifest_size": application_size,
                    "development_only": development,
                    "egg_sha256": egg_record["sha256"],
                    "store_archive_sha256": store_record["sha256"],
                    "store_archive_size": store_record["size"],
                }
            ],
            source_tree_digest=staged["source_tree_digest"],
            source_revision=revision,
            release_specific=True,
        )
        store_index_path = output_stage / RELEASE_STORE_INDEX_NAME
        _write_json(store_index_path, store_index)

        artifacts = [
            store_record,
            egg_record,
            _artifact_record(sbom_path, "sbom"),
            _artifact_record(provenance_path, "provenance"),
            _artifact_record(super_path, "super-rar-index"),
            _artifact_record(store_index_path, "store-index"),
        ]
        artifacts.sort(key=lambda item: item["filename"].encode("utf-8"))
        release_manifest = {
            "artifacts": artifacts,
            "development_only": development,
            "release": signed and not worktree,
            "schema": RELEASE_SCHEMA,
            "signed": signed,
            "source_commit": revision,
            "source_git_tree": material.git_tree,
            "source_tree_digest": staged["source_tree_digest"],
            "version": __version__,
        }
        release_path = output_stage / RELEASE_MANIFEST_NAME
        _write_json(release_path, release_manifest)
        if signed:
            sign_release_manifest(
                release_path,
                output_stage / RELEASE_SIGNATURE_NAME,
                key_path=Path(signing_key),
                repository_root=repository,
                trust_path=selected_trust,
            )
        checksummed = [*artifacts, _artifact_record(release_path, "release-manifest")]
        if signed:
            checksummed.append(
                _artifact_record(
                    output_stage / RELEASE_SIGNATURE_NAME,
                    "detached-signature",
                )
            )
        checksum_lines = [
            f"{item['sha256']}  {item['filename']}"
            for item in sorted(
                checksummed,
                key=lambda item: item["filename"].encode("utf-8"),
            )
        ]
        atomic_write(
            output_stage / CHECKSUMS_NAME,
            ("\n".join(checksum_lines) + "\n").encode("ascii"),
        )
        expected_names = _exact_output_names(signed)
        observed = {
            item.name
            for item in output_stage.iterdir()
        }
        if observed != expected_names:
            raise PackagingError("builder output inventory is not exact")
        release_digest, _ = sha256_file(release_path)
        verified_release = verify_release(
            release_path,
            expected_manifest_sha256=release_digest,
            trust_path=selected_trust,
            source_root=source if worktree else repository,
            allow_unsigned_development=not signed,
        )
        recheck_source_material(repository, material)
        os.replace(output_stage, destination)
        return {
            "artifacts": [
                _artifact_record(destination / name, "release-output")
                for name in sorted(expected_names)
            ],
            "development_only": release_manifest["development_only"],
            "egg_file_count": egg_verified["file_count"],
            "key_id": verified_release["key_id"],
            "release": release_manifest["release"],
            "release_manifest_sha256": release_digest,
            "signed": signed,
            "source_git_tree": material.git_tree,
            "source_tree_digest": staged["source_tree_digest"],
            "store_file_count": store_verified["file_count"],
        }
    except Exception:
        if output_stage is not None:
            shutil.rmtree(output_stage, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
