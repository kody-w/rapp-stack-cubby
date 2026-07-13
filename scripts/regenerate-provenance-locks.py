#!/usr/bin/env python3
"""Refresh deterministic local-file provenance and matching lock manifests."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rapp_stack_cubby.context import SCHEMAS  # noqa: E402
from rapp_stack_cubby.packaging.source import scan_source_tree  # noqa: E402


def digest(path: str) -> str:
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def record(path: str, *, generated: bool = False) -> dict[str, str]:
    return {
        "path": path,
        "provenance": "generated_local" if generated else "original_new",
        "sha256": digest(path),
    }


def manifest_digest(records: list[dict]) -> str:
    payload = json.dumps(
        records,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def main() -> int:
    controller_source = (
        ROOT / "cubbies/kody-w/agents/rapp_stack_cubby_agent.py"
    )
    cubby_path = ROOT / "cubbies/kody-w/cubby.json"
    cubby = json.loads(cubby_path.read_text(encoding="utf-8"))
    cubby["controller"]["sha256"] = hashlib.sha256(
        controller_source.read_bytes()
    ).hexdigest()
    cubby_path.write_text(
        json.dumps(cubby, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    application_root = (
        ROOT / "cubbies/kody-w/rapplications/rapp-stack"
    )
    application_path = application_root / "manifest.json"
    application = json.loads(application_path.read_text(encoding="utf-8"))

    def descriptor(relative: str) -> dict[str, object]:
        path = application_root / relative
        return {
            "mode": "0755" if path.stat().st_mode & 0o111 else "0644",
            "path": relative,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size": path.stat().st_size,
        }

    application["controller"] = descriptor(
        "singleton/rapp_stack_cubby_agent.py"
    )
    application["agents"] = [
        descriptor(path.relative_to(application_root).as_posix())
        for path in sorted((application_root / "twin/agents").glob("*_agent.py"))
    ]
    application["soul"] = descriptor("twin/soul.md")
    application_path.write_text(
        json.dumps(application, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    application_sha = hashlib.sha256(application_path.read_bytes()).hexdigest()
    store_path = ROOT / "STORE_INDEX.json"
    store = json.loads(store_path.read_text(encoding="utf-8"))
    store["applications"][0]["application_manifest_sha256"] = application_sha
    store["applications"][0]["application_manifest_size"] = (
        application_path.stat().st_size
    )
    store_path.write_text(
        json.dumps(store, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    super_path = ROOT / "rapp-super-rar.json"
    super_index = json.loads(super_path.read_text(encoding="utf-8"))
    for item in super_index["entries"]:
        source = ROOT / item["sources"][0]
        item["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        item["size"] = source.stat().st_size
    super_path.write_text(
        json.dumps(super_index, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    provenance_path = ROOT / "PROVENANCE.json"
    lock_path = ROOT / "STACK_LOCK.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    action_lock = json.loads(
        (ROOT / "GITHUB_ACTIONS_LOCK.json").read_text(encoding="utf-8")
    )
    action_entries = {
        item.get("id"): item
        for item in provenance["entries"]
        if isinstance(item, dict)
        and str(item.get("id", "")).startswith("dependency-github-action-")
    }
    for action in action_lock["actions"]:
        slug = action["uses"].split("/", 1)[1]
        identifier = f"dependency-github-action-{slug}"
        action_entries[identifier] = {
            "cleared_files": [],
            "commit": action["commit"],
            "commit_url": f"{action['repository']}/tree/{action['commit']}",
            "copied_files": [],
            "id": identifier,
            "inclusion_state": "dependency_locked",
            "license": {
                "file_url": (
                    f"{action['repository']}/blob/{action['commit']}/"
                    f"{action['license']['path']}"
                ),
                "sha256": action["license"]["sha256"],
                "spdx": action["license"]["spdx"],
                "status": "verified_license_bytes_at_pinned_commit",
            },
            "planned_use": (
                f"Execute the official {action['uses']} workflow action only "
                "at its immutable full commit SHA."
            ),
            "repository_url": action["repository"],
            "review": {
                "action_lock": "GITHUB_ACTIONS_LOCK.json",
                "mutable_tag_used": False,
                "status": "official_action_full_sha_pinned",
                "unreviewed_files_cleared": False,
            },
            "source_family": "official GitHub workflow action",
            "stack_lock_id": None,
            "version": action["tag"],
        }
    provenance["entries"] = [
        item
        for item in provenance["entries"]
        if not (
            isinstance(item, dict)
            and str(item.get("id", "")).startswith(
                "dependency-github-action-"
            )
        )
    ] + [
        action_entries[key] for key in sorted(action_entries)
    ]
    provenance["entries"].sort(key=lambda item: item["id"])
    target = next(
        item
        for item in provenance["entries"]
        if item.get("id") == "target-rapp-stack-cubby"
    )
    target["license"] = {
        "copyright": "Copyright (c) 2026 Kody Wildfeuer",
        "file": "LICENSE",
        "spdx": "MIT",
        "status": "declared_for_newly_authored_code",
    }

    original_paths = {
        item["path"] for item in target["original_files"]
    } - {
        "docs/decisions/explicit-copilot-token-file.md",
        "docs/operations/PROVIDER_AUTH.md",
        "tests/runtime/test_github_auth.py",
    } | {
        "src/rapp_stack_cubby/command_manifest.py",
        "src/rapp_stack_cubby/demo.py",
        "src/rapp_stack_cubby/doctor.py",
        "src/rapp_stack_cubby/runtime/github_auth.py",
    }
    target["original_files"] = [
        record(path) for path in sorted(original_paths)
    ]

    context_paths = sorted(
        {
            "AI_CONTEXT.md",
            "CONTEXT_INDEX.json",
            "scripts/context-check.sh",
            "src/rapp_stack_cubby/context.py",
            "tests/test_context.py",
            *(f"schemas/{name}" for name in SCHEMAS),
        }
    )
    target["context_closure_files"] = [
        record(path, generated=path == "CONTEXT_INDEX.json")
        for path in context_paths
    ]

    imessage_paths = {
        item["path"] for item in target.get("imessage_original_files", [])
    } | {
        "docs/canon/IMPLEMENTATION_STATUS.md",
        "docs/canon/MESSAGING_IMESSAGE.md",
        "docs/decisions/owner-only-imessage-v1.md",
        "docs/operations/INCIDENT_RESPONSE.md",
        "tests/fixtures/imsg-v0.12.3-chat-catalog.json",
        "tests/fixtures/imsg-v0.12.3-message-notification.json",
        "tests/fixtures/imsg-v0.12.3-rpc-chats-list.json",
        "tests/fixtures/imsg-v0.12.3-send-ok-no-guid.json",
    }
    target["imessage_original_files"] = [
        record(path) for path in sorted(imessage_paths)
    ]

    packaging_paths = {
        item["path"] for item in target.get("packaging_files", [])
    } | {
        "COMMAND_MANIFEST.json",
        "PUBLICATION_SCAN_POLICY.json",
        "schemas/command-manifest.schema.json",
        "schemas/demo-receipt.schema.json",
        "schemas/installed-offline-attestation.schema.json",
        "schemas/publication-scan-policy.schema.json",
        "schemas/publication-scan-receipt.schema.json",
        "schemas/publication-scan-signature.schema.json",
        "schemas/evidence-signature.schema.json",
        "schemas/live-proof.schema.json",
        "schemas/promotion-receipt.schema.json",
        "schemas/publication-attestation-result.schema.json",
        "schemas/rollback-receipt.schema.json",
        "scripts/attest-installed-offline.sh",
        "scripts/bootstrap-development.sh",
        "scripts/demo-product.sh",
        "scripts/regenerate-provenance-locks.py",
        "scripts/rollback-product.sh",
        "scripts/configure-repository.sh",
        "scripts/promote-release.sh",
        "scripts/scan-publication.sh",
        "scripts/verify-publication-scan.sh",
        "src/rapp_stack_cubby/command_manifest.py",
        "src/rapp_stack_cubby/demo.py",
        "src/rapp_stack_cubby/doctor.py",
        "src/rapp_stack_cubby/packaging/publication.py",
        "src/rapp_stack_cubby/promotion.py",
        "tests/controller/test_attestation.py",
        "tests/packaging/test_publication_scan.py",
        "tests/packaging/test_promotion.py",
        "tests/packaging/test_repository_settings.py",
        "tests/packaging/test_rollback_script.py",
        "tests/test_doctor_demo.py",
    }
    target["packaging_files"] = [
        record(path, generated=path == "COMMAND_MANIFEST.json")
        for path in sorted(packaging_paths)
    ]

    pages_paths = {
        item["path"] for item in target.get("pages_files", [])
    } - {
        "LIVE_PROVIDER_STATUS.json",
    } | {
        ".github/workflows/promote.yml",
        "scripts/configure-repository.sh",
        "scripts/promote-release.sh",
        "src/rapp_stack_cubby/promotion.py",
    }
    generated_pages = {
        "docs/pages-manifest.json",
        *(f"docs/api/v1/{name}" for name in (
            "architecture.json",
            "capabilities.json",
            "context.json",
            "downloads.json",
            "prompts.json",
            "status.json",
        )),
    }
    target["pages_files"] = [
        record(path, generated=path in generated_pages)
        for path in sorted(pages_paths)
    ]

    def refresh(value: object) -> None:
        if isinstance(value, dict):
            path = value.get("path")
            if (
                isinstance(path, str)
                and "sha256" in value
                and (ROOT / path).is_file()
            ):
                value["sha256"] = digest(path)
            for child in value.values():
                refresh(child)
        elif isinstance(value, list):
            for child in value:
                refresh(child)

    refresh(target)
    refresh(provenance.get("evidence_inputs"))
    refresh(lock.get("evidence_inputs"))
    for name in (
        "original_files",
        "authored_agent_files",
        "agent_closure_support_files",
        "context_closure_files",
        "controller_support_files",
        "generated_catalog_files",
        "imessage_original_files",
        "packaging_files",
        "pages_files",
    ):
        if isinstance(target.get(name), list):
            target[name].sort(key=lambda item: item["path"])

    target["original_manifest_sha256"] = manifest_digest(
        target["original_files"]
    )
    target["authored_agent_manifest_sha256"] = manifest_digest(
        target["authored_agent_files"]
    )
    target["agent_closure_support_manifest_sha256"] = manifest_digest(
        target["agent_closure_support_files"]
    )
    target["context_closure_manifest_sha256"] = manifest_digest(
        target["context_closure_files"]
    )
    target["pages_manifest_sha256"] = manifest_digest(
        target["pages_files"]
    )
    controller_material = {
        "catalog": target["controller_catalog"],
        "receipt_template": target["controller_receipt_template"],
        "source": target["controller_source"],
        "support_files": target["controller_support_files"],
    }
    target["controller_manifest_sha256"] = hashlib.sha256(
        json.dumps(
            controller_material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()

    build = lock["build_policy"]
    build["original_runtime_manifest"]["files"] = target["original_files"]
    build["original_runtime_manifest"]["manifest_sha256"] = target[
        "original_manifest_sha256"
    ]
    actual = build["actual_agent_manifest"]
    actual["files"] = target["authored_agent_files"]
    actual["manifest_sha256"] = target["authored_agent_manifest_sha256"]
    actual["support_files"] = target["agent_closure_support_files"]
    actual["support_manifest_sha256"] = target[
        "agent_closure_support_manifest_sha256"
    ]
    by_catalog = {
        item["path"]: item for item in target["generated_catalog_files"]
    }
    actual["agent_catalog"] = by_catalog[
        "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/agent-catalog.json"
    ]
    actual["implementation_matrix"] = by_catalog[
        "cubbies/kody-w/rapplications/rapp-stack/twin/catalog/implementation-matrix.json"
    ]
    actual["soul"] = target["twin_soul"]
    build["controller_manifest"] = {
        **controller_material,
        "manifest_sha256": target["controller_manifest_sha256"],
    }
    context_by_path = {
        item["path"]: item for item in target["context_closure_files"]
    }
    build["context_manifest"] = {
        "context_index": context_by_path["CONTEXT_INDEX.json"],
        "context_schema": context_by_path[
            "schemas/context-index.schema.json"
        ],
        "files": target["context_closure_files"],
        "manifest_sha256": target["context_closure_manifest_sha256"],
    }
    build["pages_manifest"] = {
        "files": target["pages_files"],
        "manifest_sha256": target["pages_manifest_sha256"],
        "release_status": "pending",
        "site_url": "https://kody-w.github.io/rapp-stack-cubby/",
    }
    scanner_paths = (
        "PUBLICATION_SCAN_POLICY.json",
        "schemas/publication-scan-policy.schema.json",
        "schemas/publication-scan-receipt.schema.json",
        "schemas/publication-scan-signature.schema.json",
        "scripts/scan-publication.sh",
        "scripts/verify-publication-scan.sh",
        "src/rapp_stack_cubby/packaging/publication.py",
        "tests/packaging/test_publication_scan.py",
    )
    build["publication_scanner"]["files"] = [
        {"path": path, "sha256": digest(path)} for path in scanner_paths
    ]
    build["publication_scanner"]["policy_sha256"] = digest(
        "PUBLICATION_SCAN_POLICY.json"
    )
    github_actions = lock["dependency_policy"]["github_actions"]
    github_actions["action_count"] = len(action_lock["actions"])
    github_actions["actions"] = action_lock["actions"]
    github_actions["lock"] = "GITHUB_ACTIONS_LOCK.json"
    github_actions["mutable_tags_allowed"] = False
    github_actions["runner"] = action_lock["runner"]

    entries = provenance["entries"]
    states = Counter(item["inclusion_state"] for item in entries)
    counts = provenance["counts"]
    counts.update(
        {
            "agent_closure_support_file_count": len(
                target["agent_closure_support_files"]
            ),
            "authored_agent_file_count": len(
                target["authored_agent_files"]
            ),
            "context_closure_file_count": len(
                target["context_closure_files"]
            ),
            "controller_catalog_file_count": 1,
            "controller_source_file_count": 1,
            "controller_support_file_count": len(
                target["controller_support_files"]
            ),
            "controller_template_file_count": 1,
            "entry_count": len(entries),
            "external_source_entries": sum(
                item.get("inclusion_state") != "original_new"
                for item in entries
            ),
            "declared_external_commit_pins": sum(
                isinstance(item.get("commit"), str)
                and len(item["commit"]) == 40
                and all(character in "0123456789abcdef" for character in item["commit"])
                and item.get("inclusion_state") != "original_new"
                for item in entries
            ),
            "verified_external_commit_pins": sum(
                isinstance(item.get("commit"), str)
                and len(item["commit"]) == 40
                and all(character in "0123456789abcdef" for character in item["commit"])
                and item.get("inclusion_state") != "original_new"
                for item in entries
            ),
            "github_action_pin_count": sum(
                str(item.get("id", "")).startswith(
                    "dependency-github-action-"
                )
                for item in entries
            ),
            "generated_catalog_file_count": len(
                target["generated_catalog_files"]
            ),
            "generated_context_file_count": sum(
                item["provenance"] == "generated_local"
                for item in target["context_closure_files"]
            ),
            "inclusion_states": dict(states),
            "original_file_count": len(target["original_files"]),
            "pages_file_count": len(target["pages_files"]),
            "schema_profile_file_count": sum(
                item["path"].startswith("schemas/")
                for item in target["context_closure_files"]
            ),
        }
    )

    lock_path.write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    scan = scan_source_tree(ROOT)
    generated_paths: set[str] = set()

    def collect_generated(value: object) -> None:
        if isinstance(value, dict):
            if (
                value.get("provenance") == "generated_local"
                and isinstance(value.get("path"), str)
            ):
                generated_paths.add(value["path"])
            for child in value.values():
                collect_generated(child)
        elif isinstance(value, list):
            for child in value:
                collect_generated(child)

    collect_generated(target)
    generated_paths.update(
        {
            "LIVE_PROVIDER_STATUS.json",
            "SYSTEM_GRAPH.json",
            "docs/research/AUDIT_MANIFEST.json",
            *(
                f"docs/research/shards/shard-{index}.json"
                for index in range(8)
            ),
            *(
                f"docs/research/raw/shard-{index}.json"
                for index in range(8)
            ),
        }
    )
    external_evidence = {
        "SYSTEM_GRAPH.json",
        "SOURCE_CENSUS.json",
        "docs/research/AUDIT_MANIFEST.json",
        "docs/research/public-account-snapshot.json",
        *(
            f"docs/research/shards/shard-{index}.json"
            for index in range(8)
        ),
    }
    adapted_by_path = {
        item["destination"]: item
        for item in next(
            entry
            for entry in provenance["entries"]
            if entry.get("id") == "adapted-openrappter-imessage"
        )["cleared_files"]
    }
    third_party = {
        "THIRD_PARTY_LICENSES/OpenRappter-MIT.txt": {
            "copyright": "Copyright (c) 2025 Kody W",
            "license_concluded": "MIT",
        },
        "THIRD_PARTY_LICENSES/imsg-MIT.txt": {
            "copyright": "Copyright (c) 2026 Peter Steinberger",
            "license_concluded": "MIT",
        },
    }
    source_records: list[dict[str, object]] = []
    for scanned in scan["files"]:
        path = scanned["path"]
        if path in adapted_by_path:
            adapted = adapted_by_path[path]
            item: dict[str, object] = {
                "license_concluded": "MIT",
                "path": path,
                "provenance": "adapted_source",
                "sha256": scanned["sha256"],
                "source_blob": adapted["source_blob"],
                "source_commit": next(
                    entry["commit"]
                    for entry in provenance["entries"]
                    if entry.get("id") == "adapted-openrappter-imessage"
                ),
            }
        elif path in third_party:
            item = {
                **third_party[path],
                "path": path,
                "provenance": "third_party_license",
                "sha256": scanned["sha256"],
            }
        elif path == "NOTICE":
            item = {
                "path": path,
                "provenance": "mixed_notice",
                "sha256": scanned["sha256"],
            }
        elif path in external_evidence:
            item = {
                "path": path,
                "provenance": "external_evidence",
                "sha256": scanned["sha256"],
            }
        elif path in generated_paths:
            item = {
                "path": path,
                "provenance": "generated_local",
                "sha256": scanned["sha256"],
            }
        else:
            item = {
                "path": path,
                "provenance": "original_new",
                "sha256": (
                    None if path == "PROVENANCE.json" else scanned["sha256"]
                ),
            }
        source_records.append(item)
    target["source_file_provenance"] = {
        "files": source_records,
        "methodology": (
            "Exact source scan cross-bound to original/generated project "
            "records, adapted OpenRappter blobs, local third-party license "
            "copies, and mixed external evidence. Unknown or mixed evidence "
            "never receives an inferred attribution."
        ),
        "schema": "rapp-source-file-provenance/1.0",
    }
    counts["source_file_provenance_count"] = len(source_records)

    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lock_path.write_text(
        json.dumps(lock, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
