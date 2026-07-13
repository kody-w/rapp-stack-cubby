#!/usr/bin/env python3
"""Create a sanitized verifier result only from successful gh JSON evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

CORE_ASSETS = (
    "SBOM.spdx.json",
    "SHA256SUMS",
    "rapp-stack-cubby-store.zip",
    "rapp-stack-cubby.egg",
    "rapp-super-rar.json",
    "release-manifest.json",
    "release-manifest.json.sig",
    "release-provenance.json",
    "store-index.json",
)
REPOSITORY = "kody-w/rapp-stack-cubby"
RELEASE_WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"
PROMOTION_WORKFLOW = f"{REPOSITORY}/.github/workflows/promote.yml"
CANDIDATE_SCAN_ASSETS = (
    "candidate-publication-scan.json",
    "candidate-publication-scan.json.sig",
)
POSTFLIGHT_ASSETS = (
    "postflight-success.json",
    "postflight-success.json.sig",
)
FINAL_ASSETS = (
    "final-publication-scan.json",
    "final-publication-scan.json.sig",
    "live-proof-receipt.json",
    "live-proof-receipt.json.sig",
    "promotion-receipt.json",
    "promotion-receipt.json.sig",
)
PROFILES = {
    "core": CORE_ASSETS,
    "candidate": CORE_ASSETS + CANDIDATE_SCAN_ASSETS,
    "candidate-success": CORE_ASSETS + CANDIDATE_SCAN_ASSETS + POSTFLIGHT_ASSETS,
    "final": CORE_ASSETS + CANDIDATE_SCAN_ASSETS,
    "promotion": FINAL_ASSETS,
    "postflight": POSTFLIGHT_ASSETS,
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def evidence_binds(value: object, name: str, sha256: str) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        if not isinstance(item, dict):
            continue
        result = item.get("verificationResult")
        statement = result.get("statement") if isinstance(result, dict) else None
        subjects = statement.get("subject") if isinstance(statement, dict) else None
        if not isinstance(subjects, list):
            continue
        for subject in subjects:
            if not isinstance(subject, dict):
                continue
            subject_name = subject.get("name")
            digests = subject.get("digest")
            if (
                isinstance(subject_name, str)
                and PurePosixPath(subject_name).name == name
                and isinstance(digests, dict)
                and digests.get("sha256") == sha256
            ):
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--profile",
        choices=tuple(PROFILES),
        default="core",
    )
    arguments = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", arguments.source_commit) is None:
        raise SystemExit("error: source commit must be exact lowercase hex")
    release_dir = arguments.release_dir.resolve(strict=True)
    evidence_dir = arguments.evidence_dir.resolve(strict=True)
    output = arguments.output.resolve(strict=False)
    if output.exists() or output.is_symlink():
        raise SystemExit("error: attestation result output must be absent")
    assets = PROFILES[arguments.profile]
    observed = {item.name for item in release_dir.iterdir()}
    if observed != set(assets):
        raise SystemExit("error: release directory is not the exact public asset set")
    subjects = []
    for name in assets:
        path = release_dir / name
        if not path.is_file() or path.is_symlink():
            raise SystemExit(f"error: release asset is not a regular file: {name}")
        sha256 = digest(path)
        evidence_path = evidence_dir / f"{name}.json"
        try:
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SystemExit(f"error: invalid gh evidence for {name}") from error
        if not evidence_binds(evidence, name, sha256):
            raise SystemExit(f"error: gh evidence does not bind {name}")
        signer = (
            PROMOTION_WORKFLOW if name in FINAL_ASSETS else RELEASE_WORKFLOW
        )
        subjects.append(
            {"name": name, "sha256": sha256, "signer_workflow": signer}
        )
    if arguments.profile == "core":
        result = {
            "command_profile": "gh-attestation-verify/1.0",
            "predicate_type": "https://slsa.dev/provenance/v1",
            "repository": REPOSITORY,
            "schema": "rapp-github-attestation-verification/1.0",
            "signer_workflow": RELEASE_WORKFLOW,
            "source_commit": arguments.source_commit,
            "subjects": [
                {"name": item["name"], "sha256": item["sha256"]}
                for item in sorted(subjects, key=lambda item: item["name"])
            ],
            "verified": True,
        }
    else:
        result = {
            "command_profile": "gh-attestation-verify/1.0",
            "predicate_type": "https://slsa.dev/provenance/v1",
            "profile": arguments.profile,
            "repository": REPOSITORY,
            "schema": "rapp-publication-attestation-verification/1.0",
            "source_commit": arguments.source_commit,
            "subjects": sorted(subjects, key=lambda item: item["name"]),
            "verified": True,
        }
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    with output.open("xb") as destination:
        destination.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
