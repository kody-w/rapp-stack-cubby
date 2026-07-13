"""Signed external evidence that closes same-commit release promotion."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from .packaging.common import (
    PackagingError,
    atomic_write,
    pretty_json_bytes,
    read_json_object,
)
from .packaging.publication import verify_publication_receipt
from .packaging.release import (
    ALGORITHM,
    P256_ORDER,
    _private_key,
    _public_key,
    load_release_trust,
)

EVIDENCE_SIGNATURE_SCHEMA = "rapp-evidence-signature/1.0"
POSTFLIGHT_SCHEMA = "rapp-release-postflight/1.0"
LIVE_PROOF_SCHEMA = "rapp-live-proof/1.0"
PROMOTION_SCHEMA = "rapp-promotion-receipt/1.0"
PAGES_TARGET = "https://kody-w.github.io/rapp-stack-cubby/"
CORE_RELEASE_ASSETS = (
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
CANDIDATE_SCAN_ASSETS = (
    "candidate-publication-scan.json",
    "candidate-publication-scan.json.sig",
)
POSTFLIGHT_ASSETS = (
    "postflight-success.json",
    "postflight-success.json.sig",
)
PROMOTION_EVIDENCE_ASSETS = (
    "final-publication-scan.json",
    "final-publication-scan.json.sig",
    "live-proof-receipt.json",
    "live-proof-receipt.json.sig",
    "promotion-receipt.json",
    "promotion-receipt.json.sig",
)
CANDIDATE_ASSETS = CORE_RELEASE_ASSETS + CANDIDATE_SCAN_ASSETS
SUCCESSFUL_CANDIDATE_ASSETS = CANDIDATE_ASSETS
FINAL_EVIDENCE_ASSETS = PROMOTION_EVIDENCE_ASSETS
FINAL_RELEASE_ASSETS = CANDIDATE_ASSETS
PROMOTION_BUNDLE_ASSETS = (
    CANDIDATE_SCAN_ASSETS + POSTFLIGHT_ASSETS + PROMOTION_EVIDENCE_ASSETS
)

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_TAG_RE = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$"
)
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class PromotionError(PackagingError):
    """Raised when external promotion evidence is incomplete or untrusted."""


def _canonical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    value = read_json_object(path)
    raw = path.read_bytes()
    if pretty_json_bytes(value) != raw:
        raise PromotionError(f"{path.name} is not canonical JSON")
    return value, raw


def _validate_identity(tag: str, commit: str) -> None:
    if _TAG_RE.fullmatch(tag) is None or _COMMIT_RE.fullmatch(commit) is None:
        raise PromotionError("promotion tag or commit is invalid")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sign_evidence(
    artifact_path: str | Path,
    signature_path: str | Path,
    *,
    key_path: str | Path,
    repository_root: str | Path,
    trust_path: str | Path,
) -> dict[str, Any]:
    """Sign canonical external evidence with the pinned release key."""

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    artifact = Path(artifact_path)
    output = Path(signature_path)
    if not artifact.is_absolute() or not output.is_absolute():
        raise PromotionError("evidence and signature paths must be absolute")
    if output.exists() or output.is_symlink():
        raise PromotionError("evidence signature output already exists")
    _value, content = _canonical_object(artifact)
    trust = load_release_trust(trust_path)
    key = _private_key(Path(key_path), Path(repository_root), trust)
    der = key.sign(content, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = decode_dss_signature(der)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    sidecar = {
        "algorithm": ALGORITHM,
        "artifact": artifact.name,
        "artifact_sha256": hashlib.sha256(content).hexdigest(),
        "key_id": trust["key_id"],
        "schema": EVIDENCE_SIGNATURE_SCHEMA,
        "signature_der_base64": base64.b64encode(
            encode_dss_signature(r, s)
        ).decode("ascii"),
    }
    atomic_write(output, pretty_json_bytes(sidecar), mode=0o644)
    return sidecar


def verify_evidence_signature(
    artifact_path: str | Path,
    signature_path: str | Path,
    *,
    trust_path: str | Path,
) -> dict[str, Any]:
    """Verify an exact canonical evidence file and its pinned low-S signature."""

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )

    artifact = Path(artifact_path)
    signature = Path(signature_path)
    _value, content = _canonical_object(artifact)
    sidecar, sidecar_bytes = _canonical_object(signature)
    del sidecar_bytes
    trust = load_release_trust(trust_path)
    digest = hashlib.sha256(content).hexdigest()
    if (
        set(sidecar)
        != {
            "algorithm",
            "artifact",
            "artifact_sha256",
            "key_id",
            "schema",
            "signature_der_base64",
        }
        or sidecar.get("schema") != EVIDENCE_SIGNATURE_SCHEMA
        or sidecar.get("algorithm") != ALGORITHM
        or sidecar.get("artifact") != artifact.name
        or sidecar.get("artifact_sha256") != digest
        or sidecar.get("key_id") != trust["key_id"]
    ):
        raise PromotionError("evidence signature binding is invalid")
    try:
        der = base64.b64decode(
            sidecar["signature_der_base64"], validate=True
        )
        r, s = decode_dss_signature(der)
    except (binascii.Error, TypeError, ValueError) as error:
        raise PromotionError("evidence signature encoding is invalid") from error
    if (
        not 1 <= r < P256_ORDER
        or not 1 <= s <= P256_ORDER // 2
        or encode_dss_signature(r, s) != der
    ):
        raise PromotionError("evidence signature is not canonical low-S")
    try:
        _public_key(trust).verify(der, content, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as error:
        raise PromotionError("evidence signature verification failed") from error
    return {
        "artifact_sha256": digest,
        "key_id": trust["key_id"],
        "signed": True,
        "verified": True,
    }


def verify_postflight_receipt(
    receipt_path: str | Path,
    signature_path: str | Path,
    *,
    trust_path: str | Path,
    expected_tag: str,
    expected_commit: str,
    expected_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify the successful candidate public-byte postflight receipt."""

    _validate_identity(expected_tag, expected_commit)
    receipt = Path(receipt_path)
    signed = verify_evidence_signature(
        receipt, signature_path, trust_path=trust_path
    )
    value, _raw = _canonical_object(receipt)
    inventory = value.get("remote_inventory")
    if (
        set(value)
        != {
            "asset_count",
            "bytes_equal",
            "candidate_publication_scan_sha256",
            "draft",
            "failed_postflight",
            "github_attestations_verified",
            "immutable",
            "prerelease",
            "release_manifest_sha256",
            "remote_inventory",
            "remote_inventory_sha256",
            "schema",
            "source_commit",
            "tag",
            "verified",
        }
        or value.get("schema") != POSTFLIGHT_SCHEMA
        or value.get("tag") != expected_tag
        or value.get("source_commit") != expected_commit
        or value.get("asset_count") != len(CANDIDATE_ASSETS)
        or value.get("bytes_equal") is not True
        or value.get("github_attestations_verified") is not True
        or value.get("immutable") is not True
        or value.get("draft") is not False
        or value.get("prerelease") is not True
        or value.get("failed_postflight") is not False
        or value.get("verified") is not True
        or not isinstance(inventory, list)
        or inventory != sorted(CANDIDATE_ASSETS)
        or not isinstance(value.get("candidate_publication_scan_sha256"), str)
        or _DIGEST_RE.fullmatch(value["candidate_publication_scan_sha256"])
        is None
        or not isinstance(value.get("release_manifest_sha256"), str)
        or _DIGEST_RE.fullmatch(value["release_manifest_sha256"]) is None
        or value.get("remote_inventory_sha256")
        != hashlib.sha256(
            pretty_json_bytes(sorted(CANDIDATE_ASSETS))
        ).hexdigest()
    ):
        raise PromotionError("postflight receipt is not successful candidate proof")
    if (
        expected_manifest_sha256 is not None
        and value["release_manifest_sha256"] != expected_manifest_sha256
    ):
        raise PromotionError("postflight release manifest digest changed")
    return {**signed, "value": value}


def verify_live_proof_receipt(
    receipt_path: str | Path,
    signature_path: str | Path,
    *,
    trust_path: str | Path,
    expected_tag: str,
    expected_commit: str,
    expected_sha256: str | None = None,
) -> dict[str, Any]:
    """Verify sanitized live host/iMessage proof without accepting private data."""

    _validate_identity(expected_tag, expected_commit)
    receipt = Path(receipt_path)
    signed = verify_evidence_signature(
        receipt, signature_path, trust_path=trust_path
    )
    value, raw = _canonical_object(receipt)
    checks = value.get("checks")
    forbidden = re.compile(
        rb"(?:/(?:Users|home)/|iMessage;[-+];|"
        rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|"
        rb"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
    )
    if (
        set(value)
        != {
            "checks",
            "instance_identity_sha256",
            "pages_target",
            "private_values_published",
            "release_manifest_sha256",
            "schema",
            "source_commit",
            "tag",
            "timestamp",
            "verified",
        }
        or value.get("schema") != LIVE_PROOF_SCHEMA
        or value.get("tag") != expected_tag
        or value.get("source_commit") != expected_commit
        or value.get("pages_target") != PAGES_TARGET
        or value.get("private_values_published") is not False
        or value.get("verified") is not True
        or not isinstance(value.get("instance_identity_sha256"), str)
        or _DIGEST_RE.fullmatch(value["instance_identity_sha256"]) is None
        or not isinstance(value.get("release_manifest_sha256"), str)
        or _DIGEST_RE.fullmatch(value["release_manifest_sha256"]) is None
        or not isinstance(value.get("timestamp"), str)
        or _TIMESTAMP_RE.fullmatch(value["timestamp"]) is None
        or not isinstance(checks, dict)
        or set(checks)
        != {
            "full_disk_access",
            "imessage_owner_round_trip",
            "outgoing_guid_confirmed",
            "provider_preflight",
            "restart",
            "signed_twin_chat",
            "sleep_wake",
        }
        or any(result is not True for result in checks.values())
        or forbidden.search(raw) is not None
    ):
        raise PromotionError("live proof is invalid or contains private material")
    if expected_sha256 is not None and signed["artifact_sha256"] != expected_sha256:
        raise PromotionError("live proof digest does not match protected input")
    return {**signed, "value": value}


def verify_promotion_bundle(
    evidence_directory: str | Path,
    *,
    policy_path: str | Path,
    trust_path: str | Path,
    expected_tag: str,
    expected_commit: str,
    expected_live_proof_sha256: str | None = None,
    require_exact_directory: bool = True,
) -> dict[str, Any]:
    """Verify every signed receipt that externally closes final promotion."""

    _validate_identity(expected_tag, expected_commit)
    directory = Path(evidence_directory).resolve(strict=True)
    expected = set(PROMOTION_BUNDLE_ASSETS)
    observed = {item.name for item in directory.iterdir()}
    if (
        (require_exact_directory and observed != expected)
        or (not require_exact_directory and not expected.issubset(observed))
        or any(
        not (directory / name).is_file() or (directory / name).is_symlink()
        for name in expected
        )
    ):
        raise PromotionError("promotion evidence directory is not the exact set")
    candidate = verify_publication_receipt(
        directory / "candidate-publication-scan.json",
        policy_path=policy_path,
        required_phase="candidate",
        signature_path=directory / "candidate-publication-scan.json.sig",
        trust_path=trust_path,
        expected_source_commit=expected_commit,
    )
    postflight = verify_postflight_receipt(
        directory / "postflight-success.json",
        directory / "postflight-success.json.sig",
        trust_path=trust_path,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
    )
    live = verify_live_proof_receipt(
        directory / "live-proof-receipt.json",
        directory / "live-proof-receipt.json.sig",
        trust_path=trust_path,
        expected_tag=expected_tag,
        expected_commit=expected_commit,
        expected_sha256=expected_live_proof_sha256,
    )
    final = verify_publication_receipt(
        directory / "final-publication-scan.json",
        policy_path=policy_path,
        required_phase="final",
        signature_path=directory / "final-publication-scan.json.sig",
        trust_path=trust_path,
        expected_source_commit=expected_commit,
    )
    promotion_path = directory / "promotion-receipt.json"
    promotion_signed = verify_evidence_signature(
        promotion_path,
        directory / "promotion-receipt.json.sig",
        trust_path=trust_path,
    )
    promotion, _raw = _canonical_object(promotion_path)
    actions = promotion.get("actions_logs")
    if (
        set(promotion)
        != {
            "actions_logs",
            "candidate_publication_scan_sha256",
            "final_publication_scan_sha256",
            "live_proof_sha256",
            "new_source_commit",
            "pages_target",
            "postflight_success_sha256",
            "promoted",
            "release_assets_rebuilt",
            "release_manifest_sha256",
            "schema",
            "source_commit",
            "tag",
            "timestamp",
        }
        or promotion.get("schema") != PROMOTION_SCHEMA
        or promotion.get("tag") != expected_tag
        or promotion.get("source_commit") != expected_commit
        or promotion.get("pages_target") != PAGES_TARGET
        or promotion.get("promoted") is not True
        or promotion.get("new_source_commit") is not False
        or promotion.get("release_assets_rebuilt") is not False
        or not isinstance(promotion.get("timestamp"), str)
        or _TIMESTAMP_RE.fullmatch(promotion["timestamp"]) is None
        or promotion.get("candidate_publication_scan_sha256")
        != _digest(directory / "candidate-publication-scan.json")
        or promotion.get("postflight_success_sha256")
        != _digest(directory / "postflight-success.json")
        or promotion.get("live_proof_sha256")
        != _digest(directory / "live-proof-receipt.json")
        or promotion.get("final_publication_scan_sha256")
        != _digest(directory / "final-publication-scan.json")
        or promotion.get("release_manifest_sha256")
        != postflight["value"]["release_manifest_sha256"]
        or promotion.get("release_manifest_sha256")
        != live["value"]["release_manifest_sha256"]
        or not isinstance(actions, list)
        or not actions
        or any(
            not isinstance(item, dict)
            or set(item) != {"run_id", "sha256", "size"}
            or not isinstance(item.get("run_id"), str)
            or not item["run_id"].isdigit()
            or not isinstance(item.get("sha256"), str)
            or _DIGEST_RE.fullmatch(item["sha256"]) is None
            or not isinstance(item.get("size"), int)
            or isinstance(item["size"], bool)
            or item["size"] <= 0
            for item in actions
        )
    ):
        raise PromotionError("promotion receipt does not bind the evidence chain")
    final_actions = final.get("actions_evidence")
    if actions != final_actions:
        raise PromotionError("promotion Actions logs do not match final scan")
    return {
        "candidate_scan": candidate,
        "final_scan": final,
        "key_id": promotion_signed["key_id"],
        "live_proof_sha256": live["artifact_sha256"],
        "promotion_receipt_sha256": promotion_signed["artifact_sha256"],
        "release_manifest_sha256": promotion["release_manifest_sha256"],
        "source_commit": expected_commit,
        "tag": expected_tag,
        "verified": True,
    }


def verify_publication_attestation(
    result_path: str | Path,
    release_directory: str | Path,
    *,
    expected_commit: str,
    profile: str,
) -> dict[str, Any]:
    """Verify sanitized gh evidence for every profile-specific public asset."""

    profiles = {
        "candidate": CANDIDATE_ASSETS,
        "candidate-success": SUCCESSFUL_CANDIDATE_ASSETS,
        "final": FINAL_RELEASE_ASSETS,
        "postflight": POSTFLIGHT_ASSETS,
        "promotion": PROMOTION_EVIDENCE_ASSETS,
    }
    if profile not in profiles or _COMMIT_RE.fullmatch(expected_commit) is None:
        raise PromotionError("publication attestation profile is invalid")
    directory = Path(release_directory).resolve(strict=True)
    value, _raw = _canonical_object(Path(result_path))
    expected_subjects = []
    for name in profiles[profile]:
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise PromotionError("attested publication asset is unavailable")
        expected_subjects.append(
            {
                "name": name,
                "sha256": _digest(path),
                "signer_workflow": (
                    "kody-w/rapp-stack-cubby/.github/workflows/promote.yml"
                    if name in PROMOTION_EVIDENCE_ASSETS
                    else "kody-w/rapp-stack-cubby/.github/workflows/release.yml"
                ),
            }
        )
    expected_subjects.sort(key=lambda item: item["name"])
    if (
        set(value)
        != {
            "command_profile",
            "predicate_type",
            "profile",
            "repository",
            "schema",
            "source_commit",
            "subjects",
            "verified",
        }
        or value.get("schema")
        != "rapp-publication-attestation-verification/1.0"
        or value.get("command_profile") != "gh-attestation-verify/1.0"
        or value.get("predicate_type") != "https://slsa.dev/provenance/v1"
        or value.get("repository") != "kody-w/rapp-stack-cubby"
        or value.get("profile") != profile
        or value.get("source_commit") != expected_commit
        or value.get("subjects") != expected_subjects
        or value.get("verified") is not True
    ):
        raise PromotionError("publication attestations do not bind the release")
    return {
        "profile": profile,
        "result_sha256": _digest(Path(result_path)),
        "source_commit": expected_commit,
        "subject_count": len(expected_subjects),
        "verified": True,
    }


def write_promotion_receipt(
    output_path: str | Path,
    *,
    tag: str,
    commit: str,
    manifest_sha256: str,
    evidence_directory: str | Path,
    actions_evidence: Sequence[Mapping[str, Any]],
    timestamp: str,
) -> None:
    """Write the canonical unsigned promotion receipt for protected signing."""

    _validate_identity(tag, commit)
    if _DIGEST_RE.fullmatch(manifest_sha256) is None:
        raise PromotionError("promotion manifest digest is invalid")
    if _TIMESTAMP_RE.fullmatch(timestamp) is None:
        raise PromotionError("promotion timestamp is invalid")
    evidence = Path(evidence_directory)
    value = {
        "actions_logs": [dict(item) for item in actions_evidence],
        "candidate_publication_scan_sha256": _digest(
            evidence / "candidate-publication-scan.json"
        ),
        "final_publication_scan_sha256": _digest(
            evidence / "final-publication-scan.json"
        ),
        "live_proof_sha256": _digest(evidence / "live-proof-receipt.json"),
        "new_source_commit": False,
        "pages_target": PAGES_TARGET,
        "postflight_success_sha256": _digest(
            evidence / "postflight-success.json"
        ),
        "promoted": True,
        "release_assets_rebuilt": False,
        "release_manifest_sha256": manifest_sha256,
        "schema": PROMOTION_SCHEMA,
        "source_commit": commit,
        "tag": tag,
        "timestamp": timestamp,
    }
    output = Path(output_path)
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise PromotionError("promotion receipt output must be fresh and absolute")
    atomic_write(output, pretty_json_bytes(value), mode=0o644)
