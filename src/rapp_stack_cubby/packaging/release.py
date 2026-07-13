"""Pinned release trust, canonical detached signatures, and release verification."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from pathlib import Path
from collections.abc import Sequence
from typing import Any

from .common import (
    COMMIT_RE,
    SHA256_RE,
    PackagingError,
    canonical_json_bytes,
    pretty_json_bytes,
    read_json_object,
    sha256_file,
    validate_relative_path,
)
from .immutable import (
    prepare_committed_source_material,
    prepare_source_material,
    recheck_committed_source_material,
    recheck_source_material,
)
from .source import validate_source_manifest

TRUST_SCHEMA = "rapp-release-trust/1.0"
SIGNATURE_SCHEMA = "rapp-detached-signature/1.0"
ATTESTATION_SCHEMA = "rapp-github-attestation-verification/1.0"
ALGORITHM = "ecdsa-p256-sha256"
RELEASE_MANIFEST_NAME = "release-manifest.json"
RELEASE_SIGNATURE_NAME = "release-manifest.json.sig"
CHECKSUMS_NAME = "SHA256SUMS"
P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_VERIFICATION_TOKEN = object()


class ReleaseVerification(dict):
    """Capability returned only after pinned release verification succeeds."""

    def __init__(self, value: dict, token: object) -> None:
        if token is not _VERIFICATION_TOKEN:
            raise TypeError("ReleaseVerification cannot be constructed directly")
        super().__init__(value)


def _b64url_decode(value: object, expected: int) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise PackagingError("release trust JWK encoding is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as error:
        raise PackagingError("release trust JWK encoding is invalid") from error
    if len(decoded) != expected:
        raise PackagingError("release trust JWK coordinate is invalid")
    return decoded


def _jwk_key_id(jwk: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(jwk)).hexdigest()


def load_release_trust(path: str | Path) -> dict:
    """Load the sole checked-in public release trust anchor."""

    trust = read_json_object(Path(path))
    if set(trust) != {
        "algorithm",
        "generation",
        "key_id",
        "profile",
        "public_jwk",
        "schema",
    }:
        raise PackagingError("release trust fields are invalid")
    jwk = trust.get("public_jwk")
    if (
        trust.get("schema") != TRUST_SCHEMA
        or trust.get("profile") != TRUST_SCHEMA
        or trust.get("algorithm") != ALGORITHM
        or not isinstance(trust.get("generation"), str)
        or not isinstance(jwk, dict)
        or set(jwk) != {"crv", "kty", "x", "y"}
        or jwk.get("crv") != "P-256"
        or jwk.get("kty") != "EC"
        or not isinstance(trust.get("key_id"), str)
        or _KEY_ID_RE.fullmatch(trust["key_id"]) is None
        or trust["key_id"] != _jwk_key_id(jwk)
    ):
        raise PackagingError("release trust anchor is invalid")
    _b64url_decode(jwk["x"], 32)
    _b64url_decode(jwk["y"], 32)
    return trust


def _public_key(trust: dict):
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as error:
        raise PackagingError("release verification requires cryptography") from error
    jwk = trust["public_jwk"]
    try:
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(_b64url_decode(jwk["x"], 32), "big"),
            int.from_bytes(_b64url_decode(jwk["y"], 32), "big"),
            ec.SECP256R1(),
        )
        return numbers.public_key()
    except ValueError as error:
        raise PackagingError("release trust point is not on P-256") from error


def _private_key(
    key_path: Path,
    repository_root: Path,
    trust: dict,
):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as error:
        raise PackagingError("release signing requires cryptography") from error
    if not key_path.is_absolute():
        raise PackagingError("release signing key must be an explicit absolute path")
    resolved = key_path.expanduser().resolve(strict=False)
    repository = repository_root.resolve()
    if resolved == repository or repository in resolved.parents:
        raise PackagingError("release signing key cannot be under the repository")
    try:
        info = resolved.lstat()
    except OSError as error:
        raise PackagingError("release signing key is unavailable") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise PackagingError("release signing key must be a mode-0600 regular file")
    try:
        key = serialization.load_pem_private_key(
            resolved.read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as error:
        raise PackagingError("cannot load release signing key") from error
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        raise PackagingError("release signing key must be P-256")
    numbers = key.public_key().public_numbers()
    encoded = lambda value: base64.urlsafe_b64encode(
        value.to_bytes(32, "big")
    ).rstrip(b"=").decode("ascii")
    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": encoded(numbers.x),
        "y": encoded(numbers.y),
    }
    if _jwk_key_id(jwk) != trust["key_id"] or jwk != trust["public_jwk"]:
        raise PackagingError("release signing key does not match pinned trust")
    return key


def sign_release_manifest(
    manifest_path: str | Path,
    signature_path: str | Path,
    *,
    key_path: str | Path,
    repository_root: str | Path,
    trust_path: str | Path,
) -> dict:
    """Write one deterministic low-S signature without embedding a JWK."""

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError as error:
        raise PackagingError("release signing requires cryptography") from error
    manifest = Path(manifest_path)
    output = Path(signature_path)
    if output.exists() or output.is_symlink():
        raise PackagingError("release signature output already exists")
    trust = load_release_trust(trust_path)
    key = _private_key(Path(key_path), Path(repository_root), trust)
    try:
        content = manifest.read_bytes()
    except OSError as error:
        raise PackagingError("release manifest is unavailable") from error
    digest = hashlib.sha256(content).hexdigest()
    signature = key.sign(
        content,
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
    )
    r, s = decode_dss_signature(signature)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    signature = encode_dss_signature(r, s)
    sidecar = {
        "algorithm": ALGORITHM,
        "artifact": RELEASE_MANIFEST_NAME,
        "artifact_sha256": digest,
        "key_id": trust["key_id"],
        "schema": SIGNATURE_SCHEMA,
        "signature_der_base64": base64.b64encode(signature).decode("ascii"),
    }
    from .common import atomic_write

    atomic_write(output, pretty_json_bytes(sidecar))
    return sidecar


def _parse_signature(path: Path, manifest_digest: str) -> tuple[dict, bytes]:
    sidecar = read_json_object(path)
    if set(sidecar) != {
        "algorithm",
        "artifact",
        "artifact_sha256",
        "key_id",
        "schema",
        "signature_der_base64",
    }:
        raise PackagingError("release signature fields are invalid")
    if (
        sidecar.get("schema") != SIGNATURE_SCHEMA
        or sidecar.get("algorithm") != ALGORITHM
        or sidecar.get("artifact") != RELEASE_MANIFEST_NAME
        or sidecar.get("artifact_sha256") != manifest_digest
        or not isinstance(sidecar.get("key_id"), str)
    ):
        raise PackagingError("release signature binding is invalid")
    try:
        signature = base64.b64decode(
            sidecar["signature_der_base64"], validate=True
        )
    except (ValueError, TypeError) as error:
        raise PackagingError("release signature encoding is invalid") from error
    return sidecar, signature


def _verify_signature(
    manifest_bytes: bytes,
    signature_path: Path,
    trust: dict,
) -> None:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
            encode_dss_signature,
        )
    except ImportError as error:
        raise PackagingError("release verification requires cryptography") from error
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    sidecar, signature = _parse_signature(signature_path, digest)
    if sidecar["key_id"] != trust["key_id"]:
        raise PackagingError("release signature key is not pinned")
    try:
        r, s = decode_dss_signature(signature)
    except ValueError as error:
        raise PackagingError("release signature DER is invalid") from error
    if (
        r <= 0
        or r >= P256_ORDER
        or s <= 0
        or s > P256_ORDER // 2
        or encode_dss_signature(r, s) != signature
    ):
        raise PackagingError("release signature is non-canonical or high-S")
    try:
        _public_key(trust).verify(
            signature,
            manifest_bytes,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as error:
        raise PackagingError("release signature verification failed") from error


def _release_artifacts(manifest: dict) -> list[dict]:
    values = manifest.get("artifacts")
    if not isinstance(values, list) or not values:
        raise PackagingError("release manifest artifact list is invalid")
    normalized: list[dict] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, dict) or set(raw) != {
            "filename",
            "kind",
            "sha256",
            "size",
        }:
            raise PackagingError("release artifact record is invalid")
        filename = validate_relative_path(raw["filename"])
        if "/" in filename or filename in seen:
            raise PackagingError("release artifact filename is invalid")
        if (
            not isinstance(raw.get("kind"), str)
            or not raw["kind"]
            or not isinstance(raw.get("sha256"), str)
            or SHA256_RE.fullmatch(raw["sha256"]) is None
            or not isinstance(raw.get("size"), int)
            or isinstance(raw["size"], bool)
            or raw["size"] < 0
        ):
            raise PackagingError("release artifact identity is invalid")
        seen.add(filename)
        normalized.append(dict(raw))
    ordered = sorted(normalized, key=lambda item: item["filename"].encode("utf-8"))
    if normalized != ordered:
        raise PackagingError("release artifact records are not canonical")
    return ordered


def _verify_checksums(
    directory: Path,
    artifacts: list[dict],
    manifest_digest: str,
    signature_digest: str | None,
) -> None:
    expected = {
        item["filename"]: item["sha256"] for item in artifacts
    }
    expected[RELEASE_MANIFEST_NAME] = manifest_digest
    if signature_digest is not None:
        expected[RELEASE_SIGNATURE_NAME] = signature_digest
    canonical = "".join(
        f"{expected[name]}  {name}\n"
        for name in sorted(expected, key=lambda value: value.encode("utf-8"))
    ).encode("ascii")
    try:
        observed = (directory / CHECKSUMS_NAME).read_bytes()
    except OSError as error:
        raise PackagingError("release checksums are unavailable") from error
    if observed != canonical:
        raise PackagingError("SHA256SUMS is not the exact canonical asset set")


def _verify_attestation(
    path: Path,
    manifest: dict,
    artifacts: list[dict],
    *,
    manifest_digest: str,
    signature_digest: str,
    checksums_digest: str,
) -> str:
    value = read_json_object(path)
    subjects = value.get("subjects")
    expected = [
        {"name": item["filename"], "sha256": item["sha256"]}
        for item in artifacts
    ]
    expected.extend(
        (
            {"name": CHECKSUMS_NAME, "sha256": checksums_digest},
            {"name": RELEASE_MANIFEST_NAME, "sha256": manifest_digest},
            {"name": RELEASE_SIGNATURE_NAME, "sha256": signature_digest},
        )
    )
    expected.sort(key=lambda item: item["name"])
    if not isinstance(subjects, list) or any(
        not isinstance(item, dict)
        or set(item) != {"name", "sha256"}
        for item in subjects
    ):
        raise PackagingError("GitHub attestation subjects are invalid")
    if (
        set(value)
        != {
            "command_profile",
            "predicate_type",
            "repository",
            "schema",
            "signer_workflow",
            "source_commit",
            "subjects",
            "verified",
        }
        or value.get("schema") != ATTESTATION_SCHEMA
        or value.get("command_profile") != "gh-attestation-verify/1.0"
        or value.get("predicate_type") != "https://slsa.dev/provenance/v1"
        or value.get("verified") is not True
        or value.get("repository") != "kody-w/rapp-stack-cubby"
        or value.get("signer_workflow")
        != "kody-w/rapp-stack-cubby/.github/workflows/release.yml"
        or value.get("source_commit") != manifest.get("source_commit")
        or sorted(subjects, key=lambda item: str(item.get("name"))) != expected
    ):
        raise PackagingError("GitHub attestation input does not bind this release")
    digest, _size = sha256_file(path)
    return digest


def _verify_source_asset_bindings(
    directory: Path,
    manifest: dict,
    artifacts: list[dict],
) -> None:
    by_name = {item["filename"]: item for item in artifacts}
    provenance_record = by_name.get("release-provenance.json")
    egg_record = by_name.get("rapp-stack-cubby.egg")
    store_record = by_name.get("rapp-stack-cubby-store.zip")
    if not all((provenance_record, egg_record, store_record)):
        raise PackagingError("release source-binding assets are incomplete")
    provenance = read_json_object(directory / "release-provenance.json")
    if (
        provenance.get("source_revision") != manifest["source_commit"]
        or provenance.get("source_git_tree") != manifest["source_git_tree"]
        or provenance.get("source_tree_digest")
        != manifest["source_tree_digest"]
        or provenance.get("development_only")
        != manifest["development_only"]
    ):
        raise PackagingError("release provenance source binding is inconsistent")
    from .builder import verify_artifact

    egg = verify_artifact(
        directory / "rapp-stack-cubby.egg",
        expected_sha256=egg_record["sha256"],
    )
    egg_source = egg["manifest"].get("artifact")
    if not isinstance(egg_source, dict) or (
        egg_source.get("source_revision") != manifest["source_commit"]
        or egg_source.get("source_tree_digest")
        != manifest["source_tree_digest"]
        or egg_source.get("development_only")
        != manifest["development_only"]
    ):
        raise PackagingError("egg source binding is inconsistent")
    store = verify_artifact(
        directory / "rapp-stack-cubby-store.zip",
        expected_sha256=store_record["sha256"],
    )
    if (
        store["manifest"].get("source_revision") != manifest["source_commit"]
        or store["manifest"].get("source_tree_digest")
        != manifest["source_tree_digest"]
        or store["manifest"].get("development_only")
        != manifest["development_only"]
    ):
        raise PackagingError("Store source binding is inconsistent")


def verify_release(
    release_manifest: str | Path,
    *,
    expected_manifest_sha256: str,
    trust_path: str | Path,
    signature_path: str | Path | None = None,
    checksums_path: str | Path | None = None,
    source_root: str | Path | None = None,
    github_attestation: str | Path | None = None,
    additional_assets: Sequence[str] = (),
    allow_unsigned_development: bool = False,
    allow_generated_worktree: bool = False,
) -> dict:
    """Verify trust, exact asset inventory, source binding, and optional attestation."""

    if (
        not isinstance(expected_manifest_sha256, str)
        or SHA256_RE.fullmatch(expected_manifest_sha256) is None
    ):
        raise PackagingError("expected release-manifest digest is required")
    manifest_path = Path(release_manifest).resolve()
    directory = manifest_path.parent
    if manifest_path.name != RELEASE_MANIFEST_NAME:
        raise PackagingError("release manifest must use its canonical filename")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError as error:
        raise PackagingError("release manifest is unavailable") from error
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest_digest != expected_manifest_sha256:
        raise PackagingError("release manifest SHA-256 mismatch")
    manifest = read_json_object(manifest_path)
    if pretty_json_bytes(manifest) != manifest_bytes:
        raise PackagingError("release manifest encoding is not canonical")
    required = {
        "artifacts",
        "development_only",
        "release",
        "schema",
        "signed",
        "source_commit",
        "source_git_tree",
        "source_tree_digest",
        "version",
    }
    if (
        set(manifest) != required
        or manifest.get("schema") != "rapp-release-manifest/1.0"
        or not isinstance(manifest.get("development_only"), bool)
        or not isinstance(manifest.get("release"), bool)
        or not isinstance(manifest.get("signed"), bool)
        or not isinstance(manifest.get("source_tree_digest"), str)
        or SHA256_RE.fullmatch(manifest["source_tree_digest"]) is None
    ):
        raise PackagingError("release manifest fields are invalid")
    revision = manifest.get("source_commit")
    worktree = revision == "WORKTREE"
    if not worktree and (
        not isinstance(revision, str) or COMMIT_RE.fullmatch(revision) is None
    ):
        raise PackagingError("release source commit is invalid")
    git_tree = manifest.get("source_git_tree")
    if worktree:
        if git_tree is not None:
            raise PackagingError("WORKTREE cannot claim a Git tree")
    elif not isinstance(git_tree, str) or re.fullmatch(
        r"(?:[0-9a-f]{40}|[0-9a-f]{64})", git_tree
    ) is None:
        raise PackagingError("release Git tree binding is invalid")
    artifacts = _release_artifacts(manifest)
    signature = (
        Path(signature_path).resolve()
        if signature_path is not None
        else directory / RELEASE_SIGNATURE_NAME
    )
    if manifest["signed"] and signature != directory / RELEASE_SIGNATURE_NAME:
        raise PackagingError("release signature must be beside the manifest")
    trust = load_release_trust(trust_path)
    signature_digest: str | None = None
    if manifest["signed"]:
        _verify_signature(manifest_bytes, signature, trust)
        signature_digest, _ = sha256_file(signature)
    elif not (
        allow_unsigned_development
        and manifest["development_only"]
        and not manifest["release"]
    ):
        raise PackagingError("unsigned release manifests are development-only")
    if manifest["release"] != (
        manifest["signed"] and not worktree and not manifest["development_only"]
    ):
        raise PackagingError("release eligibility flags are inconsistent")
    if worktree and not manifest["development_only"]:
        raise PackagingError("WORKTREE must remain development-only")
    if not manifest["signed"] and not manifest["development_only"]:
        raise PackagingError("development release flags are inconsistent")
    for item in artifacts:
        path = directory / item["filename"]
        digest, size = sha256_file(path)
        if digest != item["sha256"] or size != item["size"]:
            raise PackagingError(f"declared release asset changed: {item['filename']}")
    _verify_source_asset_bindings(directory, manifest, artifacts)
    checksum = (
        Path(checksums_path).resolve()
        if checksums_path is not None
        else directory / CHECKSUMS_NAME
    )
    if checksum != directory / CHECKSUMS_NAME:
        raise PackagingError("checksums must be beside the release manifest")
    _verify_checksums(
        directory, artifacts, manifest_digest, signature_digest
    )
    checksums_digest, _checksums_size = sha256_file(checksum)
    extra_names: set[str] = set()
    for raw_name in additional_assets:
        name = validate_relative_path(raw_name)
        if "/" in name or name in extra_names:
            raise PackagingError("additional release asset name is invalid")
        extra_names.add(name)
    expected_names = {
        *(item["filename"] for item in artifacts),
        RELEASE_MANIFEST_NAME,
        CHECKSUMS_NAME,
    }
    if manifest["signed"]:
        expected_names.add(RELEASE_SIGNATURE_NAME)
    if extra_names & expected_names:
        raise PackagingError("additional release asset duplicates a core asset")
    expected_names.update(extra_names)
    observed = {
        item.name
        for item in directory.iterdir()
    }
    if observed != expected_names or any(
        not (directory / name).is_file() or (directory / name).is_symlink()
        for name in expected_names
    ):
        raise PackagingError("release directory is not the exact declared asset set")
    if source_root is not None:
        source = Path(source_root).resolve()
        if worktree:
            validated = validate_source_manifest(source)
            if (
                validated["source_tree_digest"]
                != manifest["source_tree_digest"]
            ):
                raise PackagingError("WORKTREE source digest does not match release")
        else:
            work = source.parent / f".verify-source-{uuid.uuid4().hex}"
            work.mkdir(mode=0o700)
            try:
                material = (
                    prepare_committed_source_material(source, revision, work)
                    if allow_generated_worktree
                    else prepare_source_material(source, revision, work)
                )
                if (
                    material.source_tree_digest
                    != manifest["source_tree_digest"]
                    or material.git_tree != git_tree
                ):
                    raise PackagingError("release source binding is invalid")
                if allow_generated_worktree:
                    recheck_committed_source_material(source, material)
                else:
                    recheck_source_material(source, material)
            finally:
                shutil.rmtree(work, ignore_errors=True)
    attestation_digest: str | None = None
    if github_attestation is not None:
        if signature_digest is None:
            raise PackagingError("GitHub-attested releases must be signed")
        attestation_digest = _verify_attestation(
            Path(github_attestation),
            manifest,
            artifacts,
            manifest_digest=manifest_digest,
            signature_digest=signature_digest,
            checksums_digest=checksums_digest,
        )
    return ReleaseVerification({
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "development_only": manifest["development_only"],
        "github_attestation_result_sha256": attestation_digest,
        "github_attestation_verified": github_attestation is not None,
        "key_id": trust["key_id"] if manifest["signed"] else None,
        "release": manifest["release"],
        "release_eligible": manifest["release"],
        "release_manifest_sha256": manifest_digest,
        "signed": manifest["signed"],
        "source_commit": revision,
        "source_git_tree": git_tree,
        "source_tree_digest": manifest["source_tree_digest"],
        "version": manifest["version"],
        "verified": True,
    }, _VERIFICATION_TOKEN)
