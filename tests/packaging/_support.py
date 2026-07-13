from __future__ import annotations

import hashlib
import json
import base64
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rapp_stack_cubby.packaging.builder import build_release
from rapp_stack_cubby.packaging.release import verify_release
from rapp_stack_cubby.packaging.source import scan_source_tree, write_source_manifest
from rapp_stack_cubby.pages import build_pages

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PUBLIC_RELEASE_ASSETS = (
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


def refresh_source_provenance(source: Path) -> None:
    scan = {
        item["path"]: item["sha256"]
        for item in scan_source_tree(source)["files"]
    }
    provenance_path = source / "PROVENANCE.json"
    if not provenance_path.is_file():
        return
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    target = next(
        item
        for item in provenance["entries"]
        if item["id"] == "target-rapp-stack-cubby"
    )
    records = target["source_file_provenance"]["files"]
    if {item["path"] for item in records} != set(scan):
        raise AssertionError("test source provenance coverage changed")
    for record in records:
        if record["path"] != "PROVENANCE.json":
            record["sha256"] = scan[record["path"]]
    provenance_path.write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_test_key_and_trust(source: Path, private_root: Path) -> Path:
    private_root.mkdir(mode=0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    key_path = private_root / "signing.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    numbers = key.public_key().public_numbers()

    def encoded(value: int) -> str:
        return (
            base64.urlsafe_b64encode(value.to_bytes(32, "big"))
            .rstrip(b"=")
            .decode("ascii")
        )

    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": encoded(numbers.x),
        "y": encoded(numbers.y),
    }
    key_id = hashlib.sha256(
        json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()
    trust = {
        "algorithm": "ecdsa-p256-sha256",
        "generation": "test-only local private operation",
        "key_id": key_id,
        "profile": "rapp-release-trust/1.0",
        "public_jwk": jwk,
        "schema": "rapp-release-trust/1.0",
    }
    (source / "RELEASE_TRUST.json").write_text(
        json.dumps(trust, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    refresh_source_provenance(source)
    write_source_manifest(source)
    return key_path


def initialize_exact_git_source(source: Path) -> str:
    subprocess.run(["git", "init", "-q", "-b", "main", str(source)], check=True)
    subprocess.run(
        ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(source), "config", "user.name", "Release Test"],
        check=True,
    )
    subprocess.run(["git", "-C", str(source), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(source), "commit", "-q", "-m", "fixture"],
        check=True,
    )
    return subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        text=True,
    ).strip()


def write_test_attestation(
    release_dir: Path,
    source_commit: str,
    output: Path,
) -> Path:
    subjects = [
        {
            "name": name,
            "sha256": hashlib.sha256((release_dir / name).read_bytes()).hexdigest(),
        }
        for name in PUBLIC_RELEASE_ASSETS
    ]
    value = {
        "command_profile": "gh-attestation-verify/1.0",
        "predicate_type": "https://slsa.dev/provenance/v1",
        "repository": "kody-w/rapp-stack-cubby",
        "schema": "rapp-github-attestation-verification/1.0",
        "signer_workflow": (
            "kody-w/rapp-stack-cubby/.github/workflows/release.yml"
        ),
        "source_commit": source_commit,
        "subjects": sorted(subjects, key=lambda item: item["name"]),
        "verified": True,
    }
    output.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output


def create_exact_signed_release(workspace: "PackagingWorkspace"):
    source, cache = workspace.copy_repository_with_fake_dependencies()
    key = write_test_key_and_trust(source, workspace.root / "private")
    build_pages(source)
    refresh_source_provenance(source)
    write_source_manifest(source)
    revision = initialize_exact_git_source(source)
    output = workspace.root / "exact-release"
    result = build_release(
        source,
        cache,
        output,
        source_date_epoch=1783892570,
        source_revision=revision,
        signing_key=key,
    )
    attestation = write_test_attestation(
        output, revision, workspace.root / "github-attestation.json"
    )
    verified = verify_release(
        output / "release-manifest.json",
        expected_manifest_sha256=result["release_manifest_sha256"],
        trust_path=source / "RELEASE_TRUST.json",
        source_root=source,
        github_attestation=attestation,
    )
    return source, cache, output, result, verified, attestation


def create_fake_installed_environment(stage: Path, python: Path, application: Path):
    del python, application
    binary = stage / "venv/bin/python"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    site = stage / "venv/lib/python3.11/site-packages"
    versions = {
        "cffi": "2.1.0",
        "cryptography": "49.0.0",
        "pycparser": "3.0",
    }

    def record_hash(content):
        digest = hashlib.sha256(content).digest()
        return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    for name, version in versions.items():
        package = site / name / "__init__.py"
        package.parent.mkdir(parents=True, exist_ok=True)
        package_content = f"__version__ = {version!r}\n".encode()
        package.write_bytes(package_content)
        metadata = site / f"{name}-{version}.dist-info/METADATA"
        metadata.parent.mkdir(parents=True)
        metadata_content = (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
        ).encode()
        metadata.write_bytes(metadata_content)
        record = metadata.parent / "RECORD"
        package_relative = package.relative_to(site).as_posix()
        metadata_relative = metadata.relative_to(site).as_posix()
        record_relative = record.relative_to(site).as_posix()
        record.write_text(
            f"{package_relative},{record_hash(package_content)},{len(package_content)}\n"
            f"{metadata_relative},{record_hash(metadata_content)},{len(metadata_content)}\n"
            f"{record_relative},,\n",
            encoding="utf-8",
        )
    tool = stage / "state/tools/imsg/0.12.3/imsg"
    tool.parent.mkdir(parents=True)
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o700)
    evidence = tool.parent / "install-evidence.json"
    evidence.write_text('{"schema":"test-imsg"}\n', encoding="utf-8")
    links = stage / "state/tools/bin"
    links.mkdir()
    (links / "imsg").symlink_to("../imsg/0.12.3/imsg")
    return versions


class PackagingWorkspace:
    def __enter__(self):
        (REPOSITORY_ROOT / "dist").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".test-packaging-",
            dir=REPOSITORY_ROOT / "dist",
        )
        self.root = Path(self.temporary.name)
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.temporary.cleanup()

    def copy_repository_with_fake_dependencies(self):
        source = self.root / "repository"

        def ignored(directory, names):
            del directory
            return {
                name
                for name in names
                if name in {".git", "dist", "build", "__pycache__"}
                or name.startswith(".test-")
            }

        shutil.copytree(REPOSITORY_ROOT, source, ignore=ignored)
        lock_path = source / "DEPENDENCY_LOCK.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        cache = self.root / "cache"
        cache.mkdir(mode=0o700)
        for package in lock["packages"]:
            artifact = package["wheel"]
            content = (
                f"synthetic locked wheel {artifact['filename']}\n".encode()
            )
            (cache / artifact["filename"]).write_bytes(content)
            artifact["sha256"] = hashlib.sha256(content).hexdigest()
            artifact["size"] = len(content)
        for tool in lock["tools"]:
            artifact = tool["release"]
            content = (
                f"synthetic locked tool {artifact['asset']}\n".encode()
            )
            (cache / artifact["asset"]).write_bytes(content)
            artifact["archive_sha256"] = hashlib.sha256(content).hexdigest()
            artifact["size"] = len(content)
        lock_path.write_text(
            json.dumps(lock, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        refresh_source_provenance(source)
        write_source_manifest(source)
        return source, cache
