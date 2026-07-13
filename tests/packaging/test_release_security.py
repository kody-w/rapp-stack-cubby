from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rapp_stack_cubby.packaging.builder import (
    EGG_ARCHIVE_NAME,
    RELEASE_MANIFEST_NAME,
    RELEASE_STORE_INDEX_NAME,
    SBOM_NAME,
    build_release,
    validate_spdx,
)
from rapp_stack_cubby.packaging.common import PackagingError
from rapp_stack_cubby.packaging.hatch import HatchTestSeam, hatch_egg
from rapp_stack_cubby.packaging.release import (
    RELEASE_SIGNATURE_NAME,
    sign_release_manifest,
    verify_release,
)
from rapp_stack_cubby.packaging.source import write_source_manifest

from ._support import (
    PackagingWorkspace,
    create_fake_installed_environment,
    refresh_source_provenance,
)


def _write_key_and_trust(source: Path, private_root: Path) -> Path:
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

    def encoded(value):
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


class ReleaseTrustTests(unittest.TestCase):
    EPOCH = 1783892570

    def setUp(self):
        self.workspace = PackagingWorkspace()
        self.workspace.__enter__()
        self.source, self.cache = (
            self.workspace.copy_repository_with_fake_dependencies()
        )
        self.key = _write_key_and_trust(
            self.source, self.workspace.root / "private"
        )

    def tearDown(self):
        self.workspace.__exit__(None, None, None)

    def _signed(self, name="signed"):
        output = self.workspace.root / name
        result = build_release(
            self.source,
            self.cache,
            output,
            source_date_epoch=self.EPOCH,
            source_revision="WORKTREE",
            signing_key=self.key,
        )
        verified = verify_release(
            output / RELEASE_MANIFEST_NAME,
            expected_manifest_sha256=result["release_manifest_sha256"],
            trust_path=self.source / "RELEASE_TRUST.json",
            source_root=self.source,
        )
        return output, result, verified

    def test_pinned_low_s_signature_and_signed_development_not_release(self):
        output, result, verified = self._signed()
        self.assertTrue(result["signed"])
        self.assertTrue(verified["verified"])
        self.assertTrue(verified["development_only"])
        self.assertFalse(verified["release"])
        self.assertFalse(verified["release_eligible"])
        sidecar = json.loads(
            (output / RELEASE_SIGNATURE_NAME).read_text(encoding="utf-8")
        )
        self.assertNotIn("public_jwk", sidecar)

    def test_wrong_hash_signer_embedded_key_and_attestation_are_rejected(self):
        output, result, _ = self._signed()
        with self.assertRaises(PackagingError):
            verify_release(
                output / RELEASE_MANIFEST_NAME,
                expected_manifest_sha256="0" * 64,
                trust_path=self.source / "RELEASE_TRUST.json",
            )
        signature = output / RELEASE_SIGNATURE_NAME
        original = signature.read_bytes()
        sidecar = json.loads(original)
        sidecar["public_jwk"] = json.loads(
            (self.source / "RELEASE_TRUST.json").read_text()
        )["public_jwk"]
        signature.write_text(
            json.dumps(sidecar, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(PackagingError):
            verify_release(
                output / RELEASE_MANIFEST_NAME,
                expected_manifest_sha256=result["release_manifest_sha256"],
                trust_path=self.source / "RELEASE_TRUST.json",
            )
        signature.write_bytes(original)
        wrong_source = self.workspace.root / "wrong-trust"
        shutil.copytree(self.source, wrong_source)
        _write_key_and_trust(wrong_source, self.workspace.root / "wrong-private")
        with self.assertRaises(PackagingError):
            verify_release(
                output / RELEASE_MANIFEST_NAME,
                expected_manifest_sha256=result["release_manifest_sha256"],
                trust_path=wrong_source / "RELEASE_TRUST.json",
            )
        attestation = self.workspace.root / "attestation.json"
        attestation.write_text(
            json.dumps(
                {
                    "repository": "attacker/repository",
                    "schema": "rapp-github-attestation-verification/1.0",
                    "source_commit": "WORKTREE",
                    "subjects": [],
                    "verified": True,
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(PackagingError):
            verify_release(
                output / RELEASE_MANIFEST_NAME,
                expected_manifest_sha256=result["release_manifest_sha256"],
                trust_path=self.source / "RELEASE_TRUST.json",
                github_attestation=attestation,
            )

    def test_missing_declared_asset_is_rejected(self):
        output, result, _ = self._signed()
        (output / RELEASE_STORE_INDEX_NAME).unlink()
        with self.assertRaises(PackagingError):
            verify_release(
                output / RELEASE_MANIFEST_NAME,
                expected_manifest_sha256=result["release_manifest_sha256"],
                trust_path=self.source / "RELEASE_TRUST.json",
            )

    def test_forged_verification_mapping_cannot_authorize_hatch(self):
        output, _, verified = self._signed()
        egg = output / EGG_ARCHIVE_NAME
        digest = hashlib.sha256(egg.read_bytes()).hexdigest()
        forged = dict(verified)
        install = self.workspace.root / "forged-install"
        with self.assertRaises(PackagingError):
            hatch_egg(
                egg,
                install,
                Path(os.path.realpath(os.sys.executable)),
                expected_egg_sha256=digest,
                release_verification=forged,
                test_seam=HatchTestSeam(create_fake_installed_environment),
            )
        self.assertFalse(install.exists())

    def test_signed_development_chain_verifies_hatches_and_stays_nonrelease(self):
        output, _, verified = self._signed()
        egg = output / EGG_ARCHIVE_NAME
        install = self.workspace.root / "installed"
        result = hatch_egg(
            egg,
            install,
            Path(os.path.realpath(os.sys.executable)),
            expected_egg_sha256=hashlib.sha256(egg.read_bytes()).hexdigest(),
            release_verification=verified,
            test_seam=HatchTestSeam(create_fake_installed_environment),
        )
        self.assertTrue(result["release_verified"])
        self.assertFalse(result["release"])

    def test_signed_development_build_is_identical_twice(self):
        first, _, _ = self._signed("signed-repeat-one")
        second = self.workspace.root / "signed-repeat-two"
        build_release(
            self.source,
            self.cache,
            second,
            source_date_epoch=self.EPOCH,
            source_revision="WORKTREE",
            signing_key=self.key,
        )
        first_paths = sorted(first.iterdir())
        self.assertEqual(
            [path.name for path in first_paths],
            [path.name for path in sorted(second.iterdir())],
        )
        for path in first_paths:
            self.assertEqual(path.read_bytes(), (second / path.name).read_bytes())

    def test_signing_key_under_repository_is_rejected(self):
        manifest = self.workspace.root / "manifest.json"
        manifest.write_text("{}\n", encoding="utf-8")
        key_under_source = self.source / "local-signing.pem"
        key_under_source.write_bytes(self.key.read_bytes())
        key_under_source.chmod(0o600)
        with self.assertRaises(PackagingError):
            sign_release_manifest(
                manifest,
                self.workspace.root / "signature.json",
                key_path=key_under_source,
                repository_root=self.source,
                trust_path=self.source / "RELEASE_TRUST.json",
            )

    def test_store_binding_and_spdx_semantics(self):
        output, _, _ = self._signed()
        store = json.loads(
            (output / RELEASE_STORE_INDEX_NAME).read_text(encoding="utf-8")
        )
        application = store["applications"][0]
        self.assertIn("application_manifest_sha256", application)
        self.assertNotIn("manifest_sha256", application)
        sbom = json.loads((output / SBOM_NAME).read_text(encoding="utf-8"))
        result = validate_spdx(sbom)
        self.assertTrue(result["valid"])
        self.assertGreater(result["file_count"], 0)

    def test_output_must_be_absent_and_failure_leaves_no_stage(self):
        output = self.workspace.root / "existing"
        output.mkdir()
        with self.assertRaises(PackagingError):
            build_release(
                self.source,
                self.cache,
                output,
                source_date_epoch=self.EPOCH,
                source_revision="WORKTREE",
            )
        failed = self.workspace.root / "failed"
        first_cache_file = next(self.cache.iterdir())
        first_cache_file.write_bytes(b"tampered")
        with self.assertRaises(PackagingError):
            build_release(
                self.source,
                self.cache,
                failed,
                source_date_epoch=self.EPOCH,
                source_revision="WORKTREE",
            )
        self.assertFalse(failed.exists())
        self.assertEqual(list(self.workspace.root.glob(".failed.build-*")), [])


class ImmutableSourceTests(unittest.TestCase):
    EPOCH = 1783892570

    def test_exact_commit_uses_git_objects_and_rejects_dirty_or_missing(self):
        with PackagingWorkspace() as workspace:
            source, cache = workspace.copy_repository_with_fake_dependencies()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "Packaging Test"],
                check=True,
            )
            subprocess.run(["git", "-C", str(source), "add", "-A"], check=True)
            subprocess.run(
                ["git", "-C", str(source), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            revision = (
                subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"])
                .decode()
                .strip()
            )
            result = build_release(
                source,
                cache,
                workspace.root / "commit-build",
                source_date_epoch=self.EPOCH,
                source_revision=revision,
            )
            self.assertIsNotNone(result["source_git_tree"])
            (source / "README.md").write_text("dirty\n", encoding="utf-8")
            with self.assertRaises(PackagingError):
                build_release(
                    source,
                    cache,
                    workspace.root / "dirty-build",
                    source_date_epoch=self.EPOCH,
                    source_revision=revision,
                )
            self.assertFalse((workspace.root / "dirty-build").exists())
            with self.assertRaises(PackagingError):
                build_release(
                    source,
                    cache,
                    workspace.root / "missing-build",
                    source_date_epoch=self.EPOCH,
                    source_revision="f" * 40,
                )


if __name__ == "__main__":
    unittest.main()
