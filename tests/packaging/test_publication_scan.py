from __future__ import annotations

import base64
import gzip
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import urllib.parse
import zipfile
from pathlib import Path

from rapp_stack_cubby.packaging.publication import (
    PublicationScanError,
    scan_publication,
    sign_publication_receipt,
    verify_publication_receipt,
    write_publication_receipt,
)

from ._support import REPOSITORY_ROOT, write_test_key_and_trust


class PublicationScanTests(unittest.TestCase):
    def setUp(self):
        (REPOSITORY_ROOT / "dist").mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".test-publication-scan-",
            dir=REPOSITORY_ROOT / "dist",
        )
        self.root = Path(self.temporary.name)
        self.policy = REPOSITORY_ROOT / "PUBLICATION_SCAN_POLICY.json"

    def tearDown(self):
        self.temporary.cleanup()

    def _source(self, name="source"):
        source = self.root / name
        source.mkdir()
        return source

    def _scan(self, source, **kwargs):
        return scan_publication(
            source,
            policy_path=self.policy,
            phase="development",
            **kwargs,
        )

    def test_detects_plain_encoded_utf16_identifiers_content_and_environment(self):
        source = self._source()
        token = (
            "gh" + "p_" + "A1b2C3d4E5f6G7h8" + "I9j0K1l2M3n4"
        ).encode()
        (source / "plain.txt").write_bytes(token)
        (source / "utf16.txt").write_bytes(
            b"\xff\xfe" + token.decode().encode("utf-16-le")
        )
        (source / "base64.txt").write_bytes(base64.b64encode(token))
        (source / "url.txt").write_text(
            urllib.parse.quote_from_bytes(token), encoding="utf-8"
        )
        email = "private.person" + "@" + "example.com"
        phone = "+" + "1 555 " + "867 " + "5309"
        guid = "12345678" + "-1234-4abc-8def-" + "1234567890ab"
        entropy = "Aa0Bb1Cc2Dd3Ee4F" + "f5Gg6Hh7Ii8Jj9Kk"
        local_path = "/" + "Users" + "/private-owner/project/file"
        private_account = "account-" + "private-" + "12345"
        (source / "identifiers.txt").write_text(
            "\n".join((email, phone, guid, entropy, local_path)) + "\n",
            encoding="utf-8",
        )
        (source / "private-data.json").write_text(
            json.dumps(
                {
                    "message": "not a public fixture",
                    "account_id": private_account,
                }
            ),
            encoding="utf-8",
        )
        (source / "environment.txt").write_text(
            "HOME=" + local_path + "\nUSER=private-owner\nPATH=/bin:/usr/bin\n",
            encoding="utf-8",
        )
        key_boundary = "-----BEGIN " + "PRIVATE KEY-----\n"
        (source / "key.txt").write_text(
            key_boundary + base64.b64encode(b"private key bytes").decode() + "\n",
            encoding="utf-8",
        )

        receipt = self._scan(source)
        rules = {item["rule"] for item in receipt["findings"]}
        self.assertEqual(receipt["result"], "fail")
        self.assertTrue(
            {
                "credential_token",
                "email_identifier",
                "environment_dump",
                "guid_identifier",
                "high_entropy_candidate",
                "phone_identifier",
                "private_content_marker",
                "private_key",
                "private_local_path",
                "transport_identifier",
            }.issubset(rules),
            rules,
        )
        encoded = json.dumps(receipt, sort_keys=True)
        self.assertNotIn(token.decode(), encoded)
        for finding in receipt["findings"]:
            self.assertEqual(
                set(finding),
                {"artifact", "digest", "member", "path", "rule"},
            )

    def test_nested_archives_corruption_traversal_and_bomb_fail_closed(self):
        source = self._source()
        token = (
            "gh" + "p_" + "Z9y8X7w6V5u4T3s2" + "R1q0P9o8N7m6"
        ).encode()
        inner_buffer = io.BytesIO()
        with zipfile.ZipFile(inner_buffer, "w") as archive:
            archive.writestr("payload/encoded.txt", base64.b64encode(token))
        outer_buffer = io.BytesIO()
        with tarfile.open(fileobj=outer_buffer, mode="w") as archive:
            info = tarfile.TarInfo("nested/inner.zip")
            content = inner_buffer.getvalue()
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
        (source / "outer.tar").write_bytes(outer_buffer.getvalue())
        (source / "corrupt.zip").write_bytes(b"PK\x03\x04not-a-zip")
        with zipfile.ZipFile(source / "bomb.zip", "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("large.txt", b"0" * (1024 * 1024))
        with zipfile.ZipFile(source / "traversal.zip", "w") as archive:
            archive.writestr("../escape.txt", b"synthetic")

        receipt = self._scan(source)
        rules = {item["rule"] for item in receipt["findings"]}
        self.assertIn("credential_token", rules)
        self.assertIn("corrupt_archive", rules)
        self.assertEqual(receipt["result"], "fail")

    def test_deleted_history_blob_is_scanned_without_checkout(self):
        source = self._source()
        subprocess.run(["git", "init", "-q", "-b", "main", str(source)], check=True)
        subprocess.run(
            ["git", "-C", str(source), "config", "user.name", "Synthetic Test"],
            check=True,
        )
        test_email = "test" + "@" + "example.invalid"
        subprocess.run(
            ["git", "-C", str(source), "config", "user.email", test_email],
            check=True,
        )
        token = "gh" + "p_" + "Q1w2E3r4T5y6U7i8" + "O9p0A1s2D3f4"
        secret = source / "deleted.txt"
        secret.write_text(token + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(source), "add", "deleted.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "-q", "-m", "synthetic add"],
            check=True,
        )
        secret.unlink()
        subprocess.run(["git", "-C", str(source), "add", "-u"], check=True)
        subprocess.run(
            ["git", "-C", str(source), "commit", "-q", "-m", "synthetic delete"],
            check=True,
        )

        receipt = self._scan(source)
        history = [
            item
            for item in receipt["findings"]
            if item["artifact"] == "git-history"
            and item["rule"] == "credential_token"
        ]
        self.assertTrue(history)
        self.assertEqual(receipt["source"]["history"], "complete")
        self.assertEqual(receipt["counts"]["git_blobs"], 1)

    def test_actions_log_archive_is_explicit_and_redacted(self):
        source = self._source()
        (source / "README.md").write_text("public\n", encoding="utf-8")
        token = "gh" + "p_" + "L1k2J3h4G5f6D7s8" + "A9p0O1i2U3y4"
        archive = self.root / "actions-log.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("1_release.txt", "token=" + token + "\n")

        receipt = self._scan(
            source, actions_logs=(("123456789", archive),)
        )
        self.assertEqual(
            receipt["actions_evidence"],
            [
                {
                    "run_id": "123456789",
                    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "size": archive.stat().st_size,
                }
            ],
        )
        self.assertTrue(
            any(
                item["artifact"] == "actions-log:123456789"
                and item["rule"] == "credential_token"
                for item in receipt["findings"]
            )
        )
        self.assertNotIn(token, json.dumps(receipt))

    def test_reviewed_public_fixture_allowlist_is_recorded(self):
        source = self._source()
        public_fixture = "test" + "@" + "example.invalid"
        (source / "fixture.txt").write_text(public_fixture + "\n", encoding="utf-8")

        first = self._scan(source)
        second = self._scan(source)
        self.assertEqual(first, second)
        self.assertEqual(first["result"], "pass")
        self.assertEqual(first["findings"], [])
        self.assertTrue(
            any(
                item["id"].startswith("public-email-identifier")
                for item in first["allowlist_uses"]
            )
        )

    def test_exact_public_noreply_identities_pass_but_private_email_fails(self):
        identities = {
            "public-github-noreply-identity-kody-w": (
                "1735900+kody-w@users.noreply.github.com"
            ),
            "public-github-noreply-identity-copilot": (
                "223556219+Copilot@users.noreply.github.com"
            ),
        }
        public_source = self._source("public-identities")
        (public_source / "commit-identities.txt").write_text(
            "\n".join(identities.values()) + "\n",
            encoding="utf-8",
        )

        public_receipt = self._scan(public_source)
        self.assertEqual(public_receipt["result"], "pass")
        self.assertEqual(public_receipt["findings"], [])
        used = {item["id"] for item in public_receipt["allowlist_uses"]}
        self.assertTrue(set(identities).issubset(used))

        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        entries = {
            item["id"]: item
            for item in policy["allowlist"]
            if item["id"] in identities
        }
        self.assertEqual(set(entries), set(identities))
        for identifier, identity in identities.items():
            self.assertEqual(
                entries[identifier]["match_sha256"],
                hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(entries[identifier]["rule"], "email_identifier")
            self.assertEqual(entries[identifier]["reviewer"], "repository-maintainer")
            self.assertIn("public GitHub noreply commit identity", entries[identifier]["reason"])
            self.assertNotIn("path", entries[identifier])

        private_source = self._source("private-identity")
        private_identity = "private.committer" + "@" + "example.com"
        (private_source / "identity.txt").write_text(
            private_identity + "\n",
            encoding="utf-8",
        )

        private_receipt = self._scan(private_source)
        self.assertEqual(private_receipt["result"], "fail")
        private_digest = hashlib.sha256(private_identity.encode("utf-8")).hexdigest()
        self.assertTrue(
            any(
                item["rule"] == "email_identifier"
                and item["digest"] == private_digest
                for item in private_receipt["findings"]
            )
        )

    def test_receipt_signature_is_deterministic_trusted_and_tamper_evident(self):
        source = self._source()
        (source / "README.md").write_text("public fixture\n", encoding="utf-8")
        private = self.root / "private"
        key = write_test_key_and_trust(source, private)
        receipt = self._scan(source)
        self.assertEqual(receipt["result"], "pass")
        receipt_path = self.root / "publication-receipt.json"
        write_publication_receipt(receipt_path, receipt)
        first_signature = self.root / "first.sig"
        second_signature = self.root / "second.sig"
        sign_publication_receipt(
            receipt_path,
            first_signature,
            key_path=key,
            repository_root=source,
            trust_path=source / "RELEASE_TRUST.json",
        )
        sign_publication_receipt(
            receipt_path,
            second_signature,
            key_path=key,
            repository_root=source,
            trust_path=source / "RELEASE_TRUST.json",
        )
        self.assertEqual(first_signature.read_bytes(), second_signature.read_bytes())
        verified = verify_publication_receipt(
            receipt_path,
            policy_path=self.policy,
            required_phase="development",
            signature_path=first_signature,
            trust_path=source / "RELEASE_TRUST.json",
        )
        self.assertTrue(verified["verified"])
        self.assertTrue(verified["signed"])

        tampered = json.loads(receipt_path.read_text(encoding="utf-8"))
        tampered["timestamp"] = "2000-01-01T00:00:00Z"
        receipt_path.write_text(
            json.dumps(tampered, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(PublicationScanError):
            verify_publication_receipt(
                receipt_path,
                policy_path=self.policy,
                required_phase="development",
                signature_path=first_signature,
                trust_path=source / "RELEASE_TRUST.json",
            )

    def test_release_phase_requires_real_history_and_all_surfaces(self):
        source = self._source()
        (source / "README.md").write_text("public\n", encoding="utf-8")
        with self.assertRaises(PublicationScanError):
            scan_publication(
                source,
                policy_path=self.policy,
                phase="candidate",
            )

    def test_repository_pages_and_development_assets_scan_clean(self):
        receipt = scan_publication(
            REPOSITORY_ROOT,
            policy_path=self.policy,
            pages_root=REPOSITORY_ROOT / "docs",
            phase="development",
        )
        self.assertEqual(receipt["result"], "pass", receipt["findings"])
        self.assertEqual(receipt["counts"]["findings"], 0)
        self.assertIn(
            receipt["source"]["history"],
            {"complete", "not_available_development"},
        )


if __name__ == "__main__":
    unittest.main()
