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

    def test_pull_ref_history_is_excluded_but_canonical_history_is_scanned(self):
        source = self._source()

        def git(*arguments, input_=None):
            return subprocess.run(
                ["git", "-C", str(source), *arguments],
                check=True,
                input=input_,
                stdout=subprocess.PIPE,
            ).stdout.strip()

        git("init", "-q", "-b", "main")
        (source / "README.md").write_text("public\n", encoding="utf-8")
        git("add", "README.md")
        tree = git("write-tree").decode("ascii")
        public_email = "test" + "@" + "example.invalid"

        def write_commit(
            *,
            parents,
            email,
            timestamp,
            message,
            signature=None,
        ):
            lines = [
                f"tree {tree}",
                *(f"parent {parent}" for parent in parents),
                f"author Synthetic Fixture <{email}> {timestamp} +0000",
                f"committer Synthetic Fixture <{email}> {timestamp} +0000",
            ]
            if signature is not None:
                lines.extend(
                    (
                        "gpgsig -----BEGIN PGP SIGNATURE-----",
                        f" {signature}",
                        " =ABCD",
                        " -----END PGP SIGNATURE-----",
                    )
                )
            content = ("\n".join(lines) + "\n\n" + message + "\n").encode()
            return git(
                "hash-object",
                "-t",
                "commit",
                "-w",
                "--stdin",
                input_=content,
            ).decode("ascii")

        base = write_commit(
            parents=(),
            email=public_email,
            timestamp=946684800,
            message="public base",
        )
        git("update-ref", "refs/heads/main", base)
        baseline = self._scan(source)
        self.assertEqual(baseline["result"], "pass", baseline["findings"])

        feature = write_commit(
            parents=(base,),
            email=public_email,
            timestamp=946684801,
            message="public feature",
        )
        private_email = "private.bot" + "@" + "example.com"
        token = "gh" + "p_" + "M1n2B3v4C5x6Z7a8" + "S9d0F1g2H3j4"
        private_message = json.dumps(
            {"message": "not a public fixture", "token": token},
            sort_keys=True,
        )
        signature = "iQIzBAABCgAdFiEE" + "A1b2C3d4E5f6G7h8I9j0K1l2"
        merge = write_commit(
            parents=(base, feature),
            email=private_email,
            timestamp=946684802,
            message=private_message,
            signature=signature,
        )
        git("update-ref", "refs/pull/123/merge", merge)
        git("remote", "add", "origin", "https://example.invalid/repository.git")
        git("update-ref", "refs/remotes/pull/123/merge", merge)

        pull_first = self._scan(source)
        pull_second = self._scan(source)
        self.assertEqual(pull_first, pull_second)
        self.assertEqual(pull_first, baseline)

        expected_rules = {
            "credential_token",
            "email_identifier",
            "private_content_marker",
        }
        canonical_receipts = []
        for ref in (
            "refs/heads/private-history",
            "refs/remotes/origin/private-history",
            "refs/tags/private-history",
        ):
            with self.subTest(ref=ref):
                git("update-ref", ref, merge)
                first = self._scan(source)
                second = self._scan(source)
                self.assertEqual(first, second)
                self.assertEqual(first["result"], "fail")
                findings = [
                    item for item in first["findings"] if item["member"] == merge
                ]
                rules = {item["rule"] for item in findings}
                self.assertTrue(expected_rules.issubset(rules), rules)
                signature_digest = hashlib.sha256(signature.encode()).hexdigest()
                self.assertFalse(
                    any(
                        item["rule"] == "high_entropy_candidate"
                        and item["digest"] == signature_digest
                        for item in findings
                    )
                )
                canonical_receipts.append(first)
                git("update-ref", "-d", ref)

        histories = [
            next(
                scope
                for scope in receipt["scopes"]
                if scope["name"] == "history"
            )
            for receipt in canonical_receipts
        ]
        self.assertTrue(all(history == histories[0] for history in histories))

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

    def test_protected_squash_hashes_allow_history_but_not_unreviewed_email(self):
        identities = {
            "public-protected-squash-merge-email-identifier-01": (
                "0dd1be59c0696e9feb662bc996c2ae7ebb7201dffc9bffc7c85cbdd2e9f2cff1"
            ),
            "public-protected-squash-merge-email-identifier-02": (
                "3c205d8fc749f72977b9331e3179773c315bb1f4860c366de2abe9ec9337730b"
            ),
        }
        policy = json.loads(self.policy.read_text(encoding="utf-8"))
        entries = {
            item["id"]: item
            for item in policy["allowlist"]
            if item["id"] in identities
        }
        self.assertEqual(set(entries), set(identities))
        for identifier, digest in identities.items():
            self.assertEqual(entries[identifier]["match_sha256"], digest)
            self.assertEqual(entries[identifier]["rule"], "email_identifier")
            self.assertEqual(entries[identifier]["reviewer"], "repository-maintainer")
            self.assertIn(
                "exact public identity inserted by GitHub's protected squash merge commit",
                entries[identifier]["reason"],
            )
            self.assertNotIn("path", entries[identifier])

        history_receipt = self._scan(REPOSITORY_ROOT)
        self.assertEqual(
            history_receipt["result"],
            "pass",
            history_receipt["findings"],
        )
        used = {item["id"] for item in history_receipt["allowlist_uses"]}
        self.assertTrue(set(identities).issubset(used))

        source = self._source("unreviewed-email")
        unreviewed = "unreviewed.history" + "@" + "example.com"
        (source / "identity.txt").write_text(unreviewed + "\n", encoding="utf-8")
        rejected = self._scan(source)
        digest = hashlib.sha256(unreviewed.encode("utf-8")).hexdigest()
        self.assertEqual(rejected["result"], "fail")
        self.assertTrue(
            any(
                item["rule"] == "email_identifier"
                and item["digest"] == digest
                for item in rejected["findings"]
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
