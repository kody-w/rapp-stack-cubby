from __future__ import annotations

import hashlib
import json
import unittest

from rapp_stack_cubby.packaging.common import pretty_json_bytes
from rapp_stack_cubby.packaging.publication import (
    sign_publication_receipt,
    write_publication_receipt,
)
from rapp_stack_cubby.promotion import (
    CANDIDATE_ASSETS,
    PromotionError,
    sign_evidence,
    verify_live_proof_receipt,
    verify_promotion_bundle,
    write_promotion_receipt,
)

from ._support import PackagingWorkspace, write_test_key_and_trust


class PromotionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = PackagingWorkspace()
        self.workspace.__enter__()
        self.source, _cache = (
            self.workspace.copy_repository_with_fake_dependencies()
        )
        self.key = write_test_key_and_trust(
            self.source, self.workspace.root / "promotion-private"
        )
        self.trust = self.source / "RELEASE_TRUST.json"
        self.evidence = self.workspace.root / "promotion-evidence"
        self.evidence.mkdir(mode=0o700)
        self.tag = "v0.1.0-rc.7"
        self.commit = "a" * 40
        self.manifest_sha = "b" * 64
        self.timestamp = "2026-07-13T00:00:00Z"

    def tearDown(self) -> None:
        self.workspace.__exit__(None, None, None)

    def _publication(self, phase: str) -> None:
        actions = (
            [{"run_id": "123", "sha256": "c" * 64, "size": 123}]
            if phase == "final"
            else []
        )
        required = ["source", "history", "pages", "release_assets"]
        if phase == "final":
            required.extend(["public_redownload", "actions_logs"])
        scopes = [
            {
                "artifact_count": 1,
                "byte_count": 1,
                "member_count": 0,
                "name": name,
                "sha256": hashlib.sha256(name.encode()).hexdigest(),
                "status": "complete",
            }
            for name in required
        ]
        value = {
            "actions_evidence": actions,
            "allowlist_uses": [],
            "counts": {
                "artifacts": len(scopes),
                "bytes": len(scopes),
                "findings": 0,
                "git_blobs": 1,
                "members": 0,
            },
            "findings": [],
            "phase": phase,
            "policy_sha256": hashlib.sha256(
                (self.source / "PUBLICATION_SCAN_POLICY.json").read_bytes()
            ).hexdigest(),
            "result": "pass",
            "scanner": "rapp-stack-cubby-publication-scanner/1.0",
            "schema": "rapp-publication-scan-receipt/1.0",
            "scopes": scopes,
            "source": {"commit": self.commit},
            "timestamp": self.timestamp,
        }
        stem = "candidate" if phase == "candidate" else "final"
        path = self.evidence / f"{stem}-publication-scan.json"
        signature = self.evidence / f"{stem}-publication-scan.json.sig"
        write_publication_receipt(path, value)
        sign_publication_receipt(
            path,
            signature,
            key_path=self.key,
            repository_root=self.source,
            trust_path=self.trust,
        )

    def _generic(self, name: str, value: dict) -> None:
        path = self.evidence / name
        path.write_bytes(pretty_json_bytes(value))
        sign_evidence(
            path,
            self.evidence / f"{name}.sig",
            key_path=self.key,
            repository_root=self.source,
            trust_path=self.trust,
        )

    def _bundle(self) -> None:
        self._publication("candidate")
        self._publication("final")
        candidate_sha = hashlib.sha256(
            (self.evidence / "candidate-publication-scan.json").read_bytes()
        ).hexdigest()
        inventory = sorted(CANDIDATE_ASSETS)
        self._generic(
            "postflight-success.json",
            {
                "asset_count": len(inventory),
                "bytes_equal": True,
                "candidate_publication_scan_sha256": candidate_sha,
                "draft": False,
                "failed_postflight": False,
                "github_attestations_verified": True,
                "immutable": True,
                "prerelease": True,
                "release_manifest_sha256": self.manifest_sha,
                "remote_inventory": inventory,
                "remote_inventory_sha256": hashlib.sha256(
                    pretty_json_bytes(inventory)
                ).hexdigest(),
                "schema": "rapp-release-postflight/1.0",
                "source_commit": self.commit,
                "tag": self.tag,
                "verified": True,
            },
        )
        self._generic(
            "live-proof-receipt.json",
            {
                "checks": {
                    "full_disk_access": True,
                    "imessage_owner_round_trip": True,
                    "outgoing_guid_confirmed": True,
                    "provider_preflight": True,
                    "restart": True,
                    "signed_twin_chat": True,
                    "sleep_wake": True,
                },
                "instance_identity_sha256": "d" * 64,
                "pages_target": "https://kody-w.github.io/rapp-stack-cubby/",
                "private_values_published": False,
                "release_manifest_sha256": self.manifest_sha,
                "schema": "rapp-live-proof/1.0",
                "source_commit": self.commit,
                "tag": self.tag,
                "timestamp": self.timestamp,
                "verified": True,
            },
        )
        write_promotion_receipt(
            self.evidence / "promotion-receipt.json",
            tag=self.tag,
            commit=self.commit,
            manifest_sha256=self.manifest_sha,
            evidence_directory=self.evidence,
            actions_evidence=[
                {"run_id": "123", "sha256": "c" * 64, "size": 123}
            ],
            timestamp=self.timestamp,
        )
        sign_evidence(
            self.evidence / "promotion-receipt.json",
            self.evidence / "promotion-receipt.json.sig",
            key_path=self.key,
            repository_root=self.source,
            trust_path=self.trust,
        )

    def test_signed_live_proof_and_actions_log_promotion_chain(self) -> None:
        self._bundle()
        result = verify_promotion_bundle(
            self.evidence,
            policy_path=self.source / "PUBLICATION_SCAN_POLICY.json",
            trust_path=self.trust,
            expected_tag=self.tag,
            expected_commit=self.commit,
            expected_live_proof_sha256=hashlib.sha256(
                (self.evidence / "live-proof-receipt.json").read_bytes()
            ).hexdigest(),
        )
        self.assertTrue(result["verified"])

    def test_live_proof_digest_and_private_material_are_rejected(self) -> None:
        self._bundle()
        with self.assertRaises(PromotionError):
            verify_live_proof_receipt(
                self.evidence / "live-proof-receipt.json",
                self.evidence / "live-proof-receipt.json.sig",
                trust_path=self.trust,
                expected_tag=self.tag,
                expected_commit=self.commit,
                expected_sha256="0" * 64,
            )
        value = json.loads(
            (self.evidence / "live-proof-receipt.json").read_text()
        )
        value["private_path"] = "/" + "Users" + "/private-owner/state"
        (self.evidence / "live-proof-receipt.json").write_bytes(
            pretty_json_bytes(value)
        )
        with self.assertRaises(PromotionError):
            verify_live_proof_receipt(
                self.evidence / "live-proof-receipt.json",
                self.evidence / "live-proof-receipt.json.sig",
                trust_path=self.trust,
                expected_tag=self.tag,
                expected_commit=self.commit,
            )


if __name__ == "__main__":
    unittest.main()
