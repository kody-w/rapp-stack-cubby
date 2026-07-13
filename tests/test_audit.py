from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from rapp_stack_cubby.audit import (
    AuditArtifactError,
    build_audit_artifacts,
    validate_audit_artifacts,
    write_audit_artifacts,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class AuditArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix=".test-audit-", dir=REPOSITORY_ROOT
        )
        self.root = Path(self.temporary.name)
        inventory_records = []
        head_observations = []
        snapshot_records = []
        for index in range(10):
            name = f"repo-{index}"
            observed_at = f"2026-07-13T03:59:45.{index:06d}Z"
            inventory = {
                "archived": False,
                "created_at": "2026-07-12T00:00:00Z",
                "default_branch": "main",
                "description": f"Repository {index}",
                "disabled": False,
                "fork": False,
                "full_name": f"kody-w/{name}",
                "has_pages": False,
                "homepage": None,
                "html_url": f"https://github.com/kody-w/{name}",
                "language": "Python",
                "license_spdx_id": "MIT",
                "name": name,
                "private": False,
                "pushed_at": "2026-07-12T00:00:00Z",
                "repository_id": index,
                "size_kib": 1,
                "topics": ["rapp"],
                "updated_at": "2026-07-12T00:00:00Z",
                "visibility": "public",
            }
            head = {
                "body_sha256": f"{index:064x}",
                "current_head_sha": f"{index:040x}",
                "default_branch": "main",
                "endpoint": f"GET /repos/kody-w/{name}/commits/main",
                "head_status": "resolved_exact",
                "head_observed_at": observed_at,
                "headers": {"etag": f'"head-{index}"'},
                "observed_at": observed_at,
                "repository_id": index,
                "repository_name": name,
                "request_started_at": observed_at,
                "response_received_at": observed_at,
                "response_time_ms": 1.0,
                "status": 200,
            }
            inventory_records.append(inventory)
            head_observations.append(head)
            snapshot_records.append(
                {
                    **inventory,
                    "candidate_audit_shard": index % 8,
                    "candidate_sorted_index": index,
                    "current_head_sha": head["current_head_sha"],
                    "current_observed_at": observed_at,
                    "head_observed_at": observed_at,
                    "head_status": "resolved_exact",
                }
            )
        canonical = json.dumps(
            snapshot_records,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        digest = hashlib.sha256(canonical).hexdigest()
        inventory_digest = hashlib.sha256(
            json.dumps(
                inventory_records,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        heads_digest = hashlib.sha256(
            json.dumps(
                head_observations,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        census_records = []
        for index, raw in enumerate(snapshot_records):
            census_records.append(
                {
                    "audit_shard": index % 8,
                    "audited": True,
                    "classification": "A",
                    "created_at": raw["created_at"],
                    "current_head_sha": raw["current_head_sha"],
                    "current_observed_at": raw["current_observed_at"],
                    "default_branch": raw["default_branch"],
                    "description": raw["description"],
                    "direct_evidence_note": "direct",
                    "evidence_head_sha": raw["current_head_sha"],
                    "evidence_locators": ["owner/repo:README.md:1"],
                    "evidence_release": "test",
                    "evidence_scope": "pinned",
                    "head_drift": "unchanged",
                    "head_observed_at": raw["head_observed_at"],
                    "has_pages": raw["has_pages"],
                    "html_url": raw["html_url"],
                    "language": raw["language"],
                    "license_spdx_id": raw["license_spdx_id"],
                    "name": raw["name"],
                    "private": raw["private"],
                    "primary_plane": "adjacent",
                    "pushed_at": raw["pushed_at"],
                    "rapp_relevance": "adjacent",
                    "repository_id": raw["repository_id"],
                    "sorted_index": index,
                    "topics": raw["topics"],
                    "updated_at": raw["updated_at"],
                    "visibility": raw["visibility"],
                    "fork": raw["fork"],
                }
            )
        (self.root / "docs/research").mkdir(parents=True)
        (self.root / "SOURCE_CENSUS.json").write_text(
            json.dumps(
                {
                    "existence_cutoff": "2026-07-13T03:59:40Z",
                    "owner": "kody-w",
                    "raw_inventory": {
                        "head_observations_sha256": heads_digest,
                        "inventory_records_sha256": inventory_digest,
                        "sha256": digest,
                        "query": {},
                    },
                    "repositories": census_records,
                    "repository_count": 10,
                    "snapshot_cutoff": "2026-07-13T03:59:43Z",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        (self.root / "docs/research/public-account-snapshot.json").write_text(
            json.dumps(
                {
                    "capture_completed_at": "2026-07-13T03:59:46Z",
                    "capture_started_at": "2026-07-13T03:59:43Z",
                    "existence_cutoff": "2026-07-13T03:59:40Z",
                    "head_observations": head_observations,
                    "heads_started_at": "2026-07-13T03:59:45Z",
                    "inventory_completed_at": "2026-07-13T03:59:44Z",
                    "inventory_records": inventory_records,
                    "raw_inventory": {
                        "head_observations_sha256": heads_digest,
                        "inventory_records_sha256": inventory_digest,
                        "sha256": digest,
                    },
                    "repositories": snapshot_records,
                    "response_pages": [
                        {
                            "body_sha256": "a" * 64,
                            "headers": {"etag": '"inventory"'},
                            "item_count": 10,
                            "page": 1,
                            "request_started_at": "2026-07-13T03:59:43Z",
                            "response_received_at": "2026-07-13T03:59:44Z",
                            "response_time_ms": 1.0,
                            "status": 200,
                        }
                    ],
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_builds_deterministic_complete_shards_and_manifest(self):
        manifest = write_audit_artifacts(self.root)
        result = validate_audit_artifacts(self.root)
        rebuilt, rebuilt_manifest = build_audit_artifacts(self.root)

        self.assertEqual(result["repository_count"], 10)
        self.assertEqual(result["shard_count"], 8)
        self.assertEqual(manifest, rebuilt_manifest)
        self.assertEqual(len(rebuilt), 8)
        self.assertEqual(
            sum(item["repository_count"] for item in manifest["shards"]), 10
        )
        self.assertFalse(manifest["external_reports_required"])
        self.assertEqual(manifest["post_window_drift"]["repository_count"], 0)

    def test_detects_tampered_shard(self):
        write_audit_artifacts(self.root)
        path = self.root / "docs/research/shards/shard-0.json"
        path.write_text("{}\n", encoding="utf-8")
        with self.assertRaises(AuditArtifactError):
            validate_audit_artifacts(self.root)

    def test_rejects_snapshot_digest_mismatch(self):
        census = json.loads(
            (self.root / "SOURCE_CENSUS.json").read_text(encoding="utf-8")
        )
        census["raw_inventory"]["sha256"] = "0" * 64
        (self.root / "SOURCE_CENSUS.json").write_text(
            json.dumps(census) + "\n", encoding="utf-8"
        )
        with self.assertRaises(AuditArtifactError):
            build_audit_artifacts(self.root)

    def _rewrite_raw_digests(self, snapshot, census):
        def digest(value):
            return hashlib.sha256(
                json.dumps(
                    value,
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            ).hexdigest()

        values = {
            "sha256": digest(snapshot["repositories"]),
            "inventory_records_sha256": digest(snapshot["inventory_records"]),
            "head_observations_sha256": digest(snapshot["head_observations"]),
        }
        snapshot["raw_inventory"].update(values)
        census["raw_inventory"].update(values)
        (self.root / "docs/research/public-account-snapshot.json").write_text(
            json.dumps(snapshot, sort_keys=True) + "\n", encoding="utf-8"
        )
        (self.root / "SOURCE_CENSUS.json").write_text(
            json.dumps(census, sort_keys=True) + "\n", encoding="utf-8"
        )

    def test_rejects_promoted_metadata_tamper_even_with_rebound_digests(self):
        snapshot = json.loads(
            (self.root / "docs/research/public-account-snapshot.json").read_text()
        )
        census = json.loads((self.root / "SOURCE_CENSUS.json").read_text())
        snapshot["inventory_records"][0]["visibility"] = "internal"
        snapshot["repositories"][0]["visibility"] = "internal"
        self._rewrite_raw_digests(snapshot, census)

        with self.assertRaisesRegex(AuditArtifactError, "promoted visibility"):
            build_audit_artifacts(self.root)

    def test_rejects_promoted_head_tamper_even_with_rebound_digests(self):
        snapshot = json.loads(
            (self.root / "docs/research/public-account-snapshot.json").read_text()
        )
        census = json.loads((self.root / "SOURCE_CENSUS.json").read_text())
        replacement = "f" * 40
        snapshot["head_observations"][0]["current_head_sha"] = replacement
        snapshot["repositories"][0]["current_head_sha"] = replacement
        self._rewrite_raw_digests(snapshot, census)

        with self.assertRaisesRegex(AuditArtifactError, "promoted current_head_sha"):
            build_audit_artifacts(self.root)

    def test_required_drift_without_exact_head_review_blocks_audit(self):
        census_path = self.root / "SOURCE_CENSUS.json"
        census = json.loads(census_path.read_text(encoding="utf-8"))
        census["repositories"][0]["evidence_head_sha"] = "e" * 40
        census["repositories"][0]["head_drift"] = (
            "observed_changed_since_evidence"
        )
        census_path.write_text(
            json.dumps(census, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(AuditArtifactError, "drift review is absent"):
            build_audit_artifacts(self.root)


if __name__ == "__main__":
    unittest.main()
