from __future__ import annotations

import json
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from rapp_stack_cubby.catalog import inspect_agent_source
from rapp_stack_cubby.runtime.registry import AgentRegistry
from rapp_stack_cubby.runtime.storage import LocalStorage

from ._support import AGENTS_DIRECTORY, AgentEnvironment, REPOSITORY_ROOT, decoded


class AgentFactoryTests(unittest.TestCase):
    def test_render_write_digest_conflict_delete_and_atomicity(self) -> None:
        with AgentEnvironment(writes=True) as environment:
            factory = environment.snapshot["AgentFactory"]
            rendered = decoded(
                factory,
                action="render",
                name="SafeSample",
                description="A safe synthetic sample.",
                parameters=[],
            )
            self.assertTrue(rendered["ok"])
            self.assertIn("class SafeSample(BasicAgent)", rendered["source"])

            created = decoded(
                factory,
                action="create",
                name="SafeSample",
                description="A safe synthetic sample.",
                parameters=[],
            )
            path = environment.generated / "safe_sample_agent.py"
            self.assertTrue(path.is_file())
            self.assertFalse(
                any(item.name.endswith(".pending") for item in path.parent.iterdir())
            )
            generated = AgentRegistry(
                environment.generated,
                storage=LocalStorage(environment.data),
            ).load()
            self.assertEqual(generated.names, ("SafeSample",))
            self.assertTrue(
                json.loads(
                    generated["SafeSample"].perform(action="run")
                )["ok"]
            )
            inspected = inspect_agent_source(path)
            self.assertEqual(
                inspected["manifest"]["provenance"], "generated_local"
            )

            no_digest = decoded(
                factory,
                action="create",
                name="SafeSample",
                description="A changed safe synthetic sample.",
                parameters=[],
            )
            self.assertEqual(
                no_digest["error"]["code"], "overwrite_requires_digest"
            )
            conflict = decoded(
                factory,
                action="create",
                name="SafeSample",
                description="A changed safe synthetic sample.",
                parameters=[],
                expected_digest="0" * 64,
            )
            self.assertEqual(conflict["error"]["code"], "digest_conflict")

            updated = decoded(
                factory,
                action="create",
                name="SafeSample",
                description="A changed safe synthetic sample.",
                parameters=[],
                expected_digest=created["sha256"],
            )
            self.assertEqual(updated["status"], "updated")
            deleted = decoded(
                factory,
                action="delete",
                name="SafeSample",
                expected_digest=updated["sha256"],
            )
            self.assertEqual(deleted["status"], "deleted")
            self.assertFalse(path.exists())

    def test_required_parameters_and_manifest_description_are_enforced(self):
        with AgentEnvironment(writes=True) as environment:
            factory = environment.snapshot["AgentFactory"]
            created = decoded(
                factory,
                action="create",
                name="RequiredSample",
                description="Require one synthetic input.",
                parameters=[
                    {
                        "name": "value",
                        "type": "string",
                        "description": "Synthetic required value.",
                        "required": True,
                    }
                ],
            )
            self.assertTrue(created["ok"], created)
            generated = AgentRegistry(
                environment.generated,
                storage=LocalStorage(environment.data),
            ).load()["RequiredSample"]
            missing = json.loads(generated.perform(action="run"))
            supplied = json.loads(
                generated.perform(action="run", value="present")
            )
            self.assertFalse(missing["ok"])
            self.assertTrue(supplied["ok"])

            too_long = decoded(
                factory,
                action="render",
                name="LongDescription",
                description="x" * 241,
                parameters=[],
            )
            self.assertFalse(too_long["ok"])

    def test_containment_and_bundled_agent_protection(self) -> None:
        with AgentEnvironment(writes=True) as environment:
            factory = environment.snapshot["AgentFactory"]
            with patch.dict(
                os.environ,
                {"RAPP_STACK_GENERATED_AGENTS_DIR": str(AGENTS_DIRECTORY)},
                clear=False,
            ):
                protected = decoded(factory, action="list")
            self.assertFalse(protected["ok"])

            outside = environment.root / "outside"
            outside.mkdir()
            link = environment.root / "linked"
            link.symlink_to(outside, target_is_directory=True)
            with patch.dict(
                os.environ,
                {"RAPP_STACK_GENERATED_AGENTS_DIR": str(link)},
                clear=False,
            ):
                rejected = decoded(factory, action="list")
            self.assertFalse(rejected["ok"])


class StackMapTests(unittest.TestCase):
    def test_census_paths_collisions_and_bounds(self) -> None:
        with AgentEnvironment() as environment:
            agent = environment.snapshot["StackMap"]
            overview = decoded(agent, action="overview")
            self.assertEqual(overview["repository_count"], 307)
            self.assertEqual(overview["capability_count"], 113)

            repository = decoded(
                agent, action="repo", repo_name="RAR", limit=1
            )
            self.assertEqual(repository["count"], 1)
            self.assertLessEqual(len(repository["repositories"]), 1)
            self.assertNotIn(str(REPOSITORY_ROOT), json.dumps(repository))

            paths = decoded(agent, action="path", query="local", limit=1)
            self.assertLessEqual(len(paths["paths"]), 1)
            collisions = decoded(
                agent, action="collision", collision_id="agent-vs-skill"
            )
            self.assertTrue(collisions["collisions"])
            capability = decoded(
                agent,
                action="capability",
                capability_id="identity.canonical-json",
            )
            self.assertEqual(
                capability["capabilities"][0]["implementation_owner"],
                "agent:Rappid/canonicalize",
            )

            invalid = decoded(agent, action="repo", limit=0)
            self.assertFalse(invalid["ok"])


class SecurityAgentTests(unittest.TestCase):
    def test_scan_redacts_values_and_rejects_escape(self) -> None:
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "scan"
            scan_root.mkdir()
            sample = scan_root / "sample.py"
            sample.write_text(
                'password = "synthetic-value"\nimport subprocess\n',
                encoding="utf-8",
            )
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()
            result = decoded(
                security,
                action="scan",
                subtree=relative,
                max_files=10,
            )
            rules = {finding["rule"] for finding in result["findings"]}
            self.assertIn("secret_assignment", rules)
            self.assertIn("process_import", rules)
            self.assertNotIn("synthetic-value", json.dumps(result))
            self.assertTrue(result["values_redacted"])

            escape = decoded(
                security,
                action="scan",
                subtree="../outside",
            )
            self.assertFalse(escape["ok"])

    def test_policy_provenance_and_structural_verification(self) -> None:
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            boundary = decoded(security, action="boundary")
            self.assertTrue(boundary["default_deny"])
            provenance = decoded(security, action="provenance")
            self.assertEqual(provenance["schema"], "rapp-provenance/1.0")
            unresolved = decoded(security, action="unresolved")
            self.assertTrue(unresolved["build_blocked"])
            verified = decoded(security, action="verify")
            self.assertTrue(verified["passed"], verified)

    def test_scan_stops_at_file_bound_without_rglob_materialization(self):
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "many"
            scan_root.mkdir()
            for index in range(20):
                (scan_root / f"{index:02d}.txt").write_text(
                    "bounded synthetic text\n", encoding="utf-8"
                )
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()
            with patch.object(
                Path,
                "rglob",
                side_effect=AssertionError("rglob must not be used"),
            ):
                result = decoded(
                    security,
                    action="scan",
                    subtree=relative,
                    max_files=3,
                )
            self.assertEqual(result["scanned_file_count"], 3)
            self.assertTrue(result["scan_truncated"])
            self.assertEqual(result["truncation_reason"], "file_limit")
            self.assertEqual(result["encountered_entry_count"], 20)

    def test_scan_is_deterministic_across_creation_order(self) -> None:
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "ordered"
            scan_root.mkdir()
            for name in ("z.txt", "a.txt", "m.txt"):
                (scan_root / name).write_text(
                    'password = "redacted-synthetic"\n',
                    encoding="utf-8",
                )
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()
            first = decoded(
                security, action="scan", subtree=relative, max_files=10
            )
            second = decoded(
                security, action="scan", subtree=relative, max_files=10
            )

            self.assertEqual(first, second)
            self.assertEqual(
                [item["file"] for item in first["findings"]],
                [
                    f"{relative}/a.txt",
                    f"{relative}/m.txt",
                    f"{relative}/z.txt",
                ],
            )

    def test_symlinks_and_special_entries_are_counted_and_rejected(self):
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "links"
            scan_root.mkdir()
            target = environment.root / "target.txt"
            target.write_text("outside scan subtree\n", encoding="utf-8")
            for index in reversed(range(24)):
                (scan_root / f"{index:02d}.link").symlink_to(target)
            os.mkfifo(scan_root / "special.fifo")
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()

            result = decoded(
                security, action="scan", subtree=relative, max_files=10
            )

            rules = [item["rule"] for item in result["findings"]]
            self.assertEqual(result["encountered_entry_count"], 25)
            self.assertEqual(result["rejected_entry_count"], 25)
            self.assertEqual(result["scanned_file_count"], 0)
            self.assertEqual(rules.count("symbolic_link"), 24)
            self.assertIn("nonregular_entry", rules)
            self.assertFalse(result["scan_truncated"])

    def test_symlink_farm_stops_at_total_entry_bound(self) -> None:
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "link-farm"
            scan_root.mkdir()
            target = environment.root / "target.txt"
            target.write_text("outside scan subtree\n", encoding="utf-8")
            for index in range(2100):
                (scan_root / f"{index:04d}.link").symlink_to(target)
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()

            result = decoded(
                security, action="scan", subtree=relative, max_files=10
            )

            self.assertEqual(result["encountered_entry_count"], 2048)
            self.assertEqual(result["rejected_entry_count"], 2048)
            self.assertEqual(result["finding_count"], 2048)
            self.assertEqual(result["truncation_reason"], "entry_limit")
            self.assertTrue(
                all(
                    item["rule"] == "symbolic_link"
                    for item in result["findings"]
                )
            )

    def test_many_empty_directories_stop_at_hard_directory_bound(self):
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "directories"
            scan_root.mkdir()
            for index in reversed(range(300)):
                (scan_root / f"d{index:03d}").mkdir()
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()

            result = decoded(
                security, action="scan", subtree=relative, max_files=10
            )

            self.assertEqual(result["encountered_entry_count"], 300)
            self.assertEqual(result["scanned_directory_count"], 256)
            self.assertEqual(result["truncation_reason"], "directory_limit")
            self.assertTrue(result["scan_truncated"])

    def test_thousand_directory_chain_stops_iteratively_at_depth_bound(self):
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "deep"
            scan_root.mkdir()
            descriptor = os.open(scan_root, os.O_RDONLY)
            try:
                for _ in range(1000):
                    os.mkdir("d", dir_fd=descriptor)
                    child = os.open("d", os.O_RDONLY, dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = child
            finally:
                os.close(descriptor)
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()
            try:
                result = decoded(
                    security, action="scan", subtree=relative, max_files=10
                )
            finally:
                recursion_limit = sys.getrecursionlimit()
                try:
                    sys.setrecursionlimit(5000)
                    shutil.rmtree(scan_root)
                finally:
                    sys.setrecursionlimit(recursion_limit)

            self.assertEqual(result["maximum_depth_scanned"], 64)
            self.assertEqual(result["truncation_reason"], "depth_limit")
            self.assertIn(
                "depth_bound",
                {item["rule"] for item in result["findings"]},
            )
            self.assertTrue(result["scan_truncated"])

    def test_file_and_total_byte_bounds_are_hard(self) -> None:
        with AgentEnvironment() as environment:
            security = environment.snapshot["Security"]
            scan_root = REPOSITORY_ROOT / environment.root.name / "bytes"
            scan_root.mkdir()
            block = b"x" * (512 * 1024)
            for index in range(9):
                (scan_root / f"{index:02d}.bin").write_bytes(block)
            relative = scan_root.relative_to(REPOSITORY_ROOT).as_posix()

            total = decoded(
                security, action="scan", subtree=relative, max_files=20
            )
            self.assertEqual(total["scanned_byte_count"], 4 * 1024 * 1024)
            self.assertEqual(total["truncation_reason"], "byte_limit")
            self.assertEqual(total["scanned_file_count"], 9)
            self.assertIn(
                "total_byte_bound",
                {item["rule"] for item in total["findings"]},
            )

            oversized_root = (
                REPOSITORY_ROOT / environment.root.name / "oversized"
            )
            oversized_root.mkdir()
            (oversized_root / "large.bin").write_bytes(
                b"x" * (512 * 1024 + 1)
            )
            oversized_relative = oversized_root.relative_to(
                REPOSITORY_ROOT
            ).as_posix()
            oversized = decoded(
                security,
                action="scan",
                subtree=oversized_relative,
                max_files=20,
            )
            self.assertEqual(oversized["scanned_byte_count"], 0)
            self.assertIn(
                "file_size_bound",
                {item["rule"] for item in oversized["findings"]},
            )
            self.assertFalse(oversized["scan_truncated"])


class SelfTestAgentTests(unittest.TestCase):
    def test_self_test_passes_clean_project(self) -> None:
        with AgentEnvironment() as environment:
            result = decoded(environment.snapshot["SelfTest"], action="run")
            self.assertTrue(result["passed"], result)
            self.assertFalse(result["subprocess_used"])
            self.assertFalse(result["network_used"])


if __name__ == "__main__":
    unittest.main()
