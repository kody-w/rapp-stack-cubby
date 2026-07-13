from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from rapp_stack_cubby.constants import EXPECTED_CONTEXT_SCHEMA_COUNT
from rapp_stack_cubby.context import (
    CANONICAL_PROFILES,
    CONTEXT_INDEX_RELATIVE,
    CONTEXT_SCHEMA_RELATIVE,
    build_context_index,
    context_summary,
    validate_context,
    validate_index_structure,
    validate_schema_instance,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class ContextClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.index = json.loads(
            (REPOSITORY_ROOT / CONTEXT_INDEX_RELATIVE).read_text(encoding="utf-8")
        )

    def test_repository_context_is_closed(self) -> None:
        result = validate_context(REPOSITORY_ROOT)

        self.assertTrue(result.ok, "\n".join(result.errors))
        self.assertEqual(result.schema_count, EXPECTED_CONTEXT_SCHEMA_COUNT)
        self.assertEqual(result.capability_count, 61)

    def test_context_index_is_deterministic(self) -> None:
        self.assertEqual(self.index, build_context_index(REPOSITORY_ROOT))

    def test_summary_has_all_required_artifact_families(self) -> None:
        summary = context_summary(REPOSITORY_ROOT)

        self.assertEqual(summary["canonical_profiles"], len(CANONICAL_PROFILES))
        self.assertEqual(summary["schemas"], EXPECTED_CONTEXT_SCHEMA_COUNT)
        self.assertEqual(summary["decisions"], 16)
        self.assertEqual(summary["runbooks"], 17)
        self.assertEqual(summary["future_owners"], 1)

    def test_every_canonical_profile_is_indexed(self) -> None:
        indexed = {
            item["path"]
            for item in self.index["entries"]
            if item["kind"] == "canonical_profile"
        }
        expected = {f"docs/canon/{name}" for name in CANONICAL_PROFILES}
        self.assertEqual(indexed, expected)

    def test_structure_rejects_duplicate_ids(self) -> None:
        broken = copy.deepcopy(self.index)
        broken["entries"][1]["id"] = broken["entries"][0]["id"]

        errors = validate_index_structure(broken, REPOSITORY_ROOT)

        self.assertTrue(any("unique" in error for error in errors))

    def test_structure_rejects_dependency_cycle(self) -> None:
        broken = copy.deepcopy(self.index)
        first = broken["entries"][0]
        second = broken["entries"][1]
        first["prerequisites"] = [second["id"]]
        first["read_after"] = [second["id"]]
        second["prerequisites"] = [first["id"]]
        second["read_after"] = [first["id"]]

        errors = validate_index_structure(broken, REPOSITORY_ROOT)

        self.assertTrue(any("cycle" in error for error in errors))

    def test_project_validator_rejects_invalid_context_schema_value(self) -> None:
        schema = json.loads(
            (REPOSITORY_ROOT / CONTEXT_SCHEMA_RELATIVE).read_text(encoding="utf-8")
        )
        broken = copy.deepcopy(self.index)
        broken["schema"] = "wrong"

        errors = validate_schema_instance(
            broken,
            schema,
            schema_path=REPOSITORY_ROOT / CONTEXT_SCHEMA_RELATIVE,
        )

        self.assertTrue(any("const" in error for error in errors))

    def test_every_selected_capability_routes_to_local_owner(self) -> None:
        entries = {item["id"]: item for item in self.index["entries"]}

        for route in self.index["capability_routes"]:
            self.assertIn(route["context_entry_id"], entries)
            self.assertIn(
                entries[route["context_entry_id"]]["status"],
                {"tested_implementation", "future_owned"},
            )
            self.assertIn(
                route["capability_status"],
                {
                    "contradictory",
                    "deprecated",
                    "implemented",
                    "partial",
                    "spec_only",
                    "unsafe_legacy",
                },
            )
            self.assertTrue(route["local_claim"])
            self.assertTrue(route["major_gaps"])
            self.assertIn(
                route["semantic_status"],
                {
                    "future_owned",
                    "narrowed_tested_implementation",
                    "safe_narrowing_of_unsafe_reference",
                    "tested_implementation",
                },
            )
            if route["implementation_state"] == "future_owned":
                self.assertTrue(route["future_owner"])
            else:
                self.assertIsNone(route["future_owner"])


if __name__ == "__main__":
    unittest.main()
