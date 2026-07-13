from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from rapp_stack_cubby.graph import (
    GraphGenerationError,
    build_system_graph,
    validate_system_graph,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class SystemGraphTests(unittest.TestCase):
    def test_repository_graph_is_deterministic_and_closed(self):
        graph = build_system_graph(REPOSITORY_ROOT)
        result = validate_system_graph(REPOSITORY_ROOT)

        self.assertEqual(graph, json.loads((REPOSITORY_ROOT / "SYSTEM_GRAPH.json").read_text()))
        self.assertEqual(result["repository_count"], 307)
        ids = {item["id"] for item in graph["non_repo_nodes"]}
        self.assertIn("product:local/rapp-stack-cubby", ids)
        self.assertIn("runtime:clean-room-brainstem", ids)
        self.assertNotIn("runtime:microsoft-hardened-adaptation", ids)
        self.assertTrue(
            any(
                edge["source_id"] == "actor:local-owner"
                and edge["target_id"] == "runtime:global-controller"
                for edge in graph["edges"]
            )
        )

    def test_every_path_is_a_continuous_resolved_edge_sequence(self):
        graph = build_system_graph(REPOSITORY_ROOT)
        edges = {item["id"]: item for item in graph["edges"]}
        for path in graph["canonical_end_to_end_paths"]:
            self.assertEqual(
                len(path["ordered_nodes"]), len(path["ordered_edges"]) + 1
            )
            for index, edge_id in enumerate(path["ordered_edges"]):
                edge = edges[edge_id]
                self.assertEqual(
                    (edge["source_id"], edge["target_id"]),
                    tuple(path["ordered_nodes"][index : index + 2]),
                )

    def test_invalid_overlay_endpoint_fails_closed(self):
        with tempfile.TemporaryDirectory(
            prefix=".test-graph-", dir=REPOSITORY_ROOT
        ) as temporary:
            root = Path(temporary)
            (root / "docs/research").mkdir(parents=True)
            census = json.loads(
                (REPOSITORY_ROOT / "SOURCE_CENSUS.json").read_text()
            )
            overlay = json.loads(
                (
                    REPOSITORY_ROOT
                    / "docs/research/system-graph-overlay.json"
                ).read_text()
            )
            overlay = copy.deepcopy(overlay)
            overlay["edges"][0]["target_id"] = "missing:node"
            (root / "SOURCE_CENSUS.json").write_text(
                json.dumps(census), encoding="utf-8"
            )
            (root / "docs/research/system-graph-overlay.json").write_text(
                json.dumps(overlay), encoding="utf-8"
            )
            with self.assertRaises(GraphGenerationError):
                build_system_graph(root)


if __name__ == "__main__":
    unittest.main()
