"""Generate the normalized system graph from census truth and curated edges."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import RappStackCubbyError

GRAPH = Path("SYSTEM_GRAPH.json")
OVERLAY = Path("docs/research/system-graph-overlay.json")
PRODUCT_NODE = "product:local/rapp-stack-cubby"


class GraphGenerationError(RappStackCubbyError, ValueError):
    """Raised when the graph source cannot produce a closed graph."""


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise GraphGenerationError(f"cannot read {path.name}") from error
    if not isinstance(value, dict):
        raise GraphGenerationError(f"{path.name} must contain an object")
    return value


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise GraphGenerationError(f"cannot hash {path.name}") from error


def _pretty(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _repo_node(record: Mapping[str, Any], owner: str) -> dict[str, Any]:
    return {
        "audited": record.get("audited"),
        "classification": record.get("classification"),
        "current_head_sha": record.get("current_head_sha"),
        "current_observed_at": record.get("current_observed_at"),
        "direct_evidence_note": record.get("direct_evidence_note"),
        "evidence": record.get("evidence_locators"),
        "evidence_head_sha": record.get("evidence_head_sha"),
        "head_drift": record.get("head_drift"),
        "head_observed_at": record.get("head_observed_at"),
        "head_sha": record.get("evidence_head_sha"),
        "id": f"repo:{owner}/{record.get('name')}",
        "name": record.get("name"),
        "node_type": "repository",
        "primary_plane": record.get("primary_plane"),
        "rapp_relevance": record.get("rapp_relevance"),
    }


def build_system_graph(root: str | Path) -> dict[str, Any]:
    """Derive all repository nodes and counts from SOURCE_CENSUS."""

    repository = Path(root).resolve()
    census = _read_object(repository / "SOURCE_CENSUS.json")
    overlay = _read_object(repository / OVERLAY)
    if overlay.get("schema") != "rapp-system-graph-overlay/1.0":
        raise GraphGenerationError("system graph overlay schema is invalid")
    records = census.get("repositories")
    owner = census.get("owner")
    if not isinstance(records, list) or not isinstance(owner, str):
        raise GraphGenerationError("source census graph inputs are invalid")
    if not all(isinstance(item, Mapping) for item in records):
        raise GraphGenerationError("source census repositories are invalid")
    repo_nodes = [_repo_node(item, owner) for item in records]
    if [item["name"] for item in repo_nodes] != sorted(
        (item["name"] for item in repo_nodes), key=str.casefold
    ):
        raise GraphGenerationError("source census repository order is invalid")

    non_repo_nodes = overlay.get("non_repo_nodes")
    edges = overlay.get("edges")
    paths = overlay.get("canonical_end_to_end_paths")
    if not isinstance(non_repo_nodes, list) or not isinstance(edges, list):
        raise GraphGenerationError("system graph overlay nodes or edges are invalid")
    if not isinstance(paths, list):
        raise GraphGenerationError("system graph paths are invalid")
    repo_ids = {item["id"] for item in repo_nodes}
    non_repo_ids = {
        item.get("id") for item in non_repo_nodes if isinstance(item, Mapping)
    }
    if len(non_repo_ids) != len(non_repo_nodes) or None in non_repo_ids:
        raise GraphGenerationError("non-repository node ids are invalid")
    if PRODUCT_NODE not in non_repo_ids:
        raise GraphGenerationError("explicit local product node is absent")
    all_ids = repo_ids | non_repo_ids
    if len(all_ids) != len(repo_ids) + len(non_repo_ids):
        raise GraphGenerationError("graph node ids are not unique")
    edge_by_id: dict[str, Mapping[str, Any]] = {}
    for edge in edges:
        if not isinstance(edge, Mapping) or not isinstance(edge.get("id"), str):
            raise GraphGenerationError("graph edge is invalid")
        edge_id = str(edge["id"])
        if edge_id in edge_by_id:
            raise GraphGenerationError("graph edge ids are not unique")
        if edge.get("source_id") not in all_ids or edge.get("target_id") not in all_ids:
            raise GraphGenerationError(f"{edge_id}: endpoint does not resolve")
        edge_by_id[edge_id] = edge
    if list(edge_by_id) != sorted(edge_by_id):
        raise GraphGenerationError("graph edges must be sorted by id")
    for path in paths:
        if not isinstance(path, Mapping):
            raise GraphGenerationError("canonical path is invalid")
        path_edges = path.get("ordered_edges")
        path_nodes = path.get("ordered_nodes")
        if not isinstance(path_edges, list) or not isinstance(path_nodes, list):
            raise GraphGenerationError("canonical path sequence is invalid")
        if len(path_nodes) != len(path_edges) + 1:
            raise GraphGenerationError(f"{path.get('id')}: path length is invalid")
        for index, edge_id in enumerate(path_edges):
            edge = edge_by_id.get(edge_id)
            if edge is None or (
                edge.get("source_id"),
                edge.get("target_id"),
            ) != (path_nodes[index], path_nodes[index + 1]):
                raise GraphGenerationError(
                    f"{path.get('id')}: edge sequence is not continuous"
                )
    collisions = overlay.get("collisions", [])
    if not isinstance(collisions, list):
        raise GraphGenerationError("system graph collisions are invalid")
    for collision in collisions:
        if not isinstance(collision, Mapping) or not isinstance(
            collision.get("node_refs"), list
        ):
            raise GraphGenerationError("system graph collision is invalid")
        missing = set(collision["node_refs"]) - all_ids
        if missing:
            raise GraphGenerationError(
                f"{collision.get('id')}: collision endpoints do not resolve"
            )

    endpoints = {
        endpoint
        for edge in edges
        for endpoint in (edge["source_id"], edge["target_id"])
    }
    orphans = sorted(repo_ids - endpoints, key=str.casefold)
    classes = Counter(str(item["classification"]) for item in repo_nodes)
    planes = Counter(str(item["primary_plane"]) for item in repo_nodes)
    relevance = Counter(str(item["rapp_relevance"]) for item in repo_nodes)
    edge_types = Counter(str(item.get("type")) for item in edges)
    return {
        "aggregates": {
            "canonical_path_count": len(paths),
            "collision_count": len(collisions),
            "edge_count": len(edges),
            "edge_counts_by_type": dict(sorted(edge_types.items())),
            "non_repo_node_count": len(non_repo_nodes),
            "orphan_repo_count": len(orphans),
            "repo_node_count": len(repo_nodes),
            "repo_nodes_by_classification": dict(sorted(classes.items())),
            "repo_nodes_by_primary_plane": dict(sorted(planes.items())),
            "repo_nodes_by_rapp_relevance": dict(sorted(relevance.items())),
            "total_node_count": len(repo_nodes) + len(non_repo_nodes),
        },
        "audited_at": census.get("audited_at"),
        "canonical_end_to_end_paths": paths,
        "collisions": collisions,
        "determinism": overlay.get("determinism"),
        "edges": edges,
        "existence_cutoff": census.get("existence_cutoff"),
        "methodology": overlay.get("methodology"),
        "non_repo_nodes": non_repo_nodes,
        "orphans": {
            "explanation": overlay.get("orphan_explanation"),
            "repo_node_ids": orphans,
        },
        "repo_nodes": repo_nodes,
        "schema": overlay.get("output_schema"),
        "snapshot_cutoff": census.get("snapshot_cutoff"),
        "observation_window": census.get("observation_window"),
        "drift_review": {
            "audit_complete": True,
            "post_window_drift_count": census.get("aggregates", {})
            .get("head_drift_counts", {})
            .get("post_window_drift", 0),
            "required_count": len(
                census.get("snapshot_comparison", {}).get(
                    "required_drift_reviews", []
                )
            ),
        },
        "source_census": {
            "local_product_in_repository_count": False,
            "local_product_node": PRODUCT_NODE,
            "ref": "SOURCE_CENSUS.json",
            "repository_count": len(repo_nodes),
            "sha256": _sha256(repository / "SOURCE_CENSUS.json"),
        },
    }


def write_system_graph(root: str | Path) -> dict[str, Any]:
    repository = Path(root).resolve()
    graph = build_system_graph(repository)
    (repository / GRAPH).write_text(
        _pretty(graph), encoding="utf-8", newline="\n"
    )
    return graph


def validate_system_graph(root: str | Path) -> dict[str, int]:
    repository = Path(root).resolve()
    expected = build_system_graph(repository)
    actual = _read_object(repository / GRAPH)
    if actual != expected:
        raise GraphGenerationError("SYSTEM_GRAPH.json is stale")
    return {
        "edge_count": len(expected["edges"]),
        "node_count": (
            len(expected["repo_nodes"]) + len(expected["non_repo_nodes"])
        ),
        "repository_count": len(expected["repo_nodes"]),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = (
            validate_system_graph(args.root)
            if args.check
            else write_system_graph(args.root)["aggregates"]
        )
    except GraphGenerationError as error:
        print(f"error: {error}")
        return 2
    print(
        "PASS system graph: "
        f"{result.get('repository_count', result.get('repo_node_count'))} "
        f"repositories, {result.get('edge_count')} edges"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
