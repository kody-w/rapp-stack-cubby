# ADR: one-repository working context

**Status:** Accepted

## Context

Future engineers and AIs must be able to understand, evolve, build, package,
hatch, and operate RAPP end to end without an external working set.

## Decision

The repository is the product. Keep normalized system facts, narrowed
contracts, schemas, decisions, status, gaps, operations, evidence, reading
order, runtime, actual agents, controller, package/hatch implementation, tests,
locks, and notices here. External repository names and links are provenance
citations only, never prerequisites.

Keep the sanitized authenticated public snapshot, all deterministic census
shards, shard digest manifest, graph overlay, and generators here as well.
The local product node is distinct from public antecedent repository records.

## Consequences

Context changes become reviewed product changes with deterministic validation.
Local profiles must be maintained when implementation truth moves.

## Verification

`AI_CONTEXT.md`, `CONTEXT_INDEX.json`, `SOURCE_CENSUS.json`,
`docs/research/AUDIT_MANIFEST.json`, `docs/research/shards/`,
`SYSTEM_GRAPH.json`, `docs/canon/`, `docs/operations/`, `schemas/`, and the
context/audit/graph tests form and validate the closure.
