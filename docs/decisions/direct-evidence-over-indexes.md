# ADR: direct evidence over indexes

**Status:** Accepted

## Context

The audited ecosystem contains maps, mirrors, “canonical” labels, and
aspirational indexes that disagree with repository-at-head behavior.

## Decision

Current tested local code and contracts lead. Local profiles select behavior;
direct audit evidence supports historical claims; indexes are cross-checks
only. An index never establishes another artifact's implementation or license.

## Consequences

Claims remain traceable and stale labels cannot silently expand scope. Audit
work is larger because each material claim needs direct evidence.

## Verification

`src/rapp_stack_cubby/context.py` enforces the authority order in the local
entrypoint and indexes `SOURCE_CENSUS.json`, `CAPABILITY_MATRIX.json`, and
`SYSTEM_GRAPH.json` as evidence rather than implementation.
