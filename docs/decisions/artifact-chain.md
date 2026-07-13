# ADR: one artifact chain

**Status:** Accepted

## Context

Cubby and egg names identify multiple incompatible historical formats.
Skipping stages obscures provenance and installed-state boundaries.

## Decision

Use exactly source → `rapp-cubby/1.0` → `rapp-application/1.0` →
`brainstem-egg/2.3-cubby` → `rapp-installed-twin/1.0`. Hash every stage and
member; verify before extraction; publish no installed state.

## Consequences

Compatibility by extension is rejected. Release remains blocked until every
transform, digest, containment rule, and round trip is implemented and tested.

## Verification

`STACK_LOCK.json`, `docs/canon/ARTIFACT_CHAIN.md`, artifact schemas, and future
packaging vectors are the acceptance set.
