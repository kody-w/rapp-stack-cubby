# ADR: grail pointer is not source

**Status:** Accepted

## Context

The strongest historical behavior pointer has no license at its selected root.
Behavioral usefulness does not grant source-copy rights.

## Decision

Treat the grail only as provenance evidence. Do not copy its files, archives,
generated bundles, or assets. Implement locally from normalized behavior and
current contracts; any future imported file requires independent per-file
authorship, license, hash, destination, and notice review.

## Consequences

The runtime remains clean-room and external fetches are unnecessary for local
work. Behavioral parity must be demonstrated by tests, not source similarity.

## Verification

`PROVENANCE.json` keeps the pointer in `pointer_only` with empty cleared/copied
files; `NOTICE` and repository verification preserve that boundary.
