# ADR: exact-commit release

**Status:** Accepted

## Context

Mutable branches, tag drift, post-build changes, and separately generated
receipts break source-to-artifact identity.

## Decision

Build once from one final 40-hex commit. Bind source manifest, provenance,
artifacts, schemas, scanner receipts, host attestation, Pages output, and
release assets to that commit and exact SHA-256 values. Verify downloaded
public bytes after publication.

## Consequences

Any content change creates a new candidate and reruns all gates. Development
hatches and null artifact digests are never release eligible.

## Verification

`STACK_LOCK.json`, `docs/operations/PACKAGING_AND_RELEASE.md`, and the future
release receipt enforce the binding.
