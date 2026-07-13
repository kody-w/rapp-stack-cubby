# ADR: the repository is the product

**Status:** Accepted

## Context

A handoff that depends on unstated repositories, private state, mutable
downloads, or operator memory cannot be understood, improved, reproduced, or
recovered safely.

## Decision

This repository contains the complete normalized context and all reviewed
source needed to understand, improve, build, package, hatch, and operate RAPP.
Generated artifacts add only the four locked offline dependency archives.
External repositories are provenance citations, not working prerequisites.
Private keys, enrollment, message content, runtime state, and final release
attestation remain external by design.

The artifact chain has no shortcut. The committed source manifest excludes
itself and never embeds its containing commit; exact commit identity is
verified separately and bound to generated release sidecars.

## Consequences

Source, context, schemas, tests, locks, notices, runbooks, builders, and
hatchers evolve together. `scripts/check.sh` rejects stale source/context
manifests and controller/singleton drift. A complete local development build
does not imply publication or release.

## Verification

Packaging tests recursively prove whole-repository/context inclusion,
deterministic ZIP bytes, exact manifests, offline dependency injection, strict
verification, isolated hatch, rollback, and installed logical-byte parity.
