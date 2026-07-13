# ADR: clean-room runtime

**Status:** Accepted

## Context

Potential runtime references have licensing ambiguity or broader unsafe
behavior. The selected local runtime must not inherit code or attack surface
through resemblance or convenience.

## Decision

Keep the runtime newly authored from normalized contracts and observed
behavior. Copy no external runtime source. Use standard-library-first fixed
dependencies, explicit local agent directories, loopback-only serving, and no
dynamic code/install surface.

## Consequences

External projects remain evidence only. Runtime behavior and hardening are
proved locally; parity claims require contract tests, not source comparison.

## Verification

`PROVENANCE.json` records the isolated brainstem runtime files as
`original_new`, with no external runtime source. The separately adapted
iMessage edge is enumerated per file and is not part of that clean-room
runtime claim. The full runtime/server/registry/provider test families
exercise the implementation.
