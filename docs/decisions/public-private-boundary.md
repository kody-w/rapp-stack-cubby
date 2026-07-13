# ADR: default-deny public/private boundary

**Status:** Accepted

## Context

Source, build output, Pages, logs, archives, and installed state can expose
credentials, identifiers, conversations, local paths, or unreviewed material.

## Decision

Treat every byte as private unless a local allowlist permits publication.
Private runtime state stays outside the checkout; file state is mode 0600 and
directories 0700. Local-v1 transport PEM is allowed only in that private
state; other secret stores require their own decision.
Scan every publication surface and fail closed on inaccessible input.

## Consequences

Convenient raw diagnostics and stateful browser surfaces are excluded.
Sanitized public receipts contain only approved status, versions, and hashes.

## Verification

`docs/PUBLIC_PRIVATE_BOUNDARY.md`, context privacy checks, source scanners, and
the incident runbook define enforcement.
