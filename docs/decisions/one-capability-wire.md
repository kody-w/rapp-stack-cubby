# ADR: one capability wire

**Status:** Accepted

## Context

Historical runtimes expose drifting chat fields plus import, eval, console,
and direct-agent routes. Multiple agent APIs weaken isolation and review.

## Decision

Use loopback `POST /chat` as the sole capability endpoint. `GET /health` is
operational only. Future signed, messaging, neighborhood, fleet, or cloud
edges must translate to the same local request/response contract.

## Consequences

The attack surface and compatibility target stay small. Edge adapters carry
their own trust and durability work without changing agent semantics.

## Verification

`tests/runtime/test_server.py`, the brainstem chat schemas, and
`docs/canon/CHAT_WIRE.md` define and test the allowed surface.
