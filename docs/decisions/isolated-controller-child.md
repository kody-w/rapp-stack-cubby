# ADR: isolated controller and child

**Status:** Accepted

## Context

Shared mutable agent directories, in-process children, and port-only process
identity permit cross-project mutation and unsafe lifecycle actions.

## Decision

The controller selects and supervises; each child owns a dedicated source,
workspace, agent copy, data root, process identity, sessions, and eventual key
binding. Lifecycle mutation is guarded, idempotent, and exact-source bound.

## Consequences

Children consume more local storage but failures and authority are contained.
Stop and purge require recorded identity rather than discovery by port/name.

## Verification

Controller lifecycle/process tests and controller state, receipt, journal, and
tombstone schemas cover the implemented boundary.
