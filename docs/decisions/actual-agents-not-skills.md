# ADR: actual agents, not skills

**Status:** Accepted

## Context

Some ecosystem material calls prompt guidance or host integrations “agents,”
and some controllers flatten child capabilities into controller tools.

## Decision

Every internal `*_agent.py` remains an independently discoverable BasicAgent
with its own manifest and actions. A skill is guidance, not executable RAPP
identity. Only the top-level controller may stream.

## Consequences

Packaging must preserve agent inventory and isolation. Controller authority
does not automatically transfer to a child capability.

## Verification

The source scanner, generated agent catalog, implementation matrix, and
`tests/agents/` prove twelve actual agents; controller tests prove one streamable
top-level agent.
