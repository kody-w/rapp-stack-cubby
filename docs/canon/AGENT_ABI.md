# Agent ABI profile

## Contract

An actual RAPP agent is one independently loadable `*_agent.py` file with:

- one `BasicAgent` subclass;
- literal class `name` and `metadata`;
- `metadata.description`;
- `metadata.parameters` as an object JSON Schema requiring `action`;
- exactly synchronous, undecorated `def perform(self, **kwargs)`; `self` and
  `kwargs` may have type annotations, and the method may have a return
  annotation, but no other parameter or decorator is permitted;
- `perform` returning JSON-serializable text, never a coroutine or awaitable;
- optional bounded `system_context()`;
- one literal `rapp-agent/1.0` manifest with name, semantic version,
  description, actions, capability IDs, mutability, default state,
  provenance, and dependencies.

Bundled source uses `original_new` provenance. AgentFactory output uses the
distinct `generated_local` value and the same scanner, 240-character manifest
description limit, import policy, registry ABI, and required-argument runtime
checks.

The source scanner rejects non-stdlib dependencies except the reviewed ABI
and storage compatibility imports, process/network imports, dynamic execution,
unsafe subprocess calls, secrets, private identifiers, and local paths.
Catalog generation parses source without importing it.

## Runtime semantics

The canonical source validator enforces the exact method shape in the AST:
`FunctionDef`, no decorators, only positional-or-keyword `self`, and only
variadic-keyword `kwargs`. The production registry loads only explicitly
configured local directories, requires exactly one native manifest and one
BasicAgent subclass, and independently confirms that exact synchronous shape
with `inspect.signature(..., follow_wrapped=False)` before construction. It
also enforces manifest/metadata/action and import parity, rejects symlinks and
duplicate names, and converts metadata to model tools.

Direct `AgentRegistry(..., compatibility_mode=True)` remains solely for
explicit legacy fixtures in `tests/`. `RuntimeConfig`, `RuntimeApp`, the CLI,
controller loadout, and product startup have no compatibility-mode path. The
orchestrator may execute at most three tool-call rounds and fails closed if a
tool somehow returns a coroutine or other awaitable; it never awaits it. An
agent failure is returned as bounded tool output; it does not authorize
dependency installation or source mutation.

## Status distinctions

| Class | State |
|---|---|
| **Profile requirement** | Preserve independently discoverable BasicAgent files through packaging and hatch. |
| **Implemented now** | Twelve actual agents, static source inspection, deterministic catalog, action tests, registry/tool-loop tests, package manifest preservation, and Store/egg/hatch round-trip tests. |
| **Mapped/reference only** | Public registries, remote stores, senses, MCP adapters, and third-party agent families. |
| **Unsafe/deprecated** | Treating prompt skills as agents, importing unknown code, request-time `pip`, undeclared dependencies, and flattening children into controller tools. |
| **Future owner** | Public release attestation must repeat the implemented artifact round trip from the final exact commit; no ABI redesign is planned. |

See `../../schemas/agent-manifest.schema.json`,
`../../cubbies/kody-w/rapplications/rapp-stack/twin/catalog/agent-catalog.json`,
and `../../tests/agents/`.
