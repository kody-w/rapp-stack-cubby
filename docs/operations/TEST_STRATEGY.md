# Test strategy

## Layers

| Family | Purpose |
|---|---|
| `tests/runtime/` | ABI, registry, provider normalization, storage containment, tool loop, server surface, CLI, and app lifecycle |
| `tests/agents/` | Source inventory, manifests, focused actions, mutability controls, security mapping, memory, and RAPPID behavior |
| `tests/controller/` | Source policy, loadout, exact-tree manifest, guarded lifecycle, process ownership, chat, and controller contract |
| `tests/protocols/` | Canonical JSON, P-256 vectors, envelopes, keys, replay, restart, and concurrency |
| `tests/imessage/` | Exact config/privacy, RPC framing and ambiguity, lease/cursor/outbox recovery, owner policy, global-controller evidence, CLI/installer/service safety, agent contract, and tutorial |
| `tests/pages/` | Static API parity, HTML/link/project paths, JS-disabled content, privacy/browser exclusions, accessibility, prompts, workflow pins, release truth, and determinism |
| `tests/test_context.py` | Context index/schema/DAG/link/example/status/privacy closure and CLI summary |
| root tests | path safety, CLI behavior, and repository verification |

Tests use only `unittest`, synthetic data, loopback sockets, scripted
providers, and repository-scoped temporary directories. They must not access
the network, user home, Messages data, Keychain, or real credentials.

## Change discipline

1. Add the smallest negative and positive test at the affected boundary.
2. Run the related family in one command.
3. Run `scripts/context-check.sh` when contracts, status, docs, or schemas move.
4. Run `scripts/check.sh` before handoff.
5. Report tests and checks separately; a unit count is not a release gate.

Security tests prove rejection, containment, exact matching, bounded
resources, signed idempotent replay, and fixed public errors. The iMessage
family proves deterministic mocked behavior; live enrollment remains a
separate attestation gate. Packaging and the static publication handoff have
full local vectors; live release/publication proof remains external.
