# Canonical system model

## Selected model

RAPP is a local-first system for turning independently discoverable AI agents
into an addressable application, running that application in an isolated
brainstem, and eventually moving it through a deterministic artifact chain to
a signed, owner-reachable twin. This repository selects one coherent profile
from a larger, incompatible historical ecosystem.

The selected layers are:

0. **Local product:** this complete repository, represented separately from
   the 307 public antecedent repositories admitted by existence cutoff
   `2026-07-13T08:57:20.399000Z` and observed over the declared non-atomic
   inventory/head window.
1. **Agent:** one reviewed Python file implementing the BasicAgent ABI.
2. **Brainstem:** registry, context collection, model tool loop, and one
   loopback `POST /chat` capability.
3. **Rapplication:** soul plus actual agents and public manifests.
4. **Controller:** the sole streamable agent; hatches and supervises children.
5. **Installed twin:** isolated source/workspace/state/process identity.
6. **Trust edge:** implemented local signed twin-chat and owner-only iMessage
   bridge; private live enrollment remains gated.
7. **Distribution:** future deterministic cubby, rapplication, and egg.

Control flow selects exact source, verifies it, prepares an isolated child,
starts the recorded process, checks health, and stops by process identity.
Child data flow enters signed-only `/chat`, verifies current-epoch canonical
bytes, claims and dispatch-marks the controller envelope, projects bounded
local context, invokes actual agents, and returns a signed response. The
separate global controller remains plain (not twin-signed) but
bearer-authenticated local control; authenticated challenged iMessage ingress
is an additional edge. Loopback itself is not authentication. Future transports
must translate into that wire rather than create a second agent API.

## Boundaries

- Public repository: source, contracts, schemas, synthetic tests, evidence.
- Controller-private root: lifecycle state, locks, receipts, and child roots.
- Child-private root: workspace, data, generated agents, logs, and sessions.
- Transport state: file-backed keys and pairings beneath explicit private
  controller/child roots for local v1.
- External repositories: provenance citations only.

## Status distinctions

| Class | This profile |
|---|---|
| **Profile requirement** | One wire, actual agents, isolated children, exact artifacts, signed trust edges, owner-only messaging, exact-commit release. |
| **Implemented now** | Complete repository product, clean-room runtime, twelve agents, sole controller, guarded lifecycle, signed local twin-chat/replay/key rotation, pinned owner-only iMessage bridge, deterministic package/egg/index/SBOM chain, strict isolated hatch, catalogs, tests, and local context corpus. |
| **Mapped/reference only** | Neighborhoods, estates, metropolis, fleets, wrapped organisms, cloud progression, Pages, and broader transports. |
| **Unsafe/deprecated** | Broad binds, wildcard CORS, remote import, auto-install, shell/eval, mutable downloads, shared mutable agent roots, and name-based compatibility. |
| **Future owner** | `release-attestation`; signed candidate/final scanner execution, live Pages/publication, and iMessage enrollment are operator/release gates, not missing local scanner source. |

## Local authority

Read `IMPLEMENTATION_STATUS.md` for current truth, `GAP_REGISTER.md` for
remaining work, and `../decisions/one-repo-context.md` for why no external
working context is required.
