# RAPP end to end

**Audit basis:** antecedent direct audit of 299 repositories on 2026-07-12,
refreshed by authenticated direct API and exact-head inspection to **307
repositories** at existence cutoff **2026-07-13T08:57:20.399000Z**, with
inventory and heads observed over the bounded non-atomic window
**2026-07-13T09:07:31.710577Z–2026-07-13T09:09:18.274404Z**.
**Reading rule:** repository-local evidence at the audited head outranks a
repository title, a “canonical” label, a mirror, an index, or an aspiration.
`STACK_LOCK.json`, `PROVENANCE.json`, and `CONFORMANCE.md` then narrow that
evidence into this project's profile. Nothing in this document is a present
conformance claim.

> **Local-context authority:** The direct antecedent synthesis is preserved in
> full and extended with eight new-repository inspections and twelve completed
> exact-head drift reviews, but future work does
> not need those repositories as
> working context. Begin with [`AI_CONTEXT.md`](AI_CONTEXT.md), then the local
> [`SYSTEM_MODEL`](docs/canon/SYSTEM_MODEL.md),
> [`IMPLEMENTATION_STATUS`](docs/canon/IMPLEMENTATION_STATUS.md), and
> [`GAP_REGISTER`](docs/canon/GAP_REGISTER.md). Domain contracts live under
> `docs/canon/`, decisions under `docs/decisions/`, operations under
> `docs/operations/`, and machine profiles under `schemas/`.
> `CONTEXT_INDEX.json` is the deterministic map. Current tested code/contracts
> outrank local decisions/profiles, which outrank this direct evidence; any
> external link is provenance only.

## The shortest accurate explanation

RAPP is not one program. It is an evolving family of conventions and
implementations for making an AI capability into a portable, addressable,
locally runnable organism:

1. a small agent exposes metadata and `perform(**kwargs)`;
2. a brainstem discovers agents, presents them to a model as tools, and carries
   the conversation over `POST /chat`;
3. identity, memory, policy, and other agents make that process a twin;
4. stores and static APIs make source and packages discoverable;
5. cubbies, rapplications, eggs, carts, and distro tools attempt to make it
   portable;
6. twin-chat, Commons events, neighborhoods, estates, fleets, and frames
   connect multiple instances;
7. Azure Functions, Dataverse, Copilot Studio, and Microsoft 365 are the
   progression from local process to enterprise body.

That is the protocol claim. The GitHub reality is a large laboratory, not one
interoperable release. The refreshed census found 39 canonical/load-bearing repositories,
76 implementations or instances, 84 adjacent repositories, 20 legacy
repositories, and 88 unrelated repositories. It found several incompatible
identity, cubby, Moment, event, static-MCP, and egg families; strong isolated
components; many static front doors; and no public repository that proves the
whole path. The coherent system therefore has to be selected, pinned, adapted,
and tested rather than assembled by trusting names.

## Independent-crawl coverage and authority

The source census contains exactly 307 unique, case-insensitively unique
repository names: 302 exact current non-empty heads and five directly reported
empty repositories. Eight local shards cover
`[39, 39, 39, 38, 38, 38, 38, 38]` repositories. Each record preserves its
evidence head separately from its individually timed current observed head.
This is not an atomic historical state: `existence_cutoff` admits repositories
by `created_at`, while inventory pages and heads mean only what their recorded
request/response times observed. Every promoted API field cross-binds to local
raw inventory/head records, and every shard embeds the exact promoted record.
All twelve required C/I or directly load-bearing drift heads were inspected
through exact tree, README, spec/manifest, relevant implementation, license,
and Pages evidence. `rapp-moonshots` and `rappterbook` received explicit
large-drift review. Five later-moving new-repository evidence heads remain
separate post-window drift rather than rewriting their prior inspections.

The audit did **not** infer one repository from another. In particular,
`rapp-spine`, `rapp-map`, `rapp-god`, `RAPP-Bible`, `rapp_docs`, and the grail
were inspected as repositories but were not accepted as evidence for their
targets. The eight checked-in shard ledgers and their digest manifest are
authoritative over those indexes.
Repository-level licensing was recorded separately from README, package, card,
or manifest declarations. Owner permission covers owner-original work only,
not forks, copied/generated/vendored material, dependencies, data, or assets.

The refresh added `rapp-heir`, `rapp-play-pokemon`, `rappterverse-data`,
`static-dynamics-365`, `static-oracle-fusion`, `static-sap-s4hana`,
`static-servicenow`, and `static-zuora`; none was removed or renamed. All
eight have exact-head category inspections in the local audit manifest.
This `rapp-stack-cubby` repository was absent from the public inventory and is
the separate local product node, not a 308th audited antecedent.

## Names that must not be collapsed

| Terms | Actual distinction |
|---|---|
| **Grail pointer vs local runtime** | `rapp-installer@5fbde17` is a behavioral pointer only. This project's runtime is newly authored clean-room code under `src/rapp_stack_cubby/runtime`; Microsoft aibast is a pinned behavioral/license reference only and supplies no adapted runtime source. |
| **RAPP distro vs OpenRappter** | `RAPP` is the species-root/reference distro: protocol corpus, agent ABI, brainstem copy, cave/cubby/egg machinery, and userland. `openrappter` is a separate Python/TypeScript/Swift consumer runtime and the strongest initial iMessage implementation. It is useful evidence, not a synonym or selected source bundle. |
| **Agent vs skill** | A RAPP agent is executable runtime code with the BasicAgent ABI and is discovered as an independent tool. A skill is host guidance/integration material (for example Claude or Copilot Studio authoring content) and does not become a RAPP agent merely by being named a capability. This CUBBY keeps every internal `*_agent.py` as an agent; it does not flatten agents into controller skills/tools. |
| **Twin-chat alias vs neighborhood specification** | `rapp-twin-chat/1.0` is the inner message envelope owned by the pinned `rapp-neighborhood-protocol/1.0`; it is not a separate complete neighborhood protocol. A neighborhood also defines pairing, transport, sealing, membership, lifecycle, and event handling. |
| **Fleet Leviathan vs wrapped-organism Leviathan** | `leviathan` coordinates many brainstem bodies as one fleet. The wrapped-organism family packages one operator's many cells/estates as one being and distributes `.leviathan.egg` artifacts. They stack conceptually but are different protocols, code, and trust boundaries. |
| **Cubby vs rapplication vs egg vs cart** | A cubby is a deterministic build/storage boundary; a rapplication is the executable application bundle of agents and metadata; an egg is a transport/recovery container; a cart is a normative one-gesture user experience contract. Shared extensions do not imply compatibility. |
| **Pages front door vs runtime** | Pages can publish documentation, catalogs, cards, static APIs, install links, and browser demos. It does not host the local Python brainstem, prove a twin is online, isolate project browser storage, or make a landing page an implementation. |
| **Local controller vs child twin** | The controller selects, builds, hatches, supervises, and aggregates. A child twin has its own workspace, virtual environment, identity/key references, agents, state, and `/chat`. A child is not a tool flattened into the controller and must not share its mutable agent directory. |

## Concise component model

| Component | Responsibility | Strong direct evidence | Reality |
|---|---|---|---|
| Identity authority | Mint and compare RAPPIDs; express lineage and ownership | `rapp-eternity`, `rapp-estate`, `rapp-zoo`, `twin` | Multiple live widths, canonicalization rules, and duplicate display namespaces are incompatible. |
| Agent ABI and registry | Define one-file agents, validate, index, install | `RAPP`, `rapp-installer`, `RAR`, `rapp-agents` | The minimal ABI is real; registry hashes and installation trust are not uniformly connected. |
| Brainstem/runtime | Discover tools, gather context, call model, execute agents, answer `/chat` | `rapp-installer`, `RAPP`, `aibast-agents-library`, `openrappter`, `rapp-brainstem-sdk` | Several runnable copies exist. Older/current copies differ materially in wire and security. |
| Memory | Session, user, shared, consent-projected, local/Azure persistence | `CommunityRAPP`, `openrappter`, ancestral Agent 365 repositories | Useful implementations exist, but identity authorization and consent behavior are not uniformly proven. |
| Discovery/stores | Publish source agents, rapplications, senses, static APIs | `RAR`, `RAPP_Store`, `RAPP_Sense_Store`, `rapp-static-apis`, `rapp-mcp` | Real indexes and workflows exist. Mutable URLs, incomplete validation, and two incompatible static-MCP schemas remain. |
| Packager/hatcher | Build cubby/rapplication/egg and materialize a twin | `RAPP`, `rapp-distro`, `rapp-zoo`, `twin`, `twin-egg-hatcher`, `rapp-egg-hub` | Many formats exist; several hatchers lack signature, containment, size, or publisher checks. |
| Twin supervisor | Mint, hatch, boot, chat, stop, freeze, restore, fan out | `RAPP-Network`, `twin`, `rapp-vscode-extension` | Implemented locally, but port ownership, process identity, isolation, and schema drift require hardening. |
| Trust/messaging adapter | Pair, sign, journal, enforce consent and transport policy | `rapp-neighborhood-protocol`, `rapp-messaging`, `openrappter` | Specifications are broader than implementations. OpenRappter has valuable durable iMessage state but is not behaviorally conformant. |
| Neighborhood/relay | Carry signed/sealed events among twins and persist rooms | `rapp-commons`, `rapp-sealed`, `rapp-vneighborhood`, `rapp-resident` | Browser and relay code exists; identity formats, kinds, replay, PIN strength, and signature checking disagree. |
| Estate/metropolis | Discover an operator's twins and aggregate neighborhoods | `rapp-estate` | The spec itself records that the live estate uses nonconformant legacy IDs. |
| Fleet/frame | Coordinate many bodies and tolerate intermittent links | `leviathan`, `rapp-frame-net`, `rapp-moonshots` | Fan-out and frame loops exist, but legacy fleet RCE and frame-authentication/ingestion defects block trust. |
| Enterprise body | Move local behavior to Azure, Dataverse, Copilot Studio/M365 | `CommunityRAPP`, `rapp-dataverse`, `rapp-oneclick-deploy` | Concrete deployment paths exist; mutable imports, weak caller identity, and demonstrator-only agents remain. |
| Experience/operations | Desktop/editor/browser UX, observability, evolution, release/rollback | `ez-rapp`, `rapp-vscode-extension`, `racon`, `rapp-spine`, `rapp-god`, `double-jump`, `rapp-postflight` | Many useful surfaces exist, but presentation is frequently ahead of implementation. |

## Artifact model

The public ecosystem uses the same words for unlike artifacts. This project
does not try to normalize every historical family. Its one exact chain is:

```text
pinned source repo
  -> rapp-cubby/1.0
  -> rapp-application/1.0
  -> brainstem-egg/2.3-cubby
  -> rapp-installed-twin/1.0
```

1. **Pinned source** is this complete reviewed product tree plus the six
   explicitly enumerated MIT OpenRappter iMessage adaptations and locked
   binary dependencies. The runtime itself is original clean-room code. A
   repository URL or branch is not source identity.
2. **Cubby** is this profile's deterministic build boundary. It carries public,
   reviewed inputs and manifests, never runtime memory, keys, journals,
   identifiers, conversations, credentials, or installed state.
3. **Rapplication** is the application assembly. The top-level controller is
   the only streaming agent; internal `*_agent.py` files remain independently
   discoverable agents.
4. **Cubby egg** is the offline transport/recovery form. Every member and the
   whole artifact are hashed; extraction rejects traversal, escaping links,
   special files, unsupported nesting, and resource-limit violations.
5. **Installed twin** is not a publishable artifact. It owns a dedicated
   workspace, Python virtual environment, identity/key references, journals,
   memory, and process state.

Other public families are reference data only: `rapp-commons-cubby/1.0` in
`double-jump` conflicts with `rapp-cubby/1.0` in `lisppy`; `.egg` may mean a
JSON pointer, JSON descriptor, hologram cartridge, RACon ZIP, twin backup,
brainstem package, or Leviathan organism. `rapp-cart/1.0` is a useful
one-gesture UX promise but its repository is specification-only. A cart is not
silently substituted for any stage above.

## Runtime model

The observed BasicAgent family has a small stable center:

- `name`;
- `metadata.description`;
- `metadata.parameters` as JSON Schema;
- `perform(**kwargs)`;
- optional `system_context()`;
- conversion to a model tool.

A brainstem reloads/discovers agents, gathers system context, asks the model
for tool calls, invokes `perform`, and returns an answer. The strongest current
behavioral implementation is `rapp-installer` 0.6.16, whose direct evidence
also shows loopback defaults, Host checks, request limits, and a broad
cross-platform preflight suite. It nevertheless supports more routes, remote
imports, and request-time package installation than this profile permits.
`RAPP` remains the species-root reference, but its current `/chat` response
omits fields required by its own frozen wire and its shipped runtime has
dangerous broad-bind/import/auto-install behavior.

The selected runtime is therefore an **original clean-room implementation**
using normalized behavior/contracts and local tests. Microsoft is
behavioral/license reference only; no Microsoft or owner-copy runtime file is
adapted. It exposes one capability endpoint: loopback `POST /chat`. The separate
global controller accepts only strict bearer-authenticated deterministic
controller routes; the bridge verifies a fresh HMAC endpoint challenge before
sending the bearer or owner content. Child ports are signed-only.
Privileged control and all twin traffic require paired signatures, exact
identity/epoch binding, replay acceptance, and an enumerated operation that
cannot execute code. No `/eval`,
`/api/agent`, remote console, arbitrary import, auto-pip, mutable download, or
unauthenticated mutation survives the adaptation.

The global controller and each child use the same narrow wire but different
state roots. Only the controller streams. Children are isolated runtimes, not
in-process controller tools.

## Trust model

RAPP's public protocols mix three different trust ideas:

1. a content-addressed RAPPID that may be PKI-free;
2. repository/collaborator ownership;
3. a cryptographic transport identity.

Those ideas are not interchangeable. This profile keeps source `rappid.json`
as immutable public product/rapplication identity. Each egg hatch, repository
hatch, or verified adoption mints a distinct private instance RAPPID from the
product identity, source revision/tree, and an unpublished local random birth
nonce. Only an instance RAPPID can run or pair with the separately generated
P-256 transport key. A local binding says which public key may speak for which
instance RAPPID. Local v1 keeps its private key only in explicit mode-0600
controller/child state; broader profiles require a new storage decision.

Twin requests use a complete `rapp-twin-chat/1.0` body inside
`rapp-commons-event/1.0`. Canonicalization is the documented project-owned
bounded JSON subset with only the top-level `sig` omitted. Received signed
wire bytes must already equal that encoding.
Requests and responses use strict PKCS#8 keys and low-S ECDSA
P-256/SHA-256 P1363 signatures. The durable journal key is
`(rappid, paired key id, key epoch, nonce)` and stores the canonical request
digest, owner lease, claim/dispatch phase, and signed result. It is fsynced
before dispatch or side effect. An abandoned pre-dispatch claim may be
reclaimed; a dispatch marker becomes a signed terminal ambiguous rejection.
An identical completed duplicate gets the prior signed result; the same nonce
with different bytes fails. The response swaps the bound participants and
cites request nonce, digest, and epoch.

Authorization is narrower than signature validity. Signed input still cannot
request shell, eval, imports, package installation, arbitrary files, or remote
administration. Messages, memories, identifiers, receipts, keys, pairings,
and installed state remain private even when signed or encrypted. Public
artifacts and Pages contain none of them.

## Network model

The common data plane is either local `/chat` or an append-only event:

- **local owner:** loopback HTTP to one installed runtime;
- **twin:** signed twin-chat inside a signed Commons wrapper;
- **iMessage:** supervised `imsg` JSON-RPC translates one enrolled owner DM
  into the same signed twin path;
- **neighborhood:** a transport carries signed and optionally sealed Commons
  events among admitted twins;
- **resident:** an Azure relay persists room events but must not become the
  identity authority;
- **estate/metropolis:** static discovery groups twins and neighborhoods;
- **project network:** a local controller boots project twins and fans out
  `/chat`;
- **fleet:** Leviathan routes one command to multiple brainstem nodes;
- **frame-net:** GitHub raw data is the slow read medium and Issues are the
  return channel for intermittently connected nodes;
- **kite:** browser/CDP/PeerJS bridges are operator tools, not an authenticated
  replacement for signed twin transport.

The broader network is mapped but not attested by CUBBY v1. V1 has no LAN,
WAN, relay, Pages-runtime, WebRTC, MCP, fleet, or cloud conformance claim.

## Protocol claim versus implementation reality, plane by plane

| Plane | Protocol claim | Direct implementation reality | CUBBY decision |
|---|---|---|---|
| Substrate | Git repositories and Pages can be stores, APIs, front doors, and the network's backup. | Static APIs, catalogs, raw JSON, Issues/Discussions, Actions, and 111 Pages-enabled repositories are real. All project Pages share one browser origin; several apps store credentials, keys, identity, or location there. | Git is source/publication substrate only. Pages, if added later, is static and credential-free; it never contacts loopback or stores private state. |
| Governance | A grail, canon, map, Bible, god, docs, and spine identify authority and drift. | They disagree, omit repositories, use mutable links, and sometimes describe unpublished targets. The spine itself reports 35/59 required protocol materials unresolved. | Direct pinned evidence first; this release's lock/profile selects behavior. Indexes are cross-checks only. |
| Identity | `rapp-eternity` offers a location-independent 64-hex content address and optional sovereignty keys. | UUID, 16-, 32-, 64-, 128-bit and 256-bit forms coexist. `twin` and `kody-w-twin` expose different identities at the same display namespace; estate data violates its own current rule. | One explicit RAPPID fixture plus an independent paired P-256 transport key; no implicit migration. |
| Kernel/runtime | One stable agent ABI and `/chat` can support many substrates without breaking userspace. | The ABI center is real. Wires and routes drift; several copies expose unauthenticated import/eval or broad CORS/binds. The installer is behavioral reference only. | Original clean-room project runtime; Microsoft is behavioral/license reference only; loopback and one capability route only. |
| Agents | A single `agent.py` can be registered, stacked, and used everywhere. | RAR has serious validation/CI, but installer paths do not always consume recorded hashes and approved code executes without a sandbox. “Skills” and prompt packs are often mislabeled as runtime agents. | Preserve the BasicAgent ABI and independent child agents; fixed build-time dependency set and exact bytes. |
| Memory/storage | Hippocampus memory can move from local files to Azure while consent controls projection. | CommunityRAPP has real local/Azure memory and tests. OpenRappter has durable iMessage state, but part of its trust projection is unreachable and consent capabilities are incomplete. GUID-based cloud ancestors do not authenticate the user represented by a GUID. | Local private state for v1, minimum authorized projection, mode 0600; cloud memory is reference-only. |
| Distribution | Cubby, rapplication, egg, cart, distro, store, and hatcher form one portable chain. | Each named piece exists somewhere, but schemas and `.egg` meanings conflict. Several hatchers accept untrusted paths, unsigned manifests, mutable branches, or unbounded archives. `rapp-carts` has no implementation. | One exact four-transform chain, SHA-256 at every node, strict extraction, no shortcut or compatibility claim. |
| Twin lifecycle | A controller can mint, plant, hatch, boot, chat, stop, freeze, and recover twins. | `RAPP-Network`, `twin`, VS Code tooling, and hatchers implement substantial pieces. Process/port ownership, workspace paths, signatures, and isolation are inconsistent. Many planted twins are static mirrors only. | Dedicated workspace/venv/identity per child, verified process ownership, signed control, deterministic freeze/restore. |
| Chat/network | Every capability rides `/chat` or a signed append-only event. | `/chat` is widely implemented, but request/response fields drift. Kite and legacy twin-chat accept unverified senders/replay. | Exact local `POST /chat`; exact signed request and response envelopes for twin traffic. |
| Messaging | Trust, consent, durable delivery, iMessage, groups, and memory can profile the existing wire. | `rapp-messaging` CI checks structure rather than behavior. OpenRappter implements WAL, leases, staged outbox, restart recovery, and echo suppression, but misses required trust/consent details and FIFO proof. | Reference the pinned spec; implement only one owner DM through a pinned `imsg`; no group or SMS. |
| Neighborhood/estate/metropolis | Signed/sealed events compose private rooms, global Commons, estates, and a metropolis. | WebCrypto sealing and browser/relay clients exist. Six-digit PINs are weak, some readers never verify signatures, replay rules are incomplete, event kind allowlists conflict, and estate IDs are stale. | Contracts and test vectors are retained; network deployment is outside v1. Twin traffic is signed even on loopback. |
| Fleet/Leviathan | One mind can coordinate many bodies; a wrapped being can move among estates. | Fleet fan-out/MCP and wrapped eggs are real separate implementations. Legacy `/api/agent/<Agent>` is intentional unauthenticated RCE; Leviathan hatchers lack origin/path checks. | Keep the homonyms separate. Fleet and wrapped-organism paths are reference-only and prohibited from v1 runtime. |
| Cloud/enterprise | A local agent can progress through Azure Functions, Dataverse, Copilot Studio, Teams, and M365. | CommunityRAPP, Dataverse CLI/static twin, and one-click import are concrete. Dynamic Azure Python, caller-supplied GUID identity, mutable solution URLs, and browser/token risks remain. Some browser agents only say “would run.” | Describe and test export boundaries later; no cloud conformance or credential-bearing Pages in v1. |
| UX/observability/evolution | Desktop/editor/RACon make agents simple; map/god/spine show drift; Moments and evolutionary loops improve organisms. | Electron, VS Code, Pyodide, Pages, Hologram, Double Jump, Coliseum, and observability dashboards exist. Some are landing pages, unsafe remote loaders, or incompatible Moment validators. | V1 UX is local chat plus supervised owner iMessage. Observability is redacted local metrics and sanitized release receipts. |
| Security/release | Pins, digests, tests, preflight, postflight, provenance, and rollback make releases trustworthy. | The best pieces are split across installer preflight, Store validation, egg-hub PII checks, postflight rollback, and impossible-product build-once provenance. Many artifacts remain unsigned or mutable. | Combine the strongest patterns, but block build/release until every lock value, source file, dependency, digest, key fixture, scanner, and attestation is resolved. |

## Control and data flows

### Control plane

1. Resolve authority and exact commits.
2. Review every selected source file and dependency; preserve notices.
3. Verify the original clean-room runtime provenance boundary and local tests;
   copy or adapt no external runtime source.
4. Reproducibly build cubby, rapplication, and egg; bind every digest.
5. Hatch only into a new isolated workspace and virtual environment.
6. Pair a child RAPPID with a local P-256 public key.
7. Start, health-check, supervise, and stop the exact child process.
8. Publish only sanitized source/artifacts/receipts; rollback or revoke the
   whole release identity after a failed post-publication check.

### Data plane

1. Local input enters loopback `/chat`.
2. The controller projects only allowed context, selects real agents, and
   returns a response.
3. Twin input arrives already canonical, then is signature/epoch checked,
   identity-bound, claimed, and dispatch-marked before provider or tools.
4. Agent output is journaled and signed before delivery.
5. iMessage and future neighborhood/fleet transports translate at the edge;
   they do not create alternate agent APIs.
6. Memory receives only policy-authorized facts and stays under the private
   state root.

## Eight canonical end-to-end sequences

### 1. Fresh local agent

**Claim:** drop in one `*_agent.py` and immediately talk to it.
**Reality:** RAR and the brainstem prove discovery and invocation, but remote
installers and request-time dependencies weaken byte identity.

1. Select a reviewed single-file agent implementing the BasicAgent ABI.
2. Record its source blob, license, destination, and SHA-256.
3. Package it through cubby and rapplication without flattening it into a
   controller tool.
4. Build and verify the cubby egg.
5. Hatch into a dedicated child environment with fixed dependencies.
6. Start on loopback; call only `POST /chat`.
7. Confirm the agent remains independently discoverable and callable.

### 2. Public rapplication publish and hatch

**Claim:** Store/Pages discovery makes a rapplication installable.
**Reality:** RAPP Store has real staging, traversal/bomb checks, approval, and
promotion, but some federation URLs remain branch-mutable.

1. Publish a signed/digested rapplication manifest and immutable artifact URL.
2. A static catalog indexes metadata and the exact release digest.
3. The local controller downloads bytes without executing them.
4. It verifies publisher policy, full digest, schema, size, and provenance.
5. It wraps/obtains the exact `brainstem-egg/2.3-cubby` artifact.
6. The hardened hatcher validates every member and installs atomically.
7. The installed manifest is compared with the lock before first boot.

### 3. Global brainstem to isolated twin

**Claim:** a global brainstem can hatch many project twins.
**Reality:** `RAPP-Network` and several hatchers implement much of this, but
legacy global agent directories, unsafe paths, and port-based process identity
break isolation.

1. The local controller selects a pinned rapplication and public product identity.
2. It builds, hatches, verifies, and adopts the exact artifact chain.
3. It allocates a child-only workspace, verified venv binding, state root,
   private instance RAPPID, key
   reference, port, and process receipt.
4. It preflights the exact model, records starting PID/PGID/OS-start identity,
   boots signed-only, and proves process plus `/health` instance identity.
5. Controller-to-child operations use signed twin-chat and the replay journal.
6. Only the controller streams; all child `*_agent.py` files remain agents.
7. Stop targets the recorded process identity, never an arbitrary port owner.

### 4. Owner iMessage to rapplication to reply

**Claim:** iMessage is just another transport over `/chat`.
**Reality:** OpenRappter supplies the best initial implementation—read state,
WAL, leases, durable outbox, unknown-send recovery, and echo suppression—but
the full messaging vectors are not proved.

1. A pinned, hash- and Developer-ID-verified `imsg` process reports a new
   direct message through supervised JSON-RPC.
2. Before model access, the adapter verifies exact chat/account/owner fields,
   rejects groups/other principals/SMS/unsupported critical types, and
   persists a stable HMAC-derived event idempotency key.
3. It challenge-authenticates the global controller, sends the exact persisted
   deterministic route with a bearer, and the controller creates the signed
   Commons/twin-chat request.
4. The twin verifies key/RAPPID/destination/time/nonce, fsyncs the journal, and
   dispatches the target rapplication.
5. Policy selects the minimum memory projection; agents produce a result.
6. The twin journals and signs a response bound to the request nonce.
7. The adapter verifies request/result/response hashes plus signed
   instance/epoch bindings, stages the reply, sends once, preserves ambiguous
   delivery without resend, classifies echoes transactionally, and advances
   state atomically.
8. Identifiers, content, cursors, journals, and receipts never enter public
   artifacts, Pages, logs, or process arguments.

### 5. Neighborhood sharing

**Claim:** admitted twins can share signed/sealed events through peer or
resident transports and aggregate into estates/metropolis.
**Reality:** the codec, browser rooms, and Azure resident exist, but weak PINs,
missing reader verification, incompatible event kinds, and stale estate IDs
prevent a general conformance claim.

1. Two twins exchange authenticated public keys and bind them to RAPPIDs.
2. The sender forms twin-chat or an allowed Commons event, signs it, and, when
   confidentiality is needed, seals the body with an independently agreed
   channel key.
3. A peer transport or resident relays opaque bytes; it is not trusted to
   assert sender identity.
4. The receiver checks signature, binding, freshness, nonce, kind, size, room
   policy, and optional seal before use.
5. Accepted data is journaled and disclosed only to the permitted audience.
6. Estate/metropolis indexes advertise discovery metadata, not private state
   or proof that a runtime is online.

This is a mapped future path, not part of the v1 attestation.

### 6. Fleet coordination

**Claim:** Leviathan lets one mind coordinate many bodies over fleet chat.
**Reality:** controller fan-out, direct-node handlers, deployment, shell, and
MCP exist; the legacy agent endpoint is unauthenticated fleet-wide RCE.

1. A controller enumerates explicitly enrolled node RAPPIDs and paired keys.
2. It signs one bounded fleet-chat operation per destination.
3. Each node verifies and journals the request, then maps only the allowlisted
   operation onto local `/chat`.
4. Nodes return independently signed, nonce-bound results.
5. The controller verifies, aggregates, and reports partial failure without
   retrying completed side effects.
6. Shell/deploy/import and the legacy `/api/agent/<Agent>` route are excluded.

The wrapped-organism path is separate: factory/wrapper/Leviathan Hub packages
one multicellular being; it does not authorize fleet control. Neither path is
enabled in CUBBY v1.

### 7. Cloud progression

**Claim:** the same agents progress from local brainstem to Azure memory,
Dataverse, Copilot Studio, Teams, and Microsoft 365.
**Reality:** CommunityRAPP exposes real Azure Functions and local/Azure
storage; `rapp-dataverse` defines deterministic Dataverse encoding and a
service-to-service hatcher; one-click deploy performs real authentication,
conversion, discovery, and solution import. This is not one proven chain.

1. Begin with a passing local rapplication and explicit public/private field
   classification.
2. Export only portable agent/schema/config inputs—never local identity,
   memory, journals, or credentials.
3. Deploy a pinned Azure Function package with managed authentication and
   fixed code; do not load mutable Python from storage.
4. Encode approved public/application records into Dataverse over HTTPS with
   least-privilege service identity.
5. Generate and checksum the exact Copilot Studio/Power Platform solution.
6. Import through a pinned workflow and verify behavior in M365/Teams against
   the same contract vectors.
7. Keep cloud identity, memory authorization, and release rollback explicit.

This progression remains reference-only for v1.

### 8. Disaster recovery and offline egg

**Claim:** “the network is the backup” and an egg can restore a being.
**Reality:** twin and egg hubs implement backup/hatch round trips, but current
hatchers often trust the egg's own manifest, unsafe workspace names, mutable
downloaders, or unsigned bytes.

1. Quiesce the installed twin and snapshot only declared portable public
   application inputs plus separately encrypted/authorized private backup
   material; never publish private state.
2. Build a deterministic egg and signed manifest with bounded members.
3. Verify the egg from offline trust roots before extraction.
4. Restore into a new empty workspace with networking disabled.
5. Reject paths, links, special files, digest mismatch, unknown schema,
   dependency drift, identity/key mismatch, and decompression excess.
6. Compare the restored installed manifest, replay journal state, and release
   identity before boot.
7. Run local `/chat`, signed duplicate/recovery, and private-state permission
   tests before replacing the failed twin.

## End-user experience layers

The ecosystem exposes several different experiences:

- **terminal/local browser:** the brainstem's chat and health surfaces;
- **desktop:** `ez-rapp` supervises a local install, but currently follows
  mutable installers;
- **editor:** the VS Code extension boots and controls twins, but has unsafe
  HTML rendering and no tests;
- **cartridge console:** RACon gives a compelling drop/fetch-and-run Pyodide
  demo, but lacks safe ZIP/digest/signature enforcement;
- **Pages front door:** cards, QR/PIN joins, demos, stores, catalogs, and
  planted identities; often a useful invitation, never proof of a runtime;
- **social/world:** Commons, Rappterbook, Rappterverse, MMO/simulation and
  Moment/Hologram surfaces;
- **messaging:** the owner speaks in an existing direct conversation and sees
  one reply without ports, repositories, or agent internals;
- **enterprise:** Copilot Studio/Teams/M365 presents the capability within
  managed work.

For this CUBBY, the supported interactive experience is intentionally
narrower: local chat plus one enrolled owner-only iMessage conversation. A
checked static Pages handoff is implemented without interactive runtime
authority. Desktop, editor, neighborhood, fleet, and cloud experiences remain
mapped integration points, not implied release claims.

## Collision, gap, and failure register

### Incompatible families

- **RAPPID:** UUID, shortened hashes, 32-hex planted IDs, 64-hex eternity IDs,
  legacy 128-bit IDs, v3 key fingerprints, differing lineage, and duplicate
  owner/slug display namespaces.
- **Cubby:** `rapp-commons-cubby/1.0` (`double-jump`) and `rapp-cubby/1.0`
  (`lisppy`) have different fields and no shared machine schema.
- **Moment:** Double Jump rejects extra keys that Hologram emits for public key,
  birth, and location proofs.
- **Egg:** JSON pointers, plaintext descriptors, ZIP cartridges, executable
  packages, twin backups, holograms, brainstem eggs, and Leviathan eggs share
  a suffix but not a trust or extraction contract.
- **Static MCP:** Python and JavaScript implementations both claim
  `rapp-static-mcp/1.0` while using different catalogs, protocol dates, and
  full- versus 48-bit hash checks.
- **Chat:** old frozen wires require `assistant_response`, `response`, user
  identity, and mode echoes; current RAPP/OpenRappter handlers emit narrower
  responses. Some twin docs send `messages`, while implementations expect
  `user_input`.
- **Commons/neighborhood:** identity key encoding, event kinds, replay,
  sealing, and reader verification differ among Commons, resident,
  neighborhood spec, and deployed rooms.
- **Canonical JSON:** Eternity's Unicode-code-point ordering and twin's RFC
  8785/UTF-16 ordering can differ for non-BMP keys.

### High-impact security failures found directly

- Broad binds plus wildcard CORS plus unauthenticated Python import/auto-pip in
  historical/current copies create browser-to-host or LAN code execution.
- Leviathan's legacy direct-agent route is explicitly unauthenticated RCE.
- Multiple hatchers accept manifest-controlled workspace/archive paths,
  unsigned self-asserted hashes, unbounded ZIPs, or LLM-triggered global
  installation.
- Mutable `main` downloads and `curl | shell` appear in planted front doors,
  desktop/editor installers, distros, hatchers, and enterprise handoffs.
- GitHub Pages project paths do not isolate localStorage or IndexedDB. A
  credential-bearing page, key-bearing neighborhood, location app, basket,
  and executable app catalog share one origin.
- Six-digit fixed-salt neighborhood PINs permit offline guessing; several
  clients render events without verifying signatures or sender/key binding.
- Frame-net accepts truncated content hashes, does not verify optional
  signatures, permits rollback, and has a producer/ingester schema mismatch.
- Cloud ancestors treat a caller-supplied GUID as memory identity or execute
  Python loaded from Azure storage.
- SMS examples do not prove iMessage trust and may omit provider-signature
  validation; SMS fallback is therefore explicitly disabled.

### License and provenance concerns

The census found only 105 parsed root-license labels, 156 reported-absent
roots, 36 absent roots with some declaration elsewhere, and two conflict
cases. Notable risks include:

- `rapp-installer`: behaviorally authoritative but no root license;
- `RAPP`: mixed PolyForm/Creative Commons/reference content;
- `twin`: mutually conflicting root, README, card, and draft identity license;
- `rapp-commons`: PolyForm Noncommercial root despite MIT prose;
- `rapp-zoo` and `rapp-egg-hub`: all-rights-reserved material;
- copied/forked Microsoft, tutorial, SDK, and upstream repositories whose
  owner-account location does not make them owner-original;
- package/card/README license claims without root text;
- generated archives, assets, fonts, data, and vendored code not cleared by a
  repository-level label.

Consequently, zero external files are currently cleared for shipping.
Reference, pointer, and protocol use do not authorize copying. Every selected
file needs its upstream blob, authorship, license, destination, attribution,
and review recorded before the build can proceed.

### Deprecated or presentation-only paths

`rapp-installer-canary`, `rapp-installer-dev`, old version selectors,
`RAPP_Desktop`, `rappbook-admin`, `RAPP_Hub`, `rapp-store-archive`, old
Copilot-Agent-365 derivatives, and static Rappbook worlds are legacy.
RappterMMO, RappterNest, and RAPPsquared are primarily landing/demo surfaces,
not the engines their names imply. Planted `pkstop-*`, Heimdall, Lumen, Tide,
Echo, and sim-demo repositories may carry identity or frozen code, but a
front door or mirror is not the current runtime.

## Canonical-spine cross-check (non-authoritative)

Only after completing the 299-repository antecedent direct crawl was the
canonical spine used as a cross-check. The later direct refresh contains 307
repositories and does not grant the spine additional authority. Its generated
coverage reports 47 repository nodes, 59
protocol entries, 53 structured issues, and only 24/59 exact required protocol
sources; 35 required materials remain unresolved.

The cross-check was useful for vocabulary and for making the two Leviathan
senses explicit, but direct evidence changed the picture:

1. It covers 47 repository identities, not the refreshed account's 307
   repositories.
2. Seven repositories classified load-bearing by direct inspection are absent
   from its repository nodes: `racon`, `rapp-kited-twin`, `rapp-postflight`,
   `rapp-static-mcp`, `rapp-zoo`, `rappter-distro`, and `twin`.
3. It references `rapp_leviathan_factory` and `wrap_leviathan`, which were not
   present in the 299-repository antecedent census (or the 307-repository
   refresh) and are described by the spine
   itself as unpublished/unresolved.
4. It presents `rapp-installer` as the grail/kernel of record; direct licensing
   and the project contract reduce it to a behavior-only pointer. The project
   runtime is original clean-room implementation; Microsoft remains a
   behavioral/license reference only.
5. It describes OpenRappter mainly as an incomplete parity target; direct
   inspection also found a substantial cross-language runtime and the
   ecosystem's strongest initial iMessage state implementation.
6. It does not expose the second incompatible `rapp-static-mcp/1.0`, the
   RAPPID/cubby/Moment/egg incompatibilities, or all copied vulnerable
   brainstem instances.
7. Its coherent neighborhood narrative hides deployed reality: weak PINs,
   unverified readers, conflicting event kinds, and resident/identity
   contradictions.
8. It indexes RAR, Store, Sense Store, Commons, estate, frame-net, and cloud
   projects, but direct inspection supplies the material security,
   implementation, and licensing qualifications recorded above.

No spine classification or edge overrides `SOURCE_CENSUS.json` or a shard's
repository-local finding.

## The coherent profile this CUBBY will implement

The exact target is
**`rapp-stack-cubby/macos-arm64-python311/1.0`**:

- arm64 macOS 26.5.1, Python `>=3.11,<3.12`, Git 2.50.1, `gh` 2.88.1,
  Messages.app 26.0, and GitHub Copilot access;
- original clean-room runtime files under `src/rapp_stack_cubby/runtime/`;
  `microsoft/aibast-agents-library@29e49d04e830012494198d746734cb19bc6eea60`
  remains a behavioral/license reference with no copied or adapted runtime
  source;
- `rapp-installer@5fbde17` as behavior-only pointer; `RAPP` and
  `openrappter` as secondary references only;
- the exact source → cubby → rapplication → cubby-egg → isolated-twin chain,
  with deterministic bytes and SHA-256 at every stage;
- one loopback capability route, `POST /chat`;
- only the top-level controller streams, while internal agent files remain
  agents;
- complete signed twin-chat requests and signed nonce-bound responses inside
  the pinned Commons wrapper, paired P-256 keys, and durable exactly-once
  replay/idempotency handling;
- one enrolled owner-only direct iMessage conversation through a pinned,
  verified `imsg`; no group, SMS, attachment, or other-principal processing;
- private state outside the checkout, 0700 directories, 0600 file state,
  local-v1 mode-0600 transport keys, and no private data in source, artifacts, logs, Pages, or
  receipts;
- no dynamic code, request-time install, mutable download, shell/eval, remote
  console, unauthenticated mutation, wildcard CORS, or non-loopback listener.

This is the narrowest profile that still crosses the complete stack: source
selection, agent ABI, hardened runtime, memory/privacy boundary, every
distribution transformation, isolated hatch, parent/child twin semantics,
local `/chat`, cryptographic twin transport, durable messaging, a real
end-user transport, deterministic release, and offline recovery. Expanding to
Pages runtime, LAN, neighborhoods, fleets, or cloud would introduce another
unproved trust boundary; removing iMessage, signed twin transport, artifact
round trips, or isolated hatch would stop short of end to end.

The profile is implemented locally but **release-pending and unattested**.
Development artifact digests and the pinned `imsg` dependency are resolved;
the final exact public commit/signature, full publication scanner,
supported-host/live-owner evidence, public attestations, deployed Pages, and
downloaded-byte equality must all be resolved before any release may claim
this profile.
