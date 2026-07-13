# RAPP local context entrypoint

This file is the mandatory first read for a fresh engineer or AI. The
repository is the product: it contains the normalized facts, contracts,
implementation, evidence, decisions, gaps, operations, runtime, actual agents,
controller, package/hatch tools, tests, locks, and notices needed to
understand, improve, build, package, hatch, and operate RAPP end to end.
**Names of external repositories are provenance evidence, not missing working
context. Do not fetch another repository to understand or execute the current
profile.**

The direct public account snapshot contains 307 repositories at the inclusive
existence cutoff `2026-07-13T08:57:20.399000Z`. Inventory and individually
timed heads were captured over the bounded, non-atomic observation window
`2026-07-13T09:07:31.710577Z`–`2026-07-13T09:09:18.274404Z`; a head is a
fact at its own response time, not historical state at the cutoff. All twelve
required drift reviews are complete, while five later-moving evidence heads
are explicit post-window drift. This repository was absent from that
antecedent/public inventory and is represented separately as
`product:local/rapp-stack-cubby`: the complete local product, not a falsely
audited public antecedent. Later publication does not rewrite the frozen
evidence release.

## Exact reading order

1. `AI_CONTEXT.md` — rules, authority, routing, and validation.
2. `docs/canon/SYSTEM_MODEL.md` — selected system and trust boundaries.
3. `docs/canon/IMPLEMENTATION_STATUS.md` — what exists now.
4. `docs/canon/GAP_REGISTER.md` — what remains and who owns it.
5. The task-specific canonical profile selected from the table below.
6. `docs/operations/HANDOFF.md` — end-to-end operational handoff.
7. `docs/operations/REPOSITORY_VERIFICATION.md` — local proof commands.
8. `RAPP_END_TO_END.md` — preserved antecedent synthesis plus the direct
   307-repository bounded-window refresh at existence cutoff
   `2026-07-13T08:57:20.399000Z`.
9. `CAPABILITY_MATRIX.json`, `SYSTEM_GRAPH.json`, `SOURCE_CENSUS.json`,
   `docs/research/AUDIT_MANIFEST.json`, and `PROVENANCE.json` only when
   claim-level audit detail is needed.

`CONTEXT_INDEX.json` is the machine-readable map of this order and every
load-bearing local artifact.

## Authority hierarchy

Resolve disagreement in this order:

1. current tested code and executable contracts;
2. local decisions and narrowed canonical profiles;
3. direct local audit evidence;
4. external provenance links.

Generated indexes summarize their inputs; they do not overrule tested code.
Historical names, “canonical” labels, mirrors, a grail, or an external index
never override direct evidence. `STACK_LOCK.json` remains build-blocking until
its real release gaps are resolved.

## Task routing

| Work | Read first | Implementation/evidence |
|---|---|---|
| Runtime, provider auth, or `/chat` | `docs/canon/CHAT_WIRE.md`, `docs/canon/AGENT_ABI.md`, `docs/operations/PROVIDER_AUTH.md` | `src/rapp_stack_cubby/runtime/`, `tests/runtime/` |
| Agent behavior | `docs/canon/AGENT_ABI.md` | twin `agents/`, agent catalog, `tests/agents/` |
| Controller/hatch | `docs/canon/TWIN_LIFECYCLE.md` | controller source, `src/rapp_stack_cubby/controller/`, `tests/controller/` |
| Identity or signing | `docs/canon/IDENTITY_AND_TRUST.md`, `docs/canon/TWIN_CHAT.md` | `src/rapp_stack_cubby/protocols/`, transport schemas, protocol tests |
| Packaging/release | `docs/canon/ARTIFACT_CHAIN.md` | `src/rapp_stack_cubby/packaging/`, `tests/packaging/`, packaging/fetch/hatch runbooks, `STACK_LOCK.json` |
| iMessage | `docs/canon/MESSAGING_IMESSAGE.md`, `docs/operations/IMESSAGE_ONBOARDING.md` | `src/rapp_stack_cubby/imessage/`, `tests/imessage/`, pinned installer |
| Neighborhood/fleet/cloud | matching canonical profile | local capability matrix and system graph |
| Security/privacy | `docs/canon/SECURITY_AND_RELEASE.md` | `SECURITY.md`, `docs/PUBLIC_PRIVATE_BOUNDARY.md` |
| Publication scan | `docs/PUBLIC_PRIVATE_BOUNDARY.md`, `docs/operations/PACKAGING_AND_RELEASE.md` | `PUBLICATION_SCAN_POLICY.json`, `src/rapp_stack_cubby/packaging/publication.py`, scanner scripts/tests |
| Static Pages/workflows | `docs/decisions/static-pages-public-boundary.md`, `docs/operations/PAGES_OPERATIONS.md` | `src/rapp_stack_cubby/pages.py`, `docs/`, `.github/workflows/`, `tests/pages/` |
| Context maintenance | `docs/operations/CONTEXT_MAINTENANCE.md` | `src/rapp_stack_cubby/context.py`, `tests/test_context.py` |
| Census/audit refresh | `docs/research/account-crawl.md` | authenticated candidate-only refresher, local raw snapshot, eight shard ledgers, audit/graph generators and tests |
| Current gaps/next work | `docs/canon/GAP_REGISTER.md`, `docs/canon/ROADMAP.md` | implementation matrix and `STACK_LOCK.json` |

## Non-negotiable invariants

- One capability wire: loopback `POST /chat`; `/health` is operational only.
  The reserved canonical controller envelope is explicit-config,
  controller-loadout-only, deterministic registry/tool execution with no LLM
  choice; every other chat remains normal.
- Production runtime startup requires a live-preflighted explicit
  chat-completions model and one dedicated process with explicit root, data,
  principal, and optional generated-agent/iMessage status context. Provider
  token files are explicit absolute mode-0600 JSON with no symlink component;
  no Brainstem/OpenRappter/home path is searched and no model fallback exists.
- The top-level controller is the only streamable agent. Internal
  `*_agent.py` files remain strict native-manifest BasicAgent tools, never
  flattened skills. Production requires exactly synchronous, undecorated
  `def perform(self, **kwargs)` and rejects awaitable results. Compatibility
  registry loading is direct-test-only and is absent from product config,
  CLI, and controller paths.
- Controller and child have separate roots. Each child owns an isolated
  workspace, agents, data, process identity, and key binding. All lifecycle
  components are no-follow beneath the resolved private root and stale phase
  journals recover under exclusive locks.
- No remote code loading, request-time installation, shell/eval, mutable
  download, wildcard CORS, broad listener, or unauthenticated mutation.
- Exact source commit and digest checks precede lifecycle mutation.
- The committed source manifest excludes itself and never embeds its
  containing commit; Git/controller verify exact HEAD separately and a
  generated sidecar binds revision to artifacts.
- The artifact chain has no shortcut: source → cubby → rapplication →
  cubby egg → isolated installed twin → verified controller adoption.
- Source `rappid.json` is immutable public product identity. Egg hatch,
  repository hatch, and adoption mint distinct private instance RAPPIDs from
  non-published random birth nonces; only instance RAPPIDs run or pair.
- Controller twin traffic uses paired P-256 signatures, identity binding,
  strict canonical low-S epoch binding, durable phased replay handling, and
  signed nonce/digest-bound responses through only `POST /chat`; children are
  signed-only, pre-dispatch claims alone are reclaimable, and a possible
  dispatch becomes a signed terminal rejection rather than a redispatch.
- The separately configured global controller `/chat` is plain (not
  twin-signed) but bearer-authenticated local control. The enrolled owner
  iMessage edge reaches it only through authenticated challenged IPC.
  Loopback alone is not authentication.
- iMessage v1 accepts one enrolled owner direct conversation only; groups,
  SMS fallback, other principals, and public message data are forbidden.
- Private state stays outside the checkout: directories mode 0700, private
  PKCS8 and file state mode 0600, and public JWK mode 0644 only beneath
  private roots. A controller may pass an external provider token-file path
  only in fixed child argv; path and bytes never enter workspaces, receipts,
  logs, Pages, or artifacts. Keychain is not required by local v1.
- A local verifier or Pages pass is not a live deployment, release,
  publication, or conformance claim.
- Candidate publication requires one signed zero-finding source/history/Pages/
  artifact scan receipt; final promotion requires a second signed receipt over
  public redownload and explicitly supplied completed Actions log archives.

## Generated files

Do not hand-edit `CONTEXT_INDEX.json`, `SYSTEM_GRAPH.json`, census shards,
`AUDIT_MANIFEST.json`, the local agent catalog, the implementation matrix,
the controller catalog, or `docs/api/v1/*.json`.

```sh
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.context --root . --write
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.catalog --root . --write
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.audit --root .
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby.graph --root .
PYTHON=/opt/homebrew/bin/python3.11 scripts/pages-build.sh
```

`refresh-census` is the sole networked context tool. It requires an explicit
UTC cutoff and repository-local candidate output, never overwrites audited
evidence, and requires direct human classification before promotion.

After an intentional generated-file or context change, update the matching
`original_new`/`generated_local` SHA-256 records in `PROVENANCE.json` and
`STACK_LOCK.json`, then run every validation command below. Never “fix” a hash
without reviewing the changed bytes and status claim.

## Validation commands

All checks are local, deterministic, and network-free after the exact locked
Python dependencies are installed.

```sh
PYTHON=/opt/homebrew/bin/python3.11 scripts/context-check.sh
PYTHON=/opt/homebrew/bin/python3.11 scripts/check.sh
PYTHON=/opt/homebrew/bin/python3.11 scripts/pages-check.sh
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby context --root .
PYTHONPATH=src /opt/homebrew/bin/python3.11 -m rapp_stack_cubby verify --root .
```

## Privacy boundary

Only public source, original documentation, schemas, synthetic examples, and
sanitized evidence belong here. Do not add credentials, private keys, account
or transport identifiers, phone numbers, message content, memory content,
receipts, journals, databases, installed state, environment dumps, or
workstation paths. Follow `docs/PUBLIC_PRIVATE_BOUNDARY.md` and
`docs/operations/INCIDENT_RESPONSE.md`.

For a fresh fork or new Mac, follow
`docs/operations/IMESSAGE_ONBOARDING.md`. It keeps owner identifiers and
message state outside source and stops before enrollment until the exact
public twin exists.

## Release workflow

The complete local deterministic artifact chain, exhaustive target-free
installed verification, fail-closed publication scanner, static Pages handoff,
and pinned preparation workflows are implemented and may be
verified/exercised. Unsigned or `WORKTREE` output is development-only. A
future release must resolve every remaining
`STACK_LOCK.json` publication/attestation item, rebuild from one clean exact
commit, produce both signed scan receipts from explicit public inputs, prove
owner-only messaging, attest the supported host, publish once, and compare
downloaded bytes. See `docs/operations/PACKAGING_AND_RELEASE.md`.
