# RAPP Stack CUBBY

**Product chain:** complete source repository → `rapp-cubby/1.0` →
`rapp-application/1.0` → deterministic Store ZIP and
`brainstem-egg/2.3-cubby` → verified isolated
`rapp-installed-twin/1.1`.

> **This repository is the product.** It contains the complete normalized
> context, runtime, all actual agents, controller, signed twin-chat, owner-only
> iMessage bridge/tutorial/scripts, schemas, tests, dependency locks,
> packaging, hatch, SBOM, provenance, verification, and operating runbooks
> needed to understand, improve, build, package, hatch, and operate RAPP.
> Deterministic development artifacts, isolated hatch, and the complete
> offline signed installed-byte attestation journey are implemented.
> The checked static Pages handoff, immutable-SHA candidate/postflight, and
> protected same-commit promotion workflows are implemented locally.
> Publication, live owner proof, remote settings, and public byte verification
> have not been run and remain blocked and unclaimed.

**Prepared Pages target:** <https://kody-w.github.io/rapp-stack-cubby/>
The source site is release-pending until a real signed external release
sidecar is supplied. No badge or public-success claim is made.

**New Mac or fresh fork? Follow the complete
[owner-only iMessage onboarding tutorial](docs/operations/IMESSAGE_ONBOARDING.md).**

> **Complete local working context.** Start at [`AI_CONTEXT.md`](AI_CONTEXT.md).
> This repository now contains the normalized system facts, narrowed
> contracts, schema profiles, decisions, current implementation status, gaps,
> operations, provenance evidence, and reading order needed to understand and
> evolve RAPP end to end. External repository names and links are provenance
> evidence only—not missing working context.

The project implements part of the narrowed profile selected by local
canonical documents under `docs/canon/` and locked in `STACK_LOCK.json`.
`CONTEXT_INDEX.json` maps every load-bearing local artifact and all 61 selected
capabilities to tested implementation or a named future owner. Newly authored
implementation is MIT licensed. The grail remains a behavioral pointer only;
no grail source or external prose is copied here.

## Context bootstrap

Read, in order:

1. `AI_CONTEXT.md`
2. `docs/canon/SYSTEM_MODEL.md`
3. `docs/canon/IMPLEMENTATION_STATUS.md`
4. `docs/canon/GAP_REGISTER.md`
5. the task-specific profile under `docs/canon/`
6. `docs/operations/HANDOFF.md`

The machine index, 55 Draft 2020-12 schemas, 15 ADRs, and 16 runbooks are
validated without network access. The refreshed direct account inventory is
exactly **307 repositories** at existence cutoff
`2026-07-13T08:57:20.399000Z`. Inventory and individually timed heads were
observed over the non-atomic window
`2026-07-13T09:07:31.710577Z`–`2026-07-13T09:09:18.274404Z`; its raw
records, eight digest-bound shards, and complete twelve-repository drift
review are checked in. Five later-moving evidence heads are identified
separately rather than rewritten into earlier inspections.
`RAPP_END_TO_END.md` retains the antecedent synthesis and refresh; it is
evidence, not a requirement to fetch those repositories. This local product
was absent from that public inventory and is modeled separately.

## Current implementation

- Python package: `src/rapp_stack_cubby/`
- Isolated runtime: `src/rapp_stack_cubby/runtime/`
- Signed protocol and replay implementation:
  `src/rapp_stack_cubby/protocols/`
- Sole streamable controller:
  `cubbies/kody-w/agents/rapp_stack_cubby_agent.py`
- Controller catalog and receipt template: `cubbies/kody-w/catalog/`
- Controller-only external loadout builder:
  `rapp-stack-cubby controller-loadout --output-dir /absolute/external/path`
- Actual agents, including the content-free `IMessage` inspector:
  `cubbies/kody-w/rapplications/rapp-stack/twin/agents/`
- Agent-first operating contract:
  `cubbies/kody-w/rapplications/rapp-stack/twin/soul.md`
- Frozen generated catalogs:
  `cubbies/kody-w/rapplications/rapp-stack/twin/catalog/`
- Loopback service: `GET /health` and `POST /chat` only
- Runtime CLI: explicit-context `serve`, `health`, and live
  `provider-login`/`provider-refresh`/`models`/`provider-preflight`/
  `provider-smoke`; every token file is explicit, external, and mode 0600
- Fresh-user CLI: offline `doctor`, full `demo`, `attest-installed`, and
  generated `command-manifest`
- Owner-only bridge: `src/rapp_stack_cubby/imessage/`
- Bridge CLI: `rapp-stack-cubby imessage install-tool|init|preflight|status|run|service-install|service-uninstall`
- Immutable transport installer: `scripts/install-imsg.sh`
- Deterministic packaging/hatch implementation:
  `src/rapp_stack_cubby/packaging/`
- Stable public identity: `birth.json` and `rappid.json`
- Self-excluding source manifest: `rapp-release-source-manifest.json`
- Source indexes: `STORE_INDEX.json` and `rapp-super-rar.json`
- Complete rapplication source, singleton, and local UI:
  `cubbies/kody-w/rapplications/rapp-stack/`
- Public shelf placeholder: `cubbies/kody-w/`
- Reserved rapplication location:
  `cubbies/kody-w/rapplications/rapp-stack/`
- Static documentation root: `docs/`
- Dependency-free static front door: `docs/index.html`
- Deterministic static APIs: `docs/api/v1/`
- Pages generator/checker: `rapp-stack-cubby pages-build|pages-check`
- Immutable official Action lock: `GITHUB_ACTIONS_LOCK.json`
- Publication scanner/policy:
  `rapp-stack-cubby publication-scan|verify-publication-scan` and
  `PUBLICATION_SCAN_POLICY.json`
- Signed promotion verifier and protected command:
  `rapp-stack-cubby verify-promotion` and `scripts/promote-release.sh`
- Read-back-verified remote settings command:
  `scripts/configure-repository.sh` (not claimed applied)
- Candidate version/release truth: `VERSION` and `RELEASE_STATUS.json`
- Contract verifier: `python -m rapp_stack_cubby verify`
- Local context summary: `python -m rapp_stack_cubby context`
- Context validator: `scripts/context-check.sh`
- Candidate-only authenticated census refresh:
  `rapp-stack-cubby refresh-census --cutoff ... --output ...`
- Local census shard/audit generator and graph generator:
  `python -m rapp_stack_cubby.audit` and `python -m rapp_stack_cubby.graph`

The actual agent set is `AgentFactory`, `Cubby`, `Deployment`, `IMessage`,
`Memory`,
`Rappid`, `Rapplication`, `Registry`, `Security`, `SelfTest`, `StackMap`, and
the redacted read-only `TwinChat` inspector. `IMessage` reads only explicit
mode-0600 config/status files and returns content-free readiness facts.
Each is one independently loadable `*_agent.py` with the BasicAgent ABI and a
native `rapp-agent/1.0` manifest. Catalog ownership distinguishes focused
actions available now, existing unattested runtime substrate, explicit future
tasks, references, and exclusions.

`RappStackCubbyController` is the only agent in the top-level streamable
directory. It implements `inspect`, `verify`, verified `adopt_install`,
exact-commit `hatch_repo`, `list`, `status`, `start`, `stop`, `archive`,
`unarchive`, `purge`,
`rotate_keys`, signed `chat`, and signed conversational `self_test`. It has no
plaintext child fallback or alternate agent endpoint. `pack` and `export`
report `pending`; they do not create artifacts.

The supported development profile is Python `>=3.11,<3.12` with
`cryptography==49.0.0`; target wheel and transitive hashes are in
`requirements.lock` and `DEPENDENCY_LOCK.json`. The same lock records the
non-vendored signed `imsg==0.12.3` release/source/license evidence. The runtime loads only
explicitly configured local agents, keeps
state under an explicit per-instance data root, and has no login, import,
mutation, evaluation, static-file, or remote-execution route.

Agents require explicit `RAPP_STACK_ROOT` and `RAPP_STACK_DATA_DIR` values.
Generated-agent mutation additionally requires an explicit contained
`RAPP_STACK_GENERATED_AGENTS_DIR` and
`RAPP_STACK_ALLOW_AGENT_WRITES=1`. Mutation defaults disabled.

Controller mutations additionally require
`RAPP_STACK_ALLOW_CONTROLLER_MUTATIONS=1`, an explicit absolute
`RAPP_STACK_CONTROLLER_DATA_DIR`, and lifecycle idempotency keys. Child
startup requires an explicit absolute Python 3.11 executable in
`RAPP_STACK_PYTHON`; every start action also supplies an exact model that
passes runtime provider preflight. Controller production hatch fetches and verifies the
exact 40-lowercase-hex `HEAD` separately, then validates the committed
`rapp-release-source-manifest/1.0` against the fetched tree. The manifest
deliberately excludes itself and never embeds its containing commit; the
external release sidecar binds the final commit, source-tree digest, and
artifacts. The explicitly guarded controller development profile remains
non-release.

The reserved offline provider is not a model fallback. It is constructed only
when `--attestation-mode offline-self-test` and
`--model attestation-self-test/1.0` are both explicit on a signed-only child.
It has no auth/network code, emits only `SelfTest {"action":"run"}`, and then
returns empty content.

## Fresh development product proof

Choose all mutable paths outside this checkout. Fetch is separate; bootstrap
and demo are offline:

```sh
export PYTHON_BOOTSTRAP="/opt/homebrew/bin/python3.11"
export EXTERNAL_ROOT="<ABSOLUTE_EXTERNAL_ROOT>/rapp-stack-cubby"
install -d -m 700 "$EXTERNAL_ROOT" "$EXTERNAL_ROOT/cache"
PYTHON="$PYTHON_BOOTSTRAP" \
RAPP_DEPENDENCY_CACHE="$EXTERNAL_ROOT/cache" \
  scripts/fetch-dependencies.sh
scripts/bootstrap-development.sh \
  --python "$PYTHON_BOOTSTRAP" \
  --venv "$EXTERNAL_ROOT/venv" \
  --dependency-cache "$EXTERNAL_ROOT/cache" \
  --work-dir "$EXTERNAL_ROOT/work" \
  --install-dir "$EXTERNAL_ROOT/installs" \
  --controller-dir "$EXTERNAL_ROOT/controller"
scripts/demo-product.sh --python "$EXTERNAL_ROOT/venv/bin/python" \
  --work-dir "$EXTERNAL_ROOT/work" \
  --dependency-cache "$EXTERNAL_ROOT/cache" \
  --install-dir "$EXTERNAL_ROOT/installs" \
  --controller-dir "$EXTERNAL_ROOT/controller" \
  --receipt "$EXTERNAL_ROOT/demo-receipt.json" \
  --cleanup
```

The demo checks source/context/Pages, builds twice, verifies signed development
trust and egg, hatches offline, verifies installed source digest, creates a
mode-0600 controller token, adopts the install without Git, starts installed
bytes, performs signed content-free SelfTest through global `/chat`, stops,
archives/unarchives, proves no orphan, and cleans up. It never publishes,
enrolls iMessage, or sends.

## Build and hatch

Dependency fetching is the only build command permitted to use network. It
downloads exactly the four lock URLs into an explicit cache outside source,
checks size and SHA-256, and never executes bytes.

```sh
PYTHON=/absolute/python3.11 \
RAPP_DEPENDENCY_CACHE=/absolute/external/cache \
  scripts/fetch-dependencies.sh

PYTHON=/absolute/python3.11 \
RAPP_DEPENDENCY_CACHE=/absolute/external/cache \
SOURCE_DATE_EPOCH=1783892570 \
RAPP_SOURCE_REVISION=WORKTREE \
RAPP_BUILD_OUTPUT=/absolute/output \
  scripts/build-release.sh

PYTHON=/absolute/python3.11 \
RAPP_EGG=/absolute/output/rapp-stack-cubby.egg \
RAPP_EGG_SHA256=<verified-64-hex> \
RAPP_RELEASE_MANIFEST=/absolute/output/release-manifest.json \
RAPP_RELEASE_MANIFEST_SHA256=<verified-64-hex> \
RAPP_RELEASE_TRUST=/absolute/source/RELEASE_TRUST.json \
RAPP_INSTALL_ROOT=/absolute/new/install \
  scripts/hatch.sh
```

An unsigned build is always marked development-only. `RELEASE_TRUST.json`
pins the sole public P-256 release key; detached signatures never supply their
own trust key. The local private key was generated once outside the repository
and is never an artifact. Signed `WORKTREE` output remains development-only and is accepted only by the
explicit trusted-development demo path.
`verify-release` checks the low-S signature, exact checksums/assets, and source
binding. Production hatch requires that result and the expected egg digest.
Hatch verifies every archive/member through one open descriptor, installs
only bundled wheels with `pip --no-index --require-hashes`, verifies and
installs the bundled pinned imsg archive, creates isolated state/loadout roots,
seals and records every immutable directory/file/link/mode, atomically
promotes, and does not start. `verify-install` compares the exhaustive set
before any installed binary could run and performs no target-interpreter
probe.

Before prerelease, run `scripts/scan-publication.sh --phase candidate` with
absolute `--pages`, `--release-assets`, `--output`, release signing key/trust,
and signature output paths. Final promotion runs `--phase final` with the
additional `--public-redownload` and repeatable
`--actions-log RUN_ID=ABSOLUTE_ZIP` inputs. Verify either receipt using
`scripts/verify-publication-scan.sh --receipt ... --phase ... --signature ...
--trust ...`. The scanner never downloads or scans private runtime roots.

Source `rappid.json` remains the immutable public product identity. Hatch and
controller adoption mint distinct private instance RAPPIDs without publishing
their random birth nonces. The production local journey is build egg, hatch,
verify install, controller adopt through the deterministic controller-only
`POST /chat` route, then signed-only start of the returned instance RAPPID.
Child ports reject all plaintext before provider/tools. Controller chat and
self-test require idempotency keys and persist one canonical, low-S,
epoch-bound request for exact timeout/restart reuse. The separate global controller `/chat` is deterministic and model-free, but
always requires the exact mode-0600 bearer token file. Loopback alone is never
treated as authentication.

## Check the repository

```sh
PYTHON=python3.11 scripts/check.sh
PYTHON=python3.11 scripts/context-check.sh
PYTHON=python3.11 scripts/pages-build.sh
PYTHON=python3.11 scripts/pages-check.sh
PYTHONPATH=src python3.11 -m rapp_stack_cubby context --root .
PYTHONPATH=src python3.11 -m rapp_stack_cubby census
PYTHONPATH=src python3.11 -m rapp_stack_cubby.catalog --root . --check
PYTHONPATH=src python3.11 -m rapp_stack_cubby command-manifest \
  --root . --check --check-docs
```

The check also validates source-manifest freshness and controller/singleton
parity. It validates dependency locks, deterministic context and Pages APIs,
the complete static deployment tree, local-link closure, accessibility
structure, browser/privacy exclusions, immutable workflow pins, capability
ownership, generated catalogs, child/controller source, compiled Python, the
complete `unittest` suite, and all repository contracts. It installs no
dependencies and performs no network access.

## Artifact status

`cubby.json` is the public non-secret shelf manifest. Source builders now
produce the complete rapplication, Store ZIP, cubby egg, SPDX SBOM, provenance,
checksums, release sidecar, and release-specific indexes. Generated artifacts
remain ignored under `dist/`; they are development evidence, not committed
source or a public release. Installed manifests and receipts are private.
Stable future download URLs are generated from the candidate tag, but remain
visibly pending. Exact artifact hashes are never embedded in source or Pages;
the release-side `SHA256SUMS` asset owns that binding.
Signed transport source exists, but generated keys, pairings, sessions, replay
state, iMessage enrollment, and message content remain outside source and
artifacts. The non-shortcut chain is:

```text
source repo -> rapp-cubby/1.0 -> rapp-application/1.0
-> brainstem-egg/2.3-cubby -> isolated installed twin
-> verified controller adoption -> private running instance
```

See `SECURITY.md` and `docs/PUBLIC_PRIVATE_BOUNDARY.md` before adding any
configuration, fixture, generated output, or artifact.

## License

Newly authored project code is available under the MIT License. External
material remains governed by `PROVENANCE.json`, `NOTICE`, and the per-file
review requirements.
